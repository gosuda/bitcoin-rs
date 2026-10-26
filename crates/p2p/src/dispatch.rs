use std::cell::RefCell;
use std::sync::Arc;

use bitcoin::bip152::BlockTransactionsRequest;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin_rs_primitives::{BlockHash, ConsensusEncode, Hash256, Header, Tx, Txid, Wtxid};

use crate::fsm::step;
use crate::handshake::{feature_messages, negotiated_features};
use crate::inv::{
    inventory_block_hash, inventory_tx_hash, is_within_inventory_bound, request_witness,
};
use crate::packages::{
    AncPkgInfo, GetPkgTxns, MSG_ANCPKGINFO, MSG_PKGTXNS, PKG_RELAY_ANC, PKG_RELAY_PKGTXNS, PkgTxns,
    SendPackages, combined_package_hash,
};
use crate::peer::{PackageRequest, Peer, PeerState};
use crate::wire::{MAX_HEADERS_MESSAGE_COUNT, MAX_MESSAGE_PAYLOAD, Message, PeerError};

/// Fully applied active-chain tip published by chainstate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedTip {
    /// Applied height.
    pub height: u32,
    /// Applied block hash.
    pub hash: BlockHash,
    /// Previous block hash from the applied tip's header.
    pub prev_hash: BlockHash,
}

/// Maximum block locator hashes accepted in one locator-based request.
pub(crate) use crate::wire::MAX_LOCATOR_HASHES;

/// Outcome of streamed inventory serving. Bodies pass through the serving
/// sink as they load and are never materialized as a whole.
#[derive(Debug, Default)]
pub struct InventoryServing {
    /// Inventory this node cannot serve (unknown type, stale, pruned, no
    /// body).
    pub not_found: Vec<Inventory>,
    /// True when production stopped at the headroom gate with items
    /// unexamined. A halt loads no body and reports no unserved item as
    /// served or missing: the caller keeps the unexamined items and resumes
    /// them once the gate opens (I9: no silent half-serve).
    pub halted: bool,
}

/// The single durable record of one compact-filter request across serving
/// attempts.
///
/// The first attempt carries the peer's request unchanged with no expected
/// end. When a serving pass stops after emitting a prefix of a range
/// (`getcfilters` only), the remainder is the same request narrowed to start
/// after the emitted prefix, with `expected_end` pinning the stop height the
/// emitted prefix was computed against. A later pass recomputes the range and
/// fails if the chain moved under the cursor, instead of splicing two
/// different ranges into one reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterRequest {
    /// The request still to serve: the peer's original message, or its
    /// narrowed remainder.
    pub request: Message,
    /// Height of the last filter the full range ends at, fixed by the first
    /// pass that emitted a prefix. `None` before anything was emitted.
    pub expected_end: Option<u32>,
}

impl FilterRequest {
    /// Wraps a peer's compact-filter request for its first serving attempt.
    #[must_use]
    pub const fn new(request: Message) -> Self {
        Self {
            request,
            expected_end: None,
        }
    }
}

/// Outcome of one compact-filter serving attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterServing {
    /// The whole request was answered (or there was nothing to answer).
    Done,
    /// Nothing more could be sent now: publication or send headroom is
    /// pending. The record is the exact remainder; passing it back resumes
    /// without replaying anything already sent.
    Pending(FilterRequest),
}

/// Header response for a BIP332 stale tip announcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StaleTipHeaders {
    /// The stale branch headers starting immediately after `fork_point`.
    Headers(crate::staletip::StaleTipAnnouncement),
    /// The stale branch is longer than [`crate::staletip::MAX_STALETIP_HEADERS`].
    TooMany,
}

/// Read-only active-chain view used by server-side P2P responders.
pub trait ChainQuery: Send + Sync {
    /// Whether the optional filter index currently covers the applied chain.
    fn compact_filters_ready(&self) -> bool {
        false
    }

    /// Serves a bounded BIP157 request from persisted filters only.
    ///
    /// PRE: `request` is a [`FilterRequest`] built by
    /// [`FilterRequest::new`] or returned by an earlier
    /// [`FilterServing::Pending`] of this same request. `headroom` reserves
    /// (or reuses) the caller's production credit immediately before each
    /// filter is loaded and returns false when none is available.
    /// POST: `Done` when every filter in the range was sent. `Pending` with
    /// the exact remainder when publication or `headroom` stopped serving; a
    /// pending record never repeats a message already sent, and `Pending`
    /// carries the input unchanged when nothing was sent. `Err` for a range
    /// that is interrupted for good (the index stopped early, or the chain
    /// moved under a resumed cursor) and for send failures.
    /// INVARIANT: a saturated outbound gate is `Pending`, never an error.
    fn serve_compact_filters(
        &self,
        _request: &FilterRequest,
        _headroom: &dyn Fn() -> bool,
        _send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<FilterServing, PeerError> {
        Ok(FilterServing::Done)
    }
    /// Returns a bounded contiguous header response: locator-based ranges
    /// walk the applied chain, while the empty-locator single-header direct
    /// lookup stays on the header-best chain.
    fn headers_after(
        &self,
        locator_hashes: &[BlockHash],
        stop_hash: BlockHash,
        limit: usize,
    ) -> Vec<Header>;

    /// Serves block inventory one response at a time, in `items` order. For
    /// each block-typed item `headroom` is consulted EXACTLY ONCE,
    /// immediately BEFORE its body load; `false` halts production and sets
    /// `halted` (I7, I9). `headroom` reserves or reuses the caller's
    /// worst-case outbound reservation, which the following `serve` spends.
    /// Full-block items are served as
    /// [`Message::BlockPayload`]; `MSG_CMPCT_BLOCK` items as
    /// [`Message::CmpctBlock`] built at the given BIP152 version — `None`
    /// (peer never negotiated) leaves compact items in `not_found`. Each
    /// `MSG_WITNESS_BLOCK` body preserves the stored consensus payload;
    /// `MSG_BLOCK` strips witness data from the validated body (BIP144).
    /// A `serve` error aborts production and propagates. Non-block / unservable items
    /// are collected into `not_found` and never loaded.
    fn serve_inventory_blocks(
        &self,
        items: &[Inventory],
        compact_version: Option<u64>,
        headroom: &dyn Fn() -> bool,
        serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<InventoryServing, PeerError>;

    /// PRE: `request` carries decoded absolute transaction indexes for one
    /// block. `compact_version` is the peer's servable BIP152 profile.
    /// POST: return the reply to send — a `blocktxn` for a block shallow
    /// enough to reconstruct, encoded for `compact_version` (v1 strips
    /// witnesses, any other profile keeps them), or the whole
    /// witness-bearing `block` for one too deep for a useful hint set
    /// (Core 31.1 answers both instead of leaving a peer to time out);
    /// `Ok(None)` leaves the request unanswered (unknown, stale, pruned,
    /// or headless block, or a saturated `headroom` gate). `Err` reports
    /// an out-of-range transaction index — a protocol disconnect per
    /// BIP152 (Core scores misbehavior).
    /// INVARIANT: `headroom` is evaluated before any block body is loaded,
    /// so a saturated outbound gate materializes no body for this request.
    fn block_transactions(
        &self,
        request: &BlockTransactionsRequest,
        compact_version: Option<u64>,
        headroom: &dyn Fn() -> bool,
    ) -> Result<Option<Message>, PeerError>;

    /// Header time of the active tip, `None` when no active tip is known.
    ///
    /// PRE: none.
    /// POST: returns UNIX seconds of the tip header Core would read as
    ///   `m_best_block_time` (`net_processing.cpp:1445-1448`); `None` means
    ///   nothing is applied, which the outbound service policy reads as the
    ///   deepest possible local chain.
    /// INVARIANT: the only local tip-age source for peer admission; no
    ///   caller walks the block tree per handshake for it.
    fn best_block_time(&self) -> Option<u32> {
        None
    }

    /// Returns the active-chain height of `hash` if it is currently an ancestor
    /// of the active tip.
    fn active_height(&self, _hash: BlockHash) -> Option<u32> {
        None
    }

    /// Builds one `cmpctblock` message for the block at `height` and `hash`
    /// at the given BIP152 version.
    fn compact_block_for(
        &self,
        _height: u32,
        _hash: BlockHash,
        _compact_version: Option<u64>,
    ) -> Option<Message> {
        None
    }

    /// The fully applied active-chain tip, or `None` if uninitialized.
    ///
    /// This is deliberately distinct from the header-tree tip: consumers of
    /// committed block effects must never treat fresher, unapplied headers as
    /// the publication frontier.
    fn committed_tip(&self) -> Option<CommittedTip> {
        None
    }

    /// Returns the BIP332 stale-tip headers for `tip` given the peer's
    /// demonstrated tips, or `None` if the tip is unknown, not stale, or
    /// not an ancestor of any demonstrated tip. Returns `TooMany` if the
    /// branch exceeds [`crate::staletip::MAX_STALETIP_HEADERS`].
    fn stale_tip_announcement(
        &self,
        tip: Hash256,
        peer_tips: &[Hash256],
    ) -> Option<StaleTipHeaders>;
}

/// Transaction inventory view and successful-getdata acknowledgement seam,
/// used by the Inv filter and transaction responder.
///
/// Implemented here for the mempool gateway; the p2p crate owns the protocol
/// adapter while mempool owns admission, orphan, and rejection state.
/// The dispatch path consults this trait to suppress redundant `getdata`
/// requests for transactions the node already holds and to serve
/// transaction bodies in reply to `getdata`.
pub trait TxInventory: Send + Sync {
    /// Returns `true` when the node already holds the transaction identified by
    /// `hash` — in the mempool, the orphan map, or the recent-rejects cache.
    /// `hash_is_wtxid` is true for `WTx` (wtxid) and false for
    /// `Transaction`/`WitnessTransaction` (txid).
    fn have_tx(&self, hash: Hash256, hash_is_wtxid: bool) -> bool;

    /// Returns the witness transaction body for `txid`, or `None` when the
    /// node does not have it. Used to answer `getdata` for txid-typed items.
    fn get_tx(&self, txid: Txid) -> Option<Tx>;

    /// Returns the witness transaction body for `wtxid`, or `None` when the
    /// node does not have it. Used to answer BIP339 `getdata` (`WTx`) items.
    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx>;

    /// Called only after a transaction body was successfully queued for getdata.
    fn transaction_sent(&self, _wtxid: Wtxid) {}

    /// The BIP331 ancestor package of `wtxid` the node can serve: its
    /// unconfirmed ancestors in topological order, then `wtxid` itself.
    ///
    /// POST: resident pool members only, never an orphan or a recent reject,
    /// and `None` when `wtxid` is not resident, the package is too large, or
    /// the provider has no resident pool. The last element is `wtxid`.
    fn resident_ancestor_package(&self, wtxid: Wtxid) -> Option<Vec<Wtxid>>;

    /// The bodies of `wtxids`, in request order, when every one is resident.
    ///
    /// POST: all or none, read from one view of the resident pool, as the
    /// pool's own handles; never an orphan or a recent reject, and never the
    /// general [`Self::get_tx_by_wtxid`] lookup. `None` when any member is
    /// absent or the provider has no resident pool. The caller bounds
    /// `wtxids.len()`.
    fn resident_package(&self, wtxids: &[Wtxid]) -> Option<Vec<Arc<Tx>>>;
}

impl TxInventory for bitcoin_rs_mempool::MempoolGateway {
    fn transaction_sent(&self, wtxid: Wtxid) {
        self.mark_broadcast(wtxid);
    }

    fn resident_ancestor_package(&self, wtxid: Wtxid) -> Option<Vec<Wtxid>> {
        Self::ancestor_package_wtxids(self, wtxid)
    }

    fn resident_package(&self, wtxids: &[Wtxid]) -> Option<Vec<Arc<Tx>>> {
        Self::resident_package(self, wtxids)
    }

    fn have_tx(&self, hash: Hash256, hash_is_wtxid: bool) -> bool {
        Self::have_tx(self, hash, hash_is_wtxid)
    }

    fn get_tx(&self, txid: Txid) -> Option<Tx> {
        Self::get_tx(self, txid)
    }

    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        Self::get_tx_by_wtxid(self, wtxid)
    }
}

impl crate::compact_blocks::CompactBlockHints for bitcoin_rs_mempool::MempoolGateway {
    fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
        Self::for_each_reconstruction_identity(self, f);
    }
    fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
        Self::reconstruction_tx_by_txid(self, txid)
    }

    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        Self::reconstruction_tx_by_wtxid(self, wtxid)
    }
}

/// Chainless dispatch: collects the protocol responses and returns them.
///
/// With `chain: None` responses can never contain a block body, so the batch
/// is protocol-bounded (at most [`MAX_HEADERS_MESSAGE_COUNT`] headers, or one
/// inventory-bound notfound/getdata echo) and safe to materialize whole.
/// Block announcements go to a no-op sink.
pub fn dispatch_inbound<S>(
    peer: &mut Peer<S>,
    message: &Message,
) -> Result<Vec<Message>, PeerError> {
    let responses = RefCell::new(Vec::new());
    dispatch_inbound_full(
        peer,
        message,
        None,
        None,
        &|| true,
        &|| true,
        &mut |response| {
            responses.borrow_mut().push(response);
            Ok(())
        },
        &mut |_| {},
        &mut |items| responses.borrow_mut().push(Message::GetData(items)),
    )?;
    Ok(responses.into_inner())
}

/// Dispatch with an active-chain view and a transaction-inventory filter.
///
/// Every response is emitted through `send` in the identical order the
/// former batch form produced (I8); `send` errors abort emission and
/// propagate. `headroom` gates block-body materialization (I7) and is
/// evaluated before each load. It reserves the outbound bytes of one
/// worst-case frame (or reuses a reservation already held) and returns
/// `false` when the connection or the node cannot take them; the next `send`
/// spends that reservation, so a body is loaded only while its queue space is
/// already owned.
///
/// When `tx_inventory` is `Some`, the `inv` arm suppresses `getdata` for
/// transactions the node already holds (mempool, orphan map, or
/// recent-rejects) and the `getdata` arm serves tx bodies for tx-typed
/// items the node has, reporting the rest as `notfound`. Inventory types
/// identify txids or wtxids independently of the peer's outbound preference.
///
/// `tx_relay_open` reports whether the node accepts transaction relay from
/// peers (it is not in initial block download). While it returns `false`,
/// the `inv` arm requests no transaction-typed vector and every other arm
/// is unchanged. The gate is evaluated lazily per `inv` message.
///
/// `announce_tx` receives missing transaction vectors for the shared request
/// owner; dispatch never chooses a download source.
///
/// `announce_block` receives the hash of every `MSG_BLOCK` and
/// `MSG_WITNESS_BLOCK` vector of an `inv`.
/// PRE: `announce_block` belongs to the connection that `peer` wraps.
/// POST: block inventory reaches `announce_block` and never a `getdata`.
/// INVARIANT: block bodies are requested only by header sync and the
/// download window (Core 31.1 `net_processing.cpp:4370-4410`).
#[expect(clippy::too_many_arguments, reason = "independent protocol sinks")]
pub fn dispatch_inbound_full<S>(
    peer: &mut Peer<S>,
    message: &Message,
    chain: Option<&dyn ChainQuery>,
    tx_inventory: Option<&dyn TxInventory>,
    tx_relay_open: &dyn Fn() -> bool,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    announce_block: &mut dyn FnMut(Hash256),
    announce_tx: &mut dyn FnMut(Vec<Inventory>),
) -> Result<(), PeerError> {
    match message {
        Message::Version(version) => {
            step(peer, message)?;
            reply_to_version(peer, version.version, send)?;
        }
        Message::Ping(nonce) => {
            step(peer, message)?;
            send(Message::Pong(*nonce))?;
        }
        Message::Inv(items) => {
            step(peer, message)?;
            receive_inv(
                peer,
                items,
                tx_inventory,
                tx_relay_open,
                announce_block,
                announce_tx,
            )?;
        }
        Message::GetHeaders(request) => {
            ensure_block_locator_within_bounds(
                &request.locator_hashes,
                "getheaders locator too large",
            )?;
            step(peer, message)?;
            send(headers_response(chain, request))?;
        }
        Message::GetCFilters(_) | Message::GetCFHeaders(_) | Message::GetCFCheckpt(_) => {
            step(peer, message)?;
            if peer.pending_filter_request.is_some() {
                return Err(PeerError::Io(std::io::Error::other(
                    "compact filter request already pending",
                )));
            }
            if let Some(chain) = chain
                && let FilterServing::Pending(remainder) = chain.serve_compact_filters(
                    &FilterRequest::new(message.clone()),
                    headroom,
                    send,
                )?
            {
                peer.pending_filter_request = Some(crate::peer::ParkedFilter::new(
                    remainder,
                    std::time::Instant::now(),
                ));
            }
        }
        Message::GetBlocks(request) => {
            ensure_block_locator_within_bounds(
                &request.locator_hashes,
                "getblocks locator too large",
            )?;
            step(peer, message)?;
        }
        Message::GetData(items) => {
            ensure_inventory_request_within_bounds(items)?;
            step(peer, message)?;
            ensure_getdata_package_types_negotiated(peer, items)?;
            serve_inbound_getdata(peer, chain, tx_inventory, items, headroom, send)?;
        }
        Message::AncPkgInfo(_)
        | Message::GetPkgTxns(_)
        | Message::PkgTxns(_)
        | Message::PkgTxnsPayload(_) => {
            step(peer, message)?;
            receive_package_message(peer, message, tx_inventory, tx_relay_open, headroom, send)?;
        }
        Message::GetBlockTxn(request) => {
            ensure_block_txn_indexes_valid(&request.txs_request)?;
            step(peer, message)?;
            let compact_version = peer.compact_blocks.servable_version();
            serve_block_txn(chain, &request.txs_request, compact_version, headroom, send)?;
        }
        _ => step(peer, message)?,
    }

    if peer.state == PeerState::Ready {
        tracing::trace!("peer handshake ready");
    }

    Ok(())
}

/// Answers the peer's `version` with our feature offers, the one BIP331
/// `sendpackages` offer, and `verack`.
///
/// POST: `sendpackages` is sent at most once per connection, before `verack`.
fn reply_to_version<S>(
    peer: &mut Peer<S>,
    remote_version: u32,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    for response in feature_messages() {
        send(response)?;
    }
    for announcement in negotiated_features(peer, remote_version) {
        send(Message::Feature(announcement))?;
    }
    if let Some(versions) = peer.package_relay.unsent_offer() {
        send(Message::SendPackages(SendPackages { versions }))?;
        peer.package_relay.record_advertised(versions);
    }
    send(Message::Verack)
}

/// Routes one `inv`: block vectors go to `announce_block`, and the
/// transaction vectors this node wants go to `announce_tx` as one request.
///
/// POST: an `inv` of a package-relay-only type is misbehavior. Compact,
/// unknown, and error vectors are ignored (Core `ProcessMessage(INV)`).
fn receive_inv<S>(
    peer: &Peer<S>,
    items: &[Inventory],
    tx_inventory: Option<&dyn TxInventory>,
    tx_relay_open: &dyn Fn() -> bool,
    announce_block: &mut dyn FnMut(Hash256),
    announce_tx: &mut dyn FnMut(Vec<Inventory>),
) -> Result<(), PeerError> {
    if items.iter().any(is_package_inventory) {
        return Err(PeerError::Misbehavior(
            "inv of a package-relay-only inventory type",
        ));
    }
    let relay_open = tx_relay_open();
    let mut requested = Vec::new();
    for item in items {
        if let Some(hash) = inventory_block_hash(item) {
            announce_block(hash);
            continue;
        }
        let Some(hash) = inventory_tx_hash(item) else {
            continue;
        };
        if !relay_open
            || tx_inventory.is_some_and(|inv| inv.have_tx(hash, matches!(item, Inventory::WTx(_))))
        {
            continue;
        }
        requested.push(*item);
    }
    if !requested.is_empty() {
        let witness = peer.remote_version.as_ref().is_some_and(|version| {
            version.services.to_u64() & bitcoin::p2p::ServiceFlags::WITNESS.to_u64() != 0
        });
        request_witness(&mut requested, witness);
        announce_tx(requested);
    }
    Ok(())
}

/// Applies one BIP331 package message once its sequence step passed.
///
/// POST: the message's `PKG_RELAY_*` bit was negotiated, otherwise the peer is
/// disconnected through the returned error. A `pkgtxns` frame is charged and
/// admitted by the node's ingress, which decodes it only after planning, so
/// dispatch checks the negotiation alone.
fn receive_package_message<S>(
    peer: &mut Peer<S>,
    message: &Message,
    tx_inventory: Option<&dyn TxInventory>,
    tx_relay_open: &dyn Fn() -> bool,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    match message {
        Message::AncPkgInfo(info) => {
            ensure_package_relay(
                peer,
                PKG_RELAY_ANC,
                "ancpkginfo without negotiated ancestor package relay",
            )?;
            if tx_relay_open() {
                peer.pending_package_request = package_request(tx_inventory, info);
            }
        }
        Message::GetPkgTxns(request) => {
            ensure_package_relay(
                peer,
                PKG_RELAY_PKGTXNS,
                "getpkgtxns without negotiated package transaction relay",
            )?;
            serve_getpkgtxns(tx_inventory, request, headroom, send)?;
        }
        _ => ensure_package_relay(
            peer,
            PKG_RELAY_PKGTXNS,
            "pkgtxns without negotiated package transaction relay",
        )?,
    }
    Ok(())
}

/// Whether `item` is one of the two BIP331 inventory types.
fn is_package_inventory(item: &Inventory) -> bool {
    matches!(
        item,
        Inventory::Unknown {
            inv_type: MSG_ANCPKGINFO | MSG_PKGTXNS,
            ..
        }
    )
}

/// The BIP331 `PKG_RELAY_*` bit `bit` must have been negotiated for the
/// connection before a message that rides it is accepted.
///
/// POST: otherwise the sender violated its own negotiation and no reply is
/// sent; the peer is disconnected through the returned error.
fn ensure_package_relay<S>(peer: &Peer<S>, bit: u64, error: &'static str) -> Result<(), PeerError> {
    if peer.package_relay_versions() & bit == 0 {
        return Err(PeerError::Misbehavior(error));
    }
    Ok(())
}

/// Rejects the `getdata` item types BIP331 forbids: `MSG_PKGTXNS` is a
/// `notfound`-only type, and `MSG_ANCPKGINFO` needs ancestor-package relay.
fn ensure_getdata_package_types_negotiated<S>(
    peer: &Peer<S>,
    items: &[Inventory],
) -> Result<(), PeerError> {
    for item in items {
        match item {
            Inventory::Unknown {
                inv_type: MSG_PKGTXNS,
                ..
            } => {
                return Err(PeerError::Misbehavior(
                    "getdata of a notfound-only package inventory type",
                ));
            }
            Inventory::Unknown {
                inv_type: MSG_ANCPKGINFO,
                ..
            } => ensure_package_relay(
                peer,
                PKG_RELAY_ANC,
                "getdata ancpkginfo without negotiated ancestor package relay",
            )?,
            _ => {}
        }
    }
    Ok(())
}

/// The download an `ancpkginfo` asks the request owner for.
///
/// A member counts as held only when it is resident in the pool: an orphan
/// or a recent reject is exactly what the package exists to resolve, so it
/// is requested again and admitted with its ancestors as one package.
/// POST: `None` when the subject is already resident or more than
/// `MAX_PACKAGE_COUNT` members are missing. Otherwise the non-resident
/// members in announced order, the subject last: the one sequence the
/// `getpkgtxns` is written from and the claim records.
fn package_request(
    tx_inventory: Option<&dyn TxInventory>,
    info: &AncPkgInfo,
) -> Option<PackageRequest> {
    let subject = info.subject()?;
    let resident = |wtxid: &Wtxid| {
        tx_inventory.is_some_and(|inventory| {
            inventory
                .resident_package(std::slice::from_ref(wtxid))
                .is_some()
        })
    };
    if resident(&subject) {
        return None;
    }
    let wtxids: Vec<Wtxid> = info
        .wtxids
        .iter()
        .copied()
        .filter(|wtxid| !resident(wtxid))
        .collect();
    if wtxids.len() > bitcoin_rs_mempool::standardness::MAX_PACKAGE_COUNT {
        return None;
    }
    Some(PackageRequest { subject, wtxids })
}

/// Answers one `getpkgtxns`: every requested transaction in one `pkgtxns`,
/// or one `notfound` of type `MSG_PKGTXNS` carrying the request's combined
/// hash and nothing else.
///
/// Members come from the resident pool only, read as one view, never from
/// the orphan or recent-reject sets. A package whose `pkgtxns` could not fit
/// one frame is unavailable too.
/// INVARIANT: one reply message, so one `headroom` reservation covers it and
/// no body is loaded while the gate is closed. A closed gate leaves the
/// request unanswered, like `getblocktxn`.
fn serve_getpkgtxns(
    tx_inventory: Option<&dyn TxInventory>,
    request: &GetPkgTxns,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    if !headroom() {
        return Ok(());
    }
    let package = tx_inventory.and_then(|inventory| {
        inventory
            .resident_package(&request.wtxids)
            .filter(|bodies| fits_one_frame(bodies))
            .map(|bodies| (inventory, bodies))
    });
    let Some((inventory, bodies)) = package else {
        return send(Message::NotFound(vec![Inventory::Unknown {
            inv_type: MSG_PKGTXNS,
            hash: combined_package_hash(&request.wtxids),
        }]));
    };
    send(Message::PkgTxns(PkgTxns {
        txs: bodies.iter().map(|tx| Tx::clone(tx)).collect(),
    }))?;
    for wtxid in &request.wtxids {
        inventory.transaction_sent(*wtxid);
    }
    Ok(())
}

/// Whether `bodies`, as one `pkgtxns`, fit the transport frame.
fn fits_one_frame(bodies: &[Arc<Tx>]) -> bool {
    let count = u64::try_from(bodies.len()).unwrap_or(u64::MAX);
    let mut total = bitcoin_rs_primitives::varint::encoded_len(count);
    for tx in bodies {
        total = total.saturating_add(tx.consensus_size());
        if total > MAX_MESSAGE_PAYLOAD {
            return false;
        }
    }
    true
}

/// Answers one `getdata(MSG_ANCPKGINFO)` item with the resident ancestor
/// package of its subject, or reports the item missing.
///
/// Returns `false`, having done nothing, when `headroom` is closed; `true`
/// once the `ancpkginfo` was sent or the item appended to `not_found`.
fn serve_ancpkginfo_item(
    tx_inventory: Option<&dyn TxInventory>,
    item: &Inventory,
    subject: Wtxid,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    not_found: &mut Vec<Inventory>,
) -> Result<bool, PeerError> {
    if !headroom() {
        return Ok(false);
    }
    let package = tx_inventory
        .and_then(|inventory| inventory.resident_ancestor_package(subject))
        .map(|wtxids| AncPkgInfo { wtxids })
        .filter(|info| info.subject() == Some(subject) && info.encode().is_ok());
    match package {
        Some(info) => send(Message::AncPkgInfo(info))?,
        None => not_found.push(*item),
    }
    Ok(true)
}

fn headers_response(chain: Option<&dyn ChainQuery>, request: &GetHeadersMessage) -> Message {
    let locator_hashes: Vec<BlockHash> = request
        .locator_hashes
        .iter()
        .map(|h| BlockHash(Hash256::from_le_bytes(h.as_byte_array())))
        .collect();
    let stop_hash = BlockHash(Hash256::from_le_bytes(request.stop_hash.as_byte_array()));
    let mut headers = chain.map_or_else(Vec::new, |chain| {
        chain.headers_after(&locator_hashes, stop_hash, MAX_HEADERS_MESSAGE_COUNT)
    });
    headers.truncate(MAX_HEADERS_MESSAGE_COUNT);
    Message::Headers(headers)
}

/// Serves one decoded `getdata` and parks what the production gate stops.
///
/// PRE: `items` passed the inventory bound and nothing is parked on `peer`:
/// the session reads nothing while a tail is parked, so a second request here
/// is a caller bug, and replacing or reordering the parked tail would
/// silently half-serve it.
/// POST: the tail [`serve_getdata`] returns is `peer.pending_getdata` and the
/// misses it keeps are `peer.pending_notfound`; both are empty when the whole
/// request was handled.
fn serve_inbound_getdata<S>(
    peer: &mut Peer<S>,
    chain: Option<&dyn ChainQuery>,
    tx_inventory: Option<&dyn TxInventory>,
    items: &[Inventory],
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    if peer.has_parked_getdata() {
        return Err(PeerError::Io(std::io::Error::other(
            "getdata already parked",
        )));
    }
    let compact_version = peer.compact_blocks.servable_version();
    let mut not_found = Vec::new();
    let tail = serve_getdata(
        chain,
        tx_inventory,
        compact_version,
        items,
        &mut not_found,
        headroom,
        send,
    )?;
    peer.pending_getdata = tail;
    peer.pending_notfound.extend(not_found);
    Ok(())
}

/// Serves `items` of one `getdata` through the sink, one item at a time and
/// in request order, until the outbound production gate halts it.
///
/// Block-typed and unknown items resolve through the chain query; with no
/// chain view they are reported missing. When `tx_inventory` is `Some`,
/// tx-typed items are served from the transaction inventory (the node's
/// mempool): a held tx is emitted as a `tx` message with the serialization
/// requested by its inventory type (P2P-01 / BIP144). BIP339 `WTx` items are
/// resolved by wtxid; `Transaction`/`WitnessTransaction` items by txid. With
/// `tx_inventory` `None` a tx-typed item is not a block and is reported
/// missing by the chain query.
///
/// PRE: `not_found` holds no item of `items`; `send` queues one message on
/// the connection that asked.
/// POST: every item before the returned tail was answered: served through
/// `send`, or appended to `not_found`. A non-empty return is `items` from the
/// first item the gate stopped at; nothing was sent for it. An empty return
/// means the whole request was handled: then one `notfound` carrying all of
/// `not_found` has been sent (I8), or — when the gate closed between the
/// last item and the trailing report — nothing was sent, `not_found` keeps
/// the misses, and the caller parks them like any other parked tail (I9).
/// A `send` or chain error aborts and propagates.
/// INVARIANT: `headroom` is consulted before every body load, every tx
/// lookup, and the trailing `notfound` send, so a saturated gate materializes
/// nothing and queues no message, and a halt neither sends nor disconnects.
/// The reservation `headroom` takes is held across lookups that send nothing
/// (a miss) and is spent by the next `send`, so a run of misses never takes
/// a second reservation. The caller, which owns the budget, reports the kept
/// misses once an exactly sized reply fits, and resumes the tail once it can
/// reserve production room again. At most one decoded request
/// (`MAX_INV_PER_MSG` items) is ever pending, so the tail and `not_found`
/// are bounded.
pub(crate) fn serve_getdata(
    chain: Option<&dyn ChainQuery>,
    tx_inventory: Option<&dyn TxInventory>,
    compact_version: Option<u64>,
    items: &[Inventory],
    not_found: &mut Vec<Inventory>,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<Vec<Inventory>, PeerError> {
    for (index, item) in items.iter().enumerate() {
        let tx_source = tx_inventory.filter(|_| {
            matches!(
                item,
                Inventory::Transaction(_) | Inventory::WitnessTransaction(_) | Inventory::WTx(_)
            )
        });
        let served = match (item, tx_source) {
            (
                Inventory::Unknown {
                    inv_type: MSG_ANCPKGINFO,
                    hash,
                },
                _,
            ) => {
                let subject = Wtxid::from(Hash256::from_le_bytes(hash));
                serve_ancpkginfo_item(tx_inventory, item, subject, headroom, send, not_found)?
            }
            (_, Some(inv)) => serve_tx_item(inv, item, headroom, send, not_found)?,
            (_, None) => serve_block_item(chain, compact_version, item, headroom, send, not_found)?,
        };
        if !served {
            return Ok(items[index..].to_vec());
        }
    }
    if not_found.is_empty() {
        return Ok(Vec::new());
    }
    // The trailing misses are answered behind every served item, but a gate
    // that closed while the last items were served must not turn into a
    // refused send: that cancels the lease for the session's own queue state.
    // The headroom check runs immediately before the send, so only a sender
    // that wins the slot concurrently can still refuse it. When it is closed,
    // the misses stay in `not_found` for the caller to park: they are not
    // items, and returning them as the tail would send them as `getdata`
    // answers.
    if !headroom() {
        return Ok(Vec::new());
    }
    send(Message::NotFound(std::mem::take(not_found)))?;
    Ok(Vec::new())
}

/// Answers one tx-typed `getdata` item from the transaction inventory.
///
/// Returns `false`, having done nothing, when `headroom` is closed; `true`
/// once the transaction was sent or the item appended to `not_found`.
fn serve_tx_item(
    inv: &dyn TxInventory,
    item: &Inventory,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    not_found: &mut Vec<Inventory>,
) -> Result<bool, PeerError> {
    if !headroom() {
        return Ok(false);
    }
    let found = match item {
        Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
            let native = Txid::from(Hash256::from_le_bytes(txid.as_byte_array()));
            inv.get_tx(native).map(|mut tx| {
                let wtxid = tx.wtxid();
                if matches!(item, Inventory::Transaction(_)) {
                    for input in &mut tx.inputs {
                        input.witness.clear();
                    }
                }
                (wtxid, tx)
            })
        }
        Inventory::WTx(wtxid) => {
            let native = Wtxid::from(Hash256::from_le_bytes(wtxid.as_byte_array()));
            inv.get_tx_by_wtxid(native).map(|tx| (native, tx))
        }
        _ => None,
    };
    match found {
        Some((wtxid, tx)) => {
            send(Message::Tx(tx))?;
            inv.transaction_sent(wtxid);
        }
        None => not_found.push(*item),
    }
    Ok(true)
}

/// Answers one block-typed or unknown `getdata` item through the chain
/// query, which consults `headroom` once before a body load.
///
/// Returns `false`, having sent nothing, when the chain query halted at the
/// gate; `true` once the item was served or appended to `not_found`.
fn serve_block_item(
    chain: Option<&dyn ChainQuery>,
    compact_version: Option<u64>,
    item: &Inventory,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    not_found: &mut Vec<Inventory>,
) -> Result<bool, PeerError> {
    let Some(chain) = chain else {
        not_found.push(*item);
        return Ok(true);
    };
    let outcome = chain.serve_inventory_blocks(
        std::slice::from_ref(item),
        compact_version,
        headroom,
        send,
    )?;
    if outcome.halted {
        return Ok(false);
    }
    not_found.extend(outcome.not_found);
    Ok(true)
}

/// Answers one `getblocktxn` through the chain view and sends whatever reply
/// it produces. PRE: the request's indexes are structurally valid.
/// `compact_version` is the peer's servable BIP152 profile (`None` leaves
/// witness encoding untouched). POST: a servable block gets its `blocktxn`
/// in the peer's profile encoding, a block too deep for a compact answer
/// gets the whole `block`, and an unknown, stale, headless, or
/// production-gated block — or a node with no chain view — leaves the
/// request unanswered. INVARIANT: the dispatch boundary never learns which
/// reply shape the chain chose, and a saturated `headroom` gate loads no
/// block body here.
fn serve_block_txn(
    chain: Option<&dyn ChainQuery>,
    request: &BlockTransactionsRequest,
    compact_version: Option<u64>,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    let Some(chain) = chain else {
        return Ok(());
    };
    if let Some(response) = chain.block_transactions(request, compact_version, headroom)? {
        send(response)?;
    }
    Ok(())
}

/// Enforces native decoded `getblocktxn` policy: nonempty, increasing indexes.
///
/// PRE: the request carries decoded absolute indexes. POST: a rejected list
/// returns `PeerError::Misbehavior` before any chain query, even without a chain.
/// Core 31.1 establishes increasing wire indexes during deserialization
/// (`blockencodings.h:23-54`, `net_processing.cpp:4333-4340`); the order check here
/// also defends in-process requests. Empty-list rejection is stricter native
/// policy: Core accepts an empty decoded list.
fn ensure_block_txn_indexes_valid(request: &BlockTransactionsRequest) -> Result<(), PeerError> {
    if request.indexes.is_empty() {
        return Err(PeerError::Misbehavior("getblocktxn with empty index list"));
    }
    if request.indexes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(PeerError::Misbehavior(
            "getblocktxn indexes not strictly increasing",
        ));
    }
    Ok(())
}

fn ensure_block_locator_within_bounds(
    locator_hashes: &[bitcoin::BlockHash],
    error: &'static str,
) -> Result<(), PeerError> {
    if locator_hashes.len() > MAX_LOCATOR_HASHES {
        return Err(PeerError::Misbehavior(error));
    }
    Ok(())
}

fn ensure_inventory_request_within_bounds(items: &[Inventory]) -> Result<(), PeerError> {
    if !is_within_inventory_bound(items) {
        return Err(PeerError::Misbehavior("getdata inventory too large"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_consensus::ValidationEngine;
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bitcoin::bip152::{BlockTransactions, BlockTransactionsRequest};
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::Magic;
    use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
    use bitcoin::p2p::message_compact_blocks::BlockTxn;
    use bitcoin_rs_primitives::{
        Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Sequence, Tx, Txid,
        Witness, Wtxid, deserialize,
    };

    use super::{
        ChainQuery, FilterRequest, FilterServing, InventoryServing, MAX_LOCATOR_HASHES,
        StaleTipHeaders, TxInventory, dispatch_inbound, dispatch_inbound_full, serve_getdata,
    };
    use crate::connection::{OutboundBudget, PeerLease};
    use crate::feature::{FEATURE_VERSION, FeatureAnnouncement, FeatureId};
    use crate::handshake::{feature_messages, negotiated_features};
    use crate::inv::MAX_INV_PER_MSG;
    use crate::packages::{
        AncPkgInfo, GetPkgTxns, MSG_ANCPKGINFO, MSG_PKGTXNS, PKG_RELAY_ANC, PKG_RELAY_PKGTXNS,
        PkgTxns, SendPackages, combined_package_hash,
    };
    use crate::peer::{PackageRequest, Peer, PeerState};
    use crate::wire::{MAX_HEADERS_MESSAGE_COUNT, Message, PROTOCOL_VERSION, PeerError};

    fn block_payload(block: &Block) -> Message {
        Message::BlockPayload(bytes::Bytes::from(bitcoin_rs_primitives::consensus_bytes(
            block,
        )))
    }

    #[derive(Default)]
    struct FakeChain {
        headers: Vec<Header>,
        blocks: Vec<Block>,
    }

    impl FakeChain {
        fn with_headers(count: u32) -> Self {
            let mut headers = Vec::new();
            let mut prev = BlockHash::default();
            for nonce in 0..count {
                let header = test_header(prev, nonce);
                prev = header.compute_hash();
                headers.push(header);
            }
            Self {
                headers,
                blocks: Vec::new(),
            }
        }

        fn with_block(mut self, block: Block) -> Self {
            self.blocks.push(block);
            self
        }
    }

    impl ChainQuery for FakeChain {
        fn stale_tip_announcement(
            &self,
            _tip: Hash256,
            _peer_tips: &[Hash256],
        ) -> Option<StaleTipHeaders> {
            None
        }
        fn serve_compact_filters(
            &self,
            request: &FilterRequest,
            _: &dyn Fn() -> bool,
            _: &mut dyn FnMut(Message) -> Result<(), PeerError>,
        ) -> Result<FilterServing, PeerError> {
            Ok(FilterServing::Pending(request.clone()))
        }
        fn headers_after(
            &self,
            _locator_hashes: &[BlockHash],
            _stop_hash: BlockHash,
            limit: usize,
        ) -> Vec<Header> {
            self.headers.iter().take(limit).copied().collect()
        }

        fn serve_inventory_blocks(
            &self,
            items: &[Inventory],
            _compact_version: Option<u64>,
            headroom: &dyn Fn() -> bool,
            serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
        ) -> Result<InventoryServing, PeerError> {
            let mut outcome = InventoryServing::default();
            for item in items {
                let Some(found) = self
                    .blocks
                    .iter()
                    .find(|block| inv_hash(item) == Some(wire_hash(block)))
                else {
                    outcome.not_found.push(*item);
                    continue;
                };
                if !headroom() {
                    outcome.halted = true;
                    return Ok(outcome);
                }
                serve(block_payload(found))?;
            }
            Ok(outcome)
        }

        fn block_transactions(
            &self,
            _request: &BlockTransactionsRequest,
            _compact_version: Option<u64>,
            _headroom: &dyn Fn() -> bool,
        ) -> Result<Option<Message>, PeerError> {
            Ok(None)
        }
    }

    /// Streaming fake mirroring `ActiveChainQuery`: block-typed items that
    /// resolve to a stored body are served behind `headroom`; everything
    /// else lands in `not_found` without a load.
    fn inv_hash(item: &Inventory) -> Option<[u8; 32]> {
        match item {
            Inventory::Block(hash) | Inventory::WitnessBlock(hash) => Some(hash.to_byte_array()),
            _ => None,
        }
    }

    fn wire_hash(block: &Block) -> [u8; 32] {
        *block.block_hash().as_bytes()
    }

    struct GreedyHeaders {
        headers: Vec<Header>,
    }

    impl ChainQuery for GreedyHeaders {
        fn stale_tip_announcement(
            &self,
            _tip: Hash256,
            _peer_tips: &[Hash256],
        ) -> Option<StaleTipHeaders> {
            None
        }
        fn headers_after(
            &self,
            _locator_hashes: &[BlockHash],
            _stop_hash: BlockHash,
            _limit: usize,
        ) -> Vec<Header> {
            self.headers.clone()
        }

        fn serve_inventory_blocks(
            &self,
            _items: &[Inventory],
            _compact_version: Option<u64>,
            _headroom: &dyn Fn() -> bool,
            _serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
        ) -> Result<InventoryServing, PeerError> {
            Ok(InventoryServing::default())
        }

        fn block_transactions(
            &self,
            _request: &BlockTransactionsRequest,
            _compact_version: Option<u64>,
            _headroom: &dyn Fn() -> bool,
        ) -> Result<Option<Message>, PeerError> {
            Ok(None)
        }
    }

    /// Collecting-sink wrapper mirroring the listener's streaming send.
    fn dispatch_collect<S>(
        peer: &mut Peer<S>,
        message: &Message,
        chain: Option<&dyn ChainQuery>,
    ) -> Result<Vec<Message>, PeerError> {
        let collected = RefCell::new(Vec::new());
        dispatch_inbound_full(
            peer,
            message,
            chain,
            None,
            &|| true,
            &|| true,
            &mut |response| {
                collected.borrow_mut().push(response);
                Ok(())
            },
            &mut |_| {},
            &mut |items| collected.borrow_mut().push(Message::GetData(items)),
        )?;
        Ok(collected.into_inner())
    }

    #[test]
    fn getheaders_returns_chain_query_headers() -> Result<(), PeerError> {
        let chain = FakeChain::with_headers(2);
        let message = Message::GetHeaders(GetHeadersMessage::new(
            vec![bitcoin::BlockHash::all_zeros()],
            bitcoin::BlockHash::all_zeros(),
        ));
        let mut peer = ready_peer();

        let responses = dispatch_collect(&mut peer, &message, Some(&chain))?;

        let [Message::Headers(headers)] = responses.as_slice() else {
            panic!("expected one headers response, got {responses:?}");
        };
        assert_eq!(headers.len(), 2);
        Ok(())
    }

    #[test]
    fn getheaders_truncates_chain_response_above_protocol_cap() -> Result<(), PeerError> {
        let count = u32::try_from(MAX_HEADERS_MESSAGE_COUNT + 1)
            .map_err(|_| PeerError::Protocol("test header count overflow"))?;
        let chain = GreedyHeaders {
            headers: FakeChain::with_headers(count).headers,
        };
        let message = Message::GetHeaders(GetHeadersMessage::new(
            vec![bitcoin::BlockHash::all_zeros()],
            bitcoin::BlockHash::all_zeros(),
        ));
        let mut peer = ready_peer();

        let responses = dispatch_collect(&mut peer, &message, Some(&chain))?;

        let [Message::Headers(headers)] = responses.as_slice() else {
            panic!("expected one headers response, got {responses:?}");
        };
        assert_eq!(headers.len(), MAX_HEADERS_MESSAGE_COUNT);
        Ok(())
    }

    #[test]
    fn oversized_getheaders_locator_is_protocol_error() {
        let locator = vec![bitcoin::BlockHash::all_zeros(); MAX_LOCATOR_HASHES + 1];
        let message = Message::GetHeaders(GetHeadersMessage::new(
            locator,
            bitcoin::BlockHash::all_zeros(),
        ));
        let mut peer = ready_peer();
        let before = peer_snapshot(&peer);

        let result = dispatch_inbound(&mut peer, &message);

        assert!(matches!(
            result,
            Err(PeerError::Misbehavior("getheaders locator too large"))
        ));
        assert_eq!(peer_snapshot(&peer), before);
    }

    #[test]
    fn oversized_getblocks_locator_is_protocol_error() {
        let locator = vec![bitcoin::BlockHash::all_zeros(); MAX_LOCATOR_HASHES + 1];
        let message = Message::GetBlocks(GetBlocksMessage::new(
            locator,
            bitcoin::BlockHash::all_zeros(),
        ));
        let mut peer = ready_peer();
        let before = peer_snapshot(&peer);

        let result = dispatch_inbound(&mut peer, &message);

        assert!(matches!(
            result,
            Err(PeerError::Misbehavior("getblocks locator too large"))
        ));
        assert_eq!(peer_snapshot(&peer), before);
    }

    #[test]
    fn getblocks_locator_at_cap_is_accepted() -> Result<(), PeerError> {
        let locator = vec![bitcoin::BlockHash::all_zeros(); MAX_LOCATOR_HASHES];
        let message = Message::GetBlocks(GetBlocksMessage::new(
            locator,
            bitcoin::BlockHash::all_zeros(),
        ));
        let mut peer = ready_peer();

        let responses = dispatch_inbound(&mut peer, &message)?;

        assert_eq!(responses, []);
        assert_eq!(peer.state, PeerState::Ready);
        Ok(())
    }

    #[test]
    fn getdata_serves_available_blocks_and_reports_missing_inventory() -> Result<(), PeerError> {
        let chain = FakeChain::with_headers(1);
        let block = Block {
            header: chain.headers[0],
            txs: Vec::new(),
        };
        let missing = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array([7; 32]));
        let chain = chain.with_block(block);
        let message = Message::GetData(vec![
            Inventory::Block(bitcoin::BlockHash::from_byte_array(
                *chain.headers[0].compute_hash().as_bytes(),
            )),
            missing,
        ]);
        let mut peer = ready_peer();

        let responses = dispatch_collect(&mut peer, &message, Some(&chain))?;

        let [Message::BlockPayload(found), Message::NotFound(not_found)] = responses.as_slice()
        else {
            panic!("expected block payload plus notfound, got {responses:?}");
        };
        let found = deserialize::<Block>(found)
            .unwrap_or_else(|error| panic!("served payload must decode: {error}"));
        assert_eq!(found.block_hash(), chain.headers[0].compute_hash());
        assert_eq!(not_found, &vec![missing]);
        Ok(())
    }

    #[test]
    fn getdata_without_chain_reports_notfound() -> Result<(), PeerError> {
        let hash = bitcoin::BlockHash::all_zeros();
        let message = Message::GetData(vec![Inventory::Block(hash)]);
        let mut peer = ready_peer();

        let responses = dispatch_inbound(&mut peer, &message)?;

        let [Message::NotFound(not_found)] = responses.as_slice() else {
            panic!("expected notfound, got {responses:?}");
        };
        assert_eq!(not_found, &vec![Inventory::Block(hash)]);
        Ok(())
    }

    #[test]
    fn getblocktxn_is_answered_with_blocktxn_from_the_chain() -> Result<(), PeerError> {
        struct ServingChain;
        impl ChainQuery for ServingChain {
            fn stale_tip_announcement(
                &self,
                _tip: Hash256,
                _peer_tips: &[Hash256],
            ) -> Option<StaleTipHeaders> {
                None
            }
            fn headers_after(
                &self,
                _locator_hashes: &[BlockHash],
                _stop_hash: BlockHash,
                _limit: usize,
            ) -> Vec<Header> {
                Vec::new()
            }

            fn serve_inventory_blocks(
                &self,
                _items: &[Inventory],
                _compact_version: Option<u64>,
                _headroom: &dyn Fn() -> bool,
                _serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
            ) -> Result<InventoryServing, PeerError> {
                Ok(InventoryServing::default())
            }

            fn block_transactions(
                &self,
                request: &BlockTransactionsRequest,
                _compact_version: Option<u64>,
                _headroom: &dyn Fn() -> bool,
            ) -> Result<Option<Message>, PeerError> {
                Ok(Some(Message::BlockTxn(BlockTxn {
                    transactions: BlockTransactions {
                        block_hash: request.block_hash,
                        transactions: Vec::new(),
                    },
                })))
            }
        }

        let mut peer = ready_peer();
        let responses = dispatch_collect(
            &mut peer,
            &Message::GetBlockTxn(bitcoin::p2p::message_compact_blocks::GetBlockTxn {
                txs_request: BlockTransactionsRequest {
                    block_hash: bitcoin::BlockHash::from_byte_array([7; 32]),
                    indexes: vec![0],
                },
            }),
            Some(&ServingChain),
        )?;

        assert!(matches!(responses.as_slice(), [Message::BlockTxn(_)]));
        Ok(())
    }

    /// Refuses one `getblocktxn` index list both with a chain attached and
    /// with none, so the boundary decision cannot depend on chain state.
    fn assert_getblocktxn_refused(indexes: Vec<u64>) {
        let chain = FakeChain::with_headers(2);
        let message = Message::GetBlockTxn(bitcoin::p2p::message_compact_blocks::GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash: bitcoin::BlockHash::from_byte_array([7; 32]),
                indexes,
            },
        });
        let view: &dyn ChainQuery = &chain;
        for case in [Some(view), None] {
            let mut peer = ready_peer();
            let outcome = dispatch_collect(&mut peer, &message, case);
            assert!(
                matches!(outcome, Err(PeerError::Misbehavior(_))),
                "a malformed getblocktxn must disconnect, got {outcome:?}",
            );
        }
    }

    #[test]
    fn invalid_getblocktxn_indexes_disconnect() {
        assert_getblocktxn_refused(Vec::new());
        assert_getblocktxn_refused(vec![1, 1]);
        assert_getblocktxn_refused(vec![3, 2]);
    }

    #[test]
    fn getblocktxn_is_unanswered_while_the_production_gate_is_saturated()
    -> Result<(), Box<dyn std::error::Error>> {
        struct GatedChain {
            observed: AtomicUsize,
            loads: AtomicUsize,
        }
        impl ChainQuery for GatedChain {
            fn stale_tip_announcement(
                &self,
                _tip: Hash256,
                _peer_tips: &[Hash256],
            ) -> Option<StaleTipHeaders> {
                None
            }
            fn headers_after(
                &self,
                _locator_hashes: &[BlockHash],
                _stop_hash: BlockHash,
                _limit: usize,
            ) -> Vec<Header> {
                Vec::new()
            }

            fn serve_inventory_blocks(
                &self,
                _items: &[Inventory],
                _compact_version: Option<u64>,
                _headroom: &dyn Fn() -> bool,
                _serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
            ) -> Result<InventoryServing, PeerError> {
                Ok(InventoryServing::default())
            }

            fn block_transactions(
                &self,
                request: &BlockTransactionsRequest,
                _compact_version: Option<u64>,
                headroom: &dyn Fn() -> bool,
            ) -> Result<Option<Message>, PeerError> {
                self.observed.fetch_add(1, Ordering::Relaxed);
                if !headroom() {
                    return Ok(None);
                }
                self.loads.fetch_add(1, Ordering::Relaxed);
                Ok(Some(Message::BlockTxn(BlockTxn {
                    transactions: BlockTransactions {
                        block_hash: request.block_hash,
                        transactions: Vec::new(),
                    },
                })))
            }
        }

        let chain = GatedChain {
            observed: AtomicUsize::new(0),
            loads: AtomicUsize::new(0),
        };
        let message = Message::GetBlockTxn(bitcoin::p2p::message_compact_blocks::GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash: bitcoin::BlockHash::from_byte_array([7; 32]),
                indexes: vec![0],
            },
        });
        let mut peer = ready_peer();
        let collected = RefCell::new(Vec::new());
        dispatch_inbound_full(
            &mut peer,
            &message,
            Some(&chain),
            None,
            &|| true,
            &|| false,
            &mut |response| {
                collected.borrow_mut().push(response);
                Ok(())
            },
            &mut |_| {},
            &mut |items| collected.borrow_mut().push(Message::GetData(items)),
        )?;

        assert_eq!(chain.observed.load(Ordering::Relaxed), 1);
        assert_eq!(
            chain.loads.load(Ordering::Relaxed),
            0,
            "a saturated gate must not produce a reply body"
        );
        assert!(
            collected.borrow().is_empty(),
            "the request stays unanswered"
        );
        Ok(())
    }

    /// Streaming chain fake mirroring `ActiveChainQuery`: block-typed items
    /// that resolve to a stored body are served behind `headroom`; all other
    /// items land in `not_found` without a load.
    struct StreamingChain {
        blocks: Vec<Block>,
        loads: AtomicUsize,
        headroom_calls: AtomicUsize,
        /// Panics when a load would reach this count (mutation-gate tripwire).
        load_tripwire: Option<usize>,
    }
    impl ChainQuery for StreamingChain {
        fn stale_tip_announcement(
            &self,
            _tip: Hash256,
            _peer_tips: &[Hash256],
        ) -> Option<StaleTipHeaders> {
            None
        }
        fn headers_after(
            &self,
            _locator_hashes: &[BlockHash],
            _stop_hash: BlockHash,
            _limit: usize,
        ) -> Vec<Header> {
            Vec::new()
        }

        fn serve_inventory_blocks(
            &self,
            items: &[Inventory],
            _compact_version: Option<u64>,
            headroom: &dyn Fn() -> bool,
            serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
        ) -> Result<InventoryServing, PeerError> {
            let mut outcome = InventoryServing::default();
            for item in items {
                let Some(hash) = inv_hash(item) else {
                    outcome.not_found.push(*item);
                    continue;
                };
                let Some(found) = self.blocks.iter().find(|block| wire_hash(block) == hash) else {
                    outcome.not_found.push(*item);
                    continue;
                };
                self.headroom_calls.fetch_add(1, Ordering::Relaxed);
                if !headroom() {
                    outcome.halted = true;
                    return Ok(outcome);
                }
                if let Some(limit) = self.load_tripwire {
                    assert!(
                        self.loads.load(Ordering::Relaxed) < limit,
                        "hostile getdata materialized beyond the derived bound"
                    );
                }
                self.loads.fetch_add(1, Ordering::Relaxed);
                serve(block_payload(found))?;
            }
            Ok(outcome)
        }

        fn block_transactions(
            &self,
            _request: &BlockTransactionsRequest,
            _compact_version: Option<u64>,
            _headroom: &dyn Fn() -> bool,
        ) -> Result<Option<Message>, PeerError> {
            Ok(None)
        }
    }

    #[test]
    fn streamed_getdata_preserves_batch_wire_order() -> Result<(), PeerError> {
        let headers = FakeChain::with_headers(2).headers;
        let block_a = Block {
            header: headers[0],
            txs: Vec::new(),
        };
        let block_b = Block {
            header: headers[1],
            txs: Vec::new(),
        };
        let inv_a = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
            *headers[0].compute_hash().as_bytes(),
        ));
        let inv_b = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
            *headers[1].compute_hash().as_bytes(),
        ));
        let tx_inv = Inventory::Transaction(bitcoin::Txid::from_byte_array([1; 32]));
        let unknown = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array([9; 32]));
        let chain = StreamingChain {
            blocks: vec![block_a.clone(), block_b.clone()],
            loads: AtomicUsize::new(0),
            headroom_calls: AtomicUsize::new(0),
            load_tripwire: None,
        };
        let mut peer = ready_peer();

        let emitted = dispatch_collect(
            &mut peer,
            &Message::GetData(vec![tx_inv, inv_a, inv_b, unknown]),
            Some(&chain),
        )?;

        assert_eq!(
            emitted,
            vec![
                block_payload(&block_a),
                block_payload(&block_b),
                Message::NotFound(vec![tx_inv, unknown]),
            ],
            "streamed emission must equal the pre-change batch shape (I8)"
        );
        assert_eq!(chain.loads.load(Ordering::Relaxed), 2);
        assert_eq!(chain.headroom_calls.load(Ordering::Relaxed), 2);
        Ok(())
    }

    #[test]
    fn headroom_false_before_first_load_parks_without_loading() {
        let headers = FakeChain::with_headers(1).headers;
        let block = Block {
            header: headers[0],
            txs: Vec::new(),
        };
        let known = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
            *headers[0].compute_hash().as_bytes(),
        ));
        let chain = StreamingChain {
            blocks: vec![block],
            loads: AtomicUsize::new(0),
            headroom_calls: AtomicUsize::new(0),
            load_tripwire: None,
        };
        let mut peer = ready_peer();
        let emitted = RefCell::new(Vec::new());

        let result = dispatch_inbound_full(
            &mut peer,
            &Message::GetData(vec![known]),
            Some(&chain),
            None,
            &|| true,
            &|| false,
            &mut |response| {
                emitted.borrow_mut().push(response);
                Ok(())
            },
            &mut |_| {},
            &mut |_| {},
        );

        assert!(
            result.is_ok(),
            "a saturated gate parks the request instead of failing the peer"
        );
        assert_eq!(chain.headroom_calls.load(Ordering::Relaxed), 1);
        assert_eq!(chain.loads.load(Ordering::Relaxed), 0);
        assert!(
            emitted.into_inner().is_empty(),
            "halt never emits a trailing notfound (I9)"
        );
        assert_eq!(peer.pending_getdata, vec![known]);
        assert_eq!(peer.pending_notfound, Vec::new());
    }

    fn wire_len_of(message: &Message) -> usize {
        crate::wire::wire_len(message).unwrap_or_else(|_| panic!("test message must encode"))
    }

    #[test]
    fn hostile_50000_item_getdata_parks_the_tail() {
        let block = Block::default();
        let block_wire_len = wire_len_of(&Message::Block(block.clone()));
        let (outbound_tx, _undrained_rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new_with_budget(
            outbound_tx,
            false,
            OutboundBudget::with_block_reserve(100_000, 4 * 2 * block_wire_len, 2 * block_wire_len),
        );
        let budget = lease.budget_handle();
        let known = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
            *block.block_hash().as_bytes(),
        ));
        let chain = StreamingChain {
            blocks: vec![block],
            loads: AtomicUsize::new(0),
            headroom_calls: AtomicUsize::new(0),
            load_tripwire: Some(8),
        };
        let mut peer = ready_peer();

        let result = dispatch_inbound_full(
            &mut peer,
            &Message::GetData(vec![known; MAX_INV_PER_MSG]),
            Some(&chain),
            None,
            &|| true,
            &|| budget.may_reserve_production(),
            &mut |message| {
                lease
                    .send(message)
                    .map_err(|_| PeerError::Protocol("outbound queue closed or saturated"))
            },
            &mut |_| {},
            &mut |_| {},
        );

        assert!(result.is_ok(), "a saturated gate parks the tail");
        assert_eq!(chain.loads.load(Ordering::Relaxed), 7);
        assert_eq!(chain.headroom_calls.load(Ordering::Relaxed), 8);
        assert_eq!(budget.pending(), (7, 7 * block_wire_len));
        assert_eq!(peer.pending_getdata.len(), MAX_INV_PER_MSG - 7);
        assert_eq!(peer.pending_notfound, Vec::new());
        assert!(!lease.is_cancelled(), "parking never cancels the lease");
    }

    /// A gate that closes mid-request parks the unexamined remainder in
    /// request order, keeps the misses found so far unsent, and the tail
    /// resumed later answers in the order the peer asked.
    #[test]
    fn halted_mixed_getdata_parks_ordered_tail_and_unsent_misses() -> Result<(), PeerError> {
        let headers = FakeChain::with_headers(2).headers;
        let block_a = Block {
            header: headers[0],
            txs: Vec::new(),
        };
        let block_b = Block {
            header: headers[1],
            txs: Vec::new(),
        };
        let inv_a =
            Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(wire_hash(&block_a)));
        let inv_b =
            Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(wire_hash(&block_b)));
        let held = dummy_tx(1);
        let tx_hit =
            Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(*held.txid().as_bytes()));
        let tx_miss = Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array([7; 32]));
        let unknown_block = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array([9; 32]));
        let inventory = FakeTxInventory::empty().with_tx(held.clone());
        let chain = StreamingChain {
            blocks: vec![block_a.clone(), block_b.clone()],
            loads: AtomicUsize::new(0),
            headroom_calls: AtomicUsize::new(0),
            load_tripwire: None,
        };
        let mut peer = ready_peer();
        let emitted = RefCell::new(Vec::new());
        // Consultations: tx_miss (1), block_a (2) pass; tx_hit (3) halts.
        let consulted = std::cell::Cell::new(0_usize);

        dispatch_inbound_full(
            &mut peer,
            &Message::GetData(vec![tx_miss, inv_a, tx_hit, inv_b, unknown_block]),
            Some(&chain),
            Some(&inventory),
            &|| true,
            &|| {
                consulted.set(consulted.get() + 1);
                consulted.get() <= 2
            },
            &mut |response| {
                emitted.borrow_mut().push(response);
                Ok(())
            },
            &mut |_| {},
            &mut |_| {},
        )?;

        assert_eq!(
            emitted.take(),
            vec![block_payload(&block_a)],
            "only what was served before the gate closed is on the wire"
        );
        assert_eq!(peer.pending_notfound, vec![tx_miss]);
        assert_eq!(peer.pending_getdata, vec![tx_hit, inv_b, unknown_block]);

        let mut misses = Vec::new();
        let rest = serve_getdata(
            Some(&chain),
            Some(&inventory),
            None,
            &peer.pending_getdata,
            &mut misses,
            &|| true,
            &mut |response| {
                emitted.borrow_mut().push(response);
                Ok(())
            },
        )?;

        assert!(rest.is_empty(), "an open gate finishes the tail");
        assert_eq!(
            emitted.take(),
            vec![
                Message::Tx(held),
                block_payload(&block_b),
                Message::NotFound(vec![unknown_block]),
            ],
            "the resumed tail keeps request order and ends in one notfound"
        );
        assert!(
            misses.is_empty(),
            "the trailing notfound drained the misses when the gate stayed open"
        );
        Ok(())
    }

    /// The probe's tail shape: the gate closes between the last served item
    /// and the trailing report. The misses must come back parked instead of
    /// being sent into a full queue, which would cancel the lease.
    #[test]
    fn gate_closed_at_the_trailing_report_parks_the_misses() -> Result<(), PeerError> {
        let headers = FakeChain::with_headers(1).headers;
        let block = Block {
            header: headers[0],
            txs: Vec::new(),
        };
        let served = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
            *headers[0].compute_hash().as_bytes(),
        ));
        let miss = Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array([6; 32]));
        let chain = StreamingChain {
            blocks: vec![block.clone()],
            loads: AtomicUsize::new(0),
            headroom_calls: AtomicUsize::new(0),
            load_tripwire: None,
        };
        let inventory = FakeTxInventory::empty();
        let emitted = RefCell::new(Vec::new());
        // Consultations: the miss (1) and the block (2) pass; the trailing
        // report (3) finds the gate closed.
        let consulted = std::cell::Cell::new(0_usize);
        let mut not_found = Vec::new();

        let tail = serve_getdata(
            Some(&chain),
            Some(&inventory),
            None,
            &[miss, served],
            &mut not_found,
            &|| {
                consulted.set(consulted.get() + 1);
                consulted.get() <= 2
            },
            &mut |response| {
                emitted.borrow_mut().push(response);
                Ok(())
            },
        )?;

        assert!(tail.is_empty(), "the whole request was handled");
        assert_eq!(
            emitted.into_inner(),
            vec![block_payload(&block)],
            "the block was served while the gate was open"
        );
        assert_eq!(
            not_found,
            vec![miss],
            "the trailing report must keep the misses parked, unsent"
        );
        Ok(())
    }

    #[test]
    fn getdata_while_one_is_parked_is_refused_and_keeps_the_tail() {
        let parked = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array([4; 32]));
        let mut peer = ready_peer();
        peer.pending_getdata = vec![parked];
        let emitted = RefCell::new(Vec::new());

        let result = dispatch_inbound_full(
            &mut peer,
            &Message::GetData(vec![Inventory::WitnessBlock(
                bitcoin::BlockHash::from_byte_array([5; 32]),
            )]),
            None,
            None,
            &|| true,
            &|| true,
            &mut |response| {
                emitted.borrow_mut().push(response);
                Ok(())
            },
            &mut |_| {},
            &mut |_| {},
        );

        assert!(matches!(result, Err(PeerError::Io(_))));
        assert_eq!(
            peer.pending_getdata,
            vec![parked],
            "the earlier tail survives"
        );
        assert_eq!(emitted.into_inner(), Vec::new());
    }

    #[test]
    fn send_refusal_mid_stream_aborts_production() {
        let block = Block::default();
        let block_wire_len = wire_len_of(&Message::Block(block.clone()));
        let (outbound_tx, _undrained_rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new_with_budget(
            outbound_tx,
            false,
            OutboundBudget::with_block_reserve(100_000, 3 * block_wire_len, 0),
        );
        let budget = lease.budget_handle();
        let known = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
            *block.block_hash().as_bytes(),
        ));
        let chain = StreamingChain {
            blocks: vec![block.clone(), block.clone(), block.clone(), block],
            loads: AtomicUsize::new(0),
            headroom_calls: AtomicUsize::new(0),
            load_tripwire: None,
        };
        let mut peer = ready_peer();

        let result = dispatch_inbound_full(
            &mut peer,
            &Message::GetData(vec![known; 4]),
            Some(&chain),
            None,
            &|| true,
            &|| true,
            &mut |message| {
                lease
                    .send(message)
                    .map_err(|_| PeerError::Protocol("outbound queue closed or saturated"))
            },
            &mut |_| {},
            &mut |_| {},
        );

        assert!(matches!(
            result,
            Err(PeerError::Protocol("outbound queue closed or saturated"))
        ));
        assert_eq!(
            chain.loads.load(Ordering::Relaxed),
            4,
            "three admitted plus one refused load"
        );
        assert!(lease.is_cancelled());
        assert_eq!(budget.pending(), (3, 3 * block_wire_len));
    }

    #[test]
    fn oversized_getdata_inventory_is_protocol_error() {
        let hash = bitcoin::BlockHash::all_zeros();
        let inventory = vec![Inventory::Block(hash); MAX_INV_PER_MSG + 1];
        let message = Message::GetData(inventory);
        let mut peer = ready_peer();
        let before = peer_snapshot(&peer);

        let result = dispatch_inbound(&mut peer, &message);

        assert!(matches!(
            result,
            Err(PeerError::Misbehavior("getdata inventory too large"))
        ));
        assert_eq!(peer_snapshot(&peer), before);
    }

    /// A fake `TxInventory` that knows a fixed set of txids/wtxids and can
    /// serve their bodies.
    struct FakeTxInventory {
        txs_by_txid: hashbrown::HashMap<bitcoin::Txid, Tx>,
        txs_by_wtxid: hashbrown::HashMap<bitcoin::Wtxid, Tx>,
        have_hashes: hashbrown::HashSet<[u8; 32]>,
        /// The resident pool: a subset of the bodies above. A body known
        /// only through `with_tx` models an orphan.
        resident: Vec<Arc<Tx>>,
        ancestor_packages: hashbrown::HashMap<Wtxid, Vec<Wtxid>>,
    }

    impl FakeTxInventory {
        fn empty() -> Self {
            Self {
                txs_by_txid: hashbrown::HashMap::new(),
                txs_by_wtxid: hashbrown::HashMap::new(),
                have_hashes: hashbrown::HashSet::new(),
                resident: Vec::new(),
                ancestor_packages: hashbrown::HashMap::new(),
            }
        }

        /// A transaction resident in the pool, so also known and servable.
        fn with_resident_tx(mut self, tx: Tx) -> Self {
            self.resident.push(Arc::new(tx.clone()));
            self.with_tx(tx)
        }

        fn with_ancestor_package(mut self, subject: Wtxid, package: Vec<Wtxid>) -> Self {
            self.ancestor_packages.insert(subject, package);
            self
        }

        fn with_tx(mut self, tx: Tx) -> Self {
            let txid = bitcoin::Txid::from_byte_array(*tx.txid().as_bytes());
            let wtxid = bitcoin::Wtxid::from_byte_array(*tx.wtxid().as_bytes());
            self.txs_by_txid.insert(txid, tx.clone());
            self.txs_by_wtxid.insert(wtxid, tx);
            self
        }

        fn with_have(mut self, hash: [u8; 32]) -> Self {
            self.have_hashes.insert(hash);
            self
        }
    }

    impl TxInventory for FakeTxInventory {
        fn have_tx(&self, hash: Hash256, _hash_is_wtxid: bool) -> bool {
            self.have_hashes.contains(hash.as_byte_array())
        }

        fn get_tx(&self, txid: Txid) -> Option<Tx> {
            let btid = bitcoin::Txid::from_byte_array(*txid.as_bytes());
            self.txs_by_txid.get(&btid).cloned()
        }

        fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
            let bwid = bitcoin::Wtxid::from_byte_array(*wtxid.as_bytes());
            self.txs_by_wtxid.get(&bwid).cloned()
        }

        fn resident_ancestor_package(&self, wtxid: Wtxid) -> Option<Vec<Wtxid>> {
            self.ancestor_packages.get(&wtxid).cloned()
        }

        fn resident_package(&self, wtxids: &[Wtxid]) -> Option<Vec<Arc<Tx>>> {
            wtxids
                .iter()
                .map(|wtxid| {
                    self.resident
                        .iter()
                        .find(|tx| tx.wtxid() == *wtxid)
                        .map(Arc::clone)
                })
                .collect()
        }
    }

    fn dummy_tx(byte: u8) -> Tx {
        use bitcoin_rs_primitives::{OutPoint, TxIn, TxOut, Witness};
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from(Hash256::from_le_bytes(&[byte; 32])),
                    vout: 0,
                },
                script_sig: vec![byte].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x6A].into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    #[test]
    fn getdata_completes_initial_broadcast_only_after_successful_send()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::serve_getdata;
        use bitcoin_rs_consensus::ValidationEngine;
        use bitcoin_rs_mempool::{
            AdmissionOrigin, Mempool, MempoolEntry, MempoolGateway, MempoolLimits,
        };
        use bitcoin_rs_primitives::Witness;
        use std::sync::Arc;
        for kind in 0..3 {
            let gateway = MempoolGateway::new(
                Arc::new(parking_lot::RwLock::new(Mempool::new(
                    MempoolLimits::default(),
                ))),
                None,
                ValidationEngine::Native,
                None,
            );
            let mut tx = dummy_tx(1);
            tx.inputs[0].witness = Witness::from_stack(vec![vec![0x51]]);
            let txid = tx.txid();
            let wtxid = tx.wtxid();
            gateway.insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(tx), 100, 1000, 1, 0, 0),
            )?;
            let sequence = gateway.read().sequence_number();
            let item = match kind {
                0 => Inventory::Transaction(bitcoin::Txid::from_byte_array(*txid.as_bytes())),
                1 => {
                    Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(*txid.as_bytes()))
                }
                _ => Inventory::WTx(bitcoin::Wtxid::from_byte_array(*wtxid.as_bytes())),
            };
            let mut not_found = Vec::new();
            assert!(
                serve_getdata(
                    None,
                    Some(&gateway),
                    None,
                    &[item],
                    &mut not_found,
                    &|| true,
                    &mut |_| Err(PeerError::Misbehavior("test sink full"))
                )
                .is_err()
            );
            assert_eq!(gateway.read().unbroadcast_transactions().count(), 1);
            let mut responses = Vec::new();
            serve_getdata(
                None,
                Some(&gateway),
                None,
                &[item],
                &mut not_found,
                &|| true,
                &mut |message| {
                    responses.push(message);
                    Ok(())
                },
            )?;
            assert!(matches!(responses.as_slice(), [Message::Tx(_)]));
            assert_eq!(gateway.read().unbroadcast_transactions().count(), 0);
            assert_eq!(gateway.read().sequence_number(), sequence);
        }
        Ok(())
    }

    #[test]
    fn announced_transactions_request_witness_without_changing_hashes() {
        let inventory = FakeTxInventory::empty();
        for witness in [false, true] {
            for filtered in [false, true] {
                let mut peer = ready_peer();
                let mut version = crate::handshake::version_message(
                    1,
                    0,
                    crate::peer_info::PeerRole::FullRelay,
                    bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
                );
                version.services = if witness {
                    bitcoin::p2p::ServiceFlags::WITNESS
                } else {
                    bitcoin::p2p::ServiceFlags::NETWORK
                };
                peer.remote_version = Some(version);
                let txid = bitcoin::Txid::from_byte_array([1; 32]);
                let wtxid = Inventory::WTx(bitcoin::Wtxid::from_byte_array([2; 32]));
                let block_hash = bitcoin::BlockHash::from_byte_array([3; 32]);
                let block = Inventory::Block(block_hash);
                let requested_tx = if witness {
                    Inventory::WitnessTransaction(txid)
                } else {
                    Inventory::Transaction(txid)
                };
                let view: Option<&dyn TxInventory> = filtered.then_some(&inventory);
                let (responses, announced) = dispatch_collect_announcements(
                    &mut peer,
                    &Message::Inv(vec![Inventory::Transaction(txid), wtxid, block]),
                    None,
                    view,
                    true,
                );
                assert_eq!(
                    responses,
                    vec![Message::GetData(vec![requested_tx, wtxid])],
                    "announced transactions keep their witness serialization and \
                     no block body is requested"
                );
                assert_eq!(announced, vec![announced_hash(block_hash)]);
            }
        }
    }

    #[test]
    fn inv_tx_vectors_not_requested_while_tx_relay_closed() {
        let txid = bitcoin::Txid::from_byte_array([1; 32]);
        let wtxid = Inventory::WTx(bitcoin::Wtxid::from_byte_array([2; 32]));
        let block_hash = bitcoin::BlockHash::from_byte_array([3; 32]);
        let block = Inventory::Block(block_hash);

        let mut peer = ready_peer();
        let (gated, announced) = dispatch_collect_announcements(
            &mut peer,
            &Message::Inv(vec![Inventory::Transaction(txid), wtxid, block]),
            None,
            None,
            false,
        );
        assert!(
            gated.is_empty(),
            "a closed relay gate must request no announced vector"
        );
        assert_eq!(
            announced,
            vec![announced_hash(block_hash)],
            "the block is announced to header sync either way"
        );

        let mut peer = ready_peer();
        let (open, announced) = dispatch_collect_announcements(
            &mut peer,
            &Message::Inv(vec![Inventory::Transaction(txid), wtxid, block]),
            None,
            None,
            true,
        );
        assert_eq!(
            open,
            vec![Message::GetData(vec![Inventory::Transaction(txid), wtxid])],
            "an open relay gate must request every announced tx"
        );
        assert_eq!(announced, vec![announced_hash(block_hash)]);
    }

    #[test]
    fn inv_wtx_vectors_not_requested_while_tx_relay_closed() {
        let inventory = FakeTxInventory::empty();
        let wtxid = Inventory::WTx(bitcoin::Wtxid::from_byte_array([2; 32]));
        let witness_txid = Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array([1; 32]));
        let block_hash = bitcoin::BlockHash::from_byte_array([3; 32]);
        let block = Inventory::Block(block_hash);

        let mut peer = ready_peer();
        let (responses, announced) = dispatch_collect_announcements(
            &mut peer,
            &Message::Inv(vec![witness_txid, wtxid, block]),
            None,
            Some(&inventory),
            false,
        );
        assert!(
            responses.is_empty(),
            "a closed relay gate must suppress txid and wtxid vectors the node does not hold"
        );
        assert_eq!(announced, vec![announced_hash(block_hash)]);
    }

    #[test]
    fn inv_block_uses_headers_not_body_getdata() {
        let block_hash = bitcoin::BlockHash::from_byte_array([3; 32]);
        for relay_open in [false, true] {
            for witness in [false, true] {
                let mut peer = ready_peer();
                let mut version = crate::handshake::version_message(
                    1,
                    0,
                    crate::peer_info::PeerRole::FullRelay,
                    bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
                );
                version.services = if witness {
                    bitcoin::p2p::ServiceFlags::WITNESS
                } else {
                    bitcoin::p2p::ServiceFlags::NETWORK
                };
                peer.remote_version = Some(version);
                let (responses, announced) = dispatch_collect_announcements(
                    &mut peer,
                    &Message::Inv(vec![
                        Inventory::Block(block_hash),
                        Inventory::WitnessBlock(block_hash),
                    ]),
                    None,
                    None,
                    relay_open,
                );
                assert!(
                    responses.is_empty(),
                    "block inventory must not emit a body getdata"
                );
                assert_eq!(
                    announced,
                    vec![announced_hash(block_hash); 2],
                    "both block flavors reach the announcement sink"
                );
            }
        }
    }

    #[test]
    fn gateway_inventory_filters_and_serves_txid_and_wtxid() {
        use std::sync::Arc;

        use bitcoin_rs_mempool::{
            AdmissionOrigin, Mempool, MempoolEntry, MempoolGateway, MempoolLimits,
        };
        use parking_lot::RwLock;

        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            None,
        );
        let mut tx = dummy_tx(0x42);
        tx.inputs[0].witness = Witness::from_stack(vec![vec![0x01]]);
        let txid_item =
            Inventory::Transaction(bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()));
        let witness_txid_item =
            Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()));
        let wtxid_item = Inventory::WTx(bitcoin::Wtxid::from_byte_array(*tx.wtxid().as_bytes()));
        assert_ne!(tx.txid().as_bytes(), tx.wtxid().as_bytes());
        assert!(
            gateway
                .insert_entry(
                    AdmissionOrigin::Rpc,
                    MempoolEntry::new(Arc::new(tx.clone()), 100, 10_000, 1, 0, 0),
                )
                .is_ok()
        );

        for (item, wtxid_relay) in [(txid_item, false), (wtxid_item, true)] {
            let mut peer = ready_peer();
            if wtxid_relay {
                peer.wtxid_relay.mark_peer_supported();
            }
            assert_eq!(
                dispatch_collect_full(&mut peer, &Message::Inv(vec![item]), None, Some(&gateway),),
                []
            );
        }

        let mut stripped = tx.clone();
        for input in &mut stripped.inputs {
            input.witness.clear();
        }
        let missing = Inventory::WTx(bitcoin::Wtxid::from_byte_array([0xFF; 32]));
        let mut peer = ready_peer();
        peer.wtxid_relay.mark_peer_supported();
        assert_eq!(
            dispatch_collect_full(
                &mut peer,
                &Message::GetData(vec![txid_item, witness_txid_item, wtxid_item, missing]),
                None,
                Some(&gateway),
            ),
            vec![
                Message::Tx(stripped),
                Message::Tx(tx.clone()),
                Message::Tx(tx.clone()),
                Message::NotFound(vec![missing])
            ],
        );
        assert_eq!(gateway.get_tx_by_wtxid(tx.wtxid()), Some(tx));
    }

    #[test]
    #[expect(clippy::too_many_lines)]
    fn one_sided_wtxid_negotiation_does_not_rerequest_pool_or_orphan_bodies() {
        use bitcoin_rs_primitives::Script;
        use std::sync::Arc;

        use bitcoin_rs_mempool::{
            AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, Mempool, MempoolEntry,
            MempoolGateway, MempoolLimits, PeerToken, SubmitOutcome,
        };
        use parking_lot::RwLock;

        struct MissingCoins;
        impl AdmissionChain for MissingCoins {
            fn snapshot(&self, _tx: &Tx) -> Option<ChainAdmissionSnapshot> {
                Some(ChainAdmissionSnapshot {
                    prevouts: Vec::new(),
                    height: 0,
                    locktime_cutoff: 0,
                    prevout_meta: hashbrown::HashMap::new(),
                    csv_active: false,
                    ..ChainAdmissionSnapshot::default()
                })
            }
        }

        for orphan in [false, true] {
            let gateway = MempoolGateway::new(
                Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
                None,
                ValidationEngine::Native,
                None,
            );
            let mut tx = dummy_tx(0x51);
            tx.inputs[0].script_sig.clear();
            tx.inputs[0].witness = Witness::from_stack(vec![vec![0x51]]);
            tx.outputs[0].script_pubkey = Script::from_bytes(vec![0x6a, 4, 1, 2, 3, 4]);
            let tx = Arc::new(tx);
            let txid = bitcoin::Txid::from_byte_array(*tx.txid().as_bytes());
            let wtxid = bitcoin::Wtxid::from_byte_array(*tx.wtxid().as_bytes());
            assert_ne!(txid.as_byte_array(), wtxid.as_byte_array());
            if orphan {
                let source = PeerToken {
                    endpoint: Some(bitcoin_rs_primitives::PeerEndpoint::Ip(
                        std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
                    )),
                    connection_id: 1,
                };
                assert!(matches!(
                    gateway.submit_transaction(
                        Arc::clone(&tx),
                        AdmissionOrigin::Peer(source),
                        None,
                        0,
                        &MissingCoins,
                    ),
                    Ok(SubmitOutcome::Held { .. })
                ));
                assert_eq!(gateway.orphan_count(), 1);
                assert_eq!(
                    gateway.get_tx_by_wtxid(tx.wtxid()).as_ref(),
                    Some(tx.as_ref())
                );
            } else {
                assert!(
                    gateway
                        .insert_entry(
                            AdmissionOrigin::Rpc,
                            MempoolEntry::new(Arc::clone(&tx), 100, 10_000, 1, 0, 0),
                        )
                        .is_ok()
                );
            }
            for (remote_requested, item) in [
                (false, Inventory::WTx(wtxid)),
                (true, Inventory::Transaction(txid)),
                (true, Inventory::WitnessTransaction(txid)),
            ] {
                let mut peer = ready_peer();
                if remote_requested {
                    peer.wtxid_relay.mark_peer_supported();
                }
                let held_suppresses = !orphan || matches!(item, Inventory::WTx(_));
                let responses = dispatch_collect_full(
                    &mut peer,
                    &Message::Inv(vec![item]),
                    None,
                    Some(&gateway),
                );
                if held_suppresses {
                    assert!(
                        responses.is_empty(),
                        "inventory type must select the held body's identity in either relay direction"
                    );
                } else {
                    assert_eq!(responses, vec![Message::GetData(vec![item])]);
                }

                let unknown = Inventory::WTx(bitcoin::Wtxid::from_byte_array([0xff; 32]));
                let expected = if held_suppresses {
                    vec![unknown]
                } else {
                    vec![item, unknown]
                };
                assert_eq!(
                    dispatch_collect_full(
                        &mut peer,
                        &Message::Inv(vec![item, unknown]),
                        None,
                        Some(&gateway),
                    ),
                    vec![Message::GetData(expected)]
                );
            }
        }
    }

    #[test]
    fn inv_filter_suppresses_held_tx() {
        let tx = dummy_tx(1);
        let txid = tx.txid();
        let inv_tx = Inventory::Transaction(bitcoin::Txid::from_byte_array(*txid.as_bytes()));
        let inventory = FakeTxInventory::empty().with_have(*txid.as_bytes());
        let mut peer = ready_peer();

        let responses = dispatch_collect_full(
            &mut peer,
            &Message::Inv(vec![inv_tx]),
            None,
            Some(&inventory),
        );

        assert!(
            responses.is_empty(),
            "inv for a held tx must produce no getdata"
        );
    }

    #[test]
    fn inv_filter_passes_unheld_tx() {
        let tx = dummy_tx(2);
        let txid = tx.txid();
        let inv_tx = Inventory::Transaction(bitcoin::Txid::from_byte_array(*txid.as_bytes()));
        let inventory = FakeTxInventory::empty();
        let mut peer = ready_peer();

        let responses = dispatch_collect_full(
            &mut peer,
            &Message::Inv(vec![inv_tx]),
            None,
            Some(&inventory),
        );

        assert_eq!(
            responses,
            vec![Message::GetData(vec![inv_tx])],
            "inv for an unheld tx must produce a getdata"
        );
    }

    #[test]
    fn getdata_serves_held_tx_and_notfound_for_missing() {
        let tx = dummy_tx(3);
        let txid = tx.txid();
        let inv_held = Inventory::Transaction(bitcoin::Txid::from_byte_array(*txid.as_bytes()));
        let inv_missing = Inventory::Transaction(bitcoin::Txid::from_byte_array([0xFF; 32]));
        let inventory = FakeTxInventory::empty().with_tx(tx);
        let mut peer = ready_peer();

        let responses = dispatch_collect_full(
            &mut peer,
            &Message::GetData(vec![inv_held, inv_missing]),
            None,
            Some(&inventory),
        );

        assert_eq!(responses.len(), 2, "expected tx + notfound");
        assert!(
            matches!(responses[0], Message::Tx(_)),
            "first response must be the held tx body"
        );
        assert_eq!(
            responses[1],
            Message::NotFound(vec![inv_missing]),
            "second response must be notfound for the missing tx"
        );
    }

    #[test]
    fn getdata_wtxid_serves_held_tx() {
        let tx = dummy_tx(4);
        let wtxid = tx.wtxid();
        let inv_wtx = Inventory::WTx(bitcoin::Wtxid::from_byte_array(*wtxid.as_bytes()));
        let inventory = FakeTxInventory::empty().with_tx(tx);
        let mut peer = ready_peer();

        let responses = dispatch_collect_full(
            &mut peer,
            &Message::GetData(vec![inv_wtx]),
            None,
            Some(&inventory),
        );

        assert_eq!(responses.len(), 1, "expected one tx response");
        assert!(
            matches!(responses[0], Message::Tx(_)),
            "wtxid-typed getdata for a held tx must serve its body"
        );
    }

    #[test]
    fn getdata_tx_without_inventory_reports_notfound() {
        let inv_tx = Inventory::Transaction(bitcoin::Txid::from_byte_array([1; 32]));
        let mut peer = ready_peer();

        let responses =
            dispatch_collect_full(&mut peer, &Message::GetData(vec![inv_tx]), None, None);

        assert_eq!(
            responses,
            vec![Message::NotFound(vec![inv_tx])],
            "getdata for tx without TxInventory must report notfound"
        );
    }

    #[test]
    fn inv_filter_bip339_wtxid() {
        let tx = dummy_tx(5);
        let wtxid = tx.wtxid();
        let inv_wtx = Inventory::WTx(bitcoin::Wtxid::from_byte_array(*wtxid.as_bytes()));
        let inventory = FakeTxInventory::empty().with_have(*wtxid.as_bytes());
        let mut peer = ready_peer();
        peer.wtxid_relay.mark_peer_supported();

        let responses = dispatch_collect_full(
            &mut peer,
            &Message::Inv(vec![inv_wtx]),
            None,
            Some(&inventory),
        );

        assert!(
            responses.is_empty(),
            "BIP339 wtxid inv for a held tx must produce no getdata"
        );
    }

    /// The hash dispatch routes to header sync for one announced block vector.
    fn announced_hash(block_hash: bitcoin::BlockHash) -> Hash256 {
        use bitcoin::hashes::Hash as _;
        Hash256::from_le_bytes(block_hash.as_byte_array())
    }

    fn dispatch_collect_full<S>(
        peer: &mut Peer<S>,
        message: &Message,
        chain: Option<&dyn ChainQuery>,
        tx_inventory: Option<&dyn TxInventory>,
    ) -> Vec<Message> {
        dispatch_collect_gated(peer, message, chain, tx_inventory, true)
    }

    /// Same helper with the transaction-relay gate under test control.
    fn dispatch_collect_gated<S>(
        peer: &mut Peer<S>,
        message: &Message,
        chain: Option<&dyn ChainQuery>,
        tx_inventory: Option<&dyn TxInventory>,
        relay_open: bool,
    ) -> Vec<Message> {
        dispatch_collect_announcements(peer, message, chain, tx_inventory, relay_open).0
    }

    /// Same helper, additionally returning the block-inventory hashes that
    /// dispatch routed to header sync instead of requesting their bodies.
    #[expect(clippy::expect_used)]
    fn dispatch_collect_announcements<S>(
        peer: &mut Peer<S>,
        message: &Message,
        chain: Option<&dyn ChainQuery>,
        tx_inventory: Option<&dyn TxInventory>,
        relay_open: bool,
    ) -> (Vec<Message>, Vec<Hash256>) {
        let collected = RefCell::new(Vec::new());
        let mut announced = Vec::new();
        dispatch_inbound_full(
            peer,
            message,
            chain,
            tx_inventory,
            &|| relay_open,
            &|| true,
            &mut |response| {
                collected.borrow_mut().push(response);
                Ok(())
            },
            &mut |hash| announced.push(hash),
            &mut |items| collected.borrow_mut().push(Message::GetData(items)),
        )
        .expect("dispatch must succeed");
        (collected.into_inner(), announced)
    }

    #[derive(Debug, PartialEq, Eq)]
    struct PeerSnapshot {
        state: PeerState,
        handshake: (bool, bool),
        capabilities: (bool, bool, bool),
    }

    fn peer_snapshot<S>(peer: &Peer<S>) -> PeerSnapshot {
        PeerSnapshot {
            state: peer.state,
            handshake: (peer.received_verack, peer.remote_version.is_some()),
            capabilities: (
                peer.capabilities.send_headers,
                peer.capabilities.addr_v2,
                peer.wtxid_relay.peer_supported(),
            ),
        }
    }

    fn ready_peer() -> Peer<Cursor<Vec<u8>>> {
        let mut peer = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);
        peer.state = PeerState::Ready;
        peer
    }

    #[test]
    fn deferred_filter_request_keeps_ping_responsive_and_bounds_pending_work()
    -> Result<(), PeerError> {
        let mut peer = ready_peer();
        let chain = FakeChain::default();
        let request = Message::GetCFilters(bitcoin::p2p::message_filter::GetCFilters {
            filter_type: 0,
            start_height: 0,
            stop_hash: bitcoin::BlockHash::all_zeros(),
        });
        let dispatch = |peer: &mut Peer<Cursor<Vec<u8>>>| {
            dispatch_inbound_full(
                peer,
                &request,
                Some(&chain),
                None,
                &|| true,
                &|| true,
                &mut |_| panic!("index not published"),
                &mut |_| {},
                &mut |_| {},
            )
        };
        dispatch(&mut peer)?;
        assert!(peer.pending_filter_request.is_some());
        assert_eq!(
            dispatch_inbound(&mut peer, &Message::Ping(42))?,
            vec![Message::Pong(42)]
        );
        assert!(matches!(dispatch(&mut peer), Err(PeerError::Io(_))));
        Ok(())
    }

    /// Serves the first filter of a request and hands back the rest, as a
    /// serving pass stopped by the outbound budget does.
    struct NarrowingChain;

    impl ChainQuery for NarrowingChain {
        fn stale_tip_announcement(
            &self,
            _tip: Hash256,
            _peer_tips: &[Hash256],
        ) -> Option<StaleTipHeaders> {
            None
        }
        fn serve_compact_filters(
            &self,
            request: &FilterRequest,
            _: &dyn Fn() -> bool,
            send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
        ) -> Result<FilterServing, PeerError> {
            let Message::GetCFilters(first) = &request.request else {
                return Ok(FilterServing::Done);
            };
            send(Message::Pong(u64::from(first.start_height)))?;
            Ok(FilterServing::Pending(FilterRequest {
                request: Message::GetCFilters(bitcoin::p2p::message_filter::GetCFilters {
                    filter_type: first.filter_type,
                    start_height: first.start_height + 1,
                    stop_hash: first.stop_hash,
                }),
                expected_end: Some(9),
            }))
        }

        fn headers_after(&self, _: &[BlockHash], _: BlockHash, _: usize) -> Vec<Header> {
            Vec::new()
        }

        fn serve_inventory_blocks(
            &self,
            _: &[Inventory],
            _: Option<u64>,
            _: &dyn Fn() -> bool,
            _: &mut dyn FnMut(Message) -> Result<(), PeerError>,
        ) -> Result<InventoryServing, PeerError> {
            Ok(InventoryServing::default())
        }

        fn block_transactions(
            &self,
            _: &BlockTransactionsRequest,
            _: Option<u64>,
            _: &dyn Fn() -> bool,
        ) -> Result<Option<Message>, PeerError> {
            Ok(None)
        }
    }

    /// The remainder a serving pass returns is the parked request's only
    /// cursor: the sent prefix is not replayed and the fixed end is kept.
    #[test]
    fn filter_remainder_is_the_parked_requests_only_cursor() -> Result<(), PeerError> {
        let mut peer = ready_peer();
        let request = Message::GetCFilters(bitcoin::p2p::message_filter::GetCFilters {
            filter_type: 0,
            start_height: 3,
            stop_hash: bitcoin::BlockHash::all_zeros(),
        });
        let mut sent = Vec::new();

        dispatch_inbound_full(
            &mut peer,
            &request,
            Some(&NarrowingChain),
            None,
            &|| true,
            &|| true,
            &mut |message| {
                sent.push(message);
                Ok(())
            },
            &mut |_| {},
            &mut |_| {},
        )?;

        assert_eq!(sent, vec![Message::Pong(3)]);
        let parked = peer
            .pending_filter_request
            .as_ref()
            .ok_or(PeerError::Protocol("the remainder was not parked"))?;
        assert_eq!(
            parked.pending,
            FilterRequest {
                request: Message::GetCFilters(bitcoin::p2p::message_filter::GetCFilters {
                    filter_type: 0,
                    start_height: 4,
                    stop_hash: bitcoin::BlockHash::all_zeros(),
                }),
                expected_end: Some(9),
            }
        );
        Ok(())
    }

    fn version_at(version: u32) -> Message {
        Message::Version(bitcoin::p2p::message_network::VersionMessage {
            version,
            ..crate::handshake::version_message(
                1,
                0,
                crate::peer_info::PeerRole::FullRelay,
                bitcoin::p2p::ServiceFlags::NETWORK,
            )
        })
    }

    /// The reply to a peer's `version` is the feature messages, then the
    /// features negotiated for its protocol version, then `verack`; a peer
    /// below BIP434's version never receives a `feature` frame.
    #[test]
    fn version_reply_orders_features_between_feature_messages_and_verack() -> Result<(), PeerError>
    {
        for version in [FEATURE_VERSION - 1, PROTOCOL_VERSION] {
            let mut peer = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::BITCOIN);
            peer.offer_stale_tip_relay(true);

            let responses = dispatch_inbound(&mut peer, &version_at(version))?;

            let mut expected = feature_messages().to_vec();
            expected.extend(
                negotiated_features(&peer, version)
                    .into_iter()
                    .map(Message::Feature),
            );
            expected.push(Message::Verack);
            assert_eq!(responses, expected);
            let announced = responses
                .iter()
                .any(|response| matches!(response, Message::Feature(_)));
            assert_eq!(announced, version >= FEATURE_VERSION);
        }
        Ok(())
    }

    /// A `feature` from the peer is absorbed silently between its `version`
    /// and `verack`, and is a protocol violation that changes nothing once the
    /// peer is ready.
    #[test]
    fn remote_feature_is_accepted_before_verack_and_rejected_after() -> Result<(), PeerError> {
        let feature = Message::Feature(FeatureAnnouncement::new(
            FeatureId::from_raw_unchecked(b"BIP332".to_vec()),
            vec![1],
        ));
        let mut peer = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::BITCOIN);
        dispatch_inbound(&mut peer, &version_at(PROTOCOL_VERSION))?;

        assert_eq!(dispatch_inbound(&mut peer, &feature)?, []);
        assert_eq!(peer.remote_feature(b"BIP332"), Some([1].as_slice()));

        dispatch_inbound(&mut peer, &Message::Verack)?;
        assert_eq!(peer.state, PeerState::Ready);
        let before = peer_snapshot(&peer);
        assert!(matches!(
            dispatch_inbound(&mut peer, &feature),
            Err(PeerError::Misbehavior(_))
        ));
        assert_eq!(peer_snapshot(&peer), before);
        assert_eq!(peer.remote_feature(b"BIP332"), Some([1].as_slice()));
        Ok(())
    }

    /// An offered `sendpackages` follows the feature messages and precedes
    /// `verack`, once; a repeated `version` does not repeat it.
    #[test]
    fn version_reply_sends_the_offered_sendpackages_once_before_verack() -> Result<(), PeerError> {
        let both = PKG_RELAY_PKGTXNS | PKG_RELAY_ANC;
        let mut peer = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::BITCOIN);
        peer.offer_package_relay(both | (1 << 40));

        let first = dispatch_inbound(&mut peer, &version_at(PROTOCOL_VERSION))?;

        let mut expected = feature_messages().to_vec();
        expected.extend(
            negotiated_features(&peer, PROTOCOL_VERSION)
                .into_iter()
                .map(Message::Feature),
        );
        expected.push(Message::SendPackages(SendPackages { versions: both }));
        expected.push(Message::Verack);
        assert_eq!(first, expected);

        let second = dispatch_inbound(&mut peer, &version_at(PROTOCOL_VERSION))?;
        assert!(
            !second
                .iter()
                .any(|response| matches!(response, Message::SendPackages(_)))
        );
        Ok(())
    }

    const BOTH_PACKAGE_BITS: u64 = PKG_RELAY_PKGTXNS | PKG_RELAY_ANC;

    /// A ready peer that negotiated package relay for `bits` on both sides.
    fn package_peer(bits: u64) -> Result<Peer<Cursor<Vec<u8>>>, PeerError> {
        let mut peer = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);
        peer.offer_package_relay(bits);
        dispatch_inbound(&mut peer, &version_at(PROTOCOL_VERSION))?;
        dispatch_inbound(&mut peer, &Message::WtxidRelay)?;
        dispatch_inbound(
            &mut peer,
            &Message::SendPackages(SendPackages { versions: bits }),
        )?;
        dispatch_inbound(&mut peer, &Message::Verack)?;
        assert_eq!(peer.package_relay_versions(), bits);
        Ok(peer)
    }

    fn package_item(inv_type: u32, wtxid: Wtxid) -> Inventory {
        Inventory::Unknown {
            inv_type,
            hash: *wtxid.as_bytes(),
        }
    }

    /// Dispatches one message against `inventory` with every gate open.
    fn dispatch_over<S>(
        peer: &mut Peer<S>,
        message: &Message,
        inventory: &dyn TxInventory,
    ) -> Result<Vec<Message>, PeerError> {
        let collected = RefCell::new(Vec::new());
        dispatch_inbound_full(
            peer,
            message,
            None,
            Some(inventory),
            &|| true,
            &|| true,
            &mut |response| {
                collected.borrow_mut().push(response);
                Ok(())
            },
            &mut |_| {},
            &mut |_| {},
        )?;
        Ok(collected.into_inner())
    }

    #[test]
    fn package_messages_without_negotiation_are_protocol_violations() {
        let wtxid = dummy_tx(1).wtxid();
        for message in [
            Message::AncPkgInfo(AncPkgInfo {
                wtxids: vec![wtxid],
            }),
            Message::GetPkgTxns(GetPkgTxns {
                wtxids: vec![wtxid],
            }),
            Message::PkgTxnsPayload(bytes::Bytes::new()),
            Message::GetData(vec![package_item(MSG_ANCPKGINFO, wtxid)]),
            Message::GetData(vec![package_item(MSG_PKGTXNS, wtxid)]),
            Message::Inv(vec![package_item(MSG_ANCPKGINFO, wtxid)]),
            Message::Inv(vec![package_item(MSG_PKGTXNS, wtxid)]),
        ] {
            let mut peer = ready_peer();
            let before = peer_snapshot(&peer);

            assert!(
                matches!(
                    dispatch_inbound(&mut peer, &message),
                    Err(PeerError::Misbehavior(_))
                ),
                "{message:?}"
            );
            assert_eq!(peer_snapshot(&peer), before);
            assert!(peer.take_package_request().is_none());
        }
    }

    #[test]
    fn a_negotiated_bit_admits_only_its_own_messages() -> Result<(), PeerError> {
        let wtxid = dummy_tx(1).wtxid();
        let ancestor_only = [
            Message::GetPkgTxns(GetPkgTxns {
                wtxids: vec![wtxid],
            }),
            Message::PkgTxnsPayload(bytes::Bytes::new()),
        ];
        for message in ancestor_only {
            let mut peer = package_peer(PKG_RELAY_ANC)?;
            assert!(matches!(
                dispatch_inbound(&mut peer, &message),
                Err(PeerError::Misbehavior(_))
            ));
        }
        let batch_only = [
            Message::AncPkgInfo(AncPkgInfo {
                wtxids: vec![wtxid],
            }),
            Message::GetData(vec![package_item(MSG_ANCPKGINFO, wtxid)]),
        ];
        for message in batch_only {
            let mut peer = package_peer(PKG_RELAY_PKGTXNS)?;
            assert!(matches!(
                dispatch_inbound(&mut peer, &message),
                Err(PeerError::Misbehavior(_))
            ));
        }
        // `pkgtxns` bytes are admitted by the node's ingress, not dispatch.
        let mut peer = package_peer(PKG_RELAY_PKGTXNS)?;
        assert_eq!(
            dispatch_inbound(&mut peer, &Message::PkgTxnsPayload(bytes::Bytes::new()))?,
            []
        );
        Ok(())
    }

    #[test]
    fn package_only_inventory_types_are_never_valid_in_inv_or_getdata6() -> Result<(), PeerError> {
        let wtxid = dummy_tx(1).wtxid();
        for message in [
            Message::Inv(vec![package_item(MSG_ANCPKGINFO, wtxid)]),
            Message::Inv(vec![package_item(MSG_PKGTXNS, wtxid)]),
            Message::GetData(vec![package_item(MSG_PKGTXNS, wtxid)]),
        ] {
            let mut peer = package_peer(BOTH_PACKAGE_BITS)?;
            assert!(
                matches!(
                    dispatch_inbound(&mut peer, &message),
                    Err(PeerError::Misbehavior(_))
                ),
                "{message:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn getdata_ancpkginfo_serves_the_resident_package_and_reports_the_rest() -> Result<(), PeerError>
    {
        let parent = dummy_tx(1);
        let child = dummy_tx(2);
        let orphan = dummy_tx(3);
        let unknown = dummy_tx(4).wtxid();
        let misdirected = dummy_tx(5);
        let inventory = FakeTxInventory::empty()
            .with_resident_tx(parent.clone())
            .with_resident_tx(child.clone())
            .with_resident_tx(misdirected.clone())
            .with_tx(orphan.clone())
            .with_ancestor_package(child.wtxid(), vec![parent.wtxid(), child.wtxid()])
            // A package that does not end at its subject is never served.
            .with_ancestor_package(misdirected.wtxid(), vec![misdirected.wtxid(), parent.wtxid()]);
        let mut peer = package_peer(BOTH_PACKAGE_BITS)?;

        let responses = dispatch_over(
            &mut peer,
            &Message::GetData(vec![
                package_item(MSG_ANCPKGINFO, child.wtxid()),
                package_item(MSG_ANCPKGINFO, orphan.wtxid()),
                package_item(MSG_ANCPKGINFO, unknown),
                package_item(MSG_ANCPKGINFO, misdirected.wtxid()),
            ]),
            &inventory,
        )?;

        assert_eq!(
            responses,
            vec![
                Message::AncPkgInfo(AncPkgInfo {
                    wtxids: vec![parent.wtxid(), child.wtxid()],
                }),
                Message::NotFound(vec![
                    package_item(MSG_ANCPKGINFO, orphan.wtxid()),
                    package_item(MSG_ANCPKGINFO, unknown),
                    package_item(MSG_ANCPKGINFO, misdirected.wtxid()),
                ]),
            ]
        );
        Ok(())
    }

    #[test]
    fn getdata_ancpkginfo_without_an_inventory_is_reported_missing() -> Result<(), PeerError> {
        let subject = dummy_tx(1).wtxid();
        let mut peer = package_peer(BOTH_PACKAGE_BITS)?;

        let responses = dispatch_inbound(
            &mut peer,
            &Message::GetData(vec![package_item(MSG_ANCPKGINFO, subject)]),
        )?;

        assert_eq!(
            responses,
            vec![Message::NotFound(vec![package_item(
                MSG_ANCPKGINFO,
                subject
            )])]
        );
        Ok(())
    }

    #[test]
    fn getpkgtxns_is_all_resident_in_request_order_or_one_notfound() -> Result<(), PeerError> {
        let parent = dummy_tx(1);
        let child = dummy_tx(2);
        let orphan = dummy_tx(3);
        let unknown = dummy_tx(4).wtxid();
        let inventory = FakeTxInventory::empty()
            .with_resident_tx(parent.clone())
            .with_resident_tx(child.clone())
            .with_tx(orphan.clone());
        let mut peer = package_peer(BOTH_PACKAGE_BITS)?;

        let served = dispatch_over(
            &mut peer,
            &Message::GetPkgTxns(GetPkgTxns {
                wtxids: vec![child.wtxid(), parent.wtxid(), child.wtxid()],
            }),
            &inventory,
        )?;
        assert_eq!(
            served,
            vec![Message::PkgTxns(PkgTxns {
                txs: vec![child.clone(), parent.clone(), child.clone()],
            })]
        );

        // One member that is only an orphan, or absent altogether, makes the
        // whole request unavailable: one notfound, nothing else.
        for unavailable in [orphan.wtxid(), unknown] {
            let wtxids = vec![parent.wtxid(), unavailable, child.wtxid()];
            let responses = dispatch_over(
                &mut peer,
                &Message::GetPkgTxns(GetPkgTxns {
                    wtxids: wtxids.clone(),
                }),
                &inventory,
            )?;
            assert_eq!(
                responses,
                vec![Message::NotFound(vec![Inventory::Unknown {
                    inv_type: MSG_PKGTXNS,
                    hash: combined_package_hash(&wtxids),
                }])]
            );
        }
        Ok(())
    }

    #[test]
    fn getpkgtxns_without_an_inventory_is_one_notfound() -> Result<(), PeerError> {
        let wtxids = vec![dummy_tx(1).wtxid(), dummy_tx(2).wtxid()];
        let mut peer = package_peer(BOTH_PACKAGE_BITS)?;

        let responses = dispatch_inbound(
            &mut peer,
            &Message::GetPkgTxns(GetPkgTxns {
                wtxids: wtxids.clone(),
            }),
        )?;

        assert_eq!(
            responses,
            vec![Message::NotFound(vec![Inventory::Unknown {
                inv_type: MSG_PKGTXNS,
                hash: combined_package_hash(&wtxids),
            }])]
        );
        Ok(())
    }

    #[test]
    fn getpkgtxns_that_cannot_fit_one_frame_is_unavailable() -> Result<(), PeerError> {
        let bulky: Vec<Tx> = (1..=3_u8)
            .map(|byte| {
                let mut tx = dummy_tx(byte);
                tx.inputs[0].script_sig = vec![byte; 1_500_000].into();
                tx
            })
            .collect();
        let wtxids: Vec<Wtxid> = bulky.iter().map(Tx::wtxid).collect();
        let inventory = bulky
            .into_iter()
            .fold(FakeTxInventory::empty(), FakeTxInventory::with_resident_tx);
        let mut peer = package_peer(BOTH_PACKAGE_BITS)?;

        let responses = dispatch_over(
            &mut peer,
            &Message::GetPkgTxns(GetPkgTxns {
                wtxids: wtxids.clone(),
            }),
            &inventory,
        )?;

        assert_eq!(
            responses,
            vec![Message::NotFound(vec![Inventory::Unknown {
                inv_type: MSG_PKGTXNS,
                hash: combined_package_hash(&wtxids),
            }])]
        );
        Ok(())
    }

    #[test]
    fn getpkgtxns_is_left_unanswered_while_the_production_gate_is_closed() -> Result<(), PeerError>
    {
        let tx = dummy_tx(1);
        let inventory = FakeTxInventory::empty().with_resident_tx(tx.clone());
        let mut peer = package_peer(BOTH_PACKAGE_BITS)?;
        let loaded = AtomicUsize::new(0);
        let counting = CountingResident {
            inner: &inventory,
            loaded: &loaded,
        };

        dispatch_inbound_full(
            &mut peer,
            &Message::GetPkgTxns(GetPkgTxns {
                wtxids: vec![tx.wtxid()],
            }),
            None,
            Some(&counting),
            &|| true,
            &|| false,
            &mut |response| panic!("a closed gate queued {response:?}"),
            &mut |_| {},
            &mut |_| {},
        )?;

        assert_eq!(loaded.load(Ordering::SeqCst), 0, "no body was loaded");
        Ok(())
    }

    /// Counts resident package loads, forwarding to `inner`.
    struct CountingResident<'a> {
        inner: &'a FakeTxInventory,
        loaded: &'a AtomicUsize,
    }

    impl TxInventory for CountingResident<'_> {
        fn have_tx(&self, hash: Hash256, hash_is_wtxid: bool) -> bool {
            self.inner.have_tx(hash, hash_is_wtxid)
        }

        fn get_tx(&self, txid: Txid) -> Option<Tx> {
            self.inner.get_tx(txid)
        }

        fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
            self.inner.get_tx_by_wtxid(wtxid)
        }

        fn resident_ancestor_package(&self, wtxid: Wtxid) -> Option<Vec<Wtxid>> {
            self.inner.resident_ancestor_package(wtxid)
        }

        fn resident_package(&self, wtxids: &[Wtxid]) -> Option<Vec<Arc<Tx>>> {
            self.loaded.fetch_add(1, Ordering::SeqCst);
            self.inner.resident_package(wtxids)
        }
    }

    #[test]
    fn ancpkginfo_hands_the_missing_members_to_the_request_owner_once() -> Result<(), PeerError> {
        let parent = dummy_tx(1);
        let child = dummy_tx(2);
        let message = Message::AncPkgInfo(AncPkgInfo {
            wtxids: vec![parent.wtxid(), child.wtxid()],
        });
        let mut peer = package_peer(BOTH_PACKAGE_BITS)?;

        // The child is a held orphan and the parent a recent reject: both are
        // known to the node, neither is resident, so both are requested.
        let refused = FakeTxInventory::empty()
            .with_tx(child.clone())
            .with_have(*parent.wtxid().as_bytes())
            .with_have(*child.wtxid().as_bytes());
        assert_eq!(dispatch_over(&mut peer, &message, &refused)?, []);
        assert_eq!(
            peer.take_package_request(),
            Some(PackageRequest {
                subject: child.wtxid(),
                wtxids: vec![parent.wtxid(), child.wtxid()],
            })
        );
        assert_eq!(peer.take_package_request(), None, "one handoff per message");

        // A resident parent is not asked for again.
        let resident_parent = FakeTxInventory::empty().with_resident_tx(parent);
        dispatch_over(&mut peer, &message, &resident_parent)?;
        assert_eq!(
            peer.take_package_request(),
            Some(PackageRequest {
                subject: child.wtxid(),
                wtxids: vec![child.wtxid()],
            })
        );
        Ok(())
    }

    #[test]
    fn ancpkginfo_requests_nothing_when_nothing_is_missing_or_the_package_is_too_large()
    -> Result<(), PeerError> {
        let max = bitcoin_rs_mempool::standardness::MAX_PACKAGE_COUNT;
        let held: Vec<Tx> = (1..=3_u8).map(dummy_tx).collect();
        let everything = held
            .iter()
            .cloned()
            .fold(FakeTxInventory::empty(), FakeTxInventory::with_resident_tx);
        let mut peer = package_peer(BOTH_PACKAGE_BITS)?;
        dispatch_over(
            &mut peer,
            &Message::AncPkgInfo(AncPkgInfo {
                wtxids: held.iter().map(Tx::wtxid).collect(),
            }),
            &everything,
        )?;
        assert_eq!(
            peer.take_package_request(),
            None,
            "subject already resident"
        );

        let too_many: Vec<Wtxid> = (0..=max)
            .map(|index| {
                let byte = u8::try_from(index).unwrap_or(u8::MAX);
                Wtxid::from(Hash256::from_le_bytes(&[byte.wrapping_add(1); 32]))
            })
            .collect();
        assert_eq!(too_many.len(), max + 1);
        dispatch_over(
            &mut peer,
            &Message::AncPkgInfo(AncPkgInfo { wtxids: too_many }),
            &FakeTxInventory::empty(),
        )?;
        assert_eq!(peer.take_package_request(), None, "above admission bound");

        let exact: Vec<Wtxid> = (1..=u8::try_from(max).unwrap_or(u8::MAX))
            .map(|byte| Wtxid::from(Hash256::from_le_bytes(&[byte; 32])))
            .collect();
        dispatch_over(
            &mut peer,
            &Message::AncPkgInfo(AncPkgInfo {
                wtxids: exact.clone(),
            }),
            &FakeTxInventory::empty(),
        )?;
        assert_eq!(
            peer.take_package_request().map(|request| request.wtxids),
            Some(exact),
            "a package at the bound is requested whole"
        );
        Ok(())
    }

    #[test]
    fn ancpkginfo_is_not_requested_while_transaction_relay_is_closed() -> Result<(), PeerError> {
        let wtxid = dummy_tx(1).wtxid();
        let mut peer = package_peer(BOTH_PACKAGE_BITS)?;

        let responses = dispatch_collect_gated(
            &mut peer,
            &Message::AncPkgInfo(AncPkgInfo {
                wtxids: vec![wtxid],
            }),
            None,
            None,
            false,
        );

        assert_eq!(responses, []);
        assert_eq!(peer.take_package_request(), None);
        Ok(())
    }

    fn test_header(prev_blockhash: BlockHash, nonce: u32) -> Header {
        Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::from_le_bytes(&[0; 32]),
            time: nonce,
            bits: CompactTarget::from_consensus(bitcoin_rs_chain::regtest_fixture::REGTEST_BITS),
            nonce,
        }
    }
}
