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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedTip {
    pub height: u32,
    pub hash: BlockHash,
    pub prev_hash: BlockHash,
}

pub(crate) use crate::wire::MAX_LOCATOR_HASHES;

#[derive(Debug, Default)]
pub struct InventoryServing {
    pub not_found: Vec<Inventory>,
    pub halted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterRequest {
    pub request: Message,
    pub expected_end: Option<u32>,
}

impl FilterRequest {
    #[must_use]
    pub const fn new(request: Message) -> Self {
        Self {
            request,
            expected_end: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterServing {
    Done,
    Pending(FilterRequest),
}

/// Header response for a BIP332 stale tip announcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StaleTipHeaders {
    Headers(crate::staletip::StaleTipAnnouncement),
    TooMany,
}

pub trait ChainQuery: Send + Sync {
    fn compact_filters_ready(&self) -> bool {
        false
    }

    /// Serves a bounded BIP157 request from persisted filters only.
    fn serve_compact_filters(
        &self,
        _request: &FilterRequest,
        _headroom: &dyn Fn() -> bool,
        _send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<FilterServing, PeerError> {
        Ok(FilterServing::Done)
    }
    fn headers_after(
        &self,
        locator_hashes: &[BlockHash],
        stop_hash: BlockHash,
        limit: usize,
    ) -> Vec<Header>;

    /// [`Message::CmpctBlock`] built at the given BIP152 version — `None`
    /// `MSG_BLOCK` strips witness data from the validated body (BIP144).
    fn serve_inventory_blocks(
        &self,
        items: &[Inventory],
        compact_version: Option<u64>,
        headroom: &dyn Fn() -> bool,
        serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<InventoryServing, PeerError>;

    /// block. `compact_version` is the peer's servable BIP152 profile.
    /// BIP152 (Core scores misbehavior).
    fn block_transactions(
        &self,
        request: &BlockTransactionsRequest,
        compact_version: Option<u64>,
        headroom: &dyn Fn() -> bool,
    ) -> Result<Option<Message>, PeerError>;

    fn best_block_time(&self) -> Option<u32> {
        None
    }

    fn active_height(&self, _hash: BlockHash) -> Option<u32> {
        None
    }

    /// at the given BIP152 version.
    fn compact_block_for(
        &self,
        _height: u32,
        _hash: BlockHash,
        _compact_version: Option<u64>,
    ) -> Option<Message> {
        None
    }

    fn committed_tip(&self) -> Option<CommittedTip> {
        None
    }

    /// Returns the BIP332 stale-tip headers for `tip` given the peer's
    fn stale_tip_announcement(
        &self,
        tip: Hash256,
        peer_tips: &[Hash256],
    ) -> Option<StaleTipHeaders>;
}

pub trait TxInventory: Send + Sync {
    fn have_tx(&self, hash: Hash256, hash_is_wtxid: bool) -> bool;

    fn get_tx(&self, txid: Txid) -> Option<Tx>;

    /// node does not have it. Used to answer BIP339 `getdata` (`WTx`) items.
    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx>;

    fn transaction_sent(&self, _wtxid: Wtxid) {}

    /// The BIP331 ancestor package of `wtxid` the node can serve: its
    fn resident_ancestor_package(&self, wtxid: Wtxid) -> Option<Vec<Wtxid>>;

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
fn ensure_package_relay<S>(peer: &Peer<S>, bit: u64, error: &'static str) -> Result<(), PeerError> {
    if peer.package_relay_versions() & bit == 0 {
        return Err(PeerError::Misbehavior(error));
    }
    Ok(())
}

/// Rejects the `getdata` item types BIP331 forbids: `MSG_PKGTXNS` is a
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

/// requested by its inventory type (P2P-01 / BIP144). BIP339 `WTx` items are
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
    if !headroom() {
        return Ok(Vec::new());
    }
    send(Message::NotFound(std::mem::take(not_found)))?;
    Ok(Vec::new())
}

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

/// `compact_version` is the peer's servable BIP152 profile (`None` leaves
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
mod tests;
