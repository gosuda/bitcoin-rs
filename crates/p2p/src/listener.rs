use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::Magic;
use bitcoin::p2p::ServiceFlags;
use bitcoin_rs_primitives::{Network, unix_time_secs};
use crossbeam_channel::{SendTimeoutError, Sender};
use thiserror::Error;

use crate::handshake::run_inbound_handshake;
use crate::peer::Peer;
use crate::socket::{HANDSHAKE_TIMEOUT, configure_peer_stream};

const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Maximum backoff for transient accept errors (ECONNABORTED, EMFILE, …).
/// Bounded so the listener recovers quickly once the pressure clears.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(10);

/// How often an otherwise quiet connection is probed with one `ping`: Core's
/// `PING_INTERVAL` is 2 * 60 seconds (`net_processing.cpp:125`).
const PING_INTERVAL: Duration = Duration::from_mins(2);

/// How long send or receive silence may last before the connection ends:
/// Core's `TIMEOUT_INTERVAL` is 20 * 60 seconds (`net.h:59`), enforced by its
/// `InactivityCheck` (`net.cpp:2043-2090`).
const TIMEOUT_INTERVAL: Duration = Duration::from_mins(20);

/// Blocks of tip staleness (in target-spacing units) within which Core will
/// still connect to a `NODE_NETWORK_LIMITED` peer:
/// `NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS` (`net_processing.cpp:161`).
const NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS: u64 = 144;

/// Proof-of-work target spacing used to express the local tip age in blocks
/// (Core `nPowTargetSpacing`, 600 seconds on every bitcoin-rs network;
/// `bitcoin_rs_primitives::Network::target_spacing_seconds`).
const POW_TARGET_SPACING_SECS: u64 = 600;

type ChainQueryHandle = Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>;

type TxInventoryHandle = Option<Arc<dyn crate::dispatch::TxInventory + 'static>>;

type CompactHintsHandle = Option<Arc<dyn crate::compact_blocks::CompactBlockHints + 'static>>;

type SyncWakeHandle = Option<Sender<()>>;

type PeerReadyHandle = Option<Arc<dyn Fn(crate::PeerSource) + Send + Sync>>;

/// Optional node-owned handles passed to [`crate::P2pService::start`].
#[derive(Clone, Default)]
pub struct ListenerExtras {
    /// Mempool / orphan / recent-rejects view for the `inv` filter and
    /// transaction `getdata` serving.
    pub tx_inventory: TxInventoryHandle,
    /// Compact-block short-ID hints (the shared mempool gateway) for BIP152
    /// reconstruction.
    pub compact_hints: CompactHintsHandle,
    /// Bounded ingress for decoded `tx` bodies from Ready peers.
    pub inbound_tx: Option<Sender<crate::InboundTx>>,
    /// Chain-owned initial-block-download latch paired with the node's
    /// configured consensus network. `None` means transaction relay is open
    /// (callers without a chain, and tests). While `Some` and active,
    /// tx-typed `inv` vectors are not requested and `tx` bodies are dropped
    /// before ingress (Core 31.1 `net_processing.cpp:4401`, `:4716`). The
    /// network travels with the latch because the wire magic is not an
    /// identity: a `--p2p-magic` override can carry another network's bytes.
    pub ibd: Option<(Arc<bitcoin_rs_chain::InitialBlockDownload>, Network)>,
    /// Block-download orchestrator, used to route block inventory announcements
    /// and to ask whether an inbound body was requested.
    /// When `None`, announcements are ignored and inbound bodies are treated
    /// as unsolicited.
    pub block_sync: Option<Arc<crate::sync::BlockSync>>,
    /// Block announcer for outbound block announcements and peer capability tracking.
    pub block_announcer: Option<Arc<crate::block_announce::BlockAnnouncer>>,
}

/// Share the wiring for one P2P start epoch.
///
/// The listener, every outbound dial, and every connection thread they
/// spawn read the same stores, sinks, and start token through clones of
/// this value.
///
/// PRE: Construct the required handles before any worker starts.
/// POST: Each clone refers to the same stores and start token.
/// INVARIANT: Count socket bytes once. Read the IBD decision lazily.
#[derive(Clone)]
pub struct ConnectionShared {
    /// Authoritative live-peer table shared with the node.
    pub peer_table: Arc<crate::PeerTable>,
    /// Manual subnet bans shared with the RPC `setban` handler.
    pub banned: crate::BannedReader,
    /// Shared P2P-owned auxiliary address book.
    pub(crate) address_book: Option<Arc<crate::addrman::AddressBook>>,
    /// A short-lived automatic handshake probe; never published as a work peer.
    pub(crate) feeler: bool,
    /// Network kill-switch behind `setnetworkactive`.
    pub activity: Arc<crate::NetworkActivity>,
    /// Start-scoped cancellation token. Tests that never cancel pass a
    /// token that stays `false`.
    pub session_cancel: bitcoin_rs_chain::LatchReader,
    /// Callback run after a connection publishes its ready metadata.
    pub peer_ready: PeerReadyHandle,
    /// Network magic of every framed message.
    pub magic: Magic,
    /// Sink for `headers` messages and body-carried headers.
    pub headers_tx: Sender<crate::InboundHeaders>,
    /// Sink for full block bodies.
    pub blocks_tx: Sender<crate::InboundBlock>,
    /// Read-only active-chain view for `getheaders` and `getdata` serving.
    pub chain_query: ChainQueryHandle,
    /// Wakes block sync after a header or block reaches its sink.
    pub wake_tx: SyncWakeHandle,
    /// Mempool / orphan / recent-rejects view for the `inv` filter and
    /// transaction `getdata` serving.
    pub tx_inventory: TxInventoryHandle,
    /// Compact-block short-ID hints for BIP152 reconstruction.
    pub compact_hints: CompactHintsHandle,
    /// Bounded ingress for decoded `tx` bodies from Ready peers.
    pub inbound_tx: Option<Sender<crate::InboundTx>>,
    /// Chain-owned initial-block-download latch paired with the node's
    /// configured consensus network. `None` means transaction relay is open.
    /// The network travels with the latch because the wire magic is not an
    /// identity: a `--p2p-magic` override can carry another network's bytes.
    pub ibd: Option<(Arc<bitcoin_rs_chain::InitialBlockDownload>, Network)>,
    /// Block-download orchestrator for this start epoch.
    pub block_sync: Option<Arc<crate::sync::BlockSync>>,
    /// Block announcer for outbound block announcements and peer capability tracking.
    pub block_announcer: Option<Arc<crate::block_announce::BlockAnnouncer>>,
    /// Inbound connection capacity: the automatic-connection maximum minus
    /// the outbound slot counts. The listener refuses inbound admission at
    /// this count and never evicts (Core `m_max_inbound`, `net.h:1127`,
    /// applied at `net.cpp:1838-1845` with eviction cut to refusal).
    pub max_inbound: usize,
    /// The services this node advertises in every `version`, inbound or
    /// outbound: `WITNESS | NETWORK` normally, `WITNESS | NETWORK_LIMITED`
    /// when pruned (Core `init.cpp:2022-2026`).
    pub local_services: ServiceFlags,
}

impl ConnectionShared {
    /// Construct the complete wiring for one start epoch.
    ///
    /// PRE: The stores belong to the same P2P start epoch. `extras` carries
    /// the node-owned transaction handles; pass [`ListenerExtras::default`]
    /// when they are absent.
    /// POST: Every field is set from the arguments; a caller cannot obtain
    /// a half-wired value.
    /// INVARIANT: `None` for `ibd` means transaction relay is open.
    #[expect(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        peer_table: Arc<crate::PeerTable>,
        banned: impl Into<crate::BannedReader>,
        activity: Arc<crate::NetworkActivity>,
        session_cancel: impl Into<bitcoin_rs_chain::LatchReader>,
        peer_ready: PeerReadyHandle,
        magic: Magic,
        headers_tx: Sender<crate::InboundHeaders>,
        blocks_tx: Sender<crate::InboundBlock>,
        chain_query: ChainQueryHandle,
        wake_tx: SyncWakeHandle,
        extras: ListenerExtras,
    ) -> Self {
        Self {
            peer_table,
            banned: banned.into(),
            address_book: None,
            feeler: false,
            activity,
            session_cancel: session_cancel.into(),
            peer_ready,
            magic,
            headers_tx,
            blocks_tx,
            chain_query,
            wake_tx,
            tx_inventory: extras.tx_inventory,
            compact_hints: extras.compact_hints,
            inbound_tx: extras.inbound_tx,
            ibd: extras.ibd,
            block_sync: extras.block_sync,
            block_announcer: extras.block_announcer,
            max_inbound: crate::service::P2pServiceConfig::default().max_inbound(),
            local_services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        }
    }

    fn check_destination(&self, addr: SocketAddr, manual: bool) -> Result<(), crate::PeerError> {
        if self.banned.is_banned(addr.ip(), SystemTime::now()) {
            return Err(crate::PeerError::BannedDestination(addr.ip()));
        }
        if !manual && self.banned.is_discouraged(addr.ip()) {
            return Err(crate::PeerError::DiscouragedDestination(addr.ip()));
        }
        Ok(())
    }

    fn note_misbehavior(
        &self,
        addr: SocketAddr,
        lease: &crate::PeerLease,
        error: &crate::PeerError,
    ) {
        if !error.is_misbehavior() || self.is_session_cancelled() || !self.activity.is_active() {
            return;
        }
        let protected = lease.is_protected();
        let local = crate::discouragement::is_local(addr.ip());
        let current = self.peer_table.with_current(lease.source(addr), || {
            if !protected && !local {
                self.banned.discourage(addr.ip());
            }
        });
        if current {
            if lease.ignores_protocol_error(error) {
                tracing::debug!(peer_addr = %addr, node_id = lease.node_id(), %error, protected, local,
                    discouraged = !protected && !local, "peer protocol violation");
            } else {
                tracing::warn!(peer_addr = %addr, node_id = lease.node_id(), %error, protected, local,
                    discouraged = !protected && !local, "peer protocol violation");
            }
        }
    }

    /// Routes one block-typed inventory hash into header sync.
    ///
    /// PRE: `source` identifies the current connection and `hash` is a block
    /// inventory hash.
    /// POST: the sync layer records the connection's best-known block and
    /// schedules `getheaders`; no block body request is emitted here.
    /// INVARIANT: block inventory never bypasses header admission and the
    /// download-window budget.
    fn announce_block(&self, source: crate::PeerSource, hash: bitcoin_rs_primitives::Hash256) {
        let Some(sync) = self.block_sync.as_ref() else {
            return;
        };
        sync.announce_block(source, hash);
        wake_sync(self.wake_tx.as_ref());
    }

    fn notify_peer_ready(&self, source: crate::PeerSource) {
        if let Some(peer_ready) = &self.peer_ready {
            peer_ready(source);
        }
    }

    /// Publish ready metadata, then notify only while this lease is current.
    ///
    /// The table lock is not held across notify: `BlockSync` takes the
    /// download window after checking identity, matching `tick`. Publication
    /// and stale-predecessor rules are owned by P2P-02.
    fn publish_info_and_notify_ready(
        &self,
        peer_addr: SocketAddr,
        lease: &crate::PeerLease,
        info: &crate::PeerInfo,
    ) -> bool {
        let source = lease.source(peer_addr);
        if self.peer_table.publish_info(peer_addr, lease, info.clone())
            && self.peer_table.is_current(source)
        {
            if let Some(announcer) = &self.block_announcer {
                announcer.on_peer_ready();
            }
            if !lease.is_inbound() {
                if let Some(book) = &self.address_book {
                    book.succeeded(peer_addr, info.services, crate::addrman::now());
                }
            }
            self.notify_peer_ready(source);
            true
        } else {
            false
        }
    }

    fn is_session_cancelled(&self) -> bool {
        self.session_cancel.load()
    }

    fn send_headers(
        &self,
        source: crate::PeerSource,
        headers: Vec<bitcoin_rs_primitives::Header>,
        wire_response: bool,
        body_fetch_owned: bool,
    ) {
        if let Err(error) = self.headers_tx.send(crate::InboundHeaders {
            headers,
            source: Some(source),
            wire_response,
            body_fetch_owned,
        }) {
            tracing::warn!(peer_addr = %source.addr, %error, "p2p inbound headers channel disconnected");
        } else {
            wake_sync(self.wake_tx.as_ref());
        }
    }

    /// Enqueues a decoded block body into ingress, then forwards its carried
    /// header to header admission.
    ///
    /// The body is queued first so the header can never reach `headers_tx`
    /// while the body is still unsent: request scheduling runs after both
    /// drains, so the staged-or-received body suppresses a duplicate
    /// `getdata` for a tip learned only by delivery.
    ///
    /// PRE: `lease` belongs to the connection that delivered `block`.
    /// POST: when [`crate::PeerLease::admit_block_forward`] admits the body,
    ///   the body reaches the shared inbound block channel and then its
    ///   header reaches the headers sink; a refused body drops both with a
    ///   counter record, so a peer over its unsolicited bound cannot grow
    ///   the header queue either.
    /// INVARIANT: one connection holds at most
    ///   [`crate::connection::MAX_UNSOLICITED_BLOCK_FORWARDS`] unsolicited
    ///   bodies in the shared channel at once, and a body the download
    ///   window owns is never dropped for that bound, so requested sync
    ///   traffic always arrives.
    fn send_block(
        &self,
        lease: &crate::PeerLease,
        peer_addr: SocketAddr,
        block: bitcoin_rs_primitives::Block,
        serialized: bytes::Bytes,
    ) {
        let source = lease.source(peer_addr);
        // Every body carries its own header; route it through the headers
        // sink too so tips learned only by body delivery (`inv` getdata,
        // compact reconstruction, or an unsolicited push) reach header
        // admission. Without a tree node the body can never become the
        // apply frontier's expected block, and no announced-tip credit
        // reaches the delivering peer. The headers drain runs before the
        // blocks drain each tick, so the body lands already expected. The
        // forward is not a `headers` response: it must not consume an
        // outstanding `getheaders` request's pending state.
        //
        // The body goes on its channel before the header goes on its own on
        // purpose: a tip learned only by body delivery arrives untracked
        // (the `inv` getdata is never marked pending), so if the header
        // reached the tree while the body still sat outside `received`, the
        // same tick would schedule a duplicate fetch for it. Queueing the
        // body first means the tick that admits the header always marks the
        // body received first.
        let header = block.header;
        let hash = bitcoin_rs_primitives::Hash256::from(header.compute_hash());
        let requested = self
            .block_sync
            .as_ref()
            .is_some_and(|sync| sync.owns_body_fetch(source, hash));
        let Some(credit) = lease.admit_block_forward(source, hash, requested) else {
            // The connection is over its unsolicited bound: drop the header
            // too, or a flood of refused bodies still grows the header queue
            // without limit.
            metrics::counter!("node.sync.dropped_unsolicited_blocks").increment(1);
            return;
        };
        if self.forward_block(block, serialized, source, Some(credit)) {
            self.send_headers(source, vec![header], false, false);
        }
    }

    /// Queues an admitted body on the shared inbound block channel.
    ///
    /// PRE: `forward_credit` admits this body into the ingress path.
    /// POST: `true` when the body is queued; `false` when it was dropped
    ///   because the session was cancelled or the channel disconnected. A
    ///   caller that pairs the body with a header must send the header only
    ///   on `true`, or sync admits a block announcement whose body never
    ///   arrives — and whose forward credit never releases.
    /// INVARIANT: backpressure waits here, never in the admission step, and
    ///   the credit is released when sync drops the body it holds.
    fn forward_block(
        &self,
        block: bitcoin_rs_primitives::Block,
        serialized: bytes::Bytes,
        source: crate::PeerSource,
        forward_credit: Option<crate::connection::BlockForwardCredit>,
    ) -> bool {
        let mut inbound = crate::InboundBlock {
            block,
            serialized,
            source: Some(source),
            forward_credit,
        };
        loop {
            if self.is_session_cancelled() {
                tracing::debug!(
                    peer_addr = %source.addr,
                    "dropping inbound block: session cancelled"
                );
                return false;
            }
            match self.blocks_tx.send_timeout(inbound, POLL_INTERVAL) {
                Ok(()) => {
                    wake_sync(self.wake_tx.as_ref());
                    return true;
                }
                Err(SendTimeoutError::Timeout(returned)) => inbound = returned,
                Err(SendTimeoutError::Disconnected(_)) => {
                    tracing::warn!(
                        peer_addr = %source.addr,
                        "p2p inbound blocks channel disconnected"
                    );
                    return false;
                }
            }
        }
    }

    /// Only transaction inventory and matching notfound replies wake download
    /// policy from the wire. Ping, headers and other traffic cannot amplify a
    /// gateway census; the relay worker owns the paced background poll.
    fn update_transaction_requests(&self, source: crate::PeerSource, message: &crate::Message) {
        let Some(inventory) = &self.tx_inventory else {
            return;
        };
        match message {
            crate::Message::NotFound(items) => {
                self.peer_table
                    .transaction_not_found(source, items, inventory.as_ref());
            }
            crate::Message::Inv(items)
                if items.iter().any(|item| {
                    matches!(
                        item,
                        bitcoin::p2p::message_blockdata::Inventory::Transaction(_)
                            | bitcoin::p2p::message_blockdata::Inventory::WitnessTransaction(_)
                            | bitcoin::p2p::message_blockdata::Inventory::WTx(_)
                    )
                }) =>
            {
                self.peer_table
                    .poll_transaction_requests(inventory.as_ref());
            }
            _ => {}
        }
    }

    /// Forwards a decoded transaction into the node's ingress channel.
    fn send_tx(&self, source: crate::PeerSource, tx: bitcoin_rs_primitives::Tx) {
        let inbound = crate::InboundTx::new(tx, source);
        let dropped = if let Some(channel) = &self.inbound_tx {
            if self.is_session_cancelled() {
                Some(inbound)
            } else {
                match channel.try_send(inbound) {
                    Ok(()) => None,
                    Err(crossbeam_channel::TrySendError::Full(inbound)) => Some(inbound),
                    Err(crossbeam_channel::TrySendError::Disconnected(inbound)) => {
                        tracing::warn!(peer_addr = %source.addr, "p2p inbound tx channel disconnected");
                        Some(inbound)
                    }
                }
            }
        } else {
            Some(inbound)
        };
        if let Some(inbound) = dropped {
            tracing::debug!(peer_addr = %source.addr, "p2p transaction ingress unavailable; dropping body");
            self.peer_table.transaction_response_completed(
                source,
                inbound.tx.txid(),
                inbound.tx.wtxid(),
            );
            if let Some(inventory) = &self.tx_inventory {
                self.peer_table.poll_transaction_response(
                    inventory.as_ref(),
                    inbound.tx.txid(),
                    inbound.tx.wtxid(),
                );
            }
        }
    }
}

/// Errors returned by the P2P listener accept loop.
#[derive(Debug, Error)]
pub enum ListenerError {
    /// Failed to bind the TCP listener.
    #[error("bind {addr}: {source}")]
    Bind {
        /// Address the listener attempted to bind.
        addr: SocketAddr,
        /// Underlying bind or listener setup failure.
        source: io::Error,
    },
    /// Accept loop returned a fatal I/O error.
    #[error("accept: {0}")]
    Accept(#[from] io::Error),
}

/// Bind the requested listening address.
///
/// Callers that report startup success must bind here first so an occupied
/// address fails before workers are spawned.
///
/// PRE: `addr` identifies the requested local endpoint.
/// POST: Return a nonblocking listener or [`ListenerError::Bind`].
/// INVARIANT: Bind before starting listener workers.
pub fn bind_listener(addr: SocketAddr) -> Result<TcpListener, ListenerError> {
    let listener =
        TcpListener::bind(addr).map_err(|source| ListenerError::Bind { addr, source })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| ListenerError::Bind { addr, source })?;
    Ok(listener)
}

/// Run the accept loop on a bound listener.
///
/// On each accepted connection, spawns a thread that runs the inbound
/// handshake followed by a message-dispatch loop. Socket flags come from
/// [`crate::socket::configure_peer_stream`]. The handshake uses
/// [`crate::socket::HANDSHAKE_TIMEOUT`]; after handshake, the message loop
/// polls inbound reads every [`crate::socket::STREAM_POLL_INTERVAL`], probing
/// a quiet peer with one `ping` per [`PING_INTERVAL`] and ending the
/// connection once a direction is silent past [`TIMEOUT_INTERVAL`].
/// The thread terminates on:
///   - successful handshake then inactivity (no send or receive for
///     [`TIMEOUT_INTERVAL`])
///   - wire / FSM error
///   - explicit FSM disconnect transition
///
/// Transient `accept` errors (ECONNABORTED, EMFILE/ENFILE under fd
/// pressure, etc.) are logged at warn and the loop continues after a
/// bounded backoff, matching Bitcoin Core's tolerant accept loop so inbound
/// P2P stays alive through temporary resource exhaustion.
///
/// Per-connection threads are NOT joined by the outer shutdown — they
/// outlive the listener by up to the timeout. On exit (clean or error),
/// the peer is removed from the authoritative peer table.
///
/// PRE: The listener is bound and nonblocking. Wiring is complete.
/// POST: Return when `shutdown` or `shared.session_cancel` is set.
/// INVARIANT: Apply the ban and activity checks to each accepted socket.
///
/// # Errors
///
/// Returns [`ListenerError::Accept`] when the listener cannot report its
/// local address.
#[expect(clippy::needless_pass_by_value)]
pub fn serve(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    shared: ConnectionShared,
) -> Result<(), ListenerError> {
    let addr = listener.local_addr()?;
    accept_connections(addr, &listener, &shutdown, &shared);
    Ok(())
}

fn accept_connections(
    addr: SocketAddr,
    listener: &TcpListener,
    shutdown: &AtomicBool,
    shared: &ConnectionShared,
) {
    let mut accept_backoff = POLL_INTERVAL;
    while !shutdown.load(Ordering::Relaxed) && !shared.is_session_cancelled() {
        #[cfg(test)]
        if ACCEPT_ERROR_INJECT.swap(false, Ordering::Relaxed) {
            tracing::warn!(addr = %addr, "test-injected accept error; backing off");
            std::thread::sleep(POLL_INTERVAL);
            continue;
        }
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                accept_backoff = POLL_INTERVAL;
                if shared.check_destination(peer_addr, false).is_err() {
                    drop(stream);
                    tracing::debug!(peer_addr = %peer_addr, "p2p inbound rejected by address policy");
                    continue;
                }
                if !shared.activity.is_active() {
                    drop(stream);
                    tracing::debug!(peer_addr = %peer_addr, "p2p inbound rejected: network inactive");
                    continue;
                }
                // Reserve the inbound slot atomically with the capacity
                // test before any thread exists: a separate count followed
                // by an unconstrained spawn races concurrent accepts.
                // Registration stays identity-checked, so the reservation
                // itself is the handshaking-peer accounting Core's connman
                // performs (`net.cpp:1838-1845`, eviction cut to refusal).
                let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded::<crate::Message>();
                let lease = crate::PeerLease::new_inbound(outbound_tx)
                    .with_no_ban(shared.banned.is_noban(peer_addr.ip()));
                let Some(lease) = shared.peer_table.try_register_inbound(
                    peer_addr,
                    lease,
                    shared.max_inbound,
                    &shared.activity,
                ) else {
                    drop(stream);
                    tracing::debug!(peer_addr = %peer_addr, "p2p inbound rejected: inactive or at capacity");
                    continue;
                };
                spawn_handshake_thread(stream, peer_addr, shared.clone(), lease, outbound_rx);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => {
                tracing::warn!(
                    addr = %addr,
                    %error,
                    backoff_ms = accept_backoff.as_millis(),
                    "p2p accept error; backing off and continuing",
                );
                std::thread::sleep(accept_backoff);
                accept_backoff = std::cmp::min(accept_backoff * 2, ACCEPT_BACKOFF_MAX);
            }
        }
    }
}

/// Spawn one automatic outbound connection dial of `role`.
///
/// The thread connects to `addr`, performs the outbound P2P handshake with
/// `role`, and enters the same message loop the inbound path uses. Errors
/// during connect or handshake bubble up via the `JoinHandle`'s `Result`; a
/// failed thread spawn yields a handle that reports the spawn I/O error.
///
/// PRE: Wiring is complete for this start epoch, and `role` is the role the
///   dialer chose for this connection.
/// POST: The handle reports connection completion or its error.
/// INVARIANT: Preserve registration, cancellation, and teardown order. The
///   role is fixed at spawn: the handshake advertises it and every relay
///   decision reads it back from the lease.
#[must_use]
pub fn spawn_outbound_connection(
    addr: SocketAddr,
    shared: ConnectionShared,
    role: crate::peer_info::PeerRole,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    spawn_dial(addr, shared, role, false, false)
}

/// Spawn one operator-pinned outbound connection dial of `role`: an address
/// the operator named, which Core marks `MANUAL` and spares from its
/// chain-sync and excess-slot eviction rules.
///
/// PRE: Wiring is complete for this start epoch, and `role` is the role the
///   dialer chose for this connection.
/// POST: The handle reports connection completion or its error.
/// INVARIANT: The lease records the pinned origin at spawn, and the eviction
///   rules read it back from there.
#[must_use]
pub(crate) fn spawn_pinned_outbound_connection(
    addr: SocketAddr,
    shared: ConnectionShared,
    role: crate::peer_info::PeerRole,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    spawn_dial(addr, shared, role, true, false)
}

pub(crate) fn spawn_dial(
    addr: SocketAddr,
    shared: ConnectionShared,
    role: crate::peer_info::PeerRole,
    pinned: bool,
    count_failure: bool,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    let thread_name = format!("bitcoin-rs-p2p-outbound-{addr}");
    let result = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || run_outbound_connection(addr, &shared, role, pinned, count_failure));

    match result {
        Ok(handle) => handle,
        Err(error) => {
            tracing::warn!(
                addr = %addr,
                %error,
                "p2p outbound spawn failed",
            );
            std::thread::spawn(move || Err(crate::wire::PeerError::Io(error)))
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "One connection owner keeps admission, TCP health, lease publication, and handshake teardown ordered"
)]
fn run_outbound_connection(
    addr: SocketAddr,
    shared: &ConnectionShared,
    role: crate::peer_info::PeerRole,
    manual: bool,
    count_failure: bool,
) -> Result<(), crate::wire::PeerError> {
    shared.check_destination(addr, manual)?;
    if !shared.activity.is_active() {
        return Err(crate::wire::PeerError::Protocol("network inactive"));
    }
    if shared.is_session_cancelled() {
        return Err(crate::wire::PeerError::Protocol("p2p startup cancelled"));
    }

    if !manual && !shared.feeler {
        let depth = approximate_best_block_depth(shared.chain_query.as_deref());
        if shared
            .address_book
            .as_ref()
            .is_some_and(|book| !book.ordinary_services_eligible(addr, depth))
        {
            return Err(crate::wire::PeerError::Protocol(
                "outbound peer lacks desirable services",
            ));
        }
    }
    let connection = TcpStream::connect_timeout(&addr, Duration::from_secs(10));
    if let Some(book) = &shared.address_book {
        // Like Core ConnectNode, record actual TCP attempts on success/failure,
        // after local admission guards. Spawn failures/cancellation are not peer evidence.
        book.attempted(addr, count_failure && !manual, crate::addrman::now());
    }
    let stream = connection.map_err(crate::wire::PeerError::Io)?;
    configure_peer_stream(&stream).map_err(crate::wire::PeerError::Io)?;
    shared.check_destination(addr, manual)?;
    if shared.is_session_cancelled() {
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Err(crate::wire::PeerError::Protocol("p2p startup cancelled"));
    }

    // Wrapped before registration and the handshake, so failed socket
    // posture cannot leave a dead peer in live-connection accounting.
    let counters = std::sync::Arc::new(crate::PeerCounters::default());
    let stream = crate::CountingStream::from_connected(stream, counters)
        .map_err(crate::wire::PeerError::Io)?;

    // Register the connection before the handshake so live-connection
    // accounting covers handshaking peers exactly like Core's connman.
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded::<crate::Message>();
    let lease = match (role, manual) {
        (crate::peer_info::PeerRole::FullRelay, false) => crate::PeerLease::new(outbound_tx),
        (crate::peer_info::PeerRole::BlockRelayOnly, false) => {
            crate::PeerLease::new_block_relay(outbound_tx)
        }
        (_, true) => crate::PeerLease::new_manual(outbound_tx, role),
    }
    .with_no_ban(shared.banned.is_noban(addr.ip()));
    let Some(lease) = shared
        .peer_table
        .try_register_outbound(addr, lease, &shared.activity)
    else {
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Err(crate::wire::PeerError::Protocol("network inactive"));
    };
    if let Err(error) = shared.check_destination(addr, manual) {
        shared.peer_table.remove_current(addr, &lease);
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Err(error);
    }
    if shared.is_session_cancelled() {
        shared.peer_table.remove_current(addr, &lease);
        lease.cancel();
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Ok(());
    }

    let nonce = generate_nonce(addr);

    let addr_bind = stream.local_addr().map_err(crate::wire::PeerError::Io)?;
    let counters = std::sync::Arc::clone(stream.counters());
    let mut peer = Peer::new(stream, shared.magic);
    peer.attach_net_trace(crate::net_trace::NetTrace::outbound(
        lease.node_id(),
        addr,
        role,
        manual,
    ));
    let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    if let Err(error) = run_outbound_handshake(
        &mut peer,
        nonce,
        0,
        &lease,
        handshake_deadline,
        addr,
        shared,
    ) {
        // `remove_current` cancels as a side effect, so revocation must be
        // read before it: a pre-cancelled lease means an external shutdown,
        // while a live lease means this handshake failed on its own.
        let revoked = lease.is_cancelled();
        if !revoked {
            shared.note_misbehavior(addr, &lease, &error);
        }
        shared.peer_table.remove_current(addr, &lease);
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        if revoked {
            tracing::debug!(peer_addr = %addr, "p2p outbound lease revoked during handshake");
            return Ok(());
        }
        return Err(error);
    }

    let Some(remote_version) = peer.remote_version.as_ref() else {
        shared.peer_table.remove_current(addr, &lease);
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        return Err(crate::wire::PeerError::Protocol(
            "missing remote version after outbound handshake",
        ));
    };
    let conn_time = unix_time_secs();
    let info = crate::PeerInfo::outbound_from_version(
        addr,
        addr_bind,
        remote_version,
        conn_time,
        peer.version_received_time.unwrap_or(conn_time),
        counters,
    );

    if shared.feeler {
        if shared.peer_table.is_current(lease.source(addr))
            && !lease.is_cancelled()
            && !shared.is_session_cancelled()
            && shared.activity.is_active()
        {
            if let Some(book) = &shared.address_book {
                book.succeeded(addr, info.services, unix_time_secs());
            }
        }
        shared.peer_table.remove_current(addr, &lease);
        lease.cancel();
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        return Ok(());
    }
    run_connected_session(&mut peer, addr, shared, lease, outbound_rx, info)
}

/// Drives the outbound handshake until the peer is ready.
///
/// PRE: `peer` wraps a connected outbound stream, `lease` belongs to it,
///   and `shared` holds this dial's chain query and service policy.
/// POST: a feeler has an accepted VERSION; an ordinary `peer` is `Ready`,
///   post-verack messages are sent, and the remote offered desirable services ([`has_all_desirable_service_flags`]).
/// INVARIANT: This function counts no bytes; the stream that `peer` wraps
///   owns byte accounting. The service check runs once the remote `version`
///   is decoded and before the peer can be published as usable.
fn run_outbound_handshake<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    nonce: u64,
    start_height: i32,
    lease: &crate::PeerLease,
    deadline: Instant,
    addr: SocketAddr,
    shared: &ConnectionShared,
) -> Result<(), crate::wire::PeerError> {
    let best_block_depth = approximate_best_block_depth(shared.chain_query.as_deref());
    let outbound_messages = crate::handshake::start(
        peer,
        nonce,
        start_height,
        lease.role(),
        shared.local_services,
    );
    for message in outbound_messages {
        peer.send(&message)?;
    }

    while peer.state != crate::peer::PeerState::Ready {
        let (accepted, responses) = crate::handshake::next_handshake_step(peer, lease, deadline)?;
        if !shared.feeler
            && matches!(accepted, crate::Message::Version(_))
            && let Some(version) = peer.remote_version.as_ref()
        {
            // Record received services even when the ordinary service gate rejects
            // this VERSION. Metadata does not imply handshake success or Good.
            let _ = shared.peer_table.with_current(lease.source(addr), || {
                if !shared.is_session_cancelled()
                    && shared.activity.is_active()
                    && let Some(book) = &shared.address_book
                {
                    book.set_services(addr, version.services.to_u64());
                }
            });
        }
        // Feelers establish address liveness from an accepted native VERSION.
        // They neither require ordinary services nor wait for VERACK/ready work.
        if shared.feeler && peer.remote_version.is_some() {
            return Ok(());
        }
        if peer.remote_version.as_ref().is_some_and(|version| {
            !has_all_desirable_service_flags(version.services, best_block_depth)
        }) {
            return Err(crate::wire::PeerError::Protocol(
                "outbound peer lacks desirable services",
            ));
        }
        for response in responses {
            peer.send(&response)?;
        }
    }
    crate::handshake::send_post_verack_messages(peer)?;
    Ok(())
}

/// Local applied-tip age in target-spacing units, shared by selection and admission.
/// Returns `u64::MAX` without a chain view/tip, preserving full-history eligibility.
/// Read the chain view before acquiring the address-book lock.
pub(crate) fn approximate_best_block_depth(query: Option<&dyn crate::ChainQuery>) -> u64 {
    let Some(tip_time) = query.and_then(crate::ChainQuery::best_block_time) else {
        return u64::MAX;
    };
    unix_time_secs().saturating_sub(u64::from(tip_time)) / POW_TARGET_SPACING_SECS
}

/// Returns the service flags required from an outbound peer.
///
/// PRE: `remote_services` is the flags received in `version`;
///   `best_block_depth` is the local approximate tip age in target-spacing
///   units ([`approximate_best_block_depth`]).
/// POST: a peer with NETWORK and WITNESS is accepted; a LIMITED peer is
///   accepted only when it also has WITNESS and `best_block_depth < 144`;
///   every other service set is rejected.
/// INVARIANT: this is the only outbound desirable-service predicate
///   (Core `HasAllDesirableServiceFlags` / `GetDesirableServiceFlags`,
///   `net_processing.cpp:1857-1872`, applied to outbound connections at
///   `net_processing.cpp:3864-3871`); inbound peers are exempt.
#[must_use]
pub fn has_all_desirable_service_flags(
    remote_services: ServiceFlags,
    best_block_depth: u64,
) -> bool {
    let required = if remote_services.has(ServiceFlags::NETWORK_LIMITED)
        && best_block_depth < NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS
    {
        ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS
    } else {
        ServiceFlags::NETWORK | ServiceFlags::WITNESS
    };
    remote_services.has(required)
}

fn spawn_handshake_thread(
    stream: TcpStream,
    peer_addr: SocketAddr,
    shared: ConnectionShared,
    lease: crate::PeerLease,
    outbound_rx: crossbeam_channel::Receiver<crate::Message>,
) {
    let thread_name = format!("bitcoin-rs-p2p-handshake-{peer_addr}");
    let peer_table = Arc::clone(&shared.peer_table);
    let reservation = lease.clone();
    let spawn_result = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            if let Err(error) = run_handshake(stream, peer_addr, &shared, lease, outbound_rx) {
                tracing::warn!(
                    peer_addr = %peer_addr,
                    %error,
                    "p2p inbound handshake failed",
                );
            }
        });

    if let Err(error) = spawn_result {
        // The accept loop reserved this lease for the thread; with no
        // thread running, the reservation must release its capacity.
        peer_table.remove_current(peer_addr, &reservation);
        reservation.cancel();
        tracing::warn!(
            peer_addr = %peer_addr,
            %error,
            "failed to spawn p2p inbound handshake thread",
        );
    }
}

fn run_handshake(
    stream: TcpStream,
    peer_addr: SocketAddr,
    shared: &ConnectionShared,
    lease: crate::PeerLease,
    outbound_rx: crossbeam_channel::Receiver<crate::Message>,
) -> Result<(), crate::wire::PeerError> {
    if let Err(error) = shared.check_destination(peer_addr, lease.is_manual()) {
        shared.peer_table.remove_current(peer_addr, &lease);
        return Err(error);
    }
    // The accept loop reserved this lease: every exit from here on must
    // release it, or a failed setup would consume an admission slot forever.
    if let Err(error) = configure_peer_stream(&stream).map_err(crate::wire::PeerError::Io) {
        shared.peer_table.remove_current(peer_addr, &lease);
        lease.cancel();
        return Err(error);
    }

    let counters = std::sync::Arc::new(crate::PeerCounters::default());
    let stream = match crate::CountingStream::from_connected(stream, counters)
        .map_err(crate::wire::PeerError::Io)
    {
        Ok(stream) => stream,
        Err(error) => {
            shared.peer_table.remove_current(peer_addr, &lease);
            lease.cancel();
            return Err(error);
        }
    };
    let addr_bind = match stream.local_addr().map_err(crate::wire::PeerError::Io) {
        Ok(addr) => addr,
        Err(error) => {
            shared.peer_table.remove_current(peer_addr, &lease);
            lease.cancel();
            return Err(error);
        }
    };
    let counters = std::sync::Arc::clone(stream.counters());

    // The accept loop already reserved this lease in the table — live
    // connection accounting covers handshaking peers exactly like Core's
    // connman — so the inbound path never registers an unrestricted
    // connection here.
    if shared.is_session_cancelled() {
        shared.peer_table.remove_current(peer_addr, &lease);
        lease.cancel();
        return Ok(());
    }

    let nonce = generate_nonce(peer_addr);
    let mut peer = Peer::new(stream, shared.magic);
    peer.attach_net_trace(crate::net_trace::NetTrace::inbound(
        lease.node_id(),
        peer_addr,
    ));
    let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    if let Err(error) = run_inbound_handshake(
        &mut peer,
        nonce,
        0,
        shared.local_services,
        &lease,
        handshake_deadline,
    ) {
        // `remove_current` cancels as a side effect, so revocation must be
        // read before it: a pre-cancelled lease means an external shutdown,
        // while a live lease means this handshake failed on its own.
        let revoked = lease.is_cancelled();
        if !revoked {
            shared.note_misbehavior(peer_addr, &lease, &error);
        }
        shared.peer_table.remove_current(peer_addr, &lease);
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        if revoked {
            tracing::debug!(peer_addr = %peer_addr, "p2p inbound lease revoked during handshake");
            return Ok(());
        }
        return Err(error);
    }

    let Some(remote_version) = peer.remote_version.as_ref() else {
        shared.peer_table.remove_current(peer_addr, &lease);
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        return Err(crate::wire::PeerError::Protocol(
            "missing remote version after successful handshake",
        ));
    };
    let conn_time = unix_time_secs();
    let info = crate::PeerInfo::inbound_from_version(
        peer_addr,
        addr_bind,
        remote_version,
        conn_time,
        peer.version_received_time.unwrap_or(conn_time),
        counters,
    );

    run_connected_session(&mut peer, peer_addr, shared, lease, outbound_rx, info)
}

/// Runs one established connection to completion.
///
/// Teardown invariant (both exit paths, in this order):
/// `PeerTable::remove_current` → `lease.cancel()` → `stream.shutdown(Both)` →
/// `drop(lease)` → `writer.join()`. `cancel()` raises the writer's close
/// signal so an idle writer wakes deterministically even when foreign lease
/// clones (registration handles, concurrent pings) are still alive; the
/// shutdown unblocks a writer blocked mid-`write_all`. Connection threads
/// are intentionally not joined by outer listener shutdown.
fn run_connected_session(
    peer: &mut Peer<crate::CountingStream<TcpStream>>,
    peer_addr: SocketAddr,
    shared: &ConnectionShared,
    lease: crate::PeerLease,
    outbound_rx: crossbeam_channel::Receiver<crate::Message>,
    mut info: crate::PeerInfo,
) -> Result<(), crate::wire::PeerError> {
    // BIP339 announcement preference is the peer's received wtxidrelay,
    // independently of our own advertisement. Publish it atomically with the
    // completed handshake so relay never chooses a type during negotiation.
    info.wtxid_relay = peer.wtxid_relay.peer_supported();
    info.send_headers = peer.capabilities.send_headers;
    let setup_result: Result<std::thread::JoinHandle<()>, crate::wire::PeerError> = (|| {
        #[cfg(test)]
        if WRITER_SETUP_FAIL.swap(false, Ordering::Relaxed) {
            return Err(crate::wire::PeerError::Io(io::Error::other(
                "test-injected writer setup failure",
            )));
        }
        let writer_stream = peer
            .stream
            .try_clone()
            .map_err(crate::wire::PeerError::Io)?;
        spawn_connection_writer(
            writer_stream,
            shared.magic,
            outbound_rx,
            lease.close_signal(),
            lease.budget_handle(),
            peer_addr,
            peer.net_trace,
        )
        .map_err(crate::wire::PeerError::Io)
    })();
    let writer = match setup_result {
        Ok(handle) => handle,
        Err(error) => {
            shared.peer_table.remove_current(peer_addr, &lease);
            lease.cancel();
            let _ = peer.stream.shutdown(std::net::Shutdown::Both);
            drop(lease);
            return Err(error);
        }
    };
    let ready = shared.publish_info_and_notify_ready(peer_addr, &lease, &info);

    let inbound = lease.is_inbound();
    tracing::info!(
        peer_addr = %peer_addr,
        inbound,
        "p2p handshake complete; entering message loop",
    );

    let loop_result = run_message_loop(peer, peer_addr, &lease, shared, shared.ibd.as_ref());

    let source = lease.source(peer_addr);
    if let Err(error) = &loop_result {
        shared.note_misbehavior(peer_addr, &lease, error);
    }
    shared.peer_table.remove_current(peer_addr, &lease);
    if let Some(inventory) = &shared.tx_inventory {
        shared
            .peer_table
            .transaction_peer_disconnected(source, inventory.as_ref());
    }
    if let Some(announcer) = &shared.block_announcer {
        announcer.on_peer_disconnected(source);
    }
    if ready && !lease.is_inbound() && !lease.is_manual() && lease.role().relays_transactions() {
        if let Some(book) = &shared.address_book {
            book.connected(peer_addr, crate::addrman::now());
        }
    }
    lease.cancel();
    let _ = peer.stream.shutdown(std::net::Shutdown::Both);
    drop(lease);
    let _ = writer.join();
    if let Err(error) = &loop_result {
        tracing::warn!(
            peer_addr = %peer_addr,
            inbound,
            %error,
            "p2p peer disconnected with error"
        );
    } else {
        tracing::debug!(peer_addr = %peer_addr, inbound, "p2p peer disconnected cleanly");
    }
    loop_result
}

/// Applies a connection's relay role to one inbound message.
///
/// PRE: `role` is the connection's role and `message` arrived on it.
/// POST: return the message for dispatch, `None` to drop it unheard, or the
///   protocol error that ends the connection.
/// INVARIANT: a block-relay-only connection carries blocks and headers and
///   nothing else. A `tx` message or a transaction `inv` is a protocol
///   violation and ends the connection, as Core's `RejectIncomingTxs`
///   requires (`net_processing.cpp:4706-4711`, and the `inv` branch at
///   `net_processing.cpp:4385-4390`). A `getdata` from such a connection is
///   answered with block inventory alone: transaction inventory is stripped
///   before dispatch, and a request that asked for nothing else is dropped
///   unheard, so the role cannot obtain a transaction body through
///   `getdata`. `addr` and `addrv2` are dropped
///   without punishment, because Core declines address relay for such a
///   peer rather than faulting it (`SetupAddressRelay`,
///   `net_processing.cpp:5952-5970`). A full-relay connection is never
///   restricted.
fn enforce_relay_role(
    role: crate::peer_info::PeerRole,
    message: crate::Message,
) -> Result<Option<crate::Message>, crate::wire::PeerError> {
    use bitcoin::p2p::message_blockdata::Inventory;
    if role.relays_transactions() {
        return Ok(Some(message));
    }
    let is_transaction = |item: &Inventory| {
        matches!(
            item,
            Inventory::Transaction(_) | Inventory::WitnessTransaction(_) | Inventory::WTx(_)
        )
    };
    if matches!(message, crate::Message::Tx(_)) {
        return Err(crate::wire::PeerError::Protocol(
            "transaction sent in violation of protocol",
        ));
    }
    if let crate::Message::Inv(items) = &message
        && items.iter().any(&is_transaction)
    {
        return Err(crate::wire::PeerError::Protocol(
            "transaction inv sent in violation of protocol",
        ));
    }
    if let crate::Message::GetData(mut items) = message {
        items.retain(|item| !is_transaction(item));
        if items.is_empty() {
            tracing::trace!("p2p dropping transaction getdata from block-relay-only peer");
            return Ok(None);
        }
        return Ok(Some(crate::Message::GetData(items)));
    }
    if matches!(message, crate::Message::Addr(_) | crate::Message::AddrV2(_)) {
        tracing::trace!("p2p dropping address message from block-relay-only peer");
        return Ok(None);
    }
    Ok(Some(message))
}

/// What one connection's keepalive ledger asks the message loop to do.
#[derive(Debug, PartialEq, Eq)]
enum KeepaliveAction {
    /// Nothing is due.
    Idle,
    /// Queue one `ping` for the peer.
    Ping,
    /// End the connection: one direction has been silent past
    /// [`TIMEOUT_INTERVAL`].
    Expired,
}

/// One connection's liveness ledger: when it last heard, last spoke, and
/// last probed.
///
/// PRE: [`Keepalive::record_recv`] runs for every message the loop reads;
///   every admitted `PeerLease::send` stamps the shared `last_send` the loop
///   folds in via [`Keepalive::observe_send`].
/// POST: [`Keepalive::next_action`] orders a `ping` once [`PING_INTERVAL`]
///   of quiet has passed since the previous probe, and an `Expired` end
///   once either direction has been silent past [`TIMEOUT_INTERVAL`].
/// INVARIANT: the decision is a pure function of the recorded instants and
///   the caller's `now`, and one ledger belongs to one connection thread,
///   so a peer is never judged on another connection's traffic. Durations
///   come from the monotonic clock, so a wall-clock adjustment cannot
///   shorten or lengthen a timeout.
struct Keepalive {
    /// The instant the loop last read a message from the peer.
    last_recv: Instant,
    /// The instant the loop last queued a message for the peer.
    last_send: Instant,
    /// The instant of the last probe this ledger ordered.
    last_ping: Option<Instant>,
}

impl Keepalive {
    /// Starts a ledger for a connection whose loop begins at `now`.
    fn starting(now: Instant) -> Self {
        Self {
            last_recv: now,
            last_send: now,
            last_ping: None,
        }
    }

    /// Credits the peer with one message read at `now`.
    fn record_recv(&mut self, now: Instant) {
        self.last_recv = now;
    }

    /// Credits this node with one message queued at `now`.
    fn record_send(&mut self, now: Instant) {
        self.last_send = now;
    }

    /// Folds a send timestamp recorded outside this loop (every admitted
    /// `PeerLease::send`) into the ledger.
    fn observe_send(&mut self, sent: Instant) {
        if sent > self.last_send {
            self.last_send = sent;
        }
    }

    /// Records a probe actually queued at `now`: the interval counts from
    /// the send, not the decision, so a probe skipped for a saturated queue
    /// stays owed instead of being consumed unsent.
    fn record_probe(&mut self, now: Instant) {
        self.last_ping = Some(now);
        self.record_send(now);
    }

    /// Returns the action owed at `now`, ordering at most one probe per
    /// [`PING_INTERVAL`] and an end once either direction is silent past
    /// [`TIMEOUT_INTERVAL`].
    ///
    /// INVARIANT: Core's `InactivityCheck` (`net.cpp:2043-2090`) ends a
    ///   connection when the send timeout or the receive timeout fires, so
    ///   either direction alone expiring is enough here.
    ///
    /// A writer stuck on a full socket does not wait out the send silence:
    /// [`crate::socket::HANDSHAKE_TIMEOUT`] bounds one blocking write at one
    /// minute, so this branch only covers a peer that takes our writes and
    /// never answers them.
    fn next_action(&self, now: Instant) -> KeepaliveAction {
        if now.saturating_duration_since(self.last_recv) > TIMEOUT_INTERVAL
            || now.saturating_duration_since(self.last_send) > TIMEOUT_INTERVAL
        {
            return KeepaliveAction::Expired;
        }
        let idle = now.saturating_duration_since(self.last_recv) >= PING_INTERVAL
            || now.saturating_duration_since(self.last_send) >= PING_INTERVAL;
        let probe_owed = self
            .last_ping
            .is_none_or(|last| now.saturating_duration_since(last) >= PING_INTERVAL);
        if probe_owed && idle {
            KeepaliveAction::Ping
        } else {
            KeepaliveAction::Idle
        }
    }
}

#[cfg(test)]
mod keepalive_tests {
    use super::{Keepalive, KeepaliveAction, PING_INTERVAL, TIMEOUT_INTERVAL};
    use std::time::{Duration, Instant};

    /// A fresh connection carries no probe obligation: a ping is owed only
    /// once a direction has been idle for an interval, then at most once per
    /// interval while it stays idle.
    #[test]
    fn probes_owe_one_ping_per_idle_interval() {
        let t0 = Instant::now();
        let mut keepalive = Keepalive::starting(t0);
        assert_eq!(
            keepalive.next_action(t0),
            KeepaliveAction::Idle,
            "a busy-enough connection sends no keepalive"
        );
        keepalive.record_send(t0);
        assert_eq!(
            keepalive.next_action(t0 + PING_INTERVAL),
            KeepaliveAction::Ping,
            "one silent direction for an interval owes a probe"
        );
        keepalive.record_probe(t0 + PING_INTERVAL);
        assert_eq!(
            keepalive.next_action(t0 + PING_INTERVAL + PING_INTERVAL / 2),
            KeepaliveAction::Idle
        );
        assert_eq!(
            keepalive.next_action(t0 + PING_INTERVAL * 2),
            KeepaliveAction::Ping
        );
    }

    #[test]
    fn receive_silence_expires_the_connection() {
        let t0 = Instant::now();
        let mut keepalive = Keepalive::starting(t0);
        keepalive.record_send(t0 + TIMEOUT_INTERVAL);
        assert_eq!(
            keepalive.next_action(t0 + TIMEOUT_INTERVAL + Duration::from_secs(1)),
            KeepaliveAction::Expired
        );
    }

    #[test]
    fn send_silence_expires_the_connection() {
        let t0 = Instant::now();
        let mut keepalive = Keepalive::starting(t0);
        keepalive.record_recv(t0 + TIMEOUT_INTERVAL);
        assert_eq!(
            keepalive.next_action(t0 + TIMEOUT_INTERVAL + Duration::from_secs(1)),
            KeepaliveAction::Expired
        );
    }

    #[test]
    fn fresh_activity_defers_the_timeout() {
        let t0 = Instant::now();
        let mut keepalive = Keepalive::starting(t0);
        let fresh = t0 + TIMEOUT_INTERVAL / 2;
        keepalive.record_recv(fresh);
        keepalive.record_send(fresh);
        assert_eq!(
            keepalive.next_action(t0 + TIMEOUT_INTERVAL),
            KeepaliveAction::Ping
        );
        keepalive.record_probe(t0 + TIMEOUT_INTERVAL);
        assert_eq!(
            keepalive.next_action(t0 + TIMEOUT_INTERVAL + PING_INTERVAL / 2),
            KeepaliveAction::Idle
        );
    }
}

/// Dispatches one Ready connection's inbound messages until it ends.
///
/// PRE: `lease` is the registered lease of the connection `peer` wraps, and
/// `shared` is the wiring of the start epoch that accepted or dialed it.
/// POST: Return `Ok` on disconnect, lease revocation, or an expired
/// keepalive (one direction silent past [`TIMEOUT_INTERVAL`]); return the
/// error that ended the connection otherwise.
/// INVARIANT: Every sink write goes through `shared`, so sinks observe the
/// start epoch's cancellation token.
///
/// `ibd` is the transaction-relay gate, read lazily per relevant message.
/// PRE: use the node-owned IBD decision. POST: a closed gate requests no
/// announced transaction and enqueues no transaction body. INVARIANT: block
/// processing and peer punishment are unchanged. Opening the gate needs no
/// reconnect, and unrelated messages never read it.
// The transaction-relay gate adds one documented parameter and one lazy
// closure to an already-large dispatch loop.
#[expect(clippy::too_many_lines)]
fn run_message_loop<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    peer_addr: SocketAddr,
    lease: &crate::PeerLease,
    shared: &ConnectionShared,
    ibd: Option<&(Arc<bitcoin_rs_chain::InitialBlockDownload>, Network)>,
) -> Result<(), crate::wire::PeerError> {
    use crate::peer::PeerState;
    use std::time::Instant;

    let tx_relay_open =
        || ibd.is_none_or(|(latch, network)| !latch.is_active(unix_time_secs(), *network));

    let mut keepalive = Keepalive::starting(Instant::now());
    let budget = lease.budget_handle();
    let mut compact_reconstruction = crate::compact_blocks::Reconstruction::new();
    let mut address_budget = 32_u64;
    let mut last_address_refill = crate::addrman::now();
    let mut answered_getaddr = false;
    if !lease.is_inbound()
        && lease.role().relays_transactions()
        && shared
            .address_book
            .as_ref()
            .is_some_and(|book| book.len() < 1024)
    {
        let _ = lease.send(crate::Message::GetAddr);
    }
    loop {
        if peer.state == PeerState::Disconnecting {
            return Ok(());
        }

        if lease.is_cancelled() {
            tracing::debug!(peer_addr = %peer_addr, "p2p peer lease revoked; closing");
            return Ok(());
        }

        keepalive.observe_send(lease.last_send());
        match keepalive.next_action(Instant::now()) {
            KeepaliveAction::Idle => {}
            KeepaliveAction::Ping => {
                // A probe queued behind a saturated outbound queue would
                // cancel the lease for our own queue state, not for the
                // peer's silence; skip it while the queue has no production
                // headroom and let the timeout rule judge the connection on
                // its next due probe.
                if budget.has_block_production_headroom() {
                    let nonce = generate_nonce(peer_addr);
                    lease.send(crate::Message::Ping(nonce)).map_err(|_| {
                        crate::wire::PeerError::Protocol("outbound queue closed or saturated")
                    })?;
                    keepalive.record_probe(Instant::now());
                }
            }
            KeepaliveAction::Expired => {
                tracing::debug!(
                    peer_addr = %peer_addr,
                    "p2p peer silent past the timeout interval; closing",
                );
                return Ok(());
            }
        }

        compact_reconstruction.prune(Instant::now());

        let read_result = peer.read_message();
        if lease.is_cancelled() {
            tracing::debug!(peer_addr = %peer_addr, "p2p peer lease revoked during read; closing");
            return Ok(());
        }
        match read_result {
            Ok((message, raw)) => {
                keepalive.record_recv(Instant::now());
                let Some(message) = enforce_relay_role(lease.role(), message)? else {
                    continue;
                };
                tracing::trace!(
                    peer_addr = %peer_addr,
                    command = ?std::mem::discriminant(&message),
                    "p2p message received",
                );
                let dispatched = crate::dispatch::dispatch_inbound_full(
                    peer,
                    &message,
                    shared.chain_query.as_deref(),
                    shared.tx_inventory.as_deref(),
                    &tx_relay_open,
                    &|| budget.has_block_production_headroom(),
                    &mut |response| {
                        lease
                            .send(response)
                            .map(|()| keepalive.record_send(Instant::now()))
                            .map_err(|_| {
                                crate::wire::PeerError::Protocol(
                                    "outbound queue closed or saturated",
                                )
                            })
                    },
                    &mut |hash| shared.announce_block(lease.source(peer_addr), hash),
                    &mut |items| {
                        shared
                            .peer_table
                            .announce_transactions(lease.source(peer_addr), &items);
                    },
                );
                if let Err(error) = dispatched {
                    if lease.ignores_protocol_error(&error) {
                        shared.note_misbehavior(peer_addr, lease, &error);
                        continue;
                    }
                    return Err(error);
                }
                match &message {
                    crate::Message::Inv(items) => shared
                        .peer_table
                        .note_transaction_inventory(lease.source(peer_addr), items),
                    crate::Message::FeeFilter(rate) => shared
                        .peer_table
                        .receive_fee_filter(lease.source(peer_addr), *rate),
                    crate::Message::Tx(tx) => {
                        use bitcoin::hashes::Hash as _;
                        shared.peer_table.note_transaction_inventory(
                            lease.source(peer_addr),
                            &[
                                bitcoin::p2p::message_blockdata::Inventory::Transaction(
                                    bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()),
                                ),
                                bitcoin::p2p::message_blockdata::Inventory::WTx(
                                    bitcoin::Wtxid::from_byte_array(*tx.wtxid().as_bytes()),
                                ),
                            ],
                        );
                    }
                    _ => {}
                }
                if tx_relay_open() {
                    shared.update_transaction_requests(lease.source(peer_addr), &message);
                }
                match message {
                    crate::Message::Addr(addresses) => {
                        let addresses: Vec<_> = addresses
                            .iter()
                            .filter_map(|(seen, addr)| {
                                addr.socket_addr().ok().map(|socket| {
                                    (socket, addr.services.to_u64(), u64::from(*seen))
                                })
                            })
                            .collect();
                        learn_addresses(
                            shared,
                            lease,
                            peer_addr,
                            &addresses,
                            &mut address_budget,
                            &mut last_address_refill,
                        );
                    }
                    crate::Message::AddrV2(addresses) => {
                        let addresses: Vec<_> = addresses
                            .iter()
                            .filter_map(|addr| {
                                let ip: std::net::IpAddr = match addr.addr {
                                    bitcoin::p2p::address::AddrV2::Ipv4(ip) => ip.into(),
                                    bitcoin::p2p::address::AddrV2::Ipv6(ip) => ip.into(),
                                    _ => return None,
                                };
                                Some((
                                    SocketAddr::new(ip, addr.port),
                                    addr.services.to_u64(),
                                    u64::from(addr.time),
                                ))
                            })
                            .collect();
                        learn_addresses(
                            shared,
                            lease,
                            peer_addr,
                            &addresses,
                            &mut address_budget,
                            &mut last_address_refill,
                        );
                    }
                    crate::Message::GetAddr
                        if lease.is_inbound()
                            && !answered_getaddr
                            && lease.role().relays_transactions() =>
                    {
                        answered_getaddr = true;
                        if let Some(book) = &shared.address_book {
                            let _ = lease
                                .send(crate::Message::Addr(book.gossip(crate::addrman::now())));
                        }
                    }
                    crate::Message::Headers(headers) => {
                        shared.send_headers(lease.source(peer_addr), headers, true, false);
                    }
                    crate::Message::Block(block) => {
                        shared.send_block(lease, peer_addr, block, raw);
                    }
                    crate::Message::Tx(tx) => forward_tx_if_relay_open(
                        shared,
                        lease.source(peer_addr),
                        tx,
                        peer_addr,
                        tx_relay_open(),
                    ),
                    crate::Message::SendHeaders => {
                        shared.peer_table.note_send_headers(lease.source(peer_addr));
                    }
                    crate::Message::SendCmpct(send_cmpct)
                        if peer
                            .compact_blocks
                            .remote_preference()
                            .is_some_and(|preference| preference.version == send_cmpct.version) =>
                    {
                        // Only a version we advertise negotiates BIP152 relay.
                        // The high-bandwidth push preference is a separate
                        // per-peer choice and must not gate compact-fetch
                        // eligibility.
                        shared
                            .peer_table
                            .note_compact_relay(lease.source(peer_addr));
                        shared.peer_table.note_compact_announcement(
                            lease.source(peer_addr),
                            &peer.compact_blocks,
                        );
                        if let Some(announcer) = &shared.block_announcer {
                            announcer.reconcile_high_bandwidth_peers();
                        }
                    }
                    crate::Message::CmpctBlock(_) | crate::Message::BlockTxn(_) => {
                        process_compact_wire_message(
                            &message,
                            &mut compact_reconstruction,
                            peer.compact_blocks.local_version(),
                            shared.compact_hints.as_deref(),
                            lease,
                            peer_addr,
                            shared,
                        );
                    }
                    _ => {}
                }
            }
            Err(crate::wire::PeerError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) if lease.ignores_protocol_error(&error) => {
                shared.note_misbehavior(peer_addr, lease, &error);
                continue;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Consume a bounded, replenishing per-connection gossip allowance before
/// touching the book. Source-group limits survive peer reconnects in the book.
fn learn_addresses(
    shared: &ConnectionShared,
    lease: &crate::PeerLease,
    peer_addr: SocketAddr,
    addresses: &[(SocketAddr, u64, u64)],
    budget: &mut u64,
    last_refill: &mut u64,
) {
    if !lease.role().relays_transactions() {
        return;
    }
    let now = crate::addrman::now();
    let refill = now.saturating_sub(*last_refill) / 10;
    *budget = budget.saturating_add(refill).min(32);
    *last_refill = last_refill.saturating_add(refill.saturating_mul(10));
    let count = addresses.len().min(usize::try_from(*budget).unwrap_or(0));
    *budget = budget.saturating_sub(u64::try_from(count).unwrap_or(0));
    if let Some(book) = &shared.address_book {
        book.learn_peer(peer_addr.ip(), &addresses[..count], now);
    }
}

/// Handles one `cmpctblock`/`blocktxn` wire message for a connection. A
/// compact announcement is itself a tip announcement: its embedded header
/// is offered to admission even when reconstruction pends or falls back,
/// so the announced tip reaches the tree and the ordinary window
/// machinery can fetch the body.
///
/// PRE: `message` came from the connection that `lease` identifies.
/// POST: Forward the outcome through `shared`: a finished block to the
/// block sink, a follow-up request to the same connection.
/// INVARIANT: A header forward marks `body_fetch_owned` exactly when the
/// outcome itself fetches the body, and is never a `headers` response.
fn process_compact_wire_message(
    message: &crate::Message,
    compact_reconstruction: &mut crate::compact_blocks::Reconstruction,
    local_compact_version: Option<u64>,
    compact_hints: Option<&dyn crate::compact_blocks::CompactBlockHints>,
    lease: &crate::PeerLease,
    peer_addr: SocketAddr,
    shared: &ConnectionShared,
) {
    let identity_version =
        local_compact_version.unwrap_or(crate::compact_blocks::COMPACT_BLOCK_VERSION);
    let outcome = process_compact_message(
        compact_reconstruction,
        message,
        identity_version,
        compact_hints,
        Instant::now(),
    );
    // A compact announcement is itself a tip announcement: when the outcome
    // emits no body (`Complete` already forwards its header via `send_block`),
    // this forward is the only path the embedded header takes to admission.
    let announced_header = if let crate::Message::CmpctBlock(cmpct) = message
        && !matches!(outcome, crate::compact_blocks::Outcome::Complete(_))
    {
        crate::compact_blocks::native_header(&cmpct.compact_block.header)
    } else {
        None
    };
    // When the outcome itself fetches the body (`RequestMissing` issues
    // a `getblocktxn`, `Fallback` a full-block `getdata`), the window
    // must record that in-flight fetch instead of scheduling a
    // duplicate request for the freshly admitted tip.
    let body_fetch_owned = matches!(
        outcome,
        crate::compact_blocks::Outcome::RequestMissing(_)
            | crate::compact_blocks::Outcome::Fallback(_)
    );
    // Ownership — the header's `body_fetch_owned` flag and the scheduler
    // mark alike — is recorded only once the follow-up request actually
    // left on the connection: a failed send enqueues nothing, and marking
    // either path anyway would suppress recovery of that block from
    // another peer.
    let fetch_issued = handle_compact_outcome(outcome, lease, peer_addr, shared);
    if let Some(header) = announced_header {
        let fetch_owned = body_fetch_owned && fetch_issued;
        shared.send_headers(lease.source(peer_addr), vec![header], false, fetch_owned);
        if fetch_owned && let Some(sync) = shared.block_sync.as_ref() {
            sync.record_owned_body_fetch(
                lease.source(peer_addr),
                bitcoin_rs_primitives::Hash256::from(header.compute_hash()),
            );
        }
    }
}

/// Applies one BIP152 receive-side outcome: a finished block enters the
/// ordinary block sink exactly like a `block` message, a missing list
/// becomes a `getblocktxn` request on the same connection, and an
/// unrecoverable reconstruction falls back to one full-block `getdata` —
/// the node's download window resolves both by hash on arrival, so no
/// request ownership is lost or duplicated.
///
/// PRE: `outcome` came from a message of the connection `lease` identifies.
/// POST: A finished block reaches `shared`'s block sink; a follow-up goes to
/// the same connection.
/// INVARIANT: A refused follow-up is dropped with a debug log; it never
/// ends the connection here.
fn handle_compact_outcome(
    outcome: crate::compact_blocks::Outcome,
    lease: &crate::PeerLease,
    peer_addr: SocketAddr,
    shared: &ConnectionShared,
) -> bool {
    let mut fetch_issued = false;
    let mut follow_up = |message: crate::Message| match lease.send(message) {
        Ok(()) => fetch_issued = true,
        Err(error) => {
            tracing::debug!(peer_addr = %peer_addr, %error, "p2p compact-block follow-up dropped");
        }
    };
    match outcome {
        crate::compact_blocks::Outcome::Complete(block) => {
            let serialized = bitcoin_rs_primitives::consensus_bytes(&block);
            tracing::info!(peer_addr = %peer_addr, hash = %block.block_hash(), "p2p compact block reconstructed");
            shared.send_block(lease, peer_addr, block, serialized.into());
        }
        crate::compact_blocks::Outcome::RequestMissing(request) => {
            tracing::info!(peer_addr = %peer_addr, "p2p compact reconstruction missing");
            follow_up(crate::Message::GetBlockTxn(request));
        }
        crate::compact_blocks::Outcome::Fallback(hash) => {
            tracing::info!(peer_addr = %peer_addr, "p2p compact reconstruction fallback");
            follow_up(crate::Message::GetData(vec![
                bitcoin::p2p::message_blockdata::Inventory::WitnessBlock(
                    bitcoin::BlockHash::from_byte_array(*hash.as_bytes()),
                ),
            ]));
        }
        crate::compact_blocks::Outcome::Idle => {}
    }
    fetch_issued
}

/// Feeds one receive-side BIP152 message into the loop's reconstruction
/// state and returns the outcome.
fn process_compact_message(
    reconstruction: &mut crate::compact_blocks::Reconstruction,
    message: &crate::Message,
    identity_version: u64,
    compact_hints: Option<&dyn crate::compact_blocks::CompactBlockHints>,
    now: std::time::Instant,
) -> crate::compact_blocks::Outcome {
    match message {
        crate::Message::CmpctBlock(cmpct) => match compact_hints {
            Some(hints) => reconstruction.receive_cmpctblock(cmpct, identity_version, hints, now),
            None => crate::compact_blocks::Outcome::Fallback(
                crate::compact_blocks::native_block_hash(cmpct.compact_block.header.block_hash()),
            ),
        },
        crate::Message::BlockTxn(txns) => reconstruction.receive_blocktxn(txns, now),
        _ => crate::compact_blocks::Outcome::Idle,
    }
}

/// Spawns a per-connection writer thread that drains queued outbound messages
/// and writes them to the peer. Decoupling writes from the blocking inbound
/// read ensures a momentarily silent peer can never delay outbound sends (the
/// next `getdata` during IBD). Exits on the lease close signal, when every
/// sender drops, or on write failure. Every exit shuts down the socket so the
/// reader half cannot outlive a failed writer.
///
/// PRE: `stream` is a clone of the connection's counted stream, and
/// `outbound_rx`, `close_rx`, and `budget` belong to the same lease.
/// `net_trace` is the connection's probe context, `None` on probe-free
/// connections.
/// POST: Return the writer thread's handle, or the spawn error.
/// INVARIANT: The counted stream accounts every sent byte once.
fn spawn_connection_writer(
    mut stream: crate::CountingStream<TcpStream>,
    magic: Magic,
    outbound_rx: crossbeam_channel::Receiver<crate::Message>,
    close_rx: crossbeam_channel::Receiver<()>,
    budget: Arc<crate::connection::OutboundBudget>,
    peer_addr: SocketAddr,
    net_trace: Option<crate::net_trace::NetTrace>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name(format!("bitcoin-rs-p2p-writer-{peer_addr}"))
        .spawn(move || {
            run_writer_loop(
                &outbound_rx,
                close_rx,
                &budget,
                &mut stream,
                magic,
                net_trace.as_ref(),
            );
            let _ = stream.shutdown(std::net::Shutdown::Both);
        })
}

/// Drains ready control messages behind `first` into one writev burst.
///
/// A bulk payload is never coalesced: it returns as a leftover so the writer
/// emits it as its own frame after the control burst (or immediately when it
/// is `first`).
fn collect_write_burst(
    first: crate::Message,
    outbound_rx: &crossbeam_channel::Receiver<crate::Message>,
) -> (Vec<crate::Message>, Option<crate::Message>) {
    if first.is_bulk_payload() {
        return (vec![first], None);
    }
    let mut burst = Vec::with_capacity(crate::wire::MAX_WRITE_BURST);
    burst.push(first);
    while burst.len() < crate::wire::MAX_WRITE_BURST {
        match outbound_rx.try_recv() {
            Ok(next) if next.is_bulk_payload() => return (burst, Some(next)),
            Ok(next) => burst.push(next),
            Err(_) => break,
        }
    }
    (burst, None)
}

/// Releases the outbound budget for each successfully written frame.
///
/// PRE: `sizes` holds the full wire length of each written frame, as
/// `write_frames` returned it.
/// POST: The budget releases exactly those byte counts.
/// INVARIANT: This function counts no bytes; the counted stream owns byte
/// accounting.
fn account_written(sizes: &[usize], budget: &Arc<crate::connection::OutboundBudget>) {
    for &bytes in sizes {
        budget.release(bytes);
    }
}

/// Writes `first` and any immediately ready follow-up control messages.
///
/// Returns `false` when a write fails so the caller can exit the writer loop.
///
/// PRE: `budget` admitted `first` and every message queued behind it.
/// POST: Each written frame releases its budget charge; a failed write
/// returns `false` and releases nothing.
/// INVARIANT: A bulk payload is never coalesced into a control burst.
fn write_ready_burst(
    first: crate::Message,
    outbound_rx: &crossbeam_channel::Receiver<crate::Message>,
    writer: &mut dyn std::io::Write,
    magic: Magic,
    budget: &Arc<crate::connection::OutboundBudget>,
    net_trace: Option<&crate::net_trace::NetTrace>,
) -> bool {
    let mut pending = Some(first);
    while let Some(head) = pending.take() {
        let (burst, leftover) = collect_write_burst(head, outbound_rx);
        let frames = match crate::wire::encode_frames(magic, &burst) {
            Ok(frames) => frames,
            Err(error) => {
                tracing::debug!(%error, "p2p writer thread exiting");
                return false;
            }
        };
        for (message, frame) in burst.iter().zip(&frames) {
            crate::net_trace::outbound_message(net_trace, message, frame.payload());
        }
        match crate::wire::write_frames(writer, &frames) {
            Ok(sizes) => {
                account_written(&sizes, budget);
                pending = leftover;
            }
            Err(error) => {
                tracing::debug!(%error, "p2p writer thread exiting");
                return false;
            }
        }
    }
    true
}

/// Writer loop body shared by the spawned writer thread and deterministic
/// tests: receives one message or the close signal, coalesces a ready burst
/// of control messages into one writev, and releases the admitted full wire
/// byte count after a successful burst. Exits on the close signal, sender
/// drop, or write error — never by polling. On a write error the budget is
/// deliberately not released (the connection is dying).
///
/// PRE: `outbound_rx`, `close_rx`, and `budget` belong to one lease.
/// POST: Return after the close signal, the last sender drop, or a write
/// error.
/// INVARIANT: The writer counts no bytes; the stream it writes to owns byte
/// accounting.
fn run_writer_loop(
    outbound_rx: &crossbeam_channel::Receiver<crate::Message>,
    mut close_rx: crossbeam_channel::Receiver<()>,
    budget: &Arc<crate::connection::OutboundBudget>,
    writer: &mut dyn std::io::Write,
    magic: Magic,
    net_trace: Option<&crate::net_trace::NetTrace>,
) {
    loop {
        crossbeam_channel::select! {
            recv(outbound_rx) -> message => {
                let Ok(first) = message else { break };
                if !write_ready_burst(first, outbound_rx, writer, magic, budget, net_trace) {
                    break;
                }
            }
            recv(close_rx) -> signal => {
                if signal.is_ok() {
                    break;
                }
                close_rx = crossbeam_channel::never();
            }
        }
    }
}

/// Forwards a decoded transaction into ingress while the relay gate is open.
///
/// PRE: `relay_open` was read from the node-owned IBD handle for this
/// message. POST: a closed gate enqueues no body and never punishes the peer.
/// INVARIANT: the gate is read per message, so opening it needs no reconnect.
fn forward_tx_if_relay_open(
    shared: &ConnectionShared,
    source: crate::PeerSource,
    tx: bitcoin_rs_primitives::Tx,
    peer_addr: SocketAddr,
    relay_open: bool,
) {
    if relay_open {
        shared.send_tx(source, tx);
    } else {
        tracing::debug!(peer_addr = %peer_addr, "tx dropped: initial block download");
    }
}

fn wake_sync(sync_wake_tx: Option<&Sender<()>>) {
    if let Some(tx) = sync_wake_tx {
        let _ = tx.try_send(());
    }
}

fn generate_nonce(peer_addr: SocketAddr) -> u64 {
    use std::hash::{BuildHasher, Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let random_state = std::collections::hash_map::RandomState::new();
    let mut hasher = random_state.build_hasher();
    peer_addr.hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    if let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) {
        duration.hash(&mut hasher);
    }
    hasher.finish()
}

/// Wiring for unit tests: an active network, a start token that stays
/// `false`, no bans, no ready callback, no node handles, and mainnet magic.
#[cfg(test)]
fn test_shared(
    peer_table: Arc<crate::PeerTable>,
    headers_tx: Sender<crate::InboundHeaders>,
    blocks_tx: Sender<crate::InboundBlock>,
) -> ConnectionShared {
    ConnectionShared::new(
        peer_table,
        crate::BannedReader::fixture_empty(),
        Arc::new(crate::NetworkActivity::from_shared(Arc::new(
            AtomicBool::new(true),
        ))),
        bitcoin_rs_chain::LatchReader::new(Arc::new(AtomicBool::new(false))),
        None,
        Magic::BITCOIN,
        headers_tx,
        blocks_tx,
        None,
        None,
        ListenerExtras::default(),
    )
}

#[cfg(test)]
mod transaction_poll_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct InventoryReads(AtomicUsize);
    impl crate::TxInventory for InventoryReads {
        fn have_tx(&self, _: bitcoin_rs_primitives::Hash256, _: bool) -> bool {
            self.0.fetch_add(1, Ordering::Relaxed);
            false
        }
        fn get_tx(&self, _: bitcoin_rs_primitives::Txid) -> Option<bitcoin_rs_primitives::Tx> {
            None
        }
        fn get_tx_by_wtxid(
            &self,
            _: bitcoin_rs_primitives::Wtxid,
        ) -> Option<bitcoin_rs_primitives::Tx> {
            None
        }
    }

    #[test]
    fn ping_and_nontransaction_messages_do_not_poll_gateway_inventory() {
        let table = Arc::new(crate::PeerTable::new());
        let (sender, receiver) = crossbeam_channel::bounded(4);
        let lease = crate::PeerLease::new(sender);
        let addr = ([127, 0, 0, 1], 8333).into();
        table.register(addr, lease.clone());
        let version = crate::handshake::version_message(
            1,
            0,
            crate::PeerRole::FullRelay,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        );
        table.publish_info(
            addr,
            &lease,
            crate::PeerInfo::outbound_from_version(
                addr,
                addr,
                &version,
                0,
                0,
                Arc::new(crate::PeerCounters::default()),
            ),
        );
        let source = lease.source(addr);
        let item = bitcoin::p2p::message_blockdata::Inventory::WTx(
            bitcoin::Wtxid::from_byte_array([1; 32]),
        );
        table.announce_transactions(source, &[item]);
        let (headers, _) = crossbeam_channel::bounded(1);
        let (blocks, _) = crossbeam_channel::bounded(1);
        let mut shared = test_shared(table, headers, blocks);
        let inventory = Arc::new(InventoryReads(AtomicUsize::new(0)));
        shared.tx_inventory = Some(inventory.clone());
        for nonce in 0..1_000 {
            shared.update_transaction_requests(source, &crate::Message::Ping(nonce));
            shared.update_transaction_requests(source, &crate::Message::Headers(Vec::new()));
            shared.update_transaction_requests(
                source,
                &crate::Message::Inv(vec![bitcoin::p2p::message_blockdata::Inventory::Block(
                    bitcoin::BlockHash::from_byte_array([2; 32]),
                )]),
            );
        }
        assert_eq!(inventory.0.load(Ordering::Relaxed), 0);
        assert!(receiver.try_recv().is_err());
        shared.update_transaction_requests(source, &crate::Message::Inv(vec![item]));
        assert_eq!(
            inventory.0.load(Ordering::Relaxed),
            2,
            "one background and one pre-send identity check"
        );
        assert!(matches!(
            receiver.try_recv(),
            Ok(crate::Message::GetData(_))
        ));
    }
}

#[cfg(test)]
mod outbound_tests {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::Arc;

    use super::{spawn_outbound_connection, spawn_pinned_outbound_connection, test_shared};
    use crate::PeerTable;
    use crate::peer_info::PeerRole;

    #[test]
    fn spawn_outbound_connection_to_closed_port_fails_quickly()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let addr = listener.local_addr()?;
        drop(listener);

        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(Arc::new(PeerTable::new()), headers_tx, blocks_tx);

        let handle = spawn_outbound_connection(addr, shared, PeerRole::FullRelay);
        let inner = match handle.join() {
            Ok(inner) => inner,
            Err(error) => std::panic::resume_unwind(error),
        };

        assert!(
            inner.is_err(),
            "expected connection failure to unlistened port"
        );

        Ok(())
    }

    /// An outbound dial entry point: either origin the service can choose.
    type Dial = fn(
        SocketAddr,
        crate::listener::ConnectionShared,
        PeerRole,
    ) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>>;

    /// Register one outbound dial against a listener that accepts and then
    /// hangs up, so the handshake stalls exactly where the lease is already
    /// published, and return that session.
    #[expect(
        clippy::expect_used,
        reason = "a helper that cannot build its fixture has nothing to report"
    )]
    fn registered_session(dial: Dial) -> crate::peer_table::PeerSession {
        use std::time::{Duration, Instant};

        let listener =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let addr = listener.local_addr().expect("listener address");

        let table = Arc::new(PeerTable::new());
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(Arc::clone(&table), headers_tx, blocks_tx);
        let handle = dial(addr, shared, PeerRole::FullRelay);

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut accepted = None;
        let session = loop {
            accepted = accepted.or_else(|| listener.accept().ok().map(|(stream, _)| stream));
            if let Some(session) = table.sessions().into_iter().find(|s| s.addr == addr) {
                break session;
            }
            assert!(Instant::now() < deadline, "the dial never registered");
            std::thread::sleep(Duration::from_millis(5));
        };
        drop(accepted.take());
        let _ = handle.join();
        session
    }

    /// The eviction rules read the dial origin off the lease, so it must
    /// survive from the entry point that chose it: a pinned dial carries
    /// Core's `ConnectionType::MANUAL`, an automatic dial does not.
    #[test]
    fn the_dial_origin_survives_to_the_lease() {
        let pinned = registered_session(spawn_pinned_outbound_connection);
        assert!(
            pinned.lease.is_manual(),
            "a dial the operator named must be marked manual"
        );
        assert_eq!(pinned.lease.role(), PeerRole::FullRelay);

        let automatic = registered_session(spawn_outbound_connection);
        assert!(
            !automatic.lease.is_manual(),
            "a dial the seed list produced is not the operator's"
        );
        assert_eq!(automatic.lease.role(), PeerRole::FullRelay);
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod relay_role_tests {
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_blockdata::Inventory;

    use super::enforce_relay_role;
    use crate::peer_info::PeerRole;
    use crate::wire::{Message, PeerError};

    fn tx_inv() -> Message {
        Message::Inv(vec![Inventory::Transaction(
            bitcoin::Txid::from_byte_array([7; 32]),
        )])
    }

    /// The role gate disconnects a transaction announcement, keeps block
    /// traffic, ignores address gossip, and never restricts a full-relay
    /// connection.
    #[test]
    fn relay_role_gate_splits_transaction_and_block_traffic() {
        let error = enforce_relay_role(PeerRole::BlockRelayOnly, tx_inv())
            .expect_err("a transaction announcement is a protocol violation");
        assert!(matches!(
            error,
            PeerError::Protocol("transaction inv sent in violation of protocol")
        ));

        let block_inv = Message::Inv(vec![Inventory::Block(bitcoin::BlockHash::from_byte_array(
            [8; 32],
        ))]);
        let kept = enforce_relay_role(PeerRole::BlockRelayOnly, block_inv)
            .expect("a block announcement is not a fault");
        assert!(kept.is_some(), "block traffic reaches the scheduler");

        let kept = enforce_relay_role(PeerRole::FullRelay, tx_inv())
            .expect("a full-relay connection is unrestricted");
        assert!(kept.is_some(), "transaction traffic is dispatched");

        let dropped = enforce_relay_role(PeerRole::BlockRelayOnly, Message::Addr(Vec::new()))
            .expect("address gossip is not a fault");
        assert!(
            dropped.is_none(),
            "address gossip is dropped unheard on a block-relay connection"
        );
    }
}

#[cfg(test)]
mod sync_wake_tests {
    use super::wake_sync;

    #[test]
    fn sync_wake_is_bounded_and_nonblocking() {
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);

        wake_sync(Some(&wake_tx));
        wake_sync(Some(&wake_tx));

        assert_eq!(wake_rx.try_iter().count(), 1);
    }
}

#[cfg(test)]
static ACCEPT_ERROR_INJECT: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
#[expect(clippy::expect_used)]
mod session_socket_tests {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};

    use crate::socket::{HANDSHAKE_TIMEOUT, STREAM_POLL_INTERVAL, configure_peer_stream};

    #[test]
    fn session_sockets_disable_nagle() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");

        configure_peer_stream(&client).expect("configure client");
        configure_peer_stream(&server).expect("configure server");

        assert!(client.nodelay().expect("client nodelay"));
        assert!(server.nodelay().expect("server nodelay"));
        assert_eq!(
            client.read_timeout().expect("client read timeout"),
            Some(STREAM_POLL_INTERVAL)
        );
        assert_eq!(
            server.write_timeout().expect("server write timeout"),
            Some(HANDSHAKE_TIMEOUT)
        );
    }
}

#[cfg(test)]
static WRITER_SETUP_FAIL: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
#[expect(clippy::expect_used)]
mod resilient_accept_tests {
    use std::net::{Ipv4Addr, SocketAddr, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::{ACCEPT_ERROR_INJECT, bind_listener, serve, test_shared};

    /// A transient accept error must not kill the listener thread — the loop
    /// logs, backs off, and continues until shutdown.
    #[test]
    fn serve_survives_transient_accept_error() {
        let listener =
            bind_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind listener");
        let addr = listener.local_addr().expect("local_addr");

        let shutdown = Arc::new(AtomicBool::new(false));
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);

        ACCEPT_ERROR_INJECT.store(true, Ordering::Relaxed);

        let thread_shutdown = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || serve(listener, thread_shutdown, shared));

        std::thread::sleep(Duration::from_millis(300));

        // The listener must still be alive — connect a real client to prove it.
        let _client = TcpStream::connect(addr).expect("listener should still accept");

        shutdown.store(true, Ordering::Relaxed);
        let result = handle.join().expect("listener thread panicked");
        assert!(
            result.is_ok(),
            "serve must return Ok after shutdown, got {result:?}"
        );
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod inbound_admission_tests {
    use std::io::Read;
    use std::net::{Ipv4Addr, SocketAddr, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::{bind_listener, serve, test_shared};
    use crate::PeerTable;

    #[test]
    fn inbound_admission_over_cap_drops_stream() -> Result<(), Box<dyn std::error::Error>> {
        let listener = bind_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let addr = listener.local_addr()?;
        let peer_table = Arc::new(PeerTable::new());
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let mut shared = test_shared(Arc::clone(&peer_table), headers_tx, blocks_tx);
        shared.max_inbound = 1;

        let shutdown = Arc::new(AtomicBool::new(false));
        let serve_shutdown = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || serve(listener, serve_shutdown, shared));

        let _first = TcpStream::connect(addr)?;
        let mut second = TcpStream::connect(addr)?;
        let second_addr = second.local_addr()?;
        // The refusal closes the socket as part of the same accept step that
        // admitted the first, so the EOF is the synchronization point. The
        // read bound only guards a hang: an admitted socket would sit in the
        // handshake read for the full `HANDSHAKE_TIMEOUT` (10 s) first.
        second.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut byte = [0u8; 1];
        let read = second.read(&mut byte)?;
        assert_eq!(
            read, 0,
            "the over-capacity socket must be closed by the listener"
        );
        assert_eq!(
            peer_table.live_inbound_count(),
            1,
            "the admitted socket keeps its reservation"
        );
        assert!(
            !peer_table.is_connected(second_addr),
            "the refused socket registered no lease"
        );

        shutdown.store(true, Ordering::Relaxed);
        handle.join().expect("listener thread panicked")?;
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod writer_setup_cleanup_tests {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use bitcoin::p2p::Magic;

    use super::{WRITER_SETUP_FAIL, run_connected_session, test_shared};
    use crate::peer::Peer;

    fn peer_info(addr: SocketAddr, conn_time: u64) -> crate::PeerInfo {
        crate::PeerInfo {
            addr,
            version: 70_016,
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            services: 0,
            user_agent: String::from("/test/"),
            start_height: 0,
            best_known_height: 0,
            conn_time,
            inbound: false,
            addr_bind: addr,
            time_offset: 0,
            counters: Arc::new(crate::PeerCounters::default()),
        }
    }

    #[test]
    fn writer_setup_failure_cleans_up_lease() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let client = TcpStream::connect(addr).expect("connect");
        let (server_stream, peer_addr) = listener.accept().expect("accept");
        drop(server_stream);

        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);

        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(outbound_tx);
        let lease_probe = lease.clone();
        shared.peer_table.register(peer_addr, lease.clone());

        // Lease must be registered before the failure.
        assert!(
            shared.peer_table.is_connected(peer_addr),
            "lease must be registered before writer setup"
        );

        WRITER_SETUP_FAIL.store(true, Ordering::Relaxed);

        let counters = std::sync::Arc::new(crate::PeerCounters::default());
        let stream = crate::CountingStream::new(client, counters);
        let mut peer = Peer::new(stream, Magic::BITCOIN);
        let info = peer_info(peer_addr, 0);
        let result = run_connected_session(&mut peer, peer_addr, &shared, lease, outbound_rx, info);

        assert!(result.is_err(), "writer setup failure must return Err");
        assert!(
            shared.peer_table.is_empty(),
            "peer_table must be cleaned up after writer setup failure"
        );
        assert!(
            lease_probe.is_cancelled(),
            "writer setup failure must cancel the registered lease"
        );
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod writer_shutdown_tests {
    use std::cell::Cell;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use bitcoin::p2p::Magic;

    use super::{
        collect_write_burst, run_connected_session, run_message_loop, run_writer_loop,
        spawn_connection_writer, test_shared,
    };
    use crate::connection::OutboundBudget;
    use crate::peer::{Peer, PeerState};

    const FAILSAFE: Duration = Duration::from_secs(5);

    // CONTRACT: docs/policies/p2p-compatibility.md#5-message-surface (a
    // handshake failure on a live lease surfaces its protocol error; only an
    // externally revoked lease is muted as a shutdown).
    #[test]
    fn inbound_handshake_failure_on_live_lease_returns_err() {
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(
            Arc::new(crate::PeerTable::new()),
            headers_tx,
            crossbeam_channel::unbounded().0,
        );
        let (mut client, server, peer_addr) = loopback_pair();

        // A validly framed message with a foreign magic fails the handshake
        // while the lease is fully live: nothing external revoked it. The
        // revocation mask (remove_current cancels) must not swallow this.
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33]);
        frame.extend_from_slice(b"version\0\0\0\0\0");
        frame.extend_from_slice(&0_u32.to_le_bytes());
        frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        io::Write::write_all(&mut client, &frame).expect("frame write");
        drop(client);

        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new_inbound(outbound_tx);
        let lease = shared
            .peer_table
            .try_register_inbound(peer_addr, lease, 1, &shared.activity)
            .expect("the test lease reserves its inbound slot");
        let result = crate::listener::run_handshake(server, peer_addr, &shared, lease, outbound_rx);
        let Err(error) = result else {
            panic!("handshake failure on a live lease must not be masked as revoked");
        };
        assert!(
            error.to_string().contains("magic"),
            "unexpected handshake error: {error}"
        );
    }

    fn loopback_pair() -> (TcpStream, TcpStream, SocketAddr) {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, peer_addr) = listener.accept().expect("accept");
        (client, server, peer_addr)
    }

    fn ping_len() -> usize {
        crate::wire::wire_len(&crate::Message::Ping(9)).expect("ping encodes")
    }

    fn peer_info(addr: SocketAddr, start_height: i32) -> crate::PeerInfo {
        crate::PeerInfo {
            addr,
            version: 70_016,
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            services: 1,
            user_agent: String::from("/test/"),
            start_height,
            conn_time: 0,
            best_known_height: start_height,
            inbound: false,
            addr_bind: addr,
            time_offset: 0,
            counters: std::sync::Arc::new(crate::PeerCounters::default()),
        }
    }

    #[test]
    fn sinks_stamp_exact_connection_source() -> Result<(), Box<dyn std::error::Error>> {
        let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, blocks_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_443));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let block_bytes = bitcoin::consensus::encode::serialize(&genesis);
        let block =
            bitcoin_rs_primitives::deserialize::<bitcoin_rs_primitives::Block>(&block_bytes)
                .map_err(|_| std::io::Error::other("genesis block must decode"))?;
        let serialized = bytes::Bytes::from(block_bytes);
        let source = lease.source(addr);

        shared.send_headers(source, Vec::new(), true, false);
        shared.send_block(&lease, addr, block, serialized.clone());

        assert_eq!(headers_rx.try_recv()?.source, Some(source));
        let received = blocks_rx.try_recv()?;
        assert_eq!(received.source, Some(source));
        assert_eq!(received.serialized, serialized);
        Ok(())
    }

    #[test]
    fn send_block_forwards_the_blocks_header() -> Result<(), Box<dyn std::error::Error>> {
        // Every inbound body carries its own header; `send_block` must also
        // emit it through the headers sink so body-only announcements
        // (`inv`-served, compact reconstruction, pushes) reach admission.
        let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_449));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let block_bytes = bitcoin::consensus::encode::serialize(&genesis);
        let block =
            bitcoin_rs_primitives::deserialize::<bitcoin_rs_primitives::Block>(&block_bytes)
                .map_err(|_| std::io::Error::other("genesis block must decode"))?;
        let header = block.header;
        let source = lease.source(addr);

        shared.send_block(&lease, addr, block, bytes::Bytes::from(block_bytes));

        let forwarded = headers_rx.try_recv()?;
        assert_eq!(forwarded.source, Some(source));
        assert_eq!(forwarded.headers, vec![header]);
        assert!(
            !forwarded.wire_response,
            "a body-carried header is not a getheaders response"
        );
        Ok(())
    }

    #[test]
    fn send_block_unblocks_when_session_is_cancelled() -> Result<(), Box<dyn std::error::Error>> {
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, blocks_rx) = crossbeam_channel::bounded(1);
        let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);
        let session_cancel = shared.session_cancel.clone();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_448));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let first_bytes = bitcoin::consensus::encode::serialize(&genesis);
        let first =
            bitcoin_rs_primitives::deserialize::<bitcoin_rs_primitives::Block>(&first_bytes)
                .map_err(|_| std::io::Error::other("genesis block must decode"))?;
        let second_bytes = first_bytes.clone();
        let second =
            bitcoin_rs_primitives::deserialize::<bitcoin_rs_primitives::Block>(&second_bytes)
                .map_err(|_| std::io::Error::other("genesis block must decode"))?;
        shared.send_block(&lease, addr, first, bytes::Bytes::from(first_bytes));

        let blocked = std::thread::spawn(move || {
            shared.send_block(&lease, addr, second, bytes::Bytes::from(second_bytes));
        });
        let started = std::time::Instant::now();
        while !blocked.is_finished() && started.elapsed() < Duration::from_millis(250) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !blocked.is_finished(),
            "full inbound block channel must block until cancel"
        );
        session_cancel.store(true);
        blocked
            .join()
            .map_err(|_| std::io::Error::other("send_block thread panicked"))?;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "cancelled send_block must not wait on the full queue"
        );
        drop(blocks_rx);
        Ok(())
    }

    #[test]
    fn message_loop_exits_before_read_when_cancelled() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_444));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        lease.cancel();
        let mut peer = Peer::new(
            ScriptedStream {
                script: io::Cursor::new(Vec::new()),
            },
            Magic::BITCOIN,
        );
        peer.state = PeerState::Ready;

        let shared = test_shared(
            Arc::new(crate::PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        assert!(run_message_loop(&mut peer, addr, &lease, &shared, None).is_ok());
    }

    #[test]
    fn message_loop_exits_after_replacement_during_read() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_445));
        let table = Arc::new(crate::PeerTable::new());
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = crate::PeerLease::new(old_tx);
        table.register(addr, old.clone());
        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = crate::PeerLease::new(replacement_tx);
        table.register(addr, replacement.clone());

        let mut wire = Vec::new();
        crate::wire::write_message(
            &mut wire,
            Magic::BITCOIN,
            &crate::Message::Headers(Vec::new()),
        )
        .expect("headers encodes");
        let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
        let shared = test_shared(
            Arc::clone(&table),
            headers_tx,
            crossbeam_channel::unbounded().0,
        );
        let mut peer = Peer::new(
            ScriptedStream {
                script: io::Cursor::new(wire),
            },
            Magic::BITCOIN,
        );
        peer.state = PeerState::Ready;

        assert!(run_message_loop(&mut peer, addr, &old, &shared, None).is_ok());
        assert!(headers_rx.try_recv().is_err());
        assert!(old.is_cancelled());
        assert!(table.is_current(replacement.source(addr)));
    }

    /// Drives one scripted `sendcmpct` through the message loop on a fresh
    /// table and reports the published relay preference afterwards.
    fn sendcmpct_scenario(send_compact: bool, version: u64, port: u16) -> bool {
        let mut wire = Vec::new();
        crate::wire::write_message(
            &mut wire,
            Magic::BITCOIN,
            &crate::Message::SendCmpct(bitcoin::p2p::message_compact_blocks::SendCmpct {
                send_compact,
                version,
            }),
        )
        .expect("sendcmpct encodes");
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let table = Arc::new(crate::PeerTable::new());
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        table.register(addr, lease.clone());
        assert!(table.publish_info(
            addr,
            &lease,
            crate::PeerInfo {
                addr,
                version: 70_016,
                wtxid_relay: false,
                relay_transactions: true,
                compact_block_relay: false,
                send_headers: false,
                services: 0,
                user_agent: String::from("/test/"),
                start_height: 0,
                best_known_height: 0,
                conn_time: 0,
                inbound: false,
                addr_bind: addr,
                time_offset: 0,
                counters: std::sync::Arc::new(crate::PeerCounters::default()),
            },
        ));
        let mut peer = Peer::new(ScriptedEof(io::Cursor::new(wire)), Magic::BITCOIN);
        peer.state = PeerState::Ready;
        let shared = test_shared(
            Arc::clone(&table),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        assert!(run_message_loop(&mut peer, addr, &lease, &shared, None).is_err());
        table.compact_relay_of(addr)
    }

    #[test]
    fn sendcmpct_raises_published_compact_relay_preference() {
        // A post-verack sendcmpct announces BIP152 relay, with or without the
        // high-bandwidth push preference: an inbound peer is never selected
        // for push, and fetch eligibility must not depend on it.
        assert!(sendcmpct_scenario(true, 2, 18_448));
        assert!(sendcmpct_scenario(false, 2, 18_449));
        assert!(!sendcmpct_scenario(false, 1, 18_450));
        assert!(!sendcmpct_scenario(false, 7, 18_451));
    }

    /// Serves the scripted bytes, then ends the connection with a clean
    /// EOF so the message loop exits without the idle timeout.
    struct ScriptedEof(io::Cursor<Vec<u8>>);

    impl io::Read for ScriptedEof {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match io::Read::read(&mut self.0, buf)? {
                0 => Err(io::ErrorKind::UnexpectedEof.into()),
                read => Ok(read),
            }
        }
    }

    impl io::Write for ScriptedEof {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct ContinuingStream(Arc<AtomicUsize>);

    impl io::Read for ContinuingStream {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            }
        }
    }

    impl io::Write for ContinuingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn message_loop_keeps_current_lease_running() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_446));
        let reads = Arc::new(AtomicUsize::new(0));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        let mut peer = Peer::new(ContinuingStream(Arc::clone(&reads)), Magic::BITCOIN);
        peer.state = PeerState::Ready;
        let shared = test_shared(
            Arc::new(crate::PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );

        assert!(run_message_loop(&mut peer, addr, &lease, &shared, None).is_err());
        assert_eq!(reads.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn message_loop_does_not_probe_a_peer_inside_one_interval() {
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(outbound_tx);
        let reads = Arc::new(AtomicUsize::new(0));
        let mut peer = Peer::new(ContinuingStream(Arc::clone(&reads)), Magic::BITCOIN);
        peer.state = PeerState::Ready;
        let shared = test_shared(
            Arc::new(crate::PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_448));

        assert!(run_message_loop(&mut peer, addr, &lease, &shared, None).is_err());
        assert!(
            matches!(
                outbound_rx.try_recv(),
                Err(crossbeam_channel::TryRecvError::Empty)
            ),
            "a peer quiet for less than one interval owes no probe",
        );
    }

    #[test]
    fn registration_cancels_replaced_lease() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_447));
        let table = crate::PeerTable::new();
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = crate::PeerLease::new(old_tx);
        table.register(addr, old.clone());
        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = crate::PeerLease::new(replacement_tx);

        assert!(table.register(addr, replacement.clone()));
        table.publish_info(addr, &replacement, peer_info(addr, 2));
        assert!(old.is_cancelled());
        assert!(table.is_current(replacement.source(addr)));
        assert_eq!(table.infos(), vec![peer_info(addr, 2)]);
    }

    #[test]
    fn stale_release_preserves_replacement_and_current_release_removes_it() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_448));
        let table = crate::PeerTable::new();
        let (stale_tx, _stale_rx) = crossbeam_channel::unbounded();
        let stale = crate::PeerLease::new(stale_tx);
        let (current_tx, _current_rx) = crossbeam_channel::unbounded();
        let current = crate::PeerLease::new(current_tx);
        table.register(addr, current.clone());
        table.publish_info(addr, &current, peer_info(addr, 2));

        assert!(!table.remove_current(addr, &stale));
        assert!(!current.is_cancelled());
        assert!(table.is_current(current.source(addr)));
        assert!(table.remove_current(addr, &current));
        assert!(current.is_cancelled());
        assert!(table.is_empty());
    }

    /// Test-only writer that admits exactly `remaining` bytes, then blocks
    /// on a channel signal instead of an OS socket buffer; the unblock
    /// failure simulates what `stream.shutdown(Both)` does to a real
    /// `write_all` mid-write.
    struct BlockingTestWriter {
        remaining: Cell<usize>,
        unblock: crossbeam_channel::Receiver<()>,
        blocked: crossbeam_channel::Sender<()>,
    }

    impl io::Write for BlockingTestWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let remaining = self.remaining.get();
            if buf.len() <= remaining {
                self.remaining.set(remaining - buf.len());
                Ok(buf.len())
            } else {
                let _ = self.blocked.try_send(());
                let _ = self.unblock.recv();
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "test: unblocked",
                ))
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Test-only writer that accepts everything and emits one event after
    /// each `write` returns, so tests synchronize on writes without polling.
    struct EventWriter {
        events: crossbeam_channel::Sender<()>,
    }

    impl io::Write for EventWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let _ = self.events.send(());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Serves one encoded message, then keeps the reader in the poll path.
    struct ScriptedStream {
        script: io::Cursor<Vec<u8>>,
    }

    impl io::Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match io::Read::read(&mut self.script, buf)? {
                0 => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                read => Ok(read),
            }
        }
    }

    impl io::Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn cancel_wakes_writer_blocked_on_empty_queue_with_live_senders() {
        let (_client, server, peer_addr) = loopback_pair();
        let writer_stream = crate::CountingStream::new(
            server.try_clone().expect("try_clone"),
            std::sync::Arc::new(crate::PeerCounters::default()),
        );
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(outbound_tx);
        let lease_probe = lease.clone();

        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let writer = spawn_connection_writer(
            writer_stream,
            Magic::BITCOIN,
            outbound_rx,
            lease.close_signal(),
            lease.budget_handle(),
            peer_addr,
            None,
        )
        .expect("spawn writer");
        let waiter = std::thread::spawn(move || {
            writer.join().expect("writer join");
            let _ = done_tx.send(());
        });

        // The queue is idle and a foreign lease clone keeps every sender
        // alive; only the close signal can wake the writer.
        lease.cancel();
        done_rx
            .recv_timeout(FAILSAFE)
            .expect("close signal must wake an idle writer with live senders");
        waiter.join().expect("waiter join");
        assert!(lease_probe.is_cancelled());
    }

    #[test]
    fn writer_mid_write_exits_on_unblock_deterministically() {
        let frame = ping_len();
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new_with_budget(
            outbound_tx,
            false,
            OutboundBudget::with_block_reserve(100, 100 * frame, 0),
        );

        for _ in 0..5 {
            lease
                .send(crate::Message::Ping(9))
                .expect("fresh queue admits a ping");
        }
        assert_eq!(lease.budget_handle().pending(), (5, 5 * frame));

        let (unblock_tx, unblock_rx) = crossbeam_channel::bounded(1);
        let (blocked_tx, blocked_rx) = crossbeam_channel::bounded(1);
        let mut writer = BlockingTestWriter {
            remaining: Cell::new(2 * frame),
            unblock: unblock_rx,
            blocked: blocked_tx,
        };
        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let budget = lease.budget_handle();
        let close_rx = lease.close_signal();
        let net_trace = crate::net_trace::NetTrace::outbound(
            9,
            "127.0.0.1:18444".parse().expect("valid socket address"),
            crate::peer_info::PeerRole::BlockRelayOnly,
            false,
        );
        let worker = std::thread::spawn(move || {
            run_writer_loop(
                &outbound_rx,
                close_rx,
                &budget,
                &mut writer,
                Magic::BITCOIN,
                Some(&net_trace),
            );
            let _ = done_tx.send(());
        });

        // Five pings are queued as one control burst. Two full frames (64 B)
        // succeed; the third header exceeds the remaining budget and the
        // burst fails as a unit, so nothing is released.
        blocked_rx
            .recv_timeout(FAILSAFE)
            .expect("writer must exhaust its byte budget");
        assert_eq!(
            lease.budget_handle().pending(),
            (5, 5 * frame),
            "a failed burst releases nothing"
        );

        lease.cancel();
        let _ = unblock_tx.send(());
        done_rx
            .recv_timeout(FAILSAFE)
            .expect("unblock must release the blocked writer");
        worker.join().expect("worker join");

        assert_eq!(lease.budget_handle().pending(), (5, 5 * frame));
    }

    #[test]
    fn writer_releases_budget_after_write() {
        let frame = ping_len();
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new_with_budget(
            outbound_tx,
            false,
            OutboundBudget::with_block_reserve(100, 100 * frame, 0),
        );
        lease
            .send(crate::Message::Ping(9))
            .expect("fresh queue admits a ping");
        assert_eq!(lease.budget_handle().pending(), (1, frame));

        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let mut writer = EventWriter { events: event_tx };
        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let budget = lease.budget_handle();
        let worker_budget = Arc::clone(&budget);
        let close_rx = lease.close_signal();
        let worker = std::thread::spawn(move || {
            run_writer_loop(
                &outbound_rx,
                close_rx,
                &worker_budget,
                &mut writer,
                Magic::BITCOIN,
                None,
            );
            let _ = done_tx.send(());
        });

        drop(lease);

        event_rx
            .recv_timeout(FAILSAFE)
            .expect("writer must emit an event after write returns");
        done_rx
            .recv_timeout(FAILSAFE)
            .expect("writer must exit after senders drop");
        worker.join().expect("worker join");

        assert_eq!(
            budget.pending(),
            (0, 0),
            "written bytes must be fully released"
        );
    }

    #[test]
    fn writer_exit_shuts_down_the_reader_socket_clone() {
        let (mut client, server, peer_addr) = loopback_pair();
        let reader_stream = server.try_clone().expect("reader clone");
        client.set_nonblocking(true).expect("nonblocking client");
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(outbound_tx);
        let writer = spawn_connection_writer(
            crate::CountingStream::new(server, std::sync::Arc::new(crate::PeerCounters::default())),
            Magic::BITCOIN,
            outbound_rx,
            lease.close_signal(),
            lease.budget_handle(),
            peer_addr,
            None,
        )
        .expect("spawn writer");

        lease.cancel();
        writer.join().expect("writer join");

        let mut byte = [0_u8; 1];
        assert_eq!(
            io::Read::read(&mut client, &mut byte).expect("shutdown must produce EOF"),
            0
        );
        drop(reader_stream);
    }

    #[test]
    fn run_connected_session_publishes_peer_relay_preference_and_joins_writer() {
        for peer_requested_wtxid in [false, true] {
            let (client, server, peer_addr) = loopback_pair();
            drop(client);

            let peer_table = Arc::new(crate::PeerTable::new());
            let (published_tx, published_rx) = crossbeam_channel::bounded(1);
            let observed_table = Arc::clone(&peer_table);
            let mut shared = test_shared(
                peer_table,
                crossbeam_channel::unbounded().0,
                crossbeam_channel::unbounded().0,
            );
            shared.peer_ready = Some(Arc::new(move |_source| {
                let requested = observed_table.infos()[0].wtxid_relay;
                let _ = published_tx.try_send(requested);
            }));

            let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
            let lease = crate::PeerLease::new(outbound_tx);
            let lease_probe = lease.clone();
            shared.peer_table.register(peer_addr, lease.clone());

            let info = crate::PeerInfo {
                addr: peer_addr,
                version: 70_016,
                wtxid_relay: false,
                relay_transactions: true,
                compact_block_relay: false,
                send_headers: false,
                services: 0,
                user_agent: String::from("/test/"),
                start_height: 0,
                best_known_height: 0,
                conn_time: 0,
                inbound: false,
                addr_bind: peer_addr,
                time_offset: 0,
                counters: std::sync::Arc::new(crate::PeerCounters::default()),
            };

            let (done_tx, done_rx) = crossbeam_channel::bounded(1);
            let worker = std::thread::spawn(move || {
                let mut peer = Peer::new(
                    crate::CountingStream::new(
                        server,
                        std::sync::Arc::new(crate::PeerCounters::default()),
                    ),
                    Magic::BITCOIN,
                );
                // Receiving wtxidrelay chooses outbound inventory; our own
                // advertisement alone must not switch the remote preference.
                if peer_requested_wtxid {
                    peer.wtxid_relay.mark_peer_supported();
                }
                let result =
                    run_connected_session(&mut peer, peer_addr, &shared, lease, outbound_rx, info);
                let _ = done_tx.send(result);
            });

            // The external clone keeps the queue's senders alive for the whole
            // call; only the teardown close signal lets the writer exit, so the
            // session must still return under the failsafe.
            let result = done_rx
                .recv_timeout(FAILSAFE)
                .expect("session must return while an external lease clone is alive");
            worker.join().expect("worker join");
            assert!(result.is_err(), "EOF on read must end the session");
            assert!(lease_probe.is_cancelled());
            assert_eq!(
                published_rx.try_recv().expect("published ready metadata"),
                peer_requested_wtxid
            );
        }
    }

    #[test]
    fn session_disconnect_updates_full_relay_and_preserves_block_relay_privacy() {
        for (block_relay, stale) in [(false, false), (true, false), (false, true)] {
            let (client, server, peer_addr) = loopback_pair();
            drop(client);

            let peer_table = Arc::new(crate::PeerTable::new());
            let mut shared = test_shared(
                peer_table,
                crossbeam_channel::unbounded().0,
                crossbeam_channel::unbounded().0,
            );
            let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), true);
            book.learn_dns("seed", &[peer_addr], 5000);
            shared.address_book = Some(Arc::clone(&book));

            let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
            let lease = if block_relay {
                crate::PeerLease::new_block_relay(outbound_tx)
            } else {
                crate::PeerLease::new(outbound_tx)
            };
            shared.peer_table.register(peer_addr, lease.clone());
            if stale {
                let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
                assert!(
                    shared
                        .peer_table
                        .register(peer_addr, crate::PeerLease::new(replacement_tx),)
                );
            }

            let info = crate::PeerInfo {
                addr: peer_addr,
                version: 70_016,
                wtxid_relay: false,
                compact_block_relay: false,
                send_headers: false,
                services: 9,
                user_agent: String::from("/test/"),
                start_height: 0,
                best_known_height: 0,
                conn_time: 0,
                inbound: false,
                addr_bind: peer_addr,
                time_offset: 0,
                counters: std::sync::Arc::new(crate::PeerCounters::default()),
            };

            let mut peer = Peer::new(
                crate::CountingStream::new(
                    server,
                    std::sync::Arc::new(crate::PeerCounters::default()),
                ),
                Magic::BITCOIN,
            );
            let _ = run_connected_session(&mut peer, peer_addr, &shared, lease, outbound_rx, info);

            let last_seen = book.gossip(10_000)[0].0;
            if block_relay || stale {
                assert_eq!(
                    last_seen, 5000,
                    "block-relay or rejected ready session must never refresh last_seen"
                );
            } else {
                assert_ne!(
                    last_seen, 5000,
                    "full-relay disconnect must refresh last_seen"
                );
            }
        }
    }

    #[test]
    fn message_loop_disconnects_saturated_peer() {
        let (outbound_tx, _outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new_with_budget(
            outbound_tx,
            false,
            OutboundBudget::new(1, ping_len()),
        );

        let mut wire = Vec::new();
        crate::wire::write_message(&mut wire, Magic::BITCOIN, &crate::Message::Ping(41))
            .expect("ping encodes");
        crate::wire::write_message(&mut wire, Magic::BITCOIN, &crate::Message::Ping(42))
            .expect("ping encodes");
        let mut peer = Peer::new(
            ScriptedStream {
                script: io::Cursor::new(wire),
            },
            Magic::BITCOIN,
        );
        peer.state = PeerState::Ready;

        let shared = test_shared(
            Arc::new(crate::PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_447));

        // The first Pong response takes the one-frame budget, so the second
        // cannot be admitted and the saturation policy cancels the lease and
        // ends the loop.
        let result = run_message_loop(&mut peer, addr, &lease, &shared, None);
        assert!(result.is_err(), "saturation must end the message loop");
        assert!(lease.is_cancelled());
    }

    #[test]
    fn collect_write_burst_coalesces_control_until_a_bulk_payload() {
        let (tx, rx) = crossbeam_channel::unbounded();
        tx.send(crate::Message::Pong(1)).expect("pong");
        tx.send(crate::Message::Block(
            bitcoin_rs_primitives::Block::default(),
        ))
        .expect("block");
        tx.send(crate::Message::Ping(2))
            .expect("later ping stays queued");

        let (burst, leftover) = collect_write_burst(crate::Message::Ping(0), &rx);
        assert_eq!(
            burst,
            vec![crate::Message::Ping(0), crate::Message::Pong(1)]
        );
        assert!(matches!(leftover, Some(crate::Message::Block(_))));
        assert!(matches!(rx.try_recv(), Ok(crate::Message::Ping(2))));
    }

    #[test]
    fn collect_write_burst_emits_a_bulk_payload_alone() {
        let (tx, rx) = crossbeam_channel::unbounded();
        tx.send(crate::Message::Ping(1)).expect("ping");
        let (burst, leftover) = collect_write_burst(
            crate::Message::Block(bitcoin_rs_primitives::Block::default()),
            &rx,
        );
        assert_eq!(burst.len(), 1);
        assert!(leftover.is_none());
        assert!(matches!(rx.try_recv(), Ok(crate::Message::Ping(1))));
    }
}

#[cfg(test)]
mod ready_notify_tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{ConnectionShared, test_shared};

    fn peer_info(addr: SocketAddr, start_height: i32) -> crate::PeerInfo {
        crate::PeerInfo {
            addr,
            version: 70_016,
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            services: 1,
            user_agent: String::from("/test/"),
            start_height,
            conn_time: 0,
            best_known_height: start_height,
            inbound: false,
            addr_bind: addr,
            time_offset: 0,
            counters: Arc::new(crate::PeerCounters::default()),
        }
    }

    #[test]
    fn manual_outbound_ready_updates_known_address_health_without_automatic_claims() {
        let mut shared = shared_with_notify_counter(&Arc::new(AtomicUsize::new(0)));
        let now = crate::addrman::now();
        let known = SocketAddr::from(([127, 0, 0, 1], 8333));
        let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), true, None);
        book.learn_dns("seed", &[known], now);
        shared.address_book = Some(Arc::clone(&book));
        let (tx, _) = crossbeam_channel::bounded(1);
        let lease = crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay);
        shared.peer_table.register(known, lease.clone());
        assert!(shared.publish_info_and_notify_ready(known, &lease, &peer_info(known, 0)));
        assert_eq!(book.gossip(now)[0].1.services.to_u64(), 1);
        assert_eq!(book.pending_count_excluding(&[]), 0);
        book.queued(known);
        assert!(shared.publish_info_and_notify_ready(known, &lease, &peer_info(known, 0)));
        assert_eq!(
            book.pending_count_excluding(&[]),
            1,
            "manual success does not transfer an existing automatic claim"
        );
        let unknown = SocketAddr::from(([127, 0, 0, 2], 8333));
        let manual = crate::PeerLease::new_manual(tx, crate::PeerRole::FullRelay);
        shared.peer_table.register(unknown, manual.clone());
        assert!(shared.publish_info_and_notify_ready(unknown, &manual, &peer_info(unknown, 0)));
        assert_eq!(book.len(), 1, "Good does not insert manual endpoints");
        assert_eq!(book.pending_count_excluding(&[]), 1);
    }

    fn shared_with_notify_counter(notified: &Arc<AtomicUsize>) -> ConnectionShared {
        let notified = Arc::clone(notified);
        let mut shared = test_shared(
            Arc::new(crate::PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        shared.peer_ready = Some(Arc::new(move |_| {
            notified.fetch_add(1, Ordering::Relaxed);
        }));
        shared
    }

    #[test]
    fn stale_predecessor_does_not_notify_peer_ready() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_450));
        let notified = Arc::new(AtomicUsize::new(0));
        let shared = shared_with_notify_counter(&notified);

        let (stale_tx, _stale_rx) = crossbeam_channel::unbounded();
        let stale = crate::PeerLease::new(stale_tx);
        let (current_tx, _current_rx) = crossbeam_channel::unbounded();
        let current = crate::PeerLease::new(current_tx);
        shared.peer_table.register(addr, stale.clone());
        shared.peer_table.register(addr, current.clone());

        assert!(
            !shared.publish_info_and_notify_ready(addr, &stale, &peer_info(addr, 1)),
            "replaced predecessor must not publish or notify"
        );
        assert_eq!(notified.load(Ordering::Relaxed), 0);
        assert_eq!(shared.peer_table.infos(), []);

        assert!(shared.publish_info_and_notify_ready(addr, &current, &peer_info(addr, 2)));
        assert_eq!(notified.load(Ordering::Relaxed), 1);
        assert_eq!(shared.peer_table.infos()[0].start_height, 2);
    }

    #[test]
    fn current_lease_publishes_then_notifies_ready() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_451));
        let notified = Arc::new(AtomicUsize::new(0));
        let shared = shared_with_notify_counter(&notified);

        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        shared.peer_table.register(addr, lease.clone());

        assert!(shared.publish_info_and_notify_ready(addr, &lease, &peer_info(addr, 3)));
        assert_eq!(notified.load(Ordering::Relaxed), 1);
        assert_eq!(shared.peer_table.infos(), vec![peer_info(addr, 3)]);
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod block_forward_tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use arc_swap::ArcSwapOption;
    use bitcoin_rs_primitives::{Hash256, consensus_bytes};
    use parking_lot::RwLock;

    use super::test_shared;
    use crate::connection::MAX_UNSOLICITED_BLOCK_FORWARDS;
    use crate::sync::BlockSync;
    use crate::sync::chain::SyncChain;
    use crate::sync::tests::{
        TestChain, connect_peer, current_source, mined_chain, synthetic_peer, test_addr,
    };
    use bitcoin_rs_chain::regtest_fixture;

    fn genesis_body() -> bitcoin_rs_primitives::Block {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let bytes = bitcoin::consensus::encode::serialize(&genesis);
        bitcoin_rs_primitives::deserialize::<bitcoin_rs_primitives::Block>(&bytes)
            .expect("regtest genesis block must decode")
    }

    /// One connection cannot fill the shared inbound block channel with bodies
    /// it was never asked for, and a body the download window owns is never
    /// dropped for that bound.
    #[test]
    fn unsolicited_block_flood_is_bounded_per_source() -> Result<(), Box<dyn std::error::Error>> {
        // Real sync wiring: peer A announces block 2 and the window asks A for
        // its body, so A's requested delivery must outlive A's exhausted
        // unsolicited credits.
        let (mut tree, blocks) = mined_chain(1, 0)?;
        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let peers = Arc::new(crate::PeerTable::new());
        let (sync_headers_tx, sync_headers_rx) = crossbeam_channel::unbounded();
        let (sync_blocks_tx, sync_blocks_rx) = crossbeam_channel::unbounded();
        let chain: Arc<dyn SyncChain> = Arc::new(TestChain::new(
            chain_tip,
            Arc::new(ArcSwapOption::empty()),
            Arc::clone(&block_tree),
        ));
        let sync = Arc::new(BlockSync::new(
            chain,
            Arc::clone(&peers),
            sync_headers_rx,
            sync_blocks_rx,
            crate::sync::syncing_ibd_latch(),
        ));
        sync_blocks_tx.send(crate::InboundBlock::from_decoded(blocks[0].clone()))?;
        sync.tick();

        let flooded = test_addr(9780, 0)?;
        let _rx: crossbeam_channel::Receiver<crate::Message> =
            connect_peer(&peers, synthetic_peer(flooded, 3));
        let source = current_source(&peers, flooded);
        let block2 = regtest_fixture::mined_block_with_prev_hash(
            blocks[0].block_hash(),
            2,
            vec![regtest_fixture::coinbase(2)],
        )
        .unwrap_or_else(|error| panic!("regtest fixture block: {error}"));
        sync_headers_tx.send(crate::InboundHeaders {
            headers: vec![block2.header],
            source: Some(source),
            wire_response: true,
            body_fetch_owned: false,
        })?;
        sync.tick();
        assert!(
            sync.owns_body_fetch(source, Hash256::from(block2.block_hash())),
            "fixture: the window must own block 2's body for this connection"
        );

        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, blocks_rx) = crossbeam_channel::unbounded();
        let mut shared = test_shared(Arc::clone(&peers), headers_tx, blocks_tx);
        shared.block_sync = Some(Arc::clone(&sync));
        let lease = peers
            .lease(flooded)
            .ok_or("flood connection must be registered")?;
        let unrelated = genesis_body();
        let unrelated_bytes = bytes::Bytes::from(consensus_bytes(&unrelated));

        for _ in 0..=MAX_UNSOLICITED_BLOCK_FORWARDS {
            shared.send_block(&lease, flooded, unrelated.clone(), unrelated_bytes.clone());
        }
        assert_eq!(
            blocks_rx.len(),
            MAX_UNSOLICITED_BLOCK_FORWARDS,
            "one connection may not exceed its own unsolicited forwarding bound"
        );

        shared.send_block(
            &lease,
            flooded,
            block2.clone(),
            bytes::Bytes::from(consensus_bytes(&block2)),
        );
        assert_eq!(
            blocks_rx.len(),
            MAX_UNSOLICITED_BLOCK_FORWARDS + 1,
            "a delivery the window owns is never dropped for the unsolicited bound"
        );

        let other: SocketAddr = test_addr(9781, 0)?;
        let _other_rx: crossbeam_channel::Receiver<crate::Message> =
            connect_peer(&peers, synthetic_peer(other, 3));
        let other_lease = peers
            .lease(other)
            .ok_or("second connection must be registered")?;
        shared.send_block(
            &other_lease,
            other,
            unrelated.clone(),
            unrelated_bytes.clone(),
        );
        assert_eq!(
            blocks_rx.len(),
            MAX_UNSOLICITED_BLOCK_FORWARDS + 2,
            "the bound is one connection's share of the channel, not a global cap"
        );

        while blocks_rx.try_recv().is_ok() {}
        shared.send_block(&lease, flooded, unrelated, unrelated_bytes);
        assert_eq!(
            blocks_rx.len(),
            1,
            "a forwarding slot returns once sync has taken the body"
        );
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod address_tests {
    use super::*;
    use crate::{Message, PeerState};
    use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};

    #[test]
    fn local_dial_cancellation_is_not_attempt_evidence_but_tcp_failure_is() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let target = listener.local_addr().expect("address");
        drop(listener);
        let now = crate::addrman::now();
        for cancelled in [true, false] {
            let table = Arc::new(crate::PeerTable::new());
            let (headers, _) = crossbeam_channel::unbounded();
            let (blocks, _) = crossbeam_channel::unbounded();
            let mut shared = test_shared(table, headers, blocks);
            let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), true, None);
            book.learn_dns("seed", &[target], now - 31 * 86400);
            shared.address_book = Some(Arc::clone(&book));
            shared.session_cancel.store(cancelled);
            assert!(
                run_outbound_connection(target, &shared, crate::PeerRole::FullRelay, false, false)
                    .is_err()
            );
            assert_eq!(
                book.gossip(now).is_empty(),
                cancelled,
                "only an actual TCP attempt supplies Core's recent-attempt protection"
            );
            assert_eq!(
                book.pending_count_excluding(&[]),
                0,
                "health updates do not invent automatic claims"
            );
        }
    }

    #[test]
    fn outbound_wire_getaddr_never_serves_the_address_book() {
        let table = Arc::new(crate::PeerTable::new());
        let (headers_tx, _) = crossbeam_channel::unbounded();
        let (blocks_tx, _) = crossbeam_channel::unbounded();
        let mut shared = test_shared(Arc::clone(&table), headers_tx, blocks_tx);
        let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), true, None);
        book.learn_dns(
            "seed",
            &[SocketAddr::from(([127, 0, 0, 2], 8333))],
            crate::addrman::now(),
        );
        shared.address_book = Some(book);
        let (sender, receiver) = crossbeam_channel::unbounded();
        let source = SocketAddr::from(([127, 0, 0, 1], 9000));
        let lease = crate::PeerLease::new(sender);
        table.register(source, lease.clone());
        let mut input = Vec::new();
        for _ in 0..2 {
            crate::wire::write_message(&mut input, shared.magic, &Message::GetAddr).expect("frame");
        }
        let mut peer = Peer::new(std::io::Cursor::new(input), shared.magic);
        peer.state = PeerState::Ready;
        let _ = run_message_loop(&mut peer, source, &lease, &shared, None);
        assert!(
            !receiver
                .try_iter()
                .any(|message| matches!(message, Message::Addr(_) | Message::AddrV2(_))),
            "an outbound peer cannot query our address book"
        );
    }

    #[test]
    fn wire_address_messages_share_one_book_and_getaddr_is_once_per_connection() {
        let table = Arc::new(crate::PeerTable::new());
        let (headers_tx, _) = crossbeam_channel::unbounded();
        let (blocks_tx, _) = crossbeam_channel::unbounded();
        let mut shared = test_shared(Arc::clone(&table), headers_tx, blocks_tx);
        let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), true, None);
        shared.address_book = Some(Arc::clone(&book));
        let (sender, receiver) = crossbeam_channel::unbounded();
        let source = SocketAddr::from(([127, 0, 0, 1], 9000));
        let candidate = SocketAddr::from(([127, 0, 0, 2], 8333));
        let lease = crate::PeerLease::new_inbound(sender);
        table.register(source, lease.clone());
        let timestamp = u32::try_from(crate::addrman::now()).expect("timestamp");
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let mut input = Vec::new();
        for message in [
            Message::Addr(vec![(timestamp, Address::new(&candidate, services))]),
            Message::AddrV2(vec![AddrV2Message {
                time: timestamp,
                services,
                addr: AddrV2::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 2)),
                port: 8333,
            }]),
            Message::GetAddr,
            Message::GetAddr,
        ] {
            crate::wire::write_message(&mut input, shared.magic, &message).expect("frame");
        }
        let mut peer = Peer::new(std::io::Cursor::new(input), shared.magic);
        peer.state = PeerState::Ready;
        let _ = run_message_loop(&mut peer, source, &lease, &shared, None);
        assert_eq!(book.len(), 1);
        let replies: Vec<_> = receiver.try_iter().collect();
        let [Message::Addr(addresses)] = replies.as_slice() else {
            panic!("expected exactly one addr response: {replies:?}");
        };
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].1.socket_addr().expect("socket"), candidate);
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod feeler_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct Scripted(std::io::Cursor<Vec<u8>>);
    impl std::io::Read for Scripted {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.0, bytes)
        }
    }
    impl std::io::Write for Scripted {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn version_only_feeler_uses_native_acceptance_without_publishing_work() {
        for (services, revoked) in [(0_u64, 0), (1, 0), (9, 0), (9, 1), (9, 2)] {
            let server = TcpListener::bind("127.0.0.1:0").expect("listener");
            let address = server.local_addr().expect("address");
            let table = Arc::new(crate::PeerTable::new());
            let mut shared = test_shared(
                Arc::clone(&table),
                crossbeam_channel::unbounded().0,
                crossbeam_channel::unbounded().0,
            );
            let directory = tempfile::tempdir().expect("directory");
            let base = directory.path().join("peers.dat");
            let path = directory.path().join("peers-f9beb4d9.dat");
            let book =
                crate::addrman::AddressBook::open(Some(base), shared.magic.to_bytes(), true, None);
            book.learn_peer(
                address.ip(),
                &[(address, 9, unix_time_secs())],
                unix_time_secs(),
            );
            book.set_services(address, 1);
            shared.address_book = Some(Arc::clone(&book));
            shared.feeler = true;
            assert!(book.queued_feeler(address));
            let notifications = Arc::new(AtomicUsize::new(0));
            let count = Arc::clone(&notifications);
            shared.peer_ready = Some(Arc::new(move |_| {
                count.fetch_add(1, Ordering::Relaxed);
            }));
            let magic = shared.magic;
            let remote_table = Arc::clone(&table);
            let remote = std::thread::spawn(move || {
                let (stream, _) = server.accept().expect("accept");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .expect("timeout");
                let mut peer = Peer::new(stream, magic);
                assert!(matches!(
                    peer.read_message().expect("initial version").0,
                    crate::Message::Version(_)
                ));
                assert!(
                    remote_table
                        .sessions()
                        .iter()
                        .all(|session| session.info.is_none())
                );
                if revoked == 1 {
                    remote_table.cancel_all();
                } else if revoked == 2 {
                    let replacement = crate::PeerLease::new(crossbeam_channel::unbounded().0);
                    remote_table.register(address, replacement);
                }
                let sent = peer.send(&crate::Message::Version(crate::handshake::version_message(
                    123,
                    0,
                    crate::PeerRole::FullRelay,
                    ServiceFlags::from(services),
                )));
                if revoked == 0 {
                    sent.expect("VERSION only");
                }
                // No VERACK is sent; a feeler closes after native VERSION acceptance.
                while let Ok((message, _)) = peer.read_message() {
                    assert!(
                        !matches!(message, crate::Message::GetAddr | crate::Message::Verack),
                        "no ready/post-verack publication: {message:?}"
                    );
                }
            });
            spawn_outbound_connection(address, shared, crate::PeerRole::BlockRelayOnly)
                .join()
                .expect("thread")
                .expect("probe");
            remote.join().expect("remote");
            assert!(
                book.is_feeler(address),
                "the service reaper owns claim release"
            );
            book.unqueue(address);
            assert_eq!(notifications.load(Ordering::Relaxed), 0);
            assert_eq!(table.sessions().len(), usize::from(revoked == 2));
            assert!(
                table
                    .sessions()
                    .iter()
                    .all(|session| session.info.is_none() && session.demonstrated_tips.is_empty())
            );
            book.save();
            let bytes = std::fs::read(path).expect("book");
            let stored: serde_json::Value =
                serde_json::from_slice(&bytes[..bytes.len() - 32]).expect("JSON");
            assert_eq!(
                stored["records"][0]["tried"],
                revoked == 0,
                "services={services} revoked={revoked}"
            );
        }
    }

    #[test]
    fn ordinary_handshake_still_requires_services_and_verack() {
        for services in [1_u64, 9] {
            let mut wire = Vec::new();
            crate::wire::write_message(
                &mut wire,
                Magic::BITCOIN,
                &crate::Message::Version(crate::handshake::version_message(
                    123,
                    0,
                    crate::PeerRole::FullRelay,
                    ServiceFlags::from(services),
                )),
            )
            .expect("wire");
            let mut peer = Peer::new(Scripted(std::io::Cursor::new(wire)), Magic::BITCOIN);
            let lease = crate::PeerLease::new(crossbeam_channel::unbounded().0);
            let shared = test_shared(
                Arc::new(crate::PeerTable::new()),
                crossbeam_channel::unbounded().0,
                crossbeam_channel::unbounded().0,
            );
            let result = run_outbound_handshake(
                &mut peer,
                124,
                0,
                &lease,
                Instant::now() + Duration::from_secs(1),
                "127.0.0.1:8333".parse().expect("address"),
                &shared,
            );
            assert!(
                result.is_err(),
                "services={services} without VERACK must not complete"
            );
            assert_ne!(peer.state, crate::peer::PeerState::Ready);
        }
    }
    #[test]
    fn rejected_ordinary_version_updates_services_without_good() {
        for (prior_good, services) in [(false, 1_u64), (false, 0), (true, 1), (true, 0)] {
            let directory = tempfile::tempdir().expect("directory");
            let address: SocketAddr = "127.0.0.1:8333".parse().expect("address");
            let table = Arc::new(crate::PeerTable::new());
            let mut shared = test_shared(
                Arc::clone(&table),
                crossbeam_channel::unbounded().0,
                crossbeam_channel::unbounded().0,
            );
            let book = crate::addrman::AddressBook::open(
                Some(directory.path().join("peers.dat")),
                shared.magic.to_bytes(),
                true,
                None,
            );
            book.learn_dns("seed", &[address], 10_000);
            book.set_services(address, 9);
            if prior_good {
                book.succeeded(address, 9, 10_000);
            }
            shared.address_book = Some(Arc::clone(&book));
            let lease = crate::PeerLease::new(crossbeam_channel::unbounded().0);
            table.register(address, lease.clone());
            let mut wire = Vec::new();
            crate::wire::write_message(
                &mut wire,
                shared.magic,
                &crate::Message::Version(crate::handshake::version_message(
                    123,
                    0,
                    crate::PeerRole::FullRelay,
                    ServiceFlags::from(services),
                )),
            )
            .expect("VERSION");
            let mut peer = Peer::new(Scripted(std::io::Cursor::new(wire)), shared.magic);
            assert!(
                run_outbound_handshake(
                    &mut peer,
                    124,
                    0,
                    &lease,
                    Instant::now() + Duration::from_secs(1),
                    address,
                    &shared
                )
                .is_err()
            );
            book.save();
            let bytes = std::fs::read(directory.path().join("peers-f9beb4d9.dat")).expect("book");
            let stored: serde_json::Value =
                serde_json::from_slice(&bytes[..bytes.len() - 32]).expect("JSON");
            let record = &stored["records"][0];
            assert_eq!(record["services"], services);
            assert_eq!(record["last_success"], if prior_good { 10_000 } else { 0 });
            assert_eq!(record["tried"], prior_good);
            assert!(
                !book.ordinary_services_eligible(address, u64::MAX),
                "an observed VERSION is known even when it advertises zero services; no fabricated success"
            );
        }
    }
    #[test]
    fn manual_dial_bypasses_known_incomplete_stored_services() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        drop(listener); // Local refused TCP distinguishes an attempted dial from service rejection.
        let mut shared = test_shared(
            Arc::new(crate::PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), true, None);
        book.learn_peer(
            address.ip(),
            &[(address, 1, unix_time_secs())],
            unix_time_secs(),
        );
        shared.address_book = Some(book);
        let ordinary =
            spawn_outbound_connection(address, shared.clone(), crate::PeerRole::FullRelay)
                .join()
                .expect("ordinary thread");
        assert!(matches!(
            ordinary,
            Err(crate::PeerError::Protocol(
                "outbound peer lacks desirable services"
            ))
        ));
        let manual = spawn_pinned_outbound_connection(address, shared, crate::PeerRole::FullRelay)
            .join()
            .expect("manual thread");
        assert!(
            matches!(manual, Err(crate::PeerError::Io(_))),
            "explicit manual dial reaches TCP instead of applying stored-service policy"
        );
    }
}

#[cfg(test)]
mod discouragement_tests {
    use super::*;
    use crate::{Message, PeerError, PeerLease, PeerRole};

    fn shared() -> ConnectionShared {
        let (headers, _) = crossbeam_channel::unbounded();
        let (blocks, _) = crossbeam_channel::unbounded();
        test_shared(Arc::new(crate::PeerTable::new()), headers, blocks)
    }

    fn lease(manual: bool, noban: bool) -> PeerLease {
        let (tx, _) = crossbeam_channel::unbounded();
        let lease = if manual {
            PeerLease::new_manual(tx, PeerRole::FullRelay)
        } else {
            PeerLease::new(tx)
        };
        lease.with_no_ban(noban)
    }

    struct ServiceUpdateScript {
        bytes: std::io::Cursor<Vec<u8>>,
        update_at: Option<u64>,
        book: Arc<crate::addrman::AddressBook>,
        addr: SocketAddr,
    }
    impl std::io::Read for ServiceUpdateScript {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            if self.update_at.is_some_and(|at| self.bytes.position() >= at) {
                self.update_at = None;
                self.book.learn_peer(
                    self.addr.ip(),
                    &[(self.addr, 1024, unix_time_secs())],
                    unix_time_secs(),
                );
            }
            std::io::Read::read(&mut self.bytes, bytes)
        }
    }
    impl std::io::Write for ServiceUpdateScript {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn accepted_version_updates_each_time_without_replaying_on_later_steps()
    -> Result<(), Box<dyn std::error::Error>> {
        for (repeated_version, protected) in
            [(true, false), (true, true), (false, false), (false, true)]
        {
            let directory = tempfile::tempdir()?;
            let address: SocketAddr = "8.8.8.8:8333".parse()?;
            let mut shared = shared();
            let book = crate::addrman::AddressBook::open(
                Some(directory.path().join("peers.dat")),
                shared.magic.to_bytes(),
                false,
                None,
            );
            book.learn_peer(
                address.ip(),
                &[(address, 9, unix_time_secs())],
                unix_time_secs(),
            );
            shared.address_book = Some(Arc::clone(&book));
            let lease = lease(false, protected);
            shared.peer_table.register(address, lease.clone());
            let mut wire = Vec::new();
            if protected {
                crate::wire::write_message(&mut wire, shared.magic, &Message::Verack)?;
            }
            crate::wire::write_message(
                &mut wire,
                shared.magic,
                &Message::Version(crate::handshake::version_message(
                    42,
                    0,
                    PeerRole::FullRelay,
                    ServiceFlags::from(9),
                )),
            )?;
            let update_at = (!repeated_version).then_some(u64::try_from(wire.len())?);
            if repeated_version {
                crate::wire::write_message(
                    &mut wire,
                    shared.magic,
                    &Message::Version(crate::handshake::version_message(
                        43,
                        0,
                        PeerRole::FullRelay,
                        ServiceFlags::from(1),
                    )),
                )?;
            } else {
                crate::wire::write_message(&mut wire, shared.magic, &Message::WtxidRelay)?;
                crate::wire::write_message(&mut wire, shared.magic, &Message::Verack)?;
            }
            let mut peer = Peer::new(
                ServiceUpdateScript {
                    bytes: std::io::Cursor::new(wire),
                    update_at,
                    book: Arc::clone(&book),
                    addr: address,
                },
                shared.magic,
            );
            let result = run_outbound_handshake(
                &mut peer,
                44,
                0,
                &lease,
                Instant::now() + Duration::from_secs(1),
                address,
                &shared,
            );
            if repeated_version {
                assert!(matches!(
                    result,
                    Err(PeerError::Protocol(
                        "outbound peer lacks desirable services"
                    ))
                ));
            } else {
                result?;
                assert_eq!(peer.state, crate::PeerState::Ready);
            }
            book.save();
            let bytes = std::fs::read(directory.path().join("peers-f9beb4d9.dat"))?;
            let stored: serde_json::Value = serde_json::from_slice(&bytes[..bytes.len() - 32])?;
            assert_eq!(
                stored["records"][0]["services"],
                if repeated_version { 1 } else { 1033 },
                "accepted VERSION replaces flags; later feature/VERACK must preserve a fresh gossip update"
            );
            assert_eq!(stored["records"][0]["last_success"], 0);
            assert_eq!(stored["records"][0]["tried"], false);
        }
        Ok(())
    }

    #[test]
    fn only_current_remote_protocol_faults_change_automatic_avoidance()
    -> Result<(), Box<dyn std::error::Error>> {
        let shared = shared();
        let address: SocketAddr = "8.8.8.8:8333".parse()?;
        let stale = lease(false, false);
        shared.peer_table.register(address, stale.clone());
        let current = lease(false, false);
        shared.peer_table.register(address, current.clone());
        let fault = PeerError::Incoming(Box::new(PeerError::BadChecksum));
        shared.note_misbehavior(address, &stale, &fault);
        assert!(!shared.banned.is_discouraged(address.ip()));
        for error in [
            PeerError::Protocol("outbound queue closed or saturated"),
            PeerError::Protocol("network inactive"),
            PeerError::Protocol("p2p startup cancelled"),
            PeerError::Protocol("outbound peer lacks desirable services"),
            PeerError::PayloadTooLarge(usize::MAX),
            PeerError::Io(io::Error::from(io::ErrorKind::TimedOut)),
        ] {
            shared.note_misbehavior(address, &current, &error);
        }
        assert!(
            !shared.banned.is_discouraged(address.ip()),
            "local/backpressure/policy failures are not remote misbehavior"
        );
        shared.note_misbehavior(address, &current, &fault);
        assert!(shared.banned.is_discouraged(address.ip()));
        assert!(
            shared.banned.read().is_empty(),
            "automatic avoidance must not become a manual ban"
        );
        assert!(matches!(
            shared.check_destination(address, false),
            Err(PeerError::DiscouragedDestination(_))
        ));
        assert!(
            shared.check_destination(address, true).is_ok(),
            "manual dials bypass automatic avoidance"
        );
        assert!(
            !shared
                .banned
                .automatic_snapshot(SystemTime::now())
                .allows(address.ip())
        );
        Ok(())
    }

    #[test]
    fn invalid_wire_session_closes_and_refuses_the_next_automatic_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        for inbound in [false, true] {
            let shared = shared();
            // Exercise real socket framing and teardown with a nonlocal
            // connection identity. The test never dials this public address.
            let address: SocketAddr = "8.8.8.8:8333".parse()?;
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let mut sender = TcpStream::connect(listener.local_addr()?)?;
            let (stream, _) = listener.accept()?;
            configure_peer_stream(&stream)?;
            let counters = Arc::new(crate::PeerCounters::default());
            let local = stream.local_addr()?;
            let mut peer = Peer::new(
                crate::CountingStream::new(stream, Arc::clone(&counters)),
                Magic::BITCOIN,
            );
            peer.state = crate::PeerState::Ready;
            let (tx, rx) = crossbeam_channel::unbounded();
            let lease = if inbound {
                PeerLease::new_inbound(tx)
            } else {
                PeerLease::new(tx)
            };
            let probe = lease.clone();
            shared.peer_table.register(address, lease.clone());
            let version = crate::handshake::version_message(
                42,
                0,
                PeerRole::FullRelay,
                ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            );
            let mut info =
                crate::PeerInfo::outbound_from_version(address, local, &version, 0, 0, counters);
            info.inbound = inbound;
            let mut malformed = Vec::new();
            crate::wire::write_message(&mut malformed, Magic::BITCOIN, &Message::Ping(7))?;
            malformed[20] ^= 1; // A fully delivered frame with a bad checksum.
            io::Write::write_all(&mut sender, &malformed)?;
            io::Write::write_all(&mut sender, &malformed)?;
            let Err(error) = run_connected_session(&mut peer, address, &shared, lease, rx, info)
            else {
                return Err("malformed frames must close the session with an error".into());
            };
            assert!(matches!(error, PeerError::Incoming(_)));
            assert!(probe.is_cancelled());
            assert!(shared.peer_table.sessions().is_empty());
            assert!(matches!(
                shared.check_destination(address, false),
                Err(PeerError::DiscouragedDestination(_))
            ));
            assert!(shared.banned.read().is_empty());
        }
        Ok(())
    }

    #[test]
    fn manual_protected_and_local_connections_never_discourage_an_ip()
    -> Result<(), Box<dyn std::error::Error>> {
        for (ip, manual, noban) in [
            ("8.8.8.8", true, false),
            ("8.8.4.4", false, true),
            ("127.0.0.1", false, false),
            ("::ffff:127.0.0.1", false, false),
            ("::1", false, false),
        ] {
            let shared = shared();
            let address = SocketAddr::new(ip.parse()?, 8333);
            let lease = lease(manual, noban);
            shared.peer_table.register(address, lease.clone());
            let error = PeerError::Misbehavior("getheaders locator too large");
            shared.note_misbehavior(address, &lease, &error);
            assert!(!shared.banned.is_discouraged(address.ip()), "{ip}");
            assert_eq!(lease.ignores_protocol_error(&error), manual || noban);
            assert!(
                !lease.ignores_protocol_error(&PeerError::Incoming(Box::new(
                    PeerError::WrongNetwork {
                        expected: Magic::BITCOIN,
                        actual: Magic::REGTEST
                    }
                ))),
                "unread framing cannot be safely resumed"
            );
        }
        Ok(())
    }

    #[test]
    fn protected_handshake_discards_bad_order_without_extending_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        for manual in [false, true] {
            let lease = lease(manual, !manual);
            let mut bytes = Vec::new();
            crate::wire::write_message(&mut bytes, Magic::REGTEST, &Message::Verack)?;
            crate::wire::write_message(
                &mut bytes,
                Magic::REGTEST,
                &Message::Version(crate::handshake::version_message(
                    42,
                    0,
                    PeerRole::FullRelay,
                    ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                )),
            )?;
            crate::wire::write_message(&mut bytes, Magic::REGTEST, &Message::Verack)?;
            let mut peer = Peer::new(std::io::Cursor::new(bytes), Magic::REGTEST);
            // A cursor-backed outbound reader avoids interleaving test writes
            // with unread input; the steps are the production handshake owner.
            let (accepted, _) = crate::handshake::next_handshake_step(
                &mut peer,
                &lease,
                Instant::now() + Duration::from_secs(1),
            )?;
            assert!(matches!(accepted, Message::Version(_)));
            let (accepted, _) = crate::handshake::next_handshake_step(
                &mut peer,
                &lease,
                Instant::now() + Duration::from_secs(1),
            )?;
            assert!(matches!(accepted, Message::Verack));
            assert_eq!(peer.state, crate::peer::PeerState::Ready);
        }
        Ok(())
    }
}
