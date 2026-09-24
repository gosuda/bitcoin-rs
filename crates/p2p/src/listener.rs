use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::Magic;
use bitcoin_rs_primitives::Network;
use crossbeam_channel::{SendTimeoutError, Sender};
use parking_lot::RwLock;
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

type ChainQueryHandle = Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>;

type TxInventoryHandle = Option<Arc<dyn crate::dispatch::TxInventory + 'static>>;

type CompactHintsHandle = Option<Arc<dyn crate::compact_blocks::CompactBlockHints + 'static>>;

type SyncWakeHandle = Option<Sender<()>>;

type PeerReadyHandle = Option<Arc<dyn Fn(crate::PeerSource) + Send + Sync>>;

/// Optional node-owned handles passed to [`crate::P2pService::start`].
///
/// The service copies each handle into the start epoch's
/// [`ConnectionShared`], so a new handle extends that one wiring value
/// instead of adding another entry point.
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
    /// Block-download orchestrator, used to route block inventory
    /// announcements and to ask whether an inbound body was requested.
    /// `None` (tests, and a node without a sync loop) announces nothing and
    /// treats every body as unsolicited.
    pub block_sync: Option<Arc<crate::sync::BlockSync>>,
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
    pub banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    /// Network kill-switch behind `setnetworkactive`.
    pub activity: Arc<crate::NetworkActivity>,
    /// Start-scoped cancellation token. Tests that never cancel pass a
    /// token that stays `false`.
    pub session_cancel: Arc<AtomicBool>,
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
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        peer_table: Arc<crate::PeerTable>,
        banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
        activity: Arc<crate::NetworkActivity>,
        session_cancel: Arc<AtomicBool>,
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
            banned,
            activity,
            session_cancel,
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
        info: crate::PeerInfo,
    ) -> bool {
        let source = lease.source(peer_addr);
        if self.peer_table.publish_info(peer_addr, lease, info)
            && self.peer_table.is_current(source)
        {
            self.notify_peer_ready(source);
            true
        } else {
            false
        }
    }

    fn is_session_cancelled(&self) -> bool {
        self.session_cancel.load(Ordering::Acquire)
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

    /// Forwards one inbound full block into the node's ingress.
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
        // sink too so tips learned only by body delivery (`inv`-served,
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
        let hash = bitcoin_rs_primitives::Hash256::from(block.header.compute_hash());
        let requested = self
            .block_sync
            .as_ref()
            .is_some_and(|sync| sync.owns_body_fetch(source, hash));
        let forward_credit = match lease.admit_block_forward(source, hash, requested) {
            Some(credit) => Some(credit),
            None => {
                metrics::counter!("node.sync.dropped_unsolicited_blocks").increment(1);
                self.send_headers(source, vec![block.header], false, false);
                return;
            }
        };
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
        self.forward_block(block, serialized, source, Some(credit));
        self.send_headers(source, vec![header], false, false);
    }

    /// Queues an admitted body on the shared inbound block channel.
    ///
    /// PRE: `forward_credit` admits this body into the ingress path.
    /// POST: the body is queued, or dropped because the session was cancelled
    ///   or the channel disconnected.
    /// INVARIANT: backpressure waits here, never in the admission step, and
    ///   the credit is released when sync drops the body it holds.
    fn forward_block(
        &self,
        block: bitcoin_rs_primitives::Block,
        serialized: bytes::Bytes,
        source: crate::PeerSource,
        forward_credit: Option<crate::connection::BlockForwardCredit>,
    ) {
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
                return;
            }
            match self.blocks_tx.send_timeout(inbound, POLL_INTERVAL) {
                Ok(()) => {
                    wake_sync(self.wake_tx.as_ref());
                    break;
                }
                Err(SendTimeoutError::Timeout(returned)) => inbound = returned,
                Err(SendTimeoutError::Disconnected(_)) => {
                    tracing::warn!(
                        peer_addr = %source.addr,
                        "p2p inbound blocks channel disconnected"
                    );
                    return;
                }
            }
        }
    }

    /// Forwards a decoded transaction into the node's ingress channel.
    ///
    /// The `tx` sink contract lives in `docs/policies/p2p-compatibility.md`.
    /// A full channel drops this body so the read loop can still service
    /// ping, headers, and blocks from this peer.
    fn send_tx(&self, source: crate::PeerSource, tx: bitcoin_rs_primitives::Tx) {
        let Some(inbound_tx) = self.inbound_tx.as_ref() else {
            return;
        };
        if self.is_session_cancelled() {
            return;
        }
        match inbound_tx.try_send(crate::InboundTx::new(tx, source)) {
            Ok(()) => {}
            Err(crossbeam_channel::TrySendError::Full(_)) => {
                tracing::debug!(
                    peer_addr = %source.addr,
                    "p2p inbound tx channel full; dropping body"
                );
            }
            Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                tracing::warn!(
                    peer_addr = %source.addr,
                    "p2p inbound tx channel disconnected"
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
#[allow(clippy::needless_pass_by_value)]
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
                if crate::subnet::is_banned(
                    &shared.banned.read(),
                    peer_addr.ip(),
                    SystemTime::now(),
                ) {
                    drop(stream);
                    tracing::debug!(peer_addr = %peer_addr, "p2p inbound rejected: banned");
                    continue;
                }
                if !shared.activity.is_active() {
                    drop(stream);
                    tracing::debug!(peer_addr = %peer_addr, "p2p inbound rejected: network inactive");
                    continue;
                }
                spawn_handshake_thread(stream, peer_addr, shared.clone());
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
    spawn_dial(addr, shared, role, false)
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
pub fn spawn_pinned_outbound_connection(
    addr: SocketAddr,
    shared: ConnectionShared,
    role: crate::peer_info::PeerRole,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    spawn_dial(addr, shared, role, true)
}

fn spawn_dial(
    addr: SocketAddr,
    shared: ConnectionShared,
    role: crate::peer_info::PeerRole,
    pinned: bool,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    let thread_name = format!("bitcoin-rs-p2p-outbound-{addr}");
    let result = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || run_outbound_connection(addr, &shared, role, pinned));

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

fn run_outbound_connection(
    addr: SocketAddr,
    shared: &ConnectionShared,
    role: crate::peer_info::PeerRole,
    manual: bool,
) -> Result<(), crate::wire::PeerError> {
    if crate::subnet::is_banned(&shared.banned.read(), addr.ip(), SystemTime::now()) {
        return Err(crate::wire::PeerError::BannedDestination(addr.ip()));
    }
    if !shared.activity.is_active() {
        return Err(crate::wire::PeerError::Protocol("network inactive"));
    }
    if shared.is_session_cancelled() {
        return Err(crate::wire::PeerError::Protocol("p2p startup cancelled"));
    }

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(crate::wire::PeerError::Io)?;
    configure_peer_stream(&stream).map_err(crate::wire::PeerError::Io)?;
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
    };
    shared.peer_table.register(addr, lease.clone());
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
    let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    if let Err(error) = run_outbound_handshake(&mut peer, nonce, 0, &lease, handshake_deadline) {
        // `remove_current` cancels as a side effect, so revocation must be
        // read before it: a pre-cancelled lease means an external shutdown,
        // while a live lease means this handshake failed on its own.
        let revoked = lease.is_cancelled();
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
    let conn_time = unix_secs(SystemTime::now());
    let info = crate::PeerInfo::outbound_from_version(
        addr,
        addr_bind,
        remote_version,
        conn_time,
        peer.version_received_time.unwrap_or(conn_time),
        counters,
    );

    run_connected_session(&mut peer, addr, shared, lease, outbound_rx, info)
}

/// Drives the outbound handshake until the peer is ready.
///
/// PRE: `peer` wraps a connected outbound stream, and `lease` belongs to it.
/// POST: `peer` is `Ready`, and the post-verack messages are sent.
/// INVARIANT: This function counts no bytes; the stream that `peer` wraps
/// owns byte accounting.
fn run_outbound_handshake<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    nonce: u64,
    start_height: i32,
    lease: &crate::PeerLease,
    deadline: Instant,
) -> Result<(), crate::wire::PeerError> {
    let outbound_messages = crate::handshake::start(peer, nonce, start_height, lease.role());
    for message in outbound_messages {
        peer.send(&message)?;
    }

    while peer.state != crate::peer::PeerState::Ready {
        let (inbound, _) = crate::handshake::read_handshake_message(peer, lease, deadline)?;
        let responses = crate::dispatch::dispatch_inbound(peer, &inbound)?;
        for response in responses {
            peer.send(&response)?;
        }
    }
    crate::handshake::send_post_verack_messages(peer)?;
    Ok(())
}

fn spawn_handshake_thread(stream: TcpStream, peer_addr: SocketAddr, shared: ConnectionShared) {
    let thread_name = format!("bitcoin-rs-p2p-handshake-{peer_addr}");
    let spawn_result = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            if let Err(error) = run_handshake(stream, peer_addr, &shared) {
                tracing::warn!(
                    peer_addr = %peer_addr,
                    %error,
                    "p2p inbound handshake failed",
                );
            }
        });

    if let Err(error) = spawn_result {
        tracing::warn!(
            peer_addr = %peer_addr,
            %error,
            "failed to spawn p2p inbound handshake thread",
        );
    }
    // The handle is intentionally dropped: per-connection threads outlive
    // this listener thread by up to HANDSHAKE_TIMEOUT.
}

fn run_handshake(
    stream: TcpStream,
    peer_addr: SocketAddr,
    shared: &ConnectionShared,
) -> Result<(), crate::wire::PeerError> {
    configure_peer_stream(&stream).map_err(crate::wire::PeerError::Io)?;

    // Wrapped before the handshake, so the bytes it spends are counted too.
    let counters = std::sync::Arc::new(crate::PeerCounters::default());
    let stream = crate::CountingStream::from_connected(stream, counters)
        .map_err(crate::wire::PeerError::Io)?;
    let addr_bind = stream.local_addr().map_err(crate::wire::PeerError::Io)?;
    let counters = std::sync::Arc::clone(stream.counters());

    // Register the connection before the handshake so live-connection
    // accounting covers handshaking peers exactly like Core's connman.
    if shared.is_session_cancelled() {
        return Err(crate::wire::PeerError::Protocol("p2p startup cancelled"));
    }

    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded::<crate::Message>();
    let lease = crate::PeerLease::new_inbound(outbound_tx);
    shared.peer_table.register(peer_addr, lease.clone());
    if shared.is_session_cancelled() {
        shared.peer_table.remove_current(peer_addr, &lease);
        lease.cancel();
        return Ok(());
    }

    let nonce = generate_nonce(peer_addr);
    let mut peer = Peer::new(stream, shared.magic);
    let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    if let Err(error) = run_inbound_handshake(&mut peer, nonce, 0, &lease, handshake_deadline) {
        // `remove_current` cancels as a side effect, so revocation must be
        // read before it: a pre-cancelled lease means an external shutdown,
        // while a live lease means this handshake failed on its own.
        let revoked = lease.is_cancelled();
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
    let conn_time = unix_secs(SystemTime::now());
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
        )
        .map_err(crate::wire::PeerError::Io)
    })();
    let writer = match setup_result {
        Ok(handle) => handle,
        Err(error) => {
            // The lease was already registered into peer_table at
            // handshake time.  Run the same cleanup the normal exit path
            // does so a spawn failure (e.g. EAGAIN under thread/fd
            // pressure) does not leave a phantom peer registered.
            shared.peer_table.remove_current(peer_addr, &lease);
            lease.cancel();
            let _ = peer.stream.shutdown(std::net::Shutdown::Both);
            drop(lease);
            return Err(error);
        }
    };
    shared.publish_info_and_notify_ready(peer_addr, &lease, info);

    let inbound = lease.is_inbound();
    tracing::info!(
        peer_addr = %peer_addr,
        inbound,
        "p2p handshake complete; entering message loop",
    );

    let loop_result = run_message_loop(peer, peer_addr, &lease, shared, shared.ibd.as_ref());

    shared.peer_table.remove_current(peer_addr, &lease);
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
///   `net_processing.cpp:4385-4390`). `addr` and `addrv2` are dropped
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
    if matches!(message, crate::Message::Tx(_)) {
        return Err(crate::wire::PeerError::Protocol(
            "transaction sent in violation of protocol",
        ));
    }
    if let crate::Message::Inv(items) = &message
        && items.iter().any(|item| {
            matches!(
                item,
                Inventory::Transaction(_) | Inventory::WitnessTransaction(_) | Inventory::WTx(_)
            )
        })
    {
        return Err(crate::wire::PeerError::Protocol(
            "transaction inv sent in violation of protocol",
        ));
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
/// PRE: [`Keepalive::record_recv`] runs for every message the loop reads and
///   [`Keepalive::record_send`] for every message the loop queues.
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
    ///
    /// PRE: `now` is the monotonic instant the session loop starts.
    /// POST: both directions count as fresh at `now`, and the first probe is
    ///   owed immediately.
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
    fn next_action(&mut self, now: Instant) -> KeepaliveAction {
        if now.saturating_duration_since(self.last_recv) > TIMEOUT_INTERVAL
            || now.saturating_duration_since(self.last_send) > TIMEOUT_INTERVAL
        {
            return KeepaliveAction::Expired;
        }
        let probe_owed = self
            .last_ping
            .is_none_or(|last| now.saturating_duration_since(last) >= PING_INTERVAL);
        if probe_owed {
            self.last_ping = Some(now);
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

    /// A fresh connection is probed at once and then once per ping interval,
    /// never twice inside one interval.
    #[test]
    fn probes_owe_one_ping_per_interval() {
        let t0 = Instant::now();
        let mut keepalive = Keepalive::starting(t0);
        assert_eq!(keepalive.next_action(t0), KeepaliveAction::Ping);
        assert_eq!(
            keepalive.next_action(t0 + PING_INTERVAL / 2),
            KeepaliveAction::Idle
        );
        assert_eq!(
            keepalive.next_action(t0 + PING_INTERVAL),
            KeepaliveAction::Ping
        );
    }

    /// Receive silence past the timeout interval ends the connection even
    /// while pings keep the send direction fresh.
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

    /// Send silence alone ends it too: Core weighs each direction separately
    /// (`InactivityCheck`, `net.cpp:2068-2080`).
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

    /// A message in each direction inside the window clears the timeout, so a
    /// live-but-quiet peer is kept and merely probed.
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
#[allow(clippy::too_many_lines)]
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
    loop {
        if peer.state == PeerState::Disconnecting {
            return Ok(());
        }

        if lease.is_cancelled() {
            tracing::debug!(peer_addr = %peer_addr, "p2p peer lease revoked; closing");
            return Ok(());
        }

        match keepalive.next_action(Instant::now()) {
            KeepaliveAction::Idle => {}
            KeepaliveAction::Ping => {
                let nonce = generate_nonce(peer_addr);
                lease.send(crate::Message::Ping(nonce)).map_err(|_| {
                    crate::wire::PeerError::Protocol("outbound queue closed or saturated")
                })?;
                keepalive.record_send(Instant::now());
            }
            KeepaliveAction::Expired => {
                tracing::debug!(
                    peer_addr = %peer_addr,
                    "p2p peer silent past the timeout interval; closing",
                );
                return Ok(());
            }
        }

        let read_result = crate::wire::read_message(&mut peer.stream, peer.magic);
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
                crate::dispatch::dispatch_inbound_full(
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
                )?;
                match message {
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
                    crate::Message::SendCmpct(send_cmpct) => {
                        // Any `sendcmpct` (v1 or v2) announces BIP152 relay:
                        // the peer may serve `MSG_CMPCT_BLOCK` getdata at our
                        // advertised version. The high-bandwidth push
                        // preference is a separate per-peer choice and must
                        // not gate compact-fetch eligibility — an inbound peer
                        // (how the node sees its Core dial) is never selected
                        // for push announcements.
                        if matches!(send_cmpct.version, 1 | 2) {
                            shared
                                .peer_table
                                .note_compact_relay(lease.source(peer_addr));
                        }
                    }
                    crate::Message::CmpctBlock(_) | crate::Message::BlockTxn(_) => {
                        process_compact_wire_message(
                            &message,
                            &mut compact_reconstruction,
                            peer.compact_blocks.local_version,
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
            Err(error) => return Err(error),
        }
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
    if let crate::Message::CmpctBlock(cmpct) = message
        && !matches!(outcome, crate::compact_blocks::Outcome::Complete(_))
        && let Some(header) = crate::compact_blocks::native_header(&cmpct.compact_block.header)
    {
        // When the outcome itself fetches the body (`RequestMissing` issues
        // a `getblocktxn`, `Fallback` a full-block `getdata`), the window
        // must record that in-flight fetch instead of scheduling a
        // duplicate request for the freshly admitted tip.
        let body_fetch_owned = matches!(
            outcome,
            crate::compact_blocks::Outcome::RequestMissing(_)
                | crate::compact_blocks::Outcome::Fallback(_)
        );
        // Record the fetch before the follow-up leaves: a response landing
        // before the header drains still counts as requested, not
        // unsolicited (`SchedulerState::owned_body_fetches`).
        if body_fetch_owned && let Some(sync) = shared.block_sync.as_ref() {
            sync.record_owned_body_fetch(
                lease.source(peer_addr),
                bitcoin_rs_primitives::Hash256::from(header.compute_hash()),
            );
        }
        shared.send_headers(
            lease.source(peer_addr),
            vec![header],
            false,
            body_fetch_owned,
        );
    }
    handle_compact_outcome(outcome, lease, peer_addr, shared);
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
) {
    let follow_up = |message: crate::Message| {
        if let Err(error) = lease.send(message) {
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
/// POST: Return the writer thread's handle, or the spawn error.
/// INVARIANT: The counted stream accounts every sent byte once.
fn spawn_connection_writer(
    mut stream: crate::CountingStream<TcpStream>,
    magic: Magic,
    outbound_rx: crossbeam_channel::Receiver<crate::Message>,
    close_rx: crossbeam_channel::Receiver<()>,
    budget: Arc<crate::connection::OutboundBudget>,
    peer_addr: SocketAddr,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name(format!("bitcoin-rs-p2p-writer-{peer_addr}"))
        .spawn(move || {
            run_writer_loop(&outbound_rx, close_rx, &budget, &mut stream, magic);
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
/// `write_messages` returned it.
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
) -> bool {
    let mut pending = Some(first);
    while let Some(head) = pending.take() {
        let (burst, leftover) = collect_write_burst(head, outbound_rx);
        // Encode once per message: the probe consumes the same frame bytes
        // the write emits, the way Core's `CSerializedNetMsg` is shared by
        // its send path and the `net:outbound_message` probe.
        let frames = match crate::wire::encode_frames(magic, &burst) {
            Ok(frames) => frames,
            Err(error) => {
                tracing::debug!(%error, "p2p writer thread exiting");
                return false;
            }
        };
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
) {
    loop {
        crossbeam_channel::select! {
            recv(outbound_rx) -> message => {
                let Ok(first) = message else { break };
                if !write_ready_burst(first, outbound_rx, writer, magic, budget) {
                    break;
                }
            }
            recv(close_rx) -> signal => {
                if signal.is_ok() {
                    break;
                }
                // A disconnected close channel is permanently ready. Disable
                // that select arm so the disconnected outbound channel alone
                // drains any messages accepted before the last lease dropped.
                close_rx = crossbeam_channel::never();
            }
        }
    }
}

fn unix_secs(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
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
        // Unsolicited transactions are not a protocol violation; Core drops
        // them unpunished while in initial block download (:4716).
        tracing::debug!(peer_addr = %peer_addr, "tx dropped: initial block download");
    }
}

/// UNIX seconds for the chain-owned initial-block-download latch.
fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
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
        Arc::new(RwLock::new(Vec::new())),
        Arc::new(crate::NetworkActivity::from_shared(Arc::new(
            AtomicBool::new(true),
        ))),
        Arc::new(AtomicBool::new(false)),
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
    fn registered_session(dial: Dial) -> crate::PeerSession {
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
#[allow(clippy::expect_used)]
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
#[allow(clippy::expect_used)]
mod session_socket_tests {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};

    use crate::socket::{HANDSHAKE_TIMEOUT, STREAM_POLL_INTERVAL, configure_peer_stream};

    /// Contract: `docs/contracts/p2p-wire.md` `P2P-04`.
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
#[allow(clippy::expect_used)]
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

        // Inject one transient accept error.
        ACCEPT_ERROR_INJECT.store(true, Ordering::Relaxed);

        let thread_shutdown = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || serve(listener, thread_shutdown, shared));

        // Give the loop time to process the injected error and continue.
        std::thread::sleep(Duration::from_millis(300));

        // The listener must still be alive — connect a real client to prove it.
        let _client = TcpStream::connect(addr).expect("listener should still accept");

        // Shut down cleanly.
        shutdown.store(true, Ordering::Relaxed);
        let result = handle.join().expect("listener thread panicked");
        assert!(
            result.is_ok(),
            "serve must return Ok after shutdown, got {result:?}"
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
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
            compact_block_relay: false,
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

    /// When the writer-thread setup fails (`try_clone` or `spawn`), the lease
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

        // Inject writer setup failure.
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
#[allow(clippy::expect_used)]
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

        let result = crate::listener::run_handshake(server, peer_addr, &shared);
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
            compact_block_relay: false,
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
        let block = bitcoin_rs_primitives::Block::consensus_decode(&block_bytes)
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
        let block = bitcoin_rs_primitives::Block::consensus_decode(&block_bytes)
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
        let session_cancel = Arc::clone(&shared.session_cancel);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_448));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let first_bytes = bitcoin::consensus::encode::serialize(&genesis);
        let first = bitcoin_rs_primitives::Block::consensus_decode(&first_bytes)
            .map_err(|_| std::io::Error::other("genesis block must decode"))?;
        let second_bytes = first_bytes.clone();
        let second = bitcoin_rs_primitives::Block::consensus_decode(&second_bytes)
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
        session_cancel.store(true, Ordering::Release);
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

    // CONTRACT: docs/policies/p2p-compatibility.md#4-handshake-contract (a
    // known-version sendcmpct raises the published relay preference).
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
                compact_block_relay: false,
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
        // Script end ends the connection; the arm already ran.
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
        // An unknown BIP152 version is not a relay announcement.
        assert!(!sendcmpct_scenario(false, 7, 18_450));
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

    /// A quiet connection is probed with one `ping` before the peer is asked
    /// to speak, so liveness never depends on inbound traffic.
    #[test]
    fn message_loop_probes_a_quiet_peer() {
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
        let probe = outbound_rx.try_recv();
        assert!(
            matches!(probe, Ok(crate::Message::Ping(_))),
            "the loop must probe a quiet peer with one ping, got {probe:?}",
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
        let worker = std::thread::spawn(move || {
            run_writer_loop(&outbound_rx, close_rx, &budget, &mut writer, Magic::BITCOIN);
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

        // The close signal alone cannot interrupt a mid-`write_all` writer;
        // the unblock failure simulates the stream shutdown.
        lease.cancel();
        let _ = unblock_tx.send(());
        done_rx
            .recv_timeout(FAILSAFE)
            .expect("unblock must release the blocked writer");
        worker.join().expect("worker join");

        // The write-error path deliberately releases nothing.
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
            );
            let _ = done_tx.send(());
        });

        // Drop every sender clone (the lease holds the last one) so the
        // writer exits on Disconnected after processing the queue.
        drop(lease);

        event_rx
            .recv_timeout(FAILSAFE)
            .expect("writer must emit an event after write returns");
        done_rx
            .recv_timeout(FAILSAFE)
            .expect("writer must exit after senders drop");
        worker.join().expect("worker join");

        // Release was processed between the write and the next recv; the
        // released byte count equals the admitted wire length.
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
            // The client EOFs immediately, so the session's first read fails.
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
                compact_block_relay: false,
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
                } else {
                    peer.wtxid_relay.mark_local_advertised();
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

        // The loop's keepalive probe takes the one-frame budget, so the Pong
        // response cannot be admitted and the saturation policy cancels the
        // lease and ends the loop.
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
            compact_block_relay: false,
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
            !shared.publish_info_and_notify_ready(addr, &stale, peer_info(addr, 1)),
            "replaced predecessor must not publish or notify"
        );
        assert_eq!(notified.load(Ordering::Relaxed), 0);
        assert!(shared.peer_table.infos().is_empty());

        assert!(shared.publish_info_and_notify_ready(addr, &current, peer_info(addr, 2)));
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

        assert!(shared.publish_info_and_notify_ready(addr, &lease, peer_info(addr, 3)));
        assert_eq!(notified.load(Ordering::Relaxed), 1);
        assert_eq!(shared.peer_table.infos(), vec![peer_info(addr, 3)]);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod block_forward_tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use arc_swap::ArcSwapOption;
    use bitcoin_rs_primitives::{Hash256, consensus_bytes};
    use parking_lot::{Mutex, RwLock};

    use super::test_shared;
    use crate::connection::MAX_UNSOLICITED_BLOCK_FORWARDS;
    use crate::sync::BlockSync;
    use crate::sync::chain::SyncChain;
    use crate::sync::tests::{
        TestChain, coinbase_transaction, connect_peer, current_source, eligible_peer,
        mined_block_with_prev_hash, mined_chain, test_addr,
    };

    fn genesis_body() -> bitcoin_rs_primitives::Block {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let bytes = bitcoin::consensus::encode::serialize(&genesis);
        bitcoin_rs_primitives::Block::consensus_decode(&bytes)
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
            Arc::new(Mutex::new(sync_headers_rx)),
            Arc::new(Mutex::new(sync_blocks_rx)),
        ));
        sync_blocks_tx.send(crate::InboundBlock::from_decoded(blocks[0].clone()))?;
        sync.tick();

        let flooded = test_addr(9780, 0)?;
        // The outbound queue stays alive: a closed queue would cancel the
        // lease and masquerade as a disconnect.
        let _rx: crossbeam_channel::Receiver<crate::Message> =
            connect_peer(&peers, eligible_peer(flooded, 3));
        let source = current_source(&peers, flooded);
        let block2 =
            mined_block_with_prev_hash(blocks[0].block_hash(), 2, vec![coinbase_transaction(2)]);
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

        // Listener wiring over the same peer table and sync loop.
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
            connect_peer(&peers, eligible_peer(other, 3));
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
