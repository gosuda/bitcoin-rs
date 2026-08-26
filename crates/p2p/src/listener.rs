use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::p2p::Magic;
use crossbeam_channel::Sender;
use parking_lot::RwLock;
use thiserror::Error;

use crate::handshake::run_inbound_handshake;
use crate::peer::Peer;

const POLL_INTERVAL: Duration = Duration::from_millis(100);
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_mins(1);
/// Stream read timeout used while polling handshake and message reads.
const STREAM_POLL_INTERVAL: Duration = Duration::from_secs(1);

type ChainQueryHandle = Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>;
type SyncWakeHandle = Option<Sender<()>>;
type PeerRegistrationHandle =
    Option<Arc<dyn Fn(SocketAddr, crate::PeerLease, crate::PeerInfo) -> bool + Send + Sync>>;

/// State shared by the listener and every connection thread it spawns.
///
/// The peer maps and ban list are the authoritative stores shared with the
/// node and its network control plane; `activity` and `totals` carry the
/// kill-switch and aggregate traffic accounting and are present only when the
/// entry point was built from a [`crate::NetworkControls`] instance.
#[derive(Clone)]
struct ConnectionShared {
    peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, crate::PeerLease>>>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    activity: Option<Arc<crate::NetworkActivity>>,
    totals: Option<Arc<crate::TrafficTotals>>,
    chain_query: ChainQueryHandle,
    peer_registered: PeerRegistrationHandle,
}

impl ConnectionShared {
    fn from_parts(
        peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
        peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, crate::PeerLease>>>,
        banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
        chain_query: ChainQueryHandle,
        peer_registered: PeerRegistrationHandle,
    ) -> Self {
        Self {
            peer_registry,
            peer_outbound,
            banned,
            activity: None,
            totals: None,
            chain_query,
            peer_registered,
        }
    }

    fn from_controls(
        controls: &Arc<crate::NetworkControls>,
        chain_query: ChainQueryHandle,
        peer_registered: PeerRegistrationHandle,
    ) -> Self {
        Self {
            peer_registry: Arc::clone(controls.peer_registry()),
            peer_outbound: Arc::clone(controls.peer_outbound()),
            banned: Arc::clone(controls.banned()),
            activity: Some(Arc::clone(controls.activity())),
            totals: Some(Arc::clone(controls.totals())),
            chain_query,
            peer_registered,
        }
    }
}

/// Registers one connection's lease at connection start, cancelling any live
/// predecessor at the same address.
///
/// Registration happens before the handshake so live-connection accounting
/// covers handshaking peers exactly like Core's connection manager.
fn register_connection(
    peer_outbound: &RwLock<hashbrown::HashMap<SocketAddr, crate::PeerLease>>,
    peer_addr: SocketAddr,
    lease: crate::PeerLease,
) -> bool {
    let mut outbound = peer_outbound.write();
    outbound.insert(peer_addr, lease).is_some_and(|prior| {
        prior.cancel();
        true
    })
}

/// Publishes handshake metadata for an already-registered connection.
fn publish_peer_info(
    peer_registry: &RwLock<Vec<crate::PeerInfo>>,
    peer_registered: Option<
        &(dyn Fn(SocketAddr, crate::PeerLease, crate::PeerInfo) -> bool + Send + Sync),
    >,
    peer_addr: SocketAddr,
    lease: crate::PeerLease,
    info: crate::PeerInfo,
) {
    if let Some(peer_registered) = peer_registered {
        peer_registered(peer_addr, lease, info);
        return;
    }
    let mut registry = peer_registry.write();
    registry.retain(|peer| peer.addr != peer_addr);
    registry.push(info);
}

#[cfg(test)]
fn register_peer(
    peer_registry: &RwLock<Vec<crate::PeerInfo>>,
    peer_outbound: &RwLock<hashbrown::HashMap<SocketAddr, crate::PeerLease>>,
    peer_registered: Option<
        &(dyn Fn(SocketAddr, crate::PeerLease, crate::PeerInfo) -> bool + Send + Sync),
    >,
    peer_addr: SocketAddr,
    lease: crate::PeerLease,
    info: crate::PeerInfo,
) -> bool {
    let replaced = register_connection(peer_outbound, peer_addr, lease.clone());
    publish_peer_info(peer_registry, peer_registered, peer_addr, lease, info);
    replaced
}

fn remove_current_peer(
    peer_registry: &RwLock<Vec<crate::PeerInfo>>,
    peer_outbound: &RwLock<hashbrown::HashMap<SocketAddr, crate::PeerLease>>,
    peer_addr: SocketAddr,
    lease: &crate::PeerLease,
) -> bool {
    let mut outbound = peer_outbound.write();
    if !outbound
        .get(&peer_addr)
        .is_some_and(|current| current.same_connection(lease))
    {
        return false;
    }
    if let Some(removed) = outbound.remove(&peer_addr) {
        removed.cancel();
    }
    peer_registry.write().retain(|peer| peer.addr != peer_addr);
    true
}

#[derive(Clone)]
struct InboundSyncSinks {
    headers_tx: Sender<crate::InboundHeaders>,
    blocks_tx: Sender<crate::InboundBlock>,
    wake_tx: SyncWakeHandle,
}

impl InboundSyncSinks {
    fn send_headers(&self, source: crate::PeerSource, headers: Vec<bitcoin::block::Header>) {
        if let Err(error) = self.headers_tx.send(crate::InboundHeaders {
            headers,
            source: Some(source),
        }) {
            tracing::warn!(peer_addr = %source.addr, %error, "p2p inbound headers channel disconnected");
        } else {
            wake_sync(self.wake_tx.as_ref());
        }
    }

    fn send_block(
        &self,
        source: crate::PeerSource,
        block: bitcoin::Block,
        serialized: bytes::Bytes,
    ) {
        if let Err(error) = self.blocks_tx.send(crate::InboundBlock {
            block,
            serialized,
            source: Some(source),
        }) {
            tracing::warn!(peer_addr = %source.addr, %error, "p2p inbound blocks channel disconnected");
        } else {
            wake_sync(self.wake_tx.as_ref());
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

/// Binds `addr` and runs an accept loop until `shutdown` is set.
///
/// On each accepted connection, spawns a thread that runs the inbound
/// handshake followed by a message-dispatch loop. The handshake uses
/// `HANDSHAKE_READ_TIMEOUT` (60s); after handshake, the message loop polls
/// inbound reads every second while enforcing a 60s inbound idle timeout.
/// The thread terminates on:
///   - successful handshake then idle (60s of no inbound messages)
///   - wire / FSM error
///   - explicit FSM disconnect transition
///
/// Per-connection threads are NOT joined by the outer shutdown — they
/// outlive the listener by up to the timeout. On exit (clean or error),
/// the peer is removed from `peer_registry` via address-match retain.
///
/// Successful inbound handshakes append their public metadata to
/// `peer_registry`. The peer is removed from `peer_registry` when the
/// per-connection thread exits.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn serve_with_shutdown(
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    magic: Magic,
    peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, crate::PeerLease>>>,
    inbound_headers_tx: Sender<crate::InboundHeaders>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
) -> Result<(), ListenerError> {
    serve_with_shutdown_with_chain_and_sync_wake(
        addr,
        shutdown,
        magic,
        peer_registry,
        peer_outbound,
        inbound_headers_tx,
        inbound_blocks_tx,
        banned,
        None,
        None,
        None,
    )
}

/// Binds `addr` and runs an accept loop with active-chain and sync-wake handles.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn serve_with_shutdown_with_chain_and_sync_wake(
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    magic: Magic,
    peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, crate::PeerLease>>>,
    inbound_headers_tx: Sender<crate::InboundHeaders>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    chain_query: Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>,
    sync_wake_tx: Option<Sender<()>>,
    peer_registered: PeerRegistrationHandle,
) -> Result<(), ListenerError> {
    let shared = ConnectionShared::from_parts(
        peer_registry,
        peer_outbound,
        banned,
        chain_query,
        peer_registered,
    );
    let inbound_sync_sinks = InboundSyncSinks {
        headers_tx: inbound_headers_tx,
        blocks_tx: inbound_blocks_tx,
        wake_tx: sync_wake_tx,
    };
    serve_connections(addr, &shutdown, magic, &shared, &inbound_sync_sinks)
}

/// Accept-loop core shared by every listener entry point.
fn serve_connections(
    addr: SocketAddr,
    shutdown: &AtomicBool,
    magic: Magic,
    shared: &ConnectionShared,
    inbound_sync_sinks: &InboundSyncSinks,
) -> Result<(), ListenerError> {
    let listener =
        TcpListener::bind(addr).map_err(|source| ListenerError::Bind { addr, source })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| ListenerError::Bind { addr, source })?;
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                if crate::subnet::is_banned(
                    &shared.banned.read(),
                    peer_addr.ip(),
                    SystemTime::now(),
                ) {
                    drop(stream);
                    tracing::debug!(peer_addr = %peer_addr, "p2p inbound rejected: banned");
                    continue;
                }
                if shared
                    .activity
                    .as_ref()
                    .is_some_and(|activity| !activity.is_active())
                {
                    drop(stream);
                    tracing::debug!(peer_addr = %peer_addr, "p2p inbound rejected: network inactive");
                    continue;
                }
                spawn_handshake_thread(
                    stream,
                    peer_addr,
                    magic,
                    shared.clone(),
                    inbound_sync_sinks.clone(),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(ListenerError::Accept(error)),
        }
    }
    Ok(())
}

/// Binds `addr` and runs the accept loop driven by one
/// [`crate::NetworkControls`] instance.
///
/// Unlike the part-wise entry points, the listener enforces the control
/// plane's network-activity switch on new inbound connections and accounts
/// aggregate traffic into its shared totals.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn serve_with_controls(
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    magic: Magic,
    controls: Arc<crate::NetworkControls>,
    inbound_headers_tx: Sender<crate::InboundHeaders>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    chain_query: Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>,
    sync_wake_tx: Option<Sender<()>>,
    peer_registered: PeerRegistrationHandle,
) -> Result<(), ListenerError> {
    let shared = ConnectionShared::from_controls(&controls, chain_query, peer_registered);
    let inbound_sync_sinks = InboundSyncSinks {
        headers_tx: inbound_headers_tx,
        blocks_tx: inbound_blocks_tx,
        wake_tx: sync_wake_tx,
    };
    serve_connections(addr, &shutdown, magic, &shared, &inbound_sync_sinks)
}

/// Spawns an outbound TCP connection to `addr`, performs the outbound P2P
/// handshake, and enters the same message loop the inbound path uses.
///
/// Returns a `JoinHandle` for the spawned thread. Errors during connect or
/// handshake bubble up via the `JoinHandle`'s `Result`.
#[allow(clippy::needless_pass_by_value)]
pub fn spawn_outbound_connection(
    addr: SocketAddr,
    magic: Magic,
    peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, crate::PeerLease>>>,
    inbound_headers_tx: Sender<crate::InboundHeaders>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    spawn_outbound_connection_with_chain_and_sync_wake(
        addr,
        magic,
        peer_registry,
        peer_outbound,
        inbound_headers_tx,
        inbound_blocks_tx,
        banned,
        None,
        None,
        None,
    )
}

/// Spawns an outbound connection with active-chain and sync-wake handles.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn spawn_outbound_connection_with_chain_and_sync_wake(
    addr: SocketAddr,
    magic: Magic,
    peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, crate::PeerLease>>>,
    inbound_headers_tx: Sender<crate::InboundHeaders>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    chain_query: Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>,
    sync_wake_tx: Option<Sender<()>>,
    peer_registered: PeerRegistrationHandle,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    let shared = ConnectionShared::from_parts(
        peer_registry,
        peer_outbound,
        banned,
        chain_query,
        peer_registered,
    );
    spawn_outbound(
        addr,
        magic,
        shared,
        InboundSyncSinks {
            headers_tx: inbound_headers_tx,
            blocks_tx: inbound_blocks_tx,
            wake_tx: sync_wake_tx,
        },
    )
}

/// Spawns an outbound connection driven by one [`crate::NetworkControls`]
/// instance.
///
/// The dial is refused while the control plane's network-activity switch is
/// off, and aggregate traffic is accounted into the shared totals.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn spawn_outbound_connection_with_controls(
    addr: SocketAddr,
    magic: Magic,
    controls: Arc<crate::NetworkControls>,
    inbound_headers_tx: Sender<crate::InboundHeaders>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    chain_query: Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>,
    sync_wake_tx: Option<Sender<()>>,
    peer_registered: PeerRegistrationHandle,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    let shared = ConnectionShared::from_controls(&controls, chain_query, peer_registered);
    spawn_outbound(
        addr,
        magic,
        shared,
        InboundSyncSinks {
            headers_tx: inbound_headers_tx,
            blocks_tx: inbound_blocks_tx,
            wake_tx: sync_wake_tx,
        },
    )
}

fn spawn_outbound(
    addr: SocketAddr,
    magic: Magic,
    shared: ConnectionShared,
    inbound_sync_sinks: InboundSyncSinks,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    let thread_name = format!("bitcoin-rs-p2p-outbound-{addr}");
    let result = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || run_outbound_connection(addr, magic, &shared, &inbound_sync_sinks));

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
    magic: Magic,
    shared: &ConnectionShared,
    inbound_sync_sinks: &InboundSyncSinks,
) -> Result<(), crate::wire::PeerError> {
    if crate::subnet::is_banned(&shared.banned.read(), addr.ip(), SystemTime::now()) {
        return Err(crate::wire::PeerError::BannedDestination(addr.ip()));
    }
    if shared
        .activity
        .as_ref()
        .is_some_and(|activity| !activity.is_active())
    {
        return Err(crate::wire::PeerError::Protocol("network inactive"));
    }

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(crate::wire::PeerError::Io)?;
    stream
        .set_read_timeout(Some(STREAM_POLL_INTERVAL))
        .map_err(crate::wire::PeerError::Io)?;
    stream
        .set_write_timeout(Some(HANDSHAKE_READ_TIMEOUT))
        .map_err(crate::wire::PeerError::Io)?;

    // Register the connection before the handshake so live-connection
    // accounting covers handshaking peers exactly like Core's connman.
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded::<crate::Message>();
    let lease = crate::PeerLease::new(outbound_tx);
    register_connection(&shared.peer_outbound, addr, lease.clone());

    let nonce = generate_nonce(addr);
    let mut peer = Peer::new(stream, magic);
    let handshake_deadline = Instant::now() + HANDSHAKE_READ_TIMEOUT;
    if let Err(error) = run_outbound_handshake(
        &mut peer,
        nonce,
        0,
        &lease,
        shared.totals.as_ref(),
        handshake_deadline,
    ) {
        remove_current_peer(&shared.peer_registry, &shared.peer_outbound, addr, &lease);
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        if lease.is_cancelled() {
            tracing::debug!(peer_addr = %addr, "p2p outbound lease revoked during handshake");
            return Ok(());
        }
        return Err(error);
    }

    let Some(remote_version) = peer.remote_version.as_ref() else {
        remove_current_peer(&shared.peer_registry, &shared.peer_outbound, addr, &lease);
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        return Err(crate::wire::PeerError::Protocol(
            "missing remote version after outbound handshake",
        ));
    };
    let handshake_now = SystemTime::now();
    let conn_time = unix_secs(handshake_now);
    let info = crate::PeerInfo::outbound_from_version(addr, remote_version, conn_time);
    lease
        .stats()
        .set_time_offset(remote_version.timestamp - unix_secs_i64(handshake_now));

    run_connected_session(
        &mut peer,
        addr,
        magic,
        shared,
        inbound_sync_sinks,
        lease,
        outbound_rx,
        info,
    )
}

fn run_outbound_handshake<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    nonce: u64,
    start_height: i32,
    lease: &crate::PeerLease,
    totals: Option<&Arc<crate::TrafficTotals>>,
    deadline: Instant,
) -> Result<(), crate::wire::PeerError> {
    let outbound_messages = crate::handshake::start(peer, nonce, start_height);
    for message in outbound_messages {
        crate::handshake::send_handshake_message(peer, &message, lease, totals)?;
    }

    while peer.state != crate::peer::PeerState::Ready {
        let (inbound, _) = crate::handshake::read_handshake_message(peer, lease, totals, deadline)?;
        let responses = crate::dispatch::dispatch_inbound(peer, &inbound)?;
        for response in responses {
            crate::handshake::send_handshake_message(peer, &response, lease, totals)?;
        }
    }

    Ok(())
}

fn spawn_handshake_thread(
    stream: TcpStream,
    peer_addr: SocketAddr,
    magic: Magic,
    shared: ConnectionShared,
    inbound_sync_sinks: InboundSyncSinks,
) {
    let thread_name = format!("bitcoin-rs-p2p-handshake-{peer_addr}");
    let spawn_result = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            if let Err(error) =
                run_handshake(stream, peer_addr, magic, &shared, &inbound_sync_sinks)
            {
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
    // this listener thread by up to HANDSHAKE_READ_TIMEOUT.
}

fn run_handshake(
    stream: TcpStream,
    peer_addr: SocketAddr,
    magic: Magic,
    shared: &ConnectionShared,
    inbound_sync_sinks: &InboundSyncSinks,
) -> Result<(), crate::wire::PeerError> {
    stream
        .set_nonblocking(false)
        .map_err(crate::wire::PeerError::Io)?;
    stream
        .set_read_timeout(Some(STREAM_POLL_INTERVAL))
        .map_err(crate::wire::PeerError::Io)?;
    stream
        .set_write_timeout(Some(HANDSHAKE_READ_TIMEOUT))
        .map_err(crate::wire::PeerError::Io)?;

    // Register the connection before the handshake so live-connection
    // accounting covers handshaking peers exactly like Core's connman.
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded::<crate::Message>();
    let lease = crate::PeerLease::new_inbound(outbound_tx);
    register_connection(&shared.peer_outbound, peer_addr, lease.clone());

    let nonce = generate_nonce(peer_addr);
    let mut peer = Peer::new(stream, magic);
    let handshake_deadline = Instant::now() + HANDSHAKE_READ_TIMEOUT;
    if let Err(error) = run_inbound_handshake(
        &mut peer,
        nonce,
        0,
        &lease,
        shared.totals.as_ref(),
        handshake_deadline,
    ) {
        remove_current_peer(
            &shared.peer_registry,
            &shared.peer_outbound,
            peer_addr,
            &lease,
        );
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        if lease.is_cancelled() {
            tracing::debug!(peer_addr = %peer_addr, "p2p inbound lease revoked during handshake");
            return Ok(());
        }
        return Err(error);
    }

    let Some(remote_version) = peer.remote_version.as_ref() else {
        remove_current_peer(
            &shared.peer_registry,
            &shared.peer_outbound,
            peer_addr,
            &lease,
        );
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        return Err(crate::wire::PeerError::Protocol(
            "missing remote version after successful handshake",
        ));
    };
    let handshake_now = SystemTime::now();
    let conn_time = unix_secs(handshake_now);
    let info = crate::PeerInfo::inbound_from_version(peer_addr, remote_version, conn_time);
    lease
        .stats()
        .set_time_offset(remote_version.timestamp - unix_secs_i64(handshake_now));

    run_connected_session(
        &mut peer,
        peer_addr,
        magic,
        shared,
        inbound_sync_sinks,
        lease,
        outbound_rx,
        info,
    )
}

fn run_connected_session(
    peer: &mut Peer<TcpStream>,
    peer_addr: SocketAddr,
    magic: Magic,
    shared: &ConnectionShared,
    inbound_sync_sinks: &InboundSyncSinks,
    lease: crate::PeerLease,
    outbound_rx: crossbeam_channel::Receiver<crate::Message>,
    info: crate::PeerInfo,
) -> Result<(), crate::wire::PeerError> {
    let writer_stream = peer
        .stream
        .try_clone()
        .map_err(crate::wire::PeerError::Io)?;
    let writer = spawn_connection_writer(
        writer_stream,
        magic,
        outbound_rx,
        peer_addr,
        lease.stats_handle(),
        shared.totals.clone(),
    )
    .map_err(crate::wire::PeerError::Io)?;
    publish_peer_info(
        &shared.peer_registry,
        shared.peer_registered.as_deref(),
        peer_addr,
        lease.clone(),
        info,
    );

    let inbound = lease.is_inbound();
    tracing::info!(
        peer_addr = %peer_addr,
        inbound,
        "p2p handshake complete; entering message loop",
    );

    let loop_result = (|| {
        peer.stream
            .set_read_timeout(Some(STREAM_POLL_INTERVAL))
            .map_err(crate::wire::PeerError::Io)?;
        run_message_loop(
            peer,
            peer_addr,
            &lease,
            inbound_sync_sinks,
            shared.chain_query.as_deref(),
            shared.totals.as_ref(),
        )
    })();

    let removed_current = remove_current_peer(
        &shared.peer_registry,
        &shared.peer_outbound,
        peer_addr,
        &lease,
    );
    debug_assert!(
        removed_current
            || shared
                .peer_outbound
                .read()
                .get(&peer_addr)
                .is_none_or(|current| !current.same_connection(&lease))
    );
    let _ = peer.stream.shutdown(std::net::Shutdown::Both);
    drop(lease);
    let _ = writer.join();
    if let Err(error) = &loop_result {
        tracing::warn!(peer_addr = %peer_addr, inbound, %error, "p2p peer disconnected with error");
    } else {
        tracing::debug!(peer_addr = %peer_addr, inbound, "p2p peer disconnected cleanly");
    }
    loop_result
}

fn run_message_loop<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    peer_addr: SocketAddr,
    lease: &crate::PeerLease,
    inbound_sync_sinks: &InboundSyncSinks,
    chain_query: Option<&dyn crate::dispatch::ChainQuery>,
    totals: Option<&Arc<crate::TrafficTotals>>,
) -> Result<(), crate::wire::PeerError> {
    use crate::peer::PeerState;
    use std::time::Instant;

    const IDLE_DISCONNECT: Duration = Duration::from_mins(1);

    let mut last_inbound = Instant::now();

    loop {
        if peer.state == PeerState::Disconnecting {
            return Ok(());
        }

        if lease.is_cancelled() {
            tracing::debug!(peer_addr = %peer_addr, "p2p peer lease revoked; closing");
            return Ok(());
        }

        if last_inbound.elapsed() >= IDLE_DISCONNECT {
            tracing::debug!(peer_addr = %peer_addr, "p2p peer idle 60s; closing");
            return Ok(());
        }

        let read_result = crate::wire::read_message(&mut peer.stream, peer.magic);
        if lease.is_cancelled() {
            tracing::debug!(peer_addr = %peer_addr, "p2p peer lease revoked during read; closing");
            return Ok(());
        }
        match read_result {
            Ok((message, raw)) => {
                last_inbound = Instant::now();
                let wire_len = raw.len() + crate::wire::HEADER_LEN;
                lease
                    .stats()
                    .record_recv(u64::try_from(wire_len).unwrap_or(u64::MAX));
                lease.stats().record_msg_recv();
                if let Some(totals) = totals {
                    totals.record_recv(u64::try_from(wire_len).unwrap_or(u64::MAX));
                }
                tracing::trace!(
                    peer_addr = %peer_addr,
                    command = ?std::mem::discriminant(&message),
                    "p2p message received",
                );
                let responses =
                    crate::dispatch::dispatch_inbound_with_chain(peer, &message, chain_query)?;
                match message {
                    bitcoin::p2p::message::NetworkMessage::Headers(headers) => {
                        inbound_sync_sinks.send_headers(lease.source(peer_addr), headers);
                    }
                    bitcoin::p2p::message::NetworkMessage::Block(block) => {
                        inbound_sync_sinks.send_block(lease.source(peer_addr), block, raw);
                    }
                    bitcoin::p2p::message::NetworkMessage::Pong(nonce) => {
                        lease.stats().complete_ping(nonce, unix_micros());
                    }
                    _ => {}
                }
                for response in responses {
                    if lease.send(response).is_err() {
                        return Err(crate::wire::PeerError::Protocol(
                            "outbound writer disconnected",
                        ));
                    }
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

/// Spawns a per-connection writer thread that drains queued outbound messages
/// and writes them to the peer. Decoupling writes from the blocking inbound
/// read ensures a momentarily silent peer can never delay outbound sends (the
/// next `getdata` during IBD). Sent bytes are accounted on the connection's
/// telemetry and, when present, the shared aggregate totals. Exits when every
/// sender drops or a write fails.
fn spawn_connection_writer(
    mut stream: TcpStream,
    magic: Magic,
    outbound_rx: crossbeam_channel::Receiver<crate::Message>,
    peer_addr: SocketAddr,
    stats: Arc<crate::PeerStats>,
    totals: Option<Arc<crate::TrafficTotals>>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name(format!("bitcoin-rs-p2p-writer-{peer_addr}"))
        .spawn(move || {
            while let Ok(message) = outbound_rx.recv() {
                match crate::wire::write_message(&mut stream, magic, &message) {
                    Ok(bytes) => {
                        stats.record_sent(u64::try_from(bytes).unwrap_or(u64::MAX));
                        stats.record_msg_sent();
                        if let Some(totals) = totals.as_ref() {
                            totals.record_sent(u64::try_from(bytes).unwrap_or(u64::MAX));
                        }
                    }
                    Err(error) => {
                        tracing::debug!(peer_addr = %peer_addr, %error, "p2p writer thread exiting");
                        break;
                    }
                }
            }
        })
}

fn unix_secs(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn unix_secs_i64(now: SystemTime) -> i64 {
    now.duration_since(UNIX_EPOCH).map_or(0, |duration| {
        i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
    })
}
fn unix_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
        })
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

#[cfg(test)]
mod outbound_tests {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::Arc;

    use bitcoin::p2p::Magic;
    use parking_lot::RwLock;

    use super::spawn_outbound_connection;

    #[test]
    fn spawn_outbound_connection_to_closed_port_fails_quickly()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let addr = listener.local_addr()?;
        drop(listener);

        let registry = Arc::new(RwLock::new(Vec::new()));
        let outbound = Arc::new(RwLock::new(hashbrown::HashMap::new()));
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let banned = Arc::new(RwLock::new(Vec::new()));

        let handle = spawn_outbound_connection(
            addr,
            Magic::BITCOIN,
            registry,
            outbound,
            headers_tx,
            blocks_tx,
            banned,
        );
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
}

#[cfg(test)]
mod lease_tests {
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bitcoin::p2p::Magic;
    use parking_lot::RwLock;

    use super::{InboundSyncSinks, run_message_loop};
    use crate::peer::{Peer, PeerState};

    type OutboundMap = Arc<RwLock<hashbrown::HashMap<SocketAddr, crate::PeerLease>>>;

    fn peer_info(addr: SocketAddr, conn_time: u64) -> crate::PeerInfo {
        crate::PeerInfo {
            addr,
            version: 70_016,
            services: 0,
            user_agent: String::from("/test/"),
            start_height: 0,
            conn_time,
            inbound: false,
        }
    }

    fn sinks() -> InboundSyncSinks {
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        InboundSyncSinks {
            headers_tx,
            blocks_tx,
            wake_tx: None,
        }
    }

    struct UnreadableStream;

    impl io::Read for UnreadableStream {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            panic!("message loop must check cancellation before reading")
        }
    }

    impl io::Write for UnreadableStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct ReplacingStream {
        registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
        outbound: OutboundMap,
        addr: SocketAddr,
        replacement: Option<crate::PeerLease>,
        bytes: io::Cursor<Vec<u8>>,
    }

    impl io::Read for ReplacingStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if let Some(replacement) = self.replacement.take() {
                super::register_peer(
                    &self.registry,
                    &self.outbound,
                    None,
                    self.addr,
                    replacement,
                    peer_info(self.addr, 2),
                );
            }
            self.bytes.read(buf)
        }
    }

    impl io::Write for ReplacingStream {
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
    fn sinks_stamp_exact_connection_source() -> Result<(), Box<dyn std::error::Error>> {
        let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, blocks_rx) = crossbeam_channel::unbounded();
        let sinks = InboundSyncSinks {
            headers_tx,
            blocks_tx,
            wake_tx: None,
        };
        let addr = SocketAddr::from(([127, 0, 0, 1], 8333));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        let source = lease.source(addr);
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let serialized = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&block));

        sinks.send_headers(source, Vec::new());
        sinks.send_block(source, block, serialized.clone());

        assert_eq!(headers_rx.try_recv()?.source, Some(source));
        let received = blocks_rx.try_recv()?;
        assert_eq!(received.source, Some(source));
        assert_eq!(received.serialized, serialized);
        Ok(())
    }

    #[test]
    fn message_loop_exits_before_read_when_cancelled() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_444));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        lease.cancel();
        let mut peer = Peer::new(UnreadableStream, Magic::BITCOIN);
        peer.state = PeerState::Ready;

        assert!(run_message_loop(&mut peer, addr, &lease, &sinks(), None, None).is_ok());
    }

    #[test]
    fn message_loop_exits_after_replacement_during_read() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_445));
        let registry = Arc::new(RwLock::new(vec![peer_info(addr, 1)]));
        let outbound: OutboundMap = Arc::new(RwLock::new(hashbrown::HashMap::new()));
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = crate::PeerLease::new(old_tx);
        outbound.write().insert(addr, old.clone());
        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = crate::PeerLease::new(replacement_tx);
        let mut bytes = Vec::new();
        if let Err(error) = crate::wire::write_message(
            &mut bytes,
            Magic::BITCOIN,
            &crate::Message::Headers(Vec::new()),
        ) {
            panic!("failed to encode test headers message: {error}");
        }
        let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let test_sinks = InboundSyncSinks {
            headers_tx,
            blocks_tx,
            wake_tx: None,
        };
        let mut peer = Peer::new(
            ReplacingStream {
                registry: Arc::clone(&registry),
                outbound: Arc::clone(&outbound),
                addr,
                replacement: Some(replacement.clone()),
                bytes: io::Cursor::new(bytes),
            },
            Magic::BITCOIN,
        );
        peer.state = PeerState::Ready;

        assert!(run_message_loop(&mut peer, addr, &old, &test_sinks, None, None).is_ok());
        assert!(
            headers_rx.try_recv().is_err(),
            "a message completed after replacement must not be enqueued"
        );
        assert!(old.is_cancelled());
        assert!(
            outbound
                .read()
                .get(&addr)
                .is_some_and(|current| current.same_connection(&replacement))
        );
    }

    #[test]
    fn message_loop_keeps_current_lease_running() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_446));
        let reads = Arc::new(AtomicUsize::new(0));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        let mut peer = Peer::new(ContinuingStream(Arc::clone(&reads)), Magic::BITCOIN);
        peer.state = PeerState::Ready;

        assert!(run_message_loop(&mut peer, addr, &lease, &sinks(), None, None).is_err());
        assert_eq!(reads.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn registration_cancels_replaced_lease() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_447));
        let registry = RwLock::new(vec![peer_info(addr, 1)]);
        let outbound = RwLock::new(hashbrown::HashMap::new());
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = crate::PeerLease::new(old_tx);
        outbound.write().insert(addr, old.clone());
        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = crate::PeerLease::new(replacement_tx);

        assert!(super::register_peer(
            &registry,
            &outbound,
            None,
            addr,
            replacement.clone(),
            peer_info(addr, 2)
        ));
        assert!(old.is_cancelled());
        assert!(
            outbound
                .read()
                .get(&addr)
                .is_some_and(|current| current.same_connection(&replacement))
        );
        assert_eq!(&*registry.read(), &[peer_info(addr, 2)]);
    }

    #[test]
    fn stale_release_preserves_replacement_and_current_release_removes_it() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_448));
        let registry = RwLock::new(vec![peer_info(addr, 2)]);
        let outbound = RwLock::new(hashbrown::HashMap::new());
        let (stale_tx, _stale_rx) = crossbeam_channel::unbounded();
        let stale = crate::PeerLease::new(stale_tx);
        let (current_tx, _current_rx) = crossbeam_channel::unbounded();
        let current = crate::PeerLease::new(current_tx);
        outbound.write().insert(addr, current.clone());

        assert!(!super::remove_current_peer(
            &registry, &outbound, addr, &stale
        ));
        assert!(!current.is_cancelled());
        assert!(
            outbound
                .read()
                .get(&addr)
                .is_some_and(|lease| lease.same_connection(&current))
        );
        assert_eq!(&*registry.read(), &[peer_info(addr, 2)]);

        assert!(super::remove_current_peer(
            &registry, &outbound, addr, &current
        ));
        assert!(current.is_cancelled());
        assert!(outbound.read().is_empty());
        assert!(registry.read().is_empty());
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

    #[test]
    fn missing_sync_wake_is_noop() {
        wake_sync(None);
    }
}
