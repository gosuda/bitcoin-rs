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
/// Maximum backoff for transient accept errors (ECONNABORTED, EMFILE, …).
/// Bounded so the listener recovers quickly once the pressure clears.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(10);
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_mins(1);
/// Stream read timeout used while polling handshake and message reads.
const STREAM_POLL_INTERVAL: Duration = Duration::from_secs(1);

type ChainQueryHandle = Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>;
type SyncWakeHandle = Option<Sender<()>>;

/// State shared by the listener and every connection thread it spawns.
///
/// The peer table and ban list are the authoritative stores shared with the
/// node and its network control plane; `activity` and `totals` carry the
/// kill-switch and aggregate traffic accounting and are present only when the
/// entry point was built from a [`crate::NetworkControls`] instance.
#[derive(Clone)]
struct ConnectionShared {
    peer_table: Arc<crate::PeerTable>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    activity: Option<Arc<crate::NetworkActivity>>,
    totals: Option<Arc<crate::TrafficTotals>>,
    chain_query: ChainQueryHandle,
}

impl ConnectionShared {
    fn from_parts(
        peer_table: Arc<crate::PeerTable>,
        banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
        chain_query: ChainQueryHandle,
    ) -> Self {
        Self {
            peer_table,
            banned,
            activity: None,
            totals: None,
            chain_query,
        }
    }

    fn from_controls(
        controls: &Arc<crate::NetworkControls>,
        chain_query: ChainQueryHandle,
    ) -> Self {
        Self {
            peer_table: Arc::clone(controls.peer_table()),
            banned: Arc::clone(controls.banned()),
            activity: Some(Arc::clone(controls.activity())),
            totals: Some(Arc::clone(controls.totals())),
            chain_query,
        }
    }
}

#[derive(Clone)]
struct InboundSyncSinks {
    headers_tx: Sender<crate::InboundHeaders>,
    blocks_tx: Sender<crate::InboundBlock>,
    wake_tx: SyncWakeHandle,
}

impl InboundSyncSinks {
    fn send_headers(&self, source: crate::PeerSource, headers: Vec<bitcoin_rs_primitives::Header>) {
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
        block: bitcoin_rs_primitives::Block,
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
/// the peer is removed from the authoritative peer table.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn serve_with_shutdown(
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    network_active: Arc<AtomicBool>,
    magic: Magic,
    peer_table: Arc<crate::PeerTable>,
    inbound_headers_tx: Sender<crate::InboundHeaders>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
) -> Result<(), ListenerError> {
    serve_with_shutdown_with_chain_and_sync_wake(
        addr,
        shutdown,
        network_active,
        magic,
        peer_table,
        inbound_headers_tx,
        inbound_blocks_tx,
        banned,
        None,
        None,
    )
}

/// Binds `addr` and runs an accept loop with active-chain and sync-wake handles.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn serve_with_shutdown_with_chain_and_sync_wake(
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    network_active: Arc<AtomicBool>,
    magic: Magic,
    peer_table: Arc<crate::PeerTable>,
    inbound_headers_tx: Sender<crate::InboundHeaders>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    chain_query: Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>,
    sync_wake_tx: Option<Sender<()>>,
) -> Result<(), ListenerError> {
    let mut shared = ConnectionShared::from_parts(peer_table, banned, chain_query);
    shared.activity = Some(Arc::new(crate::NetworkActivity::from_shared(
        network_active,
    )));
    let inbound_sync_sinks = InboundSyncSinks {
        headers_tx: inbound_headers_tx,
        blocks_tx: inbound_blocks_tx,
        wake_tx: sync_wake_tx,
    };
    serve_connections(addr, &shutdown, magic, &shared, &inbound_sync_sinks)
}

/// Accept-loop core shared by every listener entry point.
///
/// Bind and `set_nonblocking` failures are fatal and propagated as
/// [`ListenerError::Bind`]. Transient `accept` errors (ECONNABORTED,
/// EMFILE/ENFILE under fd pressure, etc.) are logged at warn and the loop
/// continues after a bounded backoff — matching Bitcoin Core's tolerant
/// accept loop so inbound P2P stays alive through temporary resource
/// exhaustion rather than permanently killing the listener thread.
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
    let mut accept_backoff = POLL_INTERVAL;
    while !shutdown.load(Ordering::Relaxed) {
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
) -> Result<(), ListenerError> {
    let shared = ConnectionShared::from_controls(&controls, chain_query);
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
    network_active: Arc<AtomicBool>,
    magic: Magic,
    peer_table: Arc<crate::PeerTable>,
    inbound_headers_tx: Sender<crate::InboundHeaders>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    spawn_outbound_connection_with_chain_and_sync_wake(
        addr,
        magic,
        peer_table,
        inbound_headers_tx,
        inbound_blocks_tx,
        banned,
        network_active,
        None,
        None,
    )
}

/// Spawns an outbound connection with active-chain and sync-wake handles.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn spawn_outbound_connection_with_chain_and_sync_wake(
    addr: SocketAddr,
    magic: Magic,
    peer_table: Arc<crate::PeerTable>,
    inbound_headers_tx: Sender<crate::InboundHeaders>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    network_active: Arc<AtomicBool>,
    chain_query: Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>,
    sync_wake_tx: Option<Sender<()>>,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    let mut shared = ConnectionShared::from_parts(peer_table, banned, chain_query);
    shared.activity = Some(Arc::new(crate::NetworkActivity::from_shared(
        network_active,
    )));
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
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    let shared = ConnectionShared::from_controls(&controls, chain_query);
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
    shared.peer_table.register(addr, lease.clone());

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
        shared.peer_table.remove_current(addr, &lease);
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        if lease.is_cancelled() {
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
    shared.peer_table.register(peer_addr, lease.clone());

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
        shared.peer_table.remove_current(peer_addr, &lease);
        let _ = peer.stream.shutdown(std::net::Shutdown::Both);
        if lease.is_cancelled() {
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
    peer: &mut Peer<TcpStream>,
    peer_addr: SocketAddr,
    magic: Magic,
    shared: &ConnectionShared,
    inbound_sync_sinks: &InboundSyncSinks,
    lease: crate::PeerLease,
    outbound_rx: crossbeam_channel::Receiver<crate::Message>,
    info: crate::PeerInfo,
) -> Result<(), crate::wire::PeerError> {
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
            magic,
            outbound_rx,
            lease.close_signal(),
            lease.budget_handle(),
            peer_addr,
            lease.stats_handle(),
            shared.totals.clone(),
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
    shared.peer_table.publish_info(peer_addr, &lease, info);

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

    shared.peer_table.remove_current(peer_addr, &lease);
    lease.cancel();
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
    let budget = lease.budget_handle();

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
                crate::dispatch::dispatch_inbound_with_chain(
                    peer,
                    &message,
                    chain_query,
                    &|| budget.has_block_production_headroom(),
                    &mut |response| {
                        lease.send(response).map_err(|_| {
                            crate::wire::PeerError::Protocol("outbound queue closed or saturated")
                        })
                    },
                )?;
                match message {
                    crate::Message::Headers(headers) => {
                        inbound_sync_sinks.send_headers(lease.source(peer_addr), headers);
                    }
                    crate::Message::Block(block) => {
                        inbound_sync_sinks.send_block(lease.source(peer_addr), block, raw);
                    }
                    crate::Message::Pong(nonce) => {
                        lease.stats().complete_ping(nonce, unix_micros());
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

/// Spawns a per-connection writer thread that drains queued outbound messages
/// and writes them to the peer. Decoupling writes from the blocking inbound
/// read ensures a momentarily silent peer can never delay outbound sends (the
/// next `getdata` during IBD). Sent bytes are accounted on the connection's
/// telemetry and, when present, the shared aggregate totals. Exits on the
/// lease close signal, when every sender drops, or on write failure. Every exit
/// shuts down the socket so the reader half cannot outlive a failed writer.
fn spawn_connection_writer(
    mut stream: TcpStream,
    magic: Magic,
    outbound_rx: crossbeam_channel::Receiver<crate::Message>,
    close_rx: crossbeam_channel::Receiver<()>,
    budget: Arc<crate::connection::OutboundBudget>,
    peer_addr: SocketAddr,
    stats: Arc<crate::PeerStats>,
    totals: Option<Arc<crate::TrafficTotals>>,
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
                &stats,
                totals.as_ref(),
            );
            let _ = stream.shutdown(std::net::Shutdown::Both);
        })
}

/// Writer loop body shared by the spawned writer thread and deterministic
/// tests: receives one message or the close signal, writes it, and releases
/// the admitted full wire byte count after a successful write. Exits on the
/// close signal, sender drop, or write error — never by polling. On a write
/// error the budget is deliberately not released (the connection is dying).
fn run_writer_loop(
    outbound_rx: &crossbeam_channel::Receiver<crate::Message>,
    mut close_rx: crossbeam_channel::Receiver<()>,
    budget: &Arc<crate::connection::OutboundBudget>,
    writer: &mut dyn std::io::Write,
    magic: Magic,
    stats: &Arc<crate::PeerStats>,
    totals: Option<&Arc<crate::TrafficTotals>>,
) {
    loop {
        crossbeam_channel::select! {
            recv(outbound_rx) -> message => {
                let Ok(message) = message else { break };
                match crate::wire::write_message(writer, magic, &message) {
                    Ok(bytes) => {
                        stats.record_sent(u64::try_from(bytes).unwrap_or(u64::MAX));
                        stats.record_msg_sent();
                        if let Some(totals) = totals {
                            totals.record_sent(u64::try_from(bytes).unwrap_or(u64::MAX));
                        }
                        budget.release(bytes);
                    }
                    Err(error) => {
                        tracing::debug!(%error, "p2p writer thread exiting");
                        break;
                    }
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
    use std::sync::atomic::AtomicBool;

    use super::spawn_outbound_connection;
    use crate::PeerTable;
    use bitcoin::p2p::Magic;
    use parking_lot::RwLock;

    #[test]
    fn spawn_outbound_connection_to_closed_port_fails_quickly()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let addr = listener.local_addr()?;
        drop(listener);

        let peer_table = Arc::new(PeerTable::new());
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let banned = Arc::new(RwLock::new(Vec::new()));

        let handle = spawn_outbound_connection(
            addr,
            Arc::new(AtomicBool::new(true)),
            Magic::BITCOIN,
            peer_table,
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

#[cfg(test)]
static ACCEPT_ERROR_INJECT: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
static WRITER_SETUP_FAIL: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
#[allow(clippy::expect_used)]
mod resilient_accept_tests {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use bitcoin::p2p::Magic;
    use parking_lot::RwLock;

    use super::{ACCEPT_ERROR_INJECT, ConnectionShared, InboundSyncSinks, serve_connections};

    fn shared_state() -> ConnectionShared {
        let peer_table = Arc::new(crate::PeerTable::new());
        let banned = Arc::new(RwLock::new(Vec::new()));
        ConnectionShared::from_parts(peer_table, banned, None)
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

    /// A transient accept error must not kill the listener thread — the loop
    /// logs, backs off, and continues until shutdown.
    #[test]
    fn serve_connections_survives_transient_accept_error() {
        // Grab an ephemeral port, then release it so serve_connections can bind.
        let probe =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind probe");
        let addr = probe.local_addr().expect("local_addr");
        drop(probe);

        let shutdown = Arc::new(AtomicBool::new(false));
        let shared = shared_state();
        let sinks = sinks();

        // Inject one transient accept error.
        ACCEPT_ERROR_INJECT.store(true, Ordering::Relaxed);

        let thread_shutdown = Arc::clone(&shutdown);
        let thread_shared = shared;
        let handle = std::thread::spawn(move || {
            serve_connections(
                addr,
                &thread_shutdown,
                Magic::BITCOIN,
                &thread_shared,
                &sinks,
            )
        });

        // Give the loop time to process the injected error and continue.
        std::thread::sleep(Duration::from_millis(300));

        // The listener must still be alive — connect a real client to prove it.
        let _client = TcpStream::connect(addr).expect("listener should still accept");

        // Shut down cleanly.
        shutdown.store(true, Ordering::Relaxed);
        let result = handle.join().expect("listener thread panicked");
        assert!(
            result.is_ok(),
            "serve_connections must return Ok after shutdown, got {result:?}"
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
    use parking_lot::RwLock;

    use super::{ConnectionShared, InboundSyncSinks, WRITER_SETUP_FAIL, run_connected_session};
    use crate::peer::Peer;

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

    /// When the writer-thread setup fails (`try_clone` or `spawn`), the lease
    #[test]
    fn writer_setup_failure_cleans_up_lease() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let client = TcpStream::connect(addr).expect("connect");
        let (server_stream, peer_addr) = listener.accept().expect("accept");
        drop(server_stream);

        let peer_table = Arc::new(crate::PeerTable::new());
        let banned = Arc::new(RwLock::new(Vec::new()));
        let shared = ConnectionShared::from_parts(peer_table, banned, None);

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

        let mut peer = Peer::new(client, Magic::BITCOIN);
        let info = peer_info(peer_addr, 0);
        let result = run_connected_session(
            &mut peer,
            peer_addr,
            Magic::BITCOIN,
            &shared,
            &sinks(),
            lease,
            outbound_rx,
            info,
        );

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
    use parking_lot::RwLock;

    use super::{
        ConnectionShared, InboundSyncSinks, run_connected_session, run_message_loop,
        run_writer_loop, spawn_connection_writer,
    };
    use crate::connection::OutboundBudget;
    use crate::peer::{Peer, PeerState};

    const FAILSAFE: Duration = Duration::from_secs(5);

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
            services: 1,
            user_agent: String::from("/test/"),
            start_height,
            conn_time: 0,
            inbound: false,
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
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_443));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let block_bytes = bitcoin::consensus::encode::serialize(&genesis);
        let block = bitcoin_rs_primitives::Block::consensus_decode(&block_bytes)
            .map_err(|_| std::io::Error::other("genesis block must decode"))?;
        let serialized = bytes::Bytes::from(block_bytes);
        let source = lease.source(addr);

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
        let mut peer = Peer::new(
            ScriptedStream {
                script: io::Cursor::new(Vec::new()),
            },
            Magic::BITCOIN,
        );
        peer.state = PeerState::Ready;

        let sinks = InboundSyncSinks {
            headers_tx: crossbeam_channel::unbounded().0,
            blocks_tx: crossbeam_channel::unbounded().0,
            wake_tx: None,
        };
        assert!(run_message_loop(&mut peer, addr, &lease, &sinks, None, None).is_ok());
    }

    #[test]
    fn message_loop_exits_after_replacement_during_read() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_445));
        let table = crate::PeerTable::new();
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
        let sinks = InboundSyncSinks {
            headers_tx,
            blocks_tx: crossbeam_channel::unbounded().0,
            wake_tx: None,
        };
        let mut peer = Peer::new(
            ScriptedStream {
                script: io::Cursor::new(wire),
            },
            Magic::BITCOIN,
        );
        peer.state = PeerState::Ready;

        assert!(run_message_loop(&mut peer, addr, &old, &sinks, None, None).is_ok());
        assert!(headers_rx.try_recv().is_err());
        assert!(old.is_cancelled());
        assert!(table.is_current(replacement.source(addr)));
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
        let sinks = InboundSyncSinks {
            headers_tx: crossbeam_channel::unbounded().0,
            blocks_tx: crossbeam_channel::unbounded().0,
            wake_tx: None,
        };

        assert!(run_message_loop(&mut peer, addr, &lease, &sinks, None, None).is_err());
        assert_eq!(reads.load(Ordering::Relaxed), 2);
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
        let writer_stream = server.try_clone().expect("try_clone");
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
            lease.stats_handle(),
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
        let stats = lease.stats_handle();
        let worker = std::thread::spawn(move || {
            run_writer_loop(
                &outbound_rx,
                close_rx,
                &budget,
                &mut writer,
                Magic::BITCOIN,
                &stats,
                None,
            );
            let _ = done_tx.send(());
        });

        // Two full frames are written and released; the third blocks the
        // writer mid-`write_all`, exactly where `shutdown(Both)` would find
        // it in production.
        blocked_rx
            .recv_timeout(FAILSAFE)
            .expect("writer must exhaust its byte budget");
        assert_eq!(
            lease.budget_handle().pending(),
            (3, 3 * frame),
            "two written frames release; three remain charged"
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
        assert_eq!(lease.budget_handle().pending(), (3, 3 * frame));
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
        let stats = lease.stats_handle();
        let worker = std::thread::spawn(move || {
            run_writer_loop(
                &outbound_rx,
                close_rx,
                &worker_budget,
                &mut writer,
                Magic::BITCOIN,
                &stats,
                None,
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
            server,
            Magic::BITCOIN,
            outbound_rx,
            lease.close_signal(),
            lease.budget_handle(),
            peer_addr,
            lease.stats_handle(),
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
    fn run_connected_session_joins_writer_with_external_lease_clone_alive() {
        let (client, server, peer_addr) = loopback_pair();
        // The client EOFs immediately, so the session's first read fails.
        drop(client);

        let peer_table = Arc::new(crate::PeerTable::new());
        let banned = Arc::new(RwLock::new(Vec::new()));
        let shared = ConnectionShared::from_parts(peer_table, banned, None);

        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(outbound_tx);
        let lease_probe = lease.clone();
        shared.peer_table.register(peer_addr, lease.clone());

        let info = crate::PeerInfo {
            addr: peer_addr,
            version: 70_016,
            services: 0,
            user_agent: String::from("/test/"),
            start_height: 0,
            conn_time: 0,
            inbound: false,
        };
        let sinks = InboundSyncSinks {
            headers_tx: crossbeam_channel::unbounded().0,
            blocks_tx: crossbeam_channel::unbounded().0,
            wake_tx: None,
        };

        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let worker = std::thread::spawn(move || {
            let mut peer = Peer::new(server, Magic::BITCOIN);
            let result = run_connected_session(
                &mut peer,
                peer_addr,
                Magic::BITCOIN,
                &shared,
                &sinks,
                lease,
                outbound_rx,
                info,
            );
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
    }

    #[test]
    fn message_loop_disconnects_saturated_peer() {
        let (outbound_tx, _outbound_rx) = crossbeam_channel::unbounded();
        let lease =
            crate::PeerLease::new_with_budget(outbound_tx, false, OutboundBudget::new(0, 0));

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

        let sinks = InboundSyncSinks {
            headers_tx: crossbeam_channel::unbounded().0,
            blocks_tx: crossbeam_channel::unbounded().0,
            wake_tx: None,
        };
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_447));

        // The Pong response cannot be admitted onto the zero budget, so the
        // saturation policy cancels the lease and ends the loop.
        let result = run_message_loop(&mut peer, addr, &lease, &sinks, None, None);
        assert!(result.is_err(), "saturation must end the message loop");
        assert!(lease.is_cancelled());
    }
}
