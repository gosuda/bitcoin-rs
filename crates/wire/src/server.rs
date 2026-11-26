#![cfg_attr(not(feature = "test-seam"), allow(unreachable_pub))]

use alloc::sync::Arc;
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, IoSlice, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};
use tracing::{debug, error, warn};

use crate::auth::Auth;
use crate::error::RpcError;
use crate::handlers::Handler;

const MAX_HEADER_BYTES: usize = 16 * 1_024;
const MAX_HEADER_COUNT: usize = 100;
const RESERVED_POOL_DIVISOR: usize = 4;
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) const MAX_BODY_BYTES: usize = 16 * 1_024 * 1_024;

const WRONG_CREDENTIALS_DELAY: Duration = Duration::from_millis(250);

const MAX_DRAIN_BYTES: usize = 64 * 1_024;

const DRAIN_BUDGET: Duration = Duration::from_secs(1);

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
const CONNECTION_DRAIN_DEADLINE: Duration = Duration::from_secs(5);
const LISTENER_TOKEN: mio::Token = mio::Token(0);
const WAKER_TOKEN: mio::Token = mio::Token(1);

const PUBLIC_ESPLORA_METHODS: &[&str] = &["GET", "POST", "OPTIONS"];

const PUBLIC_ESPLORA_HEADERS: &[&str] = &["Content-Type"];

const PUBLIC_ESPLORA_EXPOSE_HEADERS: &[&str] = &["X-Total-Results"];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RpcSurface {
    #[default]
    Shared,
    Management,
    Public,
}

impl RpcSurface {
    const fn label(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Management => "management",
            Self::Public => "public",
        }
    }

    fn allows(self, route: &HttpRoute<'_>) -> bool {
        match self {
            Self::Shared => true,
            Self::Management => matches!(route, HttpRoute::JsonRpc | HttpRoute::NotFound),
            Self::Public => !matches!(route, HttpRoute::JsonRpc),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PublicPolicy {
    pub esplora_enabled: bool,
    pub broadcast_enabled: bool,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
}

impl Default for PublicPolicy {
    fn default() -> Self {
        Self {
            esplora_enabled: true,
            broadcast_enabled: true,
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
        }
    }
}

impl PublicPolicy {
    fn normalized_host(value: &str) -> String {
        let value = value.trim();
        let value = match value.strip_prefix('[') {
            Some(rest) => match rest.split_once(']') {
                Some((inside, _)) => inside,
                None => value,
            },
            None => match value.rsplit_once(':') {
                Some((host, port))
                    if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) =>
                {
                    host
                }
                _ => value,
            },
        };
        value.to_ascii_lowercase()
    }

    fn is_host_allowed(&self, host: Option<&str>) -> bool {
        if self.allowed_hosts.is_empty() {
            return true;
        }
        let Some(host) = host else {
            return false;
        };
        let normalized = Self::normalized_host(host);
        self.allowed_hosts
            .iter()
            .any(|allowed| Self::normalized_host(allowed) == normalized)
    }

    fn cors_allow_origin(&self, origin: Option<&str>) -> Option<String> {
        if self.allowed_origins.is_empty() {
            return Some("*".to_owned());
        }
        let origin = origin?.trim();
        if origin.is_empty() {
            return None;
        }
        self.allowed_origins
            .iter()
            .any(|allowed| allowed.trim() == origin)
            .then(|| origin.to_owned())
    }
}

pub struct RpcServer {
    pub listener: TcpListener,
    pub auth: Arc<Auth>,
    pub handler: Arc<Handler>,
    pub max_connections: usize,
    pub idle_timeout: Duration,
    pub rest_enabled: bool,
    pub public_policy: PublicPolicy,
}

impl RpcServer {
    pub fn bind<A: ToSocketAddrs>(
        address: A,
        auth: Arc<Auth>,
        handler: Arc<Handler>,
        max_connections: usize,
        idle_timeout: Duration,
        rest_enabled: bool,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(address)?;
        let context = Arc::clone(handler.context());
        drop(handler);
        let handler = Arc::new(Handler::new(context));
        handler.context().mark_server_bound();
        handler.configure_blocking_admission(per_source_limit(max_connections));
        Ok(Self {
            listener,
            auth,
            handler,
            max_connections,
            idle_timeout,
            rest_enabled,
            public_policy: PublicPolicy::default(),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn serve_with_shutdown(
        self,
        shutdown: impl Into<bitcoin_rs_consensus::latch::LatchReader>,
    ) -> io::Result<()> {
        self.serve_surface_with_shutdown(shutdown, RpcSurface::Shared)
    }

    pub fn serve_surface_with_shutdown(
        self,
        shutdown: impl Into<bitcoin_rs_consensus::latch::LatchReader>,
        surface: RpcSurface,
    ) -> io::Result<()> {
        self.serve_accept_loop(&shutdown.into(), surface, mio::net::TcpListener::accept)
    }

    fn serve_accept_loop(
        self,
        shutdown: &bitcoin_rs_consensus::latch::LatchReader,
        surface: RpcSurface,
        accept: impl FnMut(&mio::net::TcpListener) -> io::Result<(mio::net::TcpStream, SocketAddr)>,
    ) -> io::Result<()> {
        self.serve_accept_loop_with_connections(
            shutdown,
            surface,
            accept,
            Arc::new(ConnectionTracker::default()),
        )
    }

    #[cfg(test)]
    fn serve_accept_loop_observed(
        self,
        shutdown: &bitcoin_rs_consensus::latch::LatchReader,
        surface: RpcSurface,
        accept: impl FnMut(&mio::net::TcpListener) -> io::Result<(mio::net::TcpStream, SocketAddr)>,
        connections: Arc<ConnectionTracker>,
    ) -> io::Result<()> {
        self.serve_accept_loop_with_connections(shutdown, surface, accept, connections)
    }

    fn serve_accept_loop_with_connections(
        self,
        shutdown: &bitcoin_rs_consensus::latch::LatchReader,
        surface: RpcSurface,
        mut accept: impl FnMut(&mio::net::TcpListener) -> io::Result<(mio::net::TcpStream, SocketAddr)>,
        connections: Arc<ConnectionTracker>,
    ) -> io::Result<()> {
        let _stop = RpcStop(Arc::clone(&self.handler));
        let handler_clone = Arc::clone(&self.handler);
        let _handler_guard = shutdown.on_cancel(move || {
            handler_clone.stop();
        });
        self.handler
            .configure_blocking_admission(per_source_limit(self.max_connections));
        let mut readiness = mio::Poll::new()?;
        let listener = self.listener.try_clone()?;
        listener.set_nonblocking(true)?;
        let mut listener = mio::net::TcpListener::from_std(listener);
        readiness
            .registry()
            .register(&mut listener, LISTENER_TOKEN, mio::Interest::READABLE)?;
        let waker = Arc::new(mio::Waker::new(readiness.registry(), WAKER_TOKEN)?);
        let waker_cancel = Arc::clone(&waker);
        let _cancel_guard = shutdown.on_cancel(move || {
            let _ = waker_cancel.wake();
        });
        let connection_waker = Arc::clone(&connections);
        let _connection_guard = shutdown.on_cancel(move || {
            connection_waker.wake_readers();
        });
        let mut events = mio::Events::with_capacity(2);
        let context = AcceptContext {
            active: Arc::new(Mutex::new(ActiveConnections::default())),
            connections: Arc::clone(&connections),
            shutdown: shutdown.clone(),
            surface,
        };
        let mut outcome = Ok(());
        while !shutdown.is_triggered() {
            match accept(&listener) {
                Ok((stream, addr)) => {
                    let stream: TcpStream = stream.into();
                    if let Err(error) = stream
                        .set_nonblocking(false)
                        .and_then(|()| self.handle_accept(&context, stream, addr.ip()))
                    {
                        debug!(%error, "rpc connection setup failed");
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(error) =
                        wait_for_accept_readiness(shutdown, &mut readiness, &mut events)
                    {
                        outcome = Err(error);
                        break;
                    }
                }
                Err(error) => match error.kind() {
                    io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted => {
                        debug!(%error, "rpc accept interrupted or connection aborted");
                    }
                    io::ErrorKind::InvalidInput | io::ErrorKind::NotConnected => {
                        outcome = Err(error);
                        break;
                    }
                    _ => {
                        warn!(%error, "rpc accept failed; retrying after backoff");
                        if !wait_accept_backoff(shutdown) {
                            break;
                        }
                    }
                },
            }
        }
        connections.wake_readers();
        drain_connections(&connections);
        outcome
    }

    fn handle_accept(
        &self,
        context: &AcceptContext,
        stream: TcpStream,
        peer: IpAddr,
    ) -> io::Result<()> {
        context.connections.reap_finished();
        let surface = context.surface;
        let mut stream = match prepare_http_socket(stream) {
            Ok(stream) => stream,
            Err(error) => {
                debug!(%error, "rpc connection dropped: nodelay");
                return Ok(());
            }
        };
        let should_accept = context.active.lock().admit(peer, self.max_connections);
        if !should_accept {
            metrics::counter!("rpc.connections.rejected_total", "surface" => surface.label())
                .increment(1);
            stream.set_write_timeout(Some(self.idle_timeout))?;
            write_status(&mut stream, 503, "Service Unavailable", b"busy", false)?;
            return Ok(());
        }

        let permit = ConnectionPermit {
            active: Arc::clone(&context.active),
            peer,
            surface,
        };
        metrics::gauge!("rpc.connections.active", "surface" => surface.label()).increment(1.0);
        let auth = Arc::clone(&self.auth);
        let handler = Arc::clone(&self.handler);
        let rest_enabled = self.rest_enabled;
        let idle_timeout = self.idle_timeout;
        let policy = self.public_policy.clone();
        let id = context.connections.next_id();
        context.connections.admit(id, stream.try_clone()?);
        if context.shutdown.is_triggered() {
            context.connections.wake_readers();
        }
        let tracker = Arc::clone(&context.connections);
        let connection_shutdown = context.shutdown.clone();
        let spawned = thread::Builder::new()
            .name("rpc-connection".to_owned())
            .stack_size(RPC_CONNECTION_STACK_BYTES)
            .spawn(move || {
                let _slot = ConnectionSlot { tracker, id };
                let _permit = permit;
                if let Err(error) = serve_connection_with_policy(
                    stream,
                    &auth,
                    &handler,
                    rest_enabled,
                    idle_timeout,
                    surface,
                    policy,
                    connection_shutdown,
                ) {
                    debug!(%error, "rpc connection closed with error");
                }
            });
        match spawned {
            Ok(handle) => {
                context.connections.record_thread(handle);
                Ok(())
            }
            Err(error) => {
                context.connections.release(id);
                Err(error)
            }
        }
    }
}

fn wait_for_accept_readiness(
    shutdown: &bitcoin_rs_consensus::latch::LatchReader,
    readiness: &mut mio::Poll,
    events: &mut mio::Events,
) -> io::Result<()> {
    while !shutdown.is_triggered() {
        match readiness.poll(events, None) {
            Ok(()) if !events.is_empty() => break,
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn wait_accept_backoff(shutdown: &bitcoin_rs_consensus::latch::LatchReader) -> bool {
    if shutdown.is_triggered() {
        return false;
    }
    crossbeam_channel::select! {
        recv(crossbeam_channel::after(ACCEPT_ERROR_BACKOFF)) -> _ => true,
        recv(shutdown.closed()) -> _ => false,
    }
}

fn per_source_limit(max_connections: usize) -> usize {
    max_connections - max_connections / RESERVED_POOL_DIVISOR
}

#[derive(Default)]
struct ActiveConnections {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

impl ActiveConnections {
    fn admit(&mut self, peer: IpAddr, max_connections: usize) -> bool {
        let per_source_limit = per_source_limit(max_connections);
        if self.total >= max_connections
            || self
                .per_ip
                .get(&peer)
                .is_some_and(|&count| count >= per_source_limit)
        {
            return false;
        }
        self.total += 1;
        *self.per_ip.entry(peer).or_default() += 1;
        true
    }

    fn release(&mut self, peer: IpAddr) {
        let Some(count) = self.per_ip.get_mut(&peer) else {
            unreachable!("connection released without admission");
        };
        self.total -= 1;
        *count -= 1;
        if *count == 0 {
            self.per_ip.remove(&peer);
        }
    }
}

struct ConnectionPermit {
    active: Arc<Mutex<ActiveConnections>>,
    peer: IpAddr,
    surface: RpcSurface,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.lock().release(self.peer);
        metrics::gauge!("rpc.connections.active", "surface" => self.surface.label()).decrement(1.0);
    }
}

struct AcceptContext {
    active: Arc<Mutex<ActiveConnections>>,
    connections: Arc<ConnectionTracker>,
    shutdown: bitcoin_rs_consensus::latch::LatchReader,
    surface: RpcSurface,
}

#[derive(Default)]
struct LiveConnections {
    ids: HashSet<u64>,
}

#[derive(Default)]
struct ConnectionTracker {
    streams: Mutex<HashMap<u64, TcpStream>>,
    threads: Mutex<Vec<thread::JoinHandle<()>>>,
    live: Mutex<LiveConnections>,
    drained: Condvar,
    next_id: AtomicU64,
}

impl ConnectionTracker {
    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn admit(&self, id: u64, stream: TcpStream) {
        self.streams.lock().insert(id, stream);
        self.live.lock().ids.insert(id);
    }

    fn release(&self, id: u64) {
        self.streams.lock().remove(&id);
        let mut live = self.live.lock();
        if live.ids.remove(&id) && live.ids.is_empty() {
            self.drained.notify_all();
        }
    }

    fn record_thread(&self, handle: thread::JoinHandle<()>) {
        self.threads.lock().push(handle);
    }

    fn reap_finished(&self) {
        let mut finished = Vec::new();
        {
            let mut threads = self.threads.lock();
            let mut index = 0;
            while index < threads.len() {
                if threads[index].is_finished() {
                    finished.push(threads.swap_remove(index));
                } else {
                    index += 1;
                }
            }
        }
        for handle in finished {
            if handle.join().is_err() {
                error!("rpc connection panicked");
            }
        }
    }

    fn wake_readers(&self) {
        for stream in self.streams.lock().values() {
            let _ = stream.shutdown(std::net::Shutdown::Read);
        }
    }

    fn wait_for_drain(&self, deadline: Instant) -> bool {
        let mut live = self.live.lock();
        while !live.ids.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            if self.drained.wait_for(&mut live, remaining).timed_out() && !live.ids.is_empty() {
                return false;
            }
        }
        true
    }

    fn live_count(&self) -> usize {
        self.live.lock().ids.len()
    }

    fn take_threads(&self) -> Vec<thread::JoinHandle<()>> {
        std::mem::take(&mut *self.threads.lock())
    }
}

#[cfg(test)]
impl ConnectionTracker {
    fn retained_threads(&self) -> usize {
        self.threads.lock().len()
    }

    fn retained_threads_settled(&self) -> bool {
        self.threads
            .lock()
            .iter()
            .all(|handle| handle.is_finished())
    }
}

struct ConnectionSlot {
    tracker: Arc<ConnectionTracker>,
    id: u64,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.tracker.release(self.id);
    }
}

fn drain_connections(connections: &ConnectionTracker) {
    let deadline = Instant::now() + CONNECTION_DRAIN_DEADLINE;
    let all_drained = connections.wait_for_drain(deadline);
    if !all_drained {
        warn!(
            pending = connections.live_count(),
            "rpc connections exceeded the drain deadline"
        );
    }
    connections.reap_finished();
    for handle in connections.take_threads() {
        if (all_drained || handle.is_finished()) && handle.join().is_err() {
            error!("rpc connection panicked");
        }
    }
}

struct RpcStop(Arc<Handler>);

struct RequestTimer {
    started: Instant,
    surface: RpcSurface,
    route: &'static str,
}

impl Drop for RequestTimer {
    fn drop(&mut self) {
        metrics::histogram!(
            "rpc.http.request_seconds",
            "surface" => self.surface.label(),
            "route" => self.route,
        )
        .record(self.started.elapsed().as_secs_f64());
    }
}

impl Drop for RpcStop {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// A `shutdown` on a duplicated handle does not wake a pending `recv` on
/// Windows; the deadline stream substitutes the wake with a capped poll.
#[cfg(windows)]
const CANCEL_POLL: Duration = Duration::from_millis(100);

struct RequestDeadlineStream {
    stream: TcpStream,
    idle_timeout: Duration,
    shutdown: bitcoin_rs_consensus::latch::LatchReader,
    deadline: Instant,
    applied_timeout: Option<Duration>,
}

impl RequestDeadlineStream {
    fn new(
        stream: TcpStream,
        idle_timeout: Duration,
        shutdown: bitcoin_rs_consensus::latch::LatchReader,
    ) -> Self {
        Self {
            stream,
            idle_timeout,
            shutdown,
            deadline: Instant::now() + idle_timeout,
            applied_timeout: None,
        }
    }

    fn reset_deadline(&mut self, budget: Duration) {
        self.deadline = Instant::now() + budget;
    }

    fn socket_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }
}

impl Read for RequestDeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP request deadline exceeded",
                ));
            }
            let timeout = self.idle_timeout.min(remaining);
            #[cfg(windows)]
            let timeout = timeout.min(CANCEL_POLL);
            if self.applied_timeout != Some(timeout) {
                match self.stream.set_read_timeout(Some(timeout)) {
                    Ok(()) => self.applied_timeout = Some(timeout),
                    Err(error)
                        if cfg!(target_os = "macos")
                            && error.kind() == io::ErrorKind::InvalidInput => {}
                    Err(error) => return Err(error),
                }
            }
            match self.stream.read(buffer) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    if self.shutdown.is_triggered() {
                        return Ok(0);
                    }
                    if cfg!(windows) {
                        continue;
                    }
                    return Err(error);
                }
                other => return other,
            }
        }
    }
}

#[cfg(test)]
fn serve_connection(
    stream: TcpStream,
    auth: &Auth,
    handler: &Handler,
    rest_enabled: bool,
    idle_timeout: Duration,
    surface: RpcSurface,
    shutdown: bitcoin_rs_consensus::latch::LatchReader,
) -> io::Result<()> {
    serve_connection_with_policy(
        stream,
        auth,
        handler,
        rest_enabled,
        idle_timeout,
        surface,
        PublicPolicy::default(),
        shutdown,
    )
}

fn serve_connection_with_policy(
    stream: TcpStream,
    auth: &Auth,
    handler: &Handler,
    rest_enabled: bool,
    idle_timeout: Duration,
    surface: RpcSurface,
    policy: PublicPolicy,
    shutdown: bitcoin_rs_consensus::latch::LatchReader,
) -> io::Result<()> {
    stream.set_write_timeout(Some(idle_timeout))?;
    let mut reader = BufReader::new(RequestDeadlineStream::new(stream, idle_timeout, shutdown));
    loop {
        reader.get_mut().reset_deadline(idle_timeout);
        if reader.fill_buf()?.is_empty() {
            return Ok(());
        }
        reader.get_mut().reset_deadline(REQUEST_HEAD_TIMEOUT);
        let head = match read_request_head(&mut reader) {
            Ok(Some(head)) => head,
            Ok(None) => return Ok(()),
            Err(error) => {
                return handle_read_error(
                    reader.get_mut().socket_mut(),
                    error,
                    rest_enabled,
                    surface,
                    "invalid request: malformed http request",
                );
            }
        };
        let route = classify(&head.method, &head.path);
        let _request_timer = RequestTimer {
            started: Instant::now(),
            surface,
            route: route.label(),
        };
        if !surface.allows(&route) {
            write_not_found(reader.get_mut().socket_mut(), false)?;
            return Ok(());
        }
        if surface == RpcSurface::Public && !policy.is_host_allowed(head.host.as_deref()) {
            write_forbidden(reader.get_mut().socket_mut(), false)?;
            return Ok(());
        }
        if is_esplora_route(&route) && !policy.esplora_enabled {
            write_not_found(reader.get_mut().socket_mut(), false)?;
            return Ok(());
        }
        if is_broadcast_route(&route) && !policy.broadcast_enabled {
            write_not_found(reader.get_mut().socket_mut(), false)?;
            return Ok(());
        }
        if authenticate_json_rpc_head(auth, &mut reader, &head)? {
            return Ok(());
        }
        reader.get_mut().reset_deadline(REQUEST_BODY_TIMEOUT);
        let request = match read_request_body(&mut reader, head) {
            Ok(request) => request,
            Err(error) => {
                return handle_read_error(
                    reader.get_mut().socket_mut(),
                    error,
                    rest_enabled,
                    surface,
                    "malformed http request",
                );
            }
        };
        if handler.is_stopping() {
            return Ok(());
        }
        let keep_alive = request.keep_alive;
        if dispatch_http_request(
            reader.get_mut().socket_mut(),
            &request,
            handler,
            rest_enabled,
            surface,
            &policy,
        )? {
            return Ok(());
        }
        if !keep_alive {
            return Ok(());
        }
    }
}

fn handle_read_error(
    stream: &mut TcpStream,
    error: RequestReadError,
    rest_enabled: bool,
    surface: RpcSurface,
    malformed_msg: &'static str,
) -> io::Result<()> {
    match error {
        RequestReadError::RestBodyTooLarge => {
            let response = if rest_enabled && surface != RpcSurface::Management {
                crate::rest::getutxos_body_too_large()
            } else {
                crate::rest::not_found()
            };
            write_response(stream, &response, false, CorsPolicy::Disabled)?;
            Ok(())
        }
        RequestReadError::Io(err) => {
            let rpc_error = RpcError::InvalidRequest(malformed_msg);
            let response = JsonRpcVersion::Legacy.error_response(&rpc_error, &Value::new_null());
            write_json(stream, 400, "Bad Request", &response, false)?;
            Err(err)
        }
    }
}

fn authenticate_json_rpc_head(
    auth: &Auth,
    reader: &mut BufReader<RequestDeadlineStream>,
    head: &RequestHead,
) -> io::Result<bool> {
    if classify(&head.method, &head.path) != HttpRoute::JsonRpc
        || auth.validate_header(head.authorization.as_deref())
    {
        return Ok(false);
    }
    reject_unauthenticated_json_rpc(reader, head)?;
    Ok(true)
}

fn reject_unauthenticated_json_rpc(
    reader: &mut BufReader<RequestDeadlineStream>,
    head: &RequestHead,
) -> io::Result<()> {
    if head.authorization.is_some() {
        thread::sleep(WRONG_CREDENTIALS_DELAY);
    }
    write_unauthorized(reader.get_mut().socket_mut())?;
    drain_request(reader, head.content_length);
    reader
        .get_mut()
        .socket_mut()
        .shutdown(std::net::Shutdown::Write)
}

fn write_unauthorized(stream: &mut TcpStream) -> io::Result<()> {
    let header = "HTTP/1.1 401 Unauthorized\r\n\
                  WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n\
                  Content-Type: text/html; charset=ISO-8859-1\r\n\
                  Content-Length: 0\r\n\
                  Connection: close\r\n\r\n";
    stream.write_all(header.as_bytes())?;
    stream.flush()
}

fn drain_request(reader: &mut BufReader<RequestDeadlineStream>, declared: usize) {
    reader.get_mut().reset_deadline(DRAIN_BUDGET);
    let mut remaining = declared.min(MAX_DRAIN_BYTES);
    let mut chunk = [0_u8; BODY_READ_CHUNK];
    while remaining > 0 {
        match reader.read(&mut chunk[..remaining.min(BODY_READ_CHUNK)]) {
            Ok(0) | Err(_) => break,
            Ok(read) => remaining = remaining.saturating_sub(read),
        }
    }
}

fn dispatch_http_request(
    stream: &mut TcpStream,
    request: &HttpRequest,
    handler: &Handler,
    rest_enabled: bool,
    rpc_surface: RpcSurface,
    policy: &PublicPolicy,
) -> io::Result<bool> {
    let keep_alive = request.keep_alive;
    match classify(&request.method, &request.path) {
        HttpRoute::Rest { path, query } => {
            let response = crate::rest::route(handler.context(), path, query, rest_enabled);
            write_response(stream, &response, keep_alive, CorsPolicy::Disabled)?;
        }
        HttpRoute::RestPost { path } => {
            let response =
                crate::rest::route_post(handler.context(), path, &request.body, rest_enabled);
            write_response(stream, &response, keep_alive, CorsPolicy::Disabled)?;
        }
        HttpRoute::EsploraGet {
            surface,
            path,
            query,
        } => {
            let allow_origin = if rpc_surface == RpcSurface::Public {
                policy.cors_allow_origin(request.origin.as_deref())
            } else {
                Some("*".to_owned())
            };
            crate::esplora::respond(
                handler,
                esplora_surface(surface),
                path,
                crate::esplora::Request::Get(query),
                |response| {
                    write_response(
                        stream,
                        &response,
                        keep_alive,
                        surface.cors_policy(allow_origin),
                    )
                },
            )?;
        }
        HttpRoute::EsploraPost { surface, path } => {
            let allow_origin = if rpc_surface == RpcSurface::Public {
                policy.cors_allow_origin(request.origin.as_deref())
            } else {
                Some("*".to_owned())
            };
            crate::esplora::respond(
                handler,
                esplora_surface(surface),
                path,
                crate::esplora::Request::Post(&request.body),
                |response| {
                    write_response(
                        stream,
                        &response,
                        keep_alive,
                        surface.cors_policy(allow_origin),
                    )
                },
            )?;
        }
        HttpRoute::Preflight { surface } => {
            let response = crate::rest::Response {
                status: 204,
                reason: "No Content",
                content_type: "text/plain",
                body: Vec::new(),
            };
            let allow_origin = if rpc_surface == RpcSurface::Public {
                policy.cors_allow_origin(request.origin.as_deref())
            } else {
                Some("*".to_owned())
            };
            write_response(
                stream,
                &response,
                keep_alive,
                surface.cors_policy(allow_origin),
            )?;
        }
        HttpRoute::NotFound => {
            write_not_found(stream, keep_alive)?;
        }
        HttpRoute::JsonRpc => {
            let response = handle_json(handler, &request.body);
            let keep_alive = keep_alive && !response.close;
            if let Some(body) = response.body.as_ref() {
                write_json(stream, response.status, response.reason, body, keep_alive)?;
            } else {
                write_status(stream, 204, "No Content", b"", keep_alive)?;
            }
            if response.close {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub keep_alive: bool,
    pub body: Vec<u8>,
    pub host: Option<String>,
    pub origin: Option<String>,
}

const fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn read_head_line(reader: &mut impl BufRead, remaining: usize) -> io::Result<(String, usize)> {
    let mut line = String::new();
    let limit = u64::try_from(remaining + 1).unwrap_or(u64::MAX);
    let read = (&mut *reader).take(limit).read_line(&mut line)?;
    if read > remaining {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "headers too large",
        ));
    }
    if line.ends_with('\r')
        || line
            .as_bytes()
            .windows(2)
            .any(|bytes| bytes[0] == b'\r' && bytes[1] != b'\n')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid carriage return in HTTP head",
        ));
    }
    Ok((line, read))
}

fn trim_header_value(value: &str) -> &str {
    value.trim_matches(|byte: char| {
        matches!(byte, ' ' | '\t' | '\n' | '\u{000b}' | '\u{000c}' | '\r')
    })
}

struct ParsedHeaders {
    content_length: Option<usize>,
    authorization: Option<String>,
    keep_alive: bool,
    host: Option<String>,
    origin: Option<String>,
}

fn read_headers(reader: &mut impl BufRead, mut header_bytes: usize) -> io::Result<ParsedHeaders> {
    let mut content_length = None;
    let mut content_length_text = None;
    let mut authorization = None;
    let mut host = None;
    let mut origin = None;
    let mut keep_alive = false;
    let mut header_count = 0;
    loop {
        let (line, read) = read_head_line(reader, MAX_HEADER_BYTES - header_bytes)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "headers ended early",
            ));
        }
        header_bytes += read;
        if line == "\r\n" {
            return Ok(ParsedHeaders {
                content_length,
                authorization,
                keep_alive,
                host,
                origin,
            });
        }
        header_count += 1;
        if header_count > MAX_HEADER_COUNT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many headers",
            ));
        }
        let Some((name, value)) = line.trim_end_matches(['\r', '\n']).split_once(':') else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid header"));
        };
        if name.is_empty() || !name.bytes().all(is_token_char) || value.contains('\0') {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid header"));
        }
        let value = trim_header_value(value);
        if name.eq_ignore_ascii_case("content-length") {
            let Some(parsed) = crate::decimal::parse_ascii_decimal::<usize>(value) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid content-length",
                ));
            };
            if parsed > MAX_BODY_BYTES {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
            }
            if content_length_text.is_some_and(|previous| previous != value) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "conflicting content-length",
                ));
            }
            content_length_text = Some(value.to_owned());
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported transfer-encoding",
            ));
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("host") {
            if host.is_none() {
                host = Some(value.to_owned());
            }
        } else if name.eq_ignore_ascii_case("origin") {
            if origin.is_none() {
                origin = Some(value.to_owned());
            }
        } else if name.eq_ignore_ascii_case("connection") {
            keep_alive = value.eq_ignore_ascii_case("keep-alive");
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RequestReadError {
    #[error("i/o error reading request: {0}")]
    Io(#[from] io::Error),
    #[error("rest getutxos body exceeds limit")]
    RestBodyTooLarge,
}

pub(crate) struct RequestHead {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) authorization: Option<String>,
    pub(crate) keep_alive: bool,
    pub(crate) content_length: usize,
    pub(crate) host: Option<String>,
    pub(crate) origin: Option<String>,
}

pub(crate) fn read_request_head(
    reader: &mut impl BufRead,
) -> Result<Option<RequestHead>, RequestReadError> {
    if reader.fill_buf()?.is_empty() {
        return Ok(None);
    }
    let (request_line, bytes) = read_head_line(reader, MAX_HEADER_BYTES)?;
    if bytes == 0 {
        return Ok(None);
    }
    if !request_line.ends_with("\r\n") {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request line").into());
    }

    let request_target = request_line.trim_end_matches(['\r', '\n']);
    let mut request_parts = request_target.split(' ');
    let Some(method) = request_parts.next() else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request line").into());
    };
    let Some(path) = request_parts.next() else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request line").into());
    };
    let Some(version) = request_parts.next() else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request line").into());
    };
    if request_parts.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request line").into());
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request version").into());
    }
    if path.is_empty() || path.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request target").into());
    }
    if method.is_empty() || !method.bytes().all(is_token_char) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request method").into());
    }
    let headers = read_headers(reader, request_line.len())?;

    let content_length = match (method, headers.content_length) {
        ("POST", None) => {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "missing content-length").into(),
            );
        }
        (_, Some(len)) => len,
        (_, None) => 0,
    };
    if method == "POST"
        && crate::rest::getutxos_suffix(split_path_query(path).0).is_some()
        && content_length > crate::rest::MAX_GETUTXOS_BODY_BYTES
    {
        return Err(RequestReadError::RestBodyTooLarge);
    }
    Ok(Some(RequestHead {
        method: method.to_owned(),
        path: path.to_owned(),
        authorization: headers.authorization,
        keep_alive: headers.keep_alive,
        content_length,
        host: headers.host,
        origin: headers.origin,
    }))
}

pub(crate) fn read_request_body(
    reader: &mut impl Read,
    head: RequestHead,
) -> Result<HttpRequest, RequestReadError> {
    let mut body = Vec::new();
    read_body(reader, head.content_length, &mut body)?;
    Ok(HttpRequest {
        method: head.method,
        path: head.path,
        keep_alive: head.keep_alive,
        body,
        host: head.host,
        origin: head.origin,
    })
}

#[cfg(any(test, feature = "test-seam"))]
pub fn read_http_request(
    reader: &mut impl BufRead,
) -> Result<Option<HttpRequest>, RequestReadError> {
    match read_request_head(reader)? {
        Some(head) => read_request_body(reader, head).map(Some),
        None => Ok(None),
    }
}

const BODY_READ_CHUNK: usize = 8 * 1_024;

fn read_body(reader: &mut impl Read, content_length: usize, body: &mut Vec<u8>) -> io::Result<()> {
    let mut chunk = [0_u8; BODY_READ_CHUNK];
    while body.len() < content_length {
        let remaining = content_length - body.len();
        let read = match reader.read(&mut chunk[..remaining.min(BODY_READ_CHUNK)]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "request body ended early",
                ));
            }
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if body.capacity() - body.len() < read {
            body.try_reserve_exact(remaining.min(body.len().max(BODY_READ_CHUNK)))?;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonResponse {
    pub close: bool,
    pub status: u16,
    pub reason: &'static str,
    pub body: Option<Value>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum JsonRpcVersion {
    Legacy,
    V2,
}

impl JsonRpcVersion {
    fn classify(request: &Value) -> Result<Self, RpcError> {
        let Some(version) = request.get("jsonrpc") else {
            return Ok(Self::Legacy);
        };
        if version.is_null() {
            return Ok(Self::Legacy);
        }
        let Some(version) = version.as_str() else {
            return Err(RpcError::InvalidRequest("jsonrpc field must be a string"));
        };
        match version {
            "1.0" => Ok(Self::Legacy),
            "2.0" => Ok(Self::V2),
            _ => Err(RpcError::InvalidRequest("JSON-RPC version not supported")),
        }
    }

    fn success_response(self, result: Value, id: &Value) -> Value {
        let mut response = match self {
            Self::Legacy => json!({"result": null, "error": null, "id": id}),
            Self::V2 => json!({"jsonrpc": "2.0", "result": null, "id": id}),
        };
        let _ = response.insert("result", result);
        response
    }

    fn error_response(self, error: &RpcError, id: &Value) -> Value {
        match self {
            Self::Legacy => json!({
                "result": null,
                "error": {"code": error.code(), "message": error.to_string()},
                "id": id
            }),
            Self::V2 => json!({
                "jsonrpc": "2.0",
                "error": {"code": error.code(), "message": error.to_string()},
                "id": id
            }),
        }
    }

    const fn error_status_for(self, error: &RpcError) -> u16 {
        self.error_status_for_code(error.code())
    }

    const fn error_status_for_code(self, code: i64) -> u16 {
        match self {
            Self::Legacy => match code {
                RpcError::INVALID_REQUEST => 400,
                RpcError::METHOD_NOT_FOUND => 404,
                _ => 500,
            },
            Self::V2 => match code {
                RpcError::INVALID_REQUEST => 400,
                _ => 200,
            },
        }
    }
}

enum CallResponse {
    Reply {
        body: Value,
        version: JsonRpcVersion,
        error: Option<RpcError>,
        envelope_error: bool,
    },
    Notification {
        pre_reservation_refusal: bool,
    },
}

impl CallResponse {
    fn reply(body: Value, version: JsonRpcVersion, error: Option<RpcError>) -> Self {
        Self::Reply {
            body,
            version,
            error,
            envelope_error: false,
        }
    }

    fn envelope_error(body: Value, version: JsonRpcVersion, error: RpcError) -> Self {
        Self::Reply {
            body,
            version,
            error: Some(error),
            envelope_error: true,
        }
    }

    /// The request was refused before it could hold a reservation, so the
    /// keep-alive slot it answered on has nothing a close would release.
    const fn pre_reservation_refusal(&self) -> bool {
        matches!(
            self,
            Self::Reply {
                error: Some(RpcError::ScanInProgress(_)),
                ..
            } | Self::Notification {
                pre_reservation_refusal: true,
            }
        )
    }

    const fn http_status(&self) -> u16 {
        match self {
            Self::Reply {
                version,
                error: Some(error),
                ..
            } => version.error_status_for_code(error.code()),
            Self::Reply {
                envelope_error: true,
                ..
            } => 400,
            Self::Reply { .. } | Self::Notification { .. } => 200,
        }
    }
}

const RPC_CONNECTION_STACK_BYTES: usize = 2 * 1024 * 1024;

const MAX_JSON_DEPTH: usize = 512;

fn check_json_depth(body: &[u8]) -> Result<(), RpcError> {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in body {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'[' | b'{' => {
                    depth = depth.saturating_add(1);
                    if depth > MAX_JSON_DEPTH {
                        return Err(RpcError::TopLevelParse("JSON nesting depth limit exceeded"));
                    }
                }
                b']' | b'}' => {
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

pub fn handle_json(handler: &Handler, body: &[u8]) -> JsonResponse {
    let body_str = match core::str::from_utf8(body) {
        Ok(body) => body,
        Err(error) => {
            return legacy_error_response(&RpcError::from(error), &Value::new_null());
        }
    };
    if let Err(error) = check_json_depth(body) {
        return legacy_error_response(&error, &Value::new_null());
    }
    let request = match sonic_rs::from_str::<Value>(body_str) {
        Ok(request) => request,
        Err(error) => {
            return legacy_error_response(&RpcError::from(error), &Value::new_null());
        }
    };

    handle_decoded_json(handler, &request)
}

const MAX_BATCH_ELEMENTS: usize = 1_000;

fn v2_notification(request: &Value) -> bool {
    request.get("jsonrpc").and_then(Value::as_str) == Some("2.0") && request.get("id").is_none()
}

fn handle_decoded_json(handler: &Handler, request: &Value) -> JsonResponse {
    if let Some(requests) = request.as_array() {
        if requests.len() > MAX_BATCH_ELEMENTS {
            return legacy_error_response(
                &RpcError::InvalidRequest("Batch size limit exceeded"),
                &Value::new_null(),
            );
        }
        if requests.is_empty() {
            return JsonResponse {
                close: false,
                status: 200,
                reason: reason_for_status(200),
                body: Some(json!([])),
            };
        }
        let mut responses = Vec::with_capacity(requests.len());
        let mut worker_held = false;
        for request in requests {
            let notification = v2_notification(request);
            let response = handle_single_json(handler, request);
            let blocked =
                crate::registry::blocking_request(request) && !response.pre_reservation_refusal();
            match response {
                CallResponse::Reply {
                    body,
                    envelope_error,
                    ..
                } if !(envelope_error && notification) => {
                    worker_held |= blocked;
                    responses.push(body);
                }
                CallResponse::Reply { .. } => {}
                CallResponse::Notification { .. } => worker_held |= blocked,
            }
        }
        if responses.is_empty() {
            return if worker_held {
                closing_no_content_response()
            } else {
                no_content_response()
            };
        }
        return JsonResponse {
            close: worker_held,
            status: 200,
            reason: reason_for_status(200),
            body: Some(Value::from(responses)),
        };
    }
    let close = crate::registry::blocking_request(request);
    if !request.is_object() {
        return legacy_error_response(
            &RpcError::TopLevelParse("Top-level object parse error"),
            &Value::new_null(),
        );
    }

    let response = handle_single_json(handler, request);
    let status = response.http_status();
    let close = close && !response.pre_reservation_refusal();
    match response {
        CallResponse::Reply { body, .. } => JsonResponse {
            close,
            status,
            reason: reason_for_status(status),
            body: Some(body),
        },
        CallResponse::Notification { .. } => {
            if close {
                closing_no_content_response()
            } else {
                no_content_response()
            }
        }
    }
}

fn handle_single_json(handler: &Handler, request: &Value) -> CallResponse {
    let id = request.get("id").cloned().unwrap_or_else(Value::new_null);
    if !request.is_object() {
        let error = RpcError::InvalidRequest("Invalid Request object");
        let version = JsonRpcVersion::Legacy;
        return CallResponse::envelope_error(version.error_response(&error, &id), version, error);
    }
    let version = match JsonRpcVersion::classify(request) {
        Ok(version) => version,
        Err(error) => {
            let version = JsonRpcVersion::Legacy;
            return CallResponse::envelope_error(
                version.error_response(&error, &id),
                version,
                error,
            );
        }
    };
    let Some(method) = request.get("method").filter(|method| !method.is_null()) else {
        let error = RpcError::InvalidRequest("Missing method");
        return CallResponse::envelope_error(version.error_response(&error, &id), version, error);
    };
    let Some(method) = method.as_str() else {
        let error = RpcError::InvalidRequest("Method must be a string");
        return CallResponse::envelope_error(version.error_response(&error, &id), version, error);
    };
    let null_params = Value::new_null();
    let params = request.get("params").unwrap_or(&null_params);
    if !(params.is_array() || params.is_object() || params.is_null()) {
        let error = RpcError::InvalidRequest("Params must be an array or object");
        return CallResponse::envelope_error(version.error_response(&error, &id), version, error);
    }
    let empty_params = json!([]);
    // An empty params object is "no named parameters": Core routes every
    // object params through transformNamedArguments (src/rpc/server.cpp),
    // which maps `{}` to an empty positional array for any method, exactly as
    // a null params field already is (src/rpc/request.cpp).
    let params = if params.is_null() || params.as_object().is_some_and(sonic_rs::Object::is_empty) {
        &empty_params
    } else {
        params
    };
    let result = handler.dispatch(method, params);
    let pre_reservation_refusal = matches!(&result, Err(RpcError::ScanInProgress(_)));
    if v2_notification(request) {
        return CallResponse::Notification {
            pre_reservation_refusal,
        };
    }
    match result {
        Ok(result) => CallResponse::reply(version.success_response(result, &id), version, None),
        Err(error) => {
            CallResponse::reply(version.error_response(&error, &id), version, Some(error))
        }
    }
}

fn legacy_error_response(error: &RpcError, id: &Value) -> JsonResponse {
    let version = JsonRpcVersion::Legacy;
    let status = version.error_status_for(error);
    JsonResponse {
        close: false,
        status,
        reason: reason_for_status(status),
        body: Some(version.error_response(error, id)),
    }
}

const fn reason_for_status(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Internal Server Error",
    }
}

const fn no_content_response() -> JsonResponse {
    no_content_response_inner(false)
}

const fn closing_no_content_response() -> JsonResponse {
    no_content_response_inner(true)
}

const fn no_content_response_inner(close: bool) -> JsonResponse {
    JsonResponse {
        close,
        status: 204,
        reason: "No Content",
        body: None,
    }
}

fn write_json(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    value: &Value,
    keep_alive: bool,
) -> io::Result<()> {
    let body = sonic_rs::to_string(value).map_err(|error| {
        warn!(%error, "failed to serialize rpc response");
        io::Error::other("json serialization failed")
    })?;
    write_status(stream, status, reason, body.as_bytes(), keep_alive)
}

fn write_status(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
    keep_alive: bool,
) -> io::Result<()> {
    let head = ResponseHead {
        status,
        reason,
        content_type: "application/json",
        content_length: body.len(),
        keep_alive,
        cors_policy: CorsPolicy::Disabled,
    };
    let header = render_response_head(&head);
    write_all_vectored(stream, header.as_bytes(), body)?;
    stream.flush()
}

fn split_path_query(path: &str) -> (&str, &str) {
    path.split_once('?')
        .map_or((path, ""), |(path, query)| (path, query))
}

#[derive(Debug, Eq, PartialEq)]
enum HttpRoute<'a> {
    RestPost {
        path: &'a str,
    },
    Rest {
        path: &'a str,
        query: &'a str,
    },
    EsploraGet {
        surface: HttpSurface,
        path: &'a str,
        query: &'a str,
    },
    EsploraPost {
        surface: HttpSurface,
        path: &'a str,
    },
    Preflight {
        surface: HttpSurface,
    },
    NotFound,
    JsonRpc,
}

impl HttpRoute<'_> {
    const fn label(&self) -> &'static str {
        match self {
            Self::Rest { .. } | Self::RestPost { .. } => "rest",
            Self::EsploraGet {
                surface: HttpSurface::EsploraPublic,
                ..
            }
            | Self::EsploraPost {
                surface: HttpSurface::EsploraPublic,
                ..
            }
            | Self::Preflight { .. } => "esplora_public",
            Self::EsploraGet {
                surface: HttpSurface::EsploraBackend,
                ..
            }
            | Self::EsploraPost {
                surface: HttpSurface::EsploraBackend,
                ..
            } => "esplora_backend",
            Self::NotFound => "not_found",
            Self::JsonRpc => "json_rpc",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpSurface {
    EsploraPublic,
    EsploraBackend,
}

#[derive(Debug)]
enum CorsPolicy {
    Disabled,
    Public {
        methods: &'static [&'static str],
        headers: &'static [&'static str],
        expose: &'static [&'static str],
        allow_origin: Option<String>,
    },
}

impl HttpSurface {
    fn cors_policy(self, allow_origin: Option<String>) -> CorsPolicy {
        match self {
            Self::EsploraPublic => CorsPolicy::Public {
                methods: PUBLIC_ESPLORA_METHODS,
                headers: PUBLIC_ESPLORA_HEADERS,
                expose: PUBLIC_ESPLORA_EXPOSE_HEADERS,
                allow_origin,
            },
            Self::EsploraBackend => CorsPolicy::Disabled,
        }
    }
}

fn classify<'a>(method: &str, raw_path: &'a str) -> HttpRoute<'a> {
    let (path, query) = split_path_query(raw_path);
    if path.starts_with("/rest/") {
        return if method == "GET" {
            HttpRoute::Rest { path, query }
        } else if method == "POST" && crate::rest::getutxos_suffix(path).is_some() {
            HttpRoute::RestPost { path }
        } else {
            HttpRoute::NotFound
        };
    }
    if let Some((surface, rest)) = crate::esplora::namespace(path) {
        let surface = match surface {
            crate::esplora::Surface::Public => HttpSurface::EsploraPublic,
            crate::esplora::Surface::Backend => HttpSurface::EsploraBackend,
        };
        let path = if rest.is_empty() { "/" } else { rest };
        match method {
            "GET" => HttpRoute::EsploraGet {
                surface,
                path,
                query,
            },
            "POST" => HttpRoute::EsploraPost { surface, path },
            "OPTIONS" if surface == HttpSurface::EsploraPublic => HttpRoute::Preflight { surface },
            _ => HttpRoute::NotFound,
        }
    } else {
        match method {
            "POST" => HttpRoute::JsonRpc,
            _ => HttpRoute::NotFound,
        }
    }
}
fn esplora_surface(surface: HttpSurface) -> crate::esplora::Surface {
    match surface {
        HttpSurface::EsploraPublic => crate::esplora::Surface::Public,
        HttpSurface::EsploraBackend => crate::esplora::Surface::Backend,
    }
}

fn write_not_found(stream: &mut TcpStream, keep_alive: bool) -> io::Result<()> {
    write_response(
        stream,
        &crate::rest::Response {
            status: 404,
            reason: "Not Found",
            content_type: "text/plain",
            body: b"not found".to_vec(),
        },
        keep_alive,
        CorsPolicy::Disabled,
    )
}

fn write_forbidden(stream: &mut TcpStream, keep_alive: bool) -> io::Result<()> {
    write_response(
        stream,
        &crate::rest::Response {
            status: 403,
            reason: "Forbidden",
            content_type: "text/plain",
            body: b"forbidden".to_vec(),
        },
        keep_alive,
        CorsPolicy::Disabled,
    )
}

fn is_esplora_route(route: &HttpRoute<'_>) -> bool {
    matches!(
        route,
        HttpRoute::EsploraGet { .. } | HttpRoute::EsploraPost { .. } | HttpRoute::Preflight { .. }
    )
}

fn is_broadcast_route(route: &HttpRoute<'_>) -> bool {
    matches!(
        route,
        HttpRoute::EsploraPost {
            surface: HttpSurface::EsploraPublic,
            ..
        }
    )
}

fn write_response(
    stream: &mut TcpStream,
    response: &crate::rest::Response,
    keep_alive: bool,
    cors_policy: CorsPolicy,
) -> io::Result<()> {
    let head = ResponseHead {
        status: response.status,
        reason: response.reason,
        content_type: response.content_type,
        content_length: response.body.len(),
        keep_alive,
        cors_policy,
    };
    let header = render_response_head(&head);
    write_all_vectored(stream, header.as_bytes(), &response.body)?;
    stream.flush()
}

fn prepare_http_socket(stream: TcpStream) -> io::Result<TcpStream> {
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn write_all_vectored(stream: &mut impl Write, header: &[u8], body: &[u8]) -> io::Result<()> {
    let mut slices: &mut [IoSlice<'_>] = &mut [IoSlice::new(header), IoSlice::new(body)];
    while !slices.is_empty() {
        match stream.write_vectored(slices) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write http response",
                ));
            }
            Ok(written) => IoSlice::advance_slices(&mut slices, written),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn render_response_head(head: &ResponseHead<'_>) -> String {
    let connection = if head.keep_alive {
        "keep-alive"
    } else {
        "close"
    };
    let mut header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\n",
        head.status, head.reason, head.content_type
    );
    if let CorsPolicy::Public {
        methods,
        headers,
        expose,
        allow_origin: Some(allow_origin),
    } = &head.cors_policy
    {
        header.push_str("Access-Control-Allow-Origin: ");
        header.push_str(allow_origin);
        header.push_str("\r\n");
        for (name, values) in [
            ("Access-Control-Allow-Methods", *methods),
            ("Access-Control-Allow-Headers", *headers),
            ("Access-Control-Expose-Headers", *expose),
        ] {
            header.push_str(name);
            header.push_str(": ");
            header.push_str(&values.join(", "));
            header.push_str("\r\n");
        }
    }
    if head.status != 204 {
        header.push_str(&format!("Content-Length: {}\r\n", head.content_length));
    }
    header.push_str(&format!("Connection: {connection}\r\n\r\n"));
    header
}
struct ResponseHead<'a> {
    status: u16,
    reason: &'a str,
    content_type: &'a str,
    content_length: usize,
    keep_alive: bool,
    cors_policy: CorsPolicy,
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    mod listeners {
        use super::*;

        // API-10
        #[test]
        fn raw_transaction_budget_is_shared_across_public_and_authenticated_listeners()
        -> io::Result<()> {
            let ctx = Arc::new(Context::new());
            let public = RunningServer::start(&ctx, RpcSurface::Public, 32)?;
            let rpc = RunningServer::start(&ctx, RpcSurface::Shared, 32)?;
            let permits = (0..8)
                .map(|_| {
                    ctx.tx_decode_admission
                        .reserve(["00"])
                        .expect("reserve decode")
                })
                .collect::<Vec<_>>();
            std::thread::scope(|scope| {
                let tasks = (0..8)
                    .map(|_| {
                        let public = &public;
                        scope.spawn(move || {
                            let response = public.request(b"POST /api/tx HTTP/1.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n00").expect("public request");
                            assert!(response.starts_with("HTTP/1.1 503"), "{response}");
                        })
                    })
                    .collect::<Vec<_>>();
                let body =
                    r#"{"jsonrpc":"2.0","id":1,"method":"decoderawtransaction","params":["00"]}"#;
                let request = format!(
                    "POST / HTTP/1.1\r\nAuthorization: Basic {GOOD_TOKEN}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let response = rpc
                    .request(request.as_bytes())
                    .expect("authenticated request");
                assert!(
                    response.contains("raw transaction decode budget exhausted; retry"),
                    "{response}"
                );
                for task in tasks {
                    task.join().expect("public worker");
                }
            });
            let response = public
                .request(b"POST / HTTP/1.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")?;
            assert!(response.starts_with("HTTP/1.1 404"));
            drop(permits);
            let response = public.request(
                b"POST /api/tx HTTP/1.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n00",
            )?;
            assert!(
                response.starts_with("HTTP/1.1 400"),
                "decode resumes: {response}"
            );
            Ok(())
        }

        struct RunningServer {
            address: SocketAddr,
            shutdown: bitcoin_rs_consensus::latch::LatchWriter,
            worker: Option<thread::JoinHandle<io::Result<()>>>,
            handler: Arc<Handler>,
        }

        impl RunningServer {
            fn start(
                context: &Arc<Context>,
                surface: RpcSurface,
                limit: usize,
            ) -> io::Result<Self> {
                Self::start_with_policy(context, surface, limit, PublicPolicy::default())
            }

            fn start_with_policy(
                context: &Arc<Context>,
                surface: RpcSurface,
                limit: usize,
                policy: PublicPolicy,
            ) -> io::Result<Self> {
                let mut server = RpcServer::bind(
                    "127.0.0.1:0",
                    Arc::new(Auth::basic("alice", "secret")),
                    Arc::new(Handler::new(Arc::clone(context))),
                    limit,
                    Duration::from_secs(5),
                    true,
                )?;
                server.public_policy = policy;
                let address = server.local_addr()?;
                let handler = Arc::clone(&server.handler);
                let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
                let stop = shutdown.reader();
                let worker = Some(thread::spawn(move || {
                    server.serve_surface_with_shutdown(stop, surface)
                }));
                Ok(Self {
                    address,
                    shutdown,
                    worker,
                    handler,
                })
            }

            fn connect(&self) -> io::Result<TcpStream> {
                let stream = TcpStream::connect(self.address)?;
                stream.set_read_timeout(Some(Duration::from_secs(30)))?;
                stream.set_write_timeout(Some(Duration::from_secs(30)))?;
                Ok(stream)
            }

            fn request(&self, request: &[u8]) -> io::Result<String> {
                let mut stream = self.connect()?;
                stream.write_all(request)?;
                read_response(&mut stream)
            }

            fn stop(&mut self) {
                self.shutdown.trigger();
                if let Some(worker) = self.worker.take() {
                    worker
                        .join()
                        .expect("listener thread")
                        .expect("listener exit");
                }
            }
        }

        impl Drop for RunningServer {
            fn drop(&mut self) {
                self.stop();
            }
        }

        fn read_response(stream: &mut TcpStream) -> io::Result<String> {
            let mut reader = BufReader::new(stream);
            let mut response = String::new();
            let mut length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line)? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "missing HTTP head",
                    ));
                }
                if let Some(value) = line.strip_prefix("Content-Length: ") {
                    length = value.trim().parse().expect("response length");
                }
                let end = line == "\r\n";
                response.push_str(&line);
                if end {
                    break;
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body)?;
            response.push_str(&String::from_utf8_lossy(&body));
            Ok(response)
        }

        fn management_request() -> Vec<u8> {
            let body = br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#;
            let mut request = json_rpc_head(Some(GOOD_TOKEN), body.len());
            request.extend_from_slice(body);
            request
        }

        // API-08, API-09, WF-02
        #[test]
        fn expensive_query_saturation_preserves_shared_and_split_listener_service() -> io::Result<()>
        {
            let control = crate::mining::FakeMiningControl::unavailable("template fixture");
            let mut context = Context::new()
                .with_esplora_query_limit(std::num::NonZeroUsize::MIN)
                .with_mining_control(control.clone());
            context.chain.chain_network = bitcoin_rs_consensus::primitives::Network::Regtest;
            let context = Arc::new(context);
            let shared = RunningServer::start(&context, RpcSurface::Shared, 16)?;
            let public = RunningServer::start(&context, RpcSurface::Public, 16)?;
            let management = RunningServer::start(&context, RpcSurface::Management, 16)?;
            let permit = context
                .esplora_admission
                .try_acquire()
                .expect("first query");
            for server in [&shared, &public] {
                for prefix in ["/api", "/esplora"] {
                    for namespace in ["address", "scripthash"] {
                        for suffix in [
                            "",
                            "/utxo",
                            "/txs",
                            "/txs/summary",
                            "/txs/mempool",
                            "/txs/chain",
                            "/txs/chain/cursor",
                        ] {
                            let response = server.request(format!(
                        "GET {prefix}/{namespace}/invalid{suffix} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    ).as_bytes())?;
                            assert!(response.starts_with("HTTP/1.1 503"), "{response}");
                            assert_eq!(
                                response.contains("Access-Control-Allow-Origin: *"),
                                prefix == "/api"
                            );
                        }
                    }
                }
                let response = server.request(
                    b"GET /esplora/block-template HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )?;
                assert!(response.starts_with("HTTP/1.1 503"), "{response}");
                let response = server.request(
                    b"GET /api/block-template HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )?;
                assert!(response.starts_with("HTTP/1.1 404"), "{response}");
                let response = server.request(
            b"GET /api/blocks/tip/height HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )?;
                assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
            }
            assert_eq!(control.template_calls.load(Ordering::Relaxed), 0);
            for server in [&shared, &management] {
                assert!(
                    server
                        .request(&management_request())?
                        .contains("\"result\":0")
                );
                // This is a separate quota, even on the shared listener.
                let _blocking = server
                    .handler
                    .reserve_blocking_request()
                    .expect("management quota");
            }
            drop(permit);
            for server in [&shared, &public] {
                let response = server.request(
            b"GET /api/address/invalid HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )?;
                assert!(response.starts_with("HTTP/1.1 400"), "{response}");
                let response = server.request(
                    b"GET /esplora/block-template HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )?;
                assert!(response.starts_with("HTTP/1.1 503"), "{response}");
            }
            assert_eq!(control.template_calls.load(Ordering::Relaxed), 2);
            Ok(())
        }

        #[test]
        fn public_saturation_preserves_management_and_recovers() -> io::Result<()> {
            let context = Arc::new(Context::new());
            let mut public = RunningServer::start(&context, RpcSurface::Public, 2)?;
            let management = RunningServer::start(&context, RpcSurface::Management, 2)?;
            assert!(Arc::ptr_eq(
                public.handler.context(),
                management.handler.context()
            ));
            assert!(!Arc::ptr_eq(&public.handler, &management.handler));

            let mut idle = public.connect()?;
            idle.write_all(
        b"GET /api/blocks/tip/height HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
    )?;
            let response = read_response(&mut idle)?;
            assert!(
                response.contains("Access-Control-Allow-Origin: *"),
                "{response}"
            );
            let mut slow = public.connect()?;
            slow.write_all(b"G")?;
            let busy = read_response(&mut public.connect()?)?;
            assert!(
                busy.starts_with("HTTP/1.1 503 Service Unavailable"),
                "{busy}"
            );

            let response = management.request(&management_request())?;
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
            assert!(response.contains("\"result\":0"), "{response}");
            let unauthorized = management.request(&json_rpc_head(None, 0))?;
            assert_eq!(unauthorized, CORE_UNAUTHORIZED);

            drop(idle);
            let deadline = Instant::now() + Duration::from_secs(30);
            poll_until_response(
                deadline,
                "public permit was not released",
                || public_recovery_probe(&public, deadline),
                |response| response.contains("Access-Control-Allow-Origin: *"),
            )?;
            drop(slow);
            public.stop();
            assert!(public.handler.is_stopping());
            assert!(!management.handler.is_stopping());
            assert!(
                management
                    .request(&management_request())?
                    .contains("\"result\":0")
            );
            let saturation_deadline = Instant::now() + Duration::from_secs(30);
            poll_until_response(
                saturation_deadline,
                "management saturation was not observed",
                || saturation_probe(&management, saturation_deadline),
                |response| response.starts_with("HTTP/1.1 503 Service Unavailable"),
            )?;
            Ok(())
        }

        fn public_recovery_probe(public: &RunningServer, deadline: Instant) -> io::Result<String> {
            let mut recovered = public.connect()?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "recovery deadline elapsed",
                ));
            }
            recovered.set_read_timeout(Some(remaining))?;
            recovered.set_write_timeout(Some(remaining))?;
            recovered.write_all(
        b"GET /api/blocks/tip/height HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )?;
            read_response(&mut recovered)
        }

        fn saturation_probe(management: &RunningServer, deadline: Instant) -> io::Result<String> {
            let _idle_holder = management.connect()?;
            let _slow_holder = management.connect()?;
            let mut probe_stream = management.connect()?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "saturation deadline elapsed",
                ));
            }
            probe_stream.set_read_timeout(Some(remaining))?;
            probe_stream.set_write_timeout(Some(remaining))?;
            read_response(&mut probe_stream)
        }

        fn poll_until_response(
            deadline: Instant,
            pending_message: &str,
            mut attempt: impl FnMut() -> io::Result<String>,
            mut satisfied: impl FnMut(&str) -> bool,
        ) -> io::Result<()> {
            let mut attempts = 0;
            let mut last: String;
            loop {
                attempts += 1;
                match attempt() {
                    Ok(response) => {
                        if satisfied(&response) {
                            return Ok(());
                        }
                        last = response.lines().next().unwrap_or("(empty head)").to_owned();
                    }
                    Err(error) => {
                        last = error.to_string();
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "{pending_message} within 30s after {attempts} attempts; last observation: {last}"
                );
                thread::sleep(Duration::from_millis(5));
            }
        }

        // WF-02
        #[test]
        fn split_listener_routes_are_closed_before_authentication_and_body_upload() -> io::Result<()>
        {
            let context = Arc::new(Context::new());
            let public = RunningServer::start(&context, RpcSurface::Public, 8)?;
            let management = RunningServer::start(&context, RpcSurface::Management, 8)?;
            for path in ["/", "/tx", "/unknown"] {
                let request = format!(
                    "POST {path} HTTP/1.1\r\nAuthorization: Basic {GOOD_TOKEN}\r\nContent-Length: 4096\r\n\r\n"
                );
                assert!(
                    public
                        .request(request.as_bytes())?
                        .starts_with("HTTP/1.1 404 Not Found")
                );
            }
            for path in ["/api/tx", "/esplora/internal/txs", "/rest/getutxos.bin"] {
                let request = format!("POST {path} HTTP/1.1\r\nContent-Length: 4096\r\n\r\n");
                assert!(
                    management
                        .request(request.as_bytes())?
                        .starts_with("HTTP/1.1 404 Not Found")
                );
            }
            let preflight = public.request(
                b"OPTIONS /api/tx HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )?;
            assert!(preflight.starts_with("HTTP/1.1 204 No Content"));
            assert!(preflight.contains("Access-Control-Allow-Origin: *"));
            for path in [
                "/api/internal/txs",
                "/esplora/unknown",
                "/rest/unknown.json",
            ] {
                let response = public.request(
                    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )?;
                assert!(response.starts_with("HTTP/1.1 404 Not Found"), "{response}");
            }
            Ok(())
        }
        // API-08
        #[test]
        fn public_policy_defaults_stay_open() {
            let policy = PublicPolicy::default();
            assert!(policy.esplora_enabled);
            assert!(policy.broadcast_enabled);
            assert!(policy.allowed_hosts.is_empty());
            assert!(policy.allowed_origins.is_empty());
            assert!(policy.is_host_allowed(None));
            assert!(policy.is_host_allowed(Some("example.com")));
            assert_eq!(policy.cors_allow_origin(None).as_deref(), Some("*"));
            assert_eq!(
                policy
                    .cors_allow_origin(Some("https://app.example"))
                    .as_deref(),
                Some("*")
            );
        }

        // API-08
        #[test]
        fn disabled_esplora_answers_public_reads_with_not_found() -> io::Result<()> {
            let context = Arc::new(Context::new());
            let policy = PublicPolicy {
                esplora_enabled: false,
                ..PublicPolicy::default()
            };
            let public = RunningServer::start_with_policy(&context, RpcSurface::Public, 8, policy)?;
            let preflight = public.request(
                b"OPTIONS /api/tx HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )?;
            assert!(
                preflight.starts_with("HTTP/1.1 404 Not Found"),
                "{preflight}"
            );
            let read = public.request(
                b"GET /api/blocks/tip/height HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )?;
            assert!(read.starts_with("HTTP/1.1 404 Not Found"), "{read}");
            Ok(())
        }

        // API-08
        #[test]
        fn disabled_broadcast_answers_public_post_with_not_found() -> io::Result<()> {
            let context = Arc::new(Context::new());
            let policy = PublicPolicy {
                broadcast_enabled: false,
                ..PublicPolicy::default()
            };
            let public = RunningServer::start_with_policy(&context, RpcSurface::Public, 8, policy)?;
            let broadcast = public.request(
                b"POST /api/tx HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n00",
            )?;
            assert!(
                broadcast.starts_with("HTTP/1.1 404 Not Found"),
                "{broadcast}"
            );
            let read = public.request(
                b"GET /api/blocks/tip/height HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )?;
            assert!(!read.starts_with("HTTP/1.1 404 Not Found"), "{read}");
            Ok(())
        }

        // API-08
        #[test]
        fn public_host_allowlist_refuses_unknown_hosts() -> io::Result<()> {
            let context = Arc::new(Context::new());
            let policy = PublicPolicy {
                allowed_hosts: vec!["example.com".to_owned()],
                ..PublicPolicy::default()
            };
            let public = RunningServer::start_with_policy(&context, RpcSurface::Public, 8, policy)?;
            let allowed = public.request(
                b"GET /api/blocks/tip/height HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
            )?;
            assert!(!allowed.starts_with("HTTP/1.1 403 Forbidden"), "{allowed}");
            let denied = public.request(
                b"GET /api/blocks/tip/height HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
            )?;
            assert!(denied.starts_with("HTTP/1.1 403 Forbidden"), "{denied}");
            Ok(())
        }

        // API-08
        #[test]
        fn public_origin_allowlist_echoes_only_matches() -> io::Result<()> {
            let context = Arc::new(Context::new());
            let open = RunningServer::start(&context, RpcSurface::Public, 8)?;
            let response = open.request(
                b"OPTIONS /api/tx HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example\r\nConnection: close\r\n\r\n",
            )?;
            assert!(
                response.contains("Access-Control-Allow-Origin: *"),
                "{response}"
            );
            let policy = PublicPolicy {
                allowed_origins: vec!["https://app.example".to_owned()],
                ..PublicPolicy::default()
            };
            let guarded =
                RunningServer::start_with_policy(&context, RpcSurface::Public, 8, policy)?;
            let echoed = guarded.request(
                b"OPTIONS /api/tx HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example\r\nConnection: close\r\n\r\n",
            )?;
            assert!(
                echoed.contains("Access-Control-Allow-Origin: https://app.example"),
                "{echoed}"
            );
            let withheld = guarded.request(
                b"OPTIONS /api/tx HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.example\r\nConnection: close\r\n\r\n",
            )?;
            assert!(
                !withheld.contains("Access-Control-Allow-Origin:"),
                "{withheld}"
            );
            Ok(())
        }
    }

    use super::*;
    use bitcoin_rs_consensus::latch::LatchWriter;
    use core::sync::atomic::{AtomicBool, Ordering};

    use crate::context::Context;
    use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};

    fn rest_wire_request(request: &[u8], enabled: bool) -> std::io::Result<Vec<u8>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        client.set_read_timeout(Some(Duration::from_secs(3)))?;
        let (server, _) = listener.accept()?;
        let join = std::thread::spawn(move || {
            let handler = Handler::new(Arc::new(Context::new()));
            serve_connection(
                server,
                &Auth::basic("user", "pass"),
                &handler,
                enabled,
                Duration::from_secs(2),
                RpcSurface::Shared,
                bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
            )
        });
        client.write_all(request)?;
        let mut response = Vec::new();
        client.read_to_end(&mut response)?;
        let _result = join.join().expect("server thread");
        Ok(response)
    }

    fn assert_dripped_request_expires(prefix: &[u8]) -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        client.set_nodelay(true)?;
        let (server, _) = listener.accept()?;
        client.write_all(prefix)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_writer = Arc::clone(&stop);
        let writer = thread::spawn(move || {
            for _ in 0..80 {
                if stop_writer.load(Ordering::Acquire) || client.write_all(b"x").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }
            let _ = client.shutdown(Shutdown::Write);
        });

        let mut reader = BufReader::new(RequestDeadlineStream::new(
            server,
            Duration::from_secs(3),
            bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
        ));
        reader.get_mut().reset_deadline(Duration::from_millis(200));
        let start = Instant::now();
        let result = read_whole_request(
            &mut reader,
            Duration::from_millis(200),
            Duration::from_millis(200),
        );
        stop.store(true, Ordering::Release);
        writer.join().expect("writer thread");
        assert!(
            start.elapsed() < Duration::from_millis(1_500),
            "request exceeded its wall-clock budget"
        );
        match result {
            Err(RequestReadError::Io(error)) => assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ),
                "unexpected read error: {error}"
            ),
            Err(RequestReadError::RestBodyTooLarge) => panic!("unexpected size rejection"),
            Ok(_) => panic!("incomplete request was accepted"),
        }
        Ok(())
    }

    #[test]
    fn slow_drip_request_line_headers_and_body_expire() -> io::Result<()> {
        for prefix in [
            b"GET /".as_slice(),
            b"GET / HTTP/1.1\r\nX-Slow: ".as_slice(),
            b"POST / HTTP/1.1\r\nContent-Length: 256\r\n\r\n".as_slice(),
        ] {
            assert_dripped_request_expires(prefix)?;
        }
        Ok(())
    }

    #[test]
    fn keep_alive_wait_is_not_bounded_by_the_head_budget() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        let (server, _) = listener.accept()?;
        let writer = thread::spawn(move || -> io::Result<()> {
            thread::sleep(Duration::from_millis(300));
            client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        });

        let mut reader = BufReader::new(RequestDeadlineStream::new(
            server,
            Duration::from_secs(3),
            bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
        ));
        reader.get_mut().reset_deadline(Duration::from_secs(3));
        let result = read_whole_request(
            &mut reader,
            Duration::from_millis(100),
            Duration::from_millis(100),
        );
        writer.join().expect("writer thread")?;
        assert!(
            matches!(result, Ok(Some(_))),
            "a request arriving after the head budget but within the idle timeout is served"
        );
        Ok(())
    }

    #[test]
    fn an_exhausted_blocking_budget_still_serves_the_transaction_decode() {
        let handler = Handler::new(Arc::new(Context::new()));
        handler.configure_blocking_admission(2);
        let held = match handler.reserve_blocking_request() {
            Ok(held) => held,
            Err(error) => panic!("the single blocking slot must be available: {error:?}"),
        };
        let mut valid_tx_hex = String::from("0200000001");
        valid_tx_hex.push_str(&"00".repeat(32));
        valid_tx_hex.push_str("ffffffff00ffffffff010100000000000000015100000000");

        let response = handle_json(
        &handler,
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"decoderawtransaction","params":["{valid_tx_hex}"]}}"#
        )
        .as_bytes(),
    );

        assert_eq!(response.status, 200, "the decode is ordinary work");
        assert!(
            !response.close,
            "an ordinary decode must keep the connection alive"
        );
        drop(held);
    }

    /// A `scantxoutset start` refused because another scan holds the
    /// reservation kept no worker, so its keep-alive slot stays open. A `start`
    /// refused on its descriptors shares the -8 code but ran as a blocking
    /// request, so it still closes.
    #[test]
    fn a_refused_scan_start_keeps_the_connection_alive() {
        let handler = Handler::new(Arc::new(Context::new()));
        let permit = handler
            .context()
            .chain
            .utxo
            .reserve_scan()
            .expect("the first reservation always wins");

        let refused = handle_json(
            &handler,
            br#"{"jsonrpc":"2.0","id":1,"method":"scantxoutset","params":["start"]}"#,
        );
        let body = refused.body.expect("a refused start replies");
        assert_eq!(
            body.get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_i64),
            Some(-8),
            "a running scan refuses a new start: {body:?}"
        );
        assert!(
            !refused.close,
            "a pre-reservation refusal holds nothing a close would release"
        );
        drop(permit);

        let descriptor = format!("raw({})", "0".repeat(17_000));
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"scantxoutset","params":["start",["{descriptor}"]]}}"#
        );
        let bad_descriptors = handle_json(&handler, request.as_bytes());
        let body = bad_descriptors.body.expect("bad descriptors reply");
        assert_eq!(
            body.get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_i64),
            Some(-8),
            "descriptor failures share the -8 code: {body:?}"
        );
        assert!(
            bad_descriptors.close,
            "a blocking start refused on its descriptors still held a worker"
        );
    }

    /// The batch branch applies the same rule per request: a batch whose only
    /// blocking request was refused pre-reservation stays alive, while a batch
    /// containing a blocking request that ran still closes.
    #[test]
    fn a_batch_scan_refusal_keeps_the_connection_alive() {
        let handler = Handler::new(Arc::new(Context::new()));
        let _permit = handler
            .context()
            .chain
            .utxo
            .reserve_scan()
            .expect("the first reservation always wins");

        let refused_only = handle_json(
            &handler,
            br#"[{"jsonrpc":"2.0","id":1,"method":"scantxoutset","params":["start"]}]"#,
        );
        assert_eq!(refused_only.status, 200);
        assert!(
            !refused_only.close,
            "a batch whose blocking request was refused pre-reservation stays alive"
        );

        let mixed = handle_json(
            &handler,
            br#"[{"jsonrpc":"2.0","id":1,"method":"scantxoutset","params":["start"]},
             {"jsonrpc":"2.0","id":2,"method":"verifychain","params":["x"]},
             {"jsonrpc":"2.0","id":3,"method":"getblockcount","params":[]}]"#,
        );
        assert_eq!(mixed.status, 200);
        assert!(
            mixed.close,
            "a blocking request that ran still closes the batch connection"
        );
    }

    #[test]
    fn connection_admission_reserves_slots_for_other_peers() {
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let mut active = ActiveConnections::default();
        for _ in 0..96 {
            assert!(active.admit(source, 128));
        }
        assert!(
            !active.admit(source, 128),
            "a quarter of the pool stays open to other sources"
        );
        for _ in 0..32 {
            assert!(active.admit(other, 128));
        }
        assert!(!active.admit(other, 128), "the pool is full");
        active.release(source);
        assert!(active.admit(source, 128));

        let mut small_pool = ActiveConnections::default();
        for _ in 0..3 {
            assert!(small_pool.admit(source, 4));
        }
        assert!(!small_pool.admit(source, 4));
        assert!(small_pool.admit(other, 4));

        let mut two_slots = ActiveConnections::default();
        assert!(two_slots.admit(source, 2));
        assert!(two_slots.admit(source, 2));
        assert!(!two_slots.admit(other, 2), "the pool is full");
    }

    #[test]
    fn getutxos_post_preserves_http_security_and_limits() -> std::io::Result<()> {
        for (path, enabled, expected) in [
            ("/rest/getutxos.bin", true, 200),
            ("/rest/getutxos.bin", false, 404),
            ("/rest/chaininfo.json", true, 404),
            ("/rest/getutxos-extra.bin", true, 404),
            ("/", true, 401),
        ] {
            let mut request = format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n").into_bytes();
            request.extend_from_slice(&[0, 0]);
            let response = rest_wire_request(&request, enabled)?;
            assert!(response.starts_with(format!("HTTP/1.1 {expected} ").as_bytes()));
            assert!(!String::from_utf8_lossy(&response).contains("Access-Control-Allow-Origin"));
        }
        for framing in [
            "Content-Length: 2\r\nContent-Length: 3\r\n",
            "Content-Length: 2\r\nTransfer-Encoding: chunked\r\n",
            "",
        ] {
            let request = format!(
                "POST /rest/getutxos.bin HTTP/1.1\r\nHost: localhost\r\n{framing}Connection: close\r\n\r\n"
            );
            assert!(rest_wire_request(request.as_bytes(), true)?.starts_with(b"HTTP/1.1 400 "));
        }
        for (enabled, expected) in [(true, 400), (false, 404)] {
            let response = rest_wire_request(b"POST /rest/getutxos.hex?cache=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2049\r\nConnection: keep-alive\r\n\r\n", enabled)?;
            assert!(response.starts_with(format!("HTTP/1.1 {expected} ").as_bytes()));
            let text = String::from_utf8_lossy(&response);
            assert!(text.contains("Connection: close"));
            assert!(text.contains("Content-Type: text/plain"));
        }
        Ok(())
    }

    #[test]
    fn prepare_http_socket_disables_nagle() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        let client = prepare_http_socket(client).expect("configure client");
        let server = prepare_http_socket(server).expect("configure server");
        assert!(client.nodelay().expect("client nodelay"));
        assert!(server.nodelay().expect("server nodelay"));
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn serve_with_shutdown_exits_on_signal() -> std::io::Result<()> {
        let server = accept_test_server()?;
        let handler = Arc::clone(&server.handler);
        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let shutdown_reader = shutdown.reader();
        let (parked, ready) = crossbeam_channel::bounded(1);
        let handle = thread::spawn(move || {
            server.serve_accept_loop(&shutdown_reader, RpcSurface::Shared, |listener| {
                let result = listener.accept();
                if result
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
                {
                    let _ = parked.try_send(());
                }
                result
            })
        });
        ready
            .recv_timeout(Duration::from_secs(3))
            .expect("idle accept");
        thread::sleep(Duration::from_millis(45));
        let start = Instant::now();
        shutdown.trigger();
        handle.join().expect("join serve thread")?;
        let elapsed = start.elapsed();
        eprintln!("idle RPC listener shutdown: {elapsed:?}");
        assert!(
            elapsed < Duration::from_millis(80),
            "idle shutdown took {elapsed:?}"
        );
        assert!(handler.is_stopping());
        Ok(())
    }

    #[test]
    fn serve_accept_loop_cancels_promptly_on_idle_socket() -> io::Result<()> {
        let server = accept_test_server()?;
        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let reader = shutdown.reader();
        let (parked_tx, parked_rx) = crossbeam_channel::bounded(1);
        let (done_tx, done_rx) = crossbeam_channel::bounded(1);

        let handle = thread::spawn(move || {
            let result = server.serve_accept_loop(&reader, RpcSurface::Shared, |listener| {
                let result = listener.accept();
                if result
                    .as_ref()
                    .is_err_and(|err| err.kind() == io::ErrorKind::WouldBlock)
                {
                    let _ = parked_tx.send(());
                }
                result
            });
            let _ = done_tx.send(result);
        });

        parked_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server must reach idle accept state");

        let start = Instant::now();
        shutdown.trigger();

        let exit_result = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server thread must exit within 5s after latch trigger");

        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(250),
            "idle accept shutdown took {elapsed:?}; one 20 ms readiness poll plus scheduling must bound it"
        );
        exit_result?;
        handle.join().expect("join server thread");
        Ok(())
    }

    #[test]
    fn shutdown_before_serving_does_not_admit_a_queued_connection() -> io::Result<()> {
        let server = accept_test_server()?;
        let handler = Arc::clone(&server.handler);
        let _queued = TcpStream::connect(server.local_addr()?)?;
        let shutdown_writer = bitcoin_rs_consensus::latch::LatchWriter::new();
        shutdown_writer.trigger();
        let shutdown = shutdown_writer.reader();
        let mut attempts = 0;
        server.serve_accept_loop(&shutdown, RpcSurface::Shared, |listener| {
            attempts += 1;
            listener.accept()
        })?;
        assert_eq!(attempts, 0);
        assert!(handler.is_stopping());
        Ok(())
    }

    #[test]
    fn split_path_query_preserves_path_and_query() {
        assert_eq!(
            split_path_query("/rest/headers/hash.json?count=10"),
            ("/rest/headers/hash.json", "count=10")
        );
        assert_eq!(
            split_path_query("/rest/chaininfo.json"),
            ("/rest/chaininfo.json", "")
        );
    }

    #[test]
    fn wf_02_classify_splits_rest_esplora_and_json_rpc() {
        assert_eq!(
            classify("GET", "/rest/chaininfo.json"),
            HttpRoute::Rest {
                path: "/rest/chaininfo.json",
                query: ""
            }
        );
        assert_eq!(
            classify("GET", "/api/blocks/tip/height"),
            HttpRoute::EsploraGet {
                surface: HttpSurface::EsploraPublic,
                path: "/blocks/tip/height",
                query: ""
            }
        );
        assert_eq!(
            classify("GET", "/esplora/internal/mempool/txs?max_txs=1"),
            HttpRoute::EsploraGet {
                surface: HttpSurface::EsploraBackend,
                path: "/internal/mempool/txs",
                query: "max_txs=1"
            }
        );
        assert_eq!(
            classify("POST", "/api/tx"),
            HttpRoute::EsploraPost {
                surface: HttpSurface::EsploraPublic,
                path: "/tx"
            }
        );
        assert_eq!(
            classify("POST", "/esplora/internal/txs"),
            HttpRoute::EsploraPost {
                surface: HttpSurface::EsploraBackend,
                path: "/internal/txs"
            }
        );
        assert_eq!(
            classify("GET", "/blocks/tip/height"),
            HttpRoute::NotFound,
            "unprefixed GET is not Esplora"
        );
        assert_eq!(
            classify("HEAD", "/api/tx"),
            HttpRoute::NotFound,
            "HEAD /api/tx must not run POST /tx"
        );
        assert_eq!(
            classify("PUT", "/"),
            HttpRoute::NotFound,
            "non-POST methods are not JSON-RPC"
        );
        assert_eq!(
            classify("GET", "/api/v1/block-height/0"),
            HttpRoute::EsploraGet {
                surface: HttpSurface::EsploraPublic,
                path: "/v1/block-height/0",
                query: ""
            },
            "GET /api/v1 stays in the closed /api directory (404 inside Esplora)"
        );
        assert_eq!(
            classify("POST", "/api/v1/tx"),
            HttpRoute::EsploraPost {
                surface: HttpSurface::EsploraPublic,
                path: "/v1/tx"
            }
        );
        assert_eq!(
            classify("OPTIONS", "/api/blocks/tip/height"),
            HttpRoute::Preflight {
                surface: HttpSurface::EsploraPublic
            }
        );
        assert_eq!(
            classify("OPTIONS", "/esplora/internal/txs"),
            HttpRoute::NotFound
        );
        assert_eq!(
            classify("OPTIONS", "/rest/chaininfo.json"),
            HttpRoute::NotFound
        );
        assert_eq!(classify("OPTIONS", "/"), HttpRoute::NotFound);
        assert_eq!(classify("POST", "/"), HttpRoute::JsonRpc);
        assert_eq!(classify("POST", "/tx"), HttpRoute::JsonRpc);
        assert_eq!(classify("GET", "/blocks/tip/height"), HttpRoute::NotFound);
    }

    #[test]
    fn post_without_content_length_is_a_framing_error() -> std::io::Result<()> {
        let auth = Arc::new(Auth::basic("alice", "secret"));
        let handler = Arc::new(Handler::new(Arc::new(Context::new())));
        let server = RpcServer::bind(
            "127.0.0.1:0",
            auth,
            handler,
            4,
            core::time::Duration::from_millis(500),
            false,
        )?;
        let addr = server.listener.local_addr()?;
        let shutdown = LatchWriter::new();
        let shutdown_reader = shutdown.reader();
        let handle = std::thread::spawn(move || server.serve_with_shutdown(shutdown_reader));

        let mut stream = TcpStream::connect(addr)?;
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
        )?;
        stream.flush()?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        let text = String::from_utf8_lossy(&buf);
        let code: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|token| token.parse().ok())
            .expect("HTTP status");
        assert!(
            (400..500).contains(&code) && code != 401,
            "expected a framing error status, got {code}"
        );

        shutdown.trigger();
        drop(handle.join().expect("server thread"));
        Ok(())
    }

    fn read_fed_request(
        request: Vec<u8>,
        chunk: usize,
    ) -> io::Result<Result<Option<HttpRequest>, RequestReadError>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        let (server, _) = listener.accept()?;
        let writer = thread::spawn(move || -> io::Result<()> {
            for piece in request.chunks(chunk) {
                client.write_all(piece)?;
            }
            client.shutdown(Shutdown::Write)
        });
        let mut reader = BufReader::new(RequestDeadlineStream::new(
            server,
            Duration::from_secs(3),
            bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
        ));
        let result =
            read_whole_request(&mut reader, Duration::from_secs(3), Duration::from_secs(3));
        drop(reader);
        let written = writer.join().expect("writer thread");
        if result.is_ok() {
            written?;
        }
        Ok(result)
    }

    #[test]
    fn body_arriving_across_reads_is_received_whole() -> io::Result<()> {
        let body = b"0123456789abcdef".repeat(4_096);
        let mut request = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(&body);
        let Ok(Some(received)) = read_fed_request(request, 1_000)? else {
            panic!("a complete request must decode");
        };
        assert_eq!(received.body, body);
        Ok(())
    }

    #[test]
    fn declared_but_unsent_body_is_a_framing_error() -> io::Result<()> {
        let request = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {MAX_BODY_BYTES}\r\n\r\npartial"
        );
        match read_fed_request(request.into_bytes(), usize::MAX)? {
            Err(RequestReadError::Io(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
            }
            Err(RequestReadError::RestBodyTooLarge) => panic!("unexpected size rejection"),
            Ok(_) => panic!("a truncated body was accepted"),
        }
        Ok(())
    }

    #[test]
    fn declared_but_unsent_body_allocates_only_received_bytes() {
        let mut body = Vec::new();
        let result = read_body(
            &mut std::io::Cursor::new(b"partial"),
            MAX_BODY_BYTES,
            &mut body,
        );
        assert!(
            matches!(&result, Err(error) if error.kind() == io::ErrorKind::UnexpectedEof),
            "{result:?}"
        );
        assert_eq!(body, b"partial");
        assert!(
            body.capacity() < 64 * 1_024,
            "a {MAX_BODY_BYTES}-byte declaration reserved {} bytes",
            body.capacity()
        );
    }

    // API-38
    #[test]
    fn bare_carriage_returns_in_request_heads_are_rejected() -> io::Result<()> {
        for request in [
            "POST / HTTP/1.1\r\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
            "POST / HTTP/1.1\r\nX-Ignored: value\rTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}",
            "POST / HTTP/1.1\r\nContent-Length: \r2\r\n\r\n{}",
            "POST / HTTP/1.1\r\nContent-Length: 2\r\r\n\r\n{}",
        ] {
            match read_fed_request(request.as_bytes().to_vec(), usize::MAX)? {
                Err(RequestReadError::Io(error)) => {
                    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                }
                _ => panic!("a bare carriage return in the request head was accepted"),
            }
            let response = rest_wire_request(request.as_bytes(), false)?;
            assert!(response.starts_with(b"HTTP/1.1 400"), "{response:?}");
        }
        Ok(())
    }

    // API-38
    #[test]
    fn request_head_validation_preserves_field_text_and_binary_body() -> io::Result<()> {
        let mut request =
            b"POST / HTTP/1.1\r\nX-Meta: caf\xc3\xa9\tvalue\nContent-Length: 4\r\n\r\n".to_vec();
        let body = [0x00, 0xff, b'\r', b'\n'];
        request.extend_from_slice(&body);
        let Ok(Some(received)) = read_fed_request(request, 1)? else {
            panic!("valid field text and binary body must decode");
        };
        assert_eq!(received.body, body);
        Ok(())
    }

    #[test]
    fn content_length_accepts_only_digit_strings() -> io::Result<()> {
        for value in ["+2", ""] {
            let request = format!(
                "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {value}\r\n\r\n{{}}"
            );
            match read_fed_request(request.into_bytes(), usize::MAX)? {
                Err(RequestReadError::Io(error)) => {
                    assert_eq!(
                        error.kind(),
                        io::ErrorKind::InvalidData,
                        "content-length {value:?} must be a framing error"
                    );
                }
                _ => panic!("content-length {value:?} was accepted"),
            }
        }
        let request =
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}".to_owned();
        let Ok(Some(received)) = read_fed_request(request.into_bytes(), usize::MAX)? else {
            panic!("a digit content-length must decode");
        };
        assert_eq!(received.body, b"{}");
        Ok(())
    }

    #[test]
    fn header_values_trim_only_core_whitespace() -> io::Result<()> {
        let request =
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: \u{00a0}2\r\n\r\n{}".to_owned();
        match read_fed_request(request.into_bytes(), usize::MAX)? {
            Err(RequestReadError::Io(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
            _ => panic!("a non breaking space inside content-length was accepted"),
        }
        Ok(())
    }

    #[test]
    fn request_line_takes_single_space_separators_only() -> io::Result<()> {
        for request_line in ["POST\t/ HTTP/1.1", "POST  / HTTP/1.1", "POST /  HTTP/1.1"] {
            let request =
                format!("{request_line}\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{{}}");
            match read_fed_request(request.into_bytes(), usize::MAX)? {
                Err(RequestReadError::Io(error)) => {
                    assert_eq!(
                        error.kind(),
                        io::ErrorKind::InvalidData,
                        "request line {request_line:?} must be a framing error"
                    );
                }
                _ => panic!("request line {request_line:?} was accepted"),
            }
        }
        Ok(())
    }

    #[test]
    fn duplicate_content_length_compares_the_field_text() -> io::Result<()> {
        let request =
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 7\r\nContent-Length: 07\r\n\r\n{}"
            .to_owned();
        match read_fed_request(request.into_bytes(), usize::MAX)? {
            Err(RequestReadError::Io(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
            _ => panic!("different content-length field texts were accepted"),
        }
        let request =
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}"
            .to_owned();
        let Ok(Some(received)) = read_fed_request(request.into_bytes(), usize::MAX)? else {
            panic!("identical content-length fields must decode");
        };
        assert_eq!(received.body, b"{}");
        Ok(())
    }

    #[test]
    fn full_body_capacity_stays_within_the_declared_length() -> io::Result<()> {
        for content_length in [MAX_BODY_BYTES, 9_000_000] {
            let mut request = format!(
                "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {content_length}\r\n\r\n"
            )
            .into_bytes();
            request.resize(request.len() + content_length, b'x');
            let Ok(Some(received)) = read_fed_request(request, 1_460)? else {
                panic!("a complete request must decode");
            };
            assert_eq!(received.body.len(), content_length);
            assert!(
                received.body.capacity() <= content_length,
                "a {content_length}-byte body kept {} bytes",
                received.body.capacity()
            );
        }
        Ok(())
    }

    #[test]
    fn oversized_unterminated_head_is_rejected_before_newline() -> std::io::Result<()> {
        for prefix in [
            b"GET /".as_slice(),
            b"GET / HTTP/1.1\r\nX-Fill: ".as_slice(),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let address = listener.local_addr()?;
            let auth = Arc::new(Auth::basic("alice", "secret"));
            let handler = Arc::new(Handler::new(Arc::new(Context::new())));
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().expect("accept request");
                serve_connection(
                    stream,
                    &auth,
                    &handler,
                    false,
                    core::time::Duration::from_secs(5),
                    RpcSurface::Shared,
                    bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
                )
            });

            let mut client = TcpStream::connect(address)?;
            client.set_read_timeout(Some(core::time::Duration::from_secs(2)))?;
            client.write_all(prefix)?;
            client.write_all(&vec![b'a'; MAX_HEADER_BYTES])?;

            let mut response = [0_u8; 128];
            let first_read = client.read(&mut response);
            client.shutdown(Shutdown::Write)?;
            let _ = server.join().expect("server thread");
            let read = first_read?;
            assert!(
                response[..read].starts_with(b"HTTP/1.1 400 Bad Request"),
                "oversized head must fail before newline: {prefix:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn exact_request_head_budget_is_accepted() -> std::io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let auth = Arc::new(Auth::basic("alice", "secret"));
        let handler = Arc::new(Handler::new(Arc::new(Context::new())));
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept request");
            serve_connection(
                stream,
                &auth,
                &handler,
                false,
                core::time::Duration::from_secs(5),
                RpcSurface::Shared,
                bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
            )
        });

        let mut request = b"GET / HTTP/1.1\r\nX-Fill: ".to_vec();
        request.extend(vec![
            b'a';
            MAX_HEADER_BYTES - request.len() - b"\r\n\r\n".len()
        ]);
        request.extend_from_slice(b"\r\n\r\n");
        assert_eq!(request.len(), MAX_HEADER_BYTES);
        let mut client = TcpStream::connect(address)?;
        client.write_all(&request)?;
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        server.join().expect("server thread")?;
        Ok(())
    }

    // WF-02
    #[test]
    fn listener_directory_table_is_closed_over_http() -> std::io::Result<()> {
        let auth = Arc::new(Auth::basic("alice", "secret"));
        let handler = Arc::new(Handler::new(Arc::new(Context::new())));
        let server = RpcServer::bind(
            "127.0.0.1:0",
            auth,
            handler,
            4,
            core::time::Duration::from_millis(500),
            false,
        )?;
        let addr = server.listener.local_addr()?;
        let shutdown = LatchWriter::new();
        let shutdown_reader = shutdown.reader();
        let handle = std::thread::spawn(move || server.serve_with_shutdown(shutdown_reader));

        let status = |method: &str, path: &str| -> std::io::Result<u16> {
            let mut stream = TcpStream::connect(addr)?;
            write!(
                stream,
                "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )?;
            stream.flush()?;
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf)?;
            let text = String::from_utf8_lossy(&buf);
            let code = text
                .split_whitespace()
                .nth(1)
                .and_then(|token| token.parse().ok())
                .expect("HTTP status");
            Ok(code)
        };

        assert_eq!(status("GET", "/blocks/tip/height")?, 404);
        assert_eq!(status("HEAD", "/api/tx")?, 404);
        assert_eq!(status("PUT", "/")?, 404);
        assert_eq!(status("POST", "/")?, 401);
        assert_eq!(status("GET", "/api/blocks/tip/height")?, 200);

        shutdown.trigger();
        handle.join().expect("join serve thread")?;
        Ok(())
    }

    #[test]
    fn unsupported_method_is_404_at_listener() -> std::io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let auth = Arc::new(Auth::basic("alice", "secret"));
        let handler = Arc::new(Handler::new(Arc::new(Context::new())));
        let thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept request");
            serve_connection(
                stream,
                &auth,
                &handler,
                false,
                core::time::Duration::from_secs(1),
                RpcSurface::Shared,
                bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
            )
        });

        let mut client = TcpStream::connect(address)?;
        client.write_all(b"HEAD /api/tx HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        thread
            .join()
            .expect("listener thread")
            .expect("serve request");
        Ok(())
    }

    #[test]
    fn non_string_jsonrpc_version_is_an_invalid_request() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(
            &handler,
            br#"{"jsonrpc":2,"id":1,"method":"getblockcount","params":[]}"#,
        );
        let body = response.body.expect("JSON-RPC response body");

        assert_eq!(
            response.status, 400,
            "legacy -32600 maps to HTTP 400 (Core httprpc.cpp:47-49)"
        );
        assert_eq!(
            body.get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_i64),
            Some(-32600)
        );
        assert_eq!(
            body.get("error")
                .and_then(|error| error.get("message"))
                .and_then(Value::as_str),
            Some("jsonrpc field must be a string"),
            "Core's exact message for a non-string version: {body:?}"
        );
        assert!(
            body.get("result").is_none_or(Value::is_null),
            "a rejected envelope must not carry a result: {body:?}"
        );
    }

    #[test]
    fn unsupported_jsonrpc_version_is_an_invalid_request() {
        let handler = Handler::new(Arc::new(Context::new()));
        for version in ["9.0", "1.1"] {
            let request =
                format!(r#"{{"jsonrpc":"{version}","id":1,"method":"getblockcount","params":[]}}"#);
            let response = handle_json(&handler, request.as_bytes());
            let body = response.body.expect("JSON-RPC response body");

            assert_eq!(
                response.status, 400,
                "legacy -32600 maps to HTTP 400 (Core httprpc.cpp:47-49)"
            );
            assert_eq!(
                body.get("error")
                    .and_then(|error| error.get("code"))
                    .and_then(Value::as_i64),
                Some(-32600),
                "version {version} must be refused"
            );
            assert_eq!(
                body.get("error")
                    .and_then(|error| error.get("message"))
                    .and_then(Value::as_str),
                Some("JSON-RPC version not supported"),
                "Core's exact message for an unsupported version: {body:?}"
            );
        }
    }

    #[test]
    fn json_rpc_1_0_remains_accepted_as_legacy() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(
            &handler,
            br#"{"jsonrpc":"1.0","id":1,"method":"getblockchaininfo","params":[]}"#,
        );
        let body = response.body.expect("JSON-RPC response body");

        assert_eq!(response.status, 200);
        assert!(body.get("result").is_some());
        assert!(body.get("jsonrpc").is_none());
    }

    #[test]
    fn non_array_or_object_params_are_an_invalid_request() {
        let handler = Handler::new(Arc::new(Context::new()));
        for params in ["7", r#""text""#, "true"] {
            let request =
                format!(r#"{{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":{params}}}"#);
            let response = handle_json(&handler, request.as_bytes());
            let body = response.body.expect("JSON-RPC response body");

            assert_eq!(
                body.get("error")
                    .and_then(|error| error.get("code"))
                    .and_then(Value::as_i64),
                Some(-32600),
                "params {params} must be refused before dispatch"
            );
            assert_eq!(
                body.get("error")
                    .and_then(|error| error.get("message"))
                    .and_then(Value::as_str),
                Some("Params must be an array or object"),
                "Core's exact message for a malformed params field: {body:?}"
            );
        }
    }

    // API-02
    #[test]
    fn a_rejected_envelope_never_dispatches_the_method() {
        let handler = Handler::new(Arc::new(Context::new()));
        let executed = handle_json(
            &handler,
            br#"{"jsonrpc":"2.0","id":1,"method":"setnetworkactive","params":[false]}"#,
        );
        assert_eq!(
            executed.status, 200,
            "fixture: the probe method is dispatched"
        );
        assert!(
            !handler.context().network.p2p.network_active(),
            "fixture: dispatch flips the flag"
        );
        handler.context().network.p2p.set_network_active(true);

        for request in [
            br#"{"jsonrpc":"9.0","id":1,"method":"setnetworkactive","params":[false]}"#.as_slice(),
            br#"{"jsonrpc":2,"id":1,"method":"setnetworkactive","params":[false]}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"method":"setnetworkactive","params":7}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"params":[false]}"#.as_slice(),
        ] {
            let rejected = handle_json(&handler, request);
            let body = rejected.body.expect("rejected envelope replies");
            assert_eq!(
                body.get("error")
                    .and_then(|error| error.get("code"))
                    .and_then(Value::as_i64),
                Some(-32600),
                "the envelope error must replace the method's own outcome: {body:?}"
            );
            assert!(
                handler.context().network.p2p.network_active(),
                "a rejected envelope must not execute the method: {request:?}"
            );
        }
    }

    #[test]
    fn an_empty_batch_answers_an_empty_ok_batch() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(&handler, b"[]");
        let body = response.body.expect("empty batch replies");

        assert_eq!(response.status, 200);
        assert_eq!(body, json!([]), "an empty batch answers []: {body:?}");
    }

    // API-08
    #[test]
    fn an_oversized_batch_is_refused_before_any_member_runs() {
        let handler = Handler::new(Arc::new(Context::new()));
        let at_limit = (0..MAX_BATCH_ELEMENTS)
            .map(|id| json!({"jsonrpc":"2.0","id":id,"method":"getblockcount","params":[]}))
            .collect::<Vec<_>>();
        let accepted = handle_decoded_json(&handler, &Value::from(at_limit));
        assert_eq!(accepted.status, 200, "a batch at the limit is served");
        assert_eq!(
            accepted
                .body
                .expect("batch replies")
                .as_array()
                .map(sonic_rs::Array::len),
            Some(MAX_BATCH_ELEMENTS),
            "every member at the limit answers"
        );

        handler.context().network.p2p.set_network_active(true);
        let mut too_many = (0..MAX_BATCH_ELEMENTS)
            .map(|id| json!({"jsonrpc":"2.0","id":id,"method":"setnetworkactive","params":[false]}))
            .collect::<Vec<_>>();
        too_many.push(json!({
            "jsonrpc": "2.0",
            "id": MAX_BATCH_ELEMENTS,
            "method": "setnetworkactive",
            "params": [false],
        }));
        let refused = handle_decoded_json(&handler, &Value::from(too_many));
        assert_eq!(
            refused.status, 400,
            "an over-limit batch is refused as a request error"
        );
        let body = refused.body.expect("refusal replies");
        assert_eq!(
            body.get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_i64),
            Some(-32600),
            "the batch refusal is -32600: {body:?}"
        );
        assert!(
            handler.context().network.p2p.network_active(),
            "no member of a refused batch may run"
        );
    }

    #[test]
    fn a_top_level_scalar_is_a_parse_error() {
        let handler = Handler::new(Arc::new(Context::new()));
        for request in [br"5".as_slice(), br#""x""#.as_slice()] {
            let response = handle_json(&handler, request);
            let body = response.body.expect("top-level scalar replies");

            assert_eq!(response.status, 500, "-32700 keeps the legacy 500");
            assert_eq!(
                body.get("error")
                    .and_then(|error| error.get("code"))
                    .and_then(Value::as_i64),
                Some(-32700),
                "top-level scalar is a parse error: {body:?}"
            );
            assert_eq!(
                body.get("error")
                    .and_then(|error| error.get("message"))
                    .and_then(Value::as_str),
                Some("Top-level object parse error"),
                "Core's exact message: {body:?}"
            );
            assert!(
                body.get("id").is_none_or(Value::is_null),
                "a parse error carries a null id: {body:?}"
            );
        }
    }

    #[test]
    fn json_rpc_2_method_and_params_envelope_errors_answer_400() {
        let handler = Handler::new(Arc::new(Context::new()));
        for (request, message) in [
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":7}"#,
                "Params must be an array or object",
            ),
            (r#"{"jsonrpc":"2.0","id":1,"params":[]}"#, "Missing method"),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":null}"#,
                "Missing method",
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":5}"#,
                "Method must be a string",
            ),
        ] {
            let response = handle_json(&handler, request.as_bytes());
            let body = response.body.expect("JSON-RPC response body");

            assert_eq!(
                response.status, 400,
                "v2 envelope refusal maps to HTTP 400: {request}"
            );
            assert_eq!(
                body.get("jsonrpc").and_then(Value::as_str),
                Some("2.0"),
                "the body keeps the v2 envelope: {body:?}"
            );
            assert_eq!(
                body.get("error")
                    .and_then(|error| error.get("code"))
                    .and_then(Value::as_i64),
                Some(-32600),
                "envelope refusal is -32600: {body:?}"
            );
            assert_eq!(
                body.get("error")
                    .and_then(|error| error.get("message"))
                    .and_then(Value::as_str),
                Some(message),
                "Core's exact message for {request}: {body:?}"
            );
        }
    }

    #[test]
    fn an_all_notification_batch_answers_204() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(
            &handler,
            br#"[
            {"jsonrpc":"2.0","method":"getblockcount","params":[]},
            {"jsonrpc":"2.0","method":"getblockchaininfo","params":[]}
        ]"#,
        );

        assert_eq!(response.status, 204);
        assert!(response.body.is_none(), "204 carries no body");
    }

    #[test]
    fn legacy_invalid_request_maps_to_http_400() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(&handler, br#"{"id":1,"method":7,"params":[]}"#);
        assert_eq!(response.status, 400, "legacy -32600 maps to HTTP 400");
    }

    #[test]
    fn legacy_method_not_found_maps_to_http_404() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(&handler, br#"{"id":1,"method":"missing","params":[]}"#);
        assert_eq!(response.status, 404, "legacy -32601 maps to HTTP 404");
    }

    #[test]
    fn legacy_other_errors_keep_http_500() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(&handler, br#"{"id":1,"method":"getblock","params":[]}"#);
        assert_eq!(response.status, 500, "legacy -32602 keeps HTTP 500");
    }

    #[test]
    fn json_rpc_2_dispatch_errors_still_answer_http_200() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(
            &handler,
            br#"{"jsonrpc":"2.0","id":7,"method":"missing","params":[]}"#,
        );
        let body = response.body.expect("JSON-RPC response body");

        assert_eq!(response.status, 200, "v2 -32601 stays inside HTTP 200");
        assert_eq!(body.get("jsonrpc").and_then(Value::as_str), Some("2.0"));
        assert_eq!(
            body.get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_i64),
            Some(-32601)
        );
    }

    #[test]
    fn json_rpc_2_envelope_error_uses_the_legacy_status() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(
            &handler,
            br#"{"jsonrpc":"9.0","id":1,"method":"getblockcount","params":[]}"#,
        );
        let body = response.body.expect("JSON-RPC response body");

        assert_eq!(response.status, 400);
        assert!(body.get("jsonrpc").is_none(), "legacy envelope: {body:?}");
    }

    #[test]
    fn json_rpc_2_post_classification_error_keeps_the_v2_envelope() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(
            &handler,
            br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":7}"#,
        );
        let body = response.body.expect("JSON-RPC response body");

        assert_eq!(response.status, 400);
        assert_eq!(
            body.get("jsonrpc").and_then(Value::as_str),
            Some("2.0"),
            "a post-classification violation keeps the v2 envelope: {body:?}"
        );
        assert!(body.get("result").is_none(), "v2 errors omit result");
        assert_eq!(
            body.get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_i64),
            Some(-32600)
        );
    }

    // API-02
    #[test]
    fn an_explicit_null_method_is_missing() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(
            &handler,
            br#"{"jsonrpc":"2.0","id":1,"method":null,"params":[]}"#,
        );
        let body = response.body.expect("JSON-RPC response body");

        assert_eq!(
            body.get("error")
                .and_then(|error| error.get("message"))
                .and_then(Value::as_str),
            Some("Missing method"),
            "Core's exact message for a null method: {body:?}"
        );
    }

    #[test]
    fn absent_and_null_params_dispatch_as_an_empty_array() {
        let handler = Handler::new(Arc::new(Context::new()));
        for request in [
            br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount"}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":null}"#.as_slice(),
        ] {
            let response = handle_json(&handler, request);
            let body = response.body.expect("no-argument call replies");
            assert_eq!(response.status, 200, "{request:?}");
            assert!(
                body.get("result").is_some(),
                "a null params field must dispatch with defaults: {body:?}"
            );
        }
    }

    /// Core accepts `"params": {}` for every method: the object form always runs
    /// through transformNamedArguments (src/rpc/server.cpp), which maps an empty
    /// object to an empty positional array exactly like an absent or null params
    /// field (src/rpc/request.cpp). The framework's zero-argument client calls
    /// serialize exactly this form.
    #[test]
    fn empty_object_params_dispatch_as_an_empty_array() {
        let handler = Handler::new(Arc::new(Context::new()));
        for request in [
            br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":{}}"#.as_slice(),
            br#"{"id":1,"method":"getblockcount","params":{}}"#.as_slice(),
        ] {
            let response = handle_json(&handler, request);
            let body = response.body.expect("empty-object params reply");
            assert_eq!(response.status, 200, "{request:?}");
            assert!(
                body.get("result").is_some(),
                "an empty params object must dispatch with defaults: {body:?}"
            );
        }
    }

    /// A non-empty named-object params is bound to positional order per method by
    /// the handler that declares its parameter names
    /// (`handlers::bind_named_params`, mirroring Core's per-command argNames);
    /// this server-level test pins the honest partial coverage: a method without
    /// a name map keeps its local `-32602` (documented in API-02), while a bound
    /// method accepts the same names Core documents.
    #[test]
    fn named_object_params_are_bound_only_by_methods_with_a_name_map() {
        let handler = Handler::new(Arc::new(Context::new()));
        let refused = handle_json(
            &handler,
            br#"{"id":1,"method":"getblockcount","params":{"height":0}}"#,
        );
        let body = refused.body.expect("unbound method replies");
        assert_eq!(
            body.get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_i64),
            Some(-32602),
            "a method without a name map rejects the named form honestly: {body:?}"
        );

        // The framework's setnetworkactive(state=False) shape (feature_loadblock)
        // binds and executes since NG-17's closure.
        let bound = handle_json(
            &handler,
            br#"{"id":1,"method":"setnetworkactive","params":{"state":false}}"#,
        );
        let body = bound.body.expect("bound method replies");
        assert_eq!(body.get("result").and_then(Value::as_bool), Some(false));
        assert!(
            !handler.context().network.p2p.network_active(),
            "the named call must execute the method"
        );
    }

    #[test]
    fn batch_members_keep_per_member_envelope_dialect() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(
            &handler,
            br#"[
            {"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]},
            {"jsonrpc":"9.0","id":2,"method":"getblockcount","params":[]}
        ]"#,
        );
        let body = response.body.expect("JSON-RPC batch response body");
        let rows = body.as_array().expect("batch response array");

        assert_eq!(response.status, 200);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].get("result").is_some());
        assert_eq!(
            rows[1]
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_i64),
            Some(-32600)
        );
    }

    #[test]
    fn notification_with_a_malformed_envelope_is_not_executed() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(
            &handler,
            br#"{"jsonrpc":"2.0","method":"getblockcount","params":7}"#,
        );
        assert!(
            response.body.is_some(),
            "a malformed notification envelope must be reported, not executed"
        );
    }

    #[test]
    fn json_rpc_2_success_omits_null_error_for_jsonrpsee_clients() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(
            &handler,
            br#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}"#,
        );
        let response = response.body.expect("JSON-RPC response body");

        assert_eq!(response.get("jsonrpc").and_then(Value::as_str), Some("2.0"));
        assert!(response.get("result").is_some());
        assert!(response.get("error").is_none());
    }

    #[test]
    fn bitcoin_core_1_success_keeps_null_error() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(
            &handler,
            br#"{"jsonrpc":"1.0","id":1,"method":"getblockchaininfo","params":[]}"#,
        );
        let response = response.body.expect("JSON-RPC response body");

        assert!(response.get("jsonrpc").is_none());
        assert!(response.get("result").is_some());
        assert!(response.get("error").is_some_and(Value::is_null));
    }

    #[test]
    fn json_rpc_2_error_omits_result_and_uses_http_200() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(
            &handler,
            br#"{"jsonrpc":"2.0","id":7,"method":"missing","params":[]}"#,
        );
        let status = response.status;
        let body = response.body.expect("JSON-RPC response body");

        assert_eq!(status, 200);
        assert!(body.get("result").is_none());
        assert!(body.get("error").is_some_and(Value::is_object));
        assert_eq!(body.get("id").and_then(Value::as_i64), Some(7));
    }

    #[test]
    fn json_rpc_2_notification_has_no_response_body() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(
            &handler,
            br#"{"jsonrpc":"2.0","method":"getblockcount","params":[]}"#,
        );

        assert!(response.body.is_none());
    }

    #[test]
    fn json_rpc_batch_excludes_notifications() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(
            &handler,
            br#"[
            {"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]},
            {"jsonrpc":"2.0","method":"getblockcount","params":[]},
            {"jsonrpc":"2.0","id":2,"method":"missing","params":[]}
        ]"#,
        );
        let status = response.status;
        let body = response.body.expect("JSON-RPC batch response body");
        let rows = body.as_array().expect("batch response array");

        assert_eq!(status, 200);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].get("result").is_some());
        assert!(rows[1].get("error").is_some());
    }

    // API-02
    #[test]
    fn batch_drops_v2_notifications_with_refused_envelopes() {
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(
            &handler,
            br#"[{"jsonrpc":"2.0","c":"2.0","meod":"getblockcount","params":[]}]"#,
        );

        assert!(
            response.body.is_none(),
            "Core drops a batch member without an id: {:?}",
            response.body
        );
        assert_eq!(response.status, 204);

        let response = handle_json(
        &handler,
        br#"[{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]},{"jsonrpc":"2.0","c":"2.0","meod":"getblockcount","params":[]}]"#,
    );
        let body = response.body.expect("the identified member replies");
        let rows = body.as_array().expect("batch response array");

        assert_eq!(rows.len(), 1, "the notification member must be dropped");
        assert!(rows[0].get("result").is_some());

        let response = handle_json(
            &handler,
            br#"[{"jsonrpc":"2.0","id":null,"method":"getblockcount","params":7}]"#,
        );

        assert!(
            response.body.is_some(),
            "an explicit null id is not a notification"
        );
    }

    fn read_whole_request(
        reader: &mut BufReader<RequestDeadlineStream>,
        _head_timeout: Duration,
        _body_timeout: Duration,
    ) -> Result<Option<HttpRequest>, RequestReadError> {
        read_http_request(reader)
    }

    struct Exchange {
        response: String,
        eof: bool,
        elapsed: Duration,
        served: io::Result<()>,
    }

    fn exchange(request: &[u8]) -> io::Result<Exchange> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        client.set_read_timeout(Some(Duration::from_secs(5)))?;
        let server = thread::spawn(move || -> io::Result<()> {
            let (stream, _) = listener.accept()?;
            serve_connection(
                stream,
                &Auth::basic("alice", "secret"),
                &Handler::new(Arc::new(Context::new())),
                false,
                Duration::from_secs(30),
                RpcSurface::Shared,
                bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
            )
        });
        let started = Instant::now();
        client.write_all(request)?;
        let mut response = Vec::new();
        let mut eof = false;
        let mut chunk = [0_u8; 1_024];
        loop {
            match client.read(&mut chunk) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(read) => response.extend_from_slice(&chunk[..read]),
                Err(_) => break,
            }
        }
        let elapsed = started.elapsed();
        drop(client);
        let served = server.join().expect("server thread");
        Ok(Exchange {
            response: String::from_utf8_lossy(&response).into_owned(),
            eof,
            elapsed,
            served,
        })
    }

    const GOOD_TOKEN: &str = "YWxpY2U6c2VjcmV0";
    const BAD_TOKEN: &str = "YWxpY2U6YmFk";

    const CORE_UNAUTHORIZED: &str = "HTTP/1.1 401 Unauthorized\r\n\
    WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n\
    Content-Type: text/html; charset=ISO-8859-1\r\n\
    Content-Length: 0\r\n\
    Connection: close\r\n\r\n";

    fn json_rpc_head(token: Option<&str>, content_length: usize) -> Vec<u8> {
        let authorization = token.map_or_else(String::new, |token| {
            format!("Authorization: Basic {token}\r\n")
        });
        format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\n{authorization}Content-Length: {content_length}\r\n\r\n"
    )
    .into_bytes()
    }

    #[test]
    fn unauthorized_json_rpc_is_answered_from_the_head_with_core_s_tuple() -> io::Result<()> {
        for (token, delayed) in [(None, false), (Some(BAD_TOKEN), true)] {
            let seen = exchange(&json_rpc_head(token, MAX_BODY_BYTES))?;
            assert_eq!(seen.response, CORE_UNAUTHORIZED, "token {token:?}");
            assert!(seen.eof, "the server must close after the 401: {token:?}");
            assert!(seen.served.is_ok(), "a 401 is a served request: {token:?}");
            if delayed {
                assert!(
                    seen.elapsed >= WRONG_CREDENTIALS_DELAY,
                    "wrong credentials answered in {:?}",
                    seen.elapsed
                );
            }
        }
        Ok(())
    }

    #[test]
    fn unauthorized_request_never_serves_pipelined_bytes() -> io::Result<()> {
        let mut request = json_rpc_head(None, 2);
        request
            .extend_from_slice(b"{}GET /rest/chaininfo.json HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let seen = exchange(&request)?;
        assert_eq!(seen.response, CORE_UNAUTHORIZED);
        assert!(seen.eof);
        Ok(())
    }

    #[test]
    fn unauthorized_request_with_buffered_body_returns_without_the_drain_hold() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        client.set_read_timeout(Some(Duration::from_secs(5)))?;
        let (server, _) = listener.accept()?;
        let mut request = json_rpc_head(None, 1);
        request.extend_from_slice(b"X");
        client.write_all(&request)?;
        let mut reader = BufReader::new(RequestDeadlineStream::new(
            server,
            Duration::from_secs(30),
            bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
        ));
        let head = match read_request_head(&mut reader) {
            Ok(Some(head)) => head,
            Ok(None) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "missing head")),
            Err(RequestReadError::Io(error)) => return Err(error),
            Err(RequestReadError::RestBodyTooLarge) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
            }
        };
        assert_eq!(head.content_length, 1);
        reader.get_mut().reset_deadline(REQUEST_HEAD_TIMEOUT);
        assert_eq!(
            reader.fill_buf()?,
            b"X".as_slice(),
            "declared byte must be prebuffered before the 401"
        );
        let started = Instant::now();
        let handled =
            authenticate_json_rpc_head(&Auth::basic("alice", "secret"), &mut reader, &head)?;
        let elapsed = started.elapsed();
        assert!(handled, "unauthorized head must be handled");
        assert!(
            reader.buffer().is_empty(),
            "drain must consume the prebuffered byte: {:?}",
            reader.buffer()
        );
        assert!(
            elapsed < DRAIN_BUDGET,
            "a buffered body must not wait out the drain budget: {elapsed:?}"
        );
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        assert_eq!(response, CORE_UNAUTHORIZED);
        Ok(())
    }

    fn serve_unauthorized(request: &[u8], take: usize) -> io::Result<(String, Vec<u8>)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server = thread::spawn(move || -> io::Result<Vec<u8>> {
            let (stream, _) = listener.accept()?;
            let mut reader = BufReader::new(RequestDeadlineStream::new(
                stream,
                Duration::from_secs(30),
                bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
            ));
            let head = match read_request_head(&mut reader) {
                Ok(Some(head)) => head,
                Ok(None) => {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "missing head"));
                }
                Err(RequestReadError::Io(error)) => return Err(error),
                Err(RequestReadError::RestBodyTooLarge) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
                }
            };
            let handled =
                authenticate_json_rpc_head(&Auth::basic("alice", "secret"), &mut reader, &head)?;
            assert!(handled, "unauthorized head must be handled");
            let mut next = vec![0_u8; take];
            reader.read_exact(&mut next)?;
            Ok(next)
        });
        let mut client = TcpStream::connect(addr)?;
        client.set_read_timeout(Some(Duration::from_secs(5)))?;
        client.write_all(request)?;
        client.shutdown(Shutdown::Write)?;
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        let next = server.join().expect("server thread")?;
        Ok((response, next))
    }

    #[test]
    fn unauthorized_drain_consumes_exactly_the_declared_body() -> io::Result<()> {
        let mut request = json_rpc_head(None, MAX_DRAIN_BYTES);
        request.extend_from_slice(&vec![b'X'; MAX_DRAIN_BYTES]);
        request.extend_from_slice(b"NEXT");
        let (response, next) = serve_unauthorized(&request, 4)?;
        assert_eq!(response, CORE_UNAUTHORIZED);
        assert_eq!(next, b"NEXT");
        Ok(())
    }

    #[test]
    fn unauthorized_drain_stops_at_the_cap_for_an_oversized_body() -> io::Result<()> {
        const TAIL: usize = 4 * 1_024;
        let mut request = json_rpc_head(None, MAX_DRAIN_BYTES + TAIL);
        request.extend_from_slice(&vec![b'X'; MAX_DRAIN_BYTES]);
        request.extend_from_slice(&vec![b'Y'; TAIL]);
        let (response, rest) = serve_unauthorized(&request, TAIL)?;
        assert_eq!(response, CORE_UNAUTHORIZED);
        assert_eq!(rest, vec![b'Y'; TAIL]);
        Ok(())
    }

    #[test]
    fn head_framing_errors_keep_their_400_without_credentials() -> io::Result<()> {
        let oversize = json_rpc_head(None, MAX_BODY_BYTES + 1);
        for (name, request) in [
        (
            "chunked",
            b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
        ),
        (
            "missing length",
            b"POST / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        ),
        (
            "conflicting length",
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n"
                .to_vec(),
        ),
        ("oversize length", oversize),
    ] {
        let seen = exchange(&request)?;
        assert!(
            seen.response.starts_with("HTTP/1.1 400 Bad Request"),
            "{name}: {}",
            seen.response
        );
    }
        Ok(())
    }

    #[test]
    fn authorized_request_proceeds_to_body_framing() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        client.set_read_timeout(Some(Duration::from_secs(5)))?;
        let server = thread::spawn(move || -> io::Result<()> {
            let (stream, _) = listener.accept()?;
            serve_connection(
                stream,
                &Auth::basic("alice", "secret"),
                &Handler::new(Arc::new(Context::new())),
                false,
                Duration::from_secs(30),
                RpcSurface::Shared,
                bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
            )
        });
        let mut request = json_rpc_head(Some(GOOD_TOKEN), 16);
        request.extend_from_slice(b"{}");
        client.write_all(&request)?;
        client.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        client.read_to_end(&mut response)?;
        let _ignored = server.join();
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 400 Bad Request"), "{text}");
        Ok(())
    }

    fn accept_test_server() -> io::Result<RpcServer> {
        RpcServer::bind(
            "127.0.0.1:0",
            Arc::new(Auth::basic("alice", "secret")),
            Arc::new(Handler::new(Arc::new(Context::new()))),
            4,
            Duration::from_secs(1),
            false,
        )
    }

    #[test]
    fn closed_connections_leave_no_retained_tracker_entries() -> io::Result<()> {
        const CONNECTIONS: usize = 1_000;
        const MAX_CONNECTIONS: usize = 4;
        let server = accept_test_server()?;
        let addr = server.local_addr()?;
        let shutdown = LatchWriter::new();
        let reader = shutdown.reader();
        let connections = Arc::new(ConnectionTracker::default());
        let observed = Arc::clone(&connections);
        let handle = thread::spawn(move || {
            server.serve_accept_loop_observed(
                &reader,
                RpcSurface::Shared,
                mio::net::TcpListener::accept,
                observed,
            )
        });

        let exchanges = (|| -> io::Result<()> {
            let request = json_rpc_head(None, 0);
            for _ in 0..CONNECTIONS {
                let admitted_by = Instant::now() + Duration::from_secs(5);
                while connections.live_count() != 0 {
                    if Instant::now() >= admitted_by {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "the previous connection did not release its slot",
                        ));
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                let mut client = TcpStream::connect(addr)?;
                client.set_read_timeout(Some(Duration::from_secs(5)))?;
                client.write_all(&request)?;
                let mut response = String::new();
                client.read_to_string(&mut response)?;
                assert!(response.starts_with("HTTP/1.1 401"), "{response}");
            }
            Ok(())
        })();

        let deadline = Instant::now() + Duration::from_secs(10);
        if exchanges.is_ok() {
            while !connections.retained_threads_settled() {
                assert!(
                    Instant::now() < deadline,
                    "connection threads did not finish within the settle deadline"
                );
                thread::sleep(Duration::from_millis(2));
            }
        }
        let retained = connections.retained_threads();
        shutdown.trigger();
        handle.join().expect("accept thread")?;
        exchanges?;
        assert!(
            retained <= MAX_CONNECTIONS,
            "the tracker retained {retained} entries after {CONNECTIONS} short connections closed"
        );
        Ok(())
    }

    #[test]
    fn idle_accept_is_prompt_across_arrival_phases() -> io::Result<()> {
        let server = accept_test_server()?;
        let addr = server.local_addr()?;
        let shutdown = LatchWriter::new();
        let shutdown_reader = shutdown.reader();
        let (idle_tx, idle_rx) = crossbeam_channel::bounded(1);
        let (accepted_tx, accepted_rx) = crossbeam_channel::unbounded();
        let handle = thread::spawn(move || {
            server.serve_accept_loop(&shutdown_reader, RpcSurface::Shared, |listener| {
                let result = listener.accept();
                match &result {
                    Ok(_) => {
                        let _ = accepted_tx.send(Instant::now());
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        let _ = idle_tx.try_send(());
                    }
                    Err(_) => {}
                }
                result
            })
        });
        let result = (|| -> io::Result<Vec<Duration>> {
            let mut latencies = Vec::new();
            for phase in [0, 13, 37, 61, 89] {
                idle_rx
                    .recv_timeout(Duration::from_secs(3))
                    .expect("idle listener");
                thread::sleep(Duration::from_millis(phase));
                let start = Instant::now();
                let client = TcpStream::connect(addr)?;
                let accepted = accepted_rx
                    .recv_timeout(Duration::from_secs(3))
                    .expect("accepted connection");
                latencies.push(accepted.duration_since(start));
                drop(client);
            }
            Ok(latencies)
        })();
        shutdown.trigger();
        handle.join().expect("accept thread")?;
        let latencies = result?;
        eprintln!("new-connection accept delays at phases 0/13/37/61/89 ms: {latencies:?}");
        assert!(
            latencies
                .iter()
                .all(|latency| *latency < Duration::from_millis(80)),
            "new connections waited on an idle accept cadence: {latencies:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_recovers_from_resource_and_connection_errors() -> io::Result<()> {
        let server = accept_test_server()?;
        let addr = server.local_addr()?;
        let shutdown = LatchWriter::new();
        let shutdown_reader = shutdown.reader();
        let handle = thread::spawn(move || {
            let mut errors = vec![
                io::Error::from(io::ErrorKind::Interrupted),
                io::Error::from(io::ErrorKind::ConnectionAborted),
                io::Error::from(io::ErrorKind::ConnectionReset),
                io::Error::from(io::ErrorKind::PermissionDenied),
                io::Error::from(io::ErrorKind::Unsupported),
                io::Error::other("pending protocol error"),
            ];
            #[cfg(unix)]
            errors.extend([
                io::Error::from_raw_os_error(rustix::io::Errno::MFILE.raw_os_error()),
                io::Error::from_raw_os_error(rustix::io::Errno::NFILE.raw_os_error()),
            ]);
            #[cfg(target_os = "linux")]
            {
                let error =
                    io::Error::from_raw_os_error(rustix::io::Errno::OPNOTSUPP.raw_os_error());
                assert_eq!(error.kind(), io::ErrorKind::Unsupported);
                errors.push(error);
            }
            #[cfg(windows)]
            errors.push(io::Error::from_raw_os_error(10024));
            let mut errors = errors.into_iter();
            let start = Instant::now();
            server.serve_accept_loop(&shutdown_reader, RpcSurface::Shared, |listener| {
                if let Some(error) = errors.next() {
                    return Err(error);
                }
                assert!(start.elapsed() >= ACCEPT_ERROR_BACKOFF * 3);
                listener.accept()
            })
        });
        let response = (|| -> io::Result<String> {
            let mut client = TcpStream::connect(addr)?;
            client.set_read_timeout(Some(Duration::from_secs(5)))?;
            client.write_all(
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        )?;
            let mut response = String::new();
            client.read_to_string(&mut response)?;
            Ok(response)
        })();
        shutdown.trigger();
        handle.join().expect("accept thread")?;
        assert!(response?.starts_with("HTTP/1.1 401"));
        Ok(())
    }

    #[test]
    fn repeated_accept_errors_back_off_and_observe_shutdown() -> io::Result<()> {
        let server = accept_test_server()?;
        let shutdown = LatchWriter::new();
        let shutdown_reader = shutdown.reader();
        let start = Instant::now();
        let mut attempts = 0;
        server.serve_accept_loop(&shutdown_reader, RpcSurface::Shared, |_| {
            attempts += 1;
            if attempts == 3 {
                shutdown.trigger();
            }
            Err(io::Error::other("resource temporarily exhausted"))
        })?;
        assert_eq!(attempts, 3);
        assert!(start.elapsed() >= ACCEPT_ERROR_BACKOFF * 2);
        Ok(())
    }

    #[test]
    fn invalid_listener_errors_are_returned() -> io::Result<()> {
        for kind in [io::ErrorKind::InvalidInput, io::ErrorKind::NotConnected] {
            let server = accept_test_server()?;
            let shutdown = LatchWriter::new();
            let shutdown_reader = shutdown.reader();
            let mut attempts = 0;
            let result = server.serve_accept_loop(&shutdown_reader, RpcSurface::Shared, |_| {
                attempts += 1;
                Err(kind.into())
            });
            assert_eq!(result.expect_err("fatal listener error").kind(), kind);
            assert_eq!(attempts, 1);
        }
        Ok(())
    }

    #[test]
    fn rejects_header_with_whitespace_before_colon() -> io::Result<()> {
        let request = b"POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: 0\r\nTransfer-Encoding : chunked\r\n\r\n";
        let seen = exchange(request)?;
        assert!(
            seen.response.starts_with("HTTP/1.1 400 Bad Request"),
            "must reject whitespace before header colon: {}",
            seen.response
        );
        assert!(seen.eof);
        Ok(())
    }

    #[test]
    fn rejects_header_with_empty_name() -> io::Result<()> {
        let request = b"POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: 0\r\n: invalid\r\n\r\n";
        let seen = exchange(request)?;
        assert!(
            seen.response.starts_with("HTTP/1.1 400 Bad Request"),
            "must reject empty header name: {}",
            seen.response
        );
        assert!(seen.eof);
        Ok(())
    }

    #[test]
    fn rejects_header_with_nul_byte() -> io::Result<()> {
        let request = b"POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: 0\r\nX-Bad\0: 1\r\n\r\n";
        let seen = exchange(request)?;
        assert!(
            seen.response.starts_with("HTTP/1.1 400 Bad Request"),
            "must reject NUL byte in header: {}",
            seen.response
        );
        assert!(seen.eof);
        Ok(())
    }

    #[test]
    fn rejects_too_many_headers() -> io::Result<()> {
        let mut request = b"POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: 0\r\n".to_vec();
        for i in 0..101 {
            request.extend_from_slice(format!("X-Hdr-{i}: 1\r\n").as_bytes());
        }
        request.extend_from_slice(b"\r\n");
        let seen = exchange(&request)?;
        assert!(
            seen.response.starts_with("HTTP/1.1 400 Bad Request"),
            "must reject too many headers: {}",
            seen.response
        );
        assert!(seen.eof);
        Ok(())
    }

    #[test]
    fn rejects_request_line_without_http_version() -> io::Result<()> {
        let request = b"POST /\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: 0\r\n\r\n";
        let seen = exchange(request)?;
        assert!(
            seen.response.starts_with("HTTP/1.1 400 Bad Request"),
            "must reject request line without HTTP version: {}",
            seen.response
        );
        assert!(seen.eof);
        Ok(())
    }

    #[test]
    fn rejects_request_line_with_trailing_tokens() -> io::Result<()> {
        let request = b"POST / HTTP/1.1 extra\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: 0\r\n\r\n";
        let seen = exchange(request)?;
        assert!(
            seen.response.starts_with("HTTP/1.1 400 Bad Request"),
            "must reject request line with trailing tokens: {}",
            seen.response
        );
        assert!(seen.eof);
        Ok(())
    }

    #[test]
    fn rejects_request_line_with_unsupported_http_version() -> io::Result<()> {
        let request = b"POST / HTTP/2.0\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: 0\r\n\r\n";
        let seen = exchange(request)?;
        assert!(
            seen.response.starts_with("HTTP/1.1 400 Bad Request"),
            "must reject unsupported HTTP version: {}",
            seen.response
        );
        assert!(seen.eof);
        Ok(())
    }

    #[test]
    fn rejects_request_target_with_control_characters() -> io::Result<()> {
        let request = b"POST /\x01 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: 0\r\n\r\n";
        let seen = exchange(request)?;
        assert!(
            seen.response.starts_with("HTTP/1.1 400 Bad Request"),
            "must reject control characters in request target: {}",
            seen.response
        );
        assert!(seen.eof);
        Ok(())
    }

    #[test]
    fn rejects_request_target_with_nul_byte() -> io::Result<()> {
        let request = b"POST /\0 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: 0\r\n\r\n";
        let seen = exchange(request)?;
        assert!(
            seen.response.starts_with("HTTP/1.1 400 Bad Request"),
            "must reject NUL byte in request target: {}",
            seen.response
        );
        assert!(seen.eof);
        Ok(())
    }

    #[test]
    fn batch_size_n_minus_one_is_served() {
        let handler = Handler::new(Arc::new(Context::new()));
        let at_limit_minus_one = (0..MAX_BATCH_ELEMENTS - 1)
            .map(|id| json!({"jsonrpc":"2.0","id":id,"method":"getblockcount","params":[]}))
            .collect::<Vec<_>>();
        let accepted = handle_decoded_json(&handler, &Value::from(at_limit_minus_one));
        assert_eq!(accepted.status, 200);
        assert_eq!(
            accepted
                .body
                .expect("batch replies")
                .as_array()
                .map(sonic_rs::Array::len),
            Some(MAX_BATCH_ELEMENTS - 1)
        );
    }

    #[test]
    fn answers_duplicate_ids_in_batch_independently() {
        let handler = Handler::new(Arc::new(Context::new()));
        let batch = json!([
            {"jsonrpc":"2.0","id":"duplicate-id","method":"getblockcount","params":[]},
            {"jsonrpc":"2.0","id":"duplicate-id","method":"getblockcount","params":[]}
        ]);
        let response = handle_decoded_json(&handler, &batch);
        assert_eq!(response.status, 200);
        let items = response
            .body
            .expect("body")
            .as_array()
            .expect("array")
            .clone();
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[0].get("id").and_then(|v| v.as_str()),
            Some("duplicate-id")
        );
        assert_eq!(
            items[1].get("id").and_then(|v| v.as_str()),
            Some("duplicate-id")
        );
    }

    #[test]
    fn rejects_non_object_members_in_batch_as_invalid_request() {
        let handler = Handler::new(Arc::new(Context::new()));
        let batch = json!([1, "not-an-object", true, Value::new_null()]);
        let response = handle_decoded_json(&handler, &batch);
        assert_eq!(response.status, 200);
        let items = response
            .body
            .expect("body")
            .as_array()
            .expect("array")
            .clone();
        assert_eq!(items.len(), 4);
        for item in &items {
            assert_eq!(
                item.get("error").and_then(|e| e.get("code")),
                Some(&json!(RpcError::INVALID_REQUEST))
            );
            assert!(
                item.get("id")
                    .is_some_and(sonic_rs::JsonValueTrait::is_null)
            );
        }
    }

    #[test]
    fn dispatches_params_as_object_and_array_and_rejects_primitive() {
        let handler = Handler::new(Arc::new(Context::new()));
        let mut valid_tx_hex = String::from("0200000001");
        valid_tx_hex.push_str(&"00".repeat(32));
        valid_tx_hex.push_str("ffffffff00ffffffff010100000000000000015100000000");

        let array_params = json!({"jsonrpc":"2.0","id":1,"method":"decoderawtransaction","params":[valid_tx_hex.as_str()]});
        let resp_arr = handle_decoded_json(&handler, &array_params);
        assert_eq!(resp_arr.status, 200);
        assert!(resp_arr.body.as_ref().expect("body").get("error").is_none());

        let object_params = json!({"jsonrpc":"2.0","id":2,"method":"decoderawtransaction","params":{"hexstring":valid_tx_hex.as_str()}});
        let resp_obj = handle_decoded_json(&handler, &object_params);
        assert_eq!(resp_obj.status, 200);
        assert!(resp_obj.body.as_ref().expect("body").get("error").is_none());
        assert_eq!(
            resp_arr.body.expect("array body").get("result"),
            resp_obj.body.expect("obj body").get("result")
        );

        let primitive_params =
            json!({"jsonrpc":"2.0","id":3,"method":"getblockcount","params":123});
        let resp = handle_decoded_json(&handler, &primitive_params);
        assert_eq!(resp.status, 400);
        assert_eq!(
            resp.body
                .expect("body")
                .get("error")
                .and_then(|e| e.get("code")),
            Some(&json!(RpcError::INVALID_REQUEST))
        );
    }

    #[test]
    fn preserves_huge_numbers_in_request_id() {
        let handler = Handler::new(Arc::new(Context::new()));
        let max_u64_id = "18446744073709551615";
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":{max_u64_id},"method":"getblockcount","params":[]}}"#
        );
        let response = handle_json(&handler, body.as_bytes());
        assert_eq!(response.status, 200);
        let body_str = sonic_rs::to_string(&response.body.expect("body")).expect("json");
        assert!(
            body_str.contains(max_u64_id),
            "must preserve exact huge integer in id: {body_str}"
        );
    }

    #[test]
    fn rejects_invalid_utf8_in_json_rpc_body() {
        let handler = Handler::new(Arc::new(Context::new()));
        let invalid_utf8 = b"\xff\xfe\xfd";
        let response = handle_json(&handler, invalid_utf8);
        assert_eq!(response.status, 500);
        assert_eq!(
            response
                .body
                .expect("body")
                .get("error")
                .and_then(|e| e.get("code")),
            Some(&json!(-32_700))
        );
    }

    #[test]
    fn rejects_raw_nul_bytes_in_json_rpc_body() {
        let handler = Handler::new(Arc::new(Context::new()));
        let raw_nul = b"{\"jsonrpc\":\"2.0\",\"method\":\"test\0\",\"id\":1}";
        let response = handle_json(&handler, raw_nul);
        assert_eq!(response.status, 500);
        assert_eq!(
            response
                .body
                .expect("body")
                .get("error")
                .and_then(|e| e.get("code")),
            Some(&json!(-32_700))
        );
    }

    #[test]
    fn handles_deeply_nested_json_without_panic() {
        let handler = Handler::new(Arc::new(Context::new()));
        let mut nested_objects = Vec::new();
        for _ in 0..300 {
            nested_objects.extend_from_slice(b"{\"a\":");
        }
        nested_objects.extend_from_slice(b"1");
        nested_objects.extend(std::iter::repeat_n(b'}', 300));
        let response = handle_json(&handler, &nested_objects);
        assert_eq!(response.status, 400);
        assert_eq!(
            response
                .body
                .expect("body")
                .get("error")
                .and_then(|e| e.get("code")),
            Some(&json!(RpcError::INVALID_REQUEST))
        );

        let mut nested_arrays = Vec::new();
        nested_arrays.extend(std::iter::repeat_n(b'[', 300));
        nested_arrays.extend(std::iter::repeat_n(b']', 300));
        let response = handle_json(&handler, &nested_arrays);
        assert_eq!(response.status, 200);
        let items = response
            .body
            .expect("body")
            .as_array()
            .expect("array")
            .clone();
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].get("error").and_then(|e| e.get("code")),
            Some(&json!(RpcError::INVALID_REQUEST))
        );
    }

    #[test]
    fn serves_pipelined_requests_on_keep_alive_connection() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = thread::spawn(move || -> io::Result<()> {
            let (stream, _) = listener.accept()?;
            serve_connection(
                stream,
                &Auth::basic("alice", "secret"),
                &Handler::new(Arc::new(Context::new())),
                false,
                Duration::from_secs(5),
                RpcSurface::Shared,
                bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
            )
        });

        let body1 = r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#;
        let body2 = r#"{"jsonrpc":"2.0","id":2,"method":"getblockcount","params":[]}"#;
        let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body1}\
         POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body2}",
        body1.len(),
        body2.len()
    )
    .into_bytes();

        let mut client = TcpStream::connect(address)?;
        client.write_all(&request)?;
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        server.join().expect("server")?;

        let count = response.split("HTTP/1.1 200 OK").count();
        assert_eq!(
            count, 3,
            "expected exactly 2 responses in pipelined exchange: {response}"
        );
        assert!(response.contains("\"id\":1"));
        assert!(response.contains("\"id\":2"));
        Ok(())
    }

    #[test]
    fn ignores_pipelined_request_after_connection_close() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = thread::spawn(move || -> io::Result<()> {
            let (stream, _) = listener.accept()?;
            serve_connection(
                stream,
                &Auth::basic("alice", "secret"),
                &Handler::new(Arc::new(Context::new())),
                false,
                Duration::from_secs(5),
                RpcSurface::Shared,
                bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
            )
        });

        let body1 = r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#;
        let body2 = r#"{"jsonrpc":"2.0","id":2,"method":"getblockcount","params":[]}"#;
        let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body1}\
         POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body2}",
        body1.len(),
        body2.len()
    )
    .into_bytes();

        let mut client = TcpStream::connect(address)?;
        client.write_all(&request)?;
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        server.join().expect("server")?;

        let count = response.split("HTTP/1.1 200 OK").count();
        assert_eq!(
            count, 2,
            "expected exactly 1 response since first closed connection: {response}"
        );
        assert!(response.contains("\"id\":1"));
        assert!(!response.contains("\"id\":2"));
        Ok(())
    }

    #[test]
    fn recovers_from_missing_cookie_file() {
        let result = crate::auth::Auth::cookie("/tmp/nonexistent_cookie_file_for_btcrs_test");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_cookie_file_without_colon() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let cookie_path = dir.path().join(".cookie");
        std::fs::write(&cookie_path, b"user_without_password")?;
        let result = crate::auth::Auth::cookie(&cookie_path);
        assert!(matches!(result, Err(crate::auth::AuthError::InvalidCookie)));
        Ok(())
    }

    #[test]
    fn accepts_cookie_file_with_empty_password() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let cookie_path = dir.path().join(".cookie");
        std::fs::write(&cookie_path, b"alice:\n")?;
        let auth =
            crate::auth::Auth::cookie(&cookie_path).expect("valid cookie with empty password");
        assert!(auth.validate_header(Some("Basic YWxpY2U6")));
        assert!(!auth.validate_header(Some("Basic YWxpY2U6c2VjcmV0")));
        Ok(())
    }

    #[test]
    fn auth_constant_time_eq_verifies_byte_mismatch_and_length_mismatch() {
        use crate::auth::constant_time_eq;
        assert!(constant_time_eq(b"password123", b"password123"));
        assert!(!constant_time_eq(b"password123", b"password124"));
        assert!(!constant_time_eq(b"password123", b"password12"));
        assert!(!constant_time_eq(b"password12", b"password123"));
        assert!(!constant_time_eq(b"", b"p"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn json_depth_limit_exceeded_returns_parse_error_without_stack_overflow() {
        let handler = Handler::new(Arc::new(Context::new()));
        let mut deep = Vec::with_capacity(20_000);
        deep.extend(std::iter::repeat_n(b'[', 10_000));
        deep.extend(std::iter::repeat_n(b']', 10_000));
        let response = handle_json(&handler, &deep);
        assert_eq!(response.status, 500);
        assert!(response.body.is_some());
    }

    #[test]
    fn json_depth_limit_matches_core_and_parses_at_the_limit() {
        let handler = Handler::new(Arc::new(Context::new()));
        let worker = std::thread::Builder::new()
            .name("json-depth-proof".to_owned())
            .stack_size(super::RPC_CONNECTION_STACK_BYTES)
            .spawn(move || {
                let request = |nesting: usize| {
                    let mut body = Vec::from(
                        &b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockcount\",\"params\":"
                            [..],
                    );
                    body.extend(std::iter::repeat_n(b'[', nesting));
                    body.extend(std::iter::repeat_n(b']', nesting));
                    body.push(b'}');
                    body
                };
                [
                    handle_json(&handler, &request(300)),
                    handle_json(&handler, &request(511)),
                    handle_json(&handler, &request(512)),
                ]
            })
            .expect("spawn depth proof thread");
        let [accepted, at_limit, refused] = worker.join().expect("depth proof thread");
        assert_eq!(accepted.status, 200);
        assert_eq!(at_limit.status, 200);
        assert!(
            at_limit
                .body
                .expect("limit response body")
                .to_string()
                .contains("-32602"),
            "a depth 512 request must reach dispatch"
        );
        assert_eq!(refused.status, 500);
        assert!(
            refused
                .body
                .expect("refusal response body")
                .to_string()
                .contains("-32700"),
            "a depth 513 request must answer a typed parse error"
        );
    }
}
