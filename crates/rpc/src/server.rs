use alloc::sync::Arc;
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, IoSlice, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};
use tracing::{debug, warn};

use crate::auth::Auth;
use crate::error::RpcError;
use crate::handlers::Handler;

const MAX_HEADER_BYTES: usize = 16 * 1_024;
/// Share of the connection pool kept open to sources other than the busiest
/// one: a quarter, rounded down, so one source holds at most 96 of the
/// default 128.
const RESERVED_POOL_DIVISOR: usize = 4;
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) const MAX_BODY_BYTES: usize = 16 * 1_024 * 1_024;

/// How long a wrong-credential answer waits before it is written, Core's
/// brute-force deterrent (`httprpc.cpp:215-225`).
const WRONG_CREDENTIALS_DELAY: Duration = Duration::from_millis(250);

/// Most declared body bytes the unauthorized path reads after its answer.
/// Bytes past this bound stay unread, so a peer that sends more may see a
/// reset instead of a clean close.
const MAX_DRAIN_BYTES: usize = 64 * 1_024;

/// How long the drain may keep reading before the connection is closed
/// under the peer.
const DRAIN_BUDGET: Duration = Duration::from_secs(1);

const POLL_INTERVAL: core::time::Duration = core::time::Duration::from_millis(100);

const PUBLIC_ESPLORA_METHODS: &[&str] = &["GET", "POST", "OPTIONS"];

const PUBLIC_ESPLORA_HEADERS: &[&str] = &["Content-Type"];

const PUBLIC_ESPLORA_EXPOSE_HEADERS: &[&str] = &["X-Total-Results"];

/// Routes admitted by one listener, with an independent connection budget.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RpcSurface {
    /// Historical combined JSON-RPC, REST and Esplora listener.
    #[default]
    Shared,
    /// Authenticated JSON-RPC only.
    Management,
    /// REST (when enabled) and both existing Esplora namespaces; no JSON-RPC.
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

/// Synchronous HTTP/1.1 JSON-RPC server.
pub struct RpcServer {
    /// Bound TCP listener.
    pub listener: TcpListener,
    /// Shared authentication policy.
    pub auth: Arc<Auth>,
    /// Shared JSON-RPC handler.
    pub handler: Arc<Handler>,
    /// Maximum concurrent worker connections.
    pub max_connections: usize,
    /// Idle read timeout for each connection.
    pub idle_timeout: Duration,
    /// Whether Bitcoin Core-compatible REST routes are enabled.
    pub rest_enabled: bool,
}

impl RpcServer {
    /// Binds a new RPC server.
    pub fn bind<A: ToSocketAddrs>(
        address: A,
        auth: Arc<Auth>,
        handler: Arc<Handler>,
        max_connections: usize,
        idle_timeout: Duration,
        rest_enabled: bool,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(address)?;
        // A binding owns its dispatcher cancellation latch. Rebinding the
        // same Context must not reset a latch retained by old requests.
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
        })
    }

    /// Returns the local socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Runs the accept loop until `shutdown` is set to `true`.
    ///
    /// Polls non-blocking accept on a fixed cadence so the loop can observe
    /// shutdown without parking on an open socket. Each accepted connection
    /// is restored to blocking mode and handed to a bounded worker thread,
    /// preserving the configured `idle_timeout` per connection.
    pub fn serve_with_shutdown(
        self,
        shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
    ) -> io::Result<()> {
        self.serve_surface_with_shutdown(shutdown, RpcSurface::Shared)
    }

    /// Runs this listener with a closed route selection and its own budget.
    /// The historical serving entrypoint retains the shared surface.
    pub fn serve_surface_with_shutdown(
        self,
        shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
        surface: RpcSurface,
    ) -> io::Result<()> {
        self.serve_accept_loop(&shutdown.into(), surface, TcpListener::accept)
    }

    fn serve_accept_loop(
        self,
        shutdown: &bitcoin_rs_chain::LatchReader,
        surface: RpcSurface,
        mut accept: impl FnMut(&TcpListener) -> io::Result<(TcpStream, SocketAddr)>,
    ) -> io::Result<()> {
        let _stop = RpcStop(Arc::clone(&self.handler));
        self.handler
            .configure_blocking_admission(per_source_limit(self.max_connections));
        self.listener.set_nonblocking(true)?;
        let active = Arc::new(Mutex::new(ActiveConnections::default()));
        while !shutdown.is_triggered() {
            match accept(&self.listener) {
                Ok((stream, addr)) => {
                    if let Err(error) = stream
                        .set_nonblocking(false)
                        .and_then(|()| self.handle_accept(&active, stream, addr.ip(), surface))
                    {
                        debug!(%error, "rpc connection setup failed");
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(POLL_INTERVAL);
                }
                Err(error) => match error.kind() {
                    io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted => {
                        debug!(%error, "rpc accept interrupted or connection aborted");
                    }
                    io::ErrorKind::InvalidInput | io::ErrorKind::NotConnected => return Err(error),
                    _ => {
                        // Resource exhaustion (including EMFILE/ENFILE) and
                        // pending network errors need not invalidate the listener.
                        // Linux may report EOPNOTSUPP (Unsupported) for a new
                        // connection, so that kind must also remain retryable.
                        // Back off unknown OS errors too, avoiding a busy loop,
                        // and recheck shutdown before the next accept attempt.
                        warn!(%error, "rpc accept failed; retrying after backoff");
                        thread::sleep(POLL_INTERVAL);
                    }
                },
            }
        }
        // Drop cancels the new blocking RPC capabilities even when only this
        // server stops; the chainstate and its process latch may remain live.
        Ok(())
    }

    fn handle_accept(
        &self,
        active: &Arc<Mutex<ActiveConnections>>,
        stream: TcpStream,
        peer: IpAddr,
        surface: RpcSurface,
    ) -> io::Result<()> {
        // Connection-local: a nodelay failure must not stop the accept loop.
        let mut stream = match prepare_http_socket(stream) {
            Ok(stream) => stream,
            Err(error) => {
                debug!(%error, "rpc connection dropped: nodelay");
                return Ok(());
            }
        };
        let should_accept = active.lock().admit(peer, self.max_connections);
        if !should_accept {
            metrics::counter!("rpc.connections.rejected_total", "surface" => surface.label())
                .increment(1);
            stream.set_write_timeout(Some(self.idle_timeout))?;
            write_status(&mut stream, 503, "Service Unavailable", b"busy", false)?;
            return Ok(());
        }

        let permit = ConnectionPermit {
            active: Arc::clone(active),
            peer,
            surface,
        };
        metrics::gauge!("rpc.connections.active", "surface" => surface.label()).increment(1.0);
        let auth = Arc::clone(&self.auth);
        let handler = Arc::clone(&self.handler);
        let rest_enabled = self.rest_enabled;
        let idle_timeout = self.idle_timeout;
        thread::Builder::new()
            .name("rpc-connection".to_owned())
            .spawn(move || {
                let _permit = permit;
                if let Err(error) =
                    serve_connection(stream, &auth, &handler, rest_enabled, idle_timeout, surface)
                {
                    debug!(%error, "rpc connection closed with error");
                }
            })?;
        Ok(())
    }
}

/// The most connections one source address may hold: all but a quarter of
/// the pool, rounded down, so the rest stays open to other sources. A source
/// is an address, so every client behind loopback, a Docker gateway or a
/// reverse proxy shares one and can still use most of the pool. Pools below
/// four workers keep no share.
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

/// Applies a single wall-clock budget across all socket reads for a request
/// phase. A trickle of bytes cannot restart this deadline as with `SO_RCVTIMEO`.
struct RequestDeadlineStream {
    stream: TcpStream,
    idle_timeout: Duration,
    deadline: Instant,
    /// The socket read timeout last set, so an unchanged value costs no
    /// extra syscall per read.
    applied_timeout: Option<Duration>,
}

impl RequestDeadlineStream {
    fn new(stream: TcpStream, idle_timeout: Duration) -> Self {
        Self {
            stream,
            idle_timeout,
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
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP request deadline exceeded",
            ));
        }
        let timeout = self.idle_timeout.min(remaining);
        if self.applied_timeout != Some(timeout) {
            self.stream.set_read_timeout(Some(timeout))?;
            self.applied_timeout = Some(timeout);
        }
        self.stream.read(buffer)
    }
}

fn serve_connection(
    stream: TcpStream,
    auth: &Auth,
    handler: &Handler,
    rest_enabled: bool,
    idle_timeout: Duration,
    surface: RpcSurface,
) -> io::Result<()> {
    stream.set_write_timeout(Some(idle_timeout))?;
    let mut reader = BufReader::new(RequestDeadlineStream::new(stream, idle_timeout));
    loop {
        if handler.is_stopping() {
            return Ok(());
        }
        // Waiting for the next request keeps the configured idle timeout;
        // `read_request_head` starts the head budget at the request's first byte.
        reader.get_mut().reset_deadline(idle_timeout);
        let head = match read_request_head(&mut reader, REQUEST_HEAD_TIMEOUT) {
            Ok(Some(head)) => head,
            Ok(None) => return Ok(()),
            Err(RequestReadError::RestBodyTooLarge) => {
                let response = if rest_enabled && surface != RpcSurface::Management {
                    crate::rest::getutxos_body_too_large()
                } else {
                    crate::rest::not_found()
                };
                write_response(
                    reader.get_mut().socket_mut(),
                    &response,
                    false,
                    CorsPolicy::Disabled,
                )?;
                return Ok(());
            }
            Err(RequestReadError::Io(error)) => {
                // The JSON-RPC parser renders `InvalidRequest` verbatim for
                // Core compatibility; HTTP framing failures keep the local
                // prefix this variant used to carry.
                let rpc_error = RpcError::InvalidRequest("invalid request: malformed http request");
                let response =
                    JsonRpcVersion::Legacy.error_response(&rpc_error, &Value::new_null());
                write_json(
                    reader.get_mut().socket_mut(),
                    400,
                    "Bad Request",
                    &response,
                    false,
                )?;
                return Err(error);
            }
        };
        let route = classify(&head.method, &head.path);
        let _request_timer = RequestTimer {
            started: Instant::now(),
            surface,
            route: route.label(),
        };
        // Reject a route outside this listener before authentication or body
        // upload. Closing also prevents pipelined bytes crossing the boundary.
        if !surface.allows(&route) {
            write_not_found(reader.get_mut().socket_mut(), false)?;
            return Ok(());
        }
        // Authentication runs from the head alone, before any body byte is
        // read: a 16 MiB declared body without credentials gets its 401 at
        // once instead of after its upload (Core `httprpc.cpp` checks inside
        // the handler, after libevent has buffered the whole body). REST and
        // Esplora stay unauthenticated, and framing errors keep the 400
        // answer, so only the JSON-RPC route defers its body.
        if authenticate_json_rpc_head(auth, &mut reader, &head)? {
            return Ok(());
        }
        let request = match read_request_body(&mut reader, REQUEST_BODY_TIMEOUT, head) {
            Ok(request) => request,
            Err(RequestReadError::RestBodyTooLarge) => {
                let response = if rest_enabled && surface != RpcSurface::Management {
                    crate::rest::getutxos_body_too_large()
                } else {
                    crate::rest::not_found()
                };
                write_response(
                    reader.get_mut().socket_mut(),
                    &response,
                    false,
                    CorsPolicy::Disabled,
                )?;
                return Ok(());
            }
            Err(RequestReadError::Io(error)) => {
                let rpc_error = RpcError::InvalidRequest("malformed http request");
                let response =
                    JsonRpcVersion::Legacy.error_response(&rpc_error, &Value::new_null());
                write_json(
                    reader.get_mut().socket_mut(),
                    400,
                    "Bad Request",
                    &response,
                    false,
                )?;
                return Err(error);
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
        )? {
            return Ok(());
        }
        if !keep_alive {
            return Ok(());
        }
    }
}

/// Answers the unauthenticated head of a JSON-RPC request and reports that
/// the connection is finished.
///
/// The 401 carries Core's challenge, content type, an empty body, and no
/// `Date`; the connection is closed either way, so a client cannot hold the
/// worker with pipelined requests it never authenticated for.
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
    // Present but wrong credentials are slowed before the answer, Core's
    // brute-force deterrent (`httprpc.cpp:215-225`). Absent credentials
    // answer at once: there is no secret to slow down.
    if head.authorization.is_some() {
        thread::sleep(WRONG_CREDENTIALS_DELAY);
    }
    write_unauthorized(reader.get_mut().socket_mut())?;
    // No declared body means no peer bytes can belong to this request: close
    // at once instead of holding a bounded-pool worker up to DRAIN_BUDGET.
    // Otherwise discard only the declared body through the buffered reader,
    // so a well-behaved client sees a clean close instead of a reset.
    if head.content_length == 0 {
        return Ok(());
    }
    drain_request(reader, head.content_length);
    Ok(())
}

/// Writes the Core-shaped 401: a challenge, an empty HTML-typed body, and a
/// close. No `Date` is emitted, and no JSON body is serialized.
fn write_unauthorized(stream: &mut TcpStream) -> io::Result<()> {
    let header = "HTTP/1.1 401 Unauthorized\r\n\
                  WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n\
                  Content-Type: text/html; charset=ISO-8859-1\r\n\
                  Content-Length: 0\r\n\
                  Connection: close\r\n\r\n";
    stream.write_all(header.as_bytes())?;
    stream.flush()?;
    stream.shutdown(std::net::Shutdown::Write)
}

/// Reads and discards the declared body bytes the peer announced, up to
/// [`MAX_DRAIN_BYTES`] and for at most [`DRAIN_BUDGET`], then returns at EOF
/// or on the first read failure. Reads go through the buffered reader, so
/// body bytes already buffered past the head count toward the declared
/// length and a fully buffered body costs no wait. The peer then sees a
/// clean close rather than a reset for the bytes it already put on the wire.
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
            let esplora_surface = esplora_surface(surface);
            let response = crate::esplora::route(handler, esplora_surface, path, query);
            write_response(stream, &response, keep_alive, surface.cors_policy())?;
        }
        HttpRoute::EsploraPost { surface, path } => {
            let esplora_surface = esplora_surface(surface);
            let response =
                crate::esplora::route_post(handler, esplora_surface, path, &request.body);
            write_response(stream, &response, keep_alive, surface.cors_policy())?;
        }
        HttpRoute::Preflight { surface } => {
            let response = crate::rest::Response {
                status: 204,
                reason: "No Content",
                content_type: "text/plain",
                body: Vec::new(),
            };
            write_response(stream, &response, keep_alive, surface.cors_policy())?;
        }
        HttpRoute::NotFound => {
            write_not_found(stream, keep_alive)?;
        }
        // The head gate already answered every unauthenticated JSON-RPC
        // request before its body was read; whatever survives it is
        // authorized.
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

// Authorization lives on the head, which the authentication gate consumes
// before `read_request_body` runs; the completed request carries no copy.
struct HttpRequest {
    method: String,
    path: String,
    keep_alive: bool,
    body: Vec<u8>,
}

/// Reads one request-head line with the remaining aggregate budget. The
/// one-byte sentinel makes an unterminated oversized line fail before EOF.
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
    Ok((line, read))
}

/// Reads header lines until the blank terminator, enforcing the header size
/// ceiling and capturing the three headers the demux consumes.
fn read_headers(
    reader: &mut BufReader<RequestDeadlineStream>,
    mut header_bytes: usize,
) -> io::Result<(usize, Option<usize>, Option<String>, bool)> {
    let mut content_length = None;
    let mut authorization = None;
    let mut keep_alive = false;
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
            return Ok((header_bytes, content_length, authorization, keep_alive));
        }
        let Some((name, value)) = line.trim_end_matches(['\r', '\n']).split_once(':') else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid header"));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value.parse::<usize>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid content-length")
            })?;
            if parsed > MAX_BODY_BYTES {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
            }
            if content_length.is_some_and(|previous| previous != parsed) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "conflicting content-length",
                ));
            }
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            // This server supports Content-Length framing only. Accepting
            // both would leave body bytes to be interpreted as another request.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported transfer-encoding",
            ));
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("connection") {
            keep_alive = value.eq_ignore_ascii_case("keep-alive");
        }
    }
}

enum RequestReadError {
    Io(io::Error),
    RestBodyTooLarge,
}

impl From<io::Error> for RequestReadError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// The parts of a request the head carries: everything the routing and the
/// authentication gate need, before any body byte is read.
struct RequestHead {
    method: String,
    path: String,
    authorization: Option<String>,
    keep_alive: bool,
    /// `POST` without a `Content-Length` never reaches this struct: it is a
    /// framing error at the head.
    content_length: usize,
}

fn read_request_head(
    reader: &mut BufReader<RequestDeadlineStream>,
    head_timeout: Duration,
) -> Result<Option<RequestHead>, RequestReadError> {
    if reader.fill_buf()?.is_empty() {
        return Ok(None);
    }
    reader.get_mut().reset_deadline(head_timeout);
    let (request_line, bytes) = read_head_line(reader, MAX_HEADER_BYTES)?;
    if bytes == 0 {
        return Ok(None);
    }
    if !request_line.ends_with("\r\n") {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request line").into());
    }

    let request_target = request_line.trim_end_matches(['\r', '\n']);
    let mut request_parts = request_target.split_whitespace();
    let Some(method) = request_parts.next() else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request line").into());
    };
    let Some(path) = request_parts.next() else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request line").into());
    };
    if method.is_empty()
        || !method.bytes().all(|byte| {
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
        })
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request method").into());
    }
    let (_, content_length, authorization, keep_alive) = read_headers(reader, request_line.len())?;

    // A POST without Content-Length is a framing error: the JSON-RPC path is
    // body-carrying by definition. Other methods reach the demux and 404 there.
    let content_length = match (method, content_length) {
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
        authorization,
        keep_alive,
        content_length,
    }))
}

/// Reads the body the authenticated head declared. `read_request_body` runs
/// only after `authenticate_json_rpc_head` let the head through.
fn read_request_body(
    reader: &mut BufReader<RequestDeadlineStream>,
    body_timeout: Duration,
    head: RequestHead,
) -> Result<HttpRequest, RequestReadError> {
    reader.get_mut().reset_deadline(body_timeout);
    let mut body = Vec::new();
    read_body(reader, head.content_length, &mut body)?;
    Ok(HttpRequest {
        method: head.method,
        path: head.path,
        keep_alive: head.keep_alive,
        body,
    })
}

const BODY_READ_CHUNK: usize = 8 * 1_024;

/// Reads exactly `content_length` bytes into the empty `body`, which grows
/// with the bytes received, as Bitcoin Core's HTTP server does: a declared but
/// unsent body reserves little, and the buffer never exceeds `content_length`.
/// A body that ends early is `UnexpectedEof`.
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
        // Doubling capped at `content_length`; `read_to_end` would round a
        // full body's capacity up to the next power of two.
        if body.capacity() - body.len() < read {
            body.try_reserve_exact(remaining.min(body.len().max(BODY_READ_CHUNK)))?;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(())
}

struct JsonResponse {
    close: bool,
    status: u16,
    reason: &'static str,
    body: Option<Value>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum JsonRpcVersion {
    Legacy,
    V2,
}

impl JsonRpcVersion {
    /// Classifies the envelope exactly as the pinned Core 31.1 parser does
    /// (`src/rpc/request.cpp:206-224`).
    ///
    /// PRE: `request` is one decoded JSON-RPC request object.
    /// POST: `V2` for `"jsonrpc":"2.0"`, `Legacy` for an absent field or the
    ///   historical `"1.0"` form Core still accepts, and `InvalidRequest`
    ///   (-32600) with Core's message for a non-string field or any other
    ///   version string.
    /// INVARIANT: classification never executes the method; a refused
    ///   envelope is answered without dispatch.
    fn classify(request: &Value) -> Result<Self, RpcError> {
        let Some(version) = request.get("jsonrpc") else {
            return Ok(Self::Legacy);
        };
        // Core treats an absent field like `null`; only explicit non-strings
        // are refused (`request.cpp:213-216`).
        if version.is_null() {
            return Ok(Self::Legacy);
        }
        let Some(version) = version.as_str() else {
            return Err(RpcError::InvalidRequest("jsonrpc field must be a string"));
        };
        match version {
            // Core keeps the historical `{"jsonrpc":"1.0"}` request form as
            // legacy for backwards compatibility (`request.cpp:216-222`).
            "1.0" => Ok(Self::Legacy),
            "2.0" => Ok(Self::V2),
            _ => Err(RpcError::InvalidRequest("JSON-RPC version not supported")),
        }
    }

    fn success_response(self, result: &Value, id: &Value) -> Value {
        match self {
            Self::Legacy => json!({"result": result, "error": null, "id": id}),
            Self::V2 => json!({"jsonrpc": "2.0", "result": result, "id": id}),
        }
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

    /// HTTP status for a failing call in this dialect.
    ///
    /// Core answers legacy errors with an HTTP error status and v2 errors
    /// with HTTP 200 (`src/httprpc.cpp:41-56`). Within the legacy dialect,
    /// `RPC_INVALID_REQUEST` maps to 400 and `RPC_METHOD_NOT_FOUND` to 404;
    /// every other code keeps 500.
    const fn error_status_for(self, error: &RpcError) -> u16 {
        self.error_status_for_code(error.code())
    }

    /// The same mapping keyed by the error code, for callers that carry the
    /// code rather than the error.
    ///
    /// For a v2 request only *dispatch* errors stay inside HTTP 200; an
    /// envelope violation reaches Core's outer error path, which maps
    /// `-32600` to HTTP 400 regardless of the version the parser had
    /// already assigned (`src/httprpc.cpp:41-56`, `src/rpc/request.cpp:206-260`).
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
        /// The failing call's error code, when this reply is an error.
        ///
        /// The legacy HTTP status depends on the code (400 for -32600, 404
        /// for -32601), so the code travels with the reply.
        error_code: Option<i64>,
        /// Whether the error is an envelope refusal raised by the parse
        /// step itself. Core maps these `-32600`s to HTTP 400 without
        /// consulting the negotiated dialect (`src/httprpc.cpp`), while a
        /// method-level error keeps the dialect's own mapping.
        envelope_error: bool,
    },
    Notification,
}

impl CallResponse {
    fn reply(body: Value, version: JsonRpcVersion, error: Option<&RpcError>) -> Self {
        Self::Reply {
            body,
            version,
            error_code: error.map(RpcError::code),
            envelope_error: false,
        }
    }

    /// A reply for a refused envelope: Core raises `-32600` from
    /// `JSONRPCRequest::parse` and answers HTTP 400 in either dialect.
    fn envelope_error(body: Value, version: JsonRpcVersion, error: &RpcError) -> Self {
        Self::Reply {
            body,
            version,
            error_code: Some(error.code()),
            envelope_error: true,
        }
    }

    const fn http_status(&self) -> u16 {
        match self {
            // The dialect code mapping is the single owner of every reply
            // that carries a code, including envelope refusals: Core's
            // outer error path maps the post-classification `-32600` to
            // 400 through this arm in either dialect. The generic envelope
            // arm below only covers the codeless case.
            Self::Reply {
                version,
                error_code: Some(code),
                ..
            } => version.error_status_for_code(*code),
            Self::Reply {
                envelope_error: true,
                ..
            } => 400,
            Self::Reply { .. } | Self::Notification => 200,
        }
    }
}

fn handle_json(handler: &Handler, body: &[u8]) -> JsonResponse {
    let body = match core::str::from_utf8(body) {
        Ok(body) => body,
        Err(error) => {
            return legacy_error_response(&RpcError::from(error), &Value::new_null());
        }
    };
    let request = match sonic_rs::from_str::<Value>(body) {
        Ok(request) => request,
        Err(error) => {
            return legacy_error_response(&RpcError::from(error), &Value::new_null());
        }
    };

    // The close decision is owned by `handle_decoded_json`, which sees the
    // decoded envelope. Undecodable bodies name no method, so they never
    // close; every decodable shape carries the flag computed below.
    handle_decoded_json(handler, &request)
}

fn handle_decoded_json(handler: &Handler, request: &Value) -> JsonResponse {
    // Single owner of the close decision: a rejected long call must not
    // retain the reserved ordinary slot through keep-alive.
    // Batch/notification classification uses the same registry, and every
    // return below carries this flag, so no caller overwrites it and a
    // future `true` cannot be silently discarded.
    let close = request.as_array().map_or_else(
        || crate::registry::blocking_request(request),
        |requests| requests.iter().any(crate::registry::blocking_request),
    );
    if let Some(requests) = request.as_array() {
        if requests.is_empty() {
            // Core: an empty batch still answers HTTP 200 with an empty
            // result array (`httprpc.cpp` runs the batch reply path, which
            // produces `[]` for no members).
            return JsonResponse {
                close,
                status: 200,
                reason: reason_for_status(200),
                body: Some(json!([])),
            };
        }
        let mut responses = Vec::with_capacity(requests.len());
        for request in requests {
            let response = handle_single_json(handler, request);
            if let CallResponse::Reply { body, .. } = response {
                responses.push(body);
            }
        }
        if responses.is_empty() {
            return if close {
                closing_no_content_response()
            } else {
                no_content_response()
            };
        }
        // Core: "Batches never throw HTTP errors, they are always just
        // included in HTTP OK responses" (`httprpc.cpp:200-201`). A
        // per-member envelope or dispatch error stays inside the 200 batch.
        return JsonResponse {
            close,
            status: 200,
            reason: reason_for_status(200),
            body: Some(json!(responses)),
        };
    }

    // A top-level value that is neither an object nor an array is Core's
    // `RPC_PARSE_ERROR` "Top-level object parse error" (`httprpc.cpp`, the
    // final `else` of `HTTPReq_JSONRPC`), HTTP 500 under the legacy
    // mapping. Inside a batch the same value is a per-member -32600.
    if !request.is_object() {
        return legacy_error_response(
            &RpcError::TopLevelParse("Top-level object parse error"),
            &Value::new_null(),
        );
    }

    let response = handle_single_json(handler, request);
    let status = response.http_status();
    match response {
        CallResponse::Reply { body, .. } => JsonResponse {
            close,
            status,
            reason: reason_for_status(status),
            body: Some(body),
        },
        CallResponse::Notification => {
            if close {
                closing_no_content_response()
            } else {
                no_content_response()
            }
        }
    }
}

/// Validates one request object's envelope, then dispatches it.
///
/// PRE: `request` is one decoded JSON-RPC request value (not a batch).
/// POST: a reply or notification for that member. A malformed envelope is
///   refused with `-32600` before the method is resolved or executed, using
///   the pinned Core 31.1 rules: the `jsonrpc` field, when present, must be
///   a string and must be `"1.0"` or `"2.0"`; `method` must be present and
///   a string; `params`, when present, must be an array, an object, or
///   `null` (`src/rpc/request.cpp:206-260`). A violation while classifying
///   `jsonrpc` answers in the legacy dialect; a later violation keeps the
///   already-assigned dialect's envelope but still takes the legacy HTTP
///   status, matching Core's outer error path (`src/httprpc.cpp:189-194`).
/// INVARIANT: an envelope error never executes the method, and a
///   notification is only silent when its envelope was valid.
fn handle_single_json(handler: &Handler, request: &Value) -> CallResponse {
    let id = request.get("id").cloned().unwrap_or_else(Value::new_null);
    if !request.is_object() {
        let error = RpcError::InvalidRequest("Invalid Request object");
        let version = JsonRpcVersion::Legacy;
        return CallResponse::envelope_error(version.error_response(&error, &id), version, &error);
    }
    let version = match JsonRpcVersion::classify(request) {
        Ok(version) => version,
        Err(error) => {
            // Core raises -32600 from `JSONRPCRequest::parse`, before the
            // claimed version is trusted, so the reply uses the legacy
            // envelope (`request.cpp:206-224`) while the HTTP status stays
            // the 400 every envelope refusal takes (`httprpc.cpp:41-56`).
            // The error envelope still carries the request's `id`.
            let version = JsonRpcVersion::Legacy;
            return CallResponse::envelope_error(
                version.error_response(&error, &id),
                version,
                &error,
            );
        }
    };
    // Core checks `isNull()` before `isStr()` (`request.cpp:228-232`), so
    // an explicit `"method": null` is "Missing method".
    let Some(method) = request.get("method").filter(|method| !method.is_null()) else {
        let error = RpcError::InvalidRequest("Missing method");
        return CallResponse::envelope_error(version.error_response(&error, &id), version, &error);
    };
    let Some(method) = method.as_str() else {
        let error = RpcError::InvalidRequest("Method must be a string");
        return CallResponse::envelope_error(version.error_response(&error, &id), version, &error);
    };
    let null_params = Value::new_null();
    let params = request.get("params").unwrap_or(&null_params);
    // Core accepts an array or object; `null` (and an absent field) means
    // "no positional parameters". Any other JSON type is -32600.
    if !(params.is_array() || params.is_object() || params.is_null()) {
        let error = RpcError::InvalidRequest("Params must be an array or object");
        return CallResponse::envelope_error(version.error_response(&error, &id), version, &error);
    }
    // Core canonicalizes absent or explicit-null params to an empty array
    // before dispatch, so method defaults apply (`src/rpc/request.cpp:243-248`).
    let empty_params = json!([]);
    let params = if params.is_null() {
        &empty_params
    } else {
        params
    };
    let result = handler.dispatch(method, params);
    if version == JsonRpcVersion::V2 && request.get("id").is_none() {
        return CallResponse::Notification;
    }
    match result {
        Ok(result) => CallResponse::reply(version.success_response(&result, &id), version, None),
        Err(error) => {
            CallResponse::reply(version.error_response(&error, &id), version, Some(&error))
        }
    }
}

fn legacy_error_response(error: &RpcError, id: &Value) -> JsonResponse {
    let version = JsonRpcVersion::Legacy;
    let status = version.error_status_for(error);
    JsonResponse {
        // Undecodable bodies and top-level scalars name no method, so they
        // never close; the flag stays here only because there is no decoded
        // envelope for `handle_decoded_json` to classify.
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

/// A 204 drain that keeps the connection: the drained batch (or
/// notification) named no blocking method.
const fn no_content_response() -> JsonResponse {
    no_content_response_inner(false)
}

/// A 204 drain that also closes: the drained batch (or notification) named
/// a blocking method, so the reserved slot must not survive keep-alive.
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

/// Splits an HTTP request target into its path and optional query string.
fn split_path_query(path: &str) -> (&str, &str) {
    path.split_once('?')
        .map_or((path, ""), |(path, query)| (path, query))
}

/// Listener directories; see `docs/contracts/wallet-facing.md` WF-02.
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
    },
}

impl HttpSurface {
    const fn cors_policy(self) -> CorsPolicy {
        match self {
            Self::EsploraPublic => CorsPolicy::Public {
                methods: PUBLIC_ESPLORA_METHODS,
                headers: PUBLIC_ESPLORA_HEADERS,
                expose: PUBLIC_ESPLORA_EXPOSE_HEADERS,
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

/// Applies the HTTP socket contract: disable Nagle once, before any bytes move.
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

/// Renders one HTTP response head as a string so it can share a single
/// vectored write with its body: the same header bytes the response carries,
/// materialized for the one-syscall emission path.
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
    } = head.cors_policy
    {
        header.push_str("Access-Control-Allow-Origin: *\r\n");
        for (name, values) in [
            ("Access-Control-Allow-Methods", methods),
            ("Access-Control-Allow-Headers", headers),
            ("Access-Control-Expose-Headers", expose),
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
mod tests;
