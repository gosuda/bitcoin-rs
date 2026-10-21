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

const POLL_INTERVAL: core::time::Duration = core::time::Duration::from_millis(100);

const PUBLIC_ESPLORA_METHODS: &[&str] = &["GET", "POST", "OPTIONS"];

const PUBLIC_ESPLORA_HEADERS: &[&str] = &["Content-Type"];

const PUBLIC_ESPLORA_EXPOSE_HEADERS: &[&str] = &["X-Total-Results"];

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
        let shutdown = shutdown.into();
        let _stop = RpcStop(Arc::clone(&self.handler));
        self.handler
            .configure_blocking_admission(per_source_limit(self.max_connections));
        self.listener.set_nonblocking(true)?;
        let active = Arc::new(Mutex::new(ActiveConnections::default()));
        while !shutdown.is_triggered() {
            match self.listener.accept() {
                Ok((stream, addr)) => {
                    stream.set_nonblocking(false)?;
                    if let Err(error) = self.handle_accept(&active, stream, addr.ip()) {
                        debug!(%error, "rpc connection setup failed");
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(POLL_INTERVAL);
                }
                Err(error) => return Err(error),
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
            write_status(&mut stream, 503, "Service Unavailable", b"busy", false)?;
            return Ok(());
        }

        let permit = ConnectionPermit {
            active: Arc::clone(active),
            peer,
        };
        let auth = Arc::clone(&self.auth);
        let handler = Arc::clone(&self.handler);
        let rest_enabled = self.rest_enabled;
        let idle_timeout = self.idle_timeout;
        thread::Builder::new()
            .name("rpc-connection".to_owned())
            .spawn(move || {
                let _permit = permit;
                if let Err(error) =
                    serve_connection(stream, &auth, &handler, rest_enabled, idle_timeout)
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
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.lock().release(self.peer);
    }
}

struct RpcStop(Arc<Handler>);

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
) -> io::Result<()> {
    stream.set_write_timeout(Some(idle_timeout))?;
    let mut reader = BufReader::new(RequestDeadlineStream::new(stream, idle_timeout));
    loop {
        if handler.is_stopping() {
            return Ok(());
        }
        // Waiting for the next request keeps the configured idle timeout;
        // `read_request` starts the head budget at the request's first byte.
        reader.get_mut().reset_deadline(idle_timeout);
        let request = match read_request(&mut reader, REQUEST_HEAD_TIMEOUT, REQUEST_BODY_TIMEOUT) {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(()),
            Err(RequestReadError::RestBodyTooLarge) => {
                let response = if rest_enabled {
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
                // This body is not a Core-parity envelope: keep the
                // historical `invalid request: ` prefix that the verbatim
                // `InvalidRequest` payload no longer adds.
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
        if handler.is_stopping() {
            return Ok(());
        }
        let keep_alive = request.keep_alive;
        if dispatch_http_request(
            reader.get_mut().socket_mut(),
            &request,
            auth,
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

fn dispatch_http_request(
    stream: &mut TcpStream,
    request: &HttpRequest,
    auth: &Auth,
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
        HttpRoute::JsonRpc => {
            if !auth.validate_header(request.authorization.as_deref()) {
                write_status(stream, 401, "Unauthorized", b"unauthorized", false)?;
                return Ok(true);
            }
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

struct HttpRequest {
    method: String,
    path: String,
    authorization: Option<String>,
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

fn read_request(
    reader: &mut BufReader<RequestDeadlineStream>,
    head_timeout: Duration,
    body_timeout: Duration,
) -> Result<Option<HttpRequest>, RequestReadError> {
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
    reader.get_mut().reset_deadline(body_timeout);
    let mut body = Vec::new();
    read_body(reader, content_length, &mut body)?;
    Ok(Some(HttpRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        authorization,
        keep_alive,
        body,
    }))
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
    const fn error_status_for_code(self, code: i64) -> u16 {
        match self {
            Self::Legacy => match code {
                RpcError::INVALID_REQUEST => 400,
                RpcError::METHOD_NOT_FOUND => 404,
                _ => 500,
            },
            Self::V2 => 200,
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
            Self::Reply {
                envelope_error: true,
                ..
            } => 400,
            Self::Reply {
                version,
                error_code: Some(code),
                ..
            } => version.error_status_for_code(*code),
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

    let close = request.as_array().map_or_else(
        || crate::registry::blocking_request(&request),
        |requests| requests.iter().any(crate::registry::blocking_request),
    );
    let mut response = handle_decoded_json(handler, &request);
    // A rejected long call must not retain the reserved ordinary slot through
    // keep-alive. Batch/notification classification uses the same registry.
    response.close = close;
    response
}

fn handle_decoded_json(handler: &Handler, request: &Value) -> JsonResponse {
    if let Some(requests) = request.as_array() {
        if requests.is_empty() {
            // Core: an empty batch still answers HTTP 200 with an empty
            // result array (`httprpc.cpp` runs the batch reply path, which
            // produces `[]` for no members).
            return JsonResponse {
                close: false,
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
            return no_content_response();
        }
        // Core: "Batches never throw HTTP errors, they are always just
        // included in HTTP OK responses" (`httprpc.cpp:200-201`). A
        // per-member envelope or dispatch error stays inside the 200 batch.
        return JsonResponse {
            close: false,
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
            close: false,
            status,
            reason: reason_for_status(status),
            body: Some(body),
        },
        CallResponse::Notification => no_content_response(),
    }
}

/// Validates one request object's envelope, then dispatches it.
///
/// PRE: `request` is one decoded JSON-RPC request value (not a batch).
/// POST: a reply or notification for that member. A malformed envelope is
///   refused with `-32600` before the method is resolved or executed, using
///   the pinned Core 31.1 rules: the `jsonrpc` field, when present, must be
///   a string and must be `"1.0"` or `"2.0"`; `params`, when present, must
///   be an array, an object, or `null` (`src/rpc/request.cpp:206-260`).
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
    JsonResponse {
        close: false,
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
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    use crate::context::Context;
    use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};

    /// Exercises HTTP demux and framing, including refusal before a declared
    /// oversized body is uploaded. No Content-Length-sized allocation is needed.
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
            )
        });
        client.write_all(request)?;
        let mut response = Vec::new();
        client.read_to_end(&mut response)?;
        let _result = join.join().expect("server thread");
        Ok(response)
    }

    /// A peer continuously writes a byte before the idle timeout expires.
    /// Request-line, header, and body parsing must still expire promptly.
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

        let mut reader = BufReader::new(RequestDeadlineStream::new(server, Duration::from_secs(3)));
        reader.get_mut().reset_deadline(Duration::from_millis(200));
        let start = Instant::now();
        let result = read_request(
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

    /// Waiting for the next keep-alive request runs under the idle deadline;
    /// the shorter head budget starts only when the request begins.
    #[test]
    fn keep_alive_wait_is_not_bounded_by_the_head_budget() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        let (server, _) = listener.accept()?;
        let writer = thread::spawn(move || -> io::Result<()> {
            thread::sleep(Duration::from_millis(300));
            client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        });

        let mut reader = BufReader::new(RequestDeadlineStream::new(server, Duration::from_secs(3)));
        reader.get_mut().reset_deadline(Duration::from_secs(3));
        let result = read_request(
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

    /// One source filling the blocking quota still has a connection left in
    /// its own share for an ordinary call such as status or abort.
    #[test]
    fn blocking_quota_leaves_the_busiest_source_an_ordinary_slot() {
        for max_connections in [1, 2, 4, 5, 128] {
            let handler = Handler::new(Arc::new(Context::new()));
            handler.configure_blocking_admission(per_source_limit(max_connections));
            let held: Vec<_> = core::iter::from_fn(|| handler.reserve_blocking_request().ok())
                .take(max_connections)
                .collect();
            assert_eq!(
                held.len() + 1,
                per_source_limit(max_connections),
                "pool {max_connections}"
            );
        }
    }

    #[test]
    fn connection_admission_reserves_slots_for_other_peers() {
        // Loopback gets no special treatment: it is one source like any other.
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

        // Below four workers no share is kept: one client can hold a blocking
        // call and still reach the ordinary slot the quota leaves it.
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
            // Deliberately send no body: receiving an answer proves the cap
            // was enforced before the body read.
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
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || server.serve_with_shutdown(shutdown_clone));
        std::thread::sleep(core::time::Duration::from_millis(150));
        shutdown.store(true, Ordering::Release);
        handle.join().expect("join serve thread")
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

    /// WF-02: a body-carrying POST without Content-Length is a framing
    /// error, not an empty JSON-RPC request.
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
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || server.serve_with_shutdown(shutdown_clone));

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
        // The connection-level framing error surfaces as a bad-request-class
        // response before any JSON-RPC authentication or parsing runs.
        assert!(
            (400..500).contains(&code) && code != 401,
            "expected a framing error status, got {code}"
        );

        shutdown.store(true, Ordering::SeqCst);
        drop(handle.join().expect("server thread"));
        Ok(())
    }

    /// Runs `read_request` over a loopback socket fed `request` in writes of
    /// at most `chunk` bytes, after which the client closes its write half.
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
        let mut reader = BufReader::new(RequestDeadlineStream::new(server, Duration::from_secs(3)));
        let result = read_request(&mut reader, Duration::from_secs(3), Duration::from_secs(3));
        // Close the server end first: after a failed read, a writer blocked on
        // a full socket buffer would otherwise never return. The writer's
        // resulting error must not hide the read's.
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

    /// A body declared at the size cap but cut short is a framing error, as
    /// before.
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

    /// The body buffer tracks the bytes that arrived, not the declared length.
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

    /// A body received in full keeps a buffer no larger than its declared
    /// length, including at the size cap and at lengths that are not powers
    /// of two.
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

    /// The request-head budget must be enforced while bytes arrive, even if
    /// the peer never sends a newline or closes its write half.
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
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || server.serve_with_shutdown(shutdown_clone));

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

        shutdown.store(true, Ordering::Release);
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

    // CONTRACT: docs/contracts/external-api.md#API-02 — the envelope rules
    // follow the pinned Core 31.1 parser (`src/rpc/request.cpp:206-260`) and
    // its legacy HTTP mapping (`src/httprpc.cpp:41-56`).
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
        // Core keeps the historical `{"jsonrpc":"1.0"}` form as legacy
        // (`request.cpp:216-224`); it must not become an invalid request.
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

            // Core answers an envelope refusal with HTTP 400 in either
            // dialect (`httprpc.cpp`); the body keeps the accepted v2 shape.
            assert_eq!(response.status, 400, "v2 envelope refusal maps to HTTP 400");
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

    #[test]
    fn a_rejected_envelope_never_dispatches_the_method() {
        // Observable dispatch probe: `getrpcinfo` fails with an internal
        // error when no debug log path is configured, so a successful-looking
        // reply would prove execution. A malformed envelope must produce the
        // envelope error instead.
        let handler = Handler::new(Arc::new(Context::new()));
        let executed = handle_json(
            &handler,
            br#"{"jsonrpc":"2.0","id":1,"method":"getrpcinfo","params":[]}"#,
        );
        let executed_body = executed.body.expect("valid request replies");
        assert_eq!(
            executed_body
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_i64),
            Some(-32603),
            "fixture: the probe method is dispatched and fails on its own: {executed_body:?}"
        );

        for request in [
            br#"{"jsonrpc":"9.0","id":1,"method":"getrpcinfo","params":[]}"#.as_slice(),
            br#"{"jsonrpc":2,"id":1,"method":"getrpcinfo","params":[]}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"method":"getrpcinfo","params":7}"#.as_slice(),
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
        }
    }

    #[test]
    fn an_empty_batch_answers_an_empty_ok_batch() {
        // Core's batch reply path produces an empty array for an empty
        // batch (`httprpc.cpp`): HTTP 200 with `[]`.
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(&handler, b"[]");
        let body = response.body.expect("empty batch replies");

        assert_eq!(response.status, 200);
        assert_eq!(body, json!([]), "an empty batch answers []: {body:?}");
    }

    #[test]
    fn a_top_level_scalar_is_a_parse_error() {
        // Core's final `else` in `HTTPReq_JSONRPC` answers `RPC_PARSE_ERROR`
        // (-32700) "Top-level object parse error" at HTTP 500 with a null id.
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
        // parse() has already accepted `"2.0"` when method/params validation
        // throws, so the body keeps the v2 envelope while the status is the
        // 400 every envelope refusal takes (`httprpc.cpp`). `"method":null`
        // is "Missing method": Core checks `isNull()` before `isStr()`.
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
        // A non-empty batch whose members are all valid v2 notifications has
        // no reply rows, so Core answers HTTP 204 (`httprpc.cpp:219-227`).
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
        // A legacy request whose method is not a string is a -32600, which
        // Core answers with HTTP 400 (`httprpc.cpp:47-53`).
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(&handler, br#"{"id":1,"method":7,"params":[]}"#);
        assert_eq!(response.status, 400, "legacy -32600 maps to HTTP 400");
    }

    #[test]
    fn legacy_method_not_found_maps_to_http_404() {
        // Core maps RPC_METHOD_NOT_FOUND to HTTP 404 for legacy requests
        // (`httprpc.cpp:51-53`); this previously answered 500.
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(&handler, br#"{"id":1,"method":"missing","params":[]}"#);
        assert_eq!(response.status, 404, "legacy -32601 maps to HTTP 404");
    }

    #[test]
    fn legacy_other_errors_keep_http_500() {
        // Everything except -32600 and -32601 stays 500 for legacy requests.
        let handler = Handler::new(Arc::new(Context::new()));
        let response = handle_json(&handler, br#"{"id":1,"method":"getblock","params":[]}"#);
        assert_eq!(response.status, 500, "legacy -32602 keeps HTTP 500");
    }

    #[test]
    fn json_rpc_2_dispatch_errors_still_answer_http_200() {
        // Core keeps *dispatch* errors inside HTTP 200 for a v2 request
        // (`httprpc.cpp:118-124`); only envelope failures, which happen
        // before the version is trusted, take the legacy HTTP status.
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
        // A malformed envelope is refused before the claimed version is
        // trusted, so it takes the legacy HTTP mapping and envelope shape
        // (`request.cpp:206-224`, `httprpc.cpp:41-56`).
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
    fn batch_members_keep_per_member_envelope_dialect() {
        // Batch members are parsed independently by Core
        // (`httprpc.cpp:200-215`), so a v2 member and a legacy member in one
        // batch keep their own envelopes even when a sibling is malformed.
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
        // A rejected envelope must not run, so a notification cannot silently
        // cause work: the response is an error, not the 204 a notification
        // would produce.
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
}
