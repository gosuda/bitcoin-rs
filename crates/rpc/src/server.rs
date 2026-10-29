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
const RESERVED_POOL_DIVISOR: usize = 4;
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) const MAX_BODY_BYTES: usize = 16 * 1_024 * 1_024;

const WRONG_CREDENTIALS_DELAY: Duration = Duration::from_millis(250);

const MAX_DRAIN_BYTES: usize = 64 * 1_024;

const DRAIN_BUDGET: Duration = Duration::from_secs(1);

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
const ACCEPT_SHUTDOWN_CHECK: Duration = Duration::from_millis(20);

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

pub struct RpcServer {
    pub listener: TcpListener,
    pub auth: Arc<Auth>,
    pub handler: Arc<Handler>,
    pub max_connections: usize,
    pub idle_timeout: Duration,
    pub rest_enabled: bool,
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
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn serve_with_shutdown(
        self,
        shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
    ) -> io::Result<()> {
        self.serve_surface_with_shutdown(shutdown, RpcSurface::Shared)
    }

    pub fn serve_surface_with_shutdown(
        self,
        shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
        surface: RpcSurface,
    ) -> io::Result<()> {
        self.serve_accept_loop(&shutdown.into(), surface, mio::net::TcpListener::accept)
    }

    fn serve_accept_loop(
        self,
        shutdown: &bitcoin_rs_chain::LatchReader,
        surface: RpcSurface,
        mut accept: impl FnMut(&mio::net::TcpListener) -> io::Result<(mio::net::TcpStream, SocketAddr)>,
    ) -> io::Result<()> {
        let _stop = RpcStop(Arc::clone(&self.handler));
        self.handler
            .configure_blocking_admission(per_source_limit(self.max_connections));
        let mut readiness = mio::Poll::new()?;
        let listener = self.listener.try_clone()?;
        listener.set_nonblocking(true)?;
        let mut listener = mio::net::TcpListener::from_std(listener);
        readiness
            .registry()
            .register(&mut listener, mio::Token(0), mio::Interest::READABLE)?;
        let mut events = mio::Events::with_capacity(1);
        let active = Arc::new(Mutex::new(ActiveConnections::default()));
        while !shutdown.is_triggered() {
            match accept(&listener) {
                Ok((stream, addr)) => {
                    let stream: TcpStream = stream.into();
                    if let Err(error) = stream
                        .set_nonblocking(false)
                        .and_then(|()| self.handle_accept(&active, stream, addr.ip(), surface))
                    {
                        debug!(%error, "rpc connection setup failed");
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    while !shutdown.is_triggered() {
                        match readiness.poll(&mut events, Some(ACCEPT_SHUTDOWN_CHECK)) {
                            Ok(()) if !events.is_empty() => break,
                            Ok(()) => {}
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                            Err(error) => return Err(error),
                        }
                    }
                }
                Err(error) => match error.kind() {
                    io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted => {
                        debug!(%error, "rpc accept interrupted or connection aborted");
                    }
                    io::ErrorKind::InvalidInput | io::ErrorKind::NotConnected => return Err(error),
                    _ => {
                        warn!(%error, "rpc accept failed; retrying after backoff");
                        thread::sleep(ACCEPT_ERROR_BACKOFF);
                    }
                },
            }
        }
        Ok(())
    }

    fn handle_accept(
        &self,
        active: &Arc<Mutex<ActiveConnections>>,
        stream: TcpStream,
        peer: IpAddr,
        surface: RpcSurface,
    ) -> io::Result<()> {
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

struct RequestDeadlineStream {
    stream: TcpStream,
    idle_timeout: Duration,
    deadline: Instant,
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
        if !surface.allows(&route) {
            write_not_found(reader.get_mut().socket_mut(), false)?;
            return Ok(());
        }
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
    if head.content_length == 0 {
        return Ok(());
    }
    drain_request(reader, head.content_length);
    Ok(())
}

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

struct HttpRequest {
    method: String,
    path: String,
    keep_alive: bool,
    body: Vec<u8>,
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
    Ok((line, read))
}

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

struct RequestHead {
    method: String,
    path: String,
    authorization: Option<String>,
    keep_alive: bool,
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
    /// `RPC_INVALID_REQUEST` maps to 400 and `RPC_METHOD_NOT_FOUND` to 404;
    /// every other code keeps 500.
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
        error_code: Option<i64>,
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

    handle_decoded_json(handler, &request)
}

fn handle_decoded_json(handler: &Handler, request: &Value) -> JsonResponse {
    let close = request.as_array().map_or_else(
        || crate::registry::blocking_request(request),
        |requests| requests.iter().any(crate::registry::blocking_request),
    );
    if let Some(requests) = request.as_array() {
        if requests.is_empty() {
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
        return JsonResponse {
            close,
            status: 200,
            reason: reason_for_status(200),
            body: Some(json!(responses)),
        };
    }

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
            let version = JsonRpcVersion::Legacy;
            return CallResponse::envelope_error(
                version.error_response(&error, &id),
                version,
                &error,
            );
        }
    };
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
    if !(params.is_array() || params.is_object() || params.is_null()) {
        let error = RpcError::InvalidRequest("Params must be an array or object");
        return CallResponse::envelope_error(version.error_response(&error, &id), version, &error);
    }
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
