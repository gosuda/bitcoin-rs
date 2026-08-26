use alloc::sync::Arc;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, Instant};

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::Mutex;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};
use tracing::{debug, warn};

use crate::auth::{Auth, WWW_AUTHENTICATE};
use crate::error::RpcError;
use crate::handlers::Handler;

const MAX_HEADER_BYTES: usize = 16 * 1_024;
const MAX_BODY_BYTES: usize = 16 * 1_024 * 1_024;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Delay before answering present-but-wrong credentials, mirroring Core's
/// brute-force deterrence in `HTTPReq_JSONRPC`.
const AUTH_FAILURE_DELAY: Duration = Duration::from_millis(250);
/// Body of the 405 reply, exactly as Core's RPC handler writes it.
const METHOD_NOT_ALLOWED_BODY: &[u8] = b"JSONRPC server handles only POST requests";
/// Initial warmup status, matching Core's `rpcWarmupStatus` initializer.
const WARMUP_DEFAULT_STATUS: &str = "RPC server started";

/// Synchronous HTTP/1.1 JSON-RPC server.
pub struct RpcServer {
    /// Bound TCP listener.
    pub listener: TcpListener,
    /// Shared authentication policy.
    pub auth: Arc<Auth>,
    /// Shared JSON-RPC handler.
    pub handler: Arc<Handler>,
    /// Shared request lifecycle observed by every worker and by `getrpcinfo`.
    pub lifecycle: Arc<RpcLifecycle>,
    /// Maximum concurrent worker connections.
    pub max_connections: usize,
    /// Idle read timeout for each connection.
    pub idle_timeout: Duration,
    /// Whether Bitcoin Core-compatible REST routes are enabled.
    pub rest_enabled: bool,
}

impl RpcServer {
    /// Binds a new RPC server that shares `lifecycle` with Context / getrpcinfo.
    pub fn bind<A: ToSocketAddrs>(
        address: A,
        auth: Arc<Auth>,
        handler: Arc<Handler>,
        lifecycle: Arc<RpcLifecycle>,
        max_connections: usize,
        idle_timeout: Duration,
        rest_enabled: bool,
    ) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(address)?,
            auth,
            handler,
            lifecycle,
            max_connections,
            idle_timeout,
            rest_enabled,
        })
    }

    /// Returns the local socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Runs the accept loop. Each accepted connection is handled by one bounded worker thread.
    ///
    /// One [`RpcLifecycle`] is shared by every worker of this loop, so warmup,
    /// shutdown observation, and in-flight command tracking are owned in one
    /// place. The server is constructed with its node state fully injected, so
    /// serving starts with warmup already finished (Core's post-
    /// `SetRPCWarmupFinished` state); `RpcLifecycle` still exposes Core's
    /// warmup transitions for owners that sequence startup themselves.
    pub fn serve(self) -> io::Result<()> {
        let active = Arc::new(Mutex::new(0_usize));
        for stream in self.listener.incoming() {
            self.handle_accept(&active, stream?)?;
        }
        Ok(())
    }

    /// Runs the accept loop until `shutdown` is set to `true`.
    ///
    /// Polls non-blocking accept on a fixed cadence so the loop can observe
    /// shutdown without parking on an open socket. Each accepted connection
    /// is restored to blocking mode and handed to a bounded worker thread,
    /// preserving the configured `idle_timeout` per connection. The shared
    /// lifecycle observes the same flag, so commands dispatched by draining
    /// keep-alive workers after shutdown are rejected with Core's
    /// "Shutting down" error instead of executing against a stopped node.
    pub fn serve_with_shutdown(self) -> io::Result<()> {
        self.listener.set_nonblocking(true)?;
        let active = Arc::new(Mutex::new(0_usize));
        while !self.lifecycle.is_shutdown() {
            match self.listener.accept() {
                Ok((stream, _addr)) => {
                    stream.set_nonblocking(false)?;
                    self.handle_accept(&active, stream)?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(POLL_INTERVAL);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn handle_accept(&self, active: &Arc<Mutex<usize>>, mut stream: TcpStream) -> io::Result<()> {
        let should_accept = {
            let mut count = active.lock();
            if *count >= self.max_connections {
                false
            } else {
                *count += 1;
                true
            }
        };
        if !should_accept {
            write_status(&mut stream, 503, "Service Unavailable", b"busy", false)?;
            return Ok(());
        }

        let auth = Arc::clone(&self.auth);
        let handler = Arc::clone(&self.handler);
        let lifecycle = Arc::clone(&self.lifecycle);
        let rest_enabled = self.rest_enabled;
        let active = Arc::clone(active);
        let idle_timeout = self.idle_timeout;
        thread::spawn(move || {
            if let Err(error) = serve_connection(
                stream,
                &auth,
                &handler,
                &lifecycle,
                rest_enabled,
                idle_timeout,
            ) {
                debug!(%error, "rpc connection closed with error");
            }
            let mut count = active.lock();
            *count = count.saturating_sub(1);
        });
        Ok(())
    }
}

/// Core `RPCCommandExecutionInfo`: one in-flight command record.
struct CommandExecution {
    /// Monotonic identity used to erase exactly this entry on drop.
    id: u64,
    method: String,
    start: Instant,
}

/// Core's warmup guard fields (`fRPCInWarmup` plus `rpcWarmupStatus`).
struct Warmup {
    in_warmup: bool,
    status: String,
}

/// Source of node-owned warning messages projected by RPC.
///
/// Implementations return warnings in report order without copying a second
/// transport-owned registry.
pub trait RpcWarnings: Send + Sync {
    /// Active warning messages in report order.
    fn messages(&self) -> Vec<String>;
}

/// Shared request lifecycle state for one RPC serve loop.
///
/// Owns warmup, shutdown observation, authoritative process uptime, warning
/// projection, and in-flight command tracking for `getrpcinfo`.
pub struct RpcLifecycle {
    /// Shutdown flag; commands observed after it is set are rejected.
    shutdown: Arc<AtomicBool>,
    /// Node-owned wake invoked after the first transition to shutdown.
    shutdown_notify: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Process start instant recorded before the serve loop begins work.
    process_start: Instant,
    warmup: Mutex<Warmup>,
    active_commands: Mutex<Vec<CommandExecution>>,
    next_command_id: AtomicU64,
    warnings: Option<Arc<dyn RpcWarnings>>,
}

impl RpcLifecycle {
    /// Builds lifecycle state for a serve loop that observes `shutdown`.
    ///
    /// Records process start immediately. Warmup starts finished because this
    /// server is constructed with fully injected node state; owners sequencing
    /// a slower startup call [`Self::set_warmup_starting`] before serving.
    #[must_use]
    pub fn new(shutdown: Arc<AtomicBool>, process_start: Instant) -> Self {
        Self {
            shutdown,
            shutdown_notify: None,
            process_start,
            warmup: Mutex::new(Warmup {
                in_warmup: false,
                status: WARMUP_DEFAULT_STATUS.to_owned(),
            }),
            active_commands: Mutex::new(Vec::new()),
            next_command_id: AtomicU64::new(0),
            warnings: None,
        }
    }

    /// Seconds-joined warning text from the node-owned registry, when attached.
    #[must_use]
    pub fn warnings_text(&self) -> String {
        self.warnings
            .as_ref()
            .map(|warnings| warnings.messages().join("; "))
            .unwrap_or_default()
    }

    /// Attaches the node-owned warning registry projected by RPC info methods.
    #[must_use]
    pub fn with_warnings(mut self, warnings: Arc<dyn RpcWarnings>) -> Self {
        self.warnings = Some(warnings);
        self
    }

    /// Attaches the node-owned wake for the process-wide shutdown broadcast.
    #[must_use]
    pub fn with_shutdown_notifier(mut self, notify: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.shutdown_notify = Some(notify);
        self
    }

    /// Shared shutdown flag observed by the serve loop and mining waiters.
    #[must_use]
    pub fn shutdown_flag(&self) -> &Arc<AtomicBool> {
        &self.shutdown
    }

    /// Returns whether shutdown has been requested.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Requests process shutdown and wakes node-owned waiters exactly once.
    pub fn request_shutdown(&self) {
        if self
            .shutdown
            .compare_exchange(false, true, Ordering::Release, Ordering::Acquire)
            .is_ok()
            && let Some(notify) = &self.shutdown_notify
        {
            notify();
        }
    }

    /// Seconds since process start was recorded.
    #[must_use]
    pub fn uptime_secs(&self) -> u64 {
        self.process_start.elapsed().as_secs()
    }

    /// Core `SetRPCWarmupStatus`: updates the message reported by `-28`.
    pub fn set_warmup_status(&self, status: impl Into<String>) {
        self.warmup.lock().status = status.into();
    }

    /// Core `SetRPCWarmupStarting`: rejects commands with `-28`.
    pub fn set_warmup_starting(&self) {
        self.warmup.lock().in_warmup = true;
    }

    /// Core `SetRPCWarmupFinished` (which asserts warmup was active).
    pub fn set_warmup_finished(&self) {
        let mut warmup = self.warmup.lock();
        debug_assert!(warmup.in_warmup, "RPC warmup was not started");
        warmup.in_warmup = false;
    }

    /// Rejects work before method lookup, in Core's order: the warmup guard of
    /// `CRPCTable::execute` first, then the `RpcInterruptionPoint` running
    /// check.
    fn readiness(&self) -> Result<(), RpcError> {
        {
            let warmup = self.warmup.lock();
            if warmup.in_warmup {
                return Err(RpcError::InWarmup(warmup.status.clone()));
            }
        }
        if self.shutdown.load(Ordering::Acquire) {
            return Err(RpcError::ClientNotConnected);
        }
        Ok(())
    }

    /// Executes one command with authoritative in-flight registration.
    ///
    /// Registration wraps the whole dispatch, so a method-lookup miss inserts
    /// and immediately removes its entry, exactly as Core's per-command guard
    /// bookends `ExecuteCommand`; only commands that are actually executing
    /// stay observable.
    fn execute(&self, handler: &Handler, method: &str, params: &Value) -> Result<Value, RpcError> {
        self.readiness()?;
        let _tracked = self.track_command(method);
        handler.dispatch(method, params)
    }

    /// Inserts the command into the in-flight list; removal happens on drop.
    ///
    /// Public so `getrpcinfo` tests and any shared `Arc<RpcLifecycle>` holder can
    /// register without inventing a second tracker. The serve loop still tracks
    /// exclusively through [`Self::execute`].
    #[must_use]
    pub fn track_command(&self, method: &str) -> TrackedCommand<'_> {
        let id = self.next_command_id.fetch_add(1, Ordering::Relaxed);
        self.active_commands.lock().push(CommandExecution {
            id,
            method: method.to_owned(),
            start: Instant::now(),
        });
        TrackedCommand {
            lifecycle: self,
            id,
        }
    }

    /// Snapshot for `getrpcinfo`: `(method, duration in microseconds)` pairs
    /// in registration order, matching Core's
    /// `[{"method":…,"duration":…}]` result member.
    #[must_use]
    pub fn active_commands(&self) -> Vec<(String, u64)> {
        let now = Instant::now();
        self.active_commands
            .lock()
            .iter()
            .map(|execution| {
                (
                    execution.method.clone(),
                    u64::try_from(now.duration_since(execution.start).as_micros())
                        .unwrap_or(u64::MAX),
                )
            })
            .collect()
    }
}

/// RAII in-flight registration, Core's `RPCCommandExecution` guard.
pub struct TrackedCommand<'a> {
    lifecycle: &'a RpcLifecycle,
    id: u64,
}

impl Drop for TrackedCommand<'_> {
    fn drop(&mut self) {
        // Removes exactly this entry on every terminal path: success, handler
        // error, and shutdown rejection alike.
        self.lifecycle
            .active_commands
            .lock()
            .retain(|execution| execution.id != self.id);
    }
}

fn serve_connection(
    stream: TcpStream,
    auth: &Auth,
    handler: &Handler,
    lifecycle: &RpcLifecycle,
    rest_enabled: bool,
    idle_timeout: Duration,
) -> io::Result<()> {
    stream.set_read_timeout(Some(idle_timeout))?;
    stream.set_write_timeout(Some(idle_timeout))?;
    let mut reader = BufReader::new(stream);
    loop {
        let request = match read_request(&mut reader) {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(()),
            Err(error) => {
                let rpc_error = RpcError::InvalidRequest("malformed http request");
                let response =
                    JsonRpcVersion::Legacy.error_response(&rpc_error, Some(&Value::new_null()));
                write_json(reader.get_mut(), 400, "Bad Request", &response, false)?;
                return Err(error);
            }
        };
        let keep_alive = request.keep_alive;

        let (path, query) = split_path_query(&request.path);
        if path.starts_with("/rest/") && matches!(request.method.as_str(), "GET" | "HEAD") {
            let response = crate::rest::route_method(
                handler.context(),
                path,
                query,
                rest_enabled,
                &request.method,
            );
            write_rest_response(reader.get_mut(), &response, keep_alive)?;
            if !keep_alive {
                return Ok(());
            }
            continue;
        }

        let internal_route = path == "/internal" || path.starts_with("/internal/");
        if internal_route
            && matches!(request.method.as_str(), "GET" | "POST")
            && !auth.validate_header(request.authorization.as_deref())
        {
            if request.authorization.is_some() {
                // Core delays the reply only for present-but-wrong
                // credentials, never for a missing header.
                thread::sleep(AUTH_FAILURE_DELAY);
            }
            write_unauthorized(reader.get_mut())?;
            return Ok(());
        }

        if request.method == "GET" {
            let response = crate::esplora::route(handler, path, query);
            write_response(reader.get_mut(), &response, keep_alive)?;
            if !keep_alive {
                return Ok(());
            }
            continue;
        }

        if request.method != "POST" {
            // Core's RPC handler answers every non-POST method with 405.
            write_status(
                reader.get_mut(),
                405,
                "Method Not Allowed",
                METHOD_NOT_ALLOWED_BODY,
                keep_alive,
            )?;
            if !keep_alive {
                return Ok(());
            }
            continue;
        }

        if let Some(response) = crate::esplora::route_post(handler, &request.path, &request.body) {
            write_response(reader.get_mut(), &response, keep_alive)?;
            if !keep_alive {
                return Ok(());
            }
            continue;
        }

        if !auth.validate_header(request.authorization.as_deref()) {
            if request.authorization.is_some() {
                // Core delays the reply only for present-but-wrong
                // credentials, never for a missing header.
                thread::sleep(AUTH_FAILURE_DELAY);
            }
            write_unauthorized(reader.get_mut())?;
            return Ok(());
        }

        let response = handle_json(lifecycle, handler, &request.body);
        if let Some(body) = response.body.as_ref() {
            write_json(
                reader.get_mut(),
                response.status,
                response.reason,
                body,
                keep_alive,
            )?;
        } else {
            write_status(reader.get_mut(), 204, "No Content", b"", keep_alive)?;
        }
        if !keep_alive {
            return Ok(());
        }
    }
}

struct HttpRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    keep_alive: bool,
    body: Vec<u8>,
}

fn read_request(reader: &mut BufReader<TcpStream>) -> io::Result<Option<HttpRequest>> {
    let mut request_line = String::new();
    let bytes = reader.read_line(&mut request_line)?;
    if bytes == 0 {
        return Ok(None);
    }
    if !request_line.ends_with("\r\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid request line",
        ));
    }

    let request_target = request_line.trim_end_matches(['\r', '\n']);
    let mut request_parts = request_target.split_whitespace();
    let Some(method) = request_parts.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid request line",
        ));
    };
    let Some(path) = request_parts.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid request line",
        ));
    };
    let mut header_bytes = request_line.len();
    let mut content_length = None;
    let mut authorization = None;
    let mut keep_alive = false;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "headers ended early",
            ));
        }
        header_bytes = header_bytes.saturating_add(line.len());
        if header_bytes > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
        if line == "\r\n" {
            break;
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
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("connection") {
            keep_alive = value.eq_ignore_ascii_case("keep-alive");
        }
    }

    // Any method token is framed here; routing decides GET, POST, and the
    // 405 fallback, so unsupported methods still consume their declared body
    // before the connection continues.
    let content_length = match content_length {
        Some(length) => length,
        None if method != "POST" => 0,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing content-length",
            ));
        }
    };
    let mut body = vec![0_u8; content_length];
    reader.read_exact(&mut body)?;
    Ok(Some(HttpRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        authorization,
        keep_alive,
        body,
    }))
}

struct JsonResponse {
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
    /// Core `JSONRPCReplyObj`: v1 keeps a null counterpart field, v2 omits it,
    /// and the `id` member is emitted only when the request carried one.
    fn reply(self, outcome: Result<&Value, &RpcError>, id: Option<&Value>) -> Value {
        let mut reply = match (self, outcome) {
            (Self::Legacy, Ok(result)) => json!({"result": result, "error": null}),
            (Self::Legacy, Err(error)) => {
                json!({"result": null, "error": error_object(error)})
            }
            (Self::V2, Ok(result)) => json!({"jsonrpc": "2.0", "result": result}),
            (Self::V2, Err(error)) => {
                json!({"jsonrpc": "2.0", "error": error_object(error)})
            }
        };
        if let Some(id) = id {
            reply.insert("id", id.clone());
        }
        reply
    }

    fn success_response(self, result: &Value, id: Option<&Value>) -> Value {
        self.reply(Ok(result), id)
    }

    fn error_response(self, error: &RpcError, id: Option<&Value>) -> Value {
        self.reply(Err(error), id)
    }

    /// Core's error status selection: `JSONErrorReply` maps invalid requests
    /// to 400 regardless of version (envelope failures throw before v2 error
    /// catching) and legacy method-not-found to 404, while v2 execution errors
    /// stay HTTP 200 and legacy execution errors stay 500.
    fn error_status(self, error: &RpcError) -> u16 {
        if error.code() == RpcError::INVALID_REQUEST {
            return 400;
        }
        match self {
            Self::Legacy if error.code() == RpcError::METHOD_NOT_FOUND => 404,
            Self::Legacy => 500,
            Self::V2 => 200,
        }
    }
}

/// Core `JSONRPCError`: exactly `{code, message}` with no `data` member.
fn error_object(error: &RpcError) -> Value {
    json!({"code": error.code(), "message": error.wire_message()})
}

/// A parsed JSON-RPC request envelope, Core `JSONRPCRequest::parse`.
struct ParsedRequest {
    version: JsonRpcVersion,
    /// `Some(null)` distinguishes an explicit null id from an absent id.
    id: Option<Value>,
    method: String,
    /// Normalized to an empty array when absent or null, as Core does.
    params: Value,
}

/// Envelope rejection carrying the reply context parsed so far: Core parses
/// the id first, then the version, so rejections carry both partials.
struct RequestError {
    error: RpcError,
    version: JsonRpcVersion,
    id: Option<Value>,
}

/// Core `JSONRPCRequest::parse`: object shape, id presence, exact `jsonrpc`
/// version rules, string method, and array/object/null params.
fn parse_envelope(request: &Value) -> Result<ParsedRequest, RequestError> {
    if !request.is_object() {
        return Err(RequestError {
            error: RpcError::InvalidRequest("Invalid Request object"),
            version: JsonRpcVersion::Legacy,
            id: Some(Value::new_null()),
        });
    }
    let id = request.get("id").cloned();
    let mut version = JsonRpcVersion::Legacy;
    if let Some(jsonrpc) = request.get("jsonrpc").filter(|value| !value.is_null()) {
        let Some(spec) = jsonrpc.as_str() else {
            return Err(RequestError {
                error: RpcError::InvalidRequest("jsonrpc field must be a string"),
                version,
                id,
            });
        };
        version = match spec {
            // Core keeps {"jsonrpc":"1.0"} requests in the legacy protocol
            // and rejects every other version string.
            "1.0" => JsonRpcVersion::Legacy,
            "2.0" => JsonRpcVersion::V2,
            _ => {
                return Err(RequestError {
                    error: RpcError::InvalidRequest("JSON-RPC version not supported"),
                    version,
                    id,
                });
            }
        };
    }
    let Some(method_value) = request.get("method").filter(|value| !value.is_null()) else {
        return Err(RequestError {
            error: RpcError::InvalidRequest("Missing method"),
            version,
            id,
        });
    };
    let Some(method) = method_value.as_str() else {
        return Err(RequestError {
            error: RpcError::InvalidRequest("Method must be a string"),
            version,
            id,
        });
    };
    let params = match request.get("params") {
        Some(params) if params.is_array() || params.is_object() => params.clone(),
        Some(params) if params.is_null() => json!([]),
        None => json!([]),
        Some(_) => {
            return Err(RequestError {
                error: RpcError::InvalidRequest("Params must be an array or object"),
                version,
                id,
            });
        }
    };
    Ok(ParsedRequest {
        version,
        id,
        method: method.to_owned(),
        params,
    })
}

enum CallOutcome {
    Reply {
        body: Value,
        version: JsonRpcVersion,
        error: Option<RpcError>,
    },
    Notification,
}

fn handle_json(lifecycle: &RpcLifecycle, handler: &Handler, body: &[u8]) -> JsonResponse {
    let request = match parse_body(body) {
        Ok(request) => request,
        Err(error) => return transport_error_response(&error),
    };
    if let Some(requests) = request.as_array() {
        return handle_batch(lifecycle, handler, requests);
    }
    if !request.is_object() {
        return transport_error_response(&RpcError::Parse(
            "Top-level object parse error".to_owned(),
        ));
    }
    handle_single(lifecycle, handler, &request)
}

/// Reads the body as one JSON document, mirroring Core `request.read`.
fn parse_body(body: &[u8]) -> Result<Value, RpcError> {
    let text = match core::str::from_utf8(body) {
        Ok(text) => text,
        Err(error) => {
            debug!(%error, "rpc body is not valid utf-8");
            return Err(RpcError::from(error));
        }
    };
    match sonic_rs::from_str(text) {
        Ok(request) => Ok(request),
        Err(error) => {
            debug!(%error, "rpc body is not valid json");
            Err(RpcError::from(error))
        }
    }
}

/// Core's reply for requests that never parsed: the default request context is
/// legacy with a present null id, so these replies are v1-shaped with
/// `"id": null` and carry the `JSONErrorReply` status for their code.
fn transport_error_response(error: &RpcError) -> JsonResponse {
    let version = JsonRpcVersion::Legacy;
    let status = version.error_status(error);
    JsonResponse {
        status,
        reason: reason_for_status(status),
        body: Some(version.error_response(error, Some(&Value::new_null()))),
    }
}

/// Core `ExecuteHTTPRPC` singleton step.
fn handle_single(lifecycle: &RpcLifecycle, handler: &Handler, request: &Value) -> JsonResponse {
    match execute_request(lifecycle, handler, request) {
        CallOutcome::Notification => no_content_response(),
        CallOutcome::Reply {
            body,
            version,
            error,
        } => {
            let status = match &error {
                Some(error) => version.error_status(error),
                None => 200,
            };
            JsonResponse {
                status,
                reason: reason_for_status(status),
                body: Some(body),
            }
        }
    }
}

/// Core batch execution: every member executes, replies keep input order, the
/// aggregate status is always 200, an all-notification batch yields 204, and
/// an empty batch returns an empty array (Core's documented backwards-
/// compatibility choice over the JSON-RPC 2.0 spec).
fn handle_batch(lifecycle: &RpcLifecycle, handler: &Handler, requests: &[Value]) -> JsonResponse {
    let mut bodies = Vec::with_capacity(requests.len());
    for request in requests {
        if let CallOutcome::Reply { body, .. } = execute_request(lifecycle, handler, request) {
            bodies.push(body);
        }
    }
    if bodies.is_empty() && !requests.is_empty() {
        return no_content_response();
    }
    JsonResponse {
        status: 200,
        reason: "OK",
        body: Some(json!(bodies)),
    }
}

/// Core's per-request step: parse the envelope, execute, and suppress the
/// reply exactly when the request — or the partial request left by a rejected
/// envelope — is a v2 notification.
fn execute_request(lifecycle: &RpcLifecycle, handler: &Handler, request: &Value) -> CallOutcome {
    let (version, id, outcome) = match parse_envelope(request) {
        Err(reject) => (reject.version, reject.id, Err(reject.error)),
        Ok(parsed) => {
            let result = lifecycle.execute(handler, &parsed.method, &parsed.params);
            (parsed.version, parsed.id, result)
        }
    };
    if version == JsonRpcVersion::V2 && id.is_none() {
        // Core executes notifications but never responds to them, even when
        // execution fails or the envelope was rejected after the version and
        // id were parsed.
        return CallOutcome::Notification;
    }
    match outcome {
        Ok(result) => CallOutcome::Reply {
            body: version.success_response(&result, id.as_ref()),
            version,
            error: None,
        },
        Err(error) => CallOutcome::Reply {
            body: version.error_response(&error, id.as_ref()),
            version,
            error: Some(error),
        },
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
        status: 204,
        reason: "No Content",
        body: None,
    }
}

/// Writes a JSON reply: `application/json` with the trailing newline Core
/// appends (`reply.write() + "\n"`).
fn write_json(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    value: &Value,
    keep_alive: bool,
) -> io::Result<()> {
    let mut body = sonic_rs::to_string(value).map_err(|error| {
        warn!(%error, "failed to serialize rpc response");
        io::Error::other("json serialization failed")
    })?;
    body.push('\n');
    let connection = if keep_alive { "keep-alive" } else { "close" };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

/// Writes a status reply with no content type; Core only sets Content-Type on
/// JSON replies.
fn write_status(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
    keep_alive: bool,
) -> io::Result<()> {
    let connection = if keep_alive { "keep-alive" } else { "close" };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

/// Writes Core's 401 challenge: the `WWW-Authenticate` header, no body, and a
/// closed connection.
fn write_unauthorized(stream: &mut TcpStream) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: {WWW_AUTHENTICATE}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )?;
    stream.flush()
}

fn split_path_query(path: &str) -> (&str, &str) {
    path.split_once('?')
        .map_or((path, ""), |(path, query)| (path, query))
}

fn write_response(
    stream: &mut TcpStream,
    response: &crate::rest::Response,
    keep_alive: bool,
) -> io::Result<()> {
    let connection = if keep_alive { "keep-alive" } else { "close" };
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len()
    )?;
    stream.write_all(&response.body)?;
    stream.flush()
}

fn write_rest_response(
    stream: &mut TcpStream,
    response: &crate::rest::RestResponse,
    keep_alive: bool,
) -> io::Result<()> {
    let connection = if keep_alive { "keep-alive" } else { "close" };
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: {}\r\nConnection: {connection}\r\n\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.content_length,
        response.cache_control,
    )?;
    stream.write_all(&response.body)?;
    stream.flush()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::context::Context;

    fn ready_lifecycle() -> RpcLifecycle {
        RpcLifecycle::new(Arc::new(AtomicBool::new(false)), Instant::now())
    }

    fn test_handler() -> Handler {
        Handler::new(Arc::new(Context::new()))
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn serve_with_shutdown_exits_on_signal() -> std::io::Result<()> {
        let auth = Arc::new(Auth::basic("alice", "secret"));
        let handler = Arc::new(Handler::new(Arc::new(Context::new())));
        let shutdown = Arc::new(AtomicBool::new(false));
        let lifecycle = Arc::new(RpcLifecycle::new(Arc::clone(&shutdown), Instant::now()));
        let server = RpcServer::bind(
            "127.0.0.1:0",
            auth,
            handler,
            Arc::clone(&lifecycle),
            4,
            core::time::Duration::from_millis(500),
            false,
        )?;
        let handle = std::thread::spawn(move || server.serve_with_shutdown());
        std::thread::sleep(core::time::Duration::from_millis(150));
        lifecycle.request_shutdown();
        handle.join().expect("join serve thread")
    }

    #[test]
    fn request_shutdown_notifies_node_once() {
        let wakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let wake_count = Arc::clone(&wakes);
        let lifecycle = RpcLifecycle::new(Arc::new(AtomicBool::new(false)), Instant::now())
            .with_shutdown_notifier(Arc::new(move || {
                wake_count.fetch_add(1, Ordering::Relaxed);
            }));

        lifecycle.request_shutdown();
        lifecycle.request_shutdown();

        assert!(lifecycle.is_shutdown());
        assert_eq!(wakes.load(Ordering::Relaxed), 1);
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
    fn json_rpc_2_success_omits_null_error_for_jsonrpsee_clients() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();
        let response = handle_json(
            &lifecycle,
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
        let lifecycle = ready_lifecycle();
        let handler = test_handler();
        let response = handle_json(
            &lifecycle,
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
        let lifecycle = ready_lifecycle();
        let handler = test_handler();
        let response = handle_json(
            &lifecycle,
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
    fn legacy_method_not_found_maps_to_http_404() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();
        let response = handle_json(
            &lifecycle,
            &handler,
            br#"{"method":"missing","params":[],"id":7}"#,
        );
        let status = response.status;
        let reason = response.reason;
        let body = response.body.expect("JSON-RPC response body");
        let error = body.get("error").expect("error member");

        assert_eq!((status, reason), (404, "Not Found"));
        assert!(body.get("jsonrpc").is_none());
        assert!(body.get("result").is_some_and(Value::is_null));
        assert_eq!(
            error.get("code").and_then(Value::as_i64),
            Some(RpcError::METHOD_NOT_FOUND)
        );
        assert_eq!(
            error.get("message").and_then(Value::as_str),
            Some("Method not found")
        );
        assert_eq!(body.get("id").and_then(Value::as_i64), Some(7));
        assert!(error.get("data").is_none());
    }

    #[test]
    fn invalid_request_envelopes_map_to_http_400() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();
        let cases: [(&[u8], &str); 4] = [
            (br#"{"id":3,"method":5}"#, "Method must be a string"),
            (br#"{"id":3}"#, "Missing method"),
            (
                br#"{"id":3,"method":"getblockcount","params":5}"#,
                "Params must be an array or object",
            ),
            (br#"{"id":3,"method":null}"#, "Missing method"),
        ];

        for (body, message) in cases {
            let response = handle_json(&lifecycle, &handler, body);
            let error = response
                .body
                .expect("JSON-RPC response body")
                .get("error")
                .cloned()
                .unwrap_or_else(|| panic!("error member missing for {message}"));

            assert_eq!(response.status, 400, "case {message}");
            assert_eq!(response.reason, "Bad Request");
            assert_eq!(
                error.get("code").and_then(Value::as_i64),
                Some(RpcError::INVALID_REQUEST)
            );
            assert_eq!(error.get("message").and_then(Value::as_str), Some(message));
        }
    }

    #[test]
    fn unsupported_or_malformed_jsonrpc_field_is_invalid_request() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();
        let cases: [(&[u8], &str); 2] = [
            (
                br#"{"id":1,"jsonrpc":"3.0","method":"x"}"#,
                "JSON-RPC version not supported",
            ),
            (
                br#"{"id":1,"jsonrpc":2,"method":"x"}"#,
                "jsonrpc field must be a string",
            ),
        ];

        for (body, message) in cases {
            let response = handle_json(&lifecycle, &handler, body);
            let body = response.body.expect("JSON-RPC response body");

            assert_eq!(response.status, 400, "case {message}");
            assert!(body.get("jsonrpc").is_none(), "case {message}");
            assert_eq!(
                body.get("error")
                    .and_then(|error| error.get("message"))
                    .and_then(Value::as_str),
                Some(message)
            );
        }
    }

    #[test]
    fn v2_invalid_request_keeps_v2_envelope_but_maps_to_http_400() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();
        let response = handle_json(
            &lifecycle,
            &handler,
            br#"{"jsonrpc":"2.0","id":1,"method":"x","params":5}"#,
        );
        let status = response.status;
        let body = response.body.expect("JSON-RPC response body");

        assert_eq!(status, 400);
        assert_eq!(body.get("jsonrpc").and_then(Value::as_str), Some("2.0"));
        assert_eq!(
            body.get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_i64),
            Some(RpcError::INVALID_REQUEST)
        );
    }

    #[test]
    fn top_level_scalars_are_parse_errors() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();

        let bodies: [&[u8]; 2] = [br"42", br#""text""#];
        for body in bodies {
            let response = handle_json(&lifecycle, &handler, body);
            let parsed = response.body.expect("JSON-RPC response body");
            let error = parsed.get("error").expect("error member");

            assert_eq!(response.status, 500);
            assert!(parsed.get("jsonrpc").is_none());
            assert!(parsed.get("result").is_some_and(Value::is_null));
            assert_eq!(
                error.get("code").and_then(Value::as_i64),
                Some(RpcError::PARSE_ERROR)
            );
            assert_eq!(
                error.get("message").and_then(Value::as_str),
                Some("Top-level object parse error")
            );
            assert!(parsed.get("id").is_some_and(Value::is_null));
        }
    }

    #[test]
    fn malformed_json_returns_core_parse_error_envelope() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();
        let response = handle_json(&lifecycle, &handler, b"{");
        let body = response.body.expect("JSON-RPC response body");
        let error = body.get("error").expect("error member");

        assert_eq!(response.status, 500);
        assert_eq!(
            error.get("code").and_then(Value::as_i64),
            Some(RpcError::PARSE_ERROR)
        );
        assert_eq!(
            error.get("message").and_then(Value::as_str),
            Some("Parse error")
        );
        assert!(body.get("id").is_some_and(Value::is_null));
    }

    #[test]
    fn absent_id_and_explicit_null_id_are_distinct() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();

        let absent = handle_json(&lifecycle, &handler, br#"{"method":"getblockcount"}"#);
        let absent = absent.body.expect("legacy replies without an id");
        assert!(absent.get("result").is_some());
        assert!(absent.get("error").is_some_and(Value::is_null));
        assert!(absent.get("id").is_none(), "absent id must stay absent");

        let explicit = handle_json(
            &lifecycle,
            &handler,
            br#"{"jsonrpc":"2.0","id":null,"method":"getblockcount"}"#,
        );
        let explicit = explicit
            .body
            .expect("explicit null id is not a notification");
        assert!(explicit.get("result").is_some());
        assert!(explicit.get("id").is_some_and(Value::is_null));
    }

    #[test]
    fn json_rpc_2_notification_has_no_response_body() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();
        let response = handle_json(
            &lifecycle,
            &handler,
            br#"{"jsonrpc":"2.0","method":"getblockcount","params":[]}"#,
        );

        assert!(response.body.is_none());
        assert_eq!((response.status, response.reason), (204, "No Content"));
    }

    #[test]
    fn empty_batch_returns_an_empty_array_with_http_200() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();
        let response = handle_json(&lifecycle, &handler, b"[]");
        let status = response.status;
        let body = response.body.expect("empty batch reply body");

        assert_eq!(status, 200);
        assert_eq!(body.as_array().map(sonic_rs::Array::len), Some(0));
    }

    #[test]
    fn all_notification_batch_returns_no_content() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();
        let response = handle_json(
            &lifecycle,
            &handler,
            br#"[
                {"jsonrpc":"2.0","method":"getblockcount","params":[]},
                {"jsonrpc":"2.0","method":"getblockchaininfo","params":[]}
            ]"#,
        );

        assert!(response.body.is_none());
        assert_eq!((response.status, response.reason), (204, "No Content"));
    }

    #[test]
    fn invalid_v2_notification_members_are_suppressed() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();
        let response = handle_json(&lifecycle, &handler, br#"[{"jsonrpc":"2.0","method":5}]"#);

        assert!(response.body.is_none());
        assert_eq!(response.status, 204);
    }

    #[test]
    fn json_rpc_batch_excludes_notifications() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();
        let response = handle_json(
            &lifecycle,
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

    #[test]
    fn batch_replies_preserve_input_order_across_invalid_members() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();
        let response = handle_json(
            &lifecycle,
            &handler,
            br#"[
                {"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]},
                5,
                {"method":"missing","id":"a"}
            ]"#,
        );
        let status = response.status;
        let body = response.body.expect("JSON-RPC batch response body");
        let rows = body.as_array().expect("batch response array");

        assert_eq!(status, 200, "batches never carry member HTTP errors");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].get("id").and_then(Value::as_i64), Some(1));
        assert!(rows[0].get("result").is_some());
        assert_eq!(
            rows[1]
                .get("error")
                .and_then(|error| error.get("message"))
                .and_then(Value::as_str),
            Some("Invalid Request object")
        );
        assert!(rows[1].get("id").is_some_and(Value::is_null));
        assert_eq!(
            rows[2]
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_i64),
            Some(RpcError::METHOD_NOT_FOUND)
        );
        assert_eq!(rows[2].get("id").and_then(Value::as_str), Some("a"));
    }

    #[test]
    fn warmup_rejects_commands_until_finished_and_reports_status() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();
        lifecycle.set_warmup_starting();

        let legacy = handle_json(
            &lifecycle,
            &handler,
            br#"{"method":"getblockcount","id":1}"#,
        );
        let body = legacy.body.expect("warmup rejection body");
        let error = body.get("error").expect("error member");
        assert_eq!(legacy.status, 500);
        assert_eq!(
            error.get("code").and_then(Value::as_i64),
            Some(RpcError::CORE_IN_WARMUP)
        );
        assert_eq!(
            error.get("message").and_then(Value::as_str),
            Some(WARMUP_DEFAULT_STATUS)
        );

        lifecycle.set_warmup_status("Loading block index");
        let v2 = handle_json(
            &lifecycle,
            &handler,
            br#"{"jsonrpc":"2.0","method":"getblockcount","id":1}"#,
        );
        let body = v2.body.expect("v2 warmup rejection body");
        assert_eq!(v2.status, 200);
        assert_eq!(
            body.get("error")
                .and_then(|error| error.get("message"))
                .and_then(Value::as_str),
            Some("Loading block index")
        );

        lifecycle.set_warmup_finished();
        let ready = handle_json(
            &lifecycle,
            &handler,
            br#"{"method":"getblockcount","id":1}"#,
        );
        let body = ready.body.expect("ready reply body");
        assert_eq!(ready.status, 200);
        assert!(body.get("result").is_some());
    }

    #[test]
    fn shutdown_observed_between_commands_rejects_with_client_not_connected() {
        let lifecycle = RpcLifecycle::new(Arc::new(AtomicBool::new(true)), Instant::now());
        let handler = test_handler();
        let response = handle_json(
            &lifecycle,
            &handler,
            br#"{"method":"getblockcount","id":1}"#,
        );
        let body = response.body.expect("shutdown rejection body");
        let error = body.get("error").expect("error member");

        assert_eq!(response.status, 500);
        assert_eq!(
            error.get("code").and_then(Value::as_i64),
            Some(RpcError::CORE_CLIENT_NOT_CONNECTED)
        );
        assert_eq!(
            error.get("message").and_then(Value::as_str),
            Some("Shutting down")
        );
    }

    #[test]
    fn active_commands_track_registration_and_removal_in_order() {
        let lifecycle = ready_lifecycle();
        assert!(lifecycle.active_commands().is_empty());

        let first = lifecycle.track_command("getblockcount");
        {
            let _second = lifecycle.track_command("getblockchaininfo");
            let active = lifecycle.active_commands();
            let methods: Vec<&str> = active.iter().map(|(method, _)| method.as_str()).collect();
            assert_eq!(methods, ["getblockcount", "getblockchaininfo"]);
            assert!(active.iter().all(|(_, duration)| *duration < 60_000_000));
        }
        let active = lifecycle.active_commands();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].0, "getblockcount");
        drop(first);
        assert!(lifecycle.active_commands().is_empty());
    }

    #[test]
    fn failed_commands_remove_their_tracking_entry() {
        let lifecycle = ready_lifecycle();
        let handler = test_handler();

        let result = lifecycle.execute(&handler, "missing_method", &json!([]));

        assert!(result.is_err());
        assert!(lifecycle.active_commands().is_empty());
    }

    #[test]
    fn unauthorized_reply_carries_core_challenge_header() -> io::Result<()> {
        let auth = Arc::new(Auth::basic("alice", "secret"));
        let handler = Arc::new(Handler::new(Arc::new(Context::new())));
        let shutdown = Arc::new(AtomicBool::new(false));
        let lifecycle = Arc::new(RpcLifecycle::new(Arc::clone(&shutdown), Instant::now()));
        let server = RpcServer::bind(
            "127.0.0.1:0",
            auth,
            handler,
            Arc::clone(&lifecycle),
            4,
            Duration::from_secs(2),
            false,
        )?;
        let address = server.local_addr()?;
        let handle = std::thread::spawn(move || server.serve_with_shutdown());

        let mut stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        )?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        lifecycle.request_shutdown();
        let _ = handle.join();

        assert!(response.starts_with("HTTP/1.1 401 Unauthorized"));
        assert!(response.contains("WWW-Authenticate: Basic realm=\"jsonrpc\""));
        Ok(())
    }

    #[test]
    fn non_post_methods_receive_core_405_reply() -> io::Result<()> {
        let auth = Arc::new(Auth::basic("alice", "secret"));
        let handler = Arc::new(Handler::new(Arc::new(Context::new())));
        let shutdown = Arc::new(AtomicBool::new(false));
        let lifecycle = Arc::new(RpcLifecycle::new(Arc::clone(&shutdown), Instant::now()));
        let server = RpcServer::bind(
            "127.0.0.1:0",
            auth,
            handler,
            Arc::clone(&lifecycle),
            4,
            Duration::from_secs(2),
            false,
        )?;
        let address = server.local_addr()?;
        let handle = std::thread::spawn(move || server.serve_with_shutdown());

        let mut stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(
            b"DELETE / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        lifecycle.request_shutdown();
        let _ = handle.join();

        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed"));
        assert!(response.ends_with("JSONRPC server handles only POST requests"));
        Ok(())
    }
}
