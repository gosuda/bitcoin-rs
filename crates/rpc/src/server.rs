use alloc::sync::Arc;
use std::io::{self, BufRead, BufReader, IoSlice, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::Duration;

use parking_lot::Mutex;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};
use tracing::{debug, warn};

use crate::auth::Auth;
use crate::error::RpcError;
use crate::handlers::Handler;

const MAX_HEADER_BYTES: usize = 16 * 1_024;
const MAX_BODY_BYTES: usize = 16 * 1_024 * 1_024;
const POLL_INTERVAL: core::time::Duration = core::time::Duration::from_millis(100);

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
        Ok(Self {
            listener: TcpListener::bind(address)?,
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

    /// Runs the accept loop. Each accepted connection is handled by one bounded worker thread.
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
    /// preserving the configured `idle_timeout` per connection.
    #[allow(clippy::needless_pass_by_value)]
    pub fn serve_with_shutdown(
        self,
        shutdown: alloc::sync::Arc<core::sync::atomic::AtomicBool>,
    ) -> io::Result<()> {
        use core::sync::atomic::Ordering;

        self.listener.set_nonblocking(true)?;
        let active = Arc::new(Mutex::new(0_usize));
        while !shutdown.load(Ordering::Acquire) {
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

    fn handle_accept(&self, active: &Arc<Mutex<usize>>, stream: TcpStream) -> io::Result<()> {
        let mut stream = prepare_http_socket(stream)?;
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
        let rest_enabled = self.rest_enabled;
        let active = Arc::clone(active);
        let idle_timeout = self.idle_timeout;
        thread::spawn(move || {
            if let Err(error) =
                serve_connection(stream, &auth, &handler, rest_enabled, idle_timeout)
            {
                debug!(%error, "rpc connection closed with error");
            }
            let mut count = active.lock();
            *count = count.saturating_sub(1);
        });
        Ok(())
    }
}

fn serve_connection(
    stream: TcpStream,
    auth: &Auth,
    handler: &Handler,
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
                    JsonRpcVersion::Legacy.error_response(&rpc_error, &Value::new_null());
                write_json(reader.get_mut(), 400, "Bad Request", &response, false)?;
                return Err(error);
            }
        };
        let keep_alive = request.keep_alive;
        match classify(&request.method, &request.path) {
            HttpRoute::Rest { path, query } => {
                let response = crate::rest::route(handler.context(), path, query, rest_enabled);
                write_response(reader.get_mut(), &response, keep_alive)?;
            }
            HttpRoute::EsploraGet { path, query } => {
                let response = crate::esplora::route(handler, path, query);
                write_response(reader.get_mut(), &response, keep_alive)?;
            }
            HttpRoute::EsploraPost { path } => {
                match crate::esplora::route_post(handler, path, &request.body) {
                    Some(response) => {
                        write_response(reader.get_mut(), &response, keep_alive)?;
                    }
                    None => {
                        write_status(reader.get_mut(), 404, "Not Found", b"not found", keep_alive)?;
                    }
                }
            }
            HttpRoute::JsonRpc => {
                if !auth.validate_header(request.authorization.as_deref()) {
                    write_status(
                        reader.get_mut(),
                        401,
                        "Unauthorized",
                        b"unauthorized",
                        false,
                    )?;
                    return Ok(());
                }
                let response = handle_json(handler, &request.body);
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
            }
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
    if !matches!(method, "POST" | "GET") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid request method",
        ));
    }
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

    let content_length = match (method, content_length) {
        ("GET", length) => length.unwrap_or(0),
        (_, Some(length)) => length,
        (_, None) => {
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
    fn from_request(request: &Value) -> Self {
        if request.get("jsonrpc").and_then(Value::as_str) == Some("2.0") {
            Self::V2
        } else {
            Self::Legacy
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

    const fn error_status(self) -> u16 {
        match self {
            Self::Legacy => 500,
            Self::V2 => 200,
        }
    }
}

enum CallResponse {
    Reply {
        body: Value,
        version: JsonRpcVersion,
        is_error: bool,
    },
    Notification,
}

impl CallResponse {
    fn reply(body: Value, version: JsonRpcVersion, is_error: bool) -> Self {
        Self::Reply {
            body,
            version,
            is_error,
        }
    }

    const fn http_status(&self) -> u16 {
        match self {
            Self::Reply {
                version,
                is_error: true,
                ..
            } => version.error_status(),
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

    if let Some(requests) = request.as_array() {
        if requests.is_empty() {
            return legacy_error_response(
                &RpcError::InvalidRequest("batch must not be empty"),
                &Value::new_null(),
            );
        }
        let mut responses = Vec::with_capacity(requests.len());
        let mut status = 200;
        for request in requests {
            let response = handle_single_json(handler, request);
            status = status.max(response.http_status());
            if let CallResponse::Reply { body, .. } = response {
                responses.push(body);
            }
        }
        if responses.is_empty() {
            return no_content_response();
        }
        return JsonResponse {
            status,
            reason: reason_for_status(status),
            body: Some(json!(responses)),
        };
    }

    let response = handle_single_json(handler, &request);
    let status = response.http_status();
    match response {
        CallResponse::Reply { body, .. } => JsonResponse {
            status,
            reason: reason_for_status(status),
            body: Some(body),
        },
        CallResponse::Notification => no_content_response(),
    }
}

fn handle_single_json(handler: &Handler, request: &Value) -> CallResponse {
    let id = request.get("id").cloned().unwrap_or_else(Value::new_null);
    let version = JsonRpcVersion::from_request(request);
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        let error = RpcError::InvalidRequest("method is required");
        return CallResponse::reply(version.error_response(&error, &id), version, true);
    };
    let null_params = Value::new_null();
    let params = request.get("params").unwrap_or(&null_params);
    let result = handler.dispatch(method, params);
    if version == JsonRpcVersion::V2 && request.get("id").is_none() {
        return CallResponse::Notification;
    }
    match result {
        Ok(result) => CallResponse::reply(version.success_response(&result, &id), version, false),
        Err(error) => CallResponse::reply(version.error_response(&error, &id), version, true),
    }
}

fn legacy_error_response(error: &RpcError, id: &Value) -> JsonResponse {
    let version = JsonRpcVersion::Legacy;
    JsonResponse {
        status: version.error_status(),
        reason: reason_for_status(version.error_status()),
        body: Some(version.error_response(error, id)),
    }
}

const fn reason_for_status(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
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
    write_http(stream, status, reason, "application/json", body, keep_alive)
}

fn split_path_query(path: &str) -> (&str, &str) {
    path.split_once('?')
        .map_or((path, ""), |(path, query)| (path, query))
}

/// Listener directories. JSON-RPC owns `/`; Esplora owns `/api` and `/esplora`;
/// Core REST owns `/rest/`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpRoute<'a> {
    Rest { path: &'a str, query: &'a str },
    EsploraGet { path: &'a str, query: &'a str },
    EsploraPost { path: &'a str },
    JsonRpc,
}

fn classify<'a>(method: &str, raw_path: &'a str) -> HttpRoute<'a> {
    let (path, query) = split_path_query(raw_path);
    match method {
        "GET" if path.starts_with("/rest/") => HttpRoute::Rest { path, query },
        "GET" => HttpRoute::EsploraGet { path, query },
        _ if crate::esplora::namespace(path).is_some() => HttpRoute::EsploraPost { path },
        _ => HttpRoute::JsonRpc,
    }
}

fn write_response(
    stream: &mut TcpStream,
    response: &crate::rest::Response,
    keep_alive: bool,
) -> io::Result<()> {
    write_http(
        stream,
        response.status,
        response.reason,
        response.content_type,
        &response.body,
        keep_alive,
    )
}

/// Applies the HTTP socket contract: disable Nagle once, before any bytes move.
fn prepare_http_socket(stream: TcpStream) -> io::Result<TcpStream> {
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn write_http(
    stream: &mut impl Write,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
    keep_alive: bool,
) -> io::Result<()> {
    let connection = if keep_alive { "keep-alive" } else { "close" };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
        body.len()
    );
    write_all_vectored(stream, header.as_bytes(), body)?;
    stream.flush()
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    use crate::context::Context;

    #[test]
    #[allow(clippy::expect_used)]
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
    fn classify_splits_rest_esplora_and_json_rpc() {
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
                path: "/api/blocks/tip/height",
                query: ""
            }
        );
        assert_eq!(
            classify("GET", "/esplora/internal/mempool/txs?max_txs=1"),
            HttpRoute::EsploraGet {
                path: "/esplora/internal/mempool/txs",
                query: "max_txs=1"
            }
        );
        assert_eq!(
            classify("POST", "/api/tx"),
            HttpRoute::EsploraPost { path: "/api/tx" }
        );
        assert_eq!(
            classify("POST", "/esplora/internal/txs"),
            HttpRoute::EsploraPost {
                path: "/esplora/internal/txs"
            }
        );
        assert_eq!(classify("POST", "/"), HttpRoute::JsonRpc);
        assert_eq!(classify("POST", "/tx"), HttpRoute::JsonRpc);
        assert_eq!(
            classify("GET", "/blocks/tip/height"),
            HttpRoute::EsploraGet {
                path: "/blocks/tip/height",
                query: ""
            }
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

    /// Proof of `API-07`: HTTP responses use the owned socket posture and one vectored write.
    #[test]
    fn write_http_emits_header_and_body_as_one_vectored_write() {
        struct VectoredSink {
            calls: usize,
            bytes: Vec<u8>,
        }
        impl Write for VectoredSink {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                panic!("write_http must not fall back to write");
            }
            fn write_vectored(&mut self, buffers: &[IoSlice<'_>]) -> io::Result<usize> {
                self.calls += 1;
                let mut written = 0;
                for buffer in buffers {
                    self.bytes.extend_from_slice(buffer);
                    written += buffer.len();
                }
                Ok(written)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut sink = VectoredSink {
            calls: 0,
            bytes: Vec::new(),
        };
        write_http(&mut sink, 200, "OK", "application/json", b"{}", true).expect("write_http");
        assert_eq!(sink.calls, 1);
        let text = String::from_utf8(sink.bytes).expect("utf8");
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.ends_with("\r\n\r\n{}"));
    }

    /// Proof of `API-07`: accepted HTTP sockets enable TCP_NODELAY.
    #[test]
    fn prepare_http_socket_disables_nagle() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let accepting = std::thread::spawn(move || listener.accept());
        let client = TcpStream::connect(addr)?;
        assert!(
            !client.nodelay()?,
            "a raw TcpStream starts with Nagle enabled"
        );
        let prepared = prepare_http_socket(client)?;
        assert!(prepared.nodelay()?, "prepare_http_socket owns TCP_NODELAY");
        drop(prepared);
        let _accepted = accepting.join();
        Ok(())
    }
}
