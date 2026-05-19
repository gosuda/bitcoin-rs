use alloc::sync::Arc;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::Duration;

use parking_lot::Mutex;
use sonic_rs::{JsonValueTrait as _, Value, json};
use tracing::{debug, warn};

use crate::auth::Auth;
use crate::error::RpcError;
use crate::handlers::Handler;

const MAX_HEADER_BYTES: usize = 16 * 1_024;
const MAX_BODY_BYTES: usize = 16 * 1_024 * 1_024;

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
}

impl RpcServer {
    /// Binds a new RPC server.
    pub fn bind<A: ToSocketAddrs>(
        address: A,
        auth: Arc<Auth>,
        handler: Arc<Handler>,
        max_connections: usize,
        idle_timeout: Duration,
    ) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(address)?,
            auth,
            handler,
            max_connections,
            idle_timeout,
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
            let mut stream = stream?;
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
                continue;
            }

            let auth = Arc::clone(&self.auth);
            let handler = Arc::clone(&self.handler);
            let active = Arc::clone(&active);
            let idle_timeout = self.idle_timeout;
            thread::spawn(move || {
                if let Err(error) = serve_connection(stream, &auth, &handler, idle_timeout) {
                    debug!(%error, "rpc connection closed with error");
                }
                let mut count = active.lock();
                *count = count.saturating_sub(1);
            });
        }
        Ok(())
    }
}

fn serve_connection(
    stream: TcpStream,
    auth: &Auth,
    handler: &Handler,
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
                let response =
                    RpcError::InvalidRequest("malformed http request").response(&Value::new_null());
                write_json(reader.get_mut(), 400, "Bad Request", &response, false)?;
                return Err(error);
            }
        };

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

        let keep_alive = request.keep_alive;
        let response = handle_json(handler, &request.body);
        write_json(reader.get_mut(), 200, "OK", &response, keep_alive)?;
        if !keep_alive {
            return Ok(());
        }
    }
}

struct HttpRequest {
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
    if !request_line.ends_with("\r\n") || !request_line.starts_with("POST ") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid request line",
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

    let Some(content_length) = content_length else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing content-length",
        ));
    };
    let mut body = vec![0_u8; content_length];
    reader.read_exact(&mut body)?;
    Ok(Some(HttpRequest {
        authorization,
        keep_alive,
        body,
    }))
}

fn handle_json(handler: &Handler, body: &[u8]) -> Value {
    let body = match core::str::from_utf8(body) {
        Ok(body) => body,
        Err(error) => return RpcError::from(error).response(&Value::new_null()),
    };
    let request = match sonic_rs::from_str::<Value>(body) {
        Ok(request) => request,
        Err(error) => return RpcError::from(error).response(&Value::new_null()),
    };
    let id = request.get("id").cloned().unwrap_or_else(Value::new_null);
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return RpcError::InvalidRequest("method is required").response(&id);
    };
    let null_params = Value::new_null();
    let params = request.get("params").unwrap_or(&null_params);
    match handler.dispatch(method, params) {
        Ok(result) => json!({"jsonrpc": "2.0", "result": result, "error": null, "id": id}),
        Err(error) => error.response(&id),
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
    let connection = if keep_alive { "keep-alive" } else { "close" };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}
