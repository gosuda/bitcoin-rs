//! Authentication coverage for the synchronous RPC server.
extern crate alloc;

use alloc::sync::Arc;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use bitcoin_rs_rpc::auth::constant_time_eq;
use bitcoin_rs_rpc::context::Context;
use bitcoin_rs_rpc::{Auth, Handler, RpcLifecycle, RpcServer};
use sonic_rs::json;
use sonic_rs::{JsonContainerTrait, JsonValueTrait};

#[test]
fn basic_auth_accepts_and_rejects_requests() -> Result<(), Box<dyn std::error::Error>> {
    let address = spawn(Auth::basic("alice", "secret"))?;
    let body = r#"{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}"#;

    let ok = request(address, "YWxpY2U6c2VjcmV0", body)?;
    assert!(ok.starts_with("HTTP/1.1 200 OK"));
    assert!(ok.contains("\"result\":0"));

    let rejected = request(address, "YWxpY2U6YmFk", body)?;
    assert!(rejected.starts_with("HTTP/1.1 401 Unauthorized"));
    Ok(())
}

#[test]
fn json_rpc_2_error_is_http_200_without_result() -> Result<(), Box<dyn std::error::Error>> {
    let address = spawn(Auth::basic("alice", "secret"))?;
    let body = r#"{"jsonrpc":"2.0","method":"missing","params":[],"id":7}"#;
    let response = request(address, "YWxpY2U6c2VjcmV0", body)?;
    let payload = response.split_once("\r\n\r\n").ok_or("missing body")?.1;
    let value: sonic_rs::Value = sonic_rs::from_str(payload)?;

    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert_eq!(value.get("jsonrpc").and_then(|v| v.as_str()), Some("2.0"));
    assert!(value.get("error").is_some());
    assert!(value.get("result").is_none());
    Ok(())
}

#[test]
fn legacy_error_has_core_envelope_and_http_error() -> Result<(), Box<dyn std::error::Error>> {
    let address = spawn(Auth::basic("alice", "secret"))?;
    let body = r#"{"method":"missing","params":[],"id":7}"#;
    let response = request(address, "YWxpY2U6c2VjcmV0", body)?;
    let payload = response.split_once("\r\n\r\n").ok_or("missing body")?.1;
    let value: sonic_rs::Value = sonic_rs::from_str(payload)?;

    assert!(response.starts_with("HTTP/1.1 404 Not Found"));
    assert!(value.get("jsonrpc").is_none());
    assert!(value.get("error").is_some());
    assert!(value.get("result").is_some_and(|v| v.is_null()));
    Ok(())
}

#[test]
fn json_rpc_2_notification_returns_http_204() -> Result<(), Box<dyn std::error::Error>> {
    let address = spawn(Auth::basic("alice", "secret"))?;
    let body = r#"{"jsonrpc":"2.0","method":"getblockcount","params":[]}"#;
    let response = request(address, "YWxpY2U6c2VjcmV0", body)?;

    assert!(response.starts_with("HTTP/1.1 204 No Content"));
    assert!(response.ends_with("\r\n\r\n"));
    Ok(())
}

#[test]
fn json_rpc_2_batch_returns_an_array_and_excludes_notifications()
-> Result<(), Box<dyn std::error::Error>> {
    let address = spawn(Auth::basic("alice", "secret"))?;
    let body = r#"[
        {"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1},
        {"jsonrpc":"2.0","method":"getblockcount","params":[]},
        {"jsonrpc":"2.0","method":"missing","params":[],"id":2}
    ]"#;
    let response = request(address, "YWxpY2U6c2VjcmV0", body)?;
    let payload = response.split_once("\r\n\r\n").ok_or("missing body")?.1;
    let value: sonic_rs::Value = sonic_rs::from_str(payload)?;
    let rows = value.as_array().ok_or("batch response must be an array")?;

    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert_eq!(rows.len(), 2);
    assert!(rows[0].get("result").is_some());
    assert!(rows[1].get("error").is_some());
    Ok(())
}

#[test]
fn notification_only_batch_returns_http_204() -> Result<(), Box<dyn std::error::Error>> {
    let address = spawn(Auth::basic("alice", "secret"))?;
    let body = r#"[
        {"jsonrpc":"2.0","method":"getblockcount","params":[]},
        {"jsonrpc":"2.0","method":"getblockchaininfo","params":[]}
    ]"#;
    let response = request(address, "YWxpY2U6c2VjcmV0", body)?;

    assert!(response.starts_with("HTTP/1.1 204 No Content"));
    assert!(response.ends_with("\r\n\r\n"));
    Ok(())
}

#[test]
fn malformed_json_uses_core_legacy_parse_error_envelope() -> Result<(), Box<dyn std::error::Error>>
{
    let address = spawn(Auth::basic("alice", "secret"))?;
    let response = request(address, "YWxpY2U6c2VjcmV0", "{")?;
    let payload = response.split_once("\r\n\r\n").ok_or("missing body")?.1;
    let value: sonic_rs::Value = sonic_rs::from_str(payload)?;

    assert!(response.starts_with("HTTP/1.1 500 Internal Server Error"));
    assert!(value.get("jsonrpc").is_none());
    assert!(value.get("result").is_some_and(|v| v.is_null()));
    assert_eq!(
        value
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(|code| code.as_i64()),
        Some(-32_700)
    );
    assert!(value.get("id").is_some_and(|id| id.is_null()));
    Ok(())
}

#[test]
fn rest_enabled_does_not_require_authentication() -> Result<(), Box<dyn std::error::Error>> {
    let address = spawn_with_rest(Auth::basic("alice", "secret"), true)?;
    let response = request_get(address, "/rest/chaininfo.json", "close")?;
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("Content-Type: application/json"));
    let body = response.split_once("\r\n\r\n").ok_or("missing body")?.1;
    let value: sonic_rs::Value = sonic_rs::from_str(body)?;
    assert!(value.get("chain").is_some());
    Ok(())
}

#[test]
fn rest_disabled_returns_not_found_without_authentication() -> Result<(), Box<dyn std::error::Error>>
{
    let address = spawn_with_rest(Auth::basic("alice", "secret"), false)?;
    let response = request_get(address, "/rest/chaininfo.json", "close")?;
    assert!(response.starts_with("HTTP/1.1 404 Not Found"));
    Ok(())
}

#[test]
fn post_json_rpc_still_requires_and_accepts_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let address = spawn_with_rest(Auth::basic("alice", "secret"), true)?;
    let body = r#"{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}"#;
    let rejected = request_post(address, body, None, "close")?;
    assert!(rejected.starts_with("HTTP/1.1 401 Unauthorized"));
    let accepted = request_post(address, body, Some("YWxpY2U6c2VjcmV0"), "close")?;
    assert!(accepted.starts_with("HTTP/1.1 200 OK"));
    assert!(accepted.contains("\"result\":0"));
    Ok(())
}

#[test]
fn non_rest_get_returns_not_found_without_authentication() -> Result<(), Box<dyn std::error::Error>>
{
    let address = spawn_with_rest(Auth::basic("alice", "secret"), true)?;
    let response = request_get(address, "/", "close")?;
    assert!(response.starts_with("HTTP/1.1 404 Not Found"));
    Ok(())
}

#[test]
fn rest_keep_alive_serves_two_requests() -> Result<(), Box<dyn std::error::Error>> {
    let address = spawn_with_rest(Auth::basic("alice", "secret"), true)?;
    let mut stream = TcpStream::connect(address)?;
    write!(
        stream,
        "GET /rest/chaininfo.json HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n\
         GET /rest/chaininfo.json?ignored=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )?;
    let mut reader = BufReader::new(stream);
    let first = read_response(&mut reader)?;
    let second = read_response(&mut reader)?;
    assert!(first.starts_with("HTTP/1.1 200 OK"));
    assert!(second.starts_with("HTTP/1.1 200 OK"));
    Ok(())
}

#[test]
fn cookie_auth_accepts_file_backed_secret() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(".cookie");
    std::fs::write(&path, "__cookie__:cookie\n")?;
    let address = spawn(Auth::cookie(&path)?)?;
    let body = r#"{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}"#;

    let ok = request(address, "X19jb29raWVfXzpjb29raWU=", body)?;
    assert!(ok.starts_with("HTTP/1.1 200 OK"));

    let rejected = request(address, "X19jb29raWVfXzptYW5nbGVk", body)?;
    assert!(rejected.starts_with("HTTP/1.1 401 Unauthorized"));
    Ok(())
}

#[test]
fn constant_time_compare_checks_length_and_content() {
    assert!(constant_time_eq(b"same", b"same"));
    assert!(!constant_time_eq(b"same", b"diff"));
    assert!(!constant_time_eq(b"same", b"same-but-longer"));
    assert!(!constant_time_eq(b"same-but-longer", b"same"));
}

fn spawn(auth: Auth) -> Result<std::net::SocketAddr, Box<dyn std::error::Error>> {
    spawn_with_rest(auth, false)
}

fn spawn_with_rest(
    auth: Auth,
    rest_enabled: bool,
) -> Result<std::net::SocketAddr, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let ctx = Arc::new(Context::new());
    let handler = Arc::new(Handler::new(ctx));
    let server = RpcServer {
        listener,
        auth: Arc::new(auth),
        handler,
        max_connections: 8,
        idle_timeout: Duration::from_secs(2),
        rest_enabled,
        lifecycle: Arc::new(RpcLifecycle::new(Arc::new(
            std::sync::atomic::AtomicBool::new(false),
        ))),
    };
    thread::spawn(move || {
        let _ignored = server.serve();
    });
    Ok(address)
}

fn request_get(
    address: std::net::SocketAddr,
    path: &str,
    connection: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(address)?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: {connection}\r\n\r\n"
    )?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn request_post(
    address: std::net::SocketAddr,
    body: &str,
    authorization: Option<&str>,
    connection: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(address)?;
    let authorization = authorization.map_or(String::new(), |value| {
        format!("Authorization: Basic {value}\r\n")
    });
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: localhost\r\n{authorization}Content-Length: {}\r\nConnection: {connection}\r\n\r\n{body}",
        body.len()
    )?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn read_response(reader: &mut BufReader<TcpStream>) -> Result<String, Box<dyn std::error::Error>> {
    let mut headers = Vec::new();
    reader.read_until(b'\n', &mut headers)?;
    loop {
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line)?;
        headers.extend_from_slice(&line);
        if line == b"\r\n" {
            break;
        }
    }
    let header_text = String::from_utf8(headers)?;
    let content_length = header_text
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .ok_or("missing content length")?
        .parse::<usize>()?;
    let mut body = vec![0_u8; content_length];
    reader.read_exact(&mut body)?;
    Ok(format!("{header_text}{}", String::from_utf8(body)?))
}

fn request(
    address: std::net::SocketAddr,
    credentials: &str,
    body: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(address)?;
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {credentials}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[test]
fn handler_is_constructible_for_auth_tests() {
    let handler = Handler::new(Arc::new(Context::new()));
    assert!(handler.dispatch("getblockcount", &json!([])).is_ok());
}
