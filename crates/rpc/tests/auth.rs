//! Authentication coverage for the synchronous RPC server.
extern crate alloc;

use alloc::sync::Arc;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use bitcoin_rs_rpc::auth::constant_time_eq;
use bitcoin_rs_rpc::{Auth, Context, Handler, RpcServer};
use sonic_rs::json;

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
    };
    thread::spawn(move || {
        let _ignored = server.serve();
    });
    Ok(address)
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
