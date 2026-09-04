//! End-to-end HTTP workload benchmark.
//! Run with: `cargo bench -p bitcoin-rs-rpc --bench http_response`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Instant;
use std::thread;

use bitcoin_rs_rpc::{auth::Auth, context::Context, handlers::Handler, server::RpcServer};

fn main() {
    const REQUESTS: usize = 100;
    const REQUEST: &[u8] = b"POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic dXNlcjpwYXNz\r\nContent-Length: 52\r\nConnection: close\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockcount\"}";
    let server = RpcServer::bind("127.0.0.1:0", Arc::new(Auth::basic("user", "pass")),
        Arc::new(Handler::new(Arc::new(Context::new()))), 128, std::time::Duration::from_secs(5), false).unwrap();
    let address = server.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let join = thread::spawn(move || server.serve_with_shutdown(flag).unwrap());
    thread::sleep(std::time::Duration::from_millis(100));
    let start = Instant::now();
    for _ in 0..REQUESTS {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(REQUEST).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        assert!(response.windows(4).any(|window| window == b"\r\n\r\n"));
    }
    let elapsed = start.elapsed();
    eprintln!("{REQUESTS} complete HTTP requests, fixed JSON-RPC payload: {elapsed:?} ({:?}/request)", elapsed / REQUESTS as u32);
    stop.store(true, Ordering::Release);
    let _ = join.join();
}
