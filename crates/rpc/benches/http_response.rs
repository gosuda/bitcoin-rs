//! End-to-end HTTP response timing workload.
//! Run with: `cargo bench -p bitcoin-rs-rpc --bench http_response`.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Instant;

const REQUESTS: usize = 1_000;
const BODY: &[u8] = br#"{}"#;

fn main() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let address = listener.local_addr().expect("address");
    let server = thread::spawn(move || {
        for stream in listener.incoming().take(REQUESTS) {
            let mut stream = stream.expect("accept");
            let mut request = [0; 1024];
            stream.read(&mut request).expect("request");
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                BODY.len()
            );
            stream.write_all(header.as_bytes()).expect("header");
            stream.write_all(BODY).expect("body");
        }
    });
    let start = Instant::now();
    for _ in 0..REQUESTS {
        let mut stream = TcpStream::connect(address).expect("connect");
        stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("response");
        assert!(response.ends_with(BODY));
    }
    let elapsed = start.elapsed();
    server.join().expect("server");
    println!("{REQUESTS} complete HTTP requests, {}-byte body: {elapsed:?}", BODY.len());
}
