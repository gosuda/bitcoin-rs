mod listeners;

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
            RpcSurface::Shared,
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
    let result = read_whole_request(
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
    let result = read_whole_request(
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
    let server = accept_test_server()?;
    let handler = Arc::clone(&server.handler);
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);
    let (parked, ready) = crossbeam_channel::bounded(1);
    let handle = thread::spawn(move || {
        server.serve_accept_loop(&shutdown_clone.into(), RpcSurface::Shared, |listener| {
            let result = listener.accept();
            if result
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
            {
                let _ = parked.try_send(());
            }
            result
        })
    });
    ready
        .recv_timeout(Duration::from_secs(3))
        .expect("idle accept");
    thread::sleep(Duration::from_millis(45));
    let start = Instant::now();
    shutdown.store(true, Ordering::Release);
    handle.join().expect("join serve thread")?;
    let elapsed = start.elapsed();
    eprintln!("idle RPC listener shutdown: {elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(80),
        "idle shutdown took {elapsed:?}"
    );
    assert!(handler.is_stopping());
    Ok(())
}

#[test]
fn shutdown_before_serving_does_not_admit_a_queued_connection() -> io::Result<()> {
    let server = accept_test_server()?;
    let handler = Arc::clone(&server.handler);
    let _queued = TcpStream::connect(server.local_addr()?)?;
    let shutdown = Arc::new(AtomicBool::new(true));
    let mut attempts = 0;
    server.serve_accept_loop(&shutdown.into(), RpcSurface::Shared, |listener| {
        attempts += 1;
        listener.accept()
    })?;
    assert_eq!(attempts, 0);
    assert!(handler.is_stopping());
    Ok(())
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
    let result = read_whole_request(&mut reader, Duration::from_secs(3), Duration::from_secs(3));
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
                RpcSurface::Shared,
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
            RpcSurface::Shared,
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
            RpcSurface::Shared,
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
    let handler = Handler::new(Arc::new(Context::new()));
    let executed = handle_json(
        &handler,
        br#"{"jsonrpc":"2.0","id":1,"method":"setnetworkactive","params":[false]}"#,
    );
    assert_eq!(
        executed.status, 200,
        "fixture: the probe method is dispatched"
    );
    assert!(
        !handler.context().network.p2p.network_active(),
        "fixture: dispatch flips the flag"
    );
    handler.context().network.p2p.set_network_active(true);

    for request in [
        br#"{"jsonrpc":"9.0","id":1,"method":"setnetworkactive","params":[false]}"#.as_slice(),
        br#"{"jsonrpc":2,"id":1,"method":"setnetworkactive","params":[false]}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"setnetworkactive","params":7}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"params":[false]}"#.as_slice(),
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
        assert!(
            handler.context().network.p2p.network_active(),
            "a rejected envelope must not execute the method: {request:?}"
        );
    }
}

#[test]
fn an_empty_batch_answers_an_empty_ok_batch() {
    let handler = Handler::new(Arc::new(Context::new()));
    let response = handle_json(&handler, b"[]");
    let body = response.body.expect("empty batch replies");

    assert_eq!(response.status, 200);
    assert_eq!(body, json!([]), "an empty batch answers []: {body:?}");
}

#[test]
fn a_top_level_scalar_is_a_parse_error() {
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
    let handler = Handler::new(Arc::new(Context::new()));
    let response = handle_json(&handler, br#"{"id":1,"method":7,"params":[]}"#);
    assert_eq!(response.status, 400, "legacy -32600 maps to HTTP 400");
}

#[test]
fn legacy_method_not_found_maps_to_http_404() {
    let handler = Handler::new(Arc::new(Context::new()));
    let response = handle_json(&handler, br#"{"id":1,"method":"missing","params":[]}"#);
    assert_eq!(response.status, 404, "legacy -32601 maps to HTTP 404");
}

#[test]
fn legacy_other_errors_keep_http_500() {
    let handler = Handler::new(Arc::new(Context::new()));
    let response = handle_json(&handler, br#"{"id":1,"method":"getblock","params":[]}"#);
    assert_eq!(response.status, 500, "legacy -32602 keeps HTTP 500");
}

#[test]
fn json_rpc_2_dispatch_errors_still_answer_http_200() {
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
fn json_rpc_2_post_classification_error_keeps_the_v2_envelope() {
    let handler = Handler::new(Arc::new(Context::new()));
    let response = handle_json(
        &handler,
        br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":7}"#,
    );
    let body = response.body.expect("JSON-RPC response body");

    assert_eq!(response.status, 400);
    assert_eq!(
        body.get("jsonrpc").and_then(Value::as_str),
        Some("2.0"),
        "a post-classification violation keeps the v2 envelope: {body:?}"
    );
    assert!(body.get("result").is_none(), "v2 errors omit result");
    assert_eq!(
        body.get("error")
            .and_then(|error| error.get("code"))
            .and_then(Value::as_i64),
        Some(-32600)
    );
}

#[test]
fn an_explicit_null_method_is_missing() {
    let handler = Handler::new(Arc::new(Context::new()));
    let response = handle_json(
        &handler,
        br#"{"jsonrpc":"2.0","id":1,"method":null,"params":[]}"#,
    );
    let body = response.body.expect("JSON-RPC response body");

    assert_eq!(
        body.get("error")
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str),
        Some("Missing method"),
        "Core's exact message for a null method: {body:?}"
    );
}

#[test]
fn absent_and_null_params_dispatch_as_an_empty_array() {
    let handler = Handler::new(Arc::new(Context::new()));
    for request in [
        br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount"}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":null}"#.as_slice(),
    ] {
        let response = handle_json(&handler, request);
        let body = response.body.expect("no-argument call replies");
        assert_eq!(response.status, 200, "{request:?}");
        assert!(
            body.get("result").is_some(),
            "a null params field must dispatch with defaults: {body:?}"
        );
    }
}

#[test]
fn batch_members_keep_per_member_envelope_dialect() {
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

/// Reads one request the way `serve_connection` does, minus the
/// authentication gate between the two phases.
fn read_whole_request(
    reader: &mut BufReader<RequestDeadlineStream>,
    head_timeout: Duration,
    body_timeout: Duration,
) -> Result<Option<HttpRequest>, RequestReadError> {
    match read_request_head(reader, head_timeout)? {
        Some(head) => read_request_body(reader, body_timeout, head).map(Some),
        None => Ok(None),
    }
}

/// What one loopback client saw while `serve_connection` handled its request.
struct Exchange {
    /// Bytes received until the server's FIN or a read failure.
    response: String,
    /// Whether the server closed its write side. A read timeout means it
    /// neither answered nor closed.
    eof: bool,
    /// Time from the first write until the read ended.
    elapsed: Duration,
    /// The connection handler's own verdict, taken after the client hangs up.
    served: io::Result<()>,
}

/// Serves one loopback connection with `serve_connection`, writes `request` and nothing
/// more, and reports what the client saw.
///
/// The client keeps its side open until the response ends, as a client still uploading
/// would.
fn exchange(request: &[u8]) -> io::Result<Exchange> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut client = TcpStream::connect(listener.local_addr()?)?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    let server = thread::spawn(move || -> io::Result<()> {
        let (stream, _) = listener.accept()?;
        serve_connection(
            stream,
            &Auth::basic("alice", "secret"),
            &Handler::new(Arc::new(Context::new())),
            false,
            Duration::from_secs(30),
            RpcSurface::Shared,
        )
    });
    let started = Instant::now();
    client.write_all(request)?;
    let mut response = Vec::new();
    let mut eof = false;
    let mut chunk = [0_u8; 1_024];
    loop {
        match client.read(&mut chunk) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(_) => break,
        }
    }
    let elapsed = started.elapsed();
    drop(client);
    let served = server.join().expect("server thread");
    Ok(Exchange {
        response: String::from_utf8_lossy(&response).into_owned(),
        eof,
        elapsed,
        served,
    })
}

/// `Authorization` tokens for `alice:secret` and `alice:bad`.
const GOOD_TOKEN: &str = "YWxpY2U6c2VjcmV0";
const BAD_TOKEN: &str = "YWxpY2U6YmFk";

/// Core's 401 for JSON-RPC: the challenge, its default error type, an empty
/// body, a close, and no `Date`.
const CORE_UNAUTHORIZED: &str = "HTTP/1.1 401 Unauthorized\r\n\
    WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n\
    Content-Type: text/html; charset=ISO-8859-1\r\n\
    Content-Length: 0\r\n\
    Connection: close\r\n\r\n";

fn json_rpc_head(token: Option<&str>, content_length: usize) -> Vec<u8> {
    let authorization = token.map_or_else(String::new, |token| {
        format!("Authorization: Basic {token}\r\n")
    });
    format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\n{authorization}Content-Length: {content_length}\r\n\r\n"
    )
    .into_bytes()
}

/// A JSON-RPC request without valid credentials is answered from its head: the client
/// withholds all 16 MiB it declared and still gets Core's exact 401 and a FIN.
///
/// A wrong password waits out Core's brute-force delay first.
#[test]
fn unauthorized_json_rpc_is_answered_from_the_head_with_core_s_tuple() -> io::Result<()> {
    for (token, delayed) in [(None, false), (Some(BAD_TOKEN), true)] {
        let seen = exchange(&json_rpc_head(token, MAX_BODY_BYTES))?;
        assert_eq!(seen.response, CORE_UNAUTHORIZED, "token {token:?}");
        assert!(seen.eof, "the server must close after the 401: {token:?}");
        assert!(seen.served.is_ok(), "a 401 is a served request: {token:?}");
        if delayed {
            assert!(
                seen.elapsed >= WRONG_CREDENTIALS_DELAY,
                "wrong credentials answered in {:?}",
                seen.elapsed
            );
        }
    }
    Ok(())
}

/// Bytes pipelined behind an unauthorized request are discarded, never
/// served: the one response is the 401.
#[test]
fn unauthorized_request_never_serves_pipelined_bytes() -> io::Result<()> {
    let mut request = json_rpc_head(None, 2);
    request.extend_from_slice(b"{}GET /rest/chaininfo.json HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let seen = exchange(&request)?;
    assert_eq!(seen.response, CORE_UNAUTHORIZED);
    assert!(seen.eof);
    Ok(())
}

/// A 401 witnesses `authenticate_json_rpc_head` on a real loopback pair:
/// the one declared byte is prebuffered before the call, the client stays
/// open through the drain, and the call consumes the buffer without the
/// one-second budget hold before the client sees the 401 and EOF.
#[test]
fn unauthorized_request_with_buffered_body_returns_without_the_drain_hold() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut client = TcpStream::connect(listener.local_addr()?)?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (server, _) = listener.accept()?;
    let mut request = json_rpc_head(None, 1);
    request.extend_from_slice(b"X");
    client.write_all(&request)?;
    let mut reader = BufReader::new(RequestDeadlineStream::new(server, Duration::from_secs(30)));
    let head = match read_request_head(&mut reader, REQUEST_HEAD_TIMEOUT) {
        Ok(Some(head)) => head,
        Ok(None) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "missing head")),
        Err(RequestReadError::Io(error)) => return Err(error),
        Err(RequestReadError::RestBodyTooLarge) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
        }
    };
    assert_eq!(head.content_length, 1);
    reader.get_mut().reset_deadline(REQUEST_HEAD_TIMEOUT);
    assert_eq!(
        reader.fill_buf()?,
        b"X".as_slice(),
        "declared byte must be prebuffered before the 401"
    );
    let started = Instant::now();
    let handled = authenticate_json_rpc_head(&Auth::basic("alice", "secret"), &mut reader, &head)?;
    let elapsed = started.elapsed();
    assert!(handled, "unauthorized head must be handled");
    assert!(
        reader.buffer().is_empty(),
        "drain must consume the prebuffered byte: {:?}",
        reader.buffer()
    );
    assert!(
        elapsed < DRAIN_BUDGET,
        "a buffered body must not wait out the drain budget: {elapsed:?}"
    );
    let mut response = String::new();
    client.read_to_string(&mut response)?;
    assert_eq!(response, CORE_UNAUTHORIZED);
    Ok(())
}

/// Runs the unauthorized path on the server side of one loopback pair and returns the
/// client's view of the response plus the next `take` bytes the server reads once the
/// handler returns.
///
/// The server thread starts first and reads while the client writes, so neither side
/// waits on a buffer the other has not drained.
fn serve_unauthorized(request: &[u8], take: usize) -> io::Result<(String, Vec<u8>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let server = thread::spawn(move || -> io::Result<Vec<u8>> {
        let (stream, _) = listener.accept()?;
        let mut reader =
            BufReader::new(RequestDeadlineStream::new(stream, Duration::from_secs(30)));
        let head = match read_request_head(&mut reader, REQUEST_HEAD_TIMEOUT) {
            Ok(Some(head)) => head,
            Ok(None) => {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "missing head"));
            }
            Err(RequestReadError::Io(error)) => return Err(error),
            Err(RequestReadError::RestBodyTooLarge) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
            }
        };
        let handled =
            authenticate_json_rpc_head(&Auth::basic("alice", "secret"), &mut reader, &head)?;
        assert!(handled, "unauthorized head must be handled");
        let mut next = vec![0_u8; take];
        reader.read_exact(&mut next)?;
        Ok(next)
    });
    let mut client = TcpStream::connect(addr)?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    client.write_all(request)?;
    client.shutdown(Shutdown::Write)?;
    let mut response = String::new();
    client.read_to_string(&mut response)?;
    let next = server.join().expect("server thread")?;
    Ok((response, next))
}

/// The drain consumes exactly the declared body, even at the cap, so the
/// bytes pipelined behind it are still on the stream for the next read.
#[test]
fn unauthorized_drain_consumes_exactly_the_declared_body() -> io::Result<()> {
    let mut request = json_rpc_head(None, MAX_DRAIN_BYTES);
    request.extend_from_slice(&vec![b'X'; MAX_DRAIN_BYTES]);
    request.extend_from_slice(b"NEXT");
    let (response, next) = serve_unauthorized(&request, 4)?;
    assert_eq!(response, CORE_UNAUTHORIZED);
    assert_eq!(next, b"NEXT");
    Ok(())
}

/// A declared body above the cap is drained only up to the cap: the peer
/// still gets the 401 and a clean close, and the bytes past the cap stay
/// unread on the stream.
#[test]
fn unauthorized_drain_stops_at_the_cap_for_an_oversized_body() -> io::Result<()> {
    const TAIL: usize = 4 * 1_024;
    let mut request = json_rpc_head(None, MAX_DRAIN_BYTES + TAIL);
    request.extend_from_slice(&vec![b'X'; MAX_DRAIN_BYTES]);
    request.extend_from_slice(&vec![b'Y'; TAIL]);
    let (response, rest) = serve_unauthorized(&request, TAIL)?;
    assert_eq!(response, CORE_UNAUTHORIZED);
    assert_eq!(rest, vec![b'Y'; TAIL]);
    Ok(())
}

/// A head that fails HTTP framing is a 400 whether or not the client sent
/// credentials: authentication runs only on a well-framed head.
#[test]
fn head_framing_errors_keep_their_400_without_credentials() -> io::Result<()> {
    let oversize = json_rpc_head(None, MAX_BODY_BYTES + 1);
    for (name, request) in [
        (
            "chunked",
            b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
        ),
        (
            "missing length",
            b"POST / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        ),
        (
            "conflicting length",
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n"
                .to_vec(),
        ),
        ("oversize length", oversize),
    ] {
        let seen = exchange(&request)?;
        assert!(
            seen.response.starts_with("HTTP/1.1 400 Bad Request"),
            "{name}: {}",
            seen.response
        );
    }
    Ok(())
}

/// Valid credentials pass the gate and the body is then read: a body cut
/// short is the framing error it always was, not a 401 and not a hang.
#[test]
fn authorized_request_proceeds_to_body_framing() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut client = TcpStream::connect(listener.local_addr()?)?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    let server = thread::spawn(move || -> io::Result<()> {
        let (stream, _) = listener.accept()?;
        serve_connection(
            stream,
            &Auth::basic("alice", "secret"),
            &Handler::new(Arc::new(Context::new())),
            false,
            Duration::from_secs(30),
            RpcSurface::Shared,
        )
    });
    let mut request = json_rpc_head(Some(GOOD_TOKEN), 16);
    request.extend_from_slice(b"{}");
    client.write_all(&request)?;
    client.shutdown(Shutdown::Write)?;
    let mut response = Vec::new();
    client.read_to_end(&mut response)?;
    let _ignored = server.join();
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 400 Bad Request"), "{text}");
    Ok(())
}

fn accept_test_server() -> io::Result<RpcServer> {
    RpcServer::bind(
        "127.0.0.1:0",
        Arc::new(Auth::basic("alice", "secret")),
        Arc::new(Handler::new(Arc::new(Context::new()))),
        4,
        Duration::from_secs(1),
        false,
    )
}

/// Arrival phases start after a real `WouldBlock`, so the former 100-ms sleep
/// cannot hide behind a connection queued before the accept thread started.
#[test]
fn idle_accept_is_prompt_across_arrival_phases() -> io::Result<()> {
    let server = accept_test_server()?;
    let addr = server.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&shutdown);
    let (idle_tx, idle_rx) = crossbeam_channel::bounded(1);
    let (accepted_tx, accepted_rx) = crossbeam_channel::unbounded();
    let handle = thread::spawn(move || {
        server.serve_accept_loop(&stop.into(), RpcSurface::Shared, |listener| {
            let result = listener.accept();
            match &result {
                Ok(_) => {
                    let _ = accepted_tx.send(Instant::now());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let _ = idle_tx.try_send(());
                }
                Err(_) => {}
            }
            result
        })
    });
    let result = (|| -> io::Result<Vec<Duration>> {
        let mut latencies = Vec::new();
        for phase in [0, 13, 37, 61, 89] {
            idle_rx
                .recv_timeout(Duration::from_secs(3))
                .expect("idle listener");
            thread::sleep(Duration::from_millis(phase));
            let start = Instant::now();
            let client = TcpStream::connect(addr)?;
            let accepted = accepted_rx
                .recv_timeout(Duration::from_secs(3))
                .expect("accepted connection");
            latencies.push(accepted.duration_since(start));
            drop(client);
        }
        Ok(latencies)
    })();
    shutdown.store(true, Ordering::Release);
    handle.join().expect("accept thread")?;
    let latencies = result?;
    eprintln!("new-connection accept delays at phases 0/13/37/61/89 ms: {latencies:?}");
    assert!(
        latencies
            .iter()
            .all(|latency| *latency < Duration::from_millis(80)),
        "new connections waited on an idle accept cadence: {latencies:?}"
    );
    Ok(())
}

#[test]
fn accept_recovers_from_resource_and_connection_errors() -> io::Result<()> {
    let server = accept_test_server()?;
    let addr = server.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&shutdown);
    let handle = thread::spawn(move || {
        let mut errors = vec![
            io::Error::from(io::ErrorKind::Interrupted),
            io::Error::from(io::ErrorKind::ConnectionAborted),
            io::Error::from(io::ErrorKind::ConnectionReset),
            io::Error::from(io::ErrorKind::PermissionDenied),
            io::Error::from(io::ErrorKind::Unsupported),
            io::Error::other("pending protocol error"),
        ];
        #[cfg(unix)]
        errors.extend([
            io::Error::from_raw_os_error(rustix::io::Errno::MFILE.raw_os_error()),
            io::Error::from_raw_os_error(rustix::io::Errno::NFILE.raw_os_error()),
        ]);
        #[cfg(target_os = "linux")]
        {
            let error = io::Error::from_raw_os_error(rustix::io::Errno::OPNOTSUPP.raw_os_error());
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            errors.push(error);
        }
        #[cfg(windows)]
        errors.push(io::Error::from_raw_os_error(10024));
        let mut errors = errors.into_iter();
        let start = Instant::now();
        server.serve_accept_loop(&stop.into(), RpcSurface::Shared, |listener| {
            if let Some(error) = errors.next() {
                return Err(error);
            }
            assert!(start.elapsed() >= ACCEPT_ERROR_BACKOFF * 3);
            listener.accept()
        })
    });
    let response = (|| -> io::Result<String> {
        let mut client = TcpStream::connect(addr)?;
        client.set_read_timeout(Some(Duration::from_secs(5)))?;
        client.write_all(
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        )?;
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        Ok(response)
    })();
    shutdown.store(true, Ordering::Release);
    handle.join().expect("accept thread")?;
    assert!(response?.starts_with("HTTP/1.1 401"));
    Ok(())
}

#[test]
fn repeated_accept_errors_back_off_and_observe_shutdown() -> io::Result<()> {
    let server = accept_test_server()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&shutdown);
    let start = Instant::now();
    let mut attempts = 0;
    server.serve_accept_loop(&shutdown.into(), RpcSurface::Shared, |_| {
        attempts += 1;
        if attempts == 3 {
            stop.store(true, Ordering::Release);
        }
        Err(io::Error::other("resource temporarily exhausted"))
    })?;
    assert_eq!(attempts, 3);
    assert!(start.elapsed() >= ACCEPT_ERROR_BACKOFF * 3);
    Ok(())
}

#[test]
fn invalid_listener_errors_are_returned() -> io::Result<()> {
    for kind in [io::ErrorKind::InvalidInput, io::ErrorKind::NotConnected] {
        let server = accept_test_server()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut attempts = 0;
        let result = server.serve_accept_loop(&shutdown.into(), RpcSurface::Shared, |_| {
            attempts += 1;
            Err(kind.into())
        });
        assert_eq!(result.expect_err("fatal listener error").kind(), kind);
        assert_eq!(attempts, 1);
    }
    Ok(())
}
