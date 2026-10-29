//! Independent admission and route boundaries for split HTTP listeners.

use super::*;

struct RunningServer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<io::Result<()>>>,
    handler: Arc<Handler>,
}

impl RunningServer {
    fn start(context: &Arc<Context>, surface: RpcSurface, limit: usize) -> io::Result<Self> {
        let server = RpcServer::bind(
            "127.0.0.1:0",
            Arc::new(Auth::basic("alice", "secret")),
            Arc::new(Handler::new(Arc::clone(context))),
            limit,
            Duration::from_secs(5),
            true,
        )?;
        let address = server.local_addr()?;
        let handler = Arc::clone(&server.handler);
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&shutdown);
        let worker = Some(thread::spawn(move || {
            server.serve_surface_with_shutdown(stop, surface)
        }));
        Ok(Self {
            address,
            shutdown,
            worker,
            handler,
        })
    }

    fn connect(&self) -> io::Result<TcpStream> {
        let stream = TcpStream::connect(self.address)?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        Ok(stream)
    }

    fn request(&self, request: &[u8]) -> io::Result<String> {
        let mut stream = self.connect()?;
        stream.write_all(request)?;
        read_response(&mut stream)
    }

    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .expect("listener thread")
                .expect("listener exit");
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn read_response(stream: &mut TcpStream) -> io::Result<String> {
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    let mut length = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "missing HTTP head",
            ));
        }
        if let Some(value) = line.strip_prefix("Content-Length: ") {
            length = value.trim().parse().expect("response length");
        }
        let end = line == "\r\n";
        response.push_str(&line);
        if end {
            break;
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    response.push_str(&String::from_utf8_lossy(&body));
    Ok(response)
}

fn management_request() -> Vec<u8> {
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#;
    let mut request = json_rpc_head(Some(GOOD_TOKEN), body.len());
    request.extend_from_slice(body);
    request
}

#[test]
fn public_saturation_preserves_management_and_recovers() -> io::Result<()> {
    let context = Arc::new(Context::new());
    let mut public = RunningServer::start(&context, RpcSurface::Public, 2)?;
    let management = RunningServer::start(&context, RpcSurface::Management, 2)?;
    assert!(Arc::ptr_eq(
        public.handler.context(),
        management.handler.context()
    ));
    assert!(!Arc::ptr_eq(&public.handler, &management.handler));

    let mut idle = public.connect()?;
    idle.write_all(
        b"GET /api/blocks/tip/height HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
    )?;
    let response = read_response(&mut idle)?;
    assert!(
        response.contains("Access-Control-Allow-Origin: *"),
        "{response}"
    );
    let mut slow = public.connect()?;
    slow.write_all(b"G")?;
    let busy = read_response(&mut public.connect()?)?;
    assert!(
        busy.starts_with("HTTP/1.1 503 Service Unavailable"),
        "{busy}"
    );

    let response = management.request(&management_request())?;
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains("\"result\":0"), "{response}");
    let unauthorized = management.request(&json_rpc_head(None, 0))?;
    assert_eq!(unauthorized, CORE_UNAUTHORIZED);

    drop(idle);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut recovered = public.connect()?;
        recovered.write_all(
            b"GET /api/blocks/tip/height HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )?;
        let response = read_response(&mut recovered)?;
        if response.contains("Access-Control-Allow-Origin: *") {
            break;
        }
        assert!(Instant::now() < deadline, "public permit was not released");
    }
    drop(slow);
    public.stop();
    assert!(public.handler.is_stopping());
    assert!(!management.handler.is_stopping());
    assert!(
        management
            .request(&management_request())?
            .contains("\"result\":0")
    );
    let _management_idle = management.connect()?;
    let _management_slow = management.connect()?;
    let busy = read_response(&mut management.connect()?)?;
    assert!(
        busy.starts_with("HTTP/1.1 503 Service Unavailable"),
        "{busy}"
    );
    Ok(())
}

#[test]
fn split_listener_routes_are_closed_before_authentication_and_body_upload() -> io::Result<()> {
    let context = Arc::new(Context::new());
    let public = RunningServer::start(&context, RpcSurface::Public, 8)?;
    let management = RunningServer::start(&context, RpcSurface::Management, 8)?;
    for path in ["/", "/tx", "/unknown"] {
        let request = format!(
            "POST {path} HTTP/1.1\r\nAuthorization: Basic {GOOD_TOKEN}\r\nContent-Length: 4096\r\n\r\n"
        );
        assert!(
            public
                .request(request.as_bytes())?
                .starts_with("HTTP/1.1 404 Not Found")
        );
    }
    for path in ["/api/tx", "/esplora/internal/txs", "/rest/getutxos.bin"] {
        let request = format!("POST {path} HTTP/1.1\r\nContent-Length: 4096\r\n\r\n");
        assert!(
            management
                .request(request.as_bytes())?
                .starts_with("HTTP/1.1 404 Not Found")
        );
    }
    let preflight = public
        .request(b"OPTIONS /api/tx HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    assert!(preflight.starts_with("HTTP/1.1 204 No Content"));
    assert!(preflight.contains("Access-Control-Allow-Origin: *"));
    for path in [
        "/api/internal/txs",
        "/esplora/unknown",
        "/rest/unknown.json",
    ] {
        let response = public.request(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )?;
        assert!(response.starts_with("HTTP/1.1 404 Not Found"), "{response}");
    }
    Ok(())
}
