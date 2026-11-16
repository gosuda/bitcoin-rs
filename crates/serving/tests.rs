mod auth {
    extern crate alloc;

    use alloc::sync::Arc;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use crate::support::TestError;
    use bitcoin_rs_serving::auth::constant_time_eq;
    use bitcoin_rs_serving::context::Context;
    use bitcoin_rs_serving::{Auth, Handler, RpcServer, RpcSurface};
    use sonic_rs::{JsonContainerTrait, JsonValueTrait};

    type TestResult<T = ()> = Result<T, TestError>;

    #[test]
    fn basic_auth_accepts_and_rejects_requests() -> TestResult {
        let address = spawn(Auth::basic("alice", "secret"))?;
        let body = r#"{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}"#;

        let ok = request(address, "YWxpY2U6c2VjcmV0", body)?;
        assert!(ok.starts_with("HTTP/1.1 200 OK"));
        assert!(ok.contains("\"result\":0"));

        let rejected = request(address, "YWxpY2U6YmFk", body)?;
        assert!(rejected.starts_with("HTTP/1.1 401 Unauthorized"));
        assert_eq!(
            rejected
                .lines()
                .find_map(|line| line.strip_prefix("WWW-Authenticate: ")),
            Some("Basic realm=\"jsonrpc\""),
            "the 401 must carry Core's challenge: {rejected}"
        );
        assert_eq!(
            rejected
                .lines()
                .find_map(|line| line.strip_prefix("Content-Type: ")),
            Some("text/html; charset=ISO-8859-1"),
            "the 401 must carry Core's default error type: {rejected}"
        );
        assert!(
            rejected.lines().any(|line| line == "Content-Length: 0"),
            "the 401 body must be empty: {rejected}"
        );
        Ok(())
    }

    #[test]
    fn json_rpc_2_error_is_http_200_without_result() -> TestResult {
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
    fn legacy_error_has_core_envelope_and_http_error() -> TestResult {
        let address = spawn(Auth::basic("alice", "secret"))?;
        let body = r#"{"method":"missing","params":[],"id":7}"#;
        let response = request(address, "YWxpY2U6c2VjcmV0", body)?;
        let payload = response.split_once("\r\n\r\n").ok_or("missing body")?.1;
        let value: sonic_rs::Value = sonic_rs::from_str(payload)?;

        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        assert!(value.get("jsonrpc").is_none());
        assert!(value.get("error").is_some());
        assert!(
            value
                .get("result")
                .is_some_and(sonic_rs::JsonValueTrait::is_null)
        );
        Ok(())
    }

    #[test]
    fn json_rpc_2_notification_returns_http_204() -> TestResult {
        let address = spawn(Auth::basic("alice", "secret"))?;
        let body = r#"{"jsonrpc":"2.0","method":"getblockcount","params":[]}"#;
        let response = request(address, "YWxpY2U6c2VjcmV0", body)?;

        assert!(response.starts_with("HTTP/1.1 204 No Content"));
        assert!(response.ends_with("\r\n\r\n"));
        Ok(())
    }

    #[test]
    fn json_rpc_2_batch_returns_an_array_and_excludes_notifications() -> TestResult {
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
    fn notification_only_batch_returns_http_204() -> TestResult {
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
    fn malformed_json_uses_core_legacy_parse_error_envelope() -> TestResult {
        let address = spawn(Auth::basic("alice", "secret"))?;
        let response = request(address, "YWxpY2U6c2VjcmV0", "{")?;
        let payload = response.split_once("\r\n\r\n").ok_or("missing body")?.1;
        let value: sonic_rs::Value = sonic_rs::from_str(payload)?;

        assert!(response.starts_with("HTTP/1.1 500 Internal Server Error"));
        assert!(value.get("jsonrpc").is_none());
        assert!(
            value
                .get("result")
                .is_some_and(sonic_rs::JsonValueTrait::is_null)
        );
        assert_eq!(
            value
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(sonic_rs::JsonValueTrait::as_i64),
            Some(-32_700)
        );
        assert!(
            value
                .get("id")
                .is_some_and(sonic_rs::JsonValueTrait::is_null)
        );
        Ok(())
    }

    #[test]
    fn rest_enabled_does_not_require_authentication() -> TestResult {
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
    fn rest_disabled_returns_not_found_without_authentication() -> TestResult {
        let address = spawn_with_rest(Auth::basic("alice", "secret"), false)?;
        let response = request_get(address, "/rest/chaininfo.json", "close")?;
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        Ok(())
    }

    #[test]
    fn post_json_rpc_still_requires_and_accepts_authentication() -> TestResult {
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
    fn non_rest_get_returns_not_found_without_authentication() -> TestResult {
        let address = spawn_with_rest(Auth::basic("alice", "secret"), true)?;
        let response = request_get(address, "/", "close")?;
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        Ok(())
    }

    #[test]
    fn public_esplora_success_and_error_responses_allow_cross_origin_reads() -> TestResult {
        let address = spawn(Auth::basic("alice", "secret"))?;
        for path in ["/api/blocks/tip/height", "/api/not-an-esplora-route"] {
            let response = request_get(address, path, "close")?;
            assert!(response.contains("Access-Control-Allow-Origin: *\r\n"));
            assert!(response.contains("Access-Control-Expose-Headers: X-Total-Results\r\n"));
        }
        Ok(())
    }

    #[test]
    fn esplora_cors_headers_do_not_leak_to_other_listener_surfaces() -> TestResult {
        let address = spawn(Auth::basic("alice", "secret"))?;
        for path in ["/", "/rest/chaininfo.json", "/esplora/internal/mempool/txs"] {
            let response = request_get(address, path, "close")?;
            assert!(
                !response.contains("Access-Control-"),
                "CORS leaked on {path}"
            );
        }
        Ok(())
    }

    #[test]
    fn public_esplora_options_returns_cors_preflight_response() -> TestResult {
        let address = spawn(Auth::basic("alice", "secret"))?;
        let response = request_options(address, "/api/blocks/tip/height")?;

        assert!(response.starts_with("HTTP/1.1 204 No Content"));
        assert!(response.contains("Access-Control-Allow-Origin: *\r\n"));
        assert!(response.contains("Access-Control-Expose-Headers: X-Total-Results\r\n"));
        assert!(response.contains("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"));
        assert!(response.contains("Access-Control-Allow-Headers: Content-Type\r\n"));
        assert!(!response.contains("Content-Length:"));
        assert!(response.ends_with("\r\n\r\n"));
        Ok(())
    }

    #[test]
    fn options_never_falls_through_to_json_rpc_or_non_public_surfaces() -> TestResult {
        let address = spawn(Auth::basic("alice", "secret"))?;
        for path in ["/", "/rest/chaininfo.json", "/esplora/internal/mempool/txs"] {
            let response = request_options(address, path)?;
            assert!(
                response.starts_with("HTTP/1.1 404 Not Found"),
                "unexpected OPTIONS response for {path}: {response}"
            );
            assert!(
                !response.contains("Access-Control-"),
                "CORS leaked on {path}"
            );
            assert!(
                !response.contains("\"result\""),
                "JSON-RPC handled OPTIONS {path}"
            );
        }
        Ok(())
    }

    #[test]
    fn rest_keep_alive_serves_two_requests() -> TestResult {
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
    fn cookie_auth_accepts_file_backed_secret() -> TestResult {
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

    fn withheld_body_request(
        address: std::net::SocketAddr,
        credentials: Option<&str>,
    ) -> TestResult<(String, Duration)> {
        let mut stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let authorization = credentials
            .map(|value| format!("Authorization: Basic {value}\r\n"))
            .unwrap_or_default();
        let started = std::time::Instant::now();
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: localhost\r\n{authorization}\
         Content-Length: 16777216\r\n\r\n"
        )?;
        stream.flush()?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok((response, started.elapsed()))
    }

    #[test]
    fn unauthorized_request_is_answered_before_its_body_is_read() -> TestResult {
        let address = spawn(Auth::basic("alice", "secret"))?;
        for credentials in [None, Some("YWxpY2U6YmFk")] {
            let (response, elapsed) = withheld_body_request(address, credentials)?;
            assert!(
                elapsed < Duration::from_secs(2),
                "{credentials:?} took {elapsed:?}"
            );
            assert_eq!(
                response,
                "HTTP/1.1 401 Unauthorized\r\n\
             WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n\
             Content-Type: text/html; charset=ISO-8859-1\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\r\n",
                "{credentials:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn framing_errors_precede_authentication() -> TestResult {
        let address = spawn(Auth::basic("alice", "secret"))?;
        for head in [
            "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 16777217\r\n\r\n",
        ] {
            let mut stream = TcpStream::connect(address)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.write_all(head.as_bytes())?;
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            assert!(
                response.starts_with("HTTP/1.1 400 Bad Request"),
                "{head:?}: {response}"
            );
        }
        Ok(())
    }

    #[test]
    fn authorized_request_with_a_truncated_body_is_a_framing_error() -> TestResult {
        let address = spawn(Auth::basic("alice", "secret"))?;
        let mut stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\n\
         Content-Length: 16\r\n\r\n{{}}"
        )?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request"),
            "{response}"
        );
        Ok(())
    }

    #[test]
    fn pool_management_requires_authentication_and_management_surface() -> TestResult {
        let body = r#"{"jsonrpc":"2.0","method":"getpoolinfo","params":[],"id":1}"#;

        let row = bitcoin_rs_serving::manifest::MANIFEST
            .iter()
            .find(|entry| entry.name == "getpoolinfo")
            .ok_or("getpoolinfo must be a registered method")?;
        assert_eq!(
            row.feature, "pool",
            "getpoolinfo must stay a pool-gated method"
        );

        let management = spawn_on_surface(Auth::basic("alice", "secret"), RpcSurface::Management)?;
        let authorized = request(management, "YWxpY2U6c2VjcmV0", body)?;
        assert!(
            authorized.starts_with("HTTP/1.1 200 OK"),
            "authorized management request must reach the pool handler: {authorized}"
        );
        let payload = authorized.split_once("\r\n\r\n").ok_or("missing body")?.1;
        let value: sonic_rs::Value = sonic_rs::from_str(payload)?;
        assert_eq!(value.get("jsonrpc").and_then(|v| v.as_str()), Some("2.0"));
        let error = value
            .get("error")
            .ok_or("pool refusal without a ledger must be an error")?;
        #[cfg(feature = "pool")]
        {
            assert_eq!(
                error.get("code").and_then(sonic_rs::JsonValueTrait::as_i64),
                Some(-32_603),
                "disabled pool must answer MethodDisabled: {payload}"
            );
            assert!(
                error
                    .get("message")
                    .and_then(|message| message.as_str())
                    .is_some_and(|message| message.contains("Pool service is disabled")),
                "disabled pool must not fabricate status: {payload}"
            );
        }
        #[cfg(not(feature = "pool"))]
        {
            assert_eq!(
                error.get("code").and_then(sonic_rs::JsonValueTrait::as_i64),
                Some(-32_601),
                "unshipped pool method must answer MethodNotFound: {payload}"
            );
            assert!(
                error
                    .get("message")
                    .and_then(|message| message.as_str())
                    .is_some_and(|message| message.contains("getpoolinfo")),
                "unshipped pool method must name the method: {payload}"
            );
        }
        assert!(value.get("result").is_none());

        let missing = request_post(management, body, None, "close")?;
        assert!(
            missing.starts_with("HTTP/1.1 401 Unauthorized"),
            "management surface must refuse unauthenticated pool access: {missing}"
        );
        let wrong = request_post(management, body, Some("YWxpY2U6YmFk"), "close")?;
        assert!(
            wrong.starts_with("HTTP/1.1 401 Unauthorized"),
            "management surface must refuse wrong credentials: {wrong}"
        );

        let public = spawn_on_surface(Auth::basic("alice", "secret"), RpcSurface::Public)?;
        let refused = request(public, "YWxpY2U6c2VjcmV0", body)?;
        assert!(
            refused.starts_with("HTTP/1.1 404 Not Found"),
            "public surface must not route pool JSON-RPC even with valid credentials: {refused}"
        );
        Ok(())
    }

    fn spawn_on_surface(auth: Auth, surface: RpcSurface) -> TestResult<std::net::SocketAddr> {
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
            rest_enabled: false,
        };
        let shutdown = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
        thread::spawn(move || {
            let _ignored = server.serve_surface_with_shutdown(shutdown, surface);
        });
        Ok(address)
    }

    fn spawn(auth: Auth) -> TestResult<std::net::SocketAddr> {
        spawn_with_rest(auth, false)
    }

    fn spawn_with_rest(auth: Auth, rest_enabled: bool) -> TestResult<std::net::SocketAddr> {
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
        };
        let shutdown = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
        thread::spawn(move || {
            let _ignored = server.serve_with_shutdown(shutdown);
        });
        Ok(address)
    }

    fn request_get(
        address: std::net::SocketAddr,
        path: &str,
        connection: &str,
    ) -> TestResult<String> {
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
    ) -> TestResult<String> {
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
    fn request_options(address: std::net::SocketAddr, path: &str) -> TestResult<String> {
        let mut stream = TcpStream::connect(address)?;
        write!(
            stream,
            "OPTIONS {path} HTTP/1.1\r\nHost: localhost\r\nOrigin: https://wallet.example\r\n\
         Access-Control-Request-Method: GET\r\nConnection: close\r\n\r\n"
        )?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }
    fn read_response(reader: &mut BufReader<TcpStream>) -> TestResult<String> {
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

    fn request(address: std::net::SocketAddr, credentials: &str, body: &str) -> TestResult<String> {
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
}
mod core_compat {
    extern crate alloc;

    use crate::support;

    use crate::mining_fixture;

    use alloc::sync::Arc;

    use bitcoin_rs_consensus::header_rules::ChainWork;
    use bitcoin_rs_consensus::primitives::{
        BlockImage, Hash256, Network, client_version, consensus_bytes,
    };
    use bitcoin_rs_execution::chain::{NodeId, TipSnapshot};
    use bitcoin_rs_serving::Handler;
    use bitcoin_rs_serving::context::Context;
    use bitcoin_rs_serving::mining::{
        BlockTemplateRequest, BlockTemplateResult, BlockValidationResult, MiningCapability,
        MiningControl, MiningControlError, MiningInfo, TemplateMutation,
    };
    use bitcoin_rs_wire::FEATURE_VERSION;
    use bitcoin_rs_wire::wire::PROTOCOL_VERSION;
    use sonic_rs::{JsonContainerTrait as _, JsonValueMutTrait as _, JsonValueTrait as _, json};

    fn typed<T: serde::de::DeserializeOwned>(
        value: &sonic_rs::Value,
    ) -> Result<T, crate::support::TestError> {
        let text = sonic_rs::to_string(value)?;
        Ok(sonic_rs::from_str(&text)?)
    }

    fn tipped_context() -> Arc<Context> {
        let ctx = Arc::new(Context::new());
        let tip = TipSnapshot {
            tip_id: NodeId::new(0),
            height: 42,
            chainwork: ChainWork::ZERO,
            hash: Hash256::from_le_bytes(&[42_u8; 32]),
            chain_tx_count: bitcoin_rs_execution::chain::ChainTxCount::UNKNOWN,
        };
        ctx.chain.chain_tip.store(Some(Arc::new(tip.clone())));
        ctx.chain.applied_tip.store(Some(Arc::new(tip)));
        ctx
    }

    #[test]
    fn chain_state_responses_deserialize_into_pinned_types() -> Result<(), crate::support::TestError>
    {
        let handler = Handler::new(tipped_context());

        let info = support::compare::typed_getblockchain_info(
            sonic_rs::to_string(&handler.dispatch("getblockchaininfo", &json!([]))?)?.as_bytes(),
        )?;
        assert_eq!(info.chain, "main");
        assert_eq!(info.blocks, 42);
        assert_eq!(info.headers, 42);
        assert_ne!(info.best_block_hash, "");
        assert_ne!(info.bits, "");
        assert_ne!(info.target, "");
        assert_ne!(info.chain_work, "");
        assert_eq!(info.warnings, Vec::<String>::new());

        let difficulty: corepc_types::v31::GetDifficulty =
            typed(&handler.dispatch("getdifficulty", &json!([]))?)?;
        assert!((difficulty.0 - 0.0).abs() < f64::EPSILON);

        let count: corepc_types::v31::GetBlockCount =
            typed(&handler.dispatch("getblockcount", &json!([]))?)?;
        assert_eq!(count.0, 42);

        let best: corepc_types::v31::GetBestBlockHash =
            typed(&handler.dispatch("getbestblockhash", &json!([]))?)?;
        assert_eq!(best.0, info.best_block_hash);

        let tips: corepc_types::v31::GetChainTips =
            typed(&handler.dispatch("getchaintips", &json!([]))?)?;
        assert!(
            tips.0
                .iter()
                .any(|tip| tip.status == corepc_types::v31::ChainTipsStatus::Active)
        );

        let stats: corepc_types::v31::GetChainTxStats =
            typed(&handler.dispatch("getchaintxstats", &json!([]))?)?;
        assert_eq!(stats.window_final_block_height, 42);

        let empty = Handler::new(Arc::new(Context::new()));
        let verify: corepc_types::v31::VerifyChain =
            typed(&empty.dispatch("verifychain", &json!([0, 6]))?)?;
        assert!(verify.0);

        let verify: corepc_types::v31::VerifyChain =
            typed(&handler.dispatch("verifychain", &json!([0, 6]))?)?;
        assert!(!verify.0);

        let at_tip: corepc_types::v31::GetBlockHash =
            typed(&handler.dispatch("getblockhash", &json!([42]))?)?;
        assert_eq!(at_tip.0, best.0);
        assert!(handler.dispatch("pruneblockchain", &json!([1])).is_err());

        Ok(())
    }

    #[test]
    fn chaininfo_projection_rejects_unknown_fields() -> Result<(), crate::support::TestError> {
        let handler = Handler::new(tipped_context());
        let mut response = handler.dispatch("getblockchaininfo", &json!([]))?;
        response
            .as_object_mut()
            .ok_or(crate::support::TestError::Missing(
                "getblockchaininfo must return an object",
            ))?
            .insert("unexpected", json!(true));
        let body = sonic_rs::to_string(&response)?;
        let error = match support::compare::typed_getblockchain_info(body.as_bytes()) {
            Err(error) => error,
            Ok(_) => {
                return Err(crate::support::TestError::Missing(
                    "the unknown chaininfo field was accepted",
                ));
            }
        };
        assert!(
            error.to_string().contains("unexpected"),
            "strict decode error did not name the unknown field: {error}"
        );
        Ok(())
    }

    #[test]
    fn mempool_responses_deserialize_into_pinned_types() -> Result<(), crate::support::TestError> {
        let handler = Handler::new(Arc::new(Context::new()));

        let info: corepc_types::v31::GetMempoolInfo =
            typed(&handler.dispatch("getmempoolinfo", &json!([]))?)?;
        assert!(info.loaded);
        assert_eq!(info.size, 0);
        assert!(info.permit_bare_multisig);
        assert!(info.optimal);
        assert_eq!(info.max_data_carrier_size, 83);
        assert_eq!(info.limit_cluster_count, 64);
        assert_eq!(info.limit_cluster_size, 101_000);
        assert_eq!(info.max_mempool, 300_000_000);
        assert!(info.full_rbf);

        let raw: corepc_types::v31::GetRawMempool =
            typed(&handler.dispatch("getrawmempool", &json!([]))?)?;
        assert_eq!(raw.0, Vec::<String>::new());

        let sequenced: corepc_types::v31::GetRawMempoolSequence =
            typed(&handler.dispatch("getrawmempool", &json!([false, true]))?)?;
        assert_eq!(sequenced.txids, Vec::<String>::new());
        assert_eq!(sequenced.mempool_sequence, 0);

        let verbose: corepc_types::v31::GetRawMempoolVerbose =
            typed(&handler.dispatch("getrawmempool", &json!([true]))?)?;
        assert!(verbose.0.is_empty());

        let indexes: corepc_types::v31::GetIndexInfo =
            typed(&handler.dispatch("getindexinfo", &json!([]))?)?;
        assert!(indexes.0.is_empty());

        Ok(())
    }

    const CORE_31_1_PROTOCOL_VERSION: u32 = 70_016;

    #[test]
    fn network_responses_deserialize_into_pinned_types() -> Result<(), crate::support::TestError> {
        let handler = Handler::new(Arc::new(Context::new()));

        let network: corepc_types::v31::GetNetworkInfo =
            typed(&handler.dispatch("getnetworkinfo", &json!([]))?)?;
        assert_eq!(
            network.version,
            usize::try_from(client_version()).unwrap_or(usize::MAX)
        );
        assert_eq!(
            network.protocol_version,
            usize::try_from(PROTOCOL_VERSION).unwrap_or(usize::MAX),
            "getnetworkinfo reports the advertised wire protocol version"
        );
        assert_eq!(
            PROTOCOL_VERSION, FEATURE_VERSION,
            "documented deviation from Core 31.1's 70016: the BIP434 feature-negotiation threshold"
        );
        assert_eq!(
            PROTOCOL_VERSION,
            CORE_31_1_PROTOCOL_VERSION + 1,
            "the one protocol version above Core 31.1's, and only that"
        );
        assert_eq!(network.connections, 0);
        assert_eq!(
            network
                .networks
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            ["ipv4", "ipv6", "onion", "i2p"]
        );
        for row in &network.networks[2..] {
            assert!(row.limited);
            assert!(!row.reachable);
            assert_eq!(row.proxy, "");
        }
        assert_eq!(network.warnings, Vec::<String>::new());

        let peers: corepc_types::v31::GetPeerInfo =
            typed(&handler.dispatch("getpeerinfo", &json!([]))?)?;
        assert_eq!(peers.0, []);

        let totals: corepc_types::v31::GetNetTotals =
            typed(&handler.dispatch("getnettotals", &json!([]))?)?;
        assert_eq!(totals.total_bytes_received, 0);
        assert!(totals.upload_target.target_reached);

        let connections: corepc_types::v31::GetConnectionCount =
            typed(&handler.dispatch("getconnectioncount", &json!([]))?)?;
        assert_eq!(connections.0, 0);

        let added: corepc_types::v31::GetAddedNodeInfo =
            typed(&handler.dispatch("getaddednodeinfo", &json!([]))?)?;
        assert_eq!(added.0, []);

        let banned: corepc_types::v31::ListBanned =
            typed(&handler.dispatch("listbanned", &json!([]))?)?;
        assert_eq!(banned.0, []);

        let addresses: corepc_types::v31::GetNodeAddresses =
            typed(&handler.dispatch("getnodeaddresses", &json!([0]))?)?;
        assert_eq!(addresses.0, []);

        Ok(())
    }

    fn assert_sparse_invalid(value: &sonic_rs::Value) {
        let object = value
            .as_object()
            .unwrap_or_else(|| panic!("validateaddress: not an object: {value:?}"));
        assert_eq!(object.len(), 1, "expected exactly one key: {value:?}");
        assert_eq!(
            value
                .get("isvalid")
                .and_then(sonic_rs::JsonValueTrait::as_bool),
            Some(false),
            "isvalid must be false: {value:?}"
        );
        for field in [
            "address",
            "scriptPubKey",
            "isscript",
            "iswitness",
            "witness_version",
            "witness_program",
        ] {
            assert!(
                value.get(field).is_none(),
                "{field} must be absent: {value:?}"
            );
        }
    }

    #[test]
    fn util_responses_deserialize_into_pinned_types() -> Result<(), crate::support::TestError> {
        let handler = Handler::new(Arc::new(Context::new()));

        let estimate: corepc_types::v31::EstimateSmartFee =
            typed(&handler.dispatch("estimatesmartfee", &json!([2]))?)?;
        assert!(estimate.fee_rate.is_none());
        assert_eq!(estimate.blocks, 2);

        let valid: corepc_types::v31::ValidateAddress =
            typed(&handler.dispatch("validateaddress", &json!(["1111111111111111111114oLvT2"]))?)?;
        assert!(valid.is_valid);
        assert_ne!(valid.script_pubkey, "");

        assert_sparse_invalid(
            &handler.dispatch("validateaddress", &json!(["not a real address"]))?,
        );
        assert_sparse_invalid(&handler.dispatch(
            "validateaddress",
            &json!(["tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"]),
        )?);
        let descriptor: corepc_types::v31::GetDescriptorInfo = typed(&handler.dispatch(
            "getdescriptorinfo",
            &json!(["addr(1111111111111111111114oLvT2)"]),
        )?)?;
        assert!(!descriptor.is_range);
        assert!(!descriptor.is_solvable);
        assert_eq!(descriptor.checksum.len(), 8);

        let memory: corepc_types::v31::GetMemoryInfoStats =
            typed(&handler.dispatch("getmemoryinfo", &json!(["stats"]))?)?;
        assert!(memory.0.contains_key("locked"));

        Ok(())
    }

    #[test]
    fn mining_responses_error_without_a_control() {
        let handler = Handler::new(Arc::new(Context::new()));
        assert!(handler.dispatch("getblocktemplate", &json!([{}])).is_err());
        assert!(handler.dispatch("getmininginfo", &json!([])).is_err());
    }

    struct CompatMiningControl;

    impl MiningControl for CompatMiningControl {
        fn get_block_template(
            &self,
            _request: BlockTemplateRequest,
        ) -> Result<BlockTemplateResult, MiningControlError> {
            Ok(BlockTemplateResult::Template(
                mining_fixture::canned_template(
                    vec![MiningCapability::new("coinbasetxn")],
                    vec![
                        TemplateMutation::Time,
                        TemplateMutation::Transactions,
                        TemplateMutation::PreviousBlock,
                    ],
                ),
            ))
        }

        fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
            Ok(mining_fixture::canned_info())
        }

        fn submit_block(
            &self,
            _payload: BlockImage,
        ) -> Result<BlockValidationResult, MiningControlError> {
            Ok(BlockValidationResult::Accepted)
        }

        fn submit_header(
            &self,
            _header: bitcoin_rs_consensus::primitives::Header,
        ) -> Result<(), MiningControlError> {
            Ok(())
        }

        fn publish_generation(&self) {}

        fn publish_fee_delta_generation(&self, _fee_delta_sequence: u64) {}

        fn generate(
            &self,
            _request: bitcoin_rs_serving::mining::GenerateRequest,
        ) -> Result<Vec<bitcoin_rs_serving::mining::GeneratedBlock>, MiningControlError> {
            Err(MiningControlError::Unavailable("not wired".into()))
        }

        fn network_hash_ps(&self, _lookup: i64, _height: i64) -> Result<f64, MiningControlError> {
            Ok(self.mining_info()?.network_hashes_per_second)
        }
    }

    #[test]
    fn mining_responses_deserialize_into_pinned_types() -> Result<(), crate::support::TestError> {
        let mut ctx = Context::new();
        ctx.chain.chain_network = Network::Regtest;
        let handler = Handler::new(Arc::new(
            ctx.with_mining_control(Arc::new(CompatMiningControl)),
        ));

        let template: corepc_types::v31::GetBlockTemplate =
            typed(&handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?)?;
        assert_eq!(template.version, 0x2000_0000);
        assert_eq!(template.height, 0);
        assert_eq!(template.bits, "1d00ffff");
        assert_eq!(
            template.target,
            "00000000ffff0000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(template.previous_block_hash, "0".repeat(64));
        assert_eq!(template.nonce_range, "00000000ffffffff");
        assert_eq!(template.capabilities, ["coinbasetxn"]);
        assert_eq!(template.mutable, ["time", "transactions", "prevblock"]);
        assert_eq!(template.sigop_limit, 80_000);
        assert_eq!(template.size_limit, 4_000_000);
        assert_eq!(template.weight_limit, 4_000_000);
        assert_eq!(template.coinbase_value, 0);
        assert_eq!(
            template.coinbase_aux.get("flags").map(String::as_str),
            Some("")
        );
        assert_eq!(template.transactions, []);
        assert_eq!(template.rules, Vec::<String>::new());
        assert!(template.version_bits_available.is_empty());
        assert_eq!(template.version_bits_required, 0);
        assert_eq!(template.min_time, 0);
        assert_eq!(template.current_time, 0);
        assert!(
            template
                .long_poll_id
                .as_ref()
                .is_some_and(|id| !id.is_empty())
        );
        assert!(template.default_witness_commitment.is_none());
        assert!(template.signet_challenge.is_none());
        let mining: corepc_types::v31::GetMiningInfo =
            typed(&handler.dispatch("getmininginfo", &json!([]))?)?;
        assert!((mining.difficulty - 1.0).abs() < f64::EPSILON);
        assert!(mining.current_block_weight.is_none());
        assert!(mining.current_block_tx.is_none());
        assert_eq!(mining.bits, "207fffff");
        assert_eq!(
            mining.target,
            "7fffff0000000000000000000000000000000000000000000000000000000000"
        );
        assert!((mining.network_hash_ps - 0.0).abs() < f64::EPSILON);
        assert_eq!(mining.pooled_tx, 0);
        assert!((mining.block_min_tx_fee - 1e-5).abs() < f64::EPSILON);
        assert!((mining.next.difficulty - 1.0).abs() < f64::EPSILON);
        assert!(mining.signet_challenge.is_none());
        assert_eq!(mining.warnings, Vec::<String>::new());
        assert_eq!(mining.next.height, 1);
        assert_eq!(mining.next.bits, "207fffff");
        assert_eq!(mining.next.target, mining.target);

        let rate: f64 = typed(&handler.dispatch("getnetworkhashps", &json!([]))?)?;
        assert!((rate - 0.0).abs() < f64::EPSILON);
        let prioritised: std::collections::BTreeMap<String, sonic_rs::Value> =
            typed(&handler.dispatch("getprioritisedtransactions", &json!([]))?)?;
        assert!(prioritised.is_empty());

        Ok(())
    }

    #[test]
    fn primitive_responses_stay_primitives() -> Result<(), crate::support::TestError> {
        let handler = Handler::new(Arc::new(Context::new()));

        let uptime = handler.dispatch("uptime", &json!([]))?;
        assert!(uptime.as_u64().is_some());

        assert!(handler.dispatch("ping", &json!([]))?.is_null());
        assert!(
            handler
                .dispatch("addnode", &json!(["127.0.0.1:1", "onetry"]))
                .is_ok()
        );
        assert!(
            handler
                .dispatch("setban", &json!(["127.0.0.0/8", "add"]))?
                .is_null()
        );
        assert!(handler.dispatch("clearbanned", &json!([]))?.is_null());
        assert_eq!(
            handler.dispatch(
                "prioritisetransaction",
                &json!([Hash256::default().to_string(), 0, 0])
            )?,
            json!(true)
        );
        Ok(())
    }

    #[test]
    fn submitblock_truncates_trailing_bytes_to_consumed_prefix()
    -> Result<(), crate::support::TestError> {
        #[derive(Default)]
        struct RecordingSubmit {
            submitted: std::sync::Mutex<Option<Vec<u8>>>,
        }

        impl MiningControl for RecordingSubmit {
            fn get_block_template(
                &self,
                _request: BlockTemplateRequest,
            ) -> Result<BlockTemplateResult, MiningControlError> {
                Err(MiningControlError::Unavailable("not wired".into()))
            }

            fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
                Err(MiningControlError::Unavailable("not wired".into()))
            }

            fn submit_block(
                &self,
                payload: BlockImage,
            ) -> Result<BlockValidationResult, MiningControlError> {
                *self
                    .submitted
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(payload.bytes().to_vec());
                Ok(BlockValidationResult::Accepted)
            }

            fn submit_header(
                &self,
                _header: bitcoin_rs_consensus::primitives::Header,
            ) -> Result<(), MiningControlError> {
                Err(MiningControlError::Unavailable("not wired".into()))
            }

            fn publish_generation(&self) {}

            fn publish_fee_delta_generation(&self, _fee_delta_sequence: u64) {}

            fn generate(
                &self,
                _request: bitcoin_rs_serving::mining::GenerateRequest,
            ) -> Result<Vec<bitcoin_rs_serving::mining::GeneratedBlock>, MiningControlError>
            {
                Err(MiningControlError::Unavailable("not wired".into()))
            }

            fn network_hash_ps(
                &self,
                _lookup: i64,
                _height: i64,
            ) -> Result<f64, MiningControlError> {
                Err(MiningControlError::Unavailable("not wired".into()))
            }
        }

        let genesis = Network::Regtest.genesis_block();
        let canonical = consensus_bytes(&genesis);
        let mut hex = String::with_capacity(canonical.len() * 2 + 4);
        for byte in &canonical {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex.push_str("ffff");

        let control: Arc<RecordingSubmit> = Arc::new(RecordingSubmit::default());
        let handler = Handler::new(Arc::new(
            Context::new().with_mining_control(control.clone()),
        ));
        let result = handler.dispatch("submitblock", &json!([hex]))?;
        assert!(
            result.is_null(),
            "trailing bytes after the block must be accepted as Accepted: {result:?}"
        );
        assert_eq!(
            control
                .submitted
                .lock()
                .map_or(None, |guard| (*guard).clone()),
            Some(canonical),
            "the submitted payload must retain exactly the consumed prefix"
        );

        let error = match handler.dispatch("submitblock", &json!(["zz"])) {
            Err(error) => error,
            Ok(_) => return Err("undecodable hex was accepted".into()),
        };
        assert_eq!(error.code(), -22);
        Ok(())
    }
}
mod core_parity {
    use crate::support;

    use std::collections::BTreeSet;

    use bitcoin_rs_serving::manifest::MANIFEST;
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

    use support::compare::{self, LiveChain};
    use support::fixture::{
        self, BodyCheck, BodyForm, Fixture, HttpTuple, PINNED_NETWORK, Relation, RequestAuth,
    };
    use support::harness::{NodeHarness, ServerHarness};
    use support::http::{Connection, HttpError, RawRequest, RawResponse};
    use support::limits::{MAX_CORPUS_BYTES, SEED_CHAIN_BLOCKS};
    use support::manifest_check::is_shipped_rpc_method;

    const EXPECTED_ORDINALS: [&str; 8] = ["01", "04", "05", "06", "07", "17", "18", "20"];

    fn stand_up() -> Result<(NodeHarness, ServerHarness), support::Failure> {
        fixture::load_corpus()?;
        let node = NodeHarness::open()?;
        let chain = node.seed(SEED_CHAIN_BLOCKS)?;
        if chain.tip_height != SEED_CHAIN_BLOCKS {
            return Err(support::fail(
                "seed chain did not reach the requested height",
            ));
        }
        let server = ServerHarness::start(&node)?;
        Ok((node, server))
    }

    fn as_tuple(response: RawResponse) -> HttpTuple {
        let body = if response.body.is_empty() {
            BodyForm::Empty
        } else if let Ok(value) = sonic_rs::from_slice::<Value>(&response.body) {
            BodyForm::Json { value }
        } else {
            BodyForm::Text {
                text: String::from_utf8_lossy(&response.body).into_owned(),
            }
        };
        HttpTuple {
            status: response.status,
            headers: response.headers,
            body_len: Some(u64::try_from(response.body.len()).unwrap_or(u64::MAX)),
            body,
        }
    }

    fn assert_typed_chaininfo(
        fixture: &Fixture,
        response: &RawResponse,
    ) -> Result<(), support::Failure> {
        match &fixture.checks.body {
            BodyCheck::Single { envelope } => {
                let value: Value = sonic_rs::from_slice(&response.body)?;
                if envelope.result.typed_chaininfo {
                    decode_result_as_chaininfo(&value)?;
                }
            }
            BodyCheck::Batch { elements } => {
                let value: Value = sonic_rs::from_slice(&response.body)?;
                let rows = value
                    .as_array()
                    .ok_or_else(|| support::fail("batch replay must answer an array"))?;
                for (element, envelope) in rows.iter().zip(elements) {
                    if envelope.result.typed_chaininfo {
                        decode_result_as_chaininfo(element)?;
                    }
                }
            }
            BodyCheck::Empty | BodyCheck::Text => {}
        }
        Ok(())
    }
    fn decode_result_as_chaininfo(envelope: &Value) -> Result<(), support::Failure> {
        let result = envelope
            .get("result")
            .ok_or_else(|| support::fail("typed chaininfo envelope carries no result"))?;
        let typed = compare::typed_getblockchain_info(sonic_rs::to_string(result)?.as_bytes())?;
        if typed.chain != PINNED_NETWORK {
            return Err(support::fail(format!(
                "typed chaininfo decoded for chain {:?}, not {PINNED_NETWORK}",
                typed.chain
            )));
        }
        Ok(())
    }

    #[test]
    fn differential_loopback_authenticated_chain() -> Result<(), support::TestError> {
        let corpus = fixture::load_corpus()?;
        let (node, server) = stand_up()?;
        let live: LiveChain = node.live_chain()?;

        let authenticated = server.replay(
            RequestAuth::Valid,
            r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}"#,
            None,
        )?;
        if authenticated.status != 200 {
            return Err(support::fail(format!(
                "authenticated getblockchaininfo answered HTTP {}",
                authenticated.status
            ))
            .into());
        }
        let envelope: Value = sonic_rs::from_slice(&authenticated.body)?;
        decode_result_as_chaininfo(&envelope)?;

        for fixture in corpus.values() {
            let response = server.replay(
                fixture.request.auth,
                &fixture.request.body,
                fixture.request.fragment_at,
            )?;
            compare::compare(fixture, &as_tuple(response.clone()), &live)?;
            assert_typed_chaininfo(fixture, &response)?;
        }

        let rejected = server.replay(
            RequestAuth::Invalid,
            r#"{"jsonrpc":"2.0","id":18,"method":"getblockchaininfo","params":[]}"#,
            None,
        )?;
        if rejected.status != 401 {
            return Err(support::fail(format!(
                "wrong credentials answered HTTP {}, not 401",
                rejected.status
            ))
            .into());
        }

        let mut gaps = Vec::new();
        for fixture in corpus.values() {
            match fixture.relation {
                Relation::Exact => {}
                Relation::KnownGap => gaps.push(
                    fixture
                        .gap
                        .clone()
                        .ok_or_else(|| support::fail("known gap without an identifier"))?,
                ),
            }
        }
        if gaps.is_empty() {
            return Err(support::fail(format!(
                "corpus must contain known gaps pinning both sides (found {} gaps)",
                gaps.len()
            ))
            .into());
        }
        Ok(())
    }

    #[test]
    fn keepalive_two_framed_responses_without_eof() -> Result<(), support::TestError> {
        let (_node, server) = stand_up()?;

        let mut connection = Connection::connect(server.address())?;
        let notification = RawRequest {
            path: "/",
            authorization: Some(ServerHarness::basic_token()),
            body: r#"{"jsonrpc":"2.0","method":"getblockchaininfo"}"#.to_owned(),
            keep_alive: true,
        };
        let first = connection.round_trip(&notification)?;
        if first.status != 204 {
            return Err(support::fail(format!(
                "notification must answer HTTP 204, got {}",
                first.status
            ))
            .into());
        }
        if !first.body.is_empty() {
            return Err(support::fail("notification must carry an empty body").into());
        }

        let chaininfo = RawRequest {
            path: "/",
            authorization: Some(ServerHarness::basic_token()),
            body: r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}"#.to_owned(),
            keep_alive: true,
        };
        let bytes = chaininfo.bytes();
        connection.send_request_fragmented(&bytes, Some(40))?;
        let second = connection.read_response()?;
        if second.status != 200 {
            return Err(support::fail(format!(
                "fragmented request must answer HTTP 200, got {}",
                second.status
            ))
            .into());
        }
        let envelope: Value = sonic_rs::from_slice(&second.body)?;
        decode_result_as_chaininfo(&envelope)?;
        Ok(())
    }

    fn replay_during_chain_transition(
        server: &ServerHarness,
        body: &str,
    ) -> Result<RawResponse, support::TestError> {
        use std::net::SocketAddr;
        use std::sync::mpsc;
        use std::time::Duration;

        const DEADLOCK_WATCHDOG: Duration = Duration::from_secs(30);

        fn request(
            address: SocketAddr,
            authorization: String,
            body: String,
        ) -> Result<RawResponse, HttpError> {
            let mut connection = Connection::connect(address)?;
            let request = RawRequest {
                path: "/",
                authorization: Some(authorization),
                body,
                keep_alive: true,
            };
            let bytes = request.bytes();
            connection.send_request_fragmented(&bytes, None)?;
            connection.read_response()
        }

        let barrier = server.chain_transition();
        let guard = barrier.lock();
        let (sender, receiver) = mpsc::channel();
        let address = server.address();
        let authorization = ServerHarness::basic_token();
        let owned_body = body.to_owned();
        let worker = std::thread::spawn(move || {
            let _ignored = sender.send(request(address, authorization, owned_body));
        });
        let outcome = receiver.recv_timeout(DEADLOCK_WATCHDOG);
        drop(guard);
        if worker.join().is_err() {
            return Err(support::fail("the request worker panicked").into());
        }
        match outcome {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => Err(support::fail(error).into()),
            Err(_) => Err(support::fail(
                "no complete response arrived while the chain-transition barrier was held",
            )
            .into()),
        }
    }

    fn seeded_chain_tx_count(node: &NodeHarness) -> Result<u64, support::TestError> {
        let applied = node
            .state
            .chainstate()
            .applied_tip()
            .load_full()
            .ok_or_else(|| support::fail("the seeded node has no applied tip"))?;
        Ok(applied
            .chain_tx_count
            .get()
            .ok_or_else(|| support::fail("the applied tip publishes no transaction count"))?)
    }

    fn decoded_success(
        response: &RawResponse,
        method: &str,
        id: i64,
    ) -> Result<Value, support::TestError> {
        if response.status != 200 {
            return Err(support::fail(format!(
                "{method} answered HTTP {} while the barrier was held",
                response.status
            ))
            .into());
        }
        let envelope: Value = sonic_rs::from_slice(&response.body)?;
        if envelope.get("id").and_then(Value::as_i64) != Some(id) {
            return Err(
                support::fail(format!("{method} answered a different id: {envelope}")).into(),
            );
        }
        if !envelope
            .get("error")
            .is_none_or(sonic_rs::JsonValueTrait::is_null)
        {
            return Err(support::fail(format!("{method} returned an error: {envelope}")).into());
        }
        envelope
            .get("result")
            .cloned()
            .ok_or_else(|| support::fail(format!("{method} answered no result")).into())
    }

    #[test]
    fn getblockchaininfo_returns_during_chain_transition() -> Result<(), support::TestError> {
        let (node, server) = stand_up()?;
        let live = node.live_chain()?;

        let response = replay_during_chain_transition(
            &server,
            r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}"#,
        )?;
        let result = decoded_success(&response, "getblockchaininfo", 1)?;
        let reported = result
            .get("bestblockhash")
            .and_then(Value::as_str)
            .ok_or_else(|| support::fail("getblockchaininfo answered no bestblockhash"))?;
        if reported != live.best_block_hash {
            return Err(support::fail(format!(
                "getblockchaininfo reported {reported}, not the applied tip {}",
                live.best_block_hash
            ))
            .into());
        }
        Ok(())
    }

    #[test]
    fn getchaintxstats_returns_during_chain_transition() -> Result<(), support::TestError> {
        let (node, server) = stand_up()?;
        let seeded_count = seeded_chain_tx_count(&node)?;

        let response = replay_during_chain_transition(
            &server,
            r#"{"jsonrpc":"2.0","id":2,"method":"getchaintxstats","params":[0]}"#,
        )?;
        let result = decoded_success(&response, "getchaintxstats", 2)?;
        let reported = result
            .get("txcount")
            .and_then(Value::as_u64)
            .ok_or_else(|| support::fail("getchaintxstats answered no txcount"))?;
        if reported != seeded_count {
            return Err(support::fail(format!(
                "getchaintxstats reported {reported}, not the published count {seeded_count}"
            ))
            .into());
        }
        if result.get("window_tx_count").is_some() || result.get("window_interval").is_some() {
            return Err(support::fail(format!(
                "a zero-block window must omit its fields: {result}"
            ))
            .into());
        }
        Ok(())
    }

    #[test]
    fn corpus_bounds_and_provenance_hold() -> Result<(), support::TestError> {
        let corpus = fixture::load_corpus()?;

        let dir = fixture::corpus_dir();
        let mut total_bytes = 0_u64;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let size = entry.metadata()?.len();
            total_bytes += size;
            if size > support::limits::MAX_FIXTURE_BYTES {
                return Err(support::fail(format!(
                    "{} is {size} bytes, above the per-fixture ceiling",
                    entry.path().display()
                ))
                .into());
            }
        }
        if total_bytes > MAX_CORPUS_BYTES {
            return Err(support::fail(format!(
                "corpus totals {total_bytes} bytes, above the ceiling of {MAX_CORPUS_BYTES}"
            ))
            .into());
        }
        if corpus.len() != EXPECTED_ORDINALS.len() {
            return Err(support::fail(format!(
                "corpus holds {} fixtures, expected {}",
                corpus.len(),
                EXPECTED_ORDINALS.len()
            ))
            .into());
        }

        let mut ordinals = BTreeSet::new();
        for fixture in corpus.values() {
            ordinals.insert(fixture.case_ordinal.clone());
            match (&fixture.relation, &fixture.current, &fixture.gap) {
                (Relation::Exact, None, None) => {}
                (Relation::KnownGap, Some(_), Some(gap)) if !gap.trim().is_empty() => {}
                _ => {
                    return Err(support::fail(format!(
                        "fixture {} violates the relation discipline",
                        fixture.id
                    ))
                    .into());
                }
            }
            for method in &fixture.request.methods {
                let shipped = is_shipped_rpc_method(method, MANIFEST);
                if shipped != fixture.request.expect_methods_in_manifest {
                    return Err(support::fail(format!(
                        "fixture {} method {method:?}: shipped={shipped} but the fixture expects \
                     manifest membership to be {}",
                        fixture.id, fixture.request.expect_methods_in_manifest
                    ))
                    .into());
                }
            }
        }
        let expected: BTreeSet<String> =
            EXPECTED_ORDINALS.iter().map(|o| (*o).to_string()).collect();
        if ordinals != expected {
            return Err(support::fail(format!(
                "corpus ordinals {ordinals:?} do not cover the probe cases {EXPECTED_ORDINALS:?}"
            ))
            .into());
        }
        Ok(())
    }
}
mod esplora_fee_estimates {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
    use bitcoin_rs_serving::Handler;
    use bitcoin_rs_serving::context::Context;
    use bitcoin_rs_serving::esplora::{Surface, route};
    use sonic_rs::JsonValueTrait as _;

    const VSIZE: u32 = 100;
    const HIGH_FEE_SATS: u64 = 10_000;
    const LOW_FEE_SATS: u64 = 5_000;
    const ENTRY_HEIGHT: u32 = 100;

    fn spend(output_sats: u64) -> Tx {
        let mut prevout = [0_u8; 32];
        prevout[31] = u8::try_from(output_sats & 0xff).unwrap_or(0);
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&prevout)), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(output_sats),
                script_pubkey: vec![0x51].into(),
            }],
        }
    }

    fn admit_batch(ctx: &Context, fee_sats: u64, entry_height: u32) -> Vec<Tx> {
        let pool = ctx.mempool.gateway.pool();
        let mut guard = pool.write();
        let mut txs = Vec::new();
        for index in 0_u64..2 {
            let tx = spend(1_000 + u64::from(entry_height) * 16 + index);
            txs.push(tx.clone());
            if guard
                .insert_entry(MempoolEntry::new(
                    Arc::new(tx),
                    VSIZE,
                    fee_sats,
                    1,
                    entry_height,
                    0,
                ))
                .is_err()
            {
                panic!("seeded entries must be admissible");
            }
        }
        txs
    }

    fn connect_block(ctx: &Context, confirmed: &[&Tx], height: u32) {
        let pool = ctx.mempool.gateway.pool();
        let mut guard = pool.write();
        let _ = guard.remove_for_block(
            &bitcoin_rs_mempool::TransitionFacts::from_txs(confirmed),
            height,
            u64::from(height) * 600,
        );
    }

    fn fee_estimates(ctx: &Arc<Context>) -> BTreeMap<String, f64> {
        let handler = Handler::new(Arc::clone(ctx));
        let response = route(&handler, Surface::Public, "fee-estimates", "");
        assert_eq!(response.status, 200, "fee-estimates must answer 200");
        let Ok(parsed) = sonic_rs::from_slice(&response.body) else {
            panic!("fee-estimates body must parse as JSON");
        };
        parsed
    }

    fn rpc_estimates(ctx: &Arc<Context>) -> BTreeMap<String, f64> {
        let handler = Handler::new(Arc::clone(ctx));
        (1_u32..=25)
            .chain([144, 504, 1008])
            .filter_map(|target| {
                let value = handler
                    .dispatch("estimatesmartfee", &sonic_rs::json!([target]))
                    .unwrap_or_else(|error| panic!("valid target {target}: {error}"));
                value
                    .get("feerate")
                    .and_then(sonic_rs::JsonValueTrait::as_f64)
                    .map(|rate| (target.to_string(), rate * 100_000.0))
            })
            .collect()
    }

    fn confirmed_history(fee: u64, delay: u32) -> Arc<Context> {
        let ctx = Arc::new(Context::new());
        admit_batch(&ctx, fee / 2, ENTRY_HEIGHT);
        connect_block(&ctx, &[], ENTRY_HEIGHT + delay);
        let txs = admit_batch(&ctx, fee, ENTRY_HEIGHT + delay);
        let refs: Vec<_> = txs.iter().collect();
        connect_block(&ctx, &refs, ENTRY_HEIGHT + 2 * delay);
        ctx
    }

    #[test]
    fn fee_estimates_omits_every_target_without_history() {
        let ctx = Arc::new(Context::new());
        let parsed = fee_estimates(&ctx);
        assert!(
            parsed.is_empty(),
            "without history no target may appear: {parsed:?}"
        );
        assert_eq!(parsed, rpc_estimates(&ctx));
    }

    // API-26
    #[test]
    fn fee_estimates_projects_confirmed_history_to_sat_per_vbyte() {
        let ctx = confirmed_history(HIGH_FEE_SATS, 1);

        let parsed = fee_estimates(&ctx);
        assert_eq!(
            parsed.len(),
            28,
            "all declared targets carry the confirmed history: {parsed:?}"
        );

        let Some(estimate) = ctx.mempool.gateway.read().estimate_fee_rate(1) else {
            panic!("two confirmations against two sampled misses must qualify target 1");
        };
        let sat_per_kvb = estimate.as_sat_per_kvb();
        let projected =
            f64::from(u32::try_from(sat_per_kvb).unwrap_or(u32::MAX)) / 100_000_000.0 * 100_000.0;
        assert!(
            projected > 1.0,
            "the seeded history must estimate above the old 1 sat/vB floor"
        );
        assert_eq!(
            parsed.get("1"),
            Some(&projected),
            "Esplora target 1 must be the RPC estimate projected to sat/vB"
        );
        for target in ["2", "6", "25", "144", "504", "1008"] {
            assert!(
                parsed.contains_key(target),
                "target {target} must be present, not omitted"
            );
        }
        assert_eq!(parsed, rpc_estimates(&ctx));
    }

    #[test]
    fn fee_estimates_preserves_partial_history_and_rpc_rounding() {
        let ctx = confirmed_history(LOW_FEE_SATS, 6);
        let parsed = fee_estimates(&ctx);
        assert_eq!(parsed, rpc_estimates(&ctx));
        assert_eq!(parsed.len(), 23);
        for target in 1..6 {
            assert!(!parsed.contains_key(&target.to_string()));
        }
        assert!(parsed.get("6").is_some_and(|rate| *rate > 1.0));
        for target in ["144", "504", "1008"] {
            assert_eq!(parsed.get(target), parsed.get("25"));
        }
    }

    #[test]
    fn fee_estimates_is_coherent_during_concurrent_pool_changes() {
        use std::sync::{Barrier, mpsc};

        let ctx = confirmed_history(HIGH_FEE_SATS, 1);
        let other = confirmed_history(LOW_FEE_SATS, 6);
        let first = fee_estimates(&ctx);
        let second = fee_estimates(&other);
        assert_ne!(first, second);
        let mut alternate = Mempool::new(MempoolLimits::default());
        std::mem::swap(&mut *other.mempool.gateway.pool().write(), &mut alternate);
        let start = Barrier::new(2);
        std::thread::scope(|scope| {
            let (stop, stopped) = mpsc::channel::<()>();
            let ctx = &ctx;
            let start = &start;
            scope.spawn(move || {
                start.wait();
                while matches!(stopped.try_recv(), Err(mpsc::TryRecvError::Empty)) {
                    std::mem::swap(&mut *ctx.mempool.gateway.pool().write(), &mut alternate);
                    std::thread::yield_now();
                }
            });
            start.wait();
            for _ in 0..256 {
                let response = fee_estimates(ctx);
                assert!(
                    response == first || response == second,
                    "mixed estimator states: {response:?}"
                );
            }
            drop(stop);
        });
    }
}
mod handler_smoke {
    #![allow(clippy::expect_used)]
    extern crate alloc;

    use alloc::sync::Arc;
    use hashbrown::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicBool, Ordering};

    use bitcoin::hex::DisplayHex;
    use bitcoin_rs_consensus::header_rules::ChainWork;
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Network, OutPoint,
        Script, Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
    };
    use bitcoin_rs_execution::chain::{NodeId, NodeStatus, TipSnapshot};
    use bitcoin_rs_mempool::MempoolEntry;
    use bitcoin_rs_projection::block_log::BlockRecord;
    use bitcoin_rs_serving::context::{ChainControl, ChainControlError, Context};
    use bitcoin_rs_serving::mining::FakeMiningControl;
    use bitcoin_rs_serving::{Handler, RpcError};
    use bitcoin_rs_storage::block_body::BlockBodySource;
    use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
    use bitcoin_rs_wire::{PeerInfo, PeerLease, PeerTable, wire::PROTOCOL_VERSION};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

    use crate::mining_fixture;
    use crate::support::TestError;

    #[test]
    fn required_handlers_report_the_fixture_chain_mempool_and_network_facts()
    -> Result<(), TestError> {
        let fixture = Fixture::new()?;
        let handler = Handler::new(Arc::clone(&fixture.ctx));

        for (method, params, expected) in chain_and_mempool_expectations(&fixture)
            .into_iter()
            .chain(network_and_wallet_expectations(&fixture)?)
        {
            let actual = handler
                .dispatch(method, &params)
                .unwrap_or_else(|err| panic!("{method} must answer: {err}"));
            assert_contains(method, method, &actual, &expected);
        }

        let uptime = handler.dispatch("uptime", &json!([]))?;
        assert!(uptime.as_u64().is_some(), "uptime must be a second count");
        Ok(())
    }

    type Expectation = (&'static str, sonic_rs::Value, sonic_rs::Value);

    #[test]
    fn compact_filter_rpc_exposes_only_enabled_ready_data() -> Result<(), TestError> {
        use bitcoin_rs_projection::{
            BasicFilter, CompactFilterQuery, DerivedIndexInfo, TxQueryError,
        };
        struct Filters(AtomicBool);
        impl CompactFilterQuery for Filters {
            fn block_filter(&self, _: Hash256) -> Result<Option<BasicFilter>, TxQueryError> {
                if !self.0.load(Ordering::Acquire) {
                    return Err(TxQueryError::Retry(
                        bitcoin_rs_projection::RetryReason::TipMoved {
                            expected_revision: 0,
                            current_revision: 1,
                        },
                    ));
                }
                let mut header = [0; 32];
                header[0] = 1;
                Ok(Some(BasicFilter {
                    filter: vec![0],
                    hash: [2; 32],
                    header,
                }))
            }
            fn for_each_filter(
                &self,
                _: u32,
                _: Hash256,
                _: u32,
                _: &mut dyn FnMut(Hash256, BasicFilter) -> bool,
            ) -> Result<Option<[u8; 32]>, TxQueryError> {
                unreachable!("single-block RPC only")
            }
            fn filter_index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
                Ok(DerivedIndexInfo {
                    synced: self.0.load(Ordering::Acquire),
                    best_block_height: 0,
                    applied_height: 0,
                    historical_height: 0,
                    verified_height: 0,
                    coverage_height: 0,
                })
            }
        }
        let mut fixture = Fixture::new()?;
        let hash = fixture.block_hash.to_string();
        {
            let handler = Handler::new(Arc::clone(&fixture.ctx));
            assert_eq!(
                handler
                    .dispatch("getblockfilter", &json!([hash]))
                    .expect_err("disabled")
                    .code(),
                -1
            );
            for (params, code) in [
                (json!([hash, "unknown"]), -5),
                (json!([hash, 1]), -3),
                (json!(["00".repeat(32)]), -5),
                (json!(["00"]), -8),
                (json!(["zz".repeat(32)]), -8),
            ] {
                let error = handler
                    .dispatch("getblockfilter", &params)
                    .expect_err("invalid request");
                assert_eq!(error.code(), code);
                if code == -8 {
                    assert_eq!(error.to_string(), "hash must be 64 hex characters");
                }
            }
        }
        let index = Arc::new(Filters(AtomicBool::new(false)));
        let context = Arc::get_mut(&mut fixture.ctx).ok_or("fixture context still shared")?;
        context.indexes.derived_index = None;
        context.indexes.compact_filters = Some(index.clone());
        context.network.local_services |= 64;
        let handler = Handler::new(Arc::clone(&fixture.ctx));
        assert_eq!(
            handler
                .dispatch("getblockfilter", &json!([hash]))
                .expect_err("catching up")
                .code(),
            -1
        );
        let services = handler.dispatch("getnetworkinfo", &json!([]))?;
        assert_eq!(
            u64::from_str_radix(services["localservices"].as_str().ok_or("services")?, 16)? & 64,
            0
        );
        index.0.store(true, Ordering::Release);
        for params in [
            json!([hash]),
            json!([hash, null]),
            json!({"blockhash": hash, "filtertype": "basic"}),
        ] {
            assert_eq!(
                handler.dispatch("getblockfilter", &params)?,
                json!({"filter": "00", "header": format!("{}01", "00".repeat(31))})
            );
        }
        assert_eq!(
            handler.dispatch("getindexinfo", &json!([]))?,
            json!({"basic block filter index": {"synced": true, "best_block_height": 0}})
        );
        let services = handler.dispatch("getnetworkinfo", &json!([]))?;
        assert_ne!(
            u64::from_str_radix(services["localservices"].as_str().ok_or("services")?, 16)? & 64,
            0
        );
        Ok(())
    }

    fn chain_and_mempool_expectations(fixture: &Fixture) -> Vec<Expectation> {
        let tip = fixture.block_hash.to_string();
        let txid = fixture.txid.to_string();
        let raw_tx = consensus_bytes(&fixture.tx).to_lower_hex_string();
        let header_hex = &fixture.block_hex[..160];

        vec![
            ("getblockcount", json!([]), json!(FIXTURE_HEIGHT)),
            ("getbestblockhash", json!([]), json!(tip)),
            ("getblockhash", json!([FIXTURE_HEIGHT]), json!(tip)),
            ("getblockheader", json!([tip, false]), json!(header_hex)),
            (
                "getblock",
                json!([tip, 1]),
                json!({
                    "hash": tip,
                    "height": FIXTURE_HEIGHT,
                    "nTx": 1,
                    "confirmations": 1,
                    "tx": [txid],
                }),
            ),
            (
                "getblockchaininfo",
                json!([]),
                json!({
                    "chain": "regtest",
                    "blocks": FIXTURE_HEIGHT,
                    "headers": FIXTURE_HEIGHT,
                    "bestblockhash": tip,
                }),
            ),
            (
                "getchaintxstats",
                json!([]),
                json!({
                    "window_final_block_hash": tip,
                    "window_final_block_height": FIXTURE_HEIGHT,
                }),
            ),
            (
                "getblockstats",
                json!([tip]),
                json!({"blockhash": tip, "height": FIXTURE_HEIGHT, "txs": 1, "outs": 1}),
            ),
            (
                "getmempoolinfo",
                json!([]),
                json!({"size": 1, "bytes": 100}),
            ),
            ("getrawmempool", json!([]), json!([txid])),
            (
                "getmempoolentry",
                json!([txid]),
                json!({
                    "vsize": 100,
                    "height": FIXTURE_HEIGHT,
                    "ancestorcount": 1,
                    "descendantcount": 1,
                }),
            ),
            (
                "gettxout",
                json!([txid, 0_u64]),
                json!({"value": 0.00005, "bestblock": tip, "coinbase": false}),
            ),
            (
                "gettxoutsetinfo",
                json!([]),
                json!({"height": FIXTURE_HEIGHT, "bestblock": tip}),
            ),
            ("getrawtransaction", json!([txid]), json!(raw_tx)),
            ("sendrawtransaction", json!([raw_tx]), json!(txid)),
            (
                "testmempoolaccept",
                json!([[raw_tx]]),
                json!([{
                    "txid": txid,
                    "allowed": false,
                    "reject-reason": "txn-already-in-mempool",
                }]),
            ),
        ]
    }

    fn network_and_wallet_expectations(fixture: &Fixture) -> Result<Vec<Expectation>, TestError> {
        let psbt = build_valid_base64_psbt(&fixture.tx)?;

        Ok(vec![
            (
                "getindexinfo",
                json!([]),
                json!({"txindex": {"synced": true, "best_block_height": FIXTURE_HEIGHT}}),
            ),
            (
                "getnetworkinfo",
                json!([]),
                json!({"protocolversion": PROTOCOL_VERSION, "connections": 0, "networkactive": true}),
            ),
            ("getpeerinfo", json!([]), json!([])),
            ("getconnectioncount", json!([]), json!(0)),
            ("getnetworkhashps", json!([]), json!(0.0)),
            ("getprioritisedtransactions", json!([]), json!({})),
            (
                "finalizepsbt",
                json!([psbt]),
                json!({"complete": false, "psbt": psbt, "hex": null}),
            ),
            ("combinepsbt", json!([[psbt]]), json!(psbt)),
            ("verifychain", json!([]), json!(false)),
            ("getmininginfo", json!([]), json!({"chain": "regtest"})),
            (
                "getblocktemplate",
                json!([{"rules": ["segwit"]}]),
                json!({"weightlimit": 4_000_000, "sizelimit": 4_000_000}),
            ),
            ("submitblock", json!([fixture.block_hex]), json!(null)),
        ])
    }

    const FIXTURE_HEIGHT: u64 = 7;

    fn assert_contains(
        method: &str,
        path: &str,
        actual: &sonic_rs::Value,
        expected: &sonic_rs::Value,
    ) {
        if let Some(fields) = expected.as_object() {
            let found = actual
                .as_object()
                .unwrap_or_else(|| panic!("{method}: {path} must be an object, got {actual}"));
            if fields.is_empty() {
                assert_eq!(
                    found.len(),
                    0,
                    "{method}: {path} must be empty, got {actual}"
                );
                return;
            }
            for (key, value) in fields {
                let found = actual
                    .get(key)
                    .unwrap_or_else(|| panic!("{method}: {path}.{key} missing from {actual}"));
                assert_contains(method, &format!("{path}.{key}"), found, value);
            }
            return;
        }
        if let Some(items) = expected.as_array() {
            let found = actual
                .as_array()
                .unwrap_or_else(|| panic!("{method}: {path} must be an array, got {actual}"));
            assert_eq!(found.len(), items.len(), "{method}: {path} length");
            for (index, item) in items.iter().enumerate() {
                assert_contains(method, &format!("{path}[{index}]"), &found[index], item);
            }
            return;
        }
        assert_eq!(actual, expected, "{method}: {path}");
    }

    #[cfg(not(feature = "zmq"))]
    #[test]
    fn getzmqnotifications_is_absent_without_zmq() {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(ctx);
        let err = handler
            .dispatch("getzmqnotifications", &json!([]))
            .expect_err("getzmqnotifications should be absent without zmq feature");
        assert_eq!(err.code(), RpcError::METHOD_NOT_FOUND);
    }
    #[test]
    fn getblockhash_zero_returns_mainnet_genesis_on_fresh_context() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));
        let response = handler.dispatch("getblockhash", &json!([0]))?;
        let actual = response
            .as_str()
            .ok_or("getblockhash response must be a string")?;
        let expected = Network::Mainnet.genesis_block_hash().to_string();
        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn getblockchaininfo_reports_the_apply_halt_fact() -> Result<(), TestError> {
        let mut ctx = Context::new();
        let closed = bitcoin_rs_consensus::latch::LatchWriter::new();
        ctx.chain.closed_for_recovery = closed.reader();
        let ctx = Arc::new(ctx);
        let handler = Handler::new(Arc::clone(&ctx));
        let healthy = handler.dispatch("getblockchaininfo", &json!([]))?;
        assert_eq!(healthy["is_apply_halted"], json!(false));
        assert_eq!(healthy["is_closed_for_recovery"], json!(false));

        closed.trigger();
        let halted = handler.dispatch("getblockchaininfo", &json!([]))?;
        assert_eq!(halted["is_apply_halted"], json!(true));
        assert_eq!(halted["is_closed_for_recovery"], json!(true));
        Ok(())
    }

    #[test]
    fn getblockchaininfo_reports_no_halt_without_chain_control() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));
        let info = handler.dispatch("getblockchaininfo", &json!([]))?;
        assert_eq!(
            info["is_apply_halted"],
            json!(false),
            "a detached context must not report a standing halt"
        );
        Ok(())
    }

    #[derive(Debug)]
    struct RecordingChainControl {
        called: Arc<AtomicBool>,
        error: Option<ChainControlError>,
        verify_error: Option<ChainControlError>,
    }

    impl ChainControl for RecordingChainControl {
        fn invalidate_block(&self, _hash: Hash256) -> Result<(), ChainControlError> {
            self.called.store(true, Ordering::SeqCst);
            match &self.error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }

        fn dump_txoutset(
            &self,
            _path: &std::path::Path,
            _cancellation: &bitcoin_rs_consensus::latch::LatchReader,
        ) -> Result<
            bitcoin_rs_serving::context::SnapshotExport,
            bitcoin_rs_serving::context::SnapshotControlError,
        > {
            Err(
                bitcoin_rs_serving::context::SnapshotControlError::Unavailable(
                    "snapshot export is not attached to this fixture".to_owned(),
                ),
            )
        }

        fn verify_chain(
            &self,
            _check_level: u8,
            _nblocks: u32,
            _cancellation: &bitcoin_rs_consensus::latch::LatchReader,
        ) -> Result<bool, ChainControlError> {
            match &self.verify_error {
                Some(error) => Err(error.clone()),
                None => Ok(false),
            }
        }
    }

    #[test]
    fn invalidateblock_delegates_to_node_control_and_returns_null() -> Result<(), RpcError> {
        let called = Arc::new(AtomicBool::new(false));
        let control = RecordingChainControl {
            called: Arc::clone(&called),
            error: None,
            verify_error: None,
        };
        let mut ctx = Context::new().with_chain_control(Arc::new(control));
        ctx.chain.chain_network = Network::Regtest;
        let handler = Handler::new(Arc::new(ctx));
        let result = handler.dispatch(
            "invalidateblock",
            &json!(["0000000000000000000000000000000000000000000000000000000000000000"]),
        )?;
        assert!(
            result.is_null(),
            "invalidateblock must return null on success"
        );
        assert!(
            called.load(Ordering::SeqCst),
            "chain control was not called"
        );
        Ok(())
    }

    #[test]
    fn invalidateblock_maps_unknown_block_to_core_not_found() {
        let called = Arc::new(AtomicBool::new(false));
        let control = RecordingChainControl {
            called: Arc::clone(&called),
            error: Some(ChainControlError::UnknownBlock),
            verify_error: None,
        };
        let mut ctx = Context::new().with_chain_control(Arc::new(control));
        ctx.chain.chain_network = Network::Regtest;
        let handler = Handler::new(Arc::new(ctx));
        let err = handler
            .dispatch(
                "invalidateblock",
                &json!(["0000000000000000000000000000000000000000000000000000000000000000"]),
            )
            .expect_err("unknown block should map to an error");
        assert_eq!(err.code(), RpcError::CORE_NOT_FOUND);
    }

    #[test]
    fn verifychain_maps_control_interruptions_to_core_errors() {
        for (error, message) in [
            (
                ChainControlError::Interrupted,
                "Block verification interrupted",
            ),
            (
                ChainControlError::Unavailable,
                "Chainstate is unavailable for verification",
            ),
        ] {
            let control = RecordingChainControl {
                called: Arc::new(AtomicBool::new(false)),
                error: None,
                verify_error: Some(error),
            };
            let mut ctx = Context::new().with_chain_control(Arc::new(control));
            ctx.chain.chain_network = Network::Regtest;
            let tip = TipSnapshot {
                tip_id: NodeId::new(0),
                height: 42,
                hash: Hash256::from_le_bytes(&[0xff; 32]),
                chainwork: ChainWork::default(),
                chain_tx_count: bitcoin_rs_execution::chain::ChainTxCount::UNKNOWN,
            };
            ctx.chain.applied_tip.store(Some(Arc::new(tip)));
            let handler = Handler::new(Arc::new(ctx));
            let err = handler
                .dispatch("verifychain", &json!([3, 6]))
                .expect_err("control interruption must map to an error");
            assert_eq!(err.code(), -1);
            assert_eq!(err.to_string(), message);
        }
    }

    #[test]
    fn getblockchaininfo_surfaces_published_chainwork_hex() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let tip = TipSnapshot {
            tip_id: NodeId::new(0),
            height: 42,
            hash: Hash256::from_le_bytes(&[0xff; 32]),
            chainwork: ChainWork::from_be_bytes([0x11; 32]),
            chain_tx_count: bitcoin_rs_execution::chain::ChainTxCount::UNKNOWN,
        };
        ctx.chain.chain_tip.store(Some(Arc::new(tip.clone())));
        ctx.chain.applied_tip.store(Some(Arc::new(tip)));
        let handler = Handler::new(Arc::clone(&ctx));
        let result = handler.dispatch("getblockchaininfo", &json!([]))?;
        let chainwork = result
            .get("chainwork")
            .and_then(JsonValueTrait::as_str)
            .ok_or("chainwork missing")?;
        assert_eq!(
            chainwork,
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
        Ok(())
    }

    #[test]
    fn gettxoutsetinfo_returns_real_utxo_counts() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[1; 32])), 0),
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: vec![0x51].into(),
            },
            false,
            1,
        ));
        ctx.populate_fixture_coins(&changes)?;
        let handler = Handler::new(Arc::clone(&ctx));
        let result = handler.dispatch("gettxoutsetinfo", &json!([]))?;
        assert_eq!(
            result.get("txouts").and_then(JsonValueTrait::as_u64),
            Some(1)
        );
        assert_eq!(
            result.get("total_amount").and_then(JsonValueTrait::as_f64),
            Some(0.0005)
        );
        Ok(())
    }

    #[test]
    fn gettxoutsetinfo_empty_muhash_matches_core_digest() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));
        let result = handler.dispatch("gettxoutsetinfo", &json!(["muhash"]))?;
        let muhash = result
            .get("muhash")
            .and_then(JsonValueTrait::as_str)
            .ok_or("muhash missing")?;
        assert_eq!(
            muhash,
            "dd5ad2a105c2d29495f577245c357409002329b9f4d6182c0af3dc2f462555c8"
        );
        Ok(())
    }

    #[test]
    fn gettxoutsetinfo_production_triplet_matches_core_digest() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));
        let result = handler.dispatch("gettxoutsetinfo", &json!(["muhash", null, false]))?;
        let muhash = result
            .get("muhash")
            .and_then(JsonValueTrait::as_str)
            .ok_or("muhash missing")?;
        assert_eq!(
            muhash,
            "dd5ad2a105c2d29495f577245c357409002329b9f4d6182c0af3dc2f462555c8"
        );
        Ok(())
    }

    #[test]
    fn getindexinfo_returns_txindex_when_indexer_is_available() -> Result<(), TestError> {
        let mut ctx = Context::new();
        ctx.indexes.derived_index = Some(Arc::new(FakeTxIndex {
            transactions: HashMap::new(),
            values: HashMap::new(),
            info: bitcoin_rs_serving::context::DerivedIndexInfo {
                synced: true,
                best_block_height: 7,
                applied_height: 7,
                historical_height: 7,
                verified_height: 7,
                coverage_height: 7,
            },
        }));
        let handler = Handler::new(Arc::new(ctx));
        let result = handler.dispatch("getindexinfo", &json!([]))?;
        let txindex = result.get("txindex").ok_or("txindex key missing")?;
        assert_eq!(
            txindex.get("synced").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        assert_eq!(
            txindex
                .get("best_block_height")
                .and_then(JsonValueTrait::as_u64),
            Some(7)
        );
        Ok(())
    }

    #[test]
    fn getindexinfo_named_request_returns_only_that_index() -> Result<(), TestError> {
        struct UnavailableFilters;
        impl bitcoin_rs_projection::CompactFilterQuery for UnavailableFilters {
            fn block_filter(
                &self,
                _: Hash256,
            ) -> Result<
                Option<bitcoin_rs_projection::BasicFilter>,
                bitcoin_rs_projection::TxQueryError,
            > {
                unreachable!("status only")
            }
            fn for_each_filter(
                &self,
                _: u32,
                _: Hash256,
                _: u32,
                _: &mut dyn FnMut(Hash256, bitcoin_rs_projection::BasicFilter) -> bool,
            ) -> Result<Option<[u8; 32]>, bitcoin_rs_projection::TxQueryError> {
                unreachable!("status only")
            }
            fn filter_index_info(
                &self,
            ) -> Result<bitcoin_rs_projection::DerivedIndexInfo, bitcoin_rs_projection::TxQueryError>
            {
                Err(bitcoin_rs_projection::TxQueryError::Unavailable(
                    bitcoin_rs_projection::TxUnavailableCause::Other("history unavailable".into()),
                ))
            }
        }
        let mut ctx = Context::new();
        ctx.indexes.compact_filters = Some(Arc::new(UnavailableFilters));
        ctx.indexes.derived_index = Some(Arc::new(FakeTxIndex {
            transactions: HashMap::new(),
            values: HashMap::new(),
            info: bitcoin_rs_serving::context::DerivedIndexInfo {
                synced: true,
                best_block_height: 7,
                applied_height: 7,
                historical_height: 7,
                verified_height: 7,
                coverage_height: 7,
            },
        }));
        let handler = Handler::new(Arc::new(ctx));

        let txindex = handler.dispatch("getindexinfo", &json!(["txindex"]))?;
        assert!(txindex.get("txindex").is_some(), "txindex must be present");
        let all = handler.dispatch("getindexinfo", &json!([]))?;
        assert!(
            all.get("txindex").is_some(),
            "no-param request includes txindex"
        );
        let unknown = handler.dispatch("getindexinfo", &json!(["unknown"]))?;
        assert!(
            unknown.get("txindex").is_none(),
            "unknown index name yields an empty object"
        );
        Ok(())
    }

    #[test]
    fn getblockstats_errors_without_indexer() {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(ctx);
        let err = handler
            .dispatch(
                "getblockstats",
                &json!(["0000000000000000000000000000000000000000000000000000000000000000"]),
            )
            .expect_err("getblockstats should error without an indexer");
        assert_eq!(err.code(), RpcError::CORE_NOT_FOUND);
    }

    #[test]
    fn getblockstats_uses_indexer_for_fee_fields() -> Result<(), TestError> {
        let mut values = HashMap::new();
        values.insert(outpoint(21), 10_000);
        values.insert(outpoint(22), 20_000);
        let (ctx, _low_tx, _high_tx) = fee_stats_context(Some(values));
        let handler = Handler::new(Arc::clone(&ctx));
        let tip_hash = ctx
            .chain
            .block_tree
            .read()
            .tip()
            .expect("tip")
            .as_ref()
            .clone()
            .hash;
        let result = handler.dispatch("getblockstats", &json!([tip_hash.to_string()]))?;
        let percentiles = result
            .get("feerate_percentiles")
            .and_then(|value| value.as_array())
            .ok_or("feerate_percentiles missing")?;
        let values: Vec<u64> = percentiles
            .iter()
            .map(|v| v.as_u64().unwrap_or(0))
            .collect();
        assert_eq!(values, vec![0, 0, 0, 0, 0]);
        Ok(())
    }

    #[test]
    fn getblockstats_errors_when_any_prevout_missing() {
        let (ctx, _low_tx, _high_tx) = fee_stats_context(None);
        let handler = Handler::new(Arc::clone(&ctx));
        let tip_hash = ctx
            .chain
            .block_tree
            .read()
            .tip()
            .expect("tip")
            .as_ref()
            .clone()
            .hash;
        let err = handler
            .dispatch("getblockstats", &json!([tip_hash.to_string()]))
            .expect_err("getblockstats should error when prevouts cannot be resolved");
        assert_eq!(err.code(), RpcError::INTERNAL_ERROR);
    }

    #[test]
    fn empty_context_is_in_initial_block_download() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));
        let result = handler.dispatch("getblockchaininfo", &json!([]))?;
        assert_eq!(
            result
                .get("initialblockdownload")
                .and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        Ok(())
    }

    #[test]
    fn chain_rpcs_report_applied_tip_separately_from_headers() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let headers_tip = TipSnapshot {
            tip_id: NodeId::new(0),
            height: 10,
            hash: Hash256::from_le_bytes(&[0xaa; 32]),
            chainwork: ChainWork::default(),
            chain_tx_count: bitcoin_rs_execution::chain::ChainTxCount::UNKNOWN,
        };
        let applied_tip = TipSnapshot {
            tip_id: NodeId::new(0),
            height: 7,
            hash: Hash256::from_le_bytes(&[0xbb; 32]),
            chainwork: ChainWork::default(),
            chain_tx_count: bitcoin_rs_execution::chain::ChainTxCount::UNKNOWN,
        };
        ctx.chain.chain_tip.store(Some(Arc::new(headers_tip)));
        ctx.chain.applied_tip.store(Some(Arc::new(applied_tip)));
        let handler = Handler::new(Arc::clone(&ctx));
        let result = handler.dispatch("getblockchaininfo", &json!([]))?;
        assert_eq!(
            result.get("headers").and_then(JsonValueTrait::as_u64),
            Some(10)
        );
        assert_eq!(
            result.get("blocks").and_then(JsonValueTrait::as_u64),
            Some(7)
        );
        Ok(())
    }

    #[test]
    fn network_peer_methods_read_shared_peer_table() -> Result<(), TestError> {
        let peer_table = Arc::new(PeerTable::new());
        let info = PeerInfo {
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            endpoint: Some(bitcoin_rs_wire::PeerEndpoint::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ))),
            network: bitcoin_rs_wire::NetworkLabel::Ipv4,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333).into(),
            version: 70016,
            services: 0,
            user_agent: "/bitcoin-rs:0.1.0/".to_string(),
            start_height: 0,
            best_known_height: 0,
            conn_time: 0,
            inbound: true,
            addr_bind: bitcoin_rs_wire::TransportRemote::new(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            )),
            time_offset: 0,
            counters: Arc::new(bitcoin_rs_wire::PeerCounters::default()),
            transport: bitcoin_rs_wire::TransportProtocol::V1,
        };
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new(tx);
        peer_table.register(info.endpoint.expect("identified test peer"), lease.clone());
        peer_table.publish_info(info.endpoint.expect("identified test peer"), &lease, info);
        let ctx = context_with_peers(peer_table);
        let handler = Handler::new(ctx);
        let result = handler.dispatch("getpeerinfo", &json!([]))?;
        let array = result
            .as_array()
            .ok_or("getpeerinfo must return an array")?;
        assert_eq!(array.len(), 1);
        let count = handler.dispatch("getconnectioncount", &json!([]))?;
        assert_eq!(count.as_u64(), Some(1));
        Ok(())
    }

    // WF-01
    #[test]
    fn removed_wallet_methods_return_method_not_found() {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(ctx);
        for method in [
            "listunspent",
            "getbalance",
            "sendtoaddress",
            "walletcreatefundedpsbt",
            "walletprocesspsbt",
        ] {
            let err = handler
                .dispatch(method, &json!([]))
                .expect_err(&format!("{method} should return method-not-found"));
            assert_eq!(
                err.code(),
                RpcError::METHOD_NOT_FOUND,
                "{method} should return method-not-found"
            );
        }
    }

    struct FakeTxIndex {
        info: bitcoin_rs_serving::context::DerivedIndexInfo,
        transactions: HashMap<Txid, Tx>,
        values: HashMap<OutPoint, u64>,
    }

    impl bitcoin_rs_serving::context::DerivedIndexQuery for FakeTxIndex {
        fn transaction(
            &self,
            txid: &Txid,
        ) -> Result<Option<Tx>, bitcoin_rs_serving::context::TxQueryError> {
            Ok(self.transactions.get(txid).cloned())
        }

        fn outpoint_value(
            &self,
            outpoint: &OutPoint,
        ) -> Result<Option<u64>, bitcoin_rs_serving::context::TxQueryError> {
            Ok(self.values.get(outpoint).copied())
        }

        fn index_info(
            &self,
        ) -> Result<
            bitcoin_rs_serving::context::DerivedIndexInfo,
            bitcoin_rs_serving::context::TxQueryError,
        > {
            Ok(self.info)
        }
    }

    fn fee_stats_context(values: Option<HashMap<OutPoint, u64>>) -> (Arc<Context>, Tx, Tx) {
        let low_tx = fee_tx(21, 10_000);
        let high_tx = fee_tx(22, 20_000);
        let block = fee_block(low_tx.clone(), high_tx.clone());
        let mut ctx = Context::new();
        if let Some(values) = values {
            let mut transactions = HashMap::new();
            for label in [21_u8, 22] {
                transactions.insert(
                    Txid(Hash256::from_le_bytes(&[label; 32])),
                    Tx {
                        version: 2,
                        lock_time: LockTime::ZERO,
                        inputs: Vec::new(),
                        outputs: vec![TxOut {
                            value: Amount::from_sat(10_000),
                            script_pubkey: Script::new(),
                        }],
                    },
                );
            }
            ctx.indexes.derived_index = Some(Arc::new(FakeTxIndex {
                transactions,
                values,
                info: bitcoin_rs_serving::context::DerivedIndexInfo {
                    synced: true,
                    best_block_height: 7,
                    applied_height: 7,
                    historical_height: 7,
                    verified_height: 7,
                    coverage_height: 7,
                },
            }));
        }
        let block = seed_tree_chain(&ctx, &block);
        let record = BlockRecord::from_block(7, &block);
        ctx.chain.block_body_source = Some(Arc::new(SingleBlockSource {
            height: record.height,
            hash: record.hash,
            body: consensus_bytes(&block),
        }));
        ctx.chain.add_block(record);
        (Arc::new(ctx), low_tx, high_tx)
    }

    fn seed_tree_chain(ctx: &Context, block: &Block) -> Block {
        let mut tree = ctx.chain.block_tree.write();
        let mut parent = None;
        let mut prev_blockhash = BlockHash::default();

        for height in 0_u32..7 {
            let header = Header {
                version: 1,
                prev_blockhash,
                merkle_root: Hash256::default(),
                time: 1_231_006_498 + height,
                bits: block.header.bits,
                nonce: height,
            };
            prev_blockhash = header.compute_hash();
            parent = Some(
                tree.insert_node(parent, header, NodeStatus::Active)
                    .expect("insert synthetic ancestor"),
            );
        }

        let mut linked_block = block.clone();
        linked_block.header.prev_blockhash = prev_blockhash;
        tree.insert_node(parent, linked_block.header, NodeStatus::Active)
            .expect("insert fixture block");
        linked_block
    }

    fn fee_block(low_tx: Tx, high_tx: Tx) -> Block {
        let coinbase = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0_u8; 32])), u32::MAX),
                script_sig: vec![0x51].into(),
                sequence: Sequence::from_consensus(0xFFFF_FFFE),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: vec![0x51].into(),
            }],
        };
        let txs = vec![coinbase, low_tx, high_tx];
        let merkle_root =
            bitcoin_rs_execution::chain::regtest_fixture::merkle_root(&txs).unwrap_or_default();
        Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root,
                time: 1_231_006_505,
                bits: CompactTarget::from_consensus(0x1d00_ffff),
                nonce: 0,
            },
            txs,
        }
    }

    fn fee_tx(label: u8, output_sat: u64) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: outpoint(label),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0xFFFF_FFFE),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(output_sat),
                script_pubkey: vec![0x51].into(),
            }],
        }
    }

    struct SingleBlockSource {
        height: u32,
        hash: BlockHash,
        body: Vec<u8>,
    }

    impl BlockBodySource for SingleBlockSource {
        fn block_body(
            &self,
            height: u32,
            hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
            Ok((height == self.height && hash == self.hash).then(|| self.body.clone()))
        }
    }

    struct Fixture {
        ctx: Arc<Context>,
        tx: Tx,
        txid: Txid,
        block_hash: BlockHash,
        block_hex: String,
    }

    impl Fixture {
        fn new() -> Result<Self, TestError> {
            let mut ctx = Context::new().with_mining_control(FakeMiningControl::with_template(
                mining_fixture::canned_template(Vec::new(), Vec::new()),
                mining_fixture::canned_info(),
            ));

            ctx.chain.chain_network = Network::Regtest;
            let tx = tx(1, vec![0x51]);
            let merkle_root = bitcoin_rs_execution::chain::regtest_fixture::merkle_root(
                std::slice::from_ref(&tx),
            )
            .unwrap_or_default();
            let block = Block {
                header: Header {
                    version: 1,
                    prev_blockhash: BlockHash::default(),
                    merkle_root,
                    time: 1_231_006_505,
                    bits: CompactTarget::from_consensus(0x1d00_ffff),
                    nonce: 0,
                },
                txs: vec![tx.clone()],
            };
            let block = seed_tree_chain(&ctx, &block);
            let block_hash = block.block_hash();
            let tip = ctx
                .chain
                .block_tree
                .read()
                .tip()
                .expect("fixture tip missing")
                .as_ref()
                .clone();
            ctx.chain.chain_tip.store(Some(Arc::new(tip.clone())));
            ctx.chain.applied_tip.store(Some(Arc::new(tip)));
            ctx.chain.block_body_source = Some(Arc::new(SingleBlockSource {
                height: 7,
                hash: block_hash,
                body: consensus_bytes(&block),
            }));
            ctx.chain.add_block(BlockRecord::from_block(7, &block));
            let mut values = HashMap::new();
            values.insert(outpoint(1), 6_000);
            ctx.indexes.derived_index = Some(Arc::new(FakeTxIndex {
                transactions: HashMap::new(),
                values,
                info: bitcoin_rs_serving::context::DerivedIndexInfo {
                    synced: true,
                    best_block_height: 7,
                    applied_height: 7,
                    historical_height: 7,
                    verified_height: 7,
                    coverage_height: 7,
                },
            }));
            let block_hex = consensus_bytes(&block).to_lower_hex_string();
            let txid = tx.txid();
            let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 7, 0);
            ctx.mempool.gateway.pool().write().insert_entry(entry)?;
            Ok(Self {
                ctx: Arc::new(ctx),
                tx,
                txid,
                block_hash,
                block_hex,
            })
        }
    }
    fn context_with_peers(peer_table: Arc<PeerTable>) -> Arc<Context> {
        let mut ctx = Context::new();
        ctx.network.peer_table = peer_table;
        Arc::new(ctx)
    }

    fn tx(label: u8, script_pubkey: Vec<u8>) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: outpoint(label),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0xFFFF_FFFE),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000),
                script_pubkey: script_pubkey.into(),
            }],
        }
    }
    fn outpoint(label: u8) -> OutPoint {
        OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0)
    }

    fn build_valid_base64_psbt(tx: &Tx) -> Result<String, TestError> {
        let bytes = consensus_bytes(tx);
        let btc_tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&bytes)?;
        let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(btc_tx)?;
        Ok(encode_base64(&psbt.serialize()))
    }

    const BASE64_TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn encode_base64(bytes: &[u8]) -> String {
        let mut result = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0];
            let b1 = chunk.get(1).copied().unwrap_or(0);
            let b2 = chunk.get(2).copied().unwrap_or(0);
            result.push(char::from(BASE64_TABLE[usize::from(b0 >> 2)]));
            result.push(char::from(
                BASE64_TABLE[usize::from((b0 & 0x03) << 4 | b1 >> 4)],
            ));
            if chunk.len() > 1 {
                result.push(char::from(
                    BASE64_TABLE[usize::from((b1 & 0x0f) << 2 | b2 >> 6)],
                ));
            } else {
                result.push('=');
            }
            if chunk.len() > 2 {
                result.push(char::from(BASE64_TABLE[usize::from(b2 & 0x3f)]));
            } else {
                result.push('=');
            }
        }
        result
    }
}
mod manifest_coverage {
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::sync::Arc;

    use bitcoin_rs_serving::context::Context;
    use bitcoin_rs_serving::manifest::{self, Entry, Status, SurfaceKind};
    use bitcoin_rs_serving::{Handler, RpcError};
    use sonic_rs::json;

    const CORE_ZMQ_TOPICS: [&str; 5] = ["hashblock", "hashtx", "rawblock", "rawtx", "sequence"];

    const CARGO_LOCK: &str = include_str!("../../Cargo.lock");

    fn handler() -> Handler {
        Handler::new(Arc::new(Context::new()))
    }

    #[test]
    fn silent_payments_requires_build_and_runtime_opt_in() {
        let result = handler().dispatch("getblocktweaks", &json!([0]));
        #[cfg(feature = "silent-payments")]
        assert!(matches!(result, Err(RpcError::MethodDisabled(_))));
        #[cfg(not(feature = "silent-payments"))]
        assert!(matches!(result, Err(RpcError::MethodNotFound(_))));
    }

    fn shipped(kind: SurfaceKind) -> impl Iterator<Item = &'static Entry> {
        manifest::entries_of_kind(kind).filter(|entry| entry.shipped())
    }

    fn not_dispatchable(handler: &Handler, name: &str) -> bool {
        matches!(
            handler.dispatch(name, &json!([])),
            Err(RpcError::MethodNotFound(_))
        )
    }

    // API-01
    #[test]
    fn rpc_rows_and_the_live_registry_agree_both_ways() {
        let live: BTreeSet<&str> = bitcoin_rs_serving::handlers::live_registry().collect();
        assert!(
            !live.is_empty(),
            "live registry must not silently empty out"
        );
        let shipped_rows: BTreeSet<&str> =
            shipped(SurfaceKind::Rpc).map(|entry| entry.name).collect();
        let armless: Vec<&str> = shipped_rows.difference(&live).copied().collect();
        assert!(
            armless.is_empty(),
            "shipped manifest rows with no live dispatch arm: {armless:?}"
        );
        let undeclared: Vec<&str> = live.difference(&shipped_rows).copied().collect();
        assert!(
            undeclared.is_empty(),
            "live dispatch arms missing a shipped manifest row: {undeclared:?}"
        );
    }

    // API-01
    #[test]
    fn every_unimplemented_rpc_row_answers_method_not_found() {
        let handler = handler();
        let unimplemented: BTreeSet<&str> = manifest::entries_of_kind(SurfaceKind::Rpc)
            .filter(|entry| entry.status == Status::Unimplemented)
            .map(|entry| entry.name)
            .collect();
        assert!(
            !unimplemented.is_empty(),
            "Unimplemented set must not silently empty out"
        );
        for name in &unimplemented {
            assert!(
                not_dispatchable(&handler, name),
                "`{name}` is declared Unimplemented but the dispatcher answers it"
            );
        }
        assert!(
            unimplemented.is_disjoint(&shipped(SurfaceKind::Rpc).map(|entry| entry.name).collect()),
            "a row cannot be both Unimplemented and shipped"
        );
    }

    #[test]
    fn rest_rows_and_router_registrations_agree_both_ways() {
        let registered: BTreeSet<&str> = bitcoin_rs_serving::rest::REGISTRATIONS
            .iter()
            .copied()
            .collect();
        let manifest_rest: BTreeSet<&str> = shipped(SurfaceKind::Rest)
            .filter(|entry| entry.name.starts_with("/rest/"))
            .map(|entry| entry.name)
            .collect();
        let unregistered: Vec<&str> = manifest_rest.difference(&registered).copied().collect();
        assert!(
            unregistered.is_empty(),
            "manifest REST rows missing from rest::REGISTRATIONS: {unregistered:?}"
        );
        let undeclared: Vec<&str> = registered.difference(&manifest_rest).copied().collect();
        assert!(
            undeclared.is_empty(),
            "rest::REGISTRATIONS prefixes missing a manifest row: {undeclared:?}"
        );
    }

    #[test]
    fn zmq_rows_are_valid_core_topics() {
        let declared: BTreeSet<&str> = manifest::entries_of_kind(SurfaceKind::Zmq)
            .map(|entry| entry.name)
            .collect();
        let core: BTreeSet<&str> = CORE_ZMQ_TOPICS.iter().copied().collect();
        assert_eq!(
            declared, core,
            "the ZMQ rows must name exactly the Core-registered topics"
        );
    }

    #[test]
    fn deviation_rows_name_their_difference() {
        let silent: Vec<&str> = manifest::MANIFEST
            .iter()
            .filter(|entry| entry.status == Status::Deviation && entry.notes.trim().is_empty())
            .map(|entry| entry.name)
            .collect();
        assert!(
            silent.is_empty(),
            "these rows claim a deviation without stating it: {silent:?}"
        );
    }

    #[test]
    fn supported_is_not_claimable_without_the_harness() {
        let table: toml::Table = toml::from_str(manifest::MANIFEST_TOML)
            .unwrap_or_else(|err| panic!("the reference custody record must parse: {err}"));
        let harness = table
            .get("reference")
            .and_then(toml::Value::as_table)
            .and_then(|reference| reference.get("differential_harness"))
            .and_then(toml::Value::as_bool)
            .unwrap_or_else(|| panic!("`reference.differential_harness` must be a boolean"));
        if harness {
            return;
        }
        let claiming: Vec<&str> = manifest::MANIFEST
            .iter()
            .filter(|entry| entry.status == Status::Supported)
            .map(|entry| entry.name)
            .collect();
        assert!(
            claiming.is_empty(),
            "these rows claim `Supported` while no differential harness exists to have \
         verified them: {claiming:?}"
        );
    }

    #[test]
    fn the_pinned_core_reference_matches_the_locked_kernel() {
        let table: toml::Table = toml::from_str(manifest::MANIFEST_TOML)
            .unwrap_or_else(|err| panic!("the reference custody record must parse: {err}"));
        let Some(reference) = table.get("reference").and_then(toml::Value::as_table) else {
            panic!("the reference custody record must carry a `reference` table");
        };

        for (name_key, version_key) in [
            ("kernel_crate", "kernel_crate_version"),
            ("kernel_sys_crate", "kernel_sys_crate_version"),
        ] {
            let name = reference
                .get(name_key)
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("`{name_key}` must be a string"));
            let version = reference
                .get(version_key)
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("`{version_key}` must be a string"));
            let lock: toml::Table = toml::from_str(CARGO_LOCK)
                .unwrap_or_else(|err| panic!("Cargo.lock must parse as TOML: {err}"));
            let locked: Vec<&str> = lock
                .get("package")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .filter(|package| package.get("name").and_then(toml::Value::as_str) == Some(name))
                .filter_map(|package| package.get("version").and_then(toml::Value::as_str))
                .collect();
            assert!(
                !locked.is_empty(),
                "`{name}` is pinned in the reference record but absent from Cargo.lock"
            );
            assert!(
                locked
                    .iter()
                    .all(|&locked_version| locked_version == version),
                "`{name}` is locked at {locked:?} but the reference record is written \
             against {version}. The pinned Bitcoin Core revision comes from this \
             crate's vendored tree, so a bump means the claims in \
             crates/serving/core-compat.toml need re-reading, not just this line."
            );
        }
    }

    #[test]
    fn esplora_extension_row_resolves_to_the_router() {
        let row = manifest::MANIFEST
            .iter()
            .find(|entry| entry.name == "esplora/*")
            .unwrap_or_else(|| panic!("esplora/* extension row missing from MANIFEST"));
        assert_eq!(row.status, Status::Extension);
        let (surface, path) = bitcoin_rs_serving::esplora::namespace("/api/mempool")
            .unwrap_or_else(|| panic!("/api/mempool is the public Esplora directory"));
        let response = bitcoin_rs_serving::esplora::route(&handler(), surface, path, "");
        assert_eq!(
            response.status, 200,
            "esplora router must serve the row it declares"
        );
    }

    // API-01
    #[test]
    fn manifest_has_no_duplicate_rows() {
        let mut seen = BTreeSet::new();
        for entry in manifest::MANIFEST {
            assert!(
                seen.insert((entry.kind, entry.name)),
                "duplicate manifest row: {:?} {}",
                entry.kind,
                entry.name
            );
        }
    }

    #[test]
    fn generated_reference_matches_checked_in() {
        const REGEN: &str = "REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-serving \
        --test suite manifest_coverage::regenerate_reference -- --ignored";
        assert!(
            std::env::var_os("REGEN_RPC_REFERENCE").is_none(),
            "REGEN_RPC_REFERENCE is set: this is a coverage-only guard. Regenerate with \
         `{REGEN}`, unset the variable, and rerun."
        );
        let rendered = manifest::render_reference();
        let doc_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/rpc-reference.md");
        let checked_in = std::fs::read_to_string(&doc_path).unwrap_or_else(|err| {
        panic!(
            "cannot read {}: {err}; regenerate with \
             REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-serving --test suite manifest_coverage:: \
             -- --ignored regenerate_reference",
            doc_path.display()
        )
    });
        if rendered != checked_in {
            let first_diff = rendered
                .lines()
                .zip(checked_in.lines())
                .position(|(generated, checked_in)| generated != checked_in)
                .unwrap_or_else(|| rendered.lines().count().min(checked_in.lines().count()));
            panic!(
                "docs/rpc-reference.md drifted from the manifest at line {}:\n  generated: {:?}\n  checked in: {:?}\n\
             regenerate with REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-serving --test suite manifest_coverage::regenerate_reference -- --ignored",
                first_diff + 1,
                rendered.lines().nth(first_diff),
                checked_in.lines().nth(first_diff)
            );
        }
    }

    #[ignore = "writes docs/rpc-reference.md; run explicitly with REGEN_RPC_REFERENCE=1"]
    #[test]
    fn regenerate_reference() {
        assert!(
            std::env::var_os("REGEN_RPC_REFERENCE").is_some(),
            "guarded against accidental writes: run with REGEN_RPC_REFERENCE=1"
        );
        let doc_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/rpc-reference.md");
        std::fs::write(&doc_path, manifest::render_reference())
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", doc_path.display()));
    }
}
mod policy_contract {
    #![deny(clippy::expect_used)]

    extern crate alloc;

    use alloc::sync::Arc;

    use bitcoin_rs_mempool::{
        Mempool, MempoolEntry, MempoolGateway, MempoolLimits, MempoolObserver, MutationEnvelope,
        MutationOutcome, PolicyError, RbfError, RemovalReason, ReplacementCandidate,
    };

    use bitcoin_rs_consensus::header_rules::ChainWork;
    use bitcoin_rs_execution::chain::{NodeId, TipSnapshot, regtest_fixture};

    use bitcoin_rs_node::{
        Network, NodeConfig,
        reorg::{ReorgError, invalidate_block},
        state::NodeState,
    };

    use bitcoin_rs_consensus::primitives::{
        Amount, Block, CompactTarget, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn,
        TxOut, Txid, Witness, consensus_bytes, unix_time_secs,
    };
    use bitcoin_rs_consensus::script::push_int;

    use bitcoin_rs_serving::{
        Handler, RpcError,
        context::{
            ChainControl, ChainControlError, ChainHandles, Context, ContextHandles, IndexHandles,
            MempoolHandles, MiningHandles, NetworkHandles,
        },
    };

    use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};

    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

    use bitcoin::hex::DisplayHex;

    fn p2wpkh_script() -> Vec<u8> {
        [vec![0x00, 0x14], vec![0x11; 20]].concat()
    }

    fn op_true_script() -> Vec<u8> {
        vec![0x51]
    }

    fn p2sh_true_script() -> Vec<u8> {
        let redeem = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        redeem.to_p2sh().into_bytes()
    }

    fn p2sh_true_script_sig() -> Script {
        Script::from_bytes(vec![0x01, 0x51])
    }

    fn tx(prevout: OutPoint, output_value: u64, sequence: u32) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: prevout,
                script_sig: p2sh_true_script_sig(),
                sequence: Sequence::from_consensus(sequence),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: Script::from_bytes(p2wpkh_script()),
            }],
        }
    }

    fn rpc_txid(tx: &Tx) -> Txid {
        tx.txid()
    }

    fn raw_tx_hex(tx: &Tx) -> String {
        consensus_bytes(tx).to_lower_hex_string()
    }

    fn fund_utxo(ctx: &Context, label: u8, value: u64) -> OutPoint {
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: Script::from_bytes(p2sh_true_script()),
            },
            false,
            1,
        ));
        ctx.populate_fixture_coins(&changes)
            .unwrap_or_else(|error| panic!("commit_block failed: {error}"));
        OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[label; 32])),
            vout: 0,
        }
    }

    fn confirmed_outpoint(label: u8) -> OutPoint {
        OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[label; 32])),
            vout: 0,
        }
    }

    fn reject_message(error: &RpcError) -> String {
        assert_eq!(
            error.code(),
            RpcError::CORE_VERIFY_REJECTED,
            "policy rejects surface as transaction rejections"
        );
        error.to_string()
    }

    #[test]
    fn sendrawtransaction_rejects_below_min_relay_fee_and_agrees_with_the_pool()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let prevout = fund_utxo(&ctx, 0x50, 10_000);
        let tx = tx(prevout, 9_999, 0xffff_ffff);
        let handler = Handler::new(Arc::clone(&ctx));

        let message = reject_message(
            &handler
                .dispatch("sendrawtransaction", &json!([raw_tx_hex(&tx)]))
                .err()
                .ok_or("expected below-min-relay-fee rejection")?,
        );
        assert!(
            message.contains("min relay fee not met"),
            "unexpected rejection message: {message}"
        );
        assert!(
            !ctx.mempool.gateway.read().contains_txid(&rpc_txid(&tx)),
            "rejected tx must not enter the pool"
        );

        let mut pool = Mempool::new(MempoolLimits::default());
        let error = pool
            .insert_entry(MempoolEntry::new(Arc::new(tx), 82, 1, 0, 1, 0))
            .err()
            .ok_or("pool path must also reject")?;
        assert!(matches!(
            error,
            bitcoin_rs_mempool::MempoolError::Policy(PolicyError::BelowMinRelayFee { .. })
        ));
        Ok(())
    }

    fn funded_fee_tx(ctx: &Context, label: u8, fee: u64) -> Tx {
        tx(fund_utxo(ctx, label, 10_000 + fee), 10_000, 0xffff_ffff)
    }

    fn spend_vsize() -> u64 {
        tx(staged_outpoint(0x40), 10_000, 0xffff_ffff).vsize()
    }

    fn floor_fee(sat_per_kvb: u64) -> u64 {
        sat_per_kvb * spend_vsize() / 1_000
    }

    fn pool_holds(ctx: &Context, tx: &Tx) -> bool {
        ctx.mempool.gateway.read().contains_txid(&rpc_txid(tx))
    }

    fn set_relay_floor(ctx: &Context, sat_per_kvb: u64) {
        ctx.mempool
            .gateway
            .pool()
            .write()
            .limits
            .min_relay_fee_sat_per_kvb = sat_per_kvb;
    }

    #[test]
    fn sendrawtransaction_and_testmempoolaccept_quote_the_floor_before_maxfeerate()
    -> Result<(), crate::support::TestError> {
        let plain = Arc::new(Context::new());
        let ordinary = funded_fee_tx(&plain, 0x80, 1_230);
        let handler = Handler::new(Arc::clone(&plain));
        handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&ordinary)]))?;
        assert!(
            pool_holds(&plain, &ordinary),
            "an ordinary between-the-guards tx must admit"
        );

        let strict = Arc::new(Context::new());
        set_relay_floor(&strict, 20_000_000);
        let both = funded_fee_tx(&strict, 0x81, 1_230);
        let handler = Handler::new(Arc::clone(&strict));
        let message = reject_message(
            &handler
                .dispatch("sendrawtransaction", &json!([raw_tx_hex(&both)]))
                .err()
                .ok_or("expected the floor to reject the both-predicates tx")?,
        );
        assert!(
            message.contains("min relay fee not met"),
            "the floor class must win: {message}"
        );
        assert!(
            !message.contains("max-fee-exceeded"),
            "maxfeerate must not be quoted first: {message}"
        );
        let rows = handler
            .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&both)]]))?
            .as_array()
            .ok_or("expected an array of results")?
            .clone();
        assert_eq!(
            rows.first()
                .ok_or("expected one row")?
                .get("allowed")
                .and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        assert_eq!(
            rows.first()
                .ok_or("expected one row")?
                .get("reject-reason")
                .and_then(JsonValueTrait::as_str),
            Some("min relay fee not met"),
            "testmempoolaccept must report the floor class, not max-fee"
        );
        assert!(
            !pool_holds(&strict, &both),
            "rejected tx must not enter the pool"
        );

        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 20_000_000,
            ..MempoolLimits::default()
        });
        let error = pool
            .insert_entry(MempoolEntry::new(Arc::new(both), 82, 1_230, 0, 1, 0))
            .err()
            .ok_or("pool path must also reject")?;
        assert!(matches!(
            error,
            bitcoin_rs_mempool::MempoolError::Policy(PolicyError::BelowMinRelayFee { .. })
        ));

        let capped = Arc::new(Context::new());
        let high = funded_fee_tx(&capped, 0x82, 1_230);
        let handler = Handler::new(Arc::clone(&capped));
        let error = handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&high), 0.00005]))
            .err()
            .ok_or("expected the client maxfeerate to reject")?;
        assert_eq!(error.code(), RpcError::INVALID_PARAMS);
        assert!(
            error.to_string().contains("max-fee-exceeded"),
            "unexpected message: {error}"
        );
        let rows = handler
            .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&high)], 0.00005]))?
            .as_array()
            .ok_or("expected an array of results")?
            .clone();
        assert_eq!(
            rows.first()
                .ok_or("expected one row")?
                .get("allowed")
                .and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        assert_eq!(
            rows.first()
                .ok_or("expected one row")?
                .get("reject-reason")
                .and_then(JsonValueTrait::as_str),
            Some("max-fee-exceeded")
        );
        Ok(())
    }

    #[test]
    fn rpc_outlets_enforce_the_configured_floor() -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        ctx.mempool
            .gateway
            .pool()
            .write()
            .limits
            .min_relay_fee_sat_per_kvb = 5_000;
        let handler = Handler::new(Arc::clone(&ctx));

        let below = tx(fund_utxo(&ctx, 0x83, 10_164), 10_000, 0xffff_ffff);
        let message = reject_message(
            &handler
                .dispatch("sendrawtransaction", &json!([raw_tx_hex(&below)]))
                .err()
                .ok_or("expected the configured floor to reject")?,
        );
        assert!(
            message.contains("min relay fee not met"),
            "unexpected message: {message}"
        );
        let rows = handler
            .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&below)]]))?
            .as_array()
            .ok_or("expected an array of results")?
            .clone();
        assert_eq!(
            rows.first()
                .ok_or("expected one row")?
                .get("reject-reason")
                .and_then(JsonValueTrait::as_str),
            Some("min relay fee not met")
        );

        let at_floor = tx(
            fund_utxo(&ctx, 0x84, 10_000 + floor_fee(5_000)),
            10_000,
            0xffff_ffff,
        );
        handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&at_floor)]))?;
        assert!(
            ctx.mempool
                .gateway
                .read()
                .contains_txid(&rpc_txid(&at_floor)),
            "exactly-at-floor tx must be pooled"
        );

        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 5_000,
            ..MempoolLimits::default()
        });
        let error = pool
            .insert_entry(MempoolEntry::new(Arc::new(below), 82, 164, 0, 1, 0))
            .err()
            .ok_or("pool path must also reject")?;
        assert_eq!(
            error,
            bitcoin_rs_mempool::MempoolError::Policy(PolicyError::BelowMinRelayFee {
                tx_rate: 2_000,
                min_rate: 5_000,
            })
        );
        pool.insert_entry(MempoolEntry::new(Arc::new(at_floor), 82, 410, 0, 1, 0))?;
        Ok(())
    }

    fn seeded_entry(tx: Arc<Tx>, vsize: u32, fee: u64) -> MempoolEntry {
        MempoolEntry::new(tx, vsize, fee, unix_time_secs(), 1, 0)
    }

    fn staged_outpoint(label: u8) -> OutPoint {
        OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[label; 32])),
            vout: 0,
        }
    }

    fn quoted_floors(handler: &Handler) -> Result<(f64, f64), crate::support::TestError> {
        let info = handler.dispatch("getmempoolinfo", &json!([]))?;
        let floor = info
            .get("mempoolminfee")
            .and_then(JsonValueTrait::as_f64)
            .ok_or("getmempoolinfo must quote mempoolminfee")?;
        let relay = info
            .get("minrelaytxfee")
            .and_then(JsonValueTrait::as_f64)
            .ok_or("getmempoolinfo must quote minrelaytxfee")?;
        Ok((floor, relay))
    }

    fn quotes_sat_per_kvb(quoted: f64, sat_per_kvb: u32) -> bool {
        (quoted - f64::from(sat_per_kvb) / 100_000_000.0).abs() < 1e-9
    }

    fn preview_verdict(
        handler: &Handler,
        transaction: &Tx,
    ) -> Result<(bool, Option<String>), crate::support::TestError> {
        let result = handler.dispatch("testmempoolaccept", &json!([[raw_tx_hex(transaction)]]))?;
        let rows = result.as_array().ok_or("expected an array of results")?;
        let row = rows.first().ok_or("expected one row")?;
        let allowed = row
            .get("allowed")
            .and_then(JsonValueTrait::as_bool)
            .ok_or("the row must carry allowed")?;
        let reason = row
            .get("reject-reason")
            .and_then(JsonValueTrait::as_str)
            .map(ToString::to_string);
        Ok((allowed, reason))
    }

    #[test]
    fn rpc_outlets_enforce_the_floor_a_capacity_eviction_left_behind()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let unit =
            bitcoin_rs_mempool::entry_memory_usage(&tx(staged_outpoint(0x86), 1_000, 0xffff_ffff));
        let mut cheap = tx(staged_outpoint(0x85), 1_000, 0xffff_ffff);
        cheap.outputs[0].script_pubkey =
            Script::from_bytes(vec![0x51; usize::try_from(2 * unit).unwrap_or(0)]);
        let cheap_txid = rpc_txid(&cheap);
        {
            let mut pool = ctx.mempool.gateway.pool().write();
            pool.limits.max_total_bytes = bitcoin_rs_mempool::entry_memory_usage(&cheap) + 2 * unit;
            pool.insert_entry(seeded_entry(Arc::new(cheap), 300, 300))?;
            let middle = tx(staged_outpoint(0x86), 1_000, 0xffff_ffff);
            pool.insert_entry(seeded_entry(Arc::new(middle), 100, 200))?;
            let dear = tx(staged_outpoint(0x89), 1_000, 0xffff_ffff);
            pool.insert_entry(seeded_entry(Arc::new(dear), 100, 400))?;
            assert_eq!(pool.total_vsize(), 500);
        }
        let handler = Handler::new(Arc::clone(&ctx));

        let (floor, relay) = quoted_floors(&handler)?;
        assert!(
            (floor - relay).abs() < 1e-9,
            "an unevicted pool quotes the configured floor: {floor} vs {relay}"
        );
        let early = funded_fee_tx(&ctx, 0x87, 163);
        assert_eq!(preview_verdict(&handler, &early)?, (true, None));

        let trigger = funded_fee_tx(&ctx, 0x88, 1_230);
        handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&trigger)]))?;
        assert!(
            pool_holds(&ctx, &trigger),
            "the spend that overflowed stays"
        );
        assert!(
            !ctx.mempool.gateway.read().contains_txid(&cheap_txid),
            "the cheapest package must be the one evicted"
        );
        assert_eq!(ctx.mempool.gateway.read().len(), 3);

        let (floor, _) = quoted_floors(&handler)?;
        assert!(quotes_sat_per_kvb(floor, 2_000), "floor quoted {floor}");

        let lukewarm = funded_fee_tx(&ctx, 0x8a, 163);
        let message = reject_message(
            &handler
                .dispatch("sendrawtransaction", &json!([raw_tx_hex(&lukewarm)]))
                .err()
                .ok_or("expected the rolling floor to reject")?,
        );
        assert!(
            message.contains("min relay fee not met"),
            "unexpected message: {message}"
        );
        assert!(
            !message.contains("max-fee-exceeded"),
            "unexpected message: {message}"
        );
        assert_eq!(
            preview_verdict(&handler, &lukewarm)?,
            (false, Some("min relay fee not met".to_owned()))
        );

        let at_floor = funded_fee_tx(&ctx, 0x8b, floor_fee(2_000));
        assert_eq!(preview_verdict(&handler, &at_floor)?, (true, None));

        ctx.mempool
            .gateway
            .pool()
            .write()
            .insert_entry(seeded_entry(Arc::new(lukewarm), 82, 163))?;
        assert_eq!(ctx.mempool.gateway.read().len(), 4);

        let idle = Arc::new(Context::new());
        let control = funded_fee_tx(&idle, 0x8c, 163);
        Handler::new(Arc::clone(&idle))
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&control)]))?;
        assert!(
            pool_holds(&idle, &control),
            "an unevicted control tx must be pooled"
        );
        Ok(())
    }

    #[test]
    fn package_preview_leaves_other_rows_unfinished_after_a_precheck_failure()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let good = tx(fund_utxo(&ctx, 0x51, 10_000), 9_000, 0xffff_ffff);
        let below_min = tx(fund_utxo(&ctx, 0x52, 10_000), 9_999, 0xffff_ffff);
        let later = tx(fund_utxo(&ctx, 0x53, 10_000), 9_000, 0xffff_ffff);
        let handler = Handler::new(Arc::clone(&ctx));
        let rows = handler.dispatch(
            "testmempoolaccept",
            &json!([[
                raw_tx_hex(&good),
                raw_tx_hex(&below_min),
                raw_tx_hex(&later),
            ]]),
        )?;
        for index in [0, 2] {
            assert!(rows[index].get("allowed").is_none());
            assert!(rows[index].get("fees").is_none());
            assert!(rows[index].get("reject-reason").is_none());
        }
        assert_eq!(rows[1]["allowed"].as_bool(), Some(false));
        assert_eq!(
            rows[1]["reject-reason"].as_str(),
            Some("min relay fee not met")
        );
        assert!(rows[1].get("fees").is_none());
        assert_eq!(ctx.mempool.gateway.read().len(), 0);
        Ok(())
    }

    #[test]
    fn sendrawtransaction_rejects_oversized_and_nonstandard_txs()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));

        let mut oversized = tx(fund_utxo(&ctx, 0x55, 10_000), 1_000, 0xffff_ffff);
        oversized.outputs = (0..3_400)
            .map(|_| TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: Script::from_bytes(p2wpkh_script()),
            })
            .collect();
        let message = reject_message(
            &handler
                .dispatch("sendrawtransaction", &json!([raw_tx_hex(&oversized)]))
                .err()
                .ok_or("expected oversized rejection")?,
        );
        assert_eq!(
            message, "tx-size",
            "Core answers tx-size for an oversize transaction"
        );

        let weird = Tx {
            outputs: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: Script::from_bytes(op_true_script()),
            }],
            ..tx(fund_utxo(&ctx, 0x56, 10_000), 9_000, 0xffff_ffff)
        };
        let message = reject_message(
            &handler
                .dispatch("sendrawtransaction", &json!([raw_tx_hex(&weird)]))
                .err()
                .ok_or("expected non-standard rejection")?,
        );
        assert!(message.contains("non-standard output script"));
        Ok(())
    }

    fn insert_original(
        ctx: &Context,
        label: u8,
        sequence: u32,
        vsize: u32,
        fee: u64,
    ) -> Result<Tx, crate::support::TestError> {
        let original = tx(fund_utxo(ctx, label, 100_000), 92_000, sequence);
        ctx.mempool
            .gateway
            .pool()
            .write()
            .insert_entry(seeded_entry(Arc::new(original.clone()), vsize, fee))?;
        Ok(original)
    }

    #[test]
    fn sendrawtransaction_applies_an_rbf_replacement_and_sweeps_the_conflicts()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let original = insert_original(&ctx, 0x60, 0xffff_fffd, 4_000, 8_000)?;
        let replacement = tx(confirmed_outpoint(0x60), 90_000, 0xffff_ffff);
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))?;
        assert_eq!(
            result.as_str().map(ToString::to_string),
            Some(rpc_txid(&replacement).to_string())
        );
        {
            let pool = ctx.mempool.gateway.read();
            assert!(
                !pool.contains_txid(&rpc_txid(&original)),
                "the replaced original must be evicted"
            );
            assert!(
                pool.contains_txid(&rpc_txid(&replacement)),
                "the replacement must be pooled"
            );
        }

        let mut pool = Mempool::new(MempoolLimits::default());
        pool.insert_entry(MempoolEntry::new(Arc::new(original), 4_000, 8_000, 0, 1, 0))?;
        pool.replace_transaction(
            &ReplacementCandidate::new(Arc::new(replacement.clone()), 82, 10_000, 1_000),
            0,
            1,
        )?;
        assert!(pool.contains_txid(&rpc_txid(&replacement)));
        Ok(())
    }

    #[derive(Default)]
    struct RecordingGatewayObserver {
        changes: parking_lot::Mutex<Vec<(u64, Hash256, MutationOutcome)>>,
    }

    impl MempoolObserver for RecordingGatewayObserver {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            let result = &envelope.result;
            let mut changes = self.changes.lock();
            for (offset, change) in result.changes.iter().enumerate() {
                let sequence = result.sequence_of(offset).unwrap_or(u64::MAX);
                changes.push((sequence, change.txid, change.outcome));
            }
        }
    }

    #[test]
    fn sendrawtransaction_publishes_admission_through_gateway()
    -> Result<(), crate::support::TestError> {
        let observer = Arc::new(RecordingGatewayObserver::default());
        let ctx = Arc::new(Context::new_with_mempool_observer(observer.clone()));
        let plain = tx(fund_utxo(&ctx, 0x51, 100_000), 90_000, 0xffff_ffff);
        let plain_txid = rpc_txid(&plain);
        let handler = Handler::new(Arc::clone(&ctx));
        handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&plain)]))?;
        {
            let changes = observer.changes.lock();
            assert_eq!(
                *changes,
                vec![(1, Hash256::from(plain_txid), MutationOutcome::Accepted)],
                "the first production A event: one Accepted change"
            );
        }

        let original = insert_original(&ctx, 0x52, 0xffff_fffd, 4_000, 8_000)?;
        let original_txid = rpc_txid(&original);
        let child = tx(OutPoint::new(original_txid, 0), 91_000, 0xffff_fffd);
        let child_txid = rpc_txid(&child);
        ctx.mempool
            .gateway
            .pool()
            .write()
            .insert_entry(seeded_entry(
                Arc::new(child.clone()),
                u32::try_from(child.vsize()).unwrap_or(u32::MAX),
                1_000,
            ))?;
        observer.changes.lock().clear();

        let replacement = tx(confirmed_outpoint(0x52), 88_000, 0xffff_ffff);
        let replacement_txid = rpc_txid(&replacement);
        handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))?;

        let changes = observer.changes.lock();
        assert_eq!(
            *changes,
            vec![
                (
                    4,
                    Hash256::from(original_txid),
                    MutationOutcome::Removed(RemovalReason::Replaced),
                ),
                (
                    5,
                    Hash256::from(child_txid),
                    MutationOutcome::Removed(RemovalReason::Descendant),
                ),
                (
                    6,
                    Hash256::from(replacement_txid),
                    MutationOutcome::Accepted,
                ),
            ],
            "one result, commit order: conflicts first (parent before descendant), then the replacement"
        );
        Ok(())
    }

    #[test]
    fn new_unconfirmed_inputs_are_allowed_on_both_rpcs() -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let original = insert_original(&ctx, 0x98, 0xffff_fffd, 4_000, 8_000)?;
        let mut unrelated = tx(fund_utxo(&ctx, 0x99, 10_000), 9_000, 0xffff_ffff);
        unrelated.outputs[0].script_pubkey = Script::from_bytes(p2sh_true_script());
        ctx.mempool
            .gateway
            .pool()
            .write()
            .insert_entry(seeded_entry(Arc::new(unrelated.clone()), 100, 1_000))?;
        let replacement = tx_spending(
            &[
                (confirmed_outpoint(0x98), 0xffff_ffff),
                (OutPoint::new(rpc_txid(&unrelated), 0), 0xffff_ffff),
            ],
            100_000,
        );
        let handler = Handler::new(Arc::clone(&ctx));
        let before = ctx.mempool.gateway.read().sequence_number();
        let rows = handler.dispatch("testmempoolaccept", &json!([[raw_tx_hex(&replacement)]]))?;
        assert_eq!(rows[0]["allowed"].as_bool(), Some(true), "{rows:?}");
        assert_eq!(ctx.mempool.gateway.read().sequence_number(), before);
        let candidate = ReplacementCandidate::new(
            Arc::new(replacement.clone()),
            u32::try_from(replacement.vsize())?,
            9_000,
            1_000,
        );
        ctx.mempool.gateway.read().check_replacement(&candidate)?;
        handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))?;
        let pool = ctx.mempool.gateway.read();
        assert!(!pool.contains_txid(&rpc_txid(&original)));
        assert!(pool.contains_txid(&rpc_txid(&unrelated)));
        assert!(pool.contains_txid(&rpc_txid(&replacement)));
        Ok(())
    }

    #[test]
    fn sendrawtransaction_rejects_rule3_replacements_that_underpay_evicted_fees()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let original = insert_original(&ctx, 0x9a, 0xffff_fffd, 4_000, 8_000)?;
        let replacement = tx(confirmed_outpoint(0x9a), 96_000, 0xffff_ffff);
        let handler = Handler::new(Arc::clone(&ctx));
        let message = reject_message(
            &handler
                .dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))
                .err()
                .ok_or("expected rule 3 rejection")?,
        );
        assert!(
            message.contains("insufficient fee"),
            "unexpected message: {message}"
        );
        let rows = handler
            .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&replacement)]]))?
            .as_array()
            .ok_or("expected an array of results")?
            .clone();
        assert_eq!(
            rows.first()
                .ok_or("expected one row")?
                .get("reject-reason")
                .and_then(JsonValueTrait::as_str),
            Some("insufficient fee")
        );
        assert!(
            ctx.mempool
                .gateway
                .read()
                .contains_txid(&rpc_txid(&original)),
            "a rejected replacement leaves the original pooled"
        );

        let candidate = ReplacementCandidate::new(Arc::new(replacement), 82, 4_000, 1_000);
        assert_eq!(
            ctx.mempool.gateway.read().check_replacement(&candidate),
            Err(RbfError::Rule3InsufficientAbsoluteFee)
        );
        Ok(())
    }

    #[test]
    fn sendrawtransaction_rejects_a_crossing_replacement_diagram()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let original = tx(fund_utxo(&ctx, 0x9b, 200_000), 192_000, 0xffff_fffd);
        ctx.mempool
            .gateway
            .pool()
            .write()
            .insert_entry(seeded_entry(Arc::new(original.clone()), 4_000, 8_000))?;

        let (replacement, fee) = {
            let mut found = None;
            for count in 320_usize..=400 {
                let candidate = many_output_tx(confirmed_outpoint(0x9b), 500, count);
                let vsize = u64::from(u32::try_from(candidate.vsize()).unwrap_or(u32::MAX));
                let candidate_fee = 200_000 - 500 * u64::try_from(count).unwrap_or(u64::MAX);
                let rate = candidate_fee * 1_000 / vsize;
                if candidate_fee >= 8_000 + vsize && (1_000..=2_000).contains(&rate) {
                    found = Some((candidate, candidate_fee));
                    break;
                }
            }
            found.ok_or("no output count satisfies the rule-6 shape")?
        };
        let handler = Handler::new(Arc::clone(&ctx));
        let message = reject_message(
            &handler
                .dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))
                .err()
                .ok_or("expected rule 6 rejection")?,
        );
        assert!(
            message.contains("replacement-failed"),
            "unexpected message: {message}"
        );
        let rows = handler
            .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&replacement)]]))?
            .as_array()
            .ok_or("expected an array of results")?
            .clone();
        assert_eq!(
            rows.first()
                .ok_or("expected one row")?
                .get("reject-reason")
                .and_then(JsonValueTrait::as_str),
            Some("replacement-failed")
        );
        assert!(
            ctx.mempool
                .gateway
                .read()
                .contains_txid(&rpc_txid(&original)),
            "a rejected replacement leaves the original pooled"
        );

        let vsize = u32::try_from(replacement.vsize()).unwrap_or(u32::MAX);
        let candidate = ReplacementCandidate::new(Arc::new(replacement), vsize, fee, 1_000);
        assert_eq!(
            ctx.mempool.gateway.read().check_replacement(&candidate),
            Err(RbfError::InsufficientFeerateDiagram)
        );
        Ok(())
    }

    fn assert_both_rpcs_agree_on_replacement_rejection(
        handler: &Handler,
        tx_hex: &str,
        tx: &Tx,
        expected_reason_fragment: &str,
        expected_rbf_error: RbfError,
        mempool: &Arc<MempoolGateway>,
    ) -> Result<sonic_rs::Value, crate::support::TestError> {
        let message = reject_message(
            &handler
                .dispatch("sendrawtransaction", &json!([tx_hex]))
                .err()
                .ok_or("expected sendrawtransaction rejection")?,
        );
        assert!(
            message.contains(expected_reason_fragment),
            "sendrawtransaction: unexpected message: {message}"
        );

        let rows = handler
            .dispatch("testmempoolaccept", &json!([[tx_hex]]))?
            .as_array()
            .ok_or("expected an array of results")?
            .clone();
        let row = rows.first().ok_or("expected one row")?.clone();
        assert_eq!(
            row.get("allowed").and_then(JsonValueTrait::as_bool),
            Some(false),
            "preview must reject"
        );
        let reject_reason = row
            .get("reject-reason")
            .and_then(JsonValueTrait::as_str)
            .ok_or("expected reject-reason")?;
        assert!(
            reject_reason.contains(expected_reason_fragment),
            "testmempoolaccept: unexpected reject-reason: {reject_reason}"
        );

        let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
        let fee = {
            let input_value = 100_000_u64;
            let output_value = tx
                .outputs
                .iter()
                .fold(0_u64, |sum, o| sum.saturating_add(o.value.to_sat()));
            input_value.saturating_sub(output_value)
        };
        let candidate = ReplacementCandidate::new(Arc::new(tx.clone()), vsize, fee, 1_000);
        let pool = mempool.read();
        assert_eq!(
            pool.check_replacement(&candidate),
            Err(expected_rbf_error),
            "pool check_replacement must reject with the exact BIP125 rule"
        );
        Ok(row)
    }

    #[test]
    fn nonsignaling_replacements_agree_on_both_rpcs() -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let original = insert_original(&ctx, 0xa1, 0xffff_ffff, 4_000, 8_000)?;
        let replacement = tx(confirmed_outpoint(0xa1), 90_000, 0xffff_ffff);
        let handler = Handler::new(Arc::clone(&ctx));

        let sequence = ctx.mempool.gateway.read().sequence_number();
        let rows = handler.dispatch("testmempoolaccept", &json!([[raw_tx_hex(&replacement)]]))?;
        let row = rows
            .as_array()
            .and_then(|rows| rows.first())
            .ok_or("expected preview row")?;
        assert_eq!(
            row.get("allowed").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        assert_eq!(ctx.mempool.gateway.read().sequence_number(), sequence);
        assert!(
            ctx.mempool
                .gateway
                .read()
                .contains_txid(&rpc_txid(&original))
        );
        let result = handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))?;
        assert_eq!(result, json!(rpc_txid(&replacement).to_string()));
        let pool = ctx.mempool.gateway.read();
        assert!(!pool.contains_txid(&rpc_txid(&original)));
        assert!(pool.contains_txid(&rpc_txid(&replacement)));
        assert_eq!(pool.len(), 1);
        assert!(pool.sequence_number() > sequence);
        Ok(())
    }

    #[test]
    fn bip125_rule4_replacement_must_pay_incremental_relay_fee_on_both_rpcs()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let _original = insert_original(&ctx, 0xa4, 0xffff_fffd, 4_000, 8_000)?;
        let replacement = tx(confirmed_outpoint(0xa4), 92_000, 0xffff_ffff);
        let handler = Handler::new(Arc::clone(&ctx));

        let _row = assert_both_rpcs_agree_on_replacement_rejection(
            &handler,
            &raw_tx_hex(&replacement),
            &replacement,
            "insufficient fee",
            RbfError::Rule4InsufficientIncrementalFee,
            &ctx.mempool.gateway,
        )?;
        Ok(())
    }

    #[test]
    fn replacement_counts_conflicting_clusters_instead_of_descendants()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        {
            let mut pool = ctx.mempool.gateway.pool().write();
            pool.limits.cluster_count = 400;
            pool.limits.cluster_size_vbytes = 1_000_000;
        }
        let original = insert_original(&ctx, 0xa5, 0xffff_fffd, 4_000, 8_000)?;
        let original_txid = rpc_txid(&original);
        {
            let mut pool = ctx.mempool.gateway.pool().write();
            let mut prev = OutPoint::new(original_txid, 0);
            for _ in 0..100_u32 {
                let child = tx(prev, 400, 0xffff_ffff);
                prev = OutPoint::new(rpc_txid(&child), 0);
                pool.insert_entry(seeded_entry(Arc::new(child), 50, 100))?;
            }
        }
        let replacement = tx(confirmed_outpoint(0xa5), 80_000, 0xffff_ffff);
        let handler = Handler::new(Arc::clone(&ctx));

        let rows = handler.dispatch("testmempoolaccept", &json!([[raw_tx_hex(&replacement)]]))?;
        assert_eq!(rows[0]["allowed"].as_bool(), Some(true), "{rows:?}");
        assert_eq!(ctx.mempool.gateway.read().len(), 101);
        handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))?;
        assert_eq!(ctx.mempool.gateway.read().len(), 1);
        assert!(
            ctx.mempool
                .gateway
                .read()
                .contains_txid(&rpc_txid(&replacement))
        );
        Ok(())
    }

    fn chain_pool(ctx: &Context) -> Result<Vec<Tx>, crate::support::TestError> {
        let mut pool = ctx.mempool.gateway.pool().write();
        let mut txs = Vec::new();
        let mut previous = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[0x62; 32])),
            vout: 0,
        };
        for _ in 0..25 {
            let mut next = tx(previous, 1_000, 0xffff_ffff);
            next.outputs[0].script_pubkey = Script::from_bytes(p2sh_true_script());
            previous = OutPoint::new(next.txid(), 0);
            pool.insert_entry(seeded_entry(Arc::new(next.clone()), 4_000, 4_000))?;
            txs.push(next);
        }
        Ok(txs)
    }

    fn tx_multi_child(funded: &OutPoint, tip: &Tx) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![
                TxIn {
                    previous_output: *funded,
                    script_sig: p2sh_true_script_sig(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint::new(tip.txid(), 0),
                    script_sig: p2sh_true_script_sig(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            ],
            outputs: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: Script::from_bytes(p2wpkh_script()),
            }],
        }
    }

    #[test]
    fn both_rpcs_allow_more_than_25_ancestors_within_cluster_limits()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let chain = chain_pool(&ctx)?;
        let tip = chain.last().ok_or("empty chain")?;
        let follower = tx_multi_child(&fund_utxo(&ctx, 0x64, 100_000), tip);
        let handler = Handler::new(Arc::clone(&ctx));
        let rows = handler.dispatch("testmempoolaccept", &json!([[raw_tx_hex(&follower)]]))?;
        assert_eq!(rows[0]["allowed"].as_bool(), Some(true), "{rows:?}");
        handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&follower)]))?;
        assert_eq!(ctx.mempool.gateway.read().len(), 26);
        Ok(())
    }

    #[test]
    fn testmempoolaccept_and_sendrawtransaction_agree_on_cluster_count_limits()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let root = {
            let mut pool = ctx.mempool.gateway.pool().write();
            pool.limits.cluster_count = 1;
            let root = tx(
                OutPoint {
                    txid: Txid(Hash256::from_le_bytes(&[0xc1; 32])),
                    vout: 0,
                },
                50_000,
                0xffff_ffff,
            );
            pool.insert_entry(seeded_entry(Arc::new(root.clone()), 100, 10_000))?;
            root
        };
        let follower = tx_multi_child(&fund_utxo(&ctx, 0xc2, 100_000), &root);
        let handler = Handler::new(Arc::clone(&ctx));

        let rows = handler
            .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&follower)]]))?
            .as_array()
            .ok_or("expected an array of results")?
            .clone();
        let row = rows.first().ok_or("expected one row")?;
        assert_eq!(
            row.get("allowed").and_then(JsonValueTrait::as_bool),
            Some(false),
            "preview must surface cluster count limits"
        );
        let reject_reason = row
            .get("reject-reason")
            .and_then(JsonValueTrait::as_str)
            .ok_or("expected reject-reason")?;
        assert!(
            reject_reason.contains("too-large-cluster"),
            "unexpected reject-reason: {reject_reason}"
        );

        let message = reject_message(
            &handler
                .dispatch("sendrawtransaction", &json!([raw_tx_hex(&follower)]))
                .err()
                .ok_or("expected admission to enforce the cluster count")?,
        );
        assert!(
            message.contains("too-large-cluster"),
            "unexpected message: {message}"
        );

        let mut pool = Mempool::new(MempoolLimits {
            cluster_count: 1,
            ..MempoolLimits::default()
        });
        pool.insert_entry(MempoolEntry::new(Arc::new(root), 100, 10_000, 0, 1, 0))?;
        let error = pool
            .insert_entry(MempoolEntry::new(Arc::new(follower), 82, 10_000, 0, 1, 0))
            .err()
            .ok_or("pool path must also reject")?;
        assert_eq!(
            error,
            bitcoin_rs_mempool::MempoolError::Policy(PolicyError::ClusterCountLimit)
        );
        Ok(())
    }

    #[test]
    fn testmempoolaccept_and_sendrawtransaction_agree_on_cluster_size_limits()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let root = {
            let mut pool = ctx.mempool.gateway.pool().write();
            pool.limits.cluster_count = 100;
            pool.limits.cluster_size_vbytes = 250;
            let root = tx(
                OutPoint {
                    txid: Txid(Hash256::from_le_bytes(&[0xc3; 32])),
                    vout: 0,
                },
                50_000,
                0xffff_ffff,
            );
            pool.insert_entry(seeded_entry(Arc::new(root.clone()), 200, 10_000))?;
            root
        };
        let follower = tx_multi_child(&fund_utxo(&ctx, 0xc4, 100_000), &root);
        let handler = Handler::new(Arc::clone(&ctx));

        let rows = handler
            .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&follower)]]))?
            .as_array()
            .ok_or("expected an array of results")?
            .clone();
        let row = rows.first().ok_or("expected one row")?;
        assert_eq!(
            row.get("allowed").and_then(JsonValueTrait::as_bool),
            Some(false),
            "preview must surface cluster size limits"
        );
        let reject_reason = row
            .get("reject-reason")
            .and_then(JsonValueTrait::as_str)
            .ok_or("expected reject-reason")?;
        assert!(
            reject_reason.contains("too-large-cluster"),
            "unexpected reject-reason: {reject_reason}"
        );

        let message = reject_message(
            &handler
                .dispatch("sendrawtransaction", &json!([raw_tx_hex(&follower)]))
                .err()
                .ok_or("expected admission to enforce the cluster size")?,
        );
        assert!(
            message.contains("too-large-cluster"),
            "unexpected message: {message}"
        );
        Ok(())
    }

    #[test]
    fn testmempoolaccept_and_sendrawtransaction_agree_on_replacement_into_a_full_cluster()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let (root, original) = {
            let mut pool = ctx.mempool.gateway.pool().write();
            pool.limits.cluster_count = 2;
            let root = Tx {
                outputs: vec![TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: Script::from_bytes(p2sh_true_script()),
                }],
                ..tx(
                    OutPoint {
                        txid: Txid(Hash256::from_le_bytes(&[0xc5; 32])),
                        vout: 0,
                    },
                    50_000,
                    0xffff_ffff,
                )
            };
            let original = tx(OutPoint::new(rpc_txid(&root), 0), 40_000, 0xffff_fffd);
            pool.insert_entry(seeded_entry(Arc::new(root.clone()), 100, 10_000))?;
            pool.insert_entry(seeded_entry(Arc::new(original.clone()), 100, 10_000))?;
            (root, original)
        };
        let replacement = tx(OutPoint::new(rpc_txid(&root), 0), 30_000, 0xffff_ffff);
        let handler = Handler::new(Arc::clone(&ctx));

        let rows = handler
            .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&replacement)]]))?
            .as_array()
            .ok_or("expected an array of results")?
            .clone();
        let row = rows.first().ok_or("expected one row")?;
        assert_eq!(
            row.get("allowed").and_then(JsonValueTrait::as_bool),
            Some(true),
            "preview must allow a replacement that does not grow the cluster: {row:?}"
        );

        let result = handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))?;
        assert_eq!(
            result.as_str().map(ToString::to_string),
            Some(rpc_txid(&replacement).to_string())
        );
        {
            let pool = ctx.mempool.gateway.read();
            assert!(
                !pool.contains_txid(&rpc_txid(&original)),
                "the replaced original must leave"
            );
            assert!(
                pool.contains_txid(&rpc_txid(&replacement)),
                "the replacement must be pooled"
            );
            assert!(
                pool.contains_txid(&rpc_txid(&root)),
                "the shared parent must remain"
            );
        }
        Ok(())
    }

    fn tx_spending(inputs: &[(OutPoint, u32)], output_value: u64) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: inputs
                .iter()
                .map(|(prevout, sequence)| TxIn {
                    previous_output: *prevout,
                    script_sig: p2sh_true_script_sig(),
                    sequence: Sequence::from_consensus(*sequence),
                    witness: Witness::new(),
                })
                .collect(),
            outputs: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: Script::from_bytes(p2wpkh_script()),
            }],
        }
    }

    fn many_output_tx(prevout: OutPoint, value_each: u64, count: usize) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: prevout,
                script_sig: p2sh_true_script_sig(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(value_each),
                    script_pubkey: Script::from_bytes(p2wpkh_script()),
                };
                count
            ],
        }
    }

    #[test]
    fn sendrawtransaction_admission_evicts_the_lowest_fee_packages_under_size_pressure()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let root = |label: u8| OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[label; 32])),
            vout: 0,
        };
        let (high_txid, low_txid, mid_txid) = {
            let mut pool = ctx.mempool.gateway.pool().write();
            let unit = bitcoin_rs_mempool::entry_memory_usage(&tx(root(0x90), 1_000, 0xffff_ffff));
            let heavy = |label: u8| {
                let mut heavy = tx(root(label), 1_000, 0xffff_ffff);
                heavy.outputs[0].script_pubkey =
                    Script::from_bytes(vec![0x51; usize::try_from(2 * unit).unwrap_or(0)]);
                heavy
            };
            let high = heavy(0x90);
            let high_txid = high.txid();
            pool.insert_entry(seeded_entry(Arc::new(high), 1_000, 3_000))?;
            let low = heavy(0x91);
            let low_txid = low.txid();
            pool.insert_entry(seeded_entry(Arc::new(low), 1_000, 1_000))?;
            let mid = heavy(0x92);
            let mid_txid = mid.txid();
            pool.insert_entry(seeded_entry(Arc::new(mid), 1_000, 2_000))?;
            pool.limits.max_total_bytes = 5 * unit + unit / 2;
            (high_txid, low_txid, mid_txid)
        };
        let overflow = tx(fund_utxo(&ctx, 0x93, 106_000), 100_000, 0xffff_ffff);
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&overflow)]))?;
        assert_eq!(
            result.as_str().map(ToString::to_string),
            Some(rpc_txid(&overflow).to_string())
        );

        {
            let pool = ctx.mempool.gateway.read();
            assert!(
                pool.contains_txid(&high_txid),
                "the highest-rate package must survive"
            );
            assert!(
                !pool.contains_txid(&low_txid),
                "the lowest-rate package must evict first"
            );
            assert!(
                !pool.contains_txid(&mid_txid),
                "the mid-rate package must evict next"
            );
            assert_eq!(pool.len(), 2);
            assert!(
                pool.dynamic_memory_usage() <= pool.limits.max_total_bytes,
                "pool must fit the size bound again"
            );
        }

        let (floor, _) = quoted_floors(&handler)?;
        assert!(quotes_sat_per_kvb(floor, 3_000), "floor quoted {floor}");

        let evicted_rate = funded_fee_tx(&ctx, 0x94, 164);
        let message = reject_message(
            &handler
                .dispatch("sendrawtransaction", &json!([raw_tx_hex(&evicted_rate)]))
                .err()
                .ok_or("expected the evicted rate to be refused")?,
        );
        assert!(
            message.contains("min relay fee not met"),
            "unexpected message: {message}"
        );
        assert_eq!(
            preview_verdict(&handler, &evicted_rate)?,
            (false, Some("min relay fee not met".to_owned()))
        );
        let at_floor = funded_fee_tx(&ctx, 0x95, floor_fee(3_000));
        handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&at_floor)]))?;
        assert!(
            pool_holds(&ctx, &at_floor),
            "an at-floor spend must be pooled"
        );
        Ok(())
    }

    #[test]
    fn testmempoolaccept_and_sendrawtransaction_agree_on_each_class()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let good = tx(fund_utxo(&ctx, 0x70, 10_000), 9_000, 0xffff_ffff);
        let below_min = tx(fund_utxo(&ctx, 0x71, 10_000), 9_999, 0xffff_ffff);
        let nonstandard = Tx {
            outputs: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: Script::from_bytes(op_true_script()),
            }],
            ..tx(fund_utxo(&ctx, 0x72, 10_000), 9_000, 0xffff_ffff)
        };
        let dust = Tx {
            outputs: vec![TxOut {
                value: Amount::from_sat(100),
                script_pubkey: Script::from_bytes(p2wpkh_script()),
            }],
            ..tx(fund_utxo(&ctx, 0x73, 10_000), 100, 0xffff_ffff)
        };
        let txs = [&good, &below_min, &nonstandard, &dust];

        let handler = Handler::new(Arc::clone(&ctx));
        for tx in txs {
            let rows = handler.dispatch("testmempoolaccept", &json!([[raw_tx_hex(tx)]]))?;
            let preview_allowed = rows[0]["allowed"].as_bool().ok_or("row missing allowed")?;
            let submitted = handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(tx)]));
            assert_eq!(submitted.is_ok(), preview_allowed, "{rows:?}");
        }
        Ok(())
    }

    #[test]
    fn decode_failures_reject_with_deserialization_error() -> Result<(), crate::support::TestError>
    {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));
        let error = handler
            .dispatch("sendrawtransaction", &json!(["zznotahexzz"]))
            .err()
            .ok_or("expected a decode rejection")?;
        assert_eq!(error.code(), -22);
        Ok(())
    }

    const REORG_SEED_BLOCKS: u32 = 100;
    const REORG_SEED_BASE_TIME: u32 = 1_296_688_603;
    const REORG_SEED_BLOCK_INTERVAL: u32 = 600;
    const REORG_SUBSIDY_SATS: u64 = 50 * 100_000_000;
    const REORG_SPEND_FEE_SATS: u64 = 10_000;

    struct NodeInvalidator {
        handles: Arc<bitcoin_rs_execution::Chainstate>,
        followers: bitcoin_rs_node::ChainFollowers,
    }

    impl ChainControl for NodeInvalidator {
        fn invalidate_block(&self, hash: Hash256) -> core::result::Result<(), ChainControlError> {
            invalidate_block(&self.handles, &self.followers, hash)
                .map(|_| ())
                .map_err(|error| match error {
                    ReorgError::UnknownBlock(_) => ChainControlError::UnknownBlock,
                    ReorgError::CannotInvalidateGenesis => ChainControlError::Genesis,
                    other => ChainControlError::Failed(other.to_string()),
                })
        }

        fn dump_txoutset(
            &self,
            _path: &std::path::Path,
            _cancellation: &bitcoin_rs_consensus::latch::LatchReader,
        ) -> Result<
            bitcoin_rs_serving::context::SnapshotExport,
            bitcoin_rs_serving::context::SnapshotControlError,
        > {
            Err(
                bitcoin_rs_serving::context::SnapshotControlError::Unavailable(
                    "snapshot export is not attached to this fixture".to_owned(),
                ),
            )
        }

        fn verify_chain(
            &self,
            _check_level: u8,
            _nblocks: u32,
            _cancellation: &bitcoin_rs_consensus::latch::LatchReader,
        ) -> Result<bool, ChainControlError> {
            Ok(false)
        }
    }

    fn open_regtest_state() -> Result<(NodeState, tempfile::TempDir), crate::support::TestError> {
        let dir = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p.listen.clear();
        let state = NodeState::open(config, None)?;
        Ok((state, dir))
    }

    fn reorg_seed_coinbase(height: u32) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes([push_int(i64::from(height)), push_int(0)].concat()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(REORG_SUBSIDY_SATS),
                script_pubkey: Script::from_bytes(p2sh_true_script()),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn reorg_seed_coinbase_spend_with_fee(fee_sats: u64) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(reorg_seed_coinbase(1).txid(), 0),
                script_sig: p2sh_true_script_sig(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(REORG_SUBSIDY_SATS - fee_sats),
                script_pubkey: Script::from_bytes(
                    [vec![0xa9, 0x14], vec![0x22; 20], vec![0x87]].concat(),
                ),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn reorg_mine_and_apply(
        state: &NodeState,
        prev: Hash256,
        height: u32,
        txs: Vec<Tx>,
    ) -> Result<Block, crate::support::TestError> {
        let mut block = Block {
            header: bitcoin_rs_consensus::primitives::Header {
                version: 0x2000_0000,
                prev_blockhash: bitcoin_rs_consensus::primitives::BlockHash::from(prev),
                merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                time: REORG_SEED_BASE_TIME
                    .saturating_add(REORG_SEED_BLOCK_INTERVAL.saturating_mul(height)),
                bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
                nonce: 0,
            },
            txs: std::iter::once(reorg_seed_coinbase(height))
                .chain(txs)
                .collect(),
        };
        block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
            .ok_or("mined block must have a merkle root")?;
        regtest_fixture::mine_block_to_declared_target(&mut block)?;
        state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            block.clone(),
        ))?;
        Ok(block)
    }

    fn applied_tip_pair(state: &NodeState) -> Result<(Hash256, u32), crate::support::TestError> {
        let applied = state.chainstate().applied_tip_reader();
        let Some(tip) = applied.load_full() else {
            return Err(crate::support::TestError::Missing("applied tip must exist"));
        };
        Ok((tip.hash, tip.height))
    }

    fn invalidation_handler(state: &NodeState) -> Handler {
        let chainstate = state.chainstate();
        Handler::new(Arc::new(Context::from_handles(ContextHandles {
            chain: ChainHandles {
                chain_tip: chainstate.header_tip_reader(),
                applied_tip: chainstate.applied_tip_reader(),
                active_tip_wait: Some(chainstate.clone()),
                progress: chainstate.chain_progress_reader(),
                blocks: state.block_log_reader(),
                utxo: chainstate.utxo_reader(),
                coin_stats: chainstate.coin_stats_handle(),
                block_tree: chainstate.block_tree_reader(),
                chain_network: Network::Regtest,
                closed_for_recovery: chainstate.closed_for_recovery_reader(),
                chain_transition: state.stable_read(),
                chain_control: Some(Arc::new(NodeInvalidator {
                    handles: chainstate,
                    followers: state.chain_followers(),
                })),
                ..ChainHandles::default()
            },
            mempool: MempoolHandles {
                gateway: state.mempool_gateway(),
            },
            indexes: IndexHandles {
                derived_index: None,
                script_index: None,
                compact_filters: None,
                esplora_tx_index: None,
                derived_index_status: None,
            },
            network: NetworkHandles {
                overlay: bitcoin_rs_wire::overlay::OverlayConfig::default(),
                peer_table: state.peer_table(),
                p2p: state.p2p(),
                local_services: state.p2p().local_services().to_u64(),
                user_agent: state.p2p().user_agent().to_owned(),
                v2_transport: state.config().p2p.v2_transport,
            },
            mining: MiningHandles {
                mining_control: None,
            },
            ..ContextHandles::default()
        })))
    }

    #[test]
    fn invalidateblock_returns_a_mature_coinbase_spend_to_the_mempool_and_excludes_the_coinbase()
    -> Result<(), crate::support::TestError> {
        let (state, _dir) = open_regtest_state()?;
        let genesis = Network::Regtest.genesis_block();
        state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            genesis,
        ))?;
        for height in 1..=REORG_SEED_BLOCKS {
            let (prev, _) = applied_tip_pair(&state)?;
            reorg_mine_and_apply(&state, prev, height, Vec::new())?;
        }
        let (seed_tip, seed_height) = applied_tip_pair(&state)?;
        assert_eq!(seed_height, REORG_SEED_BLOCKS);

        let spend = reorg_seed_coinbase_spend_with_fee(REORG_SPEND_FEE_SATS);
        let spend_txid = spend.txid();
        {
            let mempool = state.mempool();
            let mut guard = mempool.write();
            let vsize = u32::try_from(spend.vsize()).unwrap_or(u32::MAX);
            guard.insert_entry(MempoolEntry::new(
                Arc::new(spend.clone()),
                vsize,
                REORG_SPEND_FEE_SATS,
                1,
                REORG_SEED_BLOCKS,
                0,
            ))?;
        }
        let mined_block =
            reorg_mine_and_apply(&state, seed_tip, REORG_SEED_BLOCKS + 1, vec![spend])?;
        assert!(
            state.mempool().read().is_empty(),
            "connect must drain the confirmed spend"
        );

        let handler = invalidation_handler(&state);
        let mined_hash = mined_block.block_hash();
        handler.dispatch("invalidateblock", &json!([mined_hash.to_string()]))?;

        let (tip, tip_height) = applied_tip_pair(&state)?;
        assert_eq!(
            tip_height, REORG_SEED_BLOCKS,
            "the mined block must roll back"
        );
        assert_eq!(tip, seed_tip, "the seed tip must become active again");

        let raw = handler.dispatch("getrawmempool", &json!([]))?;
        let entries = raw.as_array().ok_or("getrawmempool must answer an array")?;
        let txids: Vec<&str> = entries.iter().filter_map(|value| value.as_str()).collect();
        assert_eq!(
            txids,
            vec![spend_txid.to_string()],
            "the matured spend returns and the coinbase never does"
        );

        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(parking_lot::RwLock::new(Mempool::new(
                MempoolLimits::default(),
            ))),
            None,
            state.config().validation.engine,
            None,
        ));
        let chainstate = state.chainstate();
        let chain = bitcoin_rs_serving::context::ChainAdmissionView::new(
            chainstate.utxo_reader(),
            chainstate.applied_tip_reader(),
            chainstate.block_tree_reader(),
            chainstate.network(),
        );
        let change = gateway.begin_chain_change()?;
        let committed = gateway.reconsider_disconnected(
            &change,
            &chain,
            1,
            mined_block
                .txs
                .iter()
                .filter(|tx| !tx.is_coinbase())
                .map(|tx| Arc::new(tx.clone())),
        );
        assert_eq!(committed.len(), 1, "one admitted candidate: the spend");
        change.finish()?;
        assert!(gateway.read().contains_txid(&spend_txid));
        Ok(())
    }

    fn fund_coinbase_utxo(ctx: &Context, label: u8, value: u64, height: u32) -> OutPoint {
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: Script::from_bytes(p2sh_true_script()),
            },
            true,
            height,
        ));
        ctx.populate_fixture_coins(&changes)
            .unwrap_or_else(|error| panic!("commit_block failed: {error}"));
        OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[label; 32])),
            vout: 0,
        }
    }

    #[test]
    fn immature_coinbase_spends_reject_on_both_rpcs_and_admit_at_maturity()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let coinbase = fund_coinbase_utxo(&ctx, 0x70, 10_000, 20);
        let spend = tx(coinbase, 9_000, 0xffff_ffff);
        let handler = Handler::new(Arc::clone(&ctx));

        let message = reject_message(
            &handler
                .dispatch("sendrawtransaction", &json!([raw_tx_hex(&spend)]))
                .err()
                .ok_or("expected immature coinbase rejection")?,
        );
        assert!(
            message.contains("consensus-verification-failed"),
            "unexpected rejection message: {message}"
        );
        assert!(
            !ctx.mempool.gateway.read().contains_txid(&rpc_txid(&spend)),
            "rejected spend must not enter the pool"
        );

        let rows = handler
            .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&spend)]]))?
            .as_array()
            .ok_or("expected an array of results")?
            .clone();
        assert_eq!(rows.len(), 1, "one row per submitted tx");
        assert_eq!(
            rows[0].get("allowed").and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        assert_eq!(
            rows[0]
                .get("reject-reason")
                .and_then(JsonValueTrait::as_str),
            Some("script-verify-flag-failed")
        );

        ctx.chain.applied_tip.store(Some(Arc::new(TipSnapshot {
            tip_id: NodeId::new(0),
            height: 119,
            chainwork: ChainWork::ZERO,
            hash: Hash256::from_le_bytes(&[0x71; 32]),
            chain_tx_count: bitcoin_rs_execution::chain::ChainTxCount::UNKNOWN,
        })));
        handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&spend)]))?;
        assert!(
            ctx.mempool.gateway.read().contains_txid(&rpc_txid(&spend)),
            "mature spend must commit to the pool"
        );
        Ok(())
    }

    #[test]
    fn bip68_locked_tx_admits_while_csv_is_inactive_on_the_rpc_surface()
    -> Result<(), crate::support::TestError> {
        let ctx = Arc::new(Context::new());
        let prevout = fund_utxo(&ctx, 0x72, 10_000);
        let locked = tx(prevout, 9_000, 5);
        let handler = Handler::new(Arc::clone(&ctx));
        let rows = handler
            .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&locked)]]))?
            .as_array()
            .ok_or("expected an array of results")?
            .clone();
        assert_eq!(rows.len(), 1, "one row per submitted tx");
        assert_eq!(
            rows[0].get("allowed").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        assert_eq!(
            rows[0]
                .get("reject-reason")
                .and_then(JsonValueTrait::as_str),
            None
        );
        Ok(())
    }
}
mod reorg_notifications {
    #![cfg(feature = "zmq")]

    use std::time::{Duration, Instant};

    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash as _;
    use bitcoin_rs_e2e::helpers::{funding_address, mine_bare_blocks, submit_genesis};
    use bitcoin_rs_e2e::{Kind, ProcessNode, Result, SpawnOptions};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

    #[derive(Debug, Eq, PartialEq, serde::Serialize)]
    struct SequenceBlock {
        hash: String,
        label: u8,
        counter: u32,
    }

    fn receive_block(socket: &zmq::Socket, timeout: Duration) -> Result<Option<SequenceBlock>> {
        socket
            .set_rcvtimeo(i32::try_from(timeout.as_millis()).map_err(|error| {
                bitcoin_rs_e2e::Error::Assertion(format!("ZMQ receive timeout: {error}"))
            })?)
            .map_err(|error| bitcoin_rs_e2e::Error::Assertion(error.to_string()))?;
        let frames = match socket.recv_multipart(0) {
            Ok(frames) => frames,
            Err(zmq::Error::EAGAIN) => return Ok(None),
            Err(error) => return Err(bitcoin_rs_e2e::Error::Assertion(error.to_string())),
        };
        assert_eq!(frames.len(), 3, "sequence message must have three frames");
        assert_eq!(frames[0].as_slice(), b"sequence");
        assert_eq!(
            frames[1].len(),
            33,
            "coinbase-only reorg cannot emit mempool A/R messages"
        );
        assert_eq!(frames[2].len(), 4);
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&frames[1][..32]);
        hash.reverse();
        let counter = u32::from_le_bytes(frames[2].as_slice().try_into().map_err(|_| {
            bitcoin_rs_e2e::Error::Assertion("sequence counter is not four bytes".into())
        })?);
        Ok(Some(SequenceBlock {
            hash: BlockHash::from_byte_array(hash).to_string(),
            label: frames[1][32],
            counter,
        }))
    }

    fn next_block(socket: &zmq::Socket) -> Result<SequenceBlock> {
        receive_block(socket, Duration::from_secs(15))?.ok_or_else(|| {
            bitcoin_rs_e2e::Error::Assertion("timed out waiting for a sequence event".into())
        })
    }

    fn mine_and_submit_core_block(
        core: &mut ProcessNode,
        node: &mut ProcessNode,
    ) -> Result<String> {
        let hashes = core.rpc(
            "generatetoaddress",
            &json!([1, funding_address()?.to_string()]),
        )?;
        let hash = hashes[0].as_str().ok_or_else(|| {
            bitcoin_rs_e2e::Error::Assertion(format!("Core mining reply: {hashes}"))
        })?;
        let body = core.rpc("getblock", &json!([hash, 0]))?;
        assert!(node.rpc("submitblock", &json!([body]))?.is_null());
        Ok(hash.to_owned())
    }

    fn spawn_sequence_subscriber()
    -> Result<(tempfile::TempDir, ProcessNode, zmq::Context, zmq::Socket)> {
        let socket_dir = tempfile::tempdir()?;
        let endpoint = format!(
            "ipc://{}",
            socket_dir.path().join("sequence.sock").display()
        );
        let toml_extra = format!(
            "[[notifications.zmq]]\nendpoint = {}\ntopics = [\"sequence\"]\nhwm = 1000\n",
            toml::Value::String(endpoint.clone())
        );
        let mut node = ProcessNode::spawn_with(
            Kind::BitcoinRs,
            &SpawnOptions {
                toml_extra: &toml_extra,
                ..SpawnOptions::default()
            },
        )?;
        submit_genesis(&mut node)?;
        let notifications = node.rpc("getzmqnotifications", &json!([]))?;
        assert!(
            notifications
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| {
                    row.get("type") == Some(&json!("pubsequence"))
                        && row.get("address") == Some(&json!(endpoint))
                })),
            "sequence publisher did not bind the configured endpoint: {notifications}"
        );

        let context = zmq::Context::new();
        let subscriber = context
            .socket(zmq::SUB)
            .map_err(|error| bitcoin_rs_e2e::Error::Assertion(error.to_string()))?;
        subscriber
            .set_subscribe(b"sequence")
            .map_err(|error| bitcoin_rs_e2e::Error::Assertion(error.to_string()))?;
        subscriber
            .connect(&endpoint)
            .map_err(|error| bitcoin_rs_e2e::Error::Assertion(error.to_string()))?;
        Ok((socket_dir, node, context, subscriber))
    }

    fn wait_for_subscription_probe(
        core: &mut ProcessNode,
        node: &mut ProcessNode,
        subscriber: &zmq::Socket,
    ) -> Result<SequenceBlock> {
        for _ in 0..8 {
            let hash = mine_and_submit_core_block(core, node)?;
            let deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < deadline {
                if let Some(event) = receive_block(subscriber, Duration::from_millis(100))?
                    && event.hash == hash
                    && event.label == b'C'
                {
                    return Ok(event);
                }
            }
        }
        Err(bitcoin_rs_e2e::Error::Assertion(
            "ZMQ subscriber never observed a probe block".into(),
        ))
    }

    fn mine_core_rival(core: &mut ProcessNode) -> Result<Vec<String>> {
        let rival = core.rpc(
            "generatetoaddress",
            &json!([3, funding_address()?.to_string()]),
        )?;
        let rival = rival
            .as_array()
            .ok_or_else(|| bitcoin_rs_e2e::Error::Assertion("Core rival hashes missing".into()))?;
        assert_eq!(rival.len(), 3);
        rival
            .iter()
            .map(|hash| {
                hash.as_str().map(str::to_owned).ok_or_else(|| {
                    bitcoin_rs_e2e::Error::Assertion("Core rival hash is not a string".into())
                })
            })
            .collect()
    }

    fn assert_sequence_stream(
        subscriber: &zmq::Socket,
        ancestor: SequenceBlock,
        old: &[String],
        rival: &[String],
    ) -> Result<Vec<SequenceBlock>> {
        assert_eq!(old.len(), 2);
        assert_eq!(rival.len(), 3);
        let expected = [
            (old[0].as_str(), b'C'),
            (old[1].as_str(), b'C'),
            (old[1].as_str(), b'D'),
            (old[0].as_str(), b'D'),
            (rival[0].as_str(), b'C'),
            (rival[1].as_str(), b'C'),
            (rival[2].as_str(), b'C'),
        ];
        let mut counter = ancestor.counter;
        let mut observed = vec![ancestor];
        for (hash, label) in expected {
            let event = next_block(subscriber)?;
            counter = counter.wrapping_add(1);
            assert_eq!(
                event,
                SequenceBlock {
                    hash: hash.to_owned(),
                    label,
                    counter
                }
            );
            observed.push(event);
        }
        assert!(
            receive_block(subscriber, Duration::from_millis(200))?.is_none(),
            "branch switch emitted an unexpected extra sequence event"
        );
        Ok(observed)
    }

    fn assert_post_switch_recovery(core: &mut ProcessNode, mut node: ProcessNode) -> Result<()> {
        let datadir = node.take_datadir()?;
        node.send_sigkill();
        drop(node);
        let mut recovered =
            ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions::default(), datadir)?;
        assert_eq!(
            recovered.rpc("getbestblockhash", &json!([]))?,
            core.rpc("getbestblockhash", &json!([]))?
        );
        let reference_coins = core.rpc("gettxoutsetinfo", &json!(["muhash", null, false]))?;
        let recovered_coins = recovered.rpc("gettxoutsetinfo", &json!(["muhash", null, false]))?;
        for key in ["height", "bestblock", "transactions", "txouts", "muhash"] {
            assert_eq!(
                recovered_coins.get(key),
                reference_coins.get(key),
                "recovered {key} differs from pinned Core"
            );
        }
        assert_eq!(
            recovered_coins["total_amount"].as_f64(),
            reference_coins["total_amount"].as_f64(),
            "recovered total UTXO amount differs from pinned Core"
        );
        recovered.stop()
    }

    #[test]
    fn sequence_reports_exact_disconnect_connect_order() -> Result<()> {
        let mut core = ProcessNode::spawn(Kind::Core)?;
        let (_socket_dir, mut node, _context, subscriber) = spawn_sequence_subscriber()?;
        let ancestor = wait_for_subscription_probe(&mut core, &mut node, &subscriber)?;
        let old = mine_bare_blocks(&mut node, 2)?;
        let rival = mine_core_rival(&mut core)?;
        node.rpc("addnode", &json!([core.p2p_addr.to_string(), "onetry"]))?;
        let winning_height = core
            .rpc("getblockcount", &json!([]))?
            .as_u64()
            .ok_or_else(|| {
                bitcoin_rs_e2e::Error::Assertion("Core block count is not an integer".into())
            })?;
        node.wait_block_count(winning_height, Duration::from_secs(90))?;
        assert_eq!(node.rpc("getbestblockhash", &json!([]))?, json!(rival[2]));
        let observed = assert_sequence_stream(&subscriber, ancestor, &old, &rival)?;
        std::fs::write(
            node.evidence.join("sequence.json"),
            sonic_rs::to_vec_pretty(&observed)?,
        )?;
        assert_post_switch_recovery(&mut core, node)?;
        core.stop()
    }
}
mod scantxoutset_lifecycle {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::support::TestError;
    use bitcoin_rs_e2e::rpc::Connection;
    use bitcoin_rs_serving::{Auth, Handler, RpcServer, context::Context};
    use sonic_rs::{Value, json};

    type TestResult<T = ()> = Result<T, TestError>;

    fn call(connection: &mut Connection, method: &str, params: Value) -> TestResult<Value> {
        let mut request = json!({"jsonrpc":"2.0", "id":1,"method":method});
        request["params"] = params;
        Ok(connection.rpc(
            &request,
            ("scan", "test"),
            Instant::now() + Duration::from_secs(3),
        )?)
    }

    fn reserved(context: &Context) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while context.chain.utxo.scan_progress().is_none() {
            assert!(Instant::now() < deadline, "scan never reserved");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn scan_preserves_control_capacity_and_observes_server_shutdown() -> TestResult {
        check_scan_cancellation(CancellationMode::Abort)?;
        check_scan_cancellation(CancellationMode::Shutdown)?;
        Ok(())
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CancellationMode {
        Abort,
        Shutdown,
    }

    fn check_scan_cancellation(mode: CancellationMode) -> TestResult {
        let transition = bitcoin_rs_execution::chain::TransitionDomain::new().stable_read();
        let context = Arc::new(Context::new().with_chain_transition(transition.clone()));
        let handler = Arc::new(Handler::new(Arc::clone(&context)));
        let server = RpcServer::bind(
            "127.0.0.1:0",
            Arc::new(Auth::basic("scan", "test")),
            handler,
            2,
            Duration::from_secs(3),
            false,
        )?;
        let address = server.local_addr()?;
        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let flag = shutdown.reader();
        let serving = std::thread::spawn(move || server.serve_with_shutdown(flag));
        let mut control = Connection::new(address);
        let result = (|| -> TestResult<()> {
            assert_eq!(
                call(&mut control, "getblockcount", json!([]))?["result"],
                json!(0)
            );
            let held = transition.lock();
            let scan = std::thread::spawn(move || {
                call(
                    &mut Connection::new(address),
                    "scantxoutset",
                    json!(["start", []]),
                )
            });
            let operation = (|| -> TestResult<()> {
                reserved(&context);
                assert_eq!(
                    call(&mut control, "scantxoutset", json!(["status"]))?["result"]["progress"],
                    json!(0)
                );
                assert_eq!(
                    call(&mut control, "getblockcount", json!([]))?["result"],
                    json!(0)
                );
                match mode {
                    CancellationMode::Shutdown => {
                        assert_eq!(
                            call(&mut control, "scantxoutset", json!(["start", []]))?["error"]["code"],
                            json!(-8)
                        );
                        shutdown.trigger();
                    }
                    CancellationMode::Abort => {
                        assert_eq!(
                            call(&mut control, "scantxoutset", json!(["abort"]))?["result"],
                            json!(true)
                        );
                    }
                }

                let response = scan.join().map_err(|_| "scan worker panicked")??;
                assert_eq!(response["result"]["success"], json!(false));
                assert_eq!(response["result"]["txouts"], json!(0));
                assert_eq!(context.chain.utxo.scan_progress(), None);
                Ok(())
            })();
            drop(held);
            operation?;
            Ok(())
        })();
        shutdown.trigger();
        serving.join().map_err(|_| "server panicked")??;
        result
    }
}
mod setban_expiry {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use bitcoin_rs_serving::{Handler, RpcError, context::Context};
    use bitcoin_rs_wire::BannedSubnet;
    use sonic_rs::{JsonValueTrait as _, json};

    fn handler() -> Handler {
        Handler::new(Arc::new(Context::new()))
    }

    fn only_ban(handler: &Handler) -> BannedSubnet {
        let entries = handler.context().network.p2p.banned();
        let [entry] = entries.as_slice() else {
            panic!("expected exactly one ban entry");
        };
        entry.clone()
    }

    fn assert_overflow_fixture() {
        assert!(
            UNIX_EPOCH
                .checked_add(Duration::from_secs(u64::MAX))
                .is_none(),
            "the overflow fixture must be unrepresentable on this target"
        );
    }

    fn assert_invalid_relative_expiry(handler: &Handler, target: &str) {
        let Err(error) = handler.dispatch("setban", &json!([target, "add", u64::MAX, false]))
        else {
            panic!("unrepresentable expiry must not succeed");
        };
        assert!(matches!(&error, RpcError::InvalidParameter(_)));
        assert_eq!(error.code(), -8, "SETBAN-EXPIRY-01 invalid-value error");
    }

    fn assert_invalid_absolute_expiry(handler: &Handler, target: &str) {
        let Err(error) = handler.dispatch("setban", &json!([target, "add", u64::MAX, true])) else {
            panic!("unrepresentable expiry must not succeed");
        };
        assert!(matches!(&error, RpcError::InvalidParameter(_)));
        assert_eq!(error.code(), -8, "SETBAN-EXPIRY-01 invalid-value error");
    }

    #[test]
    fn overflow_does_not_create_a_permanent_ban() {
        assert_overflow_fixture();
        let rel_handler = handler();
        assert_invalid_relative_expiry(&rel_handler, "192.0.2.1");
        assert_eq!(rel_handler.context().network.p2p.banned().as_slice(), &[]);

        let abs_handler = handler();
        assert_invalid_absolute_expiry(&abs_handler, "192.0.2.1");
        assert_eq!(abs_handler.context().network.p2p.banned().as_slice(), &[]);
    }

    #[test]
    fn overflow_preserves_existing_entries_and_order() -> Result<(), RpcError> {
        assert_overflow_fixture();
        for target in ["192.0.2.1", "203.0.113.99"] {
            let rel_handler = handler();
            rel_handler.dispatch("setban", &json!(["192.0.2.1", "add", 60]))?;
            rel_handler.dispatch("setban", &json!(["198.51.100.0/24", "add", 120]))?;
            let before = rel_handler.context().network.p2p.banned();

            assert_invalid_relative_expiry(&rel_handler, target);
            assert_eq!(
                rel_handler.context().network.p2p.banned().as_slice(),
                before.as_slice()
            );

            let abs_handler = handler();
            abs_handler.dispatch("setban", &json!(["192.0.2.1", "add", 60]))?;
            abs_handler.dispatch("setban", &json!(["198.51.100.0/24", "add", 120]))?;
            let abs_before = abs_handler.context().network.p2p.banned();
            assert_invalid_absolute_expiry(&abs_handler, target);
            assert_eq!(
                abs_handler.context().network.p2p.banned().as_slice(),
                abs_before.as_slice()
            );
        }
        Ok(())
    }

    #[test]
    fn relative_defaults_and_explicit_durations_remain_finite() -> Result<(), RpcError> {
        for (params, expected_seconds) in [
            (json!(["192.0.2.1", "add"]), 86_400),
            (json!(["192.0.2.1", "add", null]), 86_400),
            (json!(["192.0.2.1", "add", 0, false]), 86_400),
            (json!(["192.0.2.1", "add", 1, false]), 1),
            (json!(["192.0.2.1", "add", 60, false]), 60),
        ] {
            let handler = handler();
            assert!(handler.dispatch("setban", &params)?.is_null());
            let entry = only_ban(&handler);
            assert!(entry.banned_until.is_some());
            assert_eq!(
                entry.banned_until,
                entry
                    .ban_created
                    .checked_add(Duration::from_secs(expected_seconds))
            );
        }
        Ok(())
    }

    #[test]
    fn absolute_expiry_uses_epoch_not_creation_time() -> Result<(), RpcError> {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("test clock must follow the epoch: {error}"))
            .as_secs()
            .checked_add(86_400)
            .unwrap_or_else(|| panic!("test timestamp must fit u64"));
        let handler = handler();
        assert!(
            handler
                .dispatch("setban", &json!(["192.0.2.1", "add", seconds, true]))?
                .is_null()
        );
        let entry = only_ban(&handler);
        assert!(entry.banned_until.is_some());
        assert_eq!(
            entry.banned_until,
            UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
        );
        Ok(())
    }

    fn assert_past_absolute_expiry(handler: &Handler, target: &str) {
        for bantime in [json!(null), json!(0), json!(1)] {
            let before = handler.context().network.p2p.banned();
            let Err(error) = handler.dispatch("setban", &json!([target, "add", bantime, true]))
            else {
                panic!("past absolute timestamp must not succeed");
            };
            assert_eq!(error.code(), -8);
            assert!(matches!(
                error,
                RpcError::InvalidParameter(message)
                    if message == "Error: Absolute timestamp is in the past"
            ));
            assert_eq!(
                handler.context().network.p2p.banned().as_slice(),
                before.as_slice()
            );
        }
    }

    #[test]
    fn past_absolute_expiry_does_not_create_a_ban() {
        let handler = handler();
        assert_past_absolute_expiry(&handler, "192.0.2.1");
        assert_eq!(handler.context().network.p2p.banned().as_slice(), &[]);
    }

    #[test]
    fn past_absolute_expiry_preserves_existing_entries_and_order() -> Result<(), RpcError> {
        for target in ["192.0.2.1", "203.0.113.99"] {
            let handler = handler();
            handler.dispatch("setban", &json!(["192.0.2.1", "add", 60]))?;
            handler.dispatch("setban", &json!(["198.51.100.0/24", "add", 120]))?;
            assert_past_absolute_expiry(&handler, target);
        }
        Ok(())
    }
}
mod tip_wait_admission {
    #![expect(clippy::expect_used)]

    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use bitcoin_rs_consensus::latch::{LatchReader, LatchWriter};
    use bitcoin_rs_consensus::primitives::Network;
    use bitcoin_rs_execution::Chainstate;
    use bitcoin_rs_execution::chain::{ActiveTipWait, TipSnapshot, TipWaitCondition};
    use bitcoin_rs_serving::{Auth, Handler, RpcServer, context::Context};
    use parking_lot::{Condvar, Mutex};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};

    struct ObservableTipWait {
        inner: Arc<Chainstate>,
        waiting: AtomicUsize,
        gate: Mutex<()>,
        entered: Condvar,
    }

    impl ObservableTipWait {
        fn new(inner: Arc<Chainstate>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                waiting: AtomicUsize::new(0),
                gate: Mutex::new(()),
                entered: Condvar::new(),
            })
        }

        fn wait_for_waiters(&self, count: usize) {
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut guard = self.gate.lock();
            while self.waiting.load(Ordering::Acquire) < count {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for {count} active tip waiter(s)"
                );
                self.entered.wait_for(&mut guard, Duration::from_millis(5));
            }
        }
    }

    impl ActiveTipWait for ObservableTipWait {
        fn wait_for_tip(
            &self,
            condition: TipWaitCondition,
            deadline: Option<Instant>,
            cancellation: &LatchReader,
        ) -> Option<Arc<TipSnapshot>> {
            let guard = self.gate.lock();
            self.waiting.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_all();
            drop(guard);
            let result = self.inner.wait_for_tip(condition, deadline, cancellation);
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            result
        }

        fn wake_waiters(&self) {
            self.inner.wake_waiters();
        }
    }

    fn context() -> (Arc<Context>, Arc<Chainstate>, Arc<ObservableTipWait>) {
        let chainstate = Arc::new(Chainstate::new(
            Network::Regtest,
            Arc::new(arc_swap::ArcSwapOption::empty()),
            Arc::new(arc_swap::ArcSwapOption::empty()),
            Arc::new(parking_lot::RwLock::new(
                bitcoin_rs_execution::chain::BlockTree::new(),
            )),
            Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
            Arc::new(bitcoin_rs_storage::utxo::stats::CoinStatsListener::new(
                bitcoin_rs_storage::utxo::stats::CoinStats::default(),
            )),
            Arc::new(bitcoin_rs_execution::events::ChainEventPublisher::detached(
                0,
            )),
        ));
        let genesis_payload = bitcoin_rs_consensus::primitives::BlockImage::from_local(
            Network::Regtest.genesis_block(),
        );
        chainstate.apply_block(&genesis_payload).expect("genesis");
        let observable = ObservableTipWait::new(chainstate.clone());
        let mut ctx = Context::new();
        ctx.chain.applied_tip = chainstate.applied_tip_reader();
        ctx.chain.active_tip_wait = Some(observable.clone());
        (Arc::new(ctx), chainstate, observable)
    }

    fn send(address: SocketAddr, body: &Value) -> TcpStream {
        let body = sonic_rs::to_string(body).expect("JSON");
        let mut stream = TcpStream::connect(address).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("deadline");
        write!(
        stream,
        "POST / HTTP/1.1\r\nHost: {address}\r\nAuthorization: Basic cGFyaXR5OnBhcml0eQ==\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
        body.len()
    )
    .expect("send");
        stream
    }

    fn read(mut stream: TcpStream) -> (String, Value) {
        let mut wire = String::new();
        stream
            .read_to_string(&mut wire)
            .expect("bounded response and close");
        let (head, body) = wire.split_once("\r\n\r\n").expect("HTTP head");
        let value = if body.is_empty() {
            Value::new_null()
        } else {
            sonic_rs::from_str(body).expect("JSON response")
        };
        (head.to_owned(), value)
    }

    fn ordinary_rpc(address: SocketAddr) -> Value {
        let deadline = Instant::now() + Duration::from_secs(2);
        let body = sonic_rs::to_vec(&json!({
            "id":2, "method":"getblockcount", "params":[],
        }))
        .expect("request JSON");
        loop {
            let response = bitcoin_rs_e2e::rpc::Connection::new(address)
                .http("POST", "/", &body, Some(("parity", "parity")), deadline)
                .expect("ordinary HTTP request");
            if response.status != 503 {
                assert_eq!(response.status, 200, "ordinary HTTP status");
                return response.json().expect("ordinary JSON response");
            }
            assert_eq!(response.body, b"busy");
            assert!(
                Instant::now() < deadline,
                "connection permit must be released"
            );
            std::thread::yield_now();
        }
    }

    // ARCH-09, API-34
    #[test]
    fn wait_quota_preserves_ordinary_http_and_server_only_shutdown_returns_tip() {
        let (ctx, chainstate, observable) = context();
        let handler = Arc::new(Handler::new(Arc::clone(&ctx)));
        let server = RpcServer::bind(
            "127.0.0.1:0",
            Arc::new(Auth::basic("parity", "parity")),
            handler,
            2,
            Duration::from_secs(3),
            false,
        )
        .expect("bind");
        let address = server.local_addr().expect("address");
        let shutdown = LatchWriter::new();
        let signal = shutdown.reader();
        let server_thread = std::thread::spawn(move || server.serve_with_shutdown(signal));
        let waiting = send(
            address,
            &json!({"id":1,"method":"waitforblockheight","params":[1]}),
        );
        observable.wait_for_waiters(1);
        let (head, denied) = read(send(
            address,
            &json!({"id":3,"method":"waitfornewblock","params":[]}),
        ));
        assert!(head.contains("Connection: close"));
        assert_eq!(denied["error"]["code"].as_i64(), Some(-1));
        let ordinary = ordinary_rpc(address);
        assert_eq!(ordinary["result"], json!(0));
        shutdown.trigger();
        server_thread
            .join()
            .expect("server thread")
            .expect("server exit");
        let (_, answer) = read(waiting);
        assert_eq!(answer["result"]["height"].as_u64(), Some(0));
        assert!(
            !chainstate.shutdown_reader().is_triggered(),
            "server cancellation must not stop chainstate"
        );
    }

    #[test]
    fn gbt_long_poll_counts_toward_the_blocking_quota() {
        fn send_close(address: SocketAddr, body: &Value) -> TcpStream {
            let body = sonic_rs::to_string(body).expect("JSON");
            let mut stream = TcpStream::connect(address).expect("connect");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("deadline");
            write!(
            stream,
            "POST / HTTP/1.1\r\nHost: {address}\r\nAuthorization: Basic cGFyaXR5OnBhcml0eQ==\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .expect("send");
            stream
        }

        let (ctx, _, observable) = context();
        let handler = Arc::new(Handler::new(Arc::clone(&ctx)));
        let server = RpcServer::bind(
            "127.0.0.1:0",
            Arc::new(Auth::basic("parity", "parity")),
            handler,
            2,
            Duration::from_secs(3),
            false,
        )
        .expect("bind");
        let address = server.local_addr().expect("address");
        let shutdown = LatchWriter::new();
        let signal = shutdown.reader();
        let server_thread = std::thread::spawn(move || server.serve_with_shutdown(signal));
        let waiting = send(
            address,
            &json!({"id":1,"method":"waitforblockheight","params":[1]}),
        );
        observable.wait_for_waiters(1);
        let (head, denied) = read(send(
            address,
            &json!({"id":2,"method":"getblocktemplate","params":[{"longpollid":"x"}]}),
        ));
        assert!(head.contains("Connection: close"));
        assert_eq!(denied["error"]["code"].as_i64(), Some(-1));
        let deadline = Instant::now() + Duration::from_secs(2);
        let (plain_head, plain) = loop {
            let mut stream = send_close(
                address,
                &json!({"id":3,"method":"getblocktemplate","params":[{"rules":["segwit"]}]}),
            );
            let mut wire = String::new();
            stream
                .read_to_string(&mut wire)
                .expect("bounded response and close");
            let (head, body) = wire.split_once("\r\n\r\n").expect("HTTP head");
            if !head.contains("503") {
                let value = if body.is_empty() {
                    Value::new_null()
                } else {
                    sonic_rs::from_str(body).expect("JSON response")
                };
                break (head.to_owned(), value);
            }
            assert!(
                Instant::now() < deadline,
                "connection permit must be released"
            );
            std::thread::yield_now();
        };
        assert!(plain_head.contains("Connection: close"));
        assert_eq!(plain["error"]["code"].as_i64(), Some(-32_601));
        shutdown.trigger();
        server_thread
            .join()
            .expect("server thread")
            .expect("server exit");
        let (_, answer) = read(waiting);
        assert_eq!(answer["result"]["height"].as_u64(), Some(0));
    }

    #[test]
    fn mixed_batch_and_notification_waits_share_admission_and_cancellation() {
        for notification_only in [false, true] {
            let (ctx, _, observable) = context();
            let handler = Arc::new(Handler::new(Arc::clone(&ctx)));
            let server = RpcServer::bind(
                "127.0.0.1:0",
                Arc::new(Auth::basic("parity", "parity")),
                handler,
                2,
                Duration::from_secs(3),
                false,
            )
            .expect("bind");
            let address = server.local_addr().expect("address");
            let shutdown = LatchWriter::new();
            let signal = shutdown.reader();
            let server_thread = std::thread::spawn(move || server.serve_with_shutdown(signal));
            let notification = json!({"jsonrpc":"2.0","method":"waitfornewblock","params":[]});
            let body = if notification_only {
                notification
            } else {
                json!([
                    {"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]},
                    notification,
                    {"jsonrpc":"2.0","id":2,"method":"getblockcount","params":[]}
                ])
            };
            let waiting = send(address, &body);
            observable.wait_for_waiters(1);
            let ordinary = bitcoin_rs_e2e::rpc::Connection::new(address)
                .rpc(
                    &json!({"id":3,"method":"getblockcount","params":[]}),
                    ("parity", "parity"),
                    Instant::now() + Duration::from_secs(1),
                )
                .expect("ordinary RPC");
            assert_eq!(ordinary["result"], json!(0));
            shutdown.trigger();
            server_thread.join().expect("server thread").expect("exit");
            let (head, answer) = read(waiting);
            if notification_only {
                assert!(head.starts_with("HTTP/1.1 204"));
                assert!(answer.is_null());
            } else {
                assert_eq!(answer.as_array().expect("batch").len(), 2);
                assert_eq!(answer[0]["id"].as_u64(), Some(1));
                assert_eq!(answer[1]["id"].as_u64(), Some(2));
            }
        }
    }

    #[test]
    fn rebinding_context_keeps_old_and_new_cancellation_and_budgets_separate() {
        let (ctx, _, observable) = context();
        let supplied = Arc::new(Handler::new(ctx));
        let old = RpcServer::bind(
            "127.0.0.1:0",
            Arc::new(Auth::basic("parity", "parity")),
            Arc::clone(&supplied),
            2,
            Duration::from_secs(3),
            false,
        )
        .expect("old bind");
        let old_addr = old.local_addr().expect("old address");
        let old_shutdown = LatchWriter::new();
        let old_signal = old_shutdown.reader();
        let old_thread = std::thread::spawn(move || old.serve_with_shutdown(old_signal));
        let old_wait = send(
            old_addr,
            &json!({"id":1,"method":"waitforblockheight","params":[1]}),
        );
        observable.wait_for_waiters(1);

        let new = RpcServer::bind(
            "127.0.0.1:0",
            Arc::new(Auth::basic("parity", "parity")),
            supplied,
            2,
            Duration::from_secs(3),
            false,
        )
        .expect("new bind over same context");
        let new_addr = new.local_addr().expect("new address");
        let new_shutdown = LatchWriter::new();
        let new_signal = new_shutdown.reader();
        let new_thread = std::thread::spawn(move || new.serve_with_shutdown(new_signal));
        let new_wait = send(
            new_addr,
            &json!({"id":2,"method":"waitforblockheight","params":[1]}),
        );
        observable.wait_for_waiters(2);
        old_shutdown.trigger();
        old_thread.join().expect("old server").expect("old exit");
        assert_eq!(read(old_wait).1["result"]["height"].as_u64(), Some(0));
        new_wait
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("short probe");
        assert!(
            new_wait.peek(&mut [0_u8; 1]).is_err(),
            "old cancellation must not release the replacement's wait"
        );
        new_wait
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("restore deadline");
        let ordinary = bitcoin_rs_e2e::rpc::Connection::new(new_addr)
            .rpc(
                &json!({"id":3,"method":"getblockcount","params":[]}),
                ("parity", "parity"),
                Instant::now() + Duration::from_secs(1),
            )
            .expect("replacement ordinary RPC");
        assert_eq!(ordinary["result"], json!(0));
        new_shutdown.trigger();
        new_thread.join().expect("new server").expect("new exit");
        assert_eq!(read(new_wait).1["result"]["height"].as_u64(), Some(0));
    }

    #[test]
    fn one_connection_server_rejects_waits_before_they_can_occupy_the_only_worker() {
        let (ctx, _, _) = context();
        let mut server = RpcServer::bind(
            "127.0.0.1:0",
            Arc::new(Auth::basic("parity", "parity")),
            Arc::new(Handler::new(ctx)),
            4,
            Duration::from_secs(3),
            false,
        )
        .expect("bind");
        server.max_connections = 1;
        let address = server.local_addr().expect("address");
        let shutdown = LatchWriter::new();
        let signal = shutdown.reader();
        let task = std::thread::spawn(move || server.serve_with_shutdown(signal));
        let (head, answer) = read(send(
            address,
            &json!({"id":1,"method":"waitfornewblock","params":[]}),
        ));
        assert!(head.contains("Connection: close"));
        assert_eq!(answer["error"]["code"].as_i64(), Some(-1));
        let ordinary = ordinary_rpc(address);
        assert_eq!(ordinary["result"], json!(0));
        shutdown.trigger();
        task.join().expect("server").expect("exit");
    }
}
mod transaction_methods {
    #![allow(clippy::expect_used)]

    extern crate alloc;

    use alloc::sync::Arc;

    use bitcoin::hex::{DisplayHex, FromHex};
    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
        consensus_bytes, deserialize,
    };
    use bitcoin_rs_mempool::{AdmissionOrigin, MempoolEntry};
    use bitcoin_rs_serving::context::Context;
    use bitcoin_rs_serving::{Handler, RpcError};
    use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

    use crate::support::TestError;

    const P2WPKH_SCRIPT_HEX: &str = "00141111111111111111111111111111111111111111";

    fn hex_decode(hex: &str) -> Result<Vec<u8>, TestError> {
        Ok(Vec::from_hex(hex)?)
    }

    fn is_op_return(script: &[u8]) -> bool {
        script.first() == Some(&0x6a_u8)
    }

    fn p2sh_true_script() -> Script {
        let redeem = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        Script::from_bytes(redeem.to_p2sh().into_bytes())
    }

    fn p2sh_true_spend_script_sig() -> Script {
        Script::from_bytes(vec![0x01, 0x51])
    }

    fn make_tx(prevout: OutPoint, output_value: u64, script: Vec<u8>) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: prevout,
                script_sig: p2sh_true_spend_script_sig(),
                sequence: Sequence::from_consensus(0xFFFF_FFFE),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: script.into(),
            }],
        }
    }

    fn fund_utxo(ctx: &Context, txid_byte: u8, value: u64) -> OutPoint {
        let txid = Hash256::from_le_bytes(&[txid_byte; 32]);
        let outpoint = OutPoint::new(Txid(txid), 0);
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            outpoint,
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: p2sh_true_script(),
            },
            false,
            1,
        ));
        ctx.populate_fixture_coins(&changes).expect("commit_block");
        outpoint
    }

    #[test]
    fn sendrawtransaction_admits_standard_tx_to_mempool() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
        let prevout = fund_utxo(&ctx, 0x42, 10_000);
        let tx = make_tx(prevout, 9_000, script);
        let raw = consensus_bytes(&tx).to_lower_hex_string();
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch("sendrawtransaction", &json!([raw.as_str()]))?;
        let returned_txid = result.as_str().ok_or("expected txid string")?;
        assert_eq!(returned_txid, tx.txid().to_string());

        assert!(
            ctx.mempool.gateway.read().contains_txid(&tx.txid()),
            "tx was not admitted to mempool"
        );
        Ok(())
    }

    #[test]
    fn sendrawtransaction_rejects_missing_inputs() {
        let ctx = Arc::new(Context::new());
        let script = hex_decode(P2WPKH_SCRIPT_HEX).expect("script hex");
        let prevout = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x99; 32])), 0);
        let tx = make_tx(prevout, 9_000, script);
        let raw = consensus_bytes(&tx).to_lower_hex_string();
        let handler = Handler::new(Arc::clone(&ctx));

        let err = handler
            .dispatch("sendrawtransaction", &json!([raw.as_str()]))
            .expect_err("missing-inputs tx should be rejected");
        assert_eq!(err.code(), -25);
    }

    #[test]
    fn sendrawtransaction_idempotent_for_already_in_mempool() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
        let prevout = fund_utxo(&ctx, 0x43, 10_000);
        let tx = make_tx(prevout, 9_000, script);
        let txid = tx.txid();

        let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 1, 0);
        ctx.mempool.gateway.pool().write().insert_entry(entry)?;

        let raw = consensus_bytes(&tx).to_lower_hex_string();
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch("sendrawtransaction", &json!([raw.as_str()]))?;
        assert_eq!(result.as_str(), Some(txid.to_string().as_str()));
        Ok(())
    }

    #[test]
    fn sendrawtransaction_readmits_a_transaction_evicted_from_the_mempool() -> Result<(), TestError>
    {
        let ctx = Arc::new(Context::new());
        let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
        let prevout = fund_utxo(&ctx, 0x44, 10_000);
        let tx = make_tx(prevout, 9_000, script);
        let txid = tx.txid();
        let raw = consensus_bytes(&tx).to_lower_hex_string();
        let handler = Handler::new(Arc::clone(&ctx));

        handler.dispatch("sendrawtransaction", &json!([raw.as_str()]))?;
        assert!(
            ctx.mempool.gateway.read().contains_txid(&txid),
            "first admission"
        );

        let removed = ctx
            .mempool
            .gateway
            .evict_below_fee_rate(AdmissionOrigin::Rpc, u64::MAX)
            .expect("eviction commits");
        assert!(
            !removed.changes.is_empty(),
            "the eviction must have removed the entry"
        );
        assert!(!ctx.mempool.gateway.read().contains_txid(&txid));

        let result = handler.dispatch("sendrawtransaction", &json!([raw.as_str()]))?;
        assert_eq!(result.as_str(), Some(txid.to_string().as_str()));
        assert!(
            ctx.mempool.gateway.read().contains_txid(&txid),
            "resubmitting an evicted transaction must admit it again, not report success silently"
        );
        Ok(())
    }

    fn funded_standard_tx(
        txid_byte: u8,
        funded: u64,
        output: u64,
    ) -> Result<(Arc<Context>, Tx, String), TestError> {
        let ctx = Arc::new(Context::new());
        let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
        let prevout = fund_utxo(&ctx, txid_byte, funded);
        let tx = make_tx(prevout, output, script);
        let raw = consensus_bytes(&tx).to_lower_hex_string();
        Ok((ctx, tx, raw))
    }

    #[test]
    fn sendrawtransaction_admits_the_lnd_wallet_broadcast_shape() -> Result<(), TestError> {
        let (ctx, tx, raw) = funded_standard_tx(0x50, 10_000, 9_000)?;
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch("sendrawtransaction", &json!([raw.as_str(), false]))?;

        assert_eq!(result.as_str(), Some(tx.txid().to_string().as_str()));
        assert!(
            ctx.mempool.gateway.read().contains_txid(&tx.txid()),
            "the wallet transaction must be in the mempool, not only acknowledged"
        );
        Ok(())
    }

    #[test]
    fn the_legacy_allowhighfees_false_keeps_the_default_fee_ceiling() -> Result<(), TestError> {
        let (ctx, tx, raw) = funded_standard_tx(0x51, 100_000_000, 1_000_000)?;
        let handler = Handler::new(Arc::clone(&ctx));

        let refused = handler
            .dispatch("sendrawtransaction", &json!([raw.as_str(), false]))
            .expect_err("allowhighfees=false keeps the default fee ceiling");
        assert_eq!(refused.code(), RpcError::INVALID_PARAMS, "{refused:?}");
        assert!(!ctx.mempool.gateway.read().contains_txid(&tx.txid()));

        let typed = handler
            .dispatch("sendrawtransaction", &json!([raw.as_str(), true]))
            .expect_err("allowhighfees=true is not accepted");
        assert_eq!(typed.code(), -3, "{typed:?}");
        assert!(!ctx.mempool.gateway.read().contains_txid(&tx.txid()));
        Ok(())
    }

    #[test]
    fn sendrawtransaction_fee_argument_keeps_core_amount_semantics() -> Result<(), TestError> {
        for (index, fee) in [json!(null), json!(0.1), json!("0.1"), json!(0)]
            .into_iter()
            .enumerate()
        {
            let byte = 0x60 + u8::try_from(index)?;
            let (ctx, tx, raw) = funded_standard_tx(byte, 10_000, 9_000)?;
            let handler = Handler::new(Arc::clone(&ctx));

            let sent = handler.dispatch("sendrawtransaction", &json!([raw.as_str(), fee]))?;

            assert_eq!(
                sent.as_str(),
                Some(tx.txid().to_string().as_str()),
                "{fee:?}"
            );
            assert!(ctx.mempool.gateway.read().contains_txid(&tx.txid()));
        }

        let core_type_error = -3;
        for (index, (fee, code)) in [
            (json!([false]), Some(core_type_error)),
            (json!({"maxfeerate": false}), Some(core_type_error)),
            (json!(-0.1), Some(RpcError::INVALID_PARAMS)),
            (json!(1.0), Some(RpcError::INVALID_PARAMS)),
            (json!("false"), Some(RpcError::INVALID_PARAMS)),
        ]
        .into_iter()
        .enumerate()
        {
            let byte = 0x70 + u8::try_from(index)?;
            let (ctx, tx, raw) = funded_standard_tx(byte, 10_000, 9_000)?;
            let handler = Handler::new(Arc::clone(&ctx));

            let refused = handler
                .dispatch("sendrawtransaction", &json!([raw.as_str(), fee]))
                .expect_err("a fee argument that is not an amount stays refused");

            if let Some(code) = code {
                assert_eq!(refused.code(), code, "{fee:?}: {refused:?}");
            }
            assert!(
                !ctx.mempool.gateway.read().contains_txid(&tx.txid()),
                "{fee:?} must not admit anything"
            );
        }
        Ok(())
    }

    #[test]
    fn testmempoolaccept_still_refuses_a_boolean_maxfeerate() -> Result<(), TestError> {
        let (ctx, _tx, raw) = funded_standard_tx(0x80, 10_000, 9_000)?;
        let handler = Handler::new(Arc::clone(&ctx));

        let refused = handler
            .dispatch("testmempoolaccept", &json!([[raw.as_str()], false]))
            .expect_err("testmempoolaccept keeps Core's amount-only maxfeerate");

        assert_eq!(refused.code(), -3, "{refused:?}");
        Ok(())
    }

    #[test]
    fn testmempoolaccept_reports_allowed_for_valid_tx() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
        let prevout = fund_utxo(&ctx, 0x44, 10_000);
        let tx = make_tx(prevout, 9_000, script);
        let raw = consensus_bytes(&tx).to_lower_hex_string();
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch("testmempoolaccept", &json!([[raw.as_str()]]))?;
        let rows = result.as_array().ok_or("expected array")?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("allowed").as_bool(), Some(true));
        assert!(
            rows[0].get("reject-reason").is_none(),
            "no reject-reason for allowed tx"
        );
        Ok(())
    }

    #[test]
    fn testmempoolaccept_reports_reject_for_already_in_mempool() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
        let prevout = fund_utxo(&ctx, 0x45, 10_000);
        let tx = make_tx(prevout, 9_000, script);
        let txid = tx.txid();

        let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 1, 0);
        ctx.mempool.gateway.pool().write().insert_entry(entry)?;

        let raw = consensus_bytes(&tx).to_lower_hex_string();
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch("testmempoolaccept", &json!([[raw.as_str()]]))?;
        let rows = result.as_array().ok_or("expected array")?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("allowed").as_bool(), Some(false));
        let reason = rows[0]
            .get("reject-reason")
            .and_then(JsonValueTrait::as_str)
            .ok_or("expected reject-reason")?;
        assert!(
            reason.contains("already-in-mempool"),
            "reject-reason should mention already-in-mempool: {reason}"
        );
        assert_eq!(
            rows[0].get("txid").as_str(),
            Some(txid.to_string().as_str())
        );
        Ok(())
    }

    #[test]
    fn testmempoolaccept_reports_reject_for_missing_inputs() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let script = hex_decode(P2WPKH_SCRIPT_HEX).expect("script hex");
        let prevout = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x77; 32])), 0);
        let tx = make_tx(prevout, 9_000, script);
        let raw = consensus_bytes(&tx).to_lower_hex_string();
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch("testmempoolaccept", &json!([[raw.as_str()]]))?;
        let rows = result.as_array().ok_or("expected array")?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("allowed").as_bool(), Some(false));
        let reason = rows[0]
            .get("reject-reason")
            .and_then(JsonValueTrait::as_str)
            .ok_or("expected reject-reason")?;
        assert!(
            reason.contains("missing-inputs"),
            "reject-reason should mention missing-inputs: {reason}"
        );
        Ok(())
    }

    #[test]
    fn gettxout_returns_unconfirmed_output_from_mempool() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
        let tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0xaa; 32])), 0),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0xFFFF_FFFE),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(7_500),
                script_pubkey: script.into(),
            }],
        };
        let txid = tx.txid();
        let entry = MempoolEntry::new(Arc::new(tx), 100, 500, 1, 1, 0);
        ctx.mempool.gateway.pool().write().insert_entry(entry)?;

        let handler = Handler::new(Arc::clone(&ctx));
        let result = handler.dispatch("gettxout", &json!([txid.to_string(), 0_u64]))?;

        assert!(!result.is_null(), "expected non-null for mempool output");
        assert_eq!(result.get("confirmations").as_u64(), Some(0));
        assert_eq!(result.get("coinbase").as_bool(), Some(false));
        Ok(())
    }

    #[test]
    fn gettxout_include_mempool_false_skips_mempool() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
        let tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0xbb; 32])), 0),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0xFFFF_FFFE),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(7_500),
                script_pubkey: script.into(),
            }],
        };
        let txid = tx.txid();
        let entry = MempoolEntry::new(Arc::new(tx), 100, 500, 1, 1, 0);
        ctx.mempool.gateway.pool().write().insert_entry(entry)?;

        let handler = Handler::new(Arc::clone(&ctx));
        let result = handler.dispatch("gettxout", &json!([txid.to_string(), 0_u64, false]))?;
        assert!(result.is_null(), "expected null when mempool is excluded");
        Ok(())
    }

    #[test]
    fn gettxout_returns_null_for_outpoint_spent_in_mempool() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let script = hex_decode(P2WPKH_SCRIPT_HEX)?;

        let prevout = fund_utxo(&ctx, 0x55, 10_000);

        let spending_tx = make_tx(prevout, 9_000, script);
        let entry = MempoolEntry::new(Arc::new(spending_tx), 100, 1_000, 1, 1, 0);
        ctx.mempool.gateway.pool().write().insert_entry(entry)?;

        let spent_txid = prevout.txid;
        let handler = Handler::new(Arc::clone(&ctx));
        let result = handler.dispatch("gettxout", &json!([spent_txid.to_string(), 0_u64]))?;
        assert!(
            result.is_null(),
            "expected null for outpoint spent in mempool"
        );
        Ok(())
    }

    #[test]
    fn createrawtransaction_builds_valid_hex_tx() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));

        let inputs = json!([{
            "txid": "0000000000000000000000000000000000000000000000000000000000000001",
            "vout": 0
        }]);
        let outputs = json!({
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT": 0.001
        });

        let result = handler.dispatch("createrawtransaction", &json!([inputs, outputs]))?;

        let hex = result
            .as_str()
            .ok_or("createrawtransaction should return a hex string")?;
        let bytes = hex_decode(hex)?;
        let tx: Tx = deserialize(&bytes)?;
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        let previous_output = tx.inputs[0].previous_output;
        let (input_txid, input_vout) = (previous_output.txid, previous_output.vout);
        assert_eq!(
            input_txid.to_string(),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(input_vout, 0);
        Ok(())
    }

    #[test]
    fn createrawtransaction_creates_op_return_data_output() -> Result<(), TestError> {
        let mut ctx = Context::new();
        ctx.chain.chain_network = bitcoin_rs_consensus::primitives::Network::Regtest;
        let handler = Handler::new(Arc::new(ctx));

        let inputs = json!([{
            "txid": "0000000000000000000000000000000000000000000000000000000000000002",
            "vout": 1
        }]);
        let outputs = json!({
            "data": "48656c6c6f"
        });

        let result = handler.dispatch(
            "createrawtransaction",
            &json!([inputs, outputs, 0_u64, true]),
        )?;

        let hex = result
            .as_str()
            .ok_or("createrawtransaction should return a hex string")?;
        let bytes = hex_decode(hex)?;
        let tx: Tx = deserialize(&bytes)?;
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert!(is_op_return(&tx.outputs[0].script_pubkey));
        assert_eq!(tx.outputs[0].value, 0);
        assert!(tx.inputs[0].sequence < 0xFFFF_FFFE);
        Ok(())
    }

    #[test]
    fn createrawtransaction_rejects_duplicate_input() {
        let mut ctx = Context::new();
        ctx.chain.chain_network = bitcoin_rs_consensus::primitives::Network::Regtest;
        let handler = Handler::new(Arc::new(ctx));

        let inputs = json!([
            {"txid": "0000000000000000000000000000000000000000000000000000000000000003", "vout": 0},
            {"txid": "0000000000000000000000000000000000000000000000000000000000000003", "vout": 0}
        ]);
        let outputs = json!({"data": "00"});

        let err = handler
            .dispatch("createrawtransaction", &json!([inputs, outputs]))
            .expect_err("duplicate input should be rejected");
        assert_eq!(err.code(), RpcError::INVALID_PARAMS);
    }

    #[test]
    fn broadcast_methods_report_unparseable_oversize_hex_like_core() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));
        let oversized = "00".repeat(400_001);
        let broadcast = handler.dispatch("sendrawtransaction", &json!([oversized.as_str()]));
        let preview = handler.dispatch("testmempoolaccept", &json!([[oversized.as_str()]]));
        for (method, result) in [
            ("sendrawtransaction", broadcast),
            ("testmempoolaccept", preview),
        ] {
            let error = result
                .err()
                .ok_or("oversized broadcast hex must be refused")?;
            assert!(
                matches!(&error, RpcError::Deserialization(message)
                if message.starts_with("TX decode failed")),
                "{method} refused with the wrong boundary: {error:?}"
            );
            assert_eq!(error.code(), -22, "Core answers -22 for unparseable hex");
        }
        assert!(ctx.mempool.gateway.read().is_empty());
        Ok(())
    }

    #[test]
    fn decoderawtransaction_reports_unparseable_oversize_hex_like_core() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));
        let oversized = "00".repeat(4_000_001);
        let error = handler
            .dispatch("decoderawtransaction", &json!([oversized.as_str()]))
            .err()
            .ok_or("oversized inspection hex must be refused")?;
        assert!(
            matches!(&error, RpcError::Deserialization(message) if message == "TX decode failed"),
            "inspection refused with the wrong boundary: {error:?}"
        );
        assert_eq!(error.code(), -22, "Core answers -22 for unparseable hex");
        Ok(())
    }

    #[test]
    fn decoderawtransaction_inspects_a_consensus_legal_non_standard_tx() -> Result<(), TestError> {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));
        let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
        let mut big = make_tx(fund_utxo(&ctx, 0x70, 100_000_000), 1_000, script.clone());
        big.outputs = (0..3_400)
            .map(|_| TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: script.clone().into(),
            })
            .collect();
        let raw = consensus_bytes(&big).to_lower_hex_string();
        let result = handler.dispatch("decoderawtransaction", &json!([raw.as_str()]))?;
        assert_eq!(
            result.get("txid").and_then(|value| value.as_str()),
            Some(big.txid().to_string().as_str()),
            "inspection must decode a consensus-legal tx past the standard weight bound"
        );
        Ok(())
    }
}

mod mining_block_limits {
    use crate::support::mining::fixtures as common;

    use crate::support::mining::TestError;
    use std::sync::Arc;

    use crate::mining::{
        Candidate, CandidateContext, MiningError, assemble_candidate, assemble_ordered_candidate,
    };
    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid,
        Witness, encode::consensus_bytes,
    };
    use bitcoin_rs_mempool::{Mempool, MempoolEntry};
    use common::zero_fee_pool;

    type TestResult = Result<(), TestError>;

    #[test]
    fn empty_candidate_limits_include_the_serialized_block_envelope() -> TestResult {
        for segwit_active in [false, true] {
            let pool = zero_fee_pool();
            let snapshot = pool.mining_snapshot();
            {
                let mut context = context(segwit_active);
                let candidate = assemble_candidate(&context, &pool, &[0x51])?;
                assert_serialized_limits(&candidate)?;
                let size = u64::try_from(candidate.into_unsolved_block()?.total_size())?;
                assert_eq!(size - u64::try_from(candidate.coinbase.total_size())?, 81);
                assert_eq!(candidate.weight - candidate.coinbase.weight(), 324);
                context.max_weight = candidate.weight;
                context.max_size = size;
                assert_serialized_limits(&assemble_candidate(&context, &pool, &[0x51])?)?;
                for field in ["weight", "size"] {
                    let mut limited = context.clone();
                    lower_limit(&mut limited, field);
                    assert!(matches!(
                        assemble_candidate(&limited, &pool, &[0x51]),
                        Err(MiningError::CapacityExhausted { field: actual }) if actual == field
                    ));
                }
            }
            {
                let mut context = context(segwit_active);
                let candidate = assemble_ordered_candidate(&context, &snapshot, &[0x51])?;
                assert_serialized_limits(&candidate)?;
                let size = u64::try_from(candidate.into_unsolved_block()?.total_size())?;
                assert_eq!(size - u64::try_from(candidate.coinbase.total_size())?, 81);
                assert_eq!(candidate.weight - candidate.coinbase.weight(), 324);
                context.max_weight = candidate.weight;
                context.max_size = size;
                assert_serialized_limits(&assemble_ordered_candidate(
                    &context,
                    &snapshot,
                    &[0x51],
                )?)?;
                for field in ["weight", "size"] {
                    let mut limited = context.clone();
                    lower_limit(&mut limited, field);
                    assert!(matches!(
                        assemble_ordered_candidate(&limited, &snapshot, &[0x51]),
                        Err(MiningError::CapacityExhausted { field: actual }) if actual == field
                    ));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn exact_block_limits_cover_both_sides_of_compact_size_boundary() -> TestResult {
        for segwit_active in [false, true] {
            let witness: Witness = if segwit_active {
                vec![vec![0x11; 32]].into()
            } else {
                Witness::new()
            };
            for body_count in [251, 252] {
                let pool = build_pool(body_count, &witness)?;
                let snapshot = pool.mining_snapshot();
                {
                    let mut context = context(segwit_active);
                    let candidate = assemble_candidate(&context, &pool, &[0x51])?;
                    assert_eq!(candidate.transactions.len(), body_count);
                    assert_serialized_limits(&candidate)?;
                    context.max_weight = candidate.weight;
                    context.max_size =
                        u64::try_from(candidate.into_unsolved_block()?.total_size())?;
                    let exact = assemble_candidate(&context, &pool, &[0x51])?;
                    assert_eq!(exact.transactions.len(), body_count);
                    assert_serialized_limits(&exact)?;
                }
                {
                    let mut context = context(segwit_active);
                    let candidate = assemble_ordered_candidate(&context, &snapshot, &[0x51])?;
                    assert_eq!(candidate.transactions.len(), body_count);
                    assert_serialized_limits(&candidate)?;
                    context.max_weight = candidate.weight;
                    context.max_size =
                        u64::try_from(candidate.into_unsolved_block()?.total_size())?;
                    let exact = assemble_ordered_candidate(&context, &snapshot, &[0x51])?;
                    assert_eq!(exact.transactions.len(), body_count);
                    assert_serialized_limits(&exact)?;
                    for field in ["weight", "size"] {
                        let mut limited = context.clone();
                        lower_limit(&mut limited, field);
                        assert!(matches!(
                            assemble_ordered_candidate(&limited, &snapshot, &[0x51]),
                            Err(MiningError::CapacityExhausted { field: actual }) if actual == field
                        ));
                        let selected = assemble_candidate(&limited, &pool, &[0x51])?;
                        assert_eq!(selected.transactions.len(), body_count - 1);
                        assert_serialized_limits(&selected)?;
                        assert_eq!(
                            selected.transactions.iter().map(|tx| tx.fee).sum::<u64>(),
                            u64::try_from(body_count - 1)? * 10_000
                        );
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn count_encoding_growth_fills_parent_prefix_and_skips_descendant() -> TestResult {
        for segwit_active in [false, true] {
            let witness: Witness = if segwit_active {
                vec![vec![0x11; 32]].into()
            } else {
                Witness::new()
            };
            let mut pool = build_pool(250, &witness)?;
            let parent_tx = make_tx(251, None, &witness);
            let parent_txid = parent_tx.txid();
            insert_measured(&mut pool, parent_tx, 100)?;
            let child_tx = make_tx(252, Some(parent_txid), &witness);
            let child_txid = child_tx.txid();
            insert_measured(&mut pool, child_tx, 1_000)?;
            let mut context = context(segwit_active);
            let boundary_snapshot = pool.mining_snapshot();
            let boundary = assemble_ordered_candidate(&context, &boundary_snapshot, &[0x51])?;
            assert_serialized_limits(&boundary)?;
            let descendant_tx = make_tx(253, Some(child_txid), &witness);
            let descendant_txid = descendant_tx.txid();
            insert_measured(&mut pool, descendant_tx, 1)?;
            context.max_weight = boundary.weight;
            context.max_size = u64::try_from(boundary.into_unsolved_block()?.total_size())?;
            let exact = assemble_candidate(&context, &pool, &[0x51])?;
            assert_eq!(exact.transactions.len(), 252);
            let expected_parent = pool.entry_by_txid(&parent_txid).ok_or("missing parent")?;
            assert_eq!(exact.transactions[250].txid, expected_parent.txid);
            assert_eq!(exact.transactions[250].depends, [0_u32; 0]);
            assert_eq!(exact.transactions[251].txid, child_txid);
            assert_eq!(exact.transactions[251].depends, vec![251]);
            assert!(
                !exact
                    .transactions
                    .iter()
                    .any(|tx| tx.txid == descendant_txid)
            );
            assert_eq!(
                exact.transactions.iter().map(|tx| tx.fee).sum::<u64>(),
                2_501_100
            );
            assert_serialized_limits(&exact)?;
            for field in ["weight", "size"] {
                let mut limited = context.clone();
                lower_limit(&mut limited, field);
                let selected = assemble_candidate(&limited, &pool, &[0x51])?;
                assert_eq!(selected.transactions.len(), 251);
                assert_eq!(selected.transactions[250].txid, parent_txid);
                assert_eq!(selected.transactions[250].depends, [0_u32; 0]);
                assert!(!selected.transactions.iter().any(|tx| tx.txid == child_txid));
                assert!(
                    !selected
                        .transactions
                        .iter()
                        .any(|tx| tx.txid == descendant_txid)
                );
                assert_eq!(
                    selected.transactions.iter().map(|tx| tx.fee).sum::<u64>(),
                    2_500_100
                );
                assert_serialized_limits(&selected)?;
            }
        }
        Ok(())
    }

    fn lower_limit(context: &mut CandidateContext, field: &str) {
        if field == "weight" {
            context.max_weight -= 1;
            context.max_size = 4_000_000;
        } else {
            context.max_size -= 1;
            context.max_weight = 4_000_000;
        }
    }

    fn assert_serialized_limits(candidate: &Candidate) -> TestResult {
        let block = candidate.into_unsolved_block()?;
        let bytes = consensus_bytes(&block);
        let oracle: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)?;
        assert_eq!(bitcoin::consensus::serialize(&oracle), bytes);
        assert_eq!(
            u64::try_from(block.total_size())?,
            u64::try_from(oracle.total_size())?
        );
        assert_eq!(candidate.weight, oracle.weight().to_wu());
        assert_eq!(candidate.weight, block.weight());
        assert!(candidate.weight <= candidate.max_weight);
        assert!(u64::try_from(block.total_size())? <= candidate.max_size);
        let subsidy = bitcoin_rs_consensus::block_subsidy(
            candidate.height,
            Network::Regtest.subsidy_halving_interval(),
        );
        let fees = candidate.transactions.iter().map(|tx| tx.fee).sum::<u64>();
        assert!(
            candidate.coinbase_value == subsidy + fees || candidate.coinbase_value == subsidy,
            "coinbase value is neither subsidy plus claimed fees nor bare subsidy"
        );
        Ok(())
    }

    fn build_pool(count: usize, witness: &Witness) -> Result<Mempool, TestError> {
        let mut pool = zero_fee_pool();
        for label in 1..=count {
            let tx = make_tx(u16::try_from(label)?, None, witness);
            insert_measured(&mut pool, tx, 10_000)?;
        }
        Ok(pool)
    }

    fn insert_measured(pool: &mut Mempool, tx: Tx, fee: u64) -> Result<Txid, TestError> {
        let txid = tx.txid();
        let vsize = u32::try_from(tx.vsize())?;
        pool.insert_entry(MempoolEntry::new(Arc::new(tx), vsize, fee, 0, 0, 0))?;
        Ok(txid)
    }

    fn make_tx(label: u16, parent: Option<Txid>, witness: &Witness) -> Tx {
        let mut hash = [0; 32];
        hash[..2].copy_from_slice(&label.to_le_bytes());
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(
                    parent.unwrap_or_else(|| Txid::from(Hash256::from_le_bytes(&hash))),
                    0,
                ),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: witness.clone(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x51].into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn context(segwit_active: bool) -> CandidateContext {
        CandidateContext {
            segwit_active,
            ..common::context()
        }
    }

    #[test]
    fn exact_sigops_limits_cover_n_minus_one_n_and_n_plus_one() -> TestResult {
        for segwit_active in [false, true] {
            let mut pool = zero_fee_pool();
            let witness = if segwit_active {
                vec![vec![0x11; 32]].into()
            } else {
                Witness::new()
            };
            let tx = make_tx(1, None, &witness);
            let txid = tx.txid();
            let vsize = u32::try_from(tx.vsize())?;
            let sigop_cost = 400_u32;
            pool.insert_entry(MempoolEntry::new(
                Arc::new(tx),
                vsize,
                10_000,
                0,
                0,
                sigop_cost,
            ))?;

            let snapshot = pool.mining_snapshot();
            let mut ctx = context(segwit_active);
            let baseline = assemble_candidate(&ctx, &pool, &[0x51])?;
            assert_eq!(baseline.transactions.len(), 1);
            assert_eq!(baseline.transactions[0].txid, txid);

            let exact_sigops = u64::from(sigop_cost);
            ctx.max_sigops = exact_sigops;
            let at_n = assemble_candidate(&ctx, &pool, &[0x51])?;
            assert_eq!(at_n.transactions.len(), 1);
            let at_n_ordered = assemble_ordered_candidate(&ctx, &snapshot, &[0x51])?;
            assert_eq!(at_n_ordered.transactions.len(), 1);

            ctx.max_sigops = exact_sigops + 1;
            let at_n_plus_one = assemble_candidate(&ctx, &pool, &[0x51])?;
            assert_eq!(at_n_plus_one.transactions.len(), 1);
            let at_n_plus_one_ordered = assemble_ordered_candidate(&ctx, &snapshot, &[0x51])?;
            assert_eq!(at_n_plus_one_ordered.transactions.len(), 1);

            ctx.max_sigops = exact_sigops.saturating_sub(1);
            let at_n_minus_one = assemble_candidate(&ctx, &pool, &[0x51])?;
            assert_eq!(at_n_minus_one.transactions.len(), 0);
            assert!(matches!(
                assemble_ordered_candidate(&ctx, &snapshot, &[0x51]),
                Err(MiningError::CapacityExhausted { field: "sigops" })
            ));
        }
        Ok(())
    }

    #[test]
    fn empty_template_builds_valid_envelope_and_merkle_root() -> TestResult {
        for segwit_active in [false, true] {
            let pool = zero_fee_pool();
            let ctx = context(segwit_active);
            let candidate = assemble_candidate(&ctx, &pool, &[0x51])?;

            assert!(candidate.transactions.is_empty());
            let subsidy = bitcoin_rs_consensus::block_subsidy(
                candidate.height,
                Network::Regtest.subsidy_halving_interval(),
            );
            assert_eq!(candidate.coinbase_value, subsidy);

            let block = candidate.into_unsolved_block()?;
            assert_eq!(block.txs.len(), 1);
            assert_eq!(
                block.header.prev_blockhash,
                candidate.previous_block_hash.into()
            );
            assert_eq!(
                block.header.merkle_root,
                Hash256::from(candidate.coinbase.txid())
            );

            if segwit_active {
                assert!(candidate.witness_commitment.is_some());
                assert_eq!(candidate.coinbase.outputs.len(), 2);
                assert_eq!(candidate.coinbase.inputs[0].witness.len(), 1);
                assert_eq!(
                    candidate.coinbase.inputs[0].witness.first(),
                    Some(&[0_u8; 32][..])
                );
            } else {
                assert!(candidate.witness_commitment.is_none());
                assert_eq!(candidate.coinbase.outputs.len(), 1);
                assert!(candidate.coinbase.inputs[0].witness.is_empty());
            }
        }
        Ok(())
    }

    #[test]
    fn non_final_locktime_mempool_tx_is_excluded_from_template() -> TestResult {
        let mut pool = zero_fee_pool();
        let mut tx = make_tx(1, None, &Witness::new());
        tx.lock_time = LockTime::from_consensus(500_000_100);
        tx.inputs[0].sequence = Sequence::from_consensus(0);
        let txid = tx.txid();
        let vsize = u32::try_from(tx.vsize())?;
        pool.insert_entry(MempoolEntry::new(Arc::new(tx), vsize, 5_000, 0, 0, 0))?;

        let mut ctx = context(false);
        ctx.height = 100;
        ctx.locktime_cutoff = 500_000_100;
        let excluded = assemble_candidate(&ctx, &pool, &[0x51])?;
        assert!(excluded.transactions.is_empty());

        ctx.locktime_cutoff = 500_000_101;
        let included = assemble_candidate(&ctx, &pool, &[0x51])?;
        assert_eq!(included.transactions.len(), 1);
        assert_eq!(included.transactions[0].txid, txid);
        Ok(())
    }

    #[test]
    fn coinbase_budget_admission_boundaries() -> TestResult {
        use crate::mining::CoinbaseBudget;

        let pool = zero_fee_pool();
        let ctx = context(true);
        let candidate = assemble_candidate(&ctx, &pool, &[0x51])?;

        assert!(
            candidate
                .admits(CoinbaseBudget {
                    additional_size: 10,
                    additional_sigops: 10
                })
                .is_ok()
        );
        assert!(matches!(
            candidate.admits(CoinbaseBudget {
                additional_size: u32::MAX,
                additional_sigops: 0
            }),
            Err(MiningError::CapacityExhausted { field: "weight" }
                | MiningError::CandidateScalarOverflow { .. })
        ));
        let mut limited_ctx = ctx;
        limited_ctx.max_sigops = 50_000;
        let limited = assemble_candidate(&limited_ctx, &pool, &[0x51])?;
        assert!(matches!(
            limited.admits(CoinbaseBudget {
                additional_size: 0,
                additional_sigops: u16::MAX
            }),
            Err(MiningError::CapacityExhausted { field: "sigops" })
        ));
        Ok(())
    }
}
mod mining_coinbase_sigops {
    use crate::support::mining::fixtures as common;

    use crate::support::mining::TestError;

    use crate::mining::{
        Candidate, CandidateContext, MiningError, assemble_candidate, assemble_ordered_candidate,
    };
    use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Tx, Txid};
    use bitcoin_rs_consensus::script::VerifyFlags;
    use bitcoin_rs_consensus::transaction_sigop_cost;
    use common::{context, insert_with_cost, oracle_sigop_cost, p2pkh, tx, zero_fee_pool};

    type TestResult = Result<(), TestError>;

    #[test]
    fn budgeted_coinbase_input_growth_sigop_boundary() -> TestResult {
        use crate::mining::CoinbaseBudget;
        let pool = zero_fee_pool();
        let context = CandidateContext {
            segwit_active: false,
            ..context()
        };
        let budget = CoinbaseBudget {
            additional_size: 0,
            additional_sigops: 0,
        };
        let candidate = assemble_candidate(&context, &pool, &vec![0xac; 19_999])?;
        println!(
            "A declared_base_sigops=79996 budget_sigops=0 admits={:?} prefix_bytes={}",
            candidate.admits(budget),
            candidate.coinbase.inputs[0].script_sig.len()
        );
        assert!(matches!(
            candidate.admits(budget),
            Err(MiningError::CapacityExhausted { field: "sigops" })
        ));
        for (opcode, cost) in [(0xac, 80_000), (0xae, 80_076)] {
            let mut block = candidate.into_unsolved_block()?;
            let mut script = block.txs[0].inputs[0].script_sig.as_bytes().to_vec();
            script.push(opcode);
            block.txs[0].inputs[0].script_sig = script.into();
            block.header.merkle_root = Hash256::from_le_bytes(
                &bitcoin_rs_consensus::compute_merkle_root(&mut vec![
                    *block.txs[0].txid().as_bytes(),
                ])
                .ok_or("merkle")?,
            );
            let native = bitcoin_rs_consensus::verify_block::verify_block_non_contextual(&block);
            println!(
                "A opcode={opcode:x} final_sigops={} weight={} bytes={} native={native:?}",
                oracle_sigop_cost(&block.txs[0])?,
                block.weight(),
                block.total_size()
            );
            assert_eq!(oracle_sigop_cost(&block.txs[0])?, cost);
            assert_eq!(native.is_ok(), opcode == 0xac);
        }
        let mut safe = assemble_candidate(&context, &pool, &vec![0xac; 18_040])?;
        assert!(safe.admits(budget).is_ok());
        safe.max_sigops -= 1;
        assert!(
            safe.admits(budget).is_err(),
            "the complete growth reservation is inclusive"
        );
        let mut block = safe.into_unsolved_block()?;
        let mut script = block.txs[0].inputs[0].script_sig.as_bytes().to_vec();
        script.resize(100, 0xae);
        block.txs[0].inputs[0].script_sig = script.into();
        assert_eq!(oracle_sigop_cost(&block.txs[0])?, 80_000);
        Ok(())
    }

    fn sigop_limited(segwit_active: bool, max_sigops: u64) -> CandidateContext {
        CandidateContext {
            segwit_active,
            max_sigops,
            ..context()
        }
    }

    #[test]
    fn coinbase_sigops_match_consensus_cost_in_both_assembly_paths() -> TestResult {
        let pool = zero_fee_pool();
        let snapshot = pool.mining_snapshot();
        let cases = [(vec![0x51], 0), (p2pkh(), 4), (vec![0x51, 0xae], 80)];
        for segwit_active in [false, true] {
            for (payout, expected) in &cases {
                {
                    let mut context = sigop_limited(segwit_active, *expected);
                    let candidate = assemble_candidate(&context, &pool, payout)?;
                    assert_costs(&candidate, payout, segwit_active, *expected)?;
                    if *expected > 0 {
                        context.max_sigops -= 1;
                        assert!(matches!(
                            assemble_candidate(&context, &pool, payout),
                            Err(MiningError::CapacityExhausted { field: "sigops" })
                        ));
                    }
                }
                {
                    let mut context = sigop_limited(segwit_active, *expected);
                    let candidate = assemble_ordered_candidate(&context, &snapshot, payout)?;
                    assert_costs(&candidate, payout, segwit_active, *expected)?;
                    if *expected > 0 {
                        context.max_sigops -= 1;
                        assert!(matches!(
                            assemble_ordered_candidate(&context, &snapshot, payout),
                            Err(MiningError::CapacityExhausted { field: "sigops" })
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn assert_costs(
        candidate: &Candidate,
        payout: &[u8],
        segwit_active: bool,
        expected: u64,
    ) -> TestResult {
        assert_eq!(oracle_sigop_cost(&candidate.coinbase)?, expected);
        assert_eq!(
            u64::from(transaction_sigop_cost(
                &candidate.coinbase,
                &[],
                VerifyFlags::NONE
            )),
            expected,
        );
        assert!(candidate.transactions.is_empty());
        assert_eq!(
            candidate.coinbase.outputs[0].script_pubkey.as_slice(),
            payout
        );
        assert_eq!(candidate.coinbase.has_witness(), segwit_active);
        assert_eq!(
            candidate.coinbase.outputs.len(),
            if segwit_active { 2 } else { 1 }
        );
        Ok(())
    }

    #[test]
    fn coinbase_and_admitted_package_costs_share_one_inclusive_limit() -> TestResult {
        let payout = p2pkh();
        let mut pool = zero_fee_pool();
        let parent = transaction(None, 2_000);
        let child = transaction(Some(parent.txid()), 1_000);
        let parent_txid = parent.txid();
        let child_txid = child.txid();
        for (tx, fee) in [(parent, 100), (child, 1_000)] {
            assert_eq!(oracle_sigop_cost(&tx)?, 4);
            let cost = transaction_sigop_cost(&tx, &[], VerifyFlags::NONE);
            assert_eq!(cost, 4);
            let vsize = u32::try_from(tx.vsize())?;
            insert_with_cost(&mut pool, tx, vsize, fee, 1, 100, cost)?;
        }
        let snapshot = pool.mining_snapshot();
        for segwit_active in [false, true] {
            {
                let candidate =
                    assemble_candidate(&sigop_limited(segwit_active, 12), &pool, &payout)?;
                assert_eq!(candidate.transactions.len(), 2);
                assert_eq!(block_sigop_cost(&candidate)?, 12);
            }
            {
                let candidate = assemble_ordered_candidate(
                    &sigop_limited(segwit_active, 12),
                    &snapshot,
                    &payout,
                )?;
                assert_eq!(candidate.transactions.len(), 2);
                assert_eq!(block_sigop_cost(&candidate)?, 12);
            }
            let limited = sigop_limited(segwit_active, 11);
            let selected = assemble_candidate(&limited, &pool, &payout)?;
            assert_eq!(selected.transactions.len(), 1);
            assert_eq!(selected.transactions[0].txid, parent_txid);
            assert_eq!(selected.transactions[0].fee, 100);
            assert_eq!(selected.transactions[0].depends, [0_u32; 0]);
            assert!(!selected.transactions.iter().any(|tx| tx.txid == child_txid));
            assert_eq!(block_sigop_cost(&selected)?, 8);
            assert_eq!(oracle_sigop_cost(&selected.coinbase)?, 4);
            assert!(matches!(
                assemble_ordered_candidate(&limited, &snapshot, &payout),
                Err(MiningError::CapacityExhausted { field: "sigops" })
            ));
        }
        Ok(())
    }

    fn block_sigop_cost(candidate: &Candidate) -> Result<u64, TestError> {
        Ok(candidate
            .into_unsolved_block()?
            .txs
            .iter()
            .map(oracle_sigop_cost)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .sum::<u64>())
    }

    fn transaction(parent: Option<Txid>, value: u64) -> Tx {
        let mut tx = tx(1, value, parent);
        tx.inputs[0].previous_output = OutPoint::new(
            parent.unwrap_or_else(|| Txid::from(Hash256::from_le_bytes(&[1; 32]))),
            0,
        );
        tx.outputs[0].script_pubkey = p2pkh().into();
        tx
    }
}
mod mining_coinbase_template {
    use crate::support::mining::fixtures as common;

    use crate::support::mining::TestError;
    use std::sync::Arc;

    use crate::mining::{
        CandidateContext, MiningError, TemplateId, WITNESS_RESERVED_VALUE, assemble_candidate,
    };
    use bitcoin::Wtxid as OracleWtxid;
    use bitcoin::hashes::{Hash as _, HashEngine as _, sha256d};
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_consensus::bip34::check_bip34;
    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid,
        Witness,
    };
    use bitcoin_rs_mempool::{Mempool, MempoolGateway, MempoolLimits};
    use common::{PAYOUT, insert, witnessed_tx, zero_fee_pool};

    fn context(height: u32, segwit_active: bool) -> CandidateContext {
        CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[0xab; 32]),
            height,
            segwit_active,
            min_time: 1_700_000_001,
            current_time: 1_700_000_600,
            locktime_cutoff: 1_700_000_000,
            ..common::context()
        }
    }

    fn used_empty_pool() -> Result<Mempool, TestError> {
        let mut pool = zero_fee_pool();
        let first = witnessed_tx(1, 1_000, None);
        let first_txid = first.txid();
        for tx in [first, witnessed_tx(2, 1_000, None)] {
            let vsize = u32::try_from(tx.vsize())?;
            insert(&mut pool, tx, vsize, 1_000, 0, 0)?;
        }
        pool.prioritise(first_txid, 500)?;
        pool.clear();
        assert_eq!(pool.len(), 0, "the fixture pool is empty");
        assert_ne!(
            pool.fee_delta_sequence_number(),
            0,
            "prioritisation moved it"
        );
        assert_ne!(
            pool.sequence_number(),
            pool.fee_delta_sequence_number(),
            "distinct counters expose a transposed template identity"
        );
        Ok(pool)
    }

    #[test]
    fn empty_candidate_encodes_bip34_and_exact_subsidy() -> Result<(), TestError> {
        let context = context(800_000, true);
        let pool = used_empty_pool()?;
        let candidate = assemble_candidate(&context, &pool, PAYOUT)?;

        check_bip34(800_000, &candidate.coinbase.inputs[0].script_sig)?;
        assert_eq!(
            &candidate.coinbase.inputs[0].script_sig[..4],
            &[3, 0x00, 0x35, 0x0c]
        );
        assert!(candidate.transactions.is_empty());
        assert_eq!(
            candidate.coinbase_value,
            bitcoin_rs_consensus::block_subsidy(
                800_000,
                Network::Regtest.subsidy_halving_interval()
            )
        );
        assert_eq!(
            candidate.coinbase.outputs[0].script_pubkey.as_bytes(),
            PAYOUT
        );
        assert_eq!(
            candidate.template_id,
            TemplateId::with_fee_revision(
                &context.previous_block_hash,
                pool.sequence_number(),
                pool.fee_delta_sequence_number()
            )
        );
        assert_eq!(
            candidate.template_id.as_str(),
            format!(
                "{}{}:{}",
                context.previous_block_hash.to_string_be(),
                pool.sequence_number(),
                pool.fee_delta_sequence_number()
            )
        );
        Ok(())
    }

    #[test]
    fn small_heights_use_bip34_opcodes_and_two_byte_script_sig() -> Result<(), TestError> {
        let pool = zero_fee_pool();
        for height in [1_u32, 16] {
            let candidate = assemble_candidate(&context(height, false), &pool, &[])?;
            check_bip34(height, &candidate.coinbase.inputs[0].script_sig)?;
            assert!(candidate.coinbase.inputs[0].script_sig.len() >= 2);
            assert!(candidate.witness_commitment.is_none());
            assert!(candidate.coinbase.inputs[0].witness.is_empty());
            assert_eq!(candidate.coinbase.outputs.len(), 1);
        }
        Ok(())
    }

    #[test]
    fn segwit_candidate_commits_to_selected_wtxids_and_reserved_value() -> Result<(), TestError> {
        let parent = witnessed_tx(1, 50_000, None);
        let child = witnessed_tx(2, 40_000, Some(parent.txid()));
        let mut pool = zero_fee_pool();
        insert(
            &mut pool,
            parent.clone(),
            u32::try_from(parent.vsize())?,
            2_000,
            0,
            0,
        )?;
        insert(
            &mut pool,
            child.clone(),
            u32::try_from(child.vsize())?,
            3_000,
            0,
            0,
        )?;
        let candidate = assemble_candidate(&context(100, true), &pool, PAYOUT)?;

        assert_eq!(candidate.transactions.len(), 2);
        assert_eq!(
            candidate.transactions.iter().map(|tx| tx.fee).sum::<u64>(),
            5_000
        );
        assert_eq!(
            candidate.coinbase_value,
            bitcoin_rs_consensus::block_subsidy(100, Network::Regtest.subsidy_halving_interval())
                + 5_000
        );

        assert_eq!(
            candidate.coinbase.inputs[0].witness,
            vec![WITNESS_RESERVED_VALUE.to_vec()]
        );

        let mut leaves = vec![OracleWtxid::all_zeros()];
        leaves.extend(
            candidate
                .transactions
                .iter()
                .map(|tx| OracleWtxid::from_byte_array(*tx.wtxid.as_bytes())),
        );
        let root = bitcoin::merkle_tree::calculate_root(leaves.into_iter()).ok_or("root")?;
        let expected_root = Hash256::from_le_bytes(root.as_byte_array());
        let mut engine = sha256d::Hash::engine();
        engine.input(expected_root.as_byte_array());
        engine.input(&WITNESS_RESERVED_VALUE);
        let expected_commitment =
            Hash256::from_le_bytes(sha256d::Hash::from_engine(engine).as_byte_array());
        assert_eq!(candidate.witness_commitment, Some(expected_commitment));

        let commitment_output = candidate
            .coinbase
            .outputs
            .iter()
            .rev()
            .find(|output| output.script_pubkey.first() == Some(&0x6a))
            .ok_or("missing commitment output")?;
        let script = &commitment_output.script_pubkey;
        assert_eq!(script.len(), 38);
        assert_eq!(script[0], 0x6a);
        assert_eq!(script[1], 0x24);
        assert_eq!(&script[2..6], &[0xaa, 0x21, 0xa9, 0xed]);
        assert_eq!(&script[6..], expected_commitment.as_byte_array());
        Ok(())
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn fee_overflow_is_reported_instead_of_wrapping() {
        let mut pool = zero_fee_pool();
        for tx in [witnessed_tx(1, 1_000, None), witnessed_tx(2, 1_000, None)] {
            let vsize = u32::try_from(tx.vsize()).expect("fixture vsize fits u32");
            insert(&mut pool, tx, vsize, u64::MAX, 0, 0).expect("max-fee fixture admits");
        }
        let err = assemble_candidate(&context(1, false), &pool, PAYOUT)
            .expect_err("fee overflow must fail");
        assert_eq!(err, MiningError::FeeOverflow);
    }

    #[test]
    fn maximum_priority_delta_does_not_break_candidate_construction() -> Result<(), TestError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let tx = witnessed_tx(1, 1_000, None);
        let txid = tx.txid();
        let vsize = u32::try_from(tx.vsize())?;
        insert(&mut pool, tx, vsize, 1_000, 0, 1)?;
        pool.prioritise(txid, i64::MAX)?;
        let snapshot = pool.mining_snapshot();
        assert_eq!(snapshot.sequence, pool.sequence_number());
        assert_eq!(
            snapshot.fee_delta_sequence,
            pool.fee_delta_sequence_number(),
            "snapshot fee sequence comes from the same pool state"
        );
        assert_ne!(
            snapshot.fee_delta_sequence, 0,
            "prioritisation moves the fee sequence"
        );
        assert_eq!(
            snapshot.entries[0].fee_delta,
            i64::MAX,
            "the overlay saturates at the i64 boundary"
        );
        assert_eq!(
            snapshot.entries[0].fee, 1_000,
            "actual fees fund the coinbase, the delta only orders"
        );
        let chunks: Vec<_> = pool.chunks_by_feerate().collect();
        assert_eq!(chunks.len(), 1, "one entry, one chunk");
        assert_eq!(
            chunks[0].modified_fee,
            i128::from(i64::MAX) + 1_000,
            "the chunk keeps the full i128 modified fee"
        );
        let ctx = context(2, true);
        let candidate = assemble_candidate(&ctx, &pool, PAYOUT)?;
        assert_eq!(candidate.transactions.len(), 1);
        assert_eq!(candidate.transactions[0].txid, txid);
        assert_eq!(
            candidate.template_id,
            TemplateId::with_fee_revision(
                &ctx.previous_block_hash,
                snapshot.sequence,
                snapshot.fee_delta_sequence
            )
        );
        assert_eq!(
            candidate.transactions.iter().map(|tx| tx.fee).sum::<u64>(),
            1_000,
            "priority deltas are never coinbase income"
        );
        Ok(())
    }

    struct ReorgCoins {
        funding: OutPoint,
        confirmed: TxOut,
    }

    impl bitcoin_rs_mempool::AdmissionChain for ReorgCoins {
        fn snapshot(&self, tx: &Tx) -> Option<bitcoin_rs_mempool::ChainAdmissionSnapshot> {
            Some(bitcoin_rs_mempool::ChainAdmissionSnapshot {
                prevouts: tx
                    .inputs
                    .iter()
                    .filter(|input| input.previous_output == self.funding)
                    .map(|input| (input.previous_output, self.confirmed.clone()))
                    .collect(),
                height: 100,
                ..bitcoin_rs_mempool::ChainAdmissionSnapshot::default()
            })
        }
    }

    fn reconsidered_sigop_fixture() -> Result<(Arc<MempoolGateway>, Tx, Tx), TestError> {
        use bitcoin::hashes::{hash160, sha256};

        let redeem = vec![0x00, 0x63, 0xac, 0x68, 0x51];
        let witness_script = vec![0x00, 0x63, 0x52, 0xae, 0x68, 0x51];
        let funding = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[0x44; 32])), 0);
        let confirmed = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(
                [
                    vec![0xa9, 0x14],
                    hash160::Hash::hash(&redeem).to_byte_array().to_vec(),
                    vec![0x87],
                ]
                .concat(),
            ),
        };
        let parent = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: funding,
                script_sig: Script::from_bytes(bitcoin_rs_consensus::script::push_data(&redeem)),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: Script::from_bytes(
                    [
                        vec![0x00, 0x20],
                        sha256::Hash::hash(&witness_script).to_byte_array().to_vec(),
                    ]
                    .concat(),
                ),
            }],
            lock_time: LockTime::ZERO,
        };
        let child = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(parent.txid(), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![witness_script]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(8_000),
                script_pubkey: Script::from_bytes([vec![0x00, 0x20], vec![0x22; 32]].concat()),
            }],
            lock_time: LockTime::ZERO,
        };
        let chain = ReorgCoins { funding, confirmed };
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(Mempool::new(MempoolLimits::default()).into()),
            None,
            ValidationEngine::Native,
            None,
        ));
        let transition = gateway.begin_chain_change()?;
        assert!(gateway.stable_generation().is_none());
        let changes = gateway.reconsider_disconnected(
            &transition,
            &chain,
            0,
            [Arc::new(parent.clone()), Arc::new(child.clone())],
        );
        assert_eq!(changes.len(), 2);
        transition.finish()?;

        Ok((gateway, parent, child))
    }

    #[test]
    fn reconsidered_prevout_cost_reaches_the_mining_sigop_budget() -> Result<(), TestError> {
        let (gateway, parent, child) = reconsidered_sigop_fixture()?;
        let snapshot = gateway.read().mining_snapshot();
        assert_eq!(snapshot.entries.len(), 2);
        let entry_sigop_cost = |txid: Txid| -> Result<u32, TestError> {
            Ok(snapshot
                .entries
                .iter()
                .find(|entry| entry.txid == txid)
                .ok_or("missing entry")?
                .sigop_cost)
        };
        assert_eq!(entry_sigop_cost(parent.txid())?, 4);
        assert_eq!(entry_sigop_cost(child.txid())?, 2);

        let mut limited = context(101, true);
        limited.max_sigops = 5;
        let candidate = assemble_candidate(&limited, &gateway.read(), PAYOUT)?;
        assert_eq!(candidate.transactions.len(), 1);
        assert_eq!(candidate.transactions[0].txid, parent.txid());
        assert_eq!(candidate.transactions[0].fee, 1_000);
        assert_eq!(candidate.transactions[0].depends, [0_u32; 0]);
        assert_eq!(u64::from(candidate.transactions[0].sigop_cost), 4);
        assert!(
            !candidate
                .transactions
                .iter()
                .any(|tx| tx.txid == child.txid()),
            "the child stays omitted when only its parent prefix fits"
        );
        limited.max_sigops = 6;
        let candidate = assemble_candidate(&limited, &gateway.read(), PAYOUT)?;
        assert_eq!(candidate.transactions.len(), 2);
        assert_eq!(
            candidate
                .transactions
                .iter()
                .map(|tx| u64::from(tx.sigop_cost))
                .sum::<u64>(),
            6
        );
        Ok(())
    }
}
mod mining_index_selection_oracle {
    #![expect(
        clippy::expect_used,
        reason = "integration fixtures fail loudly on a broken precondition"
    )]

    use crate::support::mining::fixtures as common;

    use std::collections::HashSet;
    use std::ops::Range;
    use std::sync::Arc;

    use crate::mining::{Candidate, CandidateContext, assemble_candidate};
    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Sequence, Tx, Txid,
    };
    use bitcoin_rs_mempool::{Mempool, MempoolEntry, SnapshotEntry};
    use common::{
        Forged, PAYOUT, insert_forged, selected_fees, serialized_size, total_sigop_cost, tx,
        zero_fee_pool,
    };
    use proptest::prelude::*;

    const NON_FINAL_LOCKTIME: u32 = 500_000_100;
    const LOCKTIME_CUTOFF: u32 = 500_000_000;

    fn context() -> CandidateContext {
        CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[0xe1; 32]),
            locktime_cutoff: LOCKTIME_CUTOFF,
            ..common::context()
        }
    }

    fn selected(candidate: &Candidate) -> Vec<Txid> {
        candidate.transactions.iter().map(|tx| tx.txid).collect()
    }

    #[derive(Clone, Copy, Debug)]
    struct Reservation {
        weight: u64,
        size: u64,
        sigops: u64,
    }

    impl Reservation {
        fn of(context: &CandidateContext) -> Self {
            let empty = assemble_candidate(context, &zero_fee_pool(), PAYOUT)
                .expect("an empty pool assembles under the generous context");
            Self {
                weight: empty.weight,
                size: serialized_size(&empty),
                sigops: total_sigop_cost(&empty),
            }
        }
    }

    fn count_bytes(body: usize) -> u64 {
        match body + 1 {
            0..=252 => 1,
            253..=65_535 => 3,
            _ => 5,
        }
    }

    fn final_in_next_block(context: &CandidateContext, pooled: &HashSet<Txid>, tx: &Tx) -> bool {
        let lock_time = tx.lock_time.to_consensus();
        let absolute = lock_time == 0 || {
            let threshold = if lock_time < 500_000_000 {
                context.height
            } else {
                context.locktime_cutoff
            };
            lock_time < threshold
                || tx
                    .inputs
                    .iter()
                    .all(|input| input.sequence.to_consensus() == 0xFFFF_FFFF)
        };
        let relative = !context.csv_active
            || tx.version < 2
            || tx.inputs.iter().all(|input| {
                let sequence = input.sequence.to_consensus();
                let locked = sequence & (1 << 31) == 0 && sequence & 0xFFFF != 0;
                !(pooled.contains(&input.previous_output.txid) && locked)
            });
        absolute && relative
    }

    const BLOCK_MIN_TX_FEE_SAT_PER_KVB: i128 = 1;

    type Run = Range<usize>;

    struct Oracle<'a> {
        context: &'a CandidateContext,
        entries: &'a [SnapshotEntry],
        charged: Vec<u64>,
        pooled: HashSet<Txid>,
        taken: Vec<bool>,
        order: Vec<Txid>,
        fees: u64,
        weight: u64,
        size: u64,
        sigops: u64,
    }

    impl Oracle<'_> {
        fn modified_fee(&self, run: &Run) -> i128 {
            self.entries[run.start..run.end]
                .iter()
                .map(|entry| i128::from(entry.fee) + i128::from(entry.fee_delta))
                .sum()
        }

        fn charged_weight(&self, run: &Run) -> u64 {
            self.charged[run.start..run.end].iter().sum()
        }

        fn pays_block_min_fee(&self, run: &Run) -> bool {
            let vsize = i128::from(self.charged_weight(run).div_ceil(4));
            self.modified_fee(run) * 1_000 >= BLOCK_MIN_TX_FEE_SAT_PER_KVB * vsize
        }

        fn blocked(&self, run: &Run) -> bool {
            self.entries[run.start..run.end]
                .iter()
                .flat_map(|entry| entry.ancestors.iter())
                .any(|&ancestor| {
                    let ancestor = usize::try_from(ancestor).expect("snapshot position fits");
                    !self.taken[ancestor] && !run.contains(&ancestor)
                })
        }

        fn is_final(&self, run: &Run) -> bool {
            self.entries[run.start..run.end]
                .iter()
                .all(|entry| final_in_next_block(self.context, &self.pooled, &entry.tx))
        }

        fn grown_by(&self, run: &Run) -> Option<(u64, u64, u64)> {
            let members = &self.entries[run.start..run.end];
            let growth =
                count_bytes(self.order.len() + members.len()) - count_bytes(self.order.len());
            let weight =
                self.weight + members.iter().map(|entry| entry.weight).sum::<u64>() + growth * 4;
            let size = self.size
                + members
                    .iter()
                    .map(|entry| u64::from(entry.size))
                    .sum::<u64>()
                + growth;
            let sigops = self.sigops
                + members
                    .iter()
                    .map(|entry| u64::from(entry.sigop_cost))
                    .sum::<u64>();
            (weight <= self.context.max_weight
                && size <= self.context.max_size
                && sigops <= self.context.max_sigops)
                .then_some((weight, size, sigops))
        }

        fn take(&mut self, run: &Run) {
            let (weight, size, sigops) = self.grown_by(run).expect("the run fits");
            self.weight = weight;
            self.size = size;
            self.sigops = sigops;
            for position in run.start..run.end {
                self.taken[position] = true;
                self.order.push(self.entries[position].txid);
                self.fees += self.entries[position].fee;
            }
        }
    }

    fn oracle(
        context: &CandidateContext,
        pool: &Mempool,
        reservation: Reservation,
    ) -> (Vec<Txid>, u64) {
        let snapshot = pool.mining_snapshot();
        let mut oracle = Oracle {
            context,
            entries: &snapshot.entries,
            charged: snapshot
                .entries
                .iter()
                .map(|entry| {
                    pool.entry_by_txid(&entry.txid)
                        .expect("snapshot entry is pooled")
                        .policy_weight()
                })
                .collect(),
            pooled: snapshot.entries.iter().map(|entry| entry.txid).collect(),
            taken: vec![false; snapshot.entries.len()],
            order: Vec::new(),
            fees: 0,
            weight: reservation.weight,
            size: reservation.size,
            sigops: reservation.sigops,
        };

        let mut runs: Vec<Run> = Vec::new();
        let mut start = 0_usize;
        for chunk in pool.chunks_by_feerate() {
            let run = start..start + chunk.len();
            assert_eq!(
                chunk.modified_fee,
                oracle.modified_fee(&run),
                "indexed chunk fee equals its member sums"
            );
            assert_eq!(
                chunk.charged_weight,
                oracle.charged_weight(&run),
                "indexed chunk weight equals its member sums"
            );
            start = run.end;
            runs.push(run);
        }
        assert_eq!(
            start,
            snapshot.entries.len(),
            "chunks partition the snapshot"
        );

        let mut skipped: Vec<Run> = Vec::new();
        for run in runs {
            if !oracle.pays_block_min_fee(&run) {
                break;
            }
            if oracle.blocked(&run) || !oracle.is_final(&run) {
                continue;
            }
            if oracle.grown_by(&run).is_none() {
                skipped.push(run);
                continue;
            }
            oracle.take(&run);
        }
        for run in skipped {
            let longest = (1..=run.len())
                .rev()
                .map(|len| run.start..run.start + len)
                .find(|prefix| {
                    oracle.pays_block_min_fee(prefix)
                        && !oracle.blocked(prefix)
                        && oracle.grown_by(prefix).is_some()
                });
            if let Some(prefix) = longest {
                oracle.take(&prefix);
            }
        }
        (oracle.order, oracle.fees)
    }

    #[derive(Clone, Copy, Debug)]
    struct Spec {
        parent: Option<usize>,
        fee: u64,
        weight: u64,
        exact_vsize: bool,
        size: u32,
        sigops: u32,
        non_final_locktime: bool,
        lock_kind: u8,
        delta: i64,
    }

    fn oracle_cases() -> u32 {
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(256)
    }

    fn spec() -> impl Strategy<Value = Spec> {
        (
            prop::option::of(0_usize..24),
            prop_oneof![
                3 => 5_000_u64..60_000,
                1 => Just(0_u64),
                1 => Just(1_u64),
                1 => Just(Amount::MAX_MONEY.to_sat()),
            ],
            prop::sample::select(vec![
                400_u64, 800, 2_000, 8_000, 401, 1_997, 2_001, 1024, 4096, 65_536, 101_008,
            ]),
            any::<bool>(),
            prop::sample::select(vec![100_u32, 200, 1_000, 101]),
            0_u32..40,
            0_u8..6,
            0_u8..4,
            prop::sample::select(vec![
                0_i64,
                0,
                0,
                -4_000,
                -2_000,
                3_000,
                90_000,
                -65_000,
                i64::MIN,
                i64::MAX,
            ]),
        )
            .prop_map(
                |(parent, fee, weight, exact_vsize, size, sigops, locktime, lock_kind, delta)| {
                    Spec {
                        parent,
                        fee,
                        weight,
                        exact_vsize,
                        size,
                        sigops,
                        non_final_locktime: locktime == 0,
                        lock_kind,
                        delta,
                    }
                },
            )
    }

    fn spec_tx(label: u8, parent: Option<Txid>, spec: &Spec) -> Tx {
        let mut transaction = tx(label, 1_000, parent);
        if let Some(parent) = parent {
            for input in &mut transaction.inputs {
                input.previous_output = OutPoint::new(parent, u32::from(label));
            }
        }
        let sequence = match spec.lock_kind {
            1 => Sequence::from_consensus(1),
            2 => Sequence::from_consensus(0x8000_0005),
            _ => Sequence::MAX,
        };
        for input in &mut transaction.inputs {
            input.sequence = sequence;
        }
        if spec.non_final_locktime {
            transaction.lock_time = LockTime::from_consensus(NON_FINAL_LOCKTIME);
            for input in &mut transaction.inputs {
                if input.sequence == Sequence::MAX {
                    input.sequence = Sequence::from_consensus(0xFFFF_FFFE);
                }
            }
        }
        transaction
    }

    fn build_pool(specs: &[Spec]) -> Mempool {
        let mut pool = zero_fee_pool();
        let mut txids: Vec<Txid> = Vec::new();
        let mut cluster_of: Vec<usize> = Vec::new();
        let mut cluster_weights: Vec<u64> = Vec::new();
        let max_cluster_weight = pool.limits.cluster_size_vbytes.saturating_mul(4);
        for (index, spec) in specs.iter().enumerate() {
            let label = u8::try_from(index).expect("at most 24 specs");
            let forged = Forged::new(spec.fee, spec.weight, spec.size).with_sigops(spec.sigops);
            let forged = if spec.exact_vsize {
                let vsize = u32::try_from(spec.weight.div_ceil(4)).expect("weight fits vsize");
                forged.with_vsize(vsize)
            } else {
                forged
            };
            let mut dummy = MempoolEntry::new(
                Arc::new(tx(label, 1_000, None)),
                forged.vsize,
                forged.fee,
                1,
                100,
                forged.sigop_cost,
            );
            dummy.weight = forged.weight;
            let policy_weight = dummy.policy_weight();
            let parent_idx = spec
                .parent
                .filter(|_| index > 0)
                .map(|choice| choice % index)
                .filter(|&choice| {
                    let cid = cluster_of[choice];
                    cluster_weights[cid].saturating_add(policy_weight) <= max_cluster_weight
                });
            let parent = parent_idx.map(|choice| txids[choice]);
            let transaction = spec_tx(label, parent, spec);
            txids.push(transaction.txid());
            match parent_idx {
                Some(choice) => {
                    let cid = cluster_of[choice];
                    cluster_of.push(cid);
                    cluster_weights[cid] = cluster_weights[cid].saturating_add(policy_weight);
                }
                None => {
                    let cid = cluster_weights.len();
                    cluster_of.push(cid);
                    cluster_weights.push(policy_weight);
                }
            }
            insert_forged(&mut pool, transaction, forged)
                .expect("generated entries stay inside admission limits");
        }
        for (txid, spec) in txids.iter().zip(specs) {
            if spec.delta != 0 {
                pool.prioritise(*txid, spec.delta)
                    .expect("overlay stays inside i64");
            }
        }
        pool
    }

    proptest! {
    #![proptest_config(proptest::test_runner::Config {
        failure_persistence: Some(std::boxed::Box::new(
            proptest::test_runner::FileFailurePersistence::Direct(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/serving/regressions/mining_index_selection_oracle.txt"
            )),
        )),
        ..(ProptestConfig {
            cases: oracle_cases(),
            ..ProptestConfig::default()
        })
    })]
        #[test]
        fn indexed_selection_matches_the_independent_oracle(
            specs in prop::collection::vec(spec(), 1..24),
            csv_active in any::<bool>(),
            weight_extra in prop::sample::select(vec![0_u64, 500, 1_200, 3_000, 20_000, 3_000_000]),
            size_extra in prop::sample::select(vec![0_u64, 150, 400, 1_500, 10_000, 3_000_000]),
            sigop_extra in prop::sample::select(vec![0_u64, 20, 60, 400, 70_000]),
        ) {
            let pool = build_pool(&specs);
            let base = CandidateContext { csv_active, ..context() };
            let reservation = Reservation::of(&base);
            let limited = CandidateContext {
                max_weight: reservation.weight + weight_extra,
                max_size: reservation.size + size_extra,
                max_sigops: reservation.sigops + sigop_extra,
                ..base
            };
            let candidate = assemble_candidate(&limited, &pool, PAYOUT)
                .expect("limits cover the reservation");
            let (order, fees) = oracle(&limited, &pool, reservation);
            prop_assert_eq!(selected(&candidate), order);
            prop_assert_eq!(selected_fees(&candidate), fees);
        }
    }

    #[test]
    fn skipped_ancestor_chunk_blocks_a_later_descendant_chunk() {
        let mut pool = zero_fee_pool();
        let a = tx(1, 1_000, None);
        let b = tx(2, 1_000, None);
        let c = tx(3, 1_000, Some(b.txid()));
        let d = tx(4, 1_000, Some(c.txid()));
        let a_txid = a.txid();
        insert_forged(&mut pool, a, Forged::new(10_000, 400, 100)).expect("A admits");
        insert_forged(&mut pool, b, Forged::new(100, 20_000, 100)).expect("B admits");
        insert_forged(&mut pool, c, Forged::new(50_000, 400, 100)).expect("C admits");
        insert_forged(&mut pool, d, Forged::new(10, 400, 100)).expect("D admits");

        let base = context();
        let reservation = Reservation::of(&base);
        let limited = CandidateContext {
            max_weight: reservation.weight + 2_000,
            ..base
        };
        let candidate = assemble_candidate(&limited, &pool, PAYOUT).expect("template");
        assert_eq!(selected(&candidate), vec![a_txid]);
        assert_eq!(oracle(&limited, &pool, reservation).0, vec![a_txid]);
    }

    #[test]
    fn overlays_rank_by_modified_fee_and_pay_actual_fees() {
        let mut pool = zero_fee_pool();
        let dear = tx(1, 1_000, None);
        let cheap = tx(2, 1_000, None);
        let mid = tx(3, 1_000, None);
        let (dear_txid, cheap_txid, mid_txid) = (dear.txid(), cheap.txid(), mid.txid());
        insert_forged(&mut pool, dear, Forged::new(9_000, 400, 100)).expect("dear admits");
        insert_forged(&mut pool, cheap, Forged::new(1_000, 400, 100)).expect("cheap admits");
        insert_forged(&mut pool, mid, Forged::new(5_000, 400, 100)).expect("mid admits");
        pool.prioritise(cheap_txid, 20_000)
            .expect("positive overlay applies");
        pool.prioritise(dear_txid, -6_000)
            .expect("negative overlay applies");

        let base = context();
        let reservation = Reservation::of(&base);
        let candidate = assemble_candidate(&base, &pool, PAYOUT).expect("template");
        assert_eq!(selected(&candidate), vec![cheap_txid, mid_txid, dear_txid]);
        assert_eq!(selected_fees(&candidate), 15_000);
        let (order, fees) = oracle(&base, &pool, reservation);
        assert_eq!(order, selected(&candidate));
        assert_eq!(fees, 15_000);
    }

    fn exact(fee: u64, weight: u64) -> Forged {
        let vsize = u32::try_from(weight.div_ceil(4)).expect("test weight fits vsize");
        Forged::new(fee, weight, vsize).with_vsize(vsize)
    }

    #[test]
    fn aggregate_floor_rescues_a_zero_fee_parent_and_ends_the_walk() {
        let mut pool = zero_fee_pool();
        let parent = tx(1, 1_000, None);
        let child = tx(2, 1_000, Some(parent.txid()));
        let idle = tx(3, 1_000, None);
        let (parent_txid, child_txid) = (parent.txid(), child.txid());
        insert_forged(&mut pool, parent, exact(0, 400)).expect("parent admits");
        insert_forged(&mut pool, child, exact(5_000, 400)).expect("child admits");
        insert_forged(&mut pool, idle, exact(0, 400)).expect("idle admits");

        let base = context();
        let reservation = Reservation::of(&base);
        let candidate = assemble_candidate(&base, &pool, PAYOUT).expect("template");
        assert_eq!(selected(&candidate), vec![parent_txid, child_txid]);
        assert_eq!(selected_fees(&candidate), 5_000);
        let (order, fees) = oracle(&base, &pool, reservation);
        assert_eq!(order, selected(&candidate));
        assert_eq!(fees, 5_000);
    }

    #[test]
    fn tail_prefix_meets_the_minimum_on_exactly_rounded_aggregate_weight() {
        let mut pool = zero_fee_pool();
        let parent = tx(1, 1_000, None);
        let middle = tx(2, 1_000, Some(parent.txid()));
        let last = tx(3, 1_000, Some(middle.txid()));
        let (parent_txid, middle_txid) = (parent.txid(), middle.txid());
        insert_forged(&mut pool, parent, exact(0, 1_997)).expect("parent admits");
        insert_forged(&mut pool, middle, exact(1, 2_001)).expect("middle admits");
        insert_forged(&mut pool, last, exact(10_000, 5_000)).expect("last admits");
        assert_eq!(
            pool.chunks_by_feerate().count(),
            1,
            "increasing fees keep the chain in one chunk"
        );

        let base = context();
        let reservation = Reservation::of(&base);
        let limited = CandidateContext {
            max_weight: reservation.weight + 5_000,
            ..base
        };
        let candidate = assemble_candidate(&limited, &pool, PAYOUT).expect("template");
        assert_eq!(selected(&candidate), vec![parent_txid, middle_txid]);
        assert_eq!(selected_fees(&candidate), 1);
        let (order, fees) = oracle(&limited, &pool, reservation);
        assert_eq!(order, selected(&candidate));
        assert_eq!(fees, 1);
    }

    #[test]
    fn tail_prefix_that_misses_the_minimum_is_not_selected() {
        let mut pool = zero_fee_pool();
        let parent = tx(1, 1_000, None);
        let child = tx(2, 1_000, Some(parent.txid()));
        insert_forged(&mut pool, parent, exact(0, 400)).expect("parent admits");
        insert_forged(&mut pool, child, exact(100_000, 1_000)).expect("child admits");
        assert_eq!(
            pool.chunks_by_feerate().count(),
            1,
            "the child's rate merges the pair into one chunk"
        );

        let base = context();
        let reservation = Reservation::of(&base);
        let limited = CandidateContext {
            max_weight: reservation.weight + 900,
            ..base
        };
        let candidate = assemble_candidate(&limited, &pool, PAYOUT).expect("template");
        let empty: [Txid; 0] = [];
        assert_eq!(selected(&candidate), empty);
        let (order, fees) = oracle(&limited, &pool, reservation);
        assert_eq!(order, empty);
        assert_eq!(fees, 0);
    }
}
mod mining_overhaul_resource_bounds {
    use crate::support::mining::TestError;
    use bitcoin_rs_consensus::{ValidationEngine, transaction_sigop_cost};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Instant;

    use crate::mining::{Candidate, CandidateContext, assemble_candidate};
    use bitcoin::hashes::{Hash as _, sha256};
    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
        unix_time_secs,
    };
    use bitcoin_rs_consensus::script::VerifyFlags;
    use bitcoin_rs_mempool::standardness::AcceptanceRejectReason;
    use bitcoin_rs_mempool::{
        AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, Mempool, MempoolEntry,
        MempoolGateway, MempoolLimits, PolicyError, ReplacementCandidate, SubmitError,
        SubmitOutcome,
    };
    use parking_lot::RwLock;
    use sonic_rs::{JsonValueTrait as _, Value, json};

    use crate::support::mining::fixtures as common;

    type TestResult<T = ()> = Result<T, TestError>;

    fn context() -> CandidateContext {
        CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[0xab; 32]),
            height: 201,
            min_time: 1_700_000_001,
            current_time: 1_700_000_600,
            locktime_cutoff: 1_700_000_000,
            ..common::context()
        }
    }
    const CLUSTERS: u32 = 100;
    const MEMBERS: u32 = 64;

    struct Fixture {
        gateway: MempoolGateway,
        roots: Vec<OutPoint>,
        tips: Vec<(OutPoint, u64)>,
    }

    fn transaction(previous_output: OutPoint, value: u64, script: &[u8]) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: Script::from_bytes(script.to_vec()),
            }],
        }
    }

    fn p2sh_true_output() -> Vec<u8> {
        bitcoin::ScriptBuf::from_bytes(vec![0x51])
            .to_p2sh()
            .into_bytes()
    }

    fn p2sh_true_script_sig() -> Script {
        Script::from_bytes(vec![0x01, 0x51])
    }

    fn fixture(members: u32) -> TestResult<Fixture> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let mut roots = Vec::new();
        let mut tips = Vec::new();
        for cluster in 0..CLUSTERS {
            let mut bytes = [0_u8; 32];
            bytes[..4].copy_from_slice(&(cluster + 1).to_le_bytes());
            let mut input = OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), 0);
            roots.push(input);
            let mut value = 1_000_000_u64;
            for depth in 0..members {
                let fee = u64::from(depth % 7 + 1) * 1_000;
                value = value.checked_sub(fee).ok_or("fixture funding exhausted")?;
                let fx = p2sh_true_output();
                let tx = Arc::new(transaction(input, value, &fx));
                input = OutPoint::new(tx.txid(), 0);
                let vsize = u32::try_from(tx.vsize())?;
                pool.insert_entry(MempoolEntry::new(tx, vsize, fee, 1, 1, 0))?;
            }
            tips.push((input, value));
        }
        assert_eq!(pool.limits.cluster_count, MEMBERS);
        assert_eq!(pool.limits.max_replacement_clusters, CLUSTERS);
        assert_eq!(pool.len(), usize::try_from(CLUSTERS * members)?);
        Ok(Fixture {
            gateway: MempoolGateway::new(
                Arc::new(RwLock::new(pool)),
                None,
                ValidationEngine::Native,
                None,
            ),
            roots,
            tips,
        })
    }

    fn rss_kib(field: &str) -> TestResult<Option<u64>> {
        if !cfg!(target_os = "linux") {
            return Ok(None);
        }
        let status = std::fs::read_to_string("/proc/self/status")?;
        let row = status
            .lines()
            .find(|line| line.starts_with(field))
            .ok_or("missing Linux RSS field")?;
        Ok(Some(
            row.split_whitespace()
                .nth(1)
                .ok_or("missing RSS value")?
                .parse()?,
        ))
    }

    fn sample(gateway: &MempoolGateway) -> TestResult<Value> {
        let pool = gateway.read();
        assert!(pool.total_vsize() <= pool.limits.max_total_bytes);
        Ok(json!({
            "entries": pool.len(), "vsize": pool.total_vsize(),
            "vsize_limit": pool.limits.max_total_bytes,
            "retained_estimate_bytes": pool.dynamic_memory_usage(),
            "rss_kib": rss_kib("VmRSS:")?, "process_rss_high_water_kib": rss_kib("VmHWM:")?,
        }))
    }

    struct Chain(Vec<(OutPoint, TxOut)>);
    impl AdmissionChain for Chain {
        fn snapshot(&self, _: &Tx) -> Option<ChainAdmissionSnapshot> {
            Some(ChainAdmissionSnapshot {
                prevouts: self.0.clone(),
                height: 200,
                csv_active: true,
                ..ChainAdmissionSnapshot::default()
            })
        }
    }

    fn exercise(stage: &str, fixture: &Fixture) -> TestResult<Value> {
        let gateway = &fixture.gateway;
        match stage {
            "replacement" => {
                let mut tx = transaction(fixture.roots[0], 1_000, &[0x51]);
                tx.inputs = fixture
                    .roots
                    .iter()
                    .map(|&previous_output| TxIn {
                        previous_output,
                        script_sig: Script::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    })
                    .collect();
                let vsize = u32::try_from(tx.vsize())?;
                let changes = gateway.replace_transaction(
                    AdmissionOrigin::Rpc,
                    &ReplacementCandidate::new(Arc::new(tx), vsize, 100_000_000, 1_000),
                    2,
                    1,
                )?;
                assert_eq!(changes.len(), usize::try_from(CLUSTERS * MEMBERS + 1)?);
                assert_eq!(gateway.read().len(), 1);
                Ok(
                    json!({"mutation_changes": changes.len(), "change_bound": CLUSTERS * MEMBERS + 1}),
                )
            }
            "package-preview" => {
                let script = [vec![0, 20], vec![1; 20]].concat();
                let txs: Vec<_> = fixture
                    .tips
                    .iter()
                    .take(25)
                    .map(|&(outpoint, value)| {
                        let mut tx = transaction(outpoint, value - 1_000, &script);
                        tx.inputs[0].script_sig = p2sh_true_script_sig();
                        tx
                    })
                    .collect();
                let sequence = gateway.read().sequence_number();
                let facts = gateway.preview_transactions(&txs, None, &Chain(Vec::new()))?;
                assert!(facts.package_error.is_none(), "{facts:?}");
                assert_eq!(facts.results.len(), 25);
                assert!(
                    facts.results.iter().all(|row| row.allowed == Some(true)),
                    "{facts:?}"
                );
                assert_eq!(gateway.read().sequence_number(), sequence);
                Ok(
                    json!({"offered": facts.results.len(), "package_bound": 25, "projected_cluster_count": MEMBERS}),
                )
            }
            "mining" => {
                let pool = gateway.read();
                let context = context();
                let candidate = assemble_candidate(&context, &pool, &[0x51])?;
                assert_eq!(candidate.transactions.len(), pool.len());
                let sigops = total_sigop_cost(&candidate);
                assert!(candidate.weight <= context.max_weight && sigops <= context.max_sigops);
                Ok(
                    json!({"selected": candidate.transactions.len(), "weight": candidate.weight,
                "weight_limit": context.max_weight, "sigops": sigops, "sigop_limit": context.max_sigops}),
                )
            }
            "eviction" => {
                let target = gateway.read().total_vsize() / 2;
                let changes = gateway.enforce_size_limit(AdmissionOrigin::Rpc, target)?;
                assert!(gateway.read().total_vsize() <= target);
                assert!(changes.len() <= usize::try_from(CLUSTERS * MEMBERS)?);
                Ok(json!({"target_vsize": target, "mutation_changes": changes.len()}))
            }
            _ => Err("unknown resource scenario".into()),
        }
    }

    fn witness_program(script: &[u8]) -> Vec<u8> {
        [
            vec![0, 32],
            sha256::Hash::hash(script).to_byte_array().to_vec(),
        ]
        .concat()
    }

    fn weight_fixture(extra: u8) -> TestResult<(MempoolGateway, Chain, Tx, u64)> {
        let heavy_script = [vec![0x00, 0x63], vec![0xae; 199], vec![0x68, 0x51]].concat();
        let middle_script = [vec![0x61; 20], vec![0x51]].concat();
        let last_script = [vec![0x61; 42 + usize::from(extra)], vec![0x51]].concat();
        let heavy_program = witness_program(&heavy_script);
        let coins: Vec<_> = (9_000_u32..9_004)
            .map(|tag| {
                let mut bytes = [0_u8; 32];
                bytes[..4].copy_from_slice(&tag.to_le_bytes());
                (
                    OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), 0),
                    TxOut {
                        value: Amount::from_sat(100_000),
                        script_pubkey: Script::from_bytes(heavy_program.clone()),
                    },
                )
            })
            .collect();
        let mut parent = transaction(coins[0].0, 300_000, &witness_program(&middle_script));
        parent.inputs = coins
            .iter()
            .map(|(outpoint, _)| TxIn {
                previous_output: *outpoint,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![heavy_script.clone()]),
            })
            .collect();
        let oracle: bitcoin::Transaction = bitcoin::consensus::deserialize(
            &bitcoin_rs_consensus::primitives::consensus_bytes(&parent),
        )?;
        let sigops = oracle.total_sigop_cost(|_| {
            Some(bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(100_000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(heavy_program.clone()),
            })
        });
        assert_eq!(sigops, 15_920, "independent rust-bitcoin sigop count");
        let wire_weight = oracle.weight().to_wu();
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            None,
        );
        let chain = Chain(coins);
        let now = unix_time_secs();
        let parent_id = parent.txid();
        assert!(matches!(
            gateway.submit_transaction(
                Arc::new(parent),
                AdmissionOrigin::Rpc,
                None,
                now,
                &chain
            )?,
            SubmitOutcome::Committed(_)
        ));
        {
            let pool = gateway.read();
            assert_eq!(pool.limits.cluster_size_vbytes, 101_000);
            let entry = pool
                .entry_by_txid(&parent_id)
                .ok_or("missing weighted parent")?;
            assert_eq!(entry.sigop_cost, 15_920);
            assert_eq!(entry.vsize, 79_600);
            assert!(wire_weight < 318_400);
            let chunk = pool.chunks_by_feerate().next().ok_or("empty pool")?;
            assert_eq!(chunk.charged_weight, 318_400);
        }
        let mut middle = transaction(
            OutPoint::new(parent_id, 0),
            299_000,
            &witness_program(&last_script),
        );
        middle.inputs[0].witness = Witness::from_stack(vec![middle_script]);
        assert_eq!(middle.weight(), 401);
        let middle_id = middle.txid();
        assert!(matches!(
            gateway.submit_transaction(
                Arc::new(middle),
                AdmissionOrigin::Rpc,
                None,
                now,
                &chain
            )?,
            SubmitOutcome::Committed(_)
        ));
        let mut last = transaction(OutPoint::new(middle_id, 0), 300, &[0, 20]);
        last.outputs = vec![
            TxOut {
                value: Amount::from_sat(300),
                script_pubkey: Script::from_bytes([vec![0, 20], vec![1; 20]].concat())
            };
            685
        ];
        last.inputs[0].witness = Witness::from_stack(vec![last_script]);
        let oracle: bitcoin::Transaction = bitcoin::consensus::deserialize(
            &bitcoin_rs_consensus::primitives::consensus_bytes(&last),
        )?;
        assert_eq!(oracle.weight().to_wu(), 85_199 + u64::from(extra));
        Ok((gateway, chain, last, wire_weight))
    }

    fn check_weight_boundary(extra: u8) -> TestResult<Value> {
        let (gateway, chain, last, root_wire_weight) = weight_fixture(extra)?;
        let before = sample(&gateway)?;
        let sequence = gateway.read().sequence_number();
        let start = Instant::now();
        let preview = gateway.preview_transactions(std::slice::from_ref(&last), None, &chain)?;
        assert_eq!(preview.results[0].allowed, Some(extra == 0));
        assert_eq!(gateway.read().sequence_number(), sequence);
        let now = unix_time_secs();
        let submitted =
            gateway.submit_transaction(Arc::new(last), AdmissionOrigin::Rpc, None, now, &chain);
        if extra == 0 {
            assert!(matches!(submitted?, SubmitOutcome::Committed(_)));
            let pool = gateway.read();
            let weight: u64 = pool
                .chunks_by_feerate()
                .map(|chunk| chunk.charged_weight)
                .sum();
            assert_eq!(weight, 404_000);
            assert_eq!(
                pool.total_vsize(),
                101_001,
                "rounded entry sizes must not replace exact cluster weight"
            );
        } else {
            assert_eq!(
                submitted,
                Err(SubmitError::Policy(AcceptanceRejectReason::PackageLimit(
                    PolicyError::ClusterSizeLimit
                )))
            );
            assert_eq!(gateway.read().sequence_number(), sequence);
        }
        Ok(
            json!({"stage": "adjusted-weight-boundary", "extra_weight": extra,
        "before": before, "after": sample(&gateway)?, "elapsed_us": start.elapsed().as_micros(),
        "result": {"root_sigops": 15_920, "root_wire_weight": root_wire_weight,
            "root_policy_weight": 318_400, "projected_cluster_weight": 404_000 + u32::from(extra),
            "cluster_weight_limit": 404_000, "allowed": extra == 0}}),
        )
    }

    #[test]
    fn mempool_policy_resource_capture_at_resolved_graph_bounds() -> TestResult {
        let mut measurements = Vec::new();
        let mut retained_endpoint_max = 0_u64;
        for stage in ["package-preview", "mining", "replacement", "eviction"] {
            let fixture = fixture(if stage == "package-preview" {
                MEMBERS - 1
            } else {
                MEMBERS
            })?;
            let before = sample(&fixture.gateway)?;
            let start = Instant::now();
            let result = exercise(stage, &fixture)?;
            let elapsed = start.elapsed().as_micros();
            let after = sample(&fixture.gateway)?;
            for value in [&before, &after] {
                retained_endpoint_max = retained_endpoint_max.max(
                    value["retained_estimate_bytes"]
                        .as_u64()
                        .ok_or("retained estimate missing")?,
                );
            }
            measurements.push(json!({"stage": stage, "elapsed_us": elapsed, "before": before, "after": after, "result": result}));
        }
        for extra in [0, 1] {
            let measurement = check_weight_boundary(extra)?;
            for endpoint in ["before", "after"] {
                retained_endpoint_max = retained_endpoint_max.max(
                    measurement[endpoint]["retained_estimate_bytes"]
                        .as_u64()
                        .ok_or("missing weight-case estimate")?,
                );
            }
            measurements.push(measurement);
        }
        let report = json!({
            "scope": "mempool policy owner; raw count-bound fixtures and verified P2WSH weight boundaries",
            "platform": std::env::consts::OS, "architecture": std::env::consts::ARCH,
            "source_sha256": {
                "fee_diagram": sha256::Hash::hash(include_bytes!("../mempool/src/fee_diagram.rs")).to_string(),
                "pool": sha256::Hash::hash(include_bytes!("../mempool/src/pool.rs")).to_string(),
                "gateway": sha256::Hash::hash(include_bytes!("../mempool/src/gateway.rs")).to_string(),
                "mining_policy": sha256::Hash::hash(include_bytes!("src/mining/policy.rs")).to_string(),
                "harness": sha256::Hash::hash(include_bytes!("tests.rs")).to_string(),
                "cargo_lock": sha256::Hash::hash(include_bytes!("../../Cargo.lock")).to_string(),
            },
            "cluster_count_bound": MEMBERS, "conflicting_cluster_bound": CLUSTERS,
            "retained_estimate_endpoint_max_bytes": retained_endpoint_max,
            "process_rss_high_water_kib": rss_kib("VmHWM:")?,
            "rss_limit": json!(null),
            "rss_unavailable_reason": (!cfg!(target_os = "linux")).then_some("No RSS collector is configured for this platform; policy checks still run."),
            "transient_retained_allocation_high_water_bytes": json!(null),
            "complete_cl14_evidence": false,
            "notes": "RSS has no configured mempool-specific cap. Retained estimates are endpoint samples and omit transient allocations. Vsize and structural limits are checked separately. These partial measurements are not complete resource evidence or a regression/throughput claim.",
            "measurements": measurements,
        });
        let directory =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/process-harness");
        std::fs::create_dir_all(&directory)?;
        let captured_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = directory.join(format!(
            "resource-bounds-{}-{captured_at}.json",
            std::process::id()
        ));
        std::fs::write(&path, sonic_rs::to_vec_pretty(&report)?)?;
        println!("RESOURCE_EVIDENCE {report}");
        println!("resource evidence: {}", path.display());
        Ok(())
    }

    fn total_sigop_cost(candidate: &Candidate) -> u64 {
        u64::from(transaction_sigop_cost(
            &candidate.coinbase,
            &[],
            VerifyFlags::NONE,
        )) + candidate
            .transactions
            .iter()
            .map(|tx| u64::from(tx.sigop_cost))
            .sum::<u64>()
    }
}
mod mining_policy_pareto {
    #![allow(clippy::expect_used)]

    use crate::support::mining::fixtures as common;

    use crate::support::mining::TestError;
    use std::collections::{HashMap, HashSet};

    use crate::mining::{
        Candidate, CandidateContext, MiningError, assemble_candidate, select_template_body,
        select_template_body_after,
    };
    use bitcoin_rs_consensus::primitives::{
        Block, Hash256, Header, LockTime, Network, Sequence, Txid,
    };
    use bitcoin_rs_mempool::{ChunkView, EntryId, Mempool};
    use common::{
        Forged, PAYOUT, insert, insert_forged, selected_fees, serialized_size, total_sigop_cost,
        tx, zero_fee_pool,
    };
    use proptest::prelude::*;

    fn context() -> CandidateContext {
        CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[0xcd; 32]),
            ..common::context()
        }
    }

    fn limits(max_weight: u64, max_size: u64, max_sigops: u64) -> CandidateContext {
        CandidateContext {
            max_weight,
            max_size,
            max_sigops,
            ..context()
        }
    }

    fn selected(candidate: &Candidate) -> Vec<Txid> {
        candidate.transactions.iter().map(|tx| tx.txid).collect()
    }

    #[test]
    fn selects_independent_transactions_in_modified_fee_order() -> Result<(), TestError> {
        let mut mempool = zero_fee_pool();
        let mut expected = Vec::with_capacity(50);
        for index in 0_u32..50 {
            let fee = u64::from(50_u32 - index) * 1_000;
            let transaction = tx(u8::try_from(index)?, 1_000, None);
            expected.push(transaction.txid());
            insert(
                &mut mempool,
                transaction,
                200,
                fee,
                u64::from(index),
                800_000,
            )?;
        }

        let candidate = assemble_candidate(&context(), &mempool, PAYOUT)?;
        assert_eq!(candidate.transactions.len(), 50);
        assert_eq!(selected(&candidate), expected);
        Ok(())
    }

    #[test]
    fn package_selection_is_dependency_closed_and_topological() -> Result<(), TestError> {
        let mut mempool = zero_fee_pool();
        let parent = tx(1, 50_000, None);
        let parent_txid = parent.txid();
        insert(&mut mempool, parent, 200, 1_000, 1, 100)?;
        insert(
            &mut mempool,
            tx(2, 40_000, Some(parent_txid)),
            200,
            10_000,
            2,
            100,
        )?;

        let candidate = assemble_candidate(&context(), &mempool, PAYOUT)?;
        assert_eq!(candidate.transactions.len(), 2);
        assert_eq!(candidate.transactions[0].txid, parent_txid);
        assert_eq!(candidate.transactions[1].depends, vec![1]);
        assert_eq!(selected_fees(&candidate), 11_000);
        Ok(())
    }

    #[test]
    fn modified_fees_rank_but_actual_fees_fund_coinbase() -> Result<(), TestError> {
        let mut mempool = zero_fee_pool();
        let low = tx(1, 1_000, None);
        let low_txid = low.txid();
        insert(&mut mempool, low, 200, 1_000, 1, 100)?;
        insert(&mut mempool, tx(2, 1_000, None), 200, 2_000, 2, 100)?;
        mempool.prioritise(low_txid, 10_000)?;

        let snapshot = mempool.mining_snapshot();
        assert_eq!(snapshot.entries[0].txid, low_txid);

        let candidate = assemble_candidate(&context(), &mempool, PAYOUT)?;
        assert_eq!(candidate.transactions[0].txid, low_txid);
        assert_eq!(candidate.transactions[0].fee, 1_000);
        assert_eq!(selected_fees(&candidate), 3_000);
        assert_eq!(
            candidate.coinbase_value,
            bitcoin_rs_consensus::block_subsidy(100, Network::Regtest.subsidy_halving_interval())
                + 3_000
        );
        Ok(())
    }

    #[test]
    fn weight_size_and_sigop_limits_are_independent() -> Result<(), TestError> {
        let cases = [
            (
                1_u8,
                10_000_u64,
                100_u32,
                0_u32,
                limits(2_000, 4_000_000, 80_000),
            ),
            (
                2_u8,
                100_u64,
                10_000_u32,
                0_u32,
                limits(4_000_000, 2_000, 80_000),
            ),
            (
                3_u8,
                100_u64,
                100_u32,
                10_000_u32,
                limits(4_000_000, 4_000_000, 100),
            ),
        ];
        for (label, weight, size, sigop_cost, context) in cases {
            let mut pool = zero_fee_pool();
            insert_forged(
                &mut pool,
                tx(label, 1_000, None),
                Forged::new(5_000, weight, size).with_sigops(sigop_cost),
            )?;
            let fitting = tx(4, 1_000, None);
            let fitting_txid = fitting.txid();
            insert_forged(
                &mut pool,
                fitting,
                Forged::new(1_000, 100, 100).with_sigops(1),
            )?;
            let candidate = assemble_candidate(&context, &pool, PAYOUT)?;
            assert_eq!(selected(&candidate), vec![fitting_txid]);
        }
        Ok(())
    }

    #[test]
    fn unconfirmed_bip68_lock_skips_its_whole_chunk_only_while_csv_is_active()
    -> Result<(), TestError> {
        for (csv_active, expected) in [(true, 0), (false, 2)] {
            let mut pool = zero_fee_pool();
            let parent_tx = tx(1, 1_000, None);
            let parent_txid = parent_tx.txid();
            insert_forged(&mut pool, parent_tx, Forged::new(1_000, 400, 100))?;
            let mut child_tx = tx(2, 1_000, Some(parent_txid));
            child_tx.inputs[0].sequence = Sequence::from_consensus(1);
            insert_forged(&mut pool, child_tx, Forged::new(10_000, 400, 100))?;
            let candidate = assemble_candidate(
                &CandidateContext {
                    csv_active,
                    ..context()
                },
                &pool,
                PAYOUT,
            )?;
            assert_eq!(
                candidate.transactions.len(),
                expected,
                "csv_active={csv_active} must select {expected} transactions"
            );
        }
        Ok(())
    }

    #[test]
    fn exact_resource_limits_accept_dependency_closed_package() -> Result<(), TestError> {
        let empty = zero_fee_pool();
        let reservation = assemble_candidate(&context(), &empty, PAYOUT)?;

        let parent_txid = tx(1, 1_000, None).txid();
        let child_txid = tx(2, 1_000, Some(parent_txid)).txid();
        let exact_limits = limits(
            reservation.weight + 100,
            serialized_size(&reservation) + 100,
            total_sigop_cost(&reservation) + 10,
        );

        let mut pool = zero_fee_pool();
        insert_forged(
            &mut pool,
            tx(1, 1_000, None),
            Forged::new(1_000, 40, 40).with_vsize(40).with_sigops(4),
        )?;
        insert_forged(
            &mut pool,
            tx(2, 1_000, Some(parent_txid)),
            Forged::new(10_000, 60, 60).with_vsize(60).with_sigops(6),
        )?;
        let exact = assemble_candidate(&exact_limits, &pool, PAYOUT)?;
        assert_eq!(selected(&exact), vec![parent_txid, child_txid]);
        assert_eq!(exact.weight, exact_limits.max_weight);

        for (weight, size, sigop_cost) in [(61_u64, 60_u32, 6_u32), (60, 61, 6), (60, 60, 7)] {
            let mut over = zero_fee_pool();
            insert_forged(
                &mut over,
                tx(1, 1_000, None),
                Forged::new(1_000, 40, 40).with_vsize(40).with_sigops(4),
            )?;
            insert_forged(
                &mut over,
                tx(2, 1_000, Some(parent_txid)),
                Forged::new(10_000, weight, size)
                    .with_vsize(60)
                    .with_sigops(sigop_cost),
            )?;
            let candidate = assemble_candidate(&exact_limits, &over, PAYOUT)?;
            assert_eq!(
                selected(&candidate),
                vec![parent_txid],
                "one excess unit must skip the whole chunk and fill the tail with its parent prefix"
            );
        }
        Ok(())
    }

    #[test]
    fn coinbase_reservation_accepts_exact_limits_and_rejects_one_over() -> Result<(), TestError> {
        let payout = vec![0xac];
        let empty = zero_fee_pool();
        let reservation = assemble_candidate(&context(), &empty, &payout)?;
        assert!(reservation.weight > 0);
        assert!(serialized_size(&reservation) > 0);
        assert!(total_sigop_cost(&reservation) > 0);

        let exact_limits = limits(
            reservation.weight,
            serialized_size(&reservation),
            total_sigop_cost(&reservation),
        );
        let exact = assemble_candidate(&exact_limits, &empty, &payout)?;
        assert_eq!(exact.weight, exact_limits.max_weight);

        let one_over = [
            (
                "weight",
                limits(
                    reservation.weight - 1,
                    serialized_size(&reservation),
                    total_sigop_cost(&reservation),
                ),
            ),
            (
                "size",
                limits(
                    reservation.weight,
                    serialized_size(&reservation) - 1,
                    total_sigop_cost(&reservation),
                ),
            ),
            (
                "sigops",
                limits(
                    reservation.weight,
                    serialized_size(&reservation),
                    total_sigop_cost(&reservation) - 1,
                ),
            ),
        ];
        for (field, context) in one_over {
            assert!(matches!(
                assemble_candidate(&context, &empty, &payout),
                Err(MiningError::CapacityExhausted { field: actual }) if actual == field
            ));
        }
        Ok(())
    }

    #[test]
    fn non_final_packages_are_skipped() -> Result<(), TestError> {
        let mut non_final = tx(2, 1_000, None);
        non_final.lock_time = LockTime::from_consensus(500_000_100);
        for input in &mut non_final.inputs {
            input.sequence = Sequence::ZERO;
        }

        let mut pool = zero_fee_pool();
        insert_forged(&mut pool, non_final, Forged::new(9_000, 400, 100))?;
        insert_forged(&mut pool, tx(1, 1_000, None), Forged::new(1_000, 400, 100))?;
        let candidate = assemble_candidate(
            &CandidateContext {
                locktime_cutoff: 500_000_000,
                ..context()
            },
            &pool,
            PAYOUT,
        )?;
        assert_eq!(candidate.transactions.len(), 1);
        assert_eq!(selected_fees(&candidate), 1_000);
        Ok(())
    }

    #[test]
    fn oversized_residual_package_is_skipped_atomically() -> Result<(), TestError> {
        let parent_txid = tx(1, 1_000, None).txid();
        let mut child_tx = tx(2, 1_000, Some(parent_txid));
        child_tx.lock_time = LockTime::ZERO;
        let other_txid = tx(3, 1_000, None).txid();

        let mut pool = zero_fee_pool();
        insert_forged(&mut pool, tx(1, 1_000, None), Forged::new(100, 99_600, 100))?;
        insert_forged(&mut pool, child_tx, Forged::new(10_000, 20_000, 100))?;
        insert_forged(&mut pool, tx(3, 1_000, None), Forged::new(1_000, 400, 100))?;

        let candidate = assemble_candidate(&limits(100_000, 4_000_000, 80_000), &pool, PAYOUT)?;
        assert_eq!(selected(&candidate), vec![other_txid]);
        Ok(())
    }

    #[test]
    fn stops_candidate_package_construction_once_a_positive_dimension_is_full()
    -> Result<(), TestError> {
        let empty = zero_fee_pool();
        let reservation = assemble_candidate(&context(), &empty, PAYOUT)?;
        for context in [
            limits(reservation.weight + 1_000, 4_000_000, 80_000),
            limits(4_000_000, serialized_size(&reservation) + 1_000, 80_000),
        ] {
            let mut pool = zero_fee_pool();
            insert_forged(
                &mut pool,
                tx(1, 1_000, None),
                Forged::new(5_000_000, 1_000, 1_000).with_vsize(1_000),
            )?;
            insert_forged(
                &mut pool,
                tx(2, 1_000, None),
                Forged::new(4_000, 10, 10).with_vsize(10),
            )?;
            let candidate = assemble_candidate(&context, &pool, PAYOUT)?;
            assert_eq!(candidate.transactions.len(), 1);
            assert_eq!(candidate.transactions[0].fee, 5_000_000);
        }
        Ok(())
    }

    #[test]
    fn transaction_count_reservation_rejects_zero_size_capacity() {
        let pool = zero_fee_pool();
        assert!(matches!(
            assemble_candidate(&limits(4_000_000, 0, 80_000), &pool, PAYOUT),
            Err(MiningError::CapacityExhausted { field: actual }) if actual == "size"
        ));
    }

    fn consistent(fee: u64, weight: u64) -> Forged {
        let vsize = u32::try_from(weight.div_ceil(4)).expect("test weight fits vsize");
        Forged::new(fee, weight, vsize).with_vsize(vsize)
    }

    fn compact_len(total: usize) -> u64 {
        if total < 253 {
            1
        } else if total < 65_536 {
            3
        } else if total < 4_294_967_296 {
            5
        } else {
            9
        }
    }

    fn chunk_has_missing_ancestor(chunk: &ChunkView<'_>, selected: &HashSet<EntryId>) -> bool {
        for member in chunk.members {
            for parent in chunk.parents_of(*member) {
                if !selected.contains(&parent) && !chunk.members.contains(&parent) {
                    return true;
                }
            }
        }
        false
    }

    fn whole_chunk_oracle_fees(
        pool: &Mempool,
        ctx: &CandidateContext,
        res_weight: u64,
        res_size: u64,
        res_sigops: u64,
    ) -> u64 {
        let mut selected: HashSet<EntryId> = HashSet::new();
        let mut ordered_len = 0_usize;
        let mut used_weight = res_weight;
        let mut used_size = res_size;
        let mut used_sigops = res_sigops;
        let mut fees = 0_u64;
        for chunk in pool.chunks_by_feerate() {
            let vsize = chunk.charged_weight.div_ceil(4);
            if vsize == 0 {
                break;
            }
            let rate = (chunk.modified_fee * 1_000).div_euclid(i128::from(vsize));
            if rate < 1 {
                break;
            }
            if chunk_has_missing_ancestor(&chunk, &selected) {
                continue;
            }
            let mut sum_weight = 0_u64;
            let mut sum_size = 0_u64;
            let mut sum_sigops = 0_u64;
            let mut sum_fees = 0_u64;
            for (_, entry) in chunk.entries() {
                sum_weight = sum_weight.saturating_add(entry.weight);
                sum_size = sum_size.saturating_add(u64::from(entry.size));
                sum_sigops = sum_sigops.saturating_add(u64::from(entry.sigop_cost));
                sum_fees = sum_fees.saturating_add(entry.fee);
            }
            let next_len = ordered_len.saturating_add(chunk.len());
            let growth = compact_len(1_usize.saturating_add(next_len))
                .saturating_sub(compact_len(1_usize.saturating_add(ordered_len)));
            let next_weight = used_weight
                .saturating_add(sum_weight)
                .saturating_add(growth.saturating_mul(4));
            let next_size = used_size.saturating_add(sum_size).saturating_add(growth);
            let next_sigops = used_sigops.saturating_add(sum_sigops);
            if next_weight > ctx.max_weight
                || next_size > ctx.max_size
                || next_sigops > ctx.max_sigops
            {
                continue;
            }
            for member in chunk.members {
                selected.insert(*member);
            }
            ordered_len = next_len;
            used_weight = next_weight;
            used_size = next_size;
            used_sigops = next_sigops;
            fees = fees.saturating_add(sum_fees);
        }
        fees
    }

    fn candidate_positions(candidate: &Candidate) -> HashMap<Txid, usize> {
        let mut positions = HashMap::new();
        for (index, tx) in candidate.transactions.iter().enumerate() {
            positions.insert(tx.txid, index);
        }
        positions
    }

    #[test]
    fn negative_modified_fee_standalone_chunk_is_excluded_while_same_size_positive_is_included()
    -> Result<(), TestError> {
        let mut pool = zero_fee_pool();
        let negative = tx(10, 1_000, None);
        let negative_txid = negative.txid();
        insert_forged(&mut pool, negative, consistent(5_000, 400))?;
        let positive = tx(11, 1_000, None);
        let positive_txid = positive.txid();
        insert_forged(&mut pool, positive, consistent(5_000, 400))?;
        pool.prioritise(negative_txid, -10_000)?;

        let candidate = assemble_candidate(&context(), &pool, PAYOUT)?;
        assert_eq!(selected(&candidate), vec![positive_txid]);
        assert_eq!(selected_fees(&candidate), 5_000);
        Ok(())
    }

    #[test]
    fn negative_modified_fee_chunk_is_excluded_as_a_whole() -> Result<(), TestError> {
        let parent_txid = tx(12, 1_000, None).txid();
        let child_txid = tx(13, 1_000, Some(parent_txid)).txid();

        let mut negative = zero_fee_pool();
        insert_forged(&mut negative, tx(12, 1_000, None), consistent(1_000, 400))?;
        insert_forged(
            &mut negative,
            tx(13, 1_000, Some(parent_txid)),
            consistent(1_000, 400),
        )?;
        negative.prioritise(parent_txid, -5_000)?;
        let excluded = assemble_candidate(&context(), &negative, PAYOUT)?;
        assert!(
            excluded.transactions.is_empty(),
            "negative aggregate chunk must be absent"
        );

        let mut positive = zero_fee_pool();
        insert_forged(&mut positive, tx(12, 1_000, None), consistent(1_000, 400))?;
        insert_forged(
            &mut positive,
            tx(13, 1_000, Some(parent_txid)),
            consistent(1_000, 400),
        )?;
        let included = assemble_candidate(&context(), &positive, PAYOUT)?;
        assert_eq!(selected(&included), vec![parent_txid, child_txid]);
        Ok(())
    }

    #[test]
    fn zero_fee_parent_is_rescued_by_child_aggregate() -> Result<(), TestError> {
        let parent_txid = tx(14, 1_000, None).txid();
        let child_txid = tx(15, 1_000, Some(parent_txid)).txid();

        let mut alone = zero_fee_pool();
        insert_forged(&mut alone, tx(14, 1_000, None), consistent(0, 400))?;
        let excluded = assemble_candidate(&context(), &alone, PAYOUT)?;
        assert!(
            excluded.transactions.is_empty(),
            "zero-fee standalone chunk must be absent"
        );

        let mut rescued = zero_fee_pool();
        insert_forged(&mut rescued, tx(14, 1_000, None), consistent(0, 400))?;
        insert_forged(
            &mut rescued,
            tx(15, 1_000, Some(parent_txid)),
            consistent(5_000, 400),
        )?;
        let candidate = assemble_candidate(&context(), &rescued, PAYOUT)?;
        assert_eq!(selected(&candidate), vec![parent_txid, child_txid]);
        assert_eq!(selected_fees(&candidate), 5_000);
        Ok(())
    }

    #[test]
    fn negative_modified_parent_is_rescued_by_child_fees() -> Result<(), TestError> {
        let parent_txid = tx(16, 1_000, None).txid();
        let child_txid = tx(17, 1_000, Some(parent_txid)).txid();

        let mut alone = zero_fee_pool();
        insert_forged(&mut alone, tx(16, 1_000, None), consistent(1_000, 400))?;
        alone.prioritise(parent_txid, -2_000)?;
        let excluded = assemble_candidate(&context(), &alone, PAYOUT)?;
        assert!(
            excluded.transactions.is_empty(),
            "negative standalone parent must be absent"
        );

        let mut rescued = zero_fee_pool();
        insert_forged(&mut rescued, tx(16, 1_000, None), consistent(1_000, 400))?;
        insert_forged(
            &mut rescued,
            tx(17, 1_000, Some(parent_txid)),
            consistent(10_000, 400),
        )?;
        rescued.prioritise(parent_txid, -2_000)?;
        let candidate = assemble_candidate(&context(), &rescued, PAYOUT)?;
        assert_eq!(selected(&candidate), vec![parent_txid, child_txid]);
        assert_eq!(selected_fees(&candidate), 11_000);
        Ok(())
    }

    #[test]
    fn tail_fills_weight_with_prefix_of_skipped_chunk() -> Result<(), TestError> {
        let empty = zero_fee_pool();
        let reservation = assemble_candidate(&context(), &empty, PAYOUT)?;
        let ctx = limits(reservation.weight + 1_000, 4_000_000, 80_000);

        let parent_txid = tx(18, 1_000, None).txid();
        let mut pool = zero_fee_pool();
        insert_forged(&mut pool, tx(18, 1_000, None), consistent(10_000, 600))?;
        insert_forged(
            &mut pool,
            tx(19, 1_000, Some(parent_txid)),
            consistent(10_000, 600),
        )?;

        let candidate = assemble_candidate(&ctx, &pool, PAYOUT)?;
        assert_eq!(selected(&candidate), vec![parent_txid]);
        assert_eq!(selected_fees(&candidate), 10_000);
        assert_eq!(candidate.weight, reservation.weight + 600);
        Ok(())
    }

    #[test]
    fn tail_prefix_rate_uses_exact_charged_weight_not_summed_vsize() -> Result<(), TestError> {
        let empty = zero_fee_pool();
        let reservation = assemble_candidate(&context(), &empty, PAYOUT)?;
        let ctx = limits(reservation.weight + 5_000, 4_000_000, 80_000);

        let parent_txid = tx(20, 1_000, None).txid();
        let middle_txid = tx(21, 1_000, Some(parent_txid)).txid();
        let mut pool = zero_fee_pool();
        insert_forged(&mut pool, tx(20, 1_000, None), consistent(0, 1_997))?;
        insert_forged(
            &mut pool,
            tx(21, 1_000, Some(parent_txid)),
            consistent(1, 2_001),
        )?;
        insert_forged(
            &mut pool,
            tx(22, 1_000, Some(middle_txid)),
            consistent(10_000, 5_000),
        )?;

        let candidate = assemble_candidate(&ctx, &pool, PAYOUT)?;
        assert_eq!(selected(&candidate), vec![parent_txid, middle_txid]);
        assert_eq!(selected_fees(&candidate), 1);
        Ok(())
    }

    #[test]
    fn tail_skips_child_when_parent_prefix_cannot_fit() -> Result<(), TestError> {
        let empty = zero_fee_pool();
        let reservation = assemble_candidate(&context(), &empty, PAYOUT)?;
        let ctx = limits(reservation.weight + 1_000, 4_000_000, 80_000);

        let parent_txid = tx(30, 1_000, None).txid();
        let mut pool = zero_fee_pool();
        insert_forged(&mut pool, tx(30, 1_000, None), consistent(20_000, 1_200))?;
        insert_forged(
            &mut pool,
            tx(31, 1_000, Some(parent_txid)),
            consistent(5_000, 400),
        )?;

        let candidate = assemble_candidate(&ctx, &pool, PAYOUT)?;
        assert!(
            candidate.transactions.is_empty(),
            "child must stay unavailable when its parent prefix cannot fit"
        );
        Ok(())
    }

    #[test]
    fn tail_does_not_rescue_prefix_from_non_final_chunk() -> Result<(), TestError> {
        let parent_txid = tx(40, 1_000, None).txid();
        let mut child = tx(41, 1_000, Some(parent_txid));
        child.lock_time = LockTime::from_consensus(500_000_100);
        for input in &mut child.inputs {
            input.sequence = Sequence::ZERO;
        }

        let mut pool = zero_fee_pool();
        insert_forged(&mut pool, tx(40, 1_000, None), consistent(1_000, 400))?;
        insert_forged(&mut pool, child, consistent(10_000, 400))?;
        let candidate = assemble_candidate(
            &CandidateContext {
                locktime_cutoff: 500_000_000,
                ..context()
            },
            &pool,
            PAYOUT,
        )?;
        assert!(
            candidate.transactions.is_empty(),
            "non-final chunk must stay skipped whole, without tail rescue"
        );
        Ok(())
    }

    fn policy_pareto_cases() -> u32 {
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(1024)
    }

    proptest! {
    #![proptest_config(proptest::test_runner::Config {
        failure_persistence: Some(std::boxed::Box::new(
            proptest::test_runner::FileFailurePersistence::Direct(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/serving/regressions/tests.txt"
            )),
        )),
        ..(ProptestConfig {
            cases: policy_pareto_cases(),
            ..ProptestConfig::default()
        })
    })]

        #[test]
        fn independent_selection_is_deterministic(
            fees in prop::collection::vec(
                prop_oneof![
                    6 => 1_000_u64..50_000,
                    1 => Just(0_u64),
                    1 => Just(2_u64.pow(50)),
                    1 => Just(1_u64),
                ],
                1..30,
            ),
            weights in prop::collection::vec(
                prop_oneof![
                    6 => Just(400_u64),
                    1 => prop_oneof![Just(512_u64), Just(1_000), Just(4_000), Just(16_000), Just(40_000), Just(64_000)],
                ],
                1..30,
            ),
        ) {
            let count = fees.len().min(weights.len());
            let mut pool = zero_fee_pool();
            for index in 0..count {
                let label = u8::try_from(index).expect("proptest vec is bounded");
                insert_forged(&mut pool, tx(label, 1_000, None), consistent(fees[index], weights[index]))
                    .expect("pool admits fixture");
            }
            let left = assemble_candidate(&context(), &pool, PAYOUT).expect("left assembly");
            let right = assemble_candidate(&context(), &pool, PAYOUT).expect("right assembly");
            assert_eq!(selected(&left), selected(&right));
            assert_eq!(selected_fees(&left), selected_fees(&right));
            assert_eq!(left.weight, right.weight);
            assert_eq!(
                left.into_unsolved_block()
                    .expect("assembly serializes")
                    .txs,
                right
                    .into_unsolved_block()
                    .expect("assembly serializes")
                    .txs
            );
            assert_eq!(total_sigop_cost(&left), total_sigop_cost(&right));
            assert_eq!(left.coinbase_value, right.coinbase_value);
        }

        #[test]
        fn tail_pass_never_loses_fees_and_preserves_invariants(
            inputs in prop::collection::vec(
                (
                    prop_oneof![0_u64..20_000, Just(0_u64), Just(2_u64.pow(50))],
                    prop_oneof![400_u64..2_000, Just(400_u64), Just(10_000_u64)],
                    0_usize..32,
                    prop_oneof![-5_000_i64..5_000, Just(i64::MIN), Just(i64::MAX), Just(0)],
                ),
                1..12,
            ),
        ) {
            let mut pool = zero_fee_pool();
            let mut txids: Vec<Txid> = Vec::new();
            let mut total_weight = 0_u64;
            for (index, (fee, weight, parent_slot, _delta)) in inputs.iter().enumerate() {
                let label = u8::try_from(index).expect("proptest pool is bounded");
                let parent = if index == 0 {
                    None
                } else {
                    let slot = parent_slot % (index + 1);
                    if slot == index {
                        None
                    } else {
                        Some(txids[slot % index])
                    }
                };
                let built = tx(label, 1_000, parent);
                txids.push(built.txid());
                total_weight = total_weight.saturating_add(*weight);
                insert_forged(&mut pool, built, consistent(*fee, *weight))
                    .expect("pool admits fixture");
            }
            for (index, (_, _, _, delta)) in inputs.iter().enumerate() {
                if *delta != 0 {
                    pool.prioritise(txids[index], *delta)
                        .expect("prioritise applies");
                }
            }

            let empty = zero_fee_pool();
            let reservation = assemble_candidate(&context(), &empty, PAYOUT)
                .expect("empty reservation assembles");
            let res_size = serialized_size(&reservation);
            let res_sigops = total_sigop_cost(&reservation);
            let ctx = limits(
                reservation.weight.saturating_add(total_weight / 2),
                4_000_000,
                80_000,
            );
            let candidate = assemble_candidate(&ctx, &pool, PAYOUT).expect("candidate assembles");
            let oracle = whole_chunk_oracle_fees(
                &pool,
                &ctx,
                reservation.weight,
                res_size,
                res_sigops,
            );
            prop_assert!(
                selected_fees(&candidate) >= oracle,
                "tail fees {} must cover whole-chunk oracle {oracle}",
                selected_fees(&candidate)
            );
            prop_assert!(candidate.weight <= ctx.max_weight, "weight within limits");
            prop_assert!(
                serialized_size(&candidate) <= ctx.max_size,
                "size within limits"
            );
            prop_assert!(
                total_sigop_cost(&candidate) <= ctx.max_sigops,
                "sigops within limits"
            );
            let positions = candidate_positions(&candidate);
            let selected_set: HashSet<Txid> =
                positions.keys().copied().collect();
            for (index, entry) in candidate.transactions.iter().enumerate() {
                for input in &entry.tx.inputs {
                    let parent = input.previous_output.txid;
                    if pool.contains_txid(&parent) {
                        prop_assert!(
                            selected_set.contains(&parent),
                            "parent closure holds"
                        );
                        let parent_pos = positions[&parent];
                        prop_assert!(parent_pos < index, "topological order holds");
                    }
                }
                for dep in &entry.depends {
                    let dep_index = usize::try_from(*dep).expect("depends fits usize");
                    prop_assert!(dep_index <= index, "depends precedes child");
                }
            }
        }
    }

    #[test]
    fn projected_selection_treats_staged_parent_as_confirmed_for_bip68() -> Result<(), TestError> {
        let parent_tx = tx(1, 1_000, None);
        let parent_txid = parent_tx.txid();
        let mut child_tx = tx(2, 1_000, Some(parent_txid));
        child_tx.inputs[0].sequence = Sequence::from_consensus(1);
        let child_txid = child_tx.txid();

        let mut pool = zero_fee_pool();
        insert_forged(&mut pool, parent_tx.clone(), Forged::new(1_000, 400, 100))?;
        insert_forged(&mut pool, child_tx, Forged::new(10_000, 400, 100))?;

        let ctx = context();
        let live = select_template_body(&pool, &ctx, PAYOUT, None)?;
        assert!(
            live.transactions.is_empty(),
            "unconfirmed relative lock must skip the whole chunk live"
        );

        let block = Block {
            header: Header::default(),
            txs: vec![parent_tx],
        };
        let plan = pool.plan_block_removals(&bitcoin_rs_mempool::TransitionFacts::from_block(
            &bitcoin_rs_consensus::primitives::BlockImage::from_local(block.clone()),
        ));
        assert_eq!(plan.removals.len(), 1, "staged block must plan the parent");
        let projected = select_template_body_after(&pool, &plan, &ctx, PAYOUT)?;

        pool.remove_for_block(
            &bitcoin_rs_mempool::TransitionFacts::from_txs(&[&block.txs[0]]),
            ctx.height,
            0,
        );
        let actual = select_template_body(&pool, &ctx, PAYOUT, None)?;

        let projected_txids: Vec<Txid> = projected
            .transactions
            .iter()
            .map(|entry| entry.txid)
            .collect();
        let actual_txids: Vec<Txid> = actual.transactions.iter().map(|entry| entry.txid).collect();
        assert_eq!(projected_txids, vec![child_txid]);
        assert_eq!(actual_txids, vec![child_txid]);
        assert_eq!(projected.fees, actual.fees);
        assert_eq!(projected.weight, actual.weight);
        Ok(())
    }
}
#[cfg(feature = "pool")]
mod mining_pool_jobs {
    use crate::support::mining::TestError;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

    use crate::mining::pool::{
        BIP320_VERSION_MASK, BlockStatus, Extranonce, ExtranonceLayout, Job, JobBook,
        JobBookConfig, JobError, JobId, Session, SessionId, SessionOpenError, ShareClass,
        ShareError, ShareOutcome, ShareSubmission, ShareTarget, ShareWork, StaleReason,
        fetch_template,
    };
    use crate::mining::{
        BlockTemplate, BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult,
        BlockValidationResult, Candidate, CandidateContext, CoinbaseBudget, GenerateRequest,
        GeneratedBlock, MiningControl, MiningControlError, MiningError, MiningInfo,
        assemble_candidate,
    };
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_consensus::bip34::check_bip34;
    use bitcoin_rs_consensus::header_rules::compact_is_met_by;
    use bitcoin_rs_consensus::primitives::{
        Amount, BlockHash, BlockImage, CompactTarget, Hash256, Header, LockTime, Network, OutPoint,
        Script, Sequence, Tx, TxIn, TxOut, Txid, Witness, encode::consensus_bytes,
    };
    use bitcoin_rs_consensus::script::VerifyFlags;
    use bitcoin_rs_consensus::verify_block::verify_block_rules;
    use bitcoin_rs_mempool::{
        AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, Mempool, MempoolGateway,
        MempoolLimits, SubmitOutcome,
    };
    use compact_str::CompactString;
    use parking_lot::RwLock;
    use sha2::{Digest, Sha256};

    type TestResult = Result<(), TestError>;

    const PAYOUT: &[u8] = &[0x51];
    static ROLLED: [u8; 4] = [7, 7, 7, 7];

    fn context(height: u32, parent: u8) -> CandidateContext {
        CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[parent; 32]),
            height,
            version: 0x2000_0000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            min_time: 1_700_000_001,
            current_time: 1_700_000_600,
            locktime_cutoff: 1_700_000_000,
            staged_parent_mtp: 1_700_000_000,
            network: Network::Regtest,
            csv_active: true,
            segwit_active: true,
            max_weight: 4_000_000,
            max_size: 4_000_000,
            max_sigops: 80_000,
        }
    }

    const COIN_VALUE_SAT: u64 = 1_000_000;
    const ADMISSION_TIME: u64 = 1_700_000_000;

    fn wsh_true_script() -> Vec<u8> {
        let program: [u8; 32] = Sha256::digest([0x51_u8]).into();
        let mut script = vec![0x00, 0x20];
        script.extend_from_slice(&program);
        script
    }

    fn p2wpkh_script(label: u8) -> Vec<u8> {
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&[label; 20]);
        script
    }

    fn coin_outpoint(label: u8) -> OutPoint {
        let mut bytes = [0xc0_u8; 32];
        bytes[0] = label;
        OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), 0)
    }

    fn spend(label: u8) -> Tx {
        let mut tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: coin_outpoint(label),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![vec![0x51]]),
            }],
            outputs: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: Script::from_bytes(p2wpkh_script(label)),
            }],
            lock_time: LockTime::ZERO,
        };
        let fee = tx.vsize() * (2 + u64::from(label));
        tx.outputs[0].value = Amount::from_sat(COIN_VALUE_SAT - fee);
        tx
    }

    struct Coins(HashMap<OutPoint, TxOut>);

    impl AdmissionChain for Coins {
        fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
            let prevouts = tx
                .inputs
                .iter()
                .filter_map(|input| {
                    self.0
                        .get(&input.previous_output)
                        .map(|output| (input.previous_output, output.clone()))
                })
                .collect();
            Some(ChainAdmissionSnapshot {
                prevouts,
                height: 1,
                locktime_cutoff: 0,
                csv_active: false,
                next_block_script_flags: VerifyFlags::STANDARD,
                confirmed: false,
                ..ChainAdmissionSnapshot::default()
            })
        }
    }

    fn admitted_gateway(count: u8) -> Result<MempoolGateway, TestError> {
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            None,
        );
        let script = wsh_true_script();
        let coins = Coins(
            (1..=count)
                .map(|label| {
                    (
                        coin_outpoint(label),
                        TxOut {
                            value: Amount::from_sat(COIN_VALUE_SAT),
                            script_pubkey: Script::from_bytes(script.clone()),
                        },
                    )
                })
                .collect(),
        );
        for label in 1..=count {
            let outcome = gateway.submit_transaction(
                Arc::new(spend(label)),
                AdmissionOrigin::Rpc,
                None,
                ADMISSION_TIME,
                &coins,
            )?;
            if !matches!(outcome, SubmitOutcome::Committed(_)) {
                return Err(TestError::Uncommitted { label });
            }
        }
        Ok(gateway)
    }

    fn assemble(context: &CandidateContext, txs: u8) -> Result<Candidate, TestError> {
        let gateway = admitted_gateway(txs)?;
        let pool = gateway.read();
        Ok(assemble_candidate(context, &pool, PAYOUT)?)
    }

    fn build_candidate(height: u32, parent: u8, txs: u8) -> Result<Arc<Candidate>, TestError> {
        let candidate = assemble(&context(height, parent), txs)?;
        assert_eq!(candidate.transactions.len(), usize::from(txs));
        assert!(
            candidate
                .transactions
                .iter()
                .all(|entry| Hash256::from(entry.txid) != Hash256::from(entry.wtxid)),
            "fixture transactions carry witness data"
        );
        Ok(Arc::new(candidate))
    }

    fn budget() -> CoinbaseBudget {
        CoinbaseBudget {
            additional_size: 200,
            additional_sigops: 100,
        }
    }

    fn config() -> JobBookConfig {
        JobBookConfig {
            budget: budget(),
            extranonce: ExtranonceLayout::new(4, 4),
            coinbase_tag: b"/pool/".to_vec(),
            version_mask: BIP320_VERSION_MASK,
            ntime_forward_secs: 600,
            max_jobs: 8,
            max_sessions: 16,
            max_shares_per_job: 64,
        }
    }

    struct Fixture {
        book: JobBook,
        session: Session,
        job: Arc<Job>,
        candidate: Arc<Candidate>,
    }

    fn fixture(config: JobBookConfig, height: u32, txs: u8) -> Result<Fixture, TestError> {
        let candidate = build_candidate(height, 0xab, txs)?;
        let mut book = JobBook::new(config)?;
        let session = book.open_session()?;
        let installed = book.install(Arc::clone(&candidate), Vec::new())?;
        Ok(Fixture {
            book,
            session,
            job: installed.job,
            candidate,
        })
    }

    fn submit_for(session: &Session, job: &Job, nonce: u32) -> ShareSubmission<'static> {
        ShareSubmission {
            session: session.id(),
            job: job.id(),
            rolled_extranonce: &ROLLED,
            ntime: job.ntime(),
            nonce,
            version: job.version(),
        }
    }

    fn nonces(
        session: &Session,
        job: &Job,
        want_block: bool,
        count: usize,
    ) -> Result<Vec<u32>, TestError> {
        let extranonce = Extranonce {
            session: session.extranonce_prefix(),
            rolled: &ROLLED,
        };
        let mut found = Vec::new();
        for nonce in 0..=u32::MAX {
            let header = job.header(extranonce, job.ntime(), job.version(), nonce)?;
            let hash = Hash256::from(header.compute_hash());
            if compact_is_met_by(job.bits(), hash) == want_block {
                found.push(nonce);
                if found.len() == count {
                    return Ok(found);
                }
            }
        }
        Err("nonce space exhausted".into())
    }

    fn header_hash(session: &Session, job: &Job, nonce: u32) -> Result<Hash256, TestError> {
        let extranonce = Extranonce {
            session: session.extranonce_prefix(),
            rolled: &ROLLED,
        };
        let header = job.header(extranonce, job.ntime(), job.version(), nonce)?;
        Ok(Hash256::from(header.compute_hash()))
    }

    fn easy() -> Result<ShareTarget, JobError> {
        ShareTarget::from_le_bytes([0xff; 32])
    }

    fn tiny_target_bytes() -> [u8; 32] {
        let mut value = [0_u8; 32];
        value[0] = 1;
        value
    }

    fn minus_one(mut little_endian: [u8; 32]) -> [u8; 32] {
        for byte in &mut little_endian {
            if *byte == 0 {
                *byte = 0xff;
            } else {
                *byte -= 1;
                break;
            }
        }
        little_endian
    }

    #[test]
    fn branch_root_equals_node_merkle_root_for_every_tree_shape() -> TestResult {
        let mut plain = config();
        plain.extranonce = ExtranonceLayout::new(0, 0);
        plain.coinbase_tag = Vec::new();
        plain.max_sessions = 1;
        for txs in [0_u8, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17] {
            let candidate = build_candidate(100, 0xab, txs)?;
            let mut book = JobBook::new(plain.clone())?;
            let installed = book.install(Arc::clone(&candidate), Vec::new())?;
            let expected = candidate.into_unsolved_block()?.header.merkle_root;
            let empty = Extranonce {
                session: &[],
                rolled: &[],
            };
            assert_eq!(
                installed.job.merkle_root(empty)?,
                expected,
                "{txs} transactions"
            );
            let leaves = usize::from(txs) + 1;
            let depth = usize::try_from((leaves - 1).bit_width())?;
            assert_eq!(
                installed.job.merkle_branch().len(),
                depth,
                "{txs} transactions"
            );
        }
        Ok(())
    }

    #[test]
    fn coinbase_split_reproduces_the_txid_serialization() -> TestResult {
        let candidate = build_candidate(800_000, 0xab, 3)?;
        let mut book = JobBook::new(config())?;
        let session = book.open_session()?;
        let installed = book.install(Arc::clone(&candidate), Vec::new())?;
        let job = &installed.job;
        let rolled = [1_u8, 2, 3, 4];
        let extranonce = Extranonce {
            session: session.extranonce_prefix(),
            rolled: &rolled,
        };

        let base = candidate.coinbase.inputs[0].script_sig.as_bytes().to_vec();
        let mut script = base.clone();
        script.extend_from_slice(b"/pool/");
        script.extend_from_slice(session.extranonce_prefix());
        script.extend_from_slice(&rolled);
        let mut expected = candidate.coinbase.clone();
        expected.inputs[0].script_sig = Script::from_bytes(script);
        check_bip34(800_000, expected.inputs[0].script_sig.as_bytes())?;

        assert_eq!(job.coinbase_txid(extranonce)?, expected.txid());
        assert_eq!(job.coinbase_prefix().len(), 42 + base.len() + 6);

        let mut stripped = expected.clone();
        stripped.inputs[0].witness = Witness::new();
        let mut joined = job.coinbase_prefix().to_vec();
        joined.extend_from_slice(session.extranonce_prefix());
        joined.extend_from_slice(&rolled);
        joined.extend_from_slice(job.coinbase_suffix());
        assert_eq!(joined, consensus_bytes(&stripped));

        let other = [9_u8, 9, 9, 9];
        assert_ne!(
            job.coinbase_txid(extranonce)?,
            job.coinbase_txid(Extranonce {
                session: session.extranonce_prefix(),
                rolled: &other,
            })?
        );
        Ok(())
    }

    #[test]
    fn block_candidate_passes_consensus_and_reproduces_the_share() -> TestResult {
        let mut fx = fixture(config(), 100, 3)?;
        let nonce = nonces(&fx.session, &fx.job, true, 1)?[0];
        let submission = submit_for(&fx.session, &fx.job, nonce);
        let target = ShareTarget::from_pool_difficulty(1)?;

        let ShareOutcome::Block(found) = fx.book.validate(&submission, &target)? else {
            return Err("a network-target hash must classify as a block".into());
        };
        assert_eq!(found.share.class, ShareClass::Block);
        verify_block_rules(&found.block)?;
        assert_eq!(found.raw, consensus_bytes(&found.block));
        assert_eq!(found.block.block_hash(), found.share.hash);
        assert!(compact_is_met_by(
            fx.candidate.bits,
            Hash256::from(found.share.hash)
        ));
        assert_eq!(found.block.txs.len(), 4);
        assert_eq!(found.coinbase_txid, found.block.txs[0].txid());
        assert_eq!(found.coinbase_value, fx.candidate.coinbase_value);
        let paid: u64 = found.block.txs[0]
            .outputs
            .iter()
            .map(|output| output.value.to_sat())
            .sum();
        assert_eq!(paid, fx.candidate.coinbase_value);
        assert!(found.block.weight() <= fx.candidate.max_weight);
        let network = ShareTarget::from_compact(fx.job.bits())?;
        assert_eq!(found.share.target, target);
        assert_eq!(found.share.work, network.work());
        assert_eq!(found.share.height, 100);
        assert_eq!(found.share.job, fx.job.id());

        let mut extranonce = fx.session.extranonce_prefix().to_vec();
        extranonce.extend_from_slice(&ROLLED);
        assert_eq!(found.share.extranonce, extranonce);
        let script_sig = found.block.txs[0].inputs[0].script_sig.as_bytes();
        assert_eq!(
            &script_sig[2..],
            [b"/pool/".as_slice(), extranonce.as_slice()]
                .concat()
                .as_slice()
        );

        let replay = fx.book.validate(&submission, &target);
        assert!(
            matches!(replay, Err(ShareError::Duplicate { first_job, .. }) if first_job == fx.job.id())
        );
        Ok(())
    }

    #[test]
    fn unburn_releases_duplicate_key_for_retry() -> TestResult {
        let mut fx = fixture(config(), 100, 2)?;
        let target = easy()?;
        let job = Arc::clone(&fx.job);
        let first = fx
            .book
            .validate(&submit_for(&fx.session, &job, 41), &target)?;
        let hash = first.share().hash;
        let replay = fx
            .book
            .validate(&submit_for(&fx.session, &job, 41), &target);
        assert!(
            matches!(replay, Err(ShareError::Duplicate { first_job, .. }) if first_job == job.id())
        );
        assert!(
            !fx.book
                .unburn(&BlockHash::from(Hash256::from_le_bytes(&[0xcc; 32])))
        );
        assert!(fx.book.unburn(&hash));
        assert!(!fx.book.unburn(&hash));
        let retry = fx
            .book
            .validate(&submit_for(&fx.session, &job, 41), &target)?;
        assert_eq!(retry.share().hash, hash);
        let replay = fx
            .book
            .validate(&submit_for(&fx.session, &job, 41), &target);
        assert!(
            matches!(replay, Err(ShareError::Duplicate { first_job, .. }) if first_job == job.id())
        );
        Ok(())
    }

    #[test]
    fn scriptsig_may_grow_to_exactly_the_consensus_limit() -> TestResult {
        let mut wide = config();
        wide.extranonce = ExtranonceLayout::new(1, 95);
        wide.coinbase_tag = Vec::new();
        wide.max_sessions = 4;
        let candidate = build_candidate(800_000, 0xab, 1)?;
        let mut book = JobBook::new(wide.clone())?;
        let session = book.open_session()?;
        let installed = book.install(Arc::clone(&candidate), Vec::new())?;
        let rolled = [0x00_u8; 95];
        let extranonce = Extranonce {
            session: session.extranonce_prefix(),
            rolled: &rolled,
        };
        let mut nonce = 0_u32;
        loop {
            let header = installed.job.header(
                extranonce,
                installed.job.ntime(),
                installed.job.version(),
                nonce,
            )?;
            if compact_is_met_by(installed.job.bits(), Hash256::from(header.compute_hash())) {
                break;
            }
            nonce += 1;
        }
        let submission = ShareSubmission {
            session: session.id(),
            job: installed.job.id(),
            rolled_extranonce: &rolled,
            ntime: installed.job.ntime(),
            nonce,
            version: installed.job.version(),
        };
        let ShareOutcome::Block(found) = book.validate(&submission, &easy()?)? else {
            return Err("expected a block".into());
        };
        assert_eq!(found.block.txs[0].inputs[0].script_sig.len(), 100);
        verify_block_rules(&found.block)?;

        wide.extranonce = ExtranonceLayout::new(1, 96);
        let mut over = JobBook::new(wide)?;
        assert_eq!(
            over.install(candidate, Vec::new()).err(),
            Some(JobError::ExtranonceExceedsScriptSig {
                room: 96,
                needed: 97
            })
        );
        Ok(())
    }

    #[test]
    fn share_classes_and_target_boundaries() -> TestResult {
        let probe = fixture(config(), 100, 3)?;
        let share_nonce = nonces(&probe.session, &probe.job, false, 1)?[0];
        let block_nonce = nonces(&probe.session, &probe.job, true, 1)?[0];
        let hash = header_hash(&probe.session, &probe.job, share_nonce)?;

        let mut fx = fixture(config(), 100, 3)?;
        let outcome = fx
            .book
            .validate(&submit_for(&fx.session, &fx.job, share_nonce), &easy()?)?;
        let ShareOutcome::Share(accepted) = outcome else {
            return Err("a hash above the network target is a share".into());
        };
        assert_eq!(accepted.class, ShareClass::Share);
        assert_eq!(accepted.hash, BlockHash::from(hash));
        assert_eq!(accepted.work.as_u128(), Some(1));
        assert_eq!(accepted.header.nonce, share_nonce);

        let mut fx = fixture(config(), 100, 3)?;
        let at_target = ShareTarget::from_le_bytes(hash.to_le_bytes())?;
        let outcome = fx
            .book
            .validate(&submit_for(&fx.session, &fx.job, share_nonce), &at_target)?;
        assert!(matches!(outcome, ShareOutcome::Share(_)));

        let mut fx = fixture(config(), 100, 3)?;
        let below = ShareTarget::from_le_bytes(minus_one(hash.to_le_bytes()))?;
        let verdict = fx
            .book
            .validate(&submit_for(&fx.session, &fx.job, share_nonce), &below);
        assert!(matches!(verdict, Err(ShareError::BelowTarget { .. })));

        let mut fx = fixture(config(), 100, 3)?;
        let tightest = ShareTarget::from_le_bytes(tiny_target_bytes())?;
        let verdict = fx
            .book
            .validate(&submit_for(&fx.session, &fx.job, block_nonce), &tightest)?;
        assert!(
            matches!(verdict, ShareOutcome::Block(_)),
            "network target takes precedence over the share target"
        );
        Ok(())
    }

    #[test]
    fn fallback_block_work_is_capped_at_the_network_target() -> TestResult {
        let mut fx = fixture(config(), 100, 3)?;
        let network = ShareTarget::from_compact(fx.job.bits())?;
        let harder = ShareTarget::from_le_bytes(tiny_target_bytes())?;
        let mut block_nonce = None;
        for candidate in nonces(&fx.session, &fx.job, true, 5)? {
            let hash = header_hash(&fx.session, &fx.job, candidate)?;
            if !harder.meets(hash) {
                block_nonce = Some((candidate, hash));
                break;
            }
        }
        let (nonce, hash) = block_nonce.ok_or("a fallback block nonce exists")?;
        assert!(compact_is_met_by(fx.job.bits(), hash));
        assert!(!harder.meets(hash));
        let ShareOutcome::Block(found) = fx
            .book
            .validate(&submit_for(&fx.session, &fx.job, nonce), &harder)?
        else {
            return Err("a network-valid hash from a harder channel target is a block".into());
        };
        assert_eq!(found.share.target, harder);
        assert_eq!(found.share.work, network.work());
        assert_ne!(found.share.work, harder.work());
        Ok(())
    }

    fn assert_malformed_session_and_job_inputs(
        book: &mut JobBook,
        session: &Session,
        job: &Arc<Job>,
        target: &ShareTarget,
    ) {
        let verdict = book.validate(
            &ShareSubmission {
                session: SessionId::new(999),
                ..submit_for(session, job, 0)
            },
            target,
        );
        assert_eq!(
            verdict.err(),
            Some(ShareError::UnknownSession(SessionId::new(999)))
        );
        for unknown in [JobId::new(0), JobId::new(77)] {
            let verdict = book.validate(
                &ShareSubmission {
                    job: unknown,
                    ..submit_for(session, job, 0)
                },
                target,
            );
            assert_eq!(verdict.err(), Some(ShareError::UnknownJob(unknown)));
        }

        let first = book.validate(&submit_for(session, job, 41), target);
        assert!(first.is_ok());
        let second = book.validate(&submit_for(session, job, 41), target);
        assert!(matches!(
            second,
            Err(ShareError::Duplicate { first_job, .. }) if first_job == job.id()
        ));

        assert!(book.close_session(session.id()));
        let verdict = book.validate(&submit_for(session, job, 42), target);
        assert_eq!(
            verdict.err(),
            Some(ShareError::UnknownSession(session.id()))
        );
    }

    #[test]
    fn malformed_shares_are_rejected_for_their_own_reason() -> TestResult {
        let mut fx = fixture(config(), 100, 2)?;
        let target = easy()?;
        let job = Arc::clone(&fx.job);

        let short = [1_u8, 2, 3];
        let verdict = fx.book.validate(
            &ShareSubmission {
                rolled_extranonce: &short,
                ..submit_for(&fx.session, &job, 0)
            },
            &target,
        );
        assert!(matches!(
            verdict,
            Err(ShareError::ExtranonceLength {
                expected: 4,
                actual: 3
            })
        ));

        let outside = job.version() ^ 0x0000_0001;
        let verdict = fx.book.validate(
            &ShareSubmission {
                version: outside,
                ..submit_for(&fx.session, &job, 0)
            },
            &target,
        );
        assert_eq!(
            verdict.err(),
            Some(ShareError::VersionOutsideMask {
                version: outside,
                job_version: job.version(),
                mask: BIP320_VERSION_MASK
            })
        );

        let rolled_version = job.version_from_rolled_bits(0x0000_2000)?;
        assert_eq!(rolled_version, job.version() | 0x0000_2000);
        assert!(
            fx.book
                .validate(
                    &ShareSubmission {
                        version: rolled_version,
                        ..submit_for(&fx.session, &job, 0)
                    },
                    &target
                )
                .is_ok()
        );
        assert!(matches!(
            job.version_from_rolled_bits(0x0000_0001),
            Err(ShareError::VersionOutsideMask { .. })
        ));

        let verdict = fx.book.validate(
            &ShareSubmission {
                ntime: job.min_ntime() - 1,
                ..submit_for(&fx.session, &job, 0)
            },
            &target,
        );
        assert_eq!(
            verdict.err(),
            Some(ShareError::TimeTooEarly {
                ntime: job.min_ntime() - 1,
                min_ntime: job.min_ntime()
            })
        );
        for edge in [job.min_ntime(), job.max_ntime()] {
            let verdict = fx.book.validate(
                &ShareSubmission {
                    ntime: edge,
                    ..submit_for(&fx.session, &job, 0)
                },
                &target,
            );
            assert!(verdict.is_ok(), "ntime {edge} is inside the window");
        }
        let verdict = fx.book.validate(
            &ShareSubmission {
                ntime: job.max_ntime() + 1,
                ..submit_for(&fx.session, &job, 0)
            },
            &target,
        );
        assert_eq!(
            verdict.err(),
            Some(ShareError::TimeTooLate {
                ntime: job.max_ntime() + 1,
                max_ntime: job.max_ntime()
            })
        );

        assert_malformed_session_and_job_inputs(&mut fx.book, &fx.session, &job, &target);
        Ok(())
    }

    #[test]
    fn rejected_input_cannot_fill_the_duplicate_set_and_capacity_never_refuses_a_block()
    -> TestResult {
        let mut tiny = config();
        tiny.max_shares_per_job = 1;
        let probe = fixture(tiny.clone(), 100, 1)?;
        let shares = nonces(&probe.session, &probe.job, false, 2)?;
        let block = nonces(&probe.session, &probe.job, true, 1)?[0];

        let mut fx = fixture(tiny, 100, 1)?;
        let tight = ShareTarget::from_le_bytes(tiny_target_bytes())?;
        for _ in 0..4 {
            let verdict = fx
                .book
                .validate(&submit_for(&fx.session, &fx.job, shares[0]), &tight);
            assert!(matches!(verdict, Err(ShareError::BelowTarget { .. })));
        }
        let target = easy()?;
        assert!(
            fx.book
                .validate(&submit_for(&fx.session, &fx.job, shares[0]), &target)
                .is_ok()
        );
        let verdict = fx
            .book
            .validate(&submit_for(&fx.session, &fx.job, shares[1]), &target);
        assert_eq!(
            verdict.err(),
            Some(ShareError::JobShareCapacity {
                job: fx.job.id(),
                capacity: 1
            })
        );
        let outcome = fx
            .book
            .validate(&submit_for(&fx.session, &fx.job, block), &target)?;
        assert!(matches!(outcome, ShareOutcome::Block(_)));
        Ok(())
    }

    #[test]
    fn block_candidate_at_job_capacity_is_remembered_as_duplicate_on_replay() -> TestResult {
        let mut tiny = config();
        tiny.max_shares_per_job = 1;
        let mut fx = fixture(tiny, 100, 1)?;
        let target = easy()?;
        let share = nonces(&fx.session, &fx.job, false, 1)?[0];
        fx.book
            .validate(&submit_for(&fx.session, &fx.job, share), &target)?;
        let block = nonces(&fx.session, &fx.job, true, 1)?[0];
        let outcome = fx
            .book
            .validate(&submit_for(&fx.session, &fx.job, block), &target)?;
        assert!(matches!(outcome, ShareOutcome::Block(_)));
        let replay = fx
            .book
            .validate(&submit_for(&fx.session, &fx.job, block), &target);
        assert!(
            matches!(replay, Err(ShareError::Duplicate { .. })),
            "a block accepted at capacity must be remembered: {replay:?}"
        );
        Ok(())
    }

    #[test]
    fn extra_outputs_are_funded_from_the_payout_and_stay_valid() -> TestResult {
        let candidate = build_candidate(100, 0xab, 2)?;
        let extra = vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![0x51, 0x51]),
        }];
        let mut book = JobBook::new(config())?;
        let session = book.open_session()?;
        let installed = book.install(Arc::clone(&candidate), extra.clone())?;
        assert_eq!(installed.job.extra_outputs(), extra.as_slice());
        let nonce = nonces(&session, &installed.job, true, 1)?[0];
        let ShareOutcome::Block(found) = book.validate(
            &submit_for(&session, &installed.job, nonce),
            &ShareTarget::from_pool_difficulty(1)?,
        )?
        else {
            return Err("expected a block".into());
        };
        verify_block_rules(&found.block)?;
        let outputs = &found.block.txs[0].outputs;
        assert_eq!(outputs.len(), 3);
        assert_eq!(outputs[0].value.to_sat(), candidate.coinbase_value - 1_000);
        assert_eq!(
            outputs[0].script_pubkey,
            candidate.coinbase.outputs[0].script_pubkey
        );
        assert_eq!(outputs[1], extra[0]);
        assert_eq!(outputs[2], candidate.coinbase.outputs[1]);
        let paid: u64 = outputs.iter().map(|output| output.value.to_sat()).sum();
        assert_eq!(paid, candidate.coinbase_value);
        Ok(())
    }

    #[test]
    fn out_of_budget_jobs_are_refused() -> TestResult {
        let candidate = build_candidate(100, 0xab, 1)?;
        let mut book = JobBook::new(config())?;

        let oversize = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::from_bytes(vec![0x51; 300]),
        }];
        assert_eq!(
            book.install(Arc::clone(&candidate), oversize).err(),
            Some(JobError::ExtraOutputsSize {
                used: 8 + 3 + 300,
                budget: 200
            })
        );

        let sigop_heavy = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::from_bytes(vec![0xac; 30]),
        }];
        assert!(matches!(
            book.install(Arc::clone(&candidate), sigop_heavy).err(),
            Some(JobError::ExtraOutputsSigops { used, budget: 100 }) if used > 100
        ));

        let overspend = vec![TxOut {
            value: Amount::from_sat(candidate.coinbase_value + 1),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }];
        assert_eq!(
            book.install(Arc::clone(&candidate), overspend).err(),
            Some(JobError::ExtraOutputsValue {
                extra: candidate.coinbase_value + 1,
                available: candidate.coinbase_value
            })
        );

        let roomy = build_candidate(100, 0xab, 0)?;
        let snug = assemble(
            &CandidateContext {
                max_weight: roomy.weight,
                ..context(100, 0xab)
            },
            0,
        )?;
        assert_eq!(
            book.install(Arc::new(snug), Vec::new()).err(),
            Some(JobError::Budget(MiningError::CapacityExhausted {
                field: "weight"
            }))
        );

        assert_eq!(book.current().map(|job| job.id()), None);
        Ok(())
    }

    #[test]
    fn sessions_get_unique_bounded_prefixes_and_reuse_oldest_freed_first() -> TestResult {
        let mut small = config();
        small.extranonce = ExtranonceLayout::new(1, 4);
        small.max_sessions = 3;
        let mut book = JobBook::new(small)?;
        let first = book.open_session()?;
        let second = book.open_session()?;
        let third = book.open_session()?;
        assert_eq!(first.extranonce_prefix(), &[0]);
        assert_eq!(second.extranonce_prefix(), &[1]);
        assert_eq!(third.extranonce_prefix(), &[2]);
        assert_eq!(
            book.open_session().err(),
            Some(SessionOpenError::Capacity { capacity: 3 })
        );
        assert!(book.close_session(second.id()));
        assert!(!book.close_session(second.id()));
        assert!(book.session(second.id()).is_none());
        let reopened = book.open_session()?;
        assert_eq!(reopened.extranonce_prefix(), &[1]);
        assert_ne!(reopened.id(), second.id());
        assert_eq!(book.session_count(), 3);

        let mut single = config();
        single.extranonce = ExtranonceLayout::new(0, 4);
        single.max_sessions = 1;
        let mut book = JobBook::new(single.clone())?;
        assert_eq!(book.open_session()?.extranonce_prefix(), &[0_u8; 0]);
        assert!(book.open_session().is_err());

        single.max_sessions = 2;
        assert!(matches!(
            JobBook::new(single).err(),
            Some(JobError::InvalidConfig(_))
        ));
        Ok(())
    }

    #[test]
    fn unusable_configurations_are_refused() {
        let broken = [
            JobBookConfig {
                max_jobs: 0,
                ..config()
            },
            JobBookConfig {
                max_sessions: 0,
                ..config()
            },
            JobBookConfig {
                max_shares_per_job: 0,
                ..config()
            },
            JobBookConfig {
                version_mask: 0x8000_0000,
                ..config()
            },
            JobBookConfig {
                ntime_forward_secs: 7_201,
                ..config()
            },
            JobBookConfig {
                extranonce: ExtranonceLayout::new(4, 90),
                ..config()
            },
        ];
        for candidate in broken {
            assert!(
                matches!(
                    JobBook::new(candidate).err(),
                    Some(JobError::InvalidConfig(_))
                ),
                "configuration must be refused"
            );
        }
    }

    #[test]
    fn install_reports_exact_parent_and_staleness_facts() -> TestResult {
        let mut book = JobBook::new(config())?;
        let session = book.open_session()?;
        let target = easy()?;

        let first = book.install(build_candidate(100, 1, 0)?, Vec::new())?;
        assert!(first.fresh && first.clean_jobs && !first.parent_changed);
        assert_eq!(first.invalidated.len(), 0);

        let unchanged = book.install(Arc::clone(first.job.candidate()), Vec::new())?;
        assert!(!unchanged.fresh && !unchanged.clean_jobs && !unchanged.parent_changed);
        assert!(Arc::ptr_eq(&unchanged.job, &first.job));

        let refreshed = book.install(build_candidate(100, 1, 1)?, Vec::new())?;
        assert!(refreshed.fresh && !refreshed.clean_jobs && !refreshed.parent_changed);
        assert_eq!(refreshed.invalidated.len(), 0);
        assert!(
            book.validate(&submit_for(&session, &first.job, 5), &target)
                .is_ok(),
            "a same-parent refresh does not stale earlier jobs"
        );

        let extended = book.install(build_candidate(101, 2, 0)?, Vec::new())?;
        assert!(extended.clean_jobs && extended.parent_changed);
        assert_eq!(
            extended.invalidated,
            vec![first.job.id(), refreshed.job.id()]
        );
        let verdict = book.validate(&submit_for(&session, &refreshed.job, 6), &target);
        assert_eq!(
            verdict.err(),
            Some(ShareError::Stale {
                job: refreshed.job.id(),
                reason: StaleReason::PreviousBlockChanged
            })
        );

        let competing = book.install(build_candidate(100, 3, 0)?, Vec::new())?;
        assert!(competing.clean_jobs && competing.parent_changed);
        assert_eq!(competing.invalidated, vec![extended.job.id()]);

        assert_eq!(book.invalidate_active(), vec![competing.job.id()]);
        assert!(book.current().is_none());
        let verdict = book.validate(&submit_for(&session, &competing.job, 7), &target);
        assert_eq!(
            verdict.err(),
            Some(ShareError::Stale {
                job: competing.job.id(),
                reason: StaleReason::Invalidated
            })
        );

        let resumed = book.install(build_candidate(100, 3, 1)?, Vec::new())?;
        assert!(resumed.clean_jobs && !resumed.parent_changed);
        assert_eq!(resumed.invalidated.len(), 0);

        let back = book.install(build_candidate(101, 1, 0)?, Vec::new())?;
        assert!(back.clean_jobs && back.parent_changed);
        let verdict = book.validate(&submit_for(&session, &first.job, 8), &target);
        assert!(
            matches!(verdict, Err(ShareError::Stale { .. })),
            "a stale job is never revived when its parent returns"
        );
        assert_eq!(book.current().map(|job| job.id()), Some(back.job.id()));
        Ok(())
    }

    #[test]
    fn retention_is_bounded_and_retired_jobs_are_stale() -> TestResult {
        let mut small = config();
        small.max_jobs = 2;
        let mut book = JobBook::new(small)?;
        let session = book.open_session()?;
        let first = book.install(build_candidate(100, 1, 0)?, Vec::new())?;
        let second = book.install(build_candidate(100, 1, 1)?, Vec::new())?;
        let third = book.install(build_candidate(100, 1, 2)?, Vec::new())?;
        assert!(book.job(first.job.id()).is_none());
        assert!(book.job(second.job.id()).is_some());
        assert!(book.job(third.job.id()).is_some());
        let target = easy()?;
        assert_eq!(
            book.validate(&submit_for(&session, &first.job, 1), &target)
                .err(),
            Some(ShareError::Stale {
                job: first.job.id(),
                reason: StaleReason::Retired
            })
        );
        assert!(
            book.validate(&submit_for(&session, &second.job, 1), &target)
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn pool_difficulty_targets_and_work_are_exact() -> TestResult {
        let one = ShareTarget::from_pool_difficulty(1)?;
        let mut expected = [0_u8; 32];
        expected[4] = 0xff;
        expected[5] = 0xff;
        assert_eq!(one.to_be_bytes(), expected);
        let mut little = expected;
        little.reverse();
        assert_eq!(one.to_le_bytes(), little);
        assert_eq!(ShareTarget::from_be_bytes(expected)?, one);
        assert_eq!(one.work().as_u128(), Some(4_295_032_833));

        let two = ShareTarget::from_pool_difficulty(2)?;
        let mut halved = [0_u8; 32];
        halved[4] = 0x7f;
        halved[5] = 0xff;
        halved[6] = 0x80;
        assert_eq!(two.to_be_bytes(), halved);
        assert!(two.work() > one.work());

        let half = ShareTarget::from_pool_difficulty_decimal("0.5")?;
        let mut doubled = [0_u8; 32];
        doubled[3] = 0x01;
        doubled[4] = 0xff;
        doubled[5] = 0xfe;
        assert_eq!(half.to_be_bytes(), doubled);
        assert_eq!(ShareTarget::from_pool_difficulty_ratio(1, 2)?, half);
        assert_eq!(ShareTarget::from_pool_difficulty_ratio(3, 6)?, half);
        assert_eq!(ShareTarget::from_pool_difficulty_decimal("2")?, two);
        assert_eq!(ShareTarget::from_pool_difficulty_decimal("2.000")?, two);
        assert_eq!(ShareTarget::from_pool_difficulty_decimal("2.")?, two);

        let everything = ShareTarget::from_le_bytes([0xff; 32])?;
        assert_eq!(
            ShareTarget::from_pool_difficulty_ratio(1, u64::MAX)?,
            everything
        );
        assert_eq!(everything.work().as_u128(), Some(1));
        let total = one
            .work()
            .checked_add(two.work())
            .and_then(ShareWork::as_u128);
        assert_eq!(
            total,
            one.work()
                .as_u128()
                .zip(two.work().as_u128())
                .map(|(a, b)| a + b)
        );

        assert_eq!(
            ShareTarget::from_le_bytes([0; 32]),
            Err(JobError::ZeroTarget)
        );
        assert_eq!(
            ShareTarget::from_pool_difficulty(0),
            Err(JobError::ZeroTarget)
        );
        assert_eq!(
            ShareTarget::from_pool_difficulty_ratio(1, 0),
            Err(JobError::ZeroTarget)
        );
        for zero in ["0", "0.0", "000.000"] {
            assert_eq!(
                ShareTarget::from_pool_difficulty_decimal(zero),
                Err(JobError::ZeroTarget),
                "{zero}"
            );
        }
        for malformed in [
            "",
            "-1",
            "1e3",
            ".5",
            "1.2.3",
            " 1",
            "12345678901234567890",
            "1,5",
        ] {
            assert_eq!(
                ShareTarget::from_pool_difficulty_decimal(malformed),
                Err(JobError::InvalidDifficulty),
                "{malformed:?}"
            );
        }
        Ok(())
    }

    struct RecordingControl {
        template: Option<BlockTemplate>,
        verdict: Mutex<Result<BlockValidationResult, MiningControlError>>,
        requests: Mutex<Vec<BlockTemplateRequest>>,
        submitted: Mutex<Vec<BlockImage>>,
    }

    impl RecordingControl {
        fn new(
            template: Option<BlockTemplate>,
            verdict: Result<BlockValidationResult, MiningControlError>,
        ) -> Self {
            Self {
                template,
                verdict: Mutex::new(verdict),
                requests: Mutex::new(Vec::new()),
                submitted: Mutex::new(Vec::new()),
            }
        }

        fn set_verdict(&self, verdict: Result<BlockValidationResult, MiningControlError>) {
            *lock(&self.verdict) = verdict;
        }
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn unused() -> MiningControlError {
        MiningControlError::Unavailable(CompactString::from("not used by these tests"))
    }

    impl MiningControl for RecordingControl {
        fn get_block_template(
            &self,
            request: BlockTemplateRequest,
        ) -> Result<BlockTemplateResult, MiningControlError> {
            lock(&self.requests).push(request);
            match &self.template {
                Some(template) => Ok(BlockTemplateResult::Template(template.clone())),
                None => Ok(BlockTemplateResult::Proposal(
                    BlockValidationResult::Accepted,
                )),
            }
        }

        fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
            Err(unused())
        }

        fn network_hash_ps(&self, _lookup: i64, _height: i64) -> Result<f64, MiningControlError> {
            Err(unused())
        }

        fn submit_block(
            &self,
            payload: BlockImage,
        ) -> Result<BlockValidationResult, MiningControlError> {
            lock(&self.submitted).push(payload);
            lock(&self.verdict).clone()
        }

        fn submit_header(&self, _header: Header) -> Result<(), MiningControlError> {
            Err(unused())
        }

        fn publish_generation(&self) {}

        fn publish_fee_delta_generation(&self, _fee_delta_sequence: u64) {}

        fn generate(
            &self,
            _request: GenerateRequest,
        ) -> Result<Vec<GeneratedBlock>, MiningControlError> {
            Err(unused())
        }
    }

    fn template_around(candidate: &Arc<Candidate>) -> BlockTemplate {
        BlockTemplate {
            candidate: Arc::clone(candidate),
            rules: Vec::new(),
            version_bits_available: Vec::new(),
            version_bits_required: 0,
            capabilities: Vec::new(),
            mutable: Vec::new(),
            submit_old: None,
            signet: None,
        }
    }

    #[test]
    fn found_blocks_reach_the_authoritative_submit_path_and_receipts_map_verdicts() -> TestResult {
        let mut fx = fixture(config(), 100, 2)?;
        let nonce = nonces(&fx.session, &fx.job, true, 1)?[0];
        let ShareOutcome::Block(found) = fx.book.validate(
            &submit_for(&fx.session, &fx.job, nonce),
            &ShareTarget::from_pool_difficulty(1)?,
        )?
        else {
            return Err("expected a block".into());
        };

        let control = RecordingControl::new(None, Ok(BlockValidationResult::Accepted));
        let receipt = found.submit(&control)?;
        assert_eq!(receipt.status(), BlockStatus::Applied);
        assert_eq!(receipt.hash, found.share.hash);
        assert_eq!(receipt.height, 100);
        assert_eq!(receipt.coinbase_txid, found.coinbase_txid);
        assert_eq!(receipt.coinbase_value, fx.candidate.coinbase_value);
        assert_eq!(receipt.session, fx.session.id());
        assert_eq!(receipt.job, fx.job.id());
        {
            let submitted = lock(&control.submitted);
            assert_eq!(submitted.len(), 1);
            assert_eq!(&submitted[0].materialize(), &found.block);
            assert_eq!(submitted[0].bytes().as_ref(), found.raw.as_slice());
        }

        let cases = [
            (BlockValidationResult::Duplicate, BlockStatus::Applied),
            (
                BlockValidationResult::DuplicateInvalid,
                BlockStatus::Rejected,
            ),
            (
                BlockValidationResult::Rejected(CompactString::from("bad-txnmrklroot")),
                BlockStatus::Rejected,
            ),
            (
                BlockValidationResult::Inconclusive,
                BlockStatus::Undetermined,
            ),
            (
                BlockValidationResult::DuplicateInconclusive,
                BlockStatus::Undetermined,
            ),
        ];
        for (verdict, status) in cases {
            control.set_verdict(Ok(verdict.clone()));
            let receipt = found.submit(&control)?;
            assert_eq!(receipt.result, verdict);
            assert_eq!(receipt.status(), status);
        }

        control.set_verdict(Err(unused()));
        assert_eq!(found.submit(&control).err(), Some(unused()));
        control.set_verdict(Ok(BlockValidationResult::Accepted));
        assert_eq!(found.submit(&control)?.status(), BlockStatus::Applied);
        Ok(())
    }

    #[test]
    fn templates_are_requested_with_the_declared_budget() -> TestResult {
        let candidate = build_candidate(100, 0xab, 1)?;
        let control = RecordingControl::new(
            Some(template_around(&candidate)),
            Ok(BlockValidationResult::Accepted),
        );
        let template = fetch_template(&control, budget(), Some("previous-generation"))?;
        assert!(Arc::ptr_eq(&template.candidate, &candidate));
        {
            let requests = lock(&control.requests);
            assert_eq!(requests.len(), 1);
            assert!(matches!(requests[0].mode, BlockTemplateMode::Template));
            assert_eq!(requests[0].coinbase_budget, Some(budget()));
            assert_eq!(
                requests[0].long_poll_id.as_deref(),
                Some("previous-generation")
            );
        }

        let proposal_only = RecordingControl::new(None, Ok(BlockValidationResult::Accepted));
        assert!(matches!(
            fetch_template(&proposal_only, budget(), None),
            Err(MiningControlError::Failed(_))
        ));
        Ok(())
    }

    #[test]
    fn accepted_block_retirement_makes_second_same_job_nonce_stale() -> TestResult {
        let mut fx = fixture(config(), 100, 2)?;
        let target = ShareTarget::from_pool_difficulty(1)?;
        let winning = nonces(&fx.session, &fx.job, true, 2)?;
        let outcome = fx
            .book
            .validate(&submit_for(&fx.session, &fx.job, winning[0]), &target)?;
        assert!(
            matches!(outcome, ShareOutcome::Block(_)),
            "first known winning nonce is accepted"
        );
        fx.book.invalidate_active();
        assert!(fx.book.current().is_none());
        let err = fx
            .book
            .validate(&submit_for(&fx.session, &fx.job, winning[1]), &target)
            .err();
        assert_eq!(
            err,
            Some(ShareError::Stale {
                job: fx.job.id(),
                reason: StaleReason::Invalidated
            }),
            "second winning nonce on the same job is stale and never resubmitted"
        );
        let replay = fx
            .book
            .validate(&submit_for(&fx.session, &fx.job, winning[0]), &target)
            .err();
        assert!(
            matches!(replay, Some(ShareError::Duplicate { .. })),
            "exact replay of an accepted share keeps duplicate identity, not stale"
        );
        let next = fx
            .book
            .install(build_candidate(101, 0xcd, 0)?, Vec::new())?;
        assert!(next.clean_jobs, "new parent job is fresh");
        let share = nonces(&fx.session, &next.job, false, 1)?[0];
        assert!(
            fx.book
                .validate(&submit_for(&fx.session, &next.job, share), &easy()?)
                .is_ok(),
            "new parent job accepts shares"
        );
        Ok(())
    }
}
#[cfg(feature = "pool")]
mod mining_pool_sv1 {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    use crate::mining::pool::stratum::sv1::{
        ConnectionLimiter, DifficultyPolicy, FrameError, LineBuffer, Observer, RefusalReason,
        Server, ServerConfig, ServerDeps, ServerEvent, SessionEnd, ShutdownReport,
        StaticAccountResolver, prevhash_from_wire, prevhash_to_wire, swap_words,
    };
    use crate::mining::pool::{
        AcceptedShare, Extranonce, ExtranonceLayout, FoundBlock, Job, JobBookConfig, PoolCore,
        RecordOutcome, ShareLedger,
    };
    use crate::mining::{
        BlockValidationResult, Candidate, CoinbaseBudget, FakeMiningControl, MiningControl,
        MiningControlError, STALE_PARENT_REASON, TemplateId,
    };
    use crate::support::mining::TestError;
    use bitcoin_rs_consensus::header_rules::compact_is_met_by;
    use bitcoin_rs_consensus::primitives::{
        Amount, CompactTarget, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
        Witness,
    };

    type TestResult = Result<(), TestError>;

    #[derive(Default)]
    struct TestLedger {
        shares: Mutex<Vec<(String, AcceptedShare)>>,
        blocks: Mutex<Vec<(String, FoundBlock)>>,
        fail_shares: Mutex<Option<usize>>,
        reject_shares: AtomicBool,
        share_calls: AtomicUsize,
    }

    impl TestLedger {
        fn disarm(&self) {
            *self
                .fail_shares
                .lock()
                .unwrap_or_else(|error| panic!("test operation failed: {error}")) = None;
        }

        fn armed_with_failures(count: usize) -> Self {
            Self {
                shares: Mutex::new(Vec::new()),
                blocks: Mutex::new(Vec::new()),
                fail_shares: Mutex::new(Some(count)),
                reject_shares: AtomicBool::new(false),
                share_calls: AtomicUsize::new(0),
            }
        }

        fn refuse_permanently(&self) {
            self.set_reject(true);
        }

        fn admit_again(&self) {
            self.set_reject(false);
        }

        fn set_reject(&self, reject: bool) {
            self.reject_shares.store(reject, Ordering::SeqCst);
        }

        fn recorded_shares(&self) -> Vec<AcceptedShare> {
            self.shares
                .lock()
                .unwrap_or_else(|error| panic!("test operation failed: {error}"))
                .iter()
                .map(|(_, s)| s.clone())
                .collect()
        }
    }

    impl ShareLedger for TestLedger {
        fn record_share(
            &self,
            worker: &crate::mining::pool::WorkerIdentity,
            share: &AcceptedShare,
        ) -> Result<RecordOutcome, crate::mining::pool::LedgerUnavailable> {
            self.share_calls.fetch_add(1, Ordering::SeqCst);
            if self.reject_shares.load(Ordering::SeqCst) {
                return Ok(RecordOutcome::Rejected);
            }
            let mut fail = self
                .fail_shares
                .lock()
                .unwrap_or_else(|error| panic!("test operation failed: {error}"));
            if let Some(remaining) = fail.as_mut()
                && *remaining > 0
            {
                *remaining -= 1;
                return Err(crate::mining::pool::LedgerUnavailable);
            }
            let mut shares = self
                .shares
                .lock()
                .unwrap_or_else(|error| panic!("test operation failed: {error}"));
            if shares.iter().any(|(_, s)| s.hash == share.hash) {
                Ok(RecordOutcome::AlreadyRecorded)
            } else {
                shares.push((
                    format!("{}.{}", worker.account, worker.worker),
                    share.clone(),
                ));
                Ok(RecordOutcome::Recorded)
            }
        }

        fn record_block(
            &self,
            worker: &crate::mining::pool::WorkerIdentity,
            block: &FoundBlock,
            _submission: &Result<crate::mining::pool::BlockReceipt, MiningControlError>,
        ) -> Result<(), crate::mining::pool::LedgerUnavailable> {
            self.blocks
                .lock()
                .unwrap_or_else(|error| panic!("test operation failed: {error}"))
                .push((
                    format!("{}.{}", worker.account, worker.worker),
                    block.clone(),
                ));
            Ok(())
        }
    }

    fn sample_candidate(prev: Hash256, bits: CompactTarget, height: u32) -> Candidate {
        let script_sig_bytes = vec![
            0x03,
            u8::try_from(height).unwrap_or_else(|_| panic!("test height must fit BIP34 byte")),
            0x00,
            0x00,
        ];
        Candidate {
            template_id: TemplateId::new(&prev, 1),
            previous_block_hash: prev,
            height,
            version: 0x2000_0000,
            bits,
            min_time: 1_700_000_000,
            current_time: 1_700_000_000,
            csv_active: true,
            segwit_active: true,
            max_weight: 4_000_000,
            max_size: 4_000_000,
            max_sigops: 80_000,
            mempool_sequence: 1,
            coinbase: Tx {
                version: 1,
                lock_time: LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(script_sig_bytes),
                    sequence: Sequence::ZERO,
                    witness: Witness::default(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(50_0000_0000),
                    script_pubkey: Script::new(),
                }],
            },
            coinbase_value: 50_0000_0000,
            weight: 1000,
            transactions: Vec::new(),
            witness_commitment: None,
        }
    }

    fn build_pool(control: Arc<dyn MiningControl>, ledger: Arc<dyn ShareLedger>) -> Arc<PoolCore> {
        build_pool_with_outbox(control, ledger, None)
    }

    fn wait_for_pending(pool: &Arc<PoolCore>, expected: usize, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while pool.pending_ledger_writes() != expected {
            assert!(
                Instant::now() < deadline,
                "outbox writes did not settle: {what}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn build_pool_with_outbox(
        control: Arc<dyn MiningControl>,
        ledger: Arc<dyn ShareLedger>,
        outbox: Option<(usize, usize)>,
    ) -> Arc<PoolCore> {
        let config = JobBookConfig {
            budget: CoinbaseBudget {
                additional_size: 100,
                additional_sigops: 10,
            },
            extranonce: ExtranonceLayout::new(4, 4),
            coinbase_tag: b"/test-pool/".to_vec(),
            version_mask: 0x1fff_e000,
            ntime_forward_secs: 7200,
            max_jobs: 16,
            max_sessions: 64,
            max_shares_per_job: 1024,
        };
        let pool = PoolCore::new(config, control, ledger)
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        match outbox {
            Some((items, bytes)) => Arc::new(pool.with_outbox(items, bytes)),
            None => Arc::new(pool),
        }
    }

    struct TestClient {
        stream: TcpStream,
        reader: BufReader<TcpStream>,
    }

    impl TestClient {
        fn connect(addr: SocketAddr) -> Self {
            let stream = TcpStream::connect(addr)
                .unwrap_or_else(|error| panic!("test operation failed: {error}"));
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap_or_else(|error| panic!("test operation failed: {error}"));
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap_or_else(|error| panic!("test operation failed: {error}"));
            let reader = BufReader::new(
                stream
                    .try_clone()
                    .unwrap_or_else(|error| panic!("test operation failed: {error}")),
            );
            Self { stream, reader }
        }

        fn send(&mut self, text: &str) {
            self.stream
                .write_all(text.as_bytes())
                .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        }

        fn read_line(&mut self) -> String {
            let mut line = String::new();
            self.reader
                .read_line(&mut line)
                .unwrap_or_else(|error| panic!("test operation failed: {error}"));
            line
        }

        fn read_available(reader: &mut BufReader<TcpStream>, into: &mut String) -> bool {
            let mut byte = [0_u8; 1];
            match reader.read(&mut byte) {
                Ok(0) => false,
                Ok(_) => {
                    into.push(char::from(byte[0]));
                    let _ = reader.read_line(into);
                    true
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    false
                }
                Err(error) => panic!("test operation failed: {error}"),
            }
        }

        fn expect_eof(&mut self) {
            let mut buf = [0_u8; 1];
            let n = self
                .reader
                .read(&mut buf)
                .unwrap_or_else(|error| panic!("test operation failed: {error}"));
            assert_eq!(n, 0, "expected connection to be closed");
        }
    }

    #[test]
    fn shared_connection_limiter_enforces_total_and_per_ip_caps() -> TestResult {
        let total_limiter = Arc::new(ConnectionLimiter::new(1, 1)?);
        let first = total_limiter
            .try_admit(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .map_err(|reason| {
                std::io::Error::other(format!("unexpected total admission refusal: {reason:?}"))
            })?;
        assert_eq!(total_limiter.active(), 1);
        assert!(matches!(
            total_limiter.try_admit(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            Err(RefusalReason::ConnectionLimit)
        ));
        drop(first);
        assert_eq!(total_limiter.active(), 0);
        let second = total_limiter
            .try_admit(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            .map_err(|reason| {
                std::io::Error::other(format!("unexpected retry admission refusal: {reason:?}"))
            })?;
        assert_eq!(total_limiter.active(), 1);
        drop(second);
        assert_eq!(total_limiter.active(), 0);

        let per_ip_limiter = Arc::new(ConnectionLimiter::new(3, 1)?);
        let first = per_ip_limiter
            .try_admit(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .map_err(|reason| {
                std::io::Error::other(format!("unexpected per-IP admission refusal: {reason:?}"))
            })?;
        assert!(matches!(
            per_ip_limiter.try_admit(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Err(RefusalReason::PerIpLimit)
        ));
        let second = per_ip_limiter
            .try_admit(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            .map_err(|reason| {
                std::io::Error::other(format!(
                    "unexpected second-IP admission refusal: {reason:?}"
                ))
            })?;
        assert_eq!(per_ip_limiter.active(), 2);
        drop(first);
        drop(second);
        assert_eq!(per_ip_limiter.active(), 0);
        Ok(())
    }

    #[test]
    fn prevhash_vector_round_trips_exact_byte_swap() {
        let wire_hex = "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000";
        let internal = prevhash_from_wire(wire_hex).unwrap_or_else(|| panic!("valid hex"));
        let back_to_wire = prevhash_to_wire(&internal);
        assert_eq!(wire_hex, back_to_wire);

        let swapped = swap_words(&internal);
        let original = swap_words(&swapped);
        assert_eq!(internal, original);
    }

    #[test]
    fn line_buffer_enforces_bounds_and_crlf() {
        let mut buf = LineBuffer::new(64);

        buf.push(b"hello")
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
        assert_eq!(
            buf.next_frame()
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
            None
        );

        buf.push(b" world\r\n")
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
        assert_eq!(
            buf.next_frame()
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
            Some(b"hello world".to_vec())
        );
        assert_eq!(
            buf.next_frame()
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
            None
        );

        buf.push(b"\r\n\nline\n")
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
        assert_eq!(
            buf.next_frame()
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
            Some(b"line".to_vec())
        );
        assert_eq!(
            buf.next_frame()
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
            None
        );

        let big = vec![b'x'; 64 + 64 * 1024 + 1];
        assert_eq!(buf.push(&big), Err(FrameError::LineTooLong));
    }

    #[test]
    fn full_sv1_handshake_and_share_submit_transcript() {
        let prev = Hash256::from_le_bytes(&[0x11; 32]);
        let candidate = Arc::new(sample_candidate(
            prev,
            CompactTarget::from_consensus(0x207f_ffff),
            1,
        ));
        let fake_control = Arc::new(FakeMiningControl::default());
        let ledger = Arc::new(TestLedger::default());
        let pool = build_pool(fake_control, ledger.clone());

        let installed = pool
            .install(candidate, Vec::new())
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let job_id = installed.job.id();

        let accounts = Arc::new(
            StaticAccountResolver::new()
                .with_account("alice", "secret123")
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
        );
        let diff_policy = DifficultyPolicy::new("0.0000000001", "0.00000000001", "1000")
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
        let config = ServerConfig::new(diff_policy);
        let server = Server::bind(
            "127.0.0.1:0",
            config,
            ServerDeps {
                pool: pool.clone(),
                accounts,
                observer: None,
            },
        )
        .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let addr = server.local_addr();

        let mut client = TestClient::connect(addr);

        client.send("{\"id\":1,\"method\":\"mining.configure\",\"params\":[[\"version-rolling\"],{\"version-rolling.mask\":\"1fffe000\",\"version-rolling.min-bit-count\":2}]}\n");
        let resp = client.read_line();
        assert!(resp.contains("\"id\":1"));
        assert!(resp.contains("\"version-rolling\":true"));
        assert!(resp.contains("\"version-rolling.mask\":\"1fffe000\""));

        client.send("{\"id\":2,\"method\":\"mining.subscribe\",\"params\":[\"miner/1.0.0\"]}\n");
        let resp = client.read_line();
        assert!(resp.contains("\"id\":2"));
        assert!(resp.contains("\"result\":[[[\"mining.set_difficulty\""));
        assert!(resp.contains("\"error\":null"));

        client.send(
        "{\"id\":3,\"method\":\"mining.authorize\",\"params\":[\"alice.worker1\",\"secret123\"]}\n",
    );
        let resp = client.read_line();
        assert_eq!(resp, "{\"id\":3,\"result\":true,\"error\":null}\n");

        let set_diff = client.read_line();
        assert!(set_diff.contains("\"method\":\"mining.set_difficulty\""));
        assert!(set_diff.contains("0.0000000001"));

        let notify = client.read_line();
        assert!(notify.contains("\"method\":\"mining.notify\""));
        assert!(notify.contains(&format!("{:08x}", job_id.get())));

        let en1 = pool.layout().session_len();
        let en2 = pool.layout().rolled_len();
        assert_eq!(en1, 4);
        assert_eq!(en2, 4);

        let extranonce2_hex = "00000001";
        let ntime_hex = format!("{:08x}", installed.job.ntime());
        let nonce_hex = "00000000";
        let version_bits_hex = "00002000";

        let submit_cmd = format!(
            "{{\"id\":4,\"method\":\"mining.submit\",\"params\":[\"alice.worker1\",\"{job_id:08x}\",\"{extranonce2_hex}\",\"{ntime_hex}\",\"{nonce_hex}\",\"{version_bits_hex}\"]}}\n",
            job_id = job_id.get()
        );
        client.send(&submit_cmd);
        let submit_resp = client.read_line();
        assert_eq!(submit_resp, "{\"id\":4,\"result\":true,\"error\":null}\n");

        let recorded = ledger.recorded_shares();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].job, job_id);

        client.send(&submit_cmd);
        let dup_resp = client.read_line();
        assert!(dup_resp.contains("\"error\":[22,\"Duplicate share\",null]"));
        assert_eq!(ledger.recorded_shares().len(), 1);

        server.shutdown();
    }

    #[test]
    fn transactional_outbox_buffers_shares_when_ledger_fails() {
        let prev = Hash256::from_le_bytes(&[0x22; 32]);
        let candidate = Arc::new(sample_candidate(
            prev,
            CompactTarget::from_consensus(0x207f_ffff),
            2,
        ));
        let fake_control = Arc::new(FakeMiningControl::default());
        let ledger = Arc::new(TestLedger::armed_with_failures(usize::MAX));
        let pool = build_pool(fake_control, ledger.clone());
        let installed = pool
            .install(candidate, Vec::new())
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let job_id = installed.job.id();

        let accounts = Arc::new(
            StaticAccountResolver::new()
                .with_account("alice", "secret123")
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
        );
        let diff_policy = DifficultyPolicy::new("0.0000000001", "0.00000000001", "1000")
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
        let config = ServerConfig::new(diff_policy);
        let server = Server::bind(
            "127.0.0.1:0",
            config,
            ServerDeps {
                pool: pool.clone(),
                accounts,
                observer: None,
            },
        )
        .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let addr = server.local_addr();

        let mut client = TestClient::connect(addr);
        client.send("{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n");
        let _ = client.read_line();
        client.send(
            "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"alice.w1\",\"secret123\"]}\n",
        );
        let _ = client.read_line();
        let _ = client.read_line();
        let _ = client.read_line();

        let submit = format!(
            "{{\"id\":3,\"method\":\"mining.submit\",\"params\":[\"alice.w1\",\"{job_id:08x}\",\"00000001\",\"{ntime:08x}\",\"00000000\"]}}\n",
            job_id = job_id.get(),
            ntime = installed.job.ntime(),
        );
        client.send(&submit);
        client
            .stream
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let mut early = String::new();
        let blocked = TestClient::read_available(&mut client.reader, &mut early);
        assert!(!blocked, "no success may precede the durable record");
        assert!(early.is_empty(), "unexpected early frame: {early:?}");

        ledger.disarm();
        pool.drain_outbox();
        client
            .stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let resp = client.read_line();
        assert_eq!(resp, "{\"id\":3,\"result\":true,\"error\":null}\n");
        assert_eq!(ledger.recorded_shares().len(), 1);

        client.send(&submit);
        let replay = client.read_line();
        assert!(replay.contains("\"error\":[22,\"Duplicate share\",null]"));
        assert_eq!(ledger.recorded_shares().len(), 1);

        server.shutdown();
    }

    #[test]
    fn second_submit_while_accounting_pending_is_shed_before_validation() {
        let prev = Hash256::from_le_bytes(&[0x44; 32]);
        let candidate = Arc::new(sample_candidate(
            prev,
            CompactTarget::from_consensus(0x207f_ffff),
            4,
        ));
        let fake_control = Arc::new(FakeMiningControl::default());
        let ledger = Arc::new(TestLedger::armed_with_failures(usize::MAX));
        let pool = build_pool(fake_control, ledger.clone());
        let installed = pool
            .install(candidate, Vec::new())
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let job_id = installed.job.id();

        let accounts = Arc::new(
            StaticAccountResolver::new()
                .with_account("alice", "secret123")
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
        );
        let diff_policy = DifficultyPolicy::new("0.0000000001", "0.00000000001", "1000")
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
        let config = ServerConfig::new(diff_policy);
        let server = Server::bind(
            "127.0.0.1:0",
            config,
            ServerDeps {
                pool: pool.clone(),
                accounts,
                observer: None,
            },
        )
        .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let addr = server.local_addr();

        let mut client = TestClient::connect(addr);
        client.send("{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n");
        let _ = client.read_line();
        client.send(
            "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"alice.w1\",\"secret123\"]}\n",
        );
        let _ = client.read_line();
        let _ = client.read_line();
        let _ = client.read_line();

        let first = format!(
            "{{\"id\":3,\"method\":\"mining.submit\",\"params\":[\"alice.w1\",\"{job_id:08x}\",\"00000001\",\"{ntime:08x}\",\"00000000\"]}}\n",
            job_id = job_id.get(),
            ntime = installed.job.ntime(),
        );
        client.send(&first);
        client
            .stream
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let mut early = String::new();
        assert!(
            !TestClient::read_available(&mut client.reader, &mut early),
            "no success may precede the durable record"
        );
        assert!(early.is_empty(), "unexpected early frame: {early:?}");

        let second = format!(
            "{{\"id\":4,\"method\":\"mining.submit\",\"params\":[\"alice.w1\",\"{job_id:08x}\",\"00000001\",\"{ntime:08x}\",\"00000001\"]}}\n",
            job_id = job_id.get(),
            ntime = installed.job.ntime(),
        );
        client.send(&second);
        client
            .stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let shed = client.read_line();
        assert!(
            shed.contains("\"error\":[20,") && shed.contains("Share accounting unavailable"),
            "second submit while pending must be shed retryably: {shed}"
        );
        assert_eq!(
            ledger.recorded_shares().len(),
            0,
            "a shed submit must not reach the ledger"
        );

        ledger.disarm();
        pool.drain_outbox();
        let resp = client.read_line();
        assert_eq!(resp, "{\"id\":3,\"result\":true,\"error\":null}\n");
        assert_eq!(ledger.recorded_shares().len(), 1);

        let retry = second.replace("\"id\":4", "\"id\":5");
        client.send(&retry);
        let retried = client.read_line();
        assert_eq!(retried, "{\"id\":5,\"result\":true,\"error\":null}\n");
        assert_eq!(ledger.recorded_shares().len(), 2);

        server.shutdown();
    }

    #[test]
    fn composed_pool_defaults_enforce_total_and_per_ip_caps() -> TestResult {
        use std::net::{IpAddr, Ipv4Addr};

        let limiter = Arc::new(ConnectionLimiter::new(128, 8)?);
        let mut held = Vec::new();
        for host in 1..=16u8 {
            let peer = IpAddr::V4(Ipv4Addr::new(127, 0, 0, host));
            for _ in 0..8 {
                held.push(limiter.try_admit(peer).map_err(|reason| {
                    std::io::Error::other(format!(
                        "composed default admission refused early: {reason:?}"
                    ))
                })?);
            }
            assert!(
                limiter.try_admit(peer).is_err(),
                "the 9th connection from one IP must be refused under the composed 8-per-IP cap"
            );
        }
        assert_eq!(held.len(), 128);
        assert!(
            limiter
                .try_admit(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 17)))
                .is_err(),
            "the 129th total connection must be refused under the composed 128-total cap"
        );
        drop(held);
        limiter
            .try_admit(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .map_err(|reason| {
                std::io::Error::other(format!("released slot not re-admittable: {reason:?}"))
            })?;
        Ok(())
    }

    #[test]
    fn job_install_with_new_parent_issues_no_ledger_write() {
        let ledger = Arc::new(TestLedger::default());
        let pool = build_pool(Arc::new(FakeMiningControl::default()), ledger.clone());
        for (parent, height) in [([0x51; 32], 10), ([0x52; 32], 11)] {
            let candidate = Arc::new(sample_candidate(
                Hash256::from_le_bytes(&parent),
                CompactTarget::from_consensus(0x207f_ffff),
                height,
            ));
            pool.install(candidate, Vec::new())
                .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        }
        assert!(
            ledger.recorded_shares().is_empty(),
            "installing jobs with new parents must not write share accounting"
        );
    }

    #[test]
    fn protocol_negative_scenarios_rejected_deterministically() {
        let prev = Hash256::from_le_bytes(&[0x33; 32]);
        let candidate = Arc::new(sample_candidate(
            prev,
            CompactTarget::from_consensus(0x207f_ffff),
            3,
        ));
        let pool = build_pool(
            Arc::new(FakeMiningControl::default()),
            Arc::new(TestLedger::default()),
        );
        let installed = pool
            .install(candidate, Vec::new())
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let job_id = installed.job.id();

        let accounts = Arc::new(
            StaticAccountResolver::new()
                .with_account("bob", "pass")
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
        );
        let diff_policy = DifficultyPolicy::new("0.0000000001", "0.00000000001", "1000")
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
        let mut config = ServerConfig::new(diff_policy);
        config.max_consecutive_violations = 4;
        let server = Server::bind(
            "127.0.0.1:0",
            config,
            ServerDeps {
                pool,
                accounts,
                observer: None,
            },
        )
        .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let addr = server.local_addr();

        let mut client = TestClient::connect(addr);

        client.send("{\"id\":1,\"method\":\"mining.submit\",\"params\":[\"bob\",\"00000001\",\"00000001\",\"60000000\",\"00000000\"]}\n");
        let resp = client.read_line();
        assert!(resp.contains("\"error\":[25,\"Not subscribed\",null]"));

        client.send("{\"id\":2,\"method\":\"mining.subscribe\",\"params\":[]}\n");
        let _ = client.read_line();

        client.send("{\"id\":3,\"method\":\"mining.submit\",\"params\":[\"bob\",\"00000001\",\"00000001\",\"60000000\",\"00000000\"]}\n");
        let resp = client.read_line();
        assert!(resp.contains("\"error\":[24,\"Unauthorized worker\",null]"));

        client.send("{\"id\":4,\"method\":\"mining.authorize\",\"params\":[\"bob\",\"wrong\"]\n");
        let parse_err = client.read_line();
        assert!(parse_err.contains("-32700"));

        client.send("{\"id\":5,\"method\":\"mining.authorize\",\"params\":[\"bob\",\"pass\"]}\n");
        assert_eq!(
            client.read_line(),
            "{\"id\":5,\"result\":true,\"error\":null}\n"
        );
        let _ = client.read_line();
        let _ = client.read_line();

        let bad_en2 = format!(
            "{{\"id\":6,\"method\":\"mining.submit\",\"params\":[\"bob\",\"{job_id:08x}\",\"01\",\"{ntime:08x}\",\"00000000\"]}}\n",
            job_id = job_id.get(),
            ntime = installed.job.ntime(),
        );
        client.send(&bad_en2);
        let en2_err = client.read_line();
        assert!(en2_err.contains("Invalid extranonce2 length") || en2_err.contains("-32602"));

        let unexp_bits = format!(
            "{{\"id\":7,\"method\":\"mining.submit\",\"params\":[\"bob\",\"{job_id:08x}\",\"00000001\",\"{ntime:08x}\",\"00000000\",\"00002000\"]}}\n",
            job_id = job_id.get(),
            ntime = installed.job.ntime(),
        );
        client.send(&unexp_bits);
        let bits_err = client.read_line();
        assert!(bits_err.contains("Unexpected version bits"));

        server.shutdown();
    }

    #[test]
    fn suggest_difficulty_validates_bounds_honestly() {
        let pool = build_pool(
            Arc::new(FakeMiningControl::default()),
            Arc::new(TestLedger::default()),
        );
        let accounts = Arc::new(
            StaticAccountResolver::new()
                .with_account("user", "pass")
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
        );
        let diff_policy = DifficultyPolicy::new("10.0", "1.0", "100.0")
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
        let config = ServerConfig::new(diff_policy);
        let server = Server::bind(
            "127.0.0.1:0",
            config,
            ServerDeps {
                pool,
                accounts,
                observer: None,
            },
        )
        .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let addr = server.local_addr();

        let mut client = TestClient::connect(addr);

        client.send("{\"id\":1,\"method\":\"mining.suggest_difficulty\",\"params\":[25.5]}\n");
        let resp = client.read_line();
        assert_eq!(resp, "{\"id\":1,\"result\":true,\"error\":null}\n");

        client.send("{\"id\":2,\"method\":\"mining.suggest_difficulty\",\"params\":[0.5]}\n");
        let resp = client.read_line();
        assert!(resp.contains("\"error\":[20,\"Difficulty out of range\",null]"));

        client.send("{\"id\":3,\"method\":\"mining.suggest_difficulty\",\"params\":[500.0]}\n");
        let resp = client.read_line();
        assert!(resp.contains("\"error\":[20,\"Difficulty out of range\",null]"));

        server.shutdown();
    }

    #[test]
    fn connection_caps_refuse_excess_peers_and_shutdown_joins_served_sessions() {
        type Tighten = fn(&mut ServerConfig);
        let cases: [(Tighten, RefusalReason); 2] = [
            (
                |config| config.max_connections = 1,
                RefusalReason::ConnectionLimit,
            ),
            (
                |config| config.max_connections_per_ip = 1,
                RefusalReason::PerIpLimit,
            ),
        ];
        for (tighten, expected) in cases {
            let pool = build_pool(
                Arc::new(FakeMiningControl::default()),
                Arc::new(TestLedger::default()),
            );
            let accounts = Arc::new(
                StaticAccountResolver::new()
                    .with_account("user", "pass")
                    .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
            );
            let mut config = ServerConfig::new(
                DifficultyPolicy::new("10.0", "1.0", "100.0")
                    .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
            );
            tighten(&mut config);

            let (events, observed) = mpsc::sync_channel::<ServerEvent>(16);
            let observer: Observer = Arc::new(move |event: &ServerEvent| {
                let _ = events.try_send(event.clone());
            });
            let server = Server::bind(
                "127.0.0.1:0",
                config,
                ServerDeps {
                    pool,
                    accounts,
                    observer: Some(observer),
                },
            )
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
            let addr = server.local_addr();

            let first = TestClient::connect(addr);
            let accepted = observed
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_else(|error| panic!("test operation failed: {error}"));
            assert!(matches!(accepted, ServerEvent::Accepted { .. }));
            assert_eq!(server.active_sessions(), 1);

            let mut second = TestClient::connect(addr);
            second.expect_eof();
            match observed
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_else(|error| panic!("test operation failed: {error}"))
            {
                ServerEvent::Refused { reason, .. } => assert_eq!(reason, expected),
                other => panic!("expected a refusal, saw {other:?}"),
            }
            assert_eq!(server.active_sessions(), 1);

            let report = server.shutdown();
            assert_eq!(report.sessions_joined, 1);
            assert_eq!(report.sessions_panicked, 0);
            drop(first);
        }
    }

    const ROLLED: [u8; 4] = [0, 0, 0, 1];

    struct MinerFixture {
        server: Server,
        client: TestClient,
        pool: Arc<PoolCore>,
        control: Arc<FakeMiningControl>,
        ledger: Arc<TestLedger>,
        job: Arc<Job>,
        prefix: [u8; 4],
        version: u32,
    }

    impl MinerFixture {
        fn start(parent: u8) -> Self {
            Self::start_with(parent, None, None)
        }

        fn start_with(
            parent: u8,
            outbox: Option<(usize, usize)>,
            ledger: Option<Arc<TestLedger>>,
        ) -> Self {
            let candidate = Arc::new(sample_candidate(
                Hash256::from_le_bytes(&[parent; 32]),
                CompactTarget::from_consensus(0x207f_ffff),
                1,
            ));
            let control = Arc::new(FakeMiningControl::default());
            let ledger = ledger.unwrap_or_default();
            let pool = build_pool_with_outbox(control.clone(), ledger.clone(), outbox);
            let installed = pool
                .install(candidate, Vec::new())
                .unwrap_or_else(|error| panic!("test operation failed: {error}"));
            let accounts = Arc::new(
                StaticAccountResolver::new()
                    .with_account("alice", "secret123")
                    .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
            );
            let policy = DifficultyPolicy::new("0.0000000001", "0.00000000001", "1000")
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
            let server = Server::bind(
                "127.0.0.1:0",
                ServerConfig::new(policy),
                ServerDeps {
                    pool: pool.clone(),
                    accounts,
                    observer: None,
                },
            )
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
            let mut client = TestClient::connect(server.local_addr());

            client.send("{\"id\":1,\"method\":\"mining.configure\",\"params\":[[\"version-rolling\"],{\"version-rolling.mask\":\"1fffe000\",\"version-rolling.min-bit-count\":2}]}\n");
            assert!(client.read_line().contains("\"id\":1"));
            client
                .send("{\"id\":2,\"method\":\"mining.subscribe\",\"params\":[\"miner/1.0.0\"]}\n");
            let subscribed = client.read_line();
            assert!(subscribed.contains("\"id\":2"));
            let ext1_hex = subscribed
                .split("]],\"")
                .nth(1)
                .and_then(|tail| tail.split('"').next())
                .unwrap_or_else(|| panic!("subscribe carries extranonce1: {subscribed}"));
            assert_eq!(ext1_hex.len(), 8, "4-byte session prefix");
            let prefix = u32::from_str_radix(ext1_hex, 16)
                .unwrap_or_else(|error| panic!("hex session prefix: {error:?}"))
                .to_be_bytes();
            let version = installed
                .job
                .version_from_rolled_bits(0x2000)
                .unwrap_or_else(|error| panic!("mask-clean version bits: {error:?}"));
            client.send(
            "{\"id\":3,\"method\":\"mining.authorize\",\"params\":[\"alice.worker1\",\"secret123\"]}\n",
        );
            assert_eq!(
                client.read_line(),
                "{\"id\":3,\"result\":true,\"error\":null}\n"
            );
            let mut seen_notify = false;
            for _ in 0..4 {
                if client.read_line().contains("\"method\":\"mining.notify\"") {
                    seen_notify = true;
                    break;
                }
            }
            assert!(seen_notify, "installed job is announced");

            Self {
                server,
                client,
                pool,
                control,
                ledger,
                job: installed.job,
                prefix,
                version,
            }
        }

        fn winning_nonce(&self, start: u32) -> u32 {
            (start..=u32::MAX)
                .find(|nonce| {
                    let header = self
                        .job
                        .header(
                            Extranonce {
                                session: &self.prefix,
                                rolled: &ROLLED,
                            },
                            self.job.ntime(),
                            self.version,
                            *nonce,
                        )
                        .unwrap_or_else(|error| panic!("header builds: {error:?}"));
                    compact_is_met_by(self.job.bits(), Hash256::from(header.compute_hash()))
                })
                .unwrap_or_else(|| panic!("a winning nonce exists"))
        }

        fn share_nonce(&self, start: u32) -> u32 {
            self.share_nonce_for(self.prefix, start)
        }

        fn share_nonce_for(&self, prefix: [u8; 4], start: u32) -> u32 {
            (start..=u32::MAX)
                .find(|nonce| {
                    let header = self
                        .job
                        .header(
                            Extranonce {
                                session: &prefix,
                                rolled: &ROLLED,
                            },
                            self.job.ntime(),
                            self.version,
                            *nonce,
                        )
                        .unwrap_or_else(|error| panic!("header builds: {error:?}"));
                    !compact_is_met_by(self.job.bits(), Hash256::from(header.compute_hash()))
                })
                .unwrap_or_else(|| panic!("a plain share nonce exists"))
        }

        fn second_client(&self, login: &str) -> (TestClient, [u8; 4]) {
            let mut client = TestClient::connect(self.server.local_addr());
            client.send("{\"id\":1,\"method\":\"mining.configure\",\"params\":[[\"version-rolling\"],{\"version-rolling.mask\":\"1fffe000\",\"version-rolling.min-bit-count\":2}]}\n");
            assert!(client.read_line().contains("\"id\":1"));
            client
                .send("{\"id\":2,\"method\":\"mining.subscribe\",\"params\":[\"miner/1.0.0\"]}\n");
            let subscribed = client.read_line();
            assert!(subscribed.contains("\"id\":2"));
            let ext1_hex = subscribed
                .split("]],\"")
                .nth(1)
                .and_then(|tail| tail.split('"').next())
                .unwrap_or_else(|| panic!("subscribe carries extranonce1: {subscribed}"));
            assert_eq!(ext1_hex.len(), 8, "4-byte session prefix");
            let prefix = u32::from_str_radix(ext1_hex, 16)
                .unwrap_or_else(|error| panic!("hex session prefix: {error:?}"))
                .to_be_bytes();
            client.send(&format!(
            "{{\"id\":3,\"method\":\"mining.authorize\",\"params\":[\"{login}\",\"secret123\"]}}\n"
        ));
            assert_eq!(
                client.read_line(),
                "{\"id\":3,\"result\":true,\"error\":null}\n"
            );
            let mut seen_notify = false;
            for _ in 0..4 {
                if client.read_line().contains("\"method\":\"mining.notify\"") {
                    seen_notify = true;
                    break;
                }
            }
            assert!(seen_notify, "installed job is announced");
            (client, prefix)
        }

        fn submit(&mut self, id: u32, job: &Job, nonce: u32) -> String {
            let (job_id, ntime) = (job.id().get(), job.ntime());
            self.client.send(&format!(
            "{{\"id\":{id},\"method\":\"mining.submit\",\"params\":[\"alice.worker1\",\"{job_id:08x}\",\"00000001\",\"{ntime:08x}\",\"{nonce:08x}\",\"00002000\"]}}\n",
        ));
            for _ in 0..8 {
                let line = self.client.read_line();
                if line.contains(&format!("\"id\":{id}")) {
                    return line;
                }
            }
            panic!("no response to submit {id}");
        }
    }

    // POOL-05
    #[test]
    fn applied_block_retires_job_and_second_submit_is_stale() {
        let mut miner = MinerFixture::start(0x22);
        let job = Arc::clone(&miner.job);
        let first = miner.winning_nonce(0);
        let second = miner.winning_nonce(first + 1);
        assert_ne!(first, second);

        let accepted = miner.submit(100, &job, first);
        assert!(
            accepted.contains("\"error\":null"),
            "first winning nonce accepted: {accepted}"
        );
        assert!(
            miner.pool.current_installed().is_none(),
            "applied block retired the job"
        );
        assert_eq!(
            miner.control.submit_calls.load(Ordering::SeqCst),
            1,
            "exactly one block reached the node"
        );

        let stale = miner.submit(200, &job, second);
        assert!(
            stale.contains("\"error\":[21,\"Stale share\""),
            "retired job submit is a stale protocol error: {stale}"
        );
        assert_eq!(
            miner.control.submit_calls.load(Ordering::SeqCst),
            1,
            "stale share never resubmitted to the node"
        );

        let next = miner
            .pool
            .install(
                Arc::new(sample_candidate(
                    Hash256::from_le_bytes(&[0x33; 32]),
                    CompactTarget::from_consensus(0x207f_ffff),
                    2,
                )),
                Vec::new(),
            )
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let fresh = miner.submit(300, &next.job, 0);
        assert!(
            fresh.contains("\"error\":null"),
            "new parent job accepted: {fresh}"
        );

        miner.server.shutdown();
    }

    #[test]
    fn inconclusive_block_submission_retries_with_bounded_recovery() {
        let mut miner = MinerFixture::start(0x22);
        let job = Arc::clone(&miner.job);
        *miner.control.submit.lock() = BlockValidationResult::Inconclusive;
        let winner = miner.winning_nonce(0);
        let response = miner.submit(100, &job, winner);
        assert!(
            response.contains("\"error\":null"),
            "inconclusive share stays acknowledged while recovery runs: {response}"
        );
        assert_eq!(
            miner.control.submit_calls.load(Ordering::SeqCst),
            5,
            "inconclusive retries bounded recovery work instead of exiting once"
        );
        {
            let blocks = miner
                .ledger
                .blocks
                .lock()
                .unwrap_or_else(|error| panic!("test operation failed: {error}"));
            assert_eq!(
                blocks.len(),
                1,
                "inconclusive block is retained, not dropped"
            );
        }
        assert!(
            miner.pool.current_installed().is_some(),
            "no retire without an applied block"
        );
        miner.server.shutdown();
    }

    // POOL-05
    #[test]
    fn stale_parent_backend_verdict_is_stale_error() {
        let mut miner = MinerFixture::start(0x44);
        let job = Arc::clone(&miner.job);

        *miner.control.submit.lock() = BlockValidationResult::Rejected(STALE_PARENT_REASON.into());
        let winner = miner.winning_nonce(0);
        let stale = miner.submit(100, &job, winner);
        assert!(
            stale.contains("\"error\":[21,\"Stale share\""),
            "stale-parent receipt is a stale protocol error: {stale}"
        );
        assert_eq!(
            miner.control.submit_calls.load(Ordering::SeqCst),
            1,
            "exactly one block reached the node"
        );
        {
            let blocks = miner
                .ledger
                .blocks
                .lock()
                .unwrap_or_else(|error| panic!("test operation failed: {error}"));
            assert_eq!(blocks.len(), 1, "rejected block stays durably recorded");
        }
        assert!(
            miner.pool.current_installed().is_some(),
            "no retire without an applied block"
        );

        *miner.control.submit.lock() = BlockValidationResult::Accepted;
        let later = miner.submit(200, &job, winner + 1);
        assert!(
            later.contains("\"error\":null"),
            "connection usable after stale error: {later}"
        );

        miner.server.shutdown();
    }

    #[test]
    fn configured_minima_cannot_fail_an_empty_outbox() {
        let mut miner = MinerFixture::start_with(0x22, Some((1, 1024)), None);
        let job = Arc::clone(&miner.job);
        let nonce = miner.share_nonce(0);
        let response = miner.submit(100, &job, nonce);
        assert!(
            response.contains("\"error\":[20,")
                && response.contains("Share accounting unavailable"),
            "tiny budget must shed retryably before validation: {response}"
        );
        assert_eq!(
            miner.pool.pending_ledger_writes(),
            0,
            "a shed submit buffers nothing"
        );
        assert!(
            miner.ledger.recorded_shares().is_empty(),
            "a shed submit must not reach the ledger"
        );
        miner.server.shutdown();
    }

    #[test]
    fn per_submit_reservation_does_not_cap_the_pool_at_one_share() {
        let ledger = Arc::new(TestLedger::armed_with_failures(usize::MAX));
        let mut miner = MinerFixture::start_with(0x22, Some((1024, 8 * 1024 * 1024)), Some(ledger));
        let first = miner.share_nonce(0);
        let (mut second_client, second_prefix) = miner.second_client("alice.worker2");
        let second = miner.share_nonce_for(second_prefix, 0);
        miner.client.send(&format!(
        "{{\"id\":101,\"method\":\"mining.submit\",\"params\":[\"alice.worker1\",\"{:08x}\",\"00000001\",\"{:08x}\",\"{:08x}\",\"00002000\"]}}\n",
        miner.job.id().get(),
        miner.job.ntime(),
        first,
    ));
        second_client.send(&format!(
        "{{\"id\":102,\"method\":\"mining.submit\",\"params\":[\"alice.worker2\",\"{:08x}\",\"00000001\",\"{:08x}\",\"{:08x}\",\"00002000\"]}}\n",
        miner.job.id().get(),
        miner.job.ntime(),
        second,
    ));
        second_client
            .stream
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let mut early = String::new();
        let shed = TestClient::read_available(&mut second_client.reader, &mut early);
        assert!(
            !shed,
            "no shed may precede the durable records, got: {early:?}"
        );
        wait_for_pending(
            &miner.pool,
            2,
            "both shares buffer instead of capping the pool at one",
        );
        assert!(
            miner.pool.current_installed().is_some(),
            "plain shares never retire the job"
        );

        miner.ledger.disarm();
        miner.pool.drain_outbox();
        miner
            .client
            .stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        second_client
            .stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let mut first_line = String::new();
        for _ in 0..8 {
            first_line = miner.client.read_line();
            if first_line.contains("\"id\":101") {
                break;
            }
        }
        assert!(
            first_line.contains("\"error\":null"),
            "buffered share 101 is accepted after drain: {first_line}"
        );
        let mut second_line = String::new();
        for _ in 0..8 {
            second_line = second_client.read_line();
            if second_line.contains("\"id\":102") {
                break;
            }
        }
        assert!(
            second_line.contains("\"error\":null"),
            "buffered share 102 is accepted after drain: {second_line}"
        );
        assert_eq!(
            miner.ledger.recorded_shares().len(),
            2,
            "both buffered shares are credited exactly once"
        );
        miner.server.shutdown();
    }

    #[test]
    fn crash_restored_share_still_delivers_its_block_record() {
        let mut first = MinerFixture::start(0x22);
        let job = Arc::clone(&first.job);
        let winner = first.winning_nonce(0);
        let accepted = first.submit(100, &job, winner);
        assert!(
            accepted.contains("\"error\":null"),
            "winning nonce accepted: {accepted}"
        );
        assert_eq!(
            first.ledger.recorded_shares().len(),
            1,
            "first pool credits the share"
        );
        {
            let blocks = first
                .ledger
                .blocks
                .lock()
                .unwrap_or_else(|error| panic!("test operation failed: {error}"));
            assert_eq!(blocks.len(), 1, "first pool records the block");
        }

        let mut second = MinerFixture::start_with(0x22, None, Some(Arc::clone(&first.ledger)));
        assert_eq!(
            second.prefix, first.prefix,
            "fresh first sessions share the extranonce prefix"
        );
        let restored = second.winning_nonce(0);
        assert_eq!(
            restored, winner,
            "same candidate and prefix rebuild the same winner"
        );
        let job_b = Arc::clone(&second.job);
        let replay = second.submit(200, &job_b, restored);
        assert!(
            replay.contains("Duplicate share"),
            "crash-restored share keeps its duplicate identity: {replay}"
        );
        {
            let blocks = second
                .ledger
                .blocks
                .lock()
                .unwrap_or_else(|error| panic!("test operation failed: {error}"));
            assert_eq!(
                blocks.len(),
                2,
                "the block record is still delivered for a restored share"
            );
        }
        assert_eq!(
            second.control.submit_calls.load(Ordering::SeqCst),
            1,
            "the restored block still reaches the node once"
        );
        first.server.shutdown();
        second.server.shutdown();
    }

    #[test]
    fn permanently_refused_share_is_rejected_without_retry_or_buffer() {
        let mut miner = MinerFixture::start(0x22);
        miner.ledger.refuse_permanently();
        let job = Arc::clone(&miner.job);
        let nonce = miner.share_nonce(0);
        let response = miner.submit(100, &job, nonce);
        assert!(
            response.contains("\"error\":[22,\"Duplicate share\",null]"),
            "permanent refusal is a rejected share: {response}"
        );
        assert_eq!(
            miner.ledger.share_calls.load(Ordering::SeqCst),
            1,
            "a permanent refusal is never retried"
        );
        assert_eq!(
            miner.pool.pending_ledger_writes(),
            0,
            "a permanent refusal never buffers"
        );
        assert!(
            miner.ledger.recorded_shares().is_empty(),
            "a refused share credits nothing"
        );
        miner.server.shutdown();
    }

    #[test]
    fn permanently_refused_buffer_never_wedges_the_drain() {
        let ledger = Arc::new(TestLedger::armed_with_failures(usize::MAX));
        let mut miner = MinerFixture::start_with(0x22, None, Some(ledger));
        let job = Arc::clone(&miner.job);
        let first = miner.share_nonce(0);
        let second = miner.share_nonce(first + 1);
        miner.client.send(&format!(
        "{{\"id\":101,\"method\":\"mining.submit\",\"params\":[\"alice.worker1\",\"{:08x}\",\"00000001\",\"{:08x}\",\"{:08x}\",\"00002000\"]}}\n",
        job.id().get(),
        job.ntime(),
        first,
    ));
        miner
            .client
            .stream
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let mut early = String::new();
        assert!(
            !TestClient::read_available(&mut miner.client.reader, &mut early),
            "transient outage buffers without answering: {early:?}"
        );
        assert_eq!(miner.pool.pending_ledger_writes(), 1);

        miner.ledger.refuse_permanently();
        miner.ledger.disarm();
        miner.pool.drain_outbox();
        wait_for_pending(
            &miner.pool,
            0,
            "the poisoned head drops instead of wedging the drain",
        );
        assert!(
            miner.ledger.recorded_shares().is_empty(),
            "a refused share credits nothing"
        );

        miner
            .client
            .stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let mut drained = String::new();
        for _ in 0..8 {
            drained = miner.client.read_line();
            if drained.contains("\"id\":101") {
                break;
            }
        }
        assert!(
            drained.contains("\"id\":101"),
            "the dropped head still answers its waiter: {drained:?}"
        );
        assert!(
            drained.contains("\"error\":[22,\"Duplicate share\",null]"),
            "the refused head reports failure, not success: {drained:?}"
        );
        assert!(
            !drained.contains("\"error\":null"),
            "a permanently refused share must not report success: {drained:?}"
        );

        miner.ledger.admit_again();
        let response = miner.submit(102, &job, second);
        assert!(
            response.contains("\"error\":null"),
            "later shares still flow after the drop: {response}"
        );
        assert_eq!(
            miner.ledger.recorded_shares().len(),
            1,
            "only the deliverable share is credited"
        );
        miner.server.shutdown();
    }

    #[test]
    fn sv1_wire_version_bits_normalize_to_the_job_version() {
        let mut miner = MinerFixture::start(0x22);
        let job = Arc::clone(&miner.job);
        let nonce = miner.share_nonce(0);
        let response = miner.submit(100, &job, nonce);
        assert!(
            response.contains("\"error\":null"),
            "mask-clean version bits accepted: {response}"
        );
        let shares = miner.ledger.recorded_shares();
        assert_eq!(shares.len(), 1);
        let expected = i32::try_from(miner.version)
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
        assert_eq!(
            shares[0].header.version, expected,
            "the edge normalizes rolled bits to the canonical job version"
        );
        assert_eq!(shares[0].job, job.id());
        miner.server.shutdown();
    }

    #[test]
    fn unknown_wire_job_rejects_before_the_common_submit_owner() {
        let mut miner = MinerFixture::start(0x22);
        miner.client.send(&format!(
        "{{\"id\":100,\"method\":\"mining.submit\",\"params\":[\"alice.worker1\",\"0000007b\",\"00000001\",\"{:08x}\",\"00000000\",\"00002000\"]}}\n",
        miner.job.ntime(),
    ));
        let response = miner.client.read_line();
        assert!(
            response.contains("\"error\":[21,\"Job not found\",null]"),
            "unknown job rejects with the owner verdict: {response}"
        );
        assert!(
            miner.ledger.recorded_shares().is_empty(),
            "an unknown job credits nothing"
        );
        miner.server.shutdown();
    }

    // POOL-03
    #[test]
    fn block_with_tiny_outbox_sheds_before_validation_instead_of_growing_unbounded() {
        let mut miner = MinerFixture::start_with(0x22, Some((2, 1024)), None);
        let job = Arc::clone(&miner.job);
        let winner = miner.winning_nonce(0);
        let reply = miner.submit(100, &job, winner);
        assert!(
            reply.contains("\"error\":[20,") && reply.contains("Share accounting unavailable"),
            "tiny outbox must shed the block retryably: {reply}"
        );
        assert_eq!(
            miner.pool.pending_ledger_writes(),
            0,
            "a shed block must buffer nothing"
        );
        assert!(
            miner.ledger.recorded_shares().is_empty(),
            "a shed block must not reach the ledger shares"
        );
        let blocks = miner
            .ledger
            .blocks
            .lock()
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        assert!(
            blocks.is_empty(),
            "a shed block must not reach the ledger blocks"
        );
        assert_eq!(
            miner.control.submit_calls.load(Ordering::SeqCst),
            0,
            "a shed block must not reach the node before reservation"
        );
        miner.server.shutdown();
    }

    #[test]
    fn cancel_wakes_idle_connection_without_waiting_for_poll_interval() {
        let pool = build_pool(
            Arc::new(FakeMiningControl::default()),
            Arc::new(TestLedger::default()),
        );
        let accounts = Arc::new(
            StaticAccountResolver::new()
                .with_account("user", "pass")
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
        );
        let mut config = ServerConfig::new(
            DifficultyPolicy::new("10.0", "1.0", "100.0")
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
        );
        config.poll_interval = Duration::from_secs(10);
        config.frame_timeout = Duration::from_secs(15);

        let (events, observed) = mpsc::sync_channel::<ServerEvent>(16);
        let observer: Observer = Arc::new(move |event: &ServerEvent| {
            let _ = events.try_send(event.clone());
        });
        let server = Server::bind(
            "127.0.0.1:0",
            config,
            ServerDeps {
                pool,
                accounts,
                observer: Some(observer),
            },
        )
        .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let addr = server.local_addr();

        let client = TestClient::connect(addr);
        let accepted = observed
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        assert!(matches!(accepted, ServerEvent::Accepted { .. }));

        let (done_tx, done_rx) = mpsc::sync_channel::<ShutdownReport>(1);
        let join_thread = thread::spawn(move || {
            let report = server.shutdown();
            let _ = done_tx.send(report);
        });

        let report = done_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|error| panic!("idle session did not wake promptly: {error}"));
        assert_eq!(report.sessions_joined, 1);
        join_thread
            .join()
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
        drop(client);
    }

    #[test]
    fn cancel_wakes_blocked_accept_loop() {
        let pool = build_pool(
            Arc::new(FakeMiningControl::default()),
            Arc::new(TestLedger::default()),
        );
        let accounts = Arc::new(
            StaticAccountResolver::new()
                .with_account("user", "pass")
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
        );
        let config = ServerConfig::new(
            DifficultyPolicy::new("10.0", "1.0", "100.0")
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
        );
        let server = Server::bind(
            "127.0.0.1:0",
            config,
            ServerDeps {
                pool,
                accounts,
                observer: None,
            },
        )
        .unwrap_or_else(|error| panic!("test operation failed: {error}"));

        let (done_tx, done_rx) = mpsc::sync_channel::<ShutdownReport>(1);
        let join_thread = thread::spawn(move || {
            let report = server.shutdown();
            let _ = done_tx.send(report);
        });

        let report = done_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|error| panic!("accept loop did not wake promptly: {error}"));
        assert_eq!(report.sessions_joined, 0);
        join_thread
            .join()
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
    }

    #[test]
    fn stratum_v1_rejects_malformed_json_and_oversize_lines() {
        let pool = build_pool(
            Arc::new(FakeMiningControl::default()),
            Arc::new(TestLedger::default()),
        );
        let accounts = Arc::new(
            StaticAccountResolver::new()
                .with_account("miner1", "pass")
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
        );
        let diff_policy = DifficultyPolicy::new("1.0", "0.1", "100.0")
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
        let mut config = ServerConfig::new(diff_policy);
        config.max_frame_bytes = 256;
        let events = Arc::new(Mutex::new(Vec::new()));
        let observer: Observer = {
            let events = Arc::clone(&events);
            Arc::new(move |event| {
                events
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(event.clone());
            })
        };
        let server = Server::bind(
            "127.0.0.1:0",
            config,
            ServerDeps {
                pool,
                accounts,
                observer: Some(observer),
            },
        )
        .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let addr = server.local_addr();

        let mut client = TestClient::connect(addr);
        client.send("{invalid json line}\n");
        let resp = client.read_line();
        assert!(resp.contains("-32700"), "must return parse error: {resp}");
        assert!(
            resp.contains("Parse error"),
            "must return parse error message: {resp}"
        );

        client.send("GET / HTTP/1.1\r\n\r\n");
        let resp = client.read_line();
        assert!(resp.contains("-32700"), "must return parse error: {resp}");

        let oversize = "a".repeat(300) + "\n";
        client.send(&oversize);
        let eof = client.read_line();
        assert!(eof.is_empty(), "oversize line must close the connection");

        server.shutdown();
        let recorded = events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            recorded.iter().any(|event| matches!(
                event,
                ServerEvent::SessionEnded {
                    end: SessionEnd::FrameTooLong,
                    ..
                }
            )),
            "must record FrameTooLong session end"
        );
    }

    #[test]
    fn stratum_v1_rejects_duplicate_subscribe_and_submit_before_authorize() {
        let pool = build_pool(
            Arc::new(FakeMiningControl::default()),
            Arc::new(TestLedger::default()),
        );
        let accounts = Arc::new(
            StaticAccountResolver::new()
                .with_account("miner2", "secret")
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
        );
        let diff_policy = DifficultyPolicy::new("1.0", "0.1", "100.0")
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
        let config = ServerConfig::new(diff_policy);
        let server = Server::bind(
            "127.0.0.1:0",
            config,
            ServerDeps {
                pool,
                accounts,
                observer: None,
            },
        )
        .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let addr = server.local_addr();

        let mut client = TestClient::connect(addr);
        client.send("{\"id\":10,\"method\":\"mining.subscribe\",\"params\":[]}\n");
        let sub1 = client.read_line();
        assert!(
            sub1.contains("\"result\":[[["),
            "first subscribe must succeed: {sub1}"
        );

        client.send("{\"id\":11,\"method\":\"mining.subscribe\",\"params\":[]}\n");
        let sub2 = client.read_line();
        assert!(
            sub2.contains("\"error\":[20,\"Already subscribed\",null]"),
            "duplicate subscribe must be rejected: {sub2}"
        );

        client.send("{\"id\":12,\"method\":\"mining.submit\",\"params\":[\"miner2\",\"00000001\",\"00000001\",\"60000000\",\"00000000\"]}\n");
        let submit_unauth = client.read_line();
        assert!(
            submit_unauth.contains("\"error\":[24,\"Unauthorized worker\",null]"),
            "submit before auth must fail: {submit_unauth}"
        );

        server.shutdown();
    }

    #[test]
    fn stratum_v1_enforces_stale_jobs_and_extranonce_overflow() {
        let prev = Hash256::from_le_bytes(&[0x77; 32]);
        let candidate = Arc::new(sample_candidate(
            prev,
            CompactTarget::from_consensus(0x207f_ffff),
            5,
        ));
        let pool = build_pool(
            Arc::new(FakeMiningControl::default()),
            Arc::new(TestLedger::default()),
        );
        let installed = pool
            .install(candidate, Vec::new())
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let job_id = installed.job.id();

        let accounts = Arc::new(
            StaticAccountResolver::new()
                .with_account("miner3", "pass")
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
        );
        let diff_policy = DifficultyPolicy::new("1.0", "0.1", "100.0")
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
        let config = ServerConfig::new(diff_policy);
        let server = Server::bind(
            "127.0.0.1:0",
            config,
            ServerDeps {
                pool,
                accounts,
                observer: None,
            },
        )
        .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let addr = server.local_addr();

        let mut client = TestClient::connect(addr);
        client.send("{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n");
        let _ = client.read_line();
        client
            .send("{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"miner3\",\"pass\"]}\n");
        let _ = client.read_line();
        let _ = client.read_line();
        let _ = client.read_line();

        client.send("{\"id\":3,\"method\":\"mining.submit\",\"params\":[\"miner3\",\"ffffffff\",\"00000001\",\"60000000\",\"00000000\"]}\n");
        let stale_resp = client.read_line();
        assert!(
            stale_resp.contains("\"error\":[21,\"Job not found\",null]"),
            "stale/unknown job must reject: {stale_resp}"
        );

        let long_en2 = format!(
            "{{\"id\":4,\"method\":\"mining.submit\",\"params\":[\"miner3\",\"{job_id:08x}\",\"0000000000000001\",\"60000000\",\"00000000\"]}}\n",
            job_id = job_id.get(),
        );
        client.send(&long_en2);
        let en2_err = client.read_line();
        assert!(
            en2_err.contains("\"error\":[-32602,\"Invalid extranonce2 length\",null]"),
            "overflow extranonce must reject: {en2_err}"
        );

        server.shutdown();
    }

    #[test]
    fn stratum_v1_enforces_difficulty_policy_edges() {
        let pool = build_pool(
            Arc::new(FakeMiningControl::default()),
            Arc::new(TestLedger::default()),
        );
        let accounts = Arc::new(
            StaticAccountResolver::new()
                .with_account("miner4", "pass")
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
        );
        let diff_policy = DifficultyPolicy::new("1.0", "0.5", "10.0")
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
        let config = ServerConfig::new(diff_policy);
        let server = Server::bind(
            "127.0.0.1:0",
            config,
            ServerDeps {
                pool,
                accounts,
                observer: None,
            },
        )
        .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let addr = server.local_addr();

        let mut client = TestClient::connect(addr);

        client.send("{\"id\":1,\"method\":\"mining.suggest_difficulty\",\"params\":[0.49]}\n");
        let below = client.read_line();
        assert!(
            below.contains("\"error\":[20,\"Difficulty out of range\",null]"),
            "below min diff must be rejected: {below}"
        );

        client.send("{\"id\":2,\"method\":\"mining.suggest_difficulty\",\"params\":[0.5]}\n");
        let at_min = client.read_line();
        assert_eq!(
            at_min, "{\"id\":2,\"result\":true,\"error\":null}\n",
            "min edge must be accepted"
        );

        client.send("{\"id\":3,\"method\":\"mining.suggest_difficulty\",\"params\":[10.0]}\n");
        let at_max = client.read_line();
        assert_eq!(
            at_max, "{\"id\":3,\"result\":true,\"error\":null}\n",
            "max edge must be accepted"
        );

        client.send("{\"id\":4,\"method\":\"mining.suggest_difficulty\",\"params\":[10.01]}\n");
        let above = client.read_line();
        assert!(
            above.contains("\"error\":[20,\"Difficulty out of range\",null]"),
            "above max diff must be rejected: {above}"
        );

        server.shutdown();
    }

    #[test]
    fn stratum_v1_recovers_from_connection_reset_mid_message() {
        let pool = build_pool(
            Arc::new(FakeMiningControl::default()),
            Arc::new(TestLedger::default()),
        );
        let accounts = Arc::new(
            StaticAccountResolver::new()
                .with_account("miner5", "pass")
                .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
        );
        let diff_policy = DifficultyPolicy::new("1.0", "0.1", "100.0")
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
        let config = ServerConfig::new(diff_policy);
        let server = Server::bind(
            "127.0.0.1:0",
            config,
            ServerDeps {
                pool,
                accounts,
                observer: None,
            },
        )
        .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        let addr = server.local_addr();

        {
            let mut stream =
                TcpStream::connect(addr).unwrap_or_else(|error| panic!("connect failed: {error}"));
            stream
                .write_all(b"{\"id\":1,\"method\":\"mining.sub")
                .unwrap_or_else(|error| panic!("write failed: {error}"));
            let _ = stream.shutdown(std::net::Shutdown::Both);
            drop(stream);
        }

        thread::sleep(Duration::from_millis(50));

        let mut next_client = TestClient::connect(addr);
        next_client.send("{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n");
        let resp = next_client.read_line();
        assert!(
            resp.contains("\"result\":[[["),
            "subsequent client must succeed after peer reset: {resp}"
        );

        let report = server.shutdown();
        assert_eq!(report.sessions_joined, 2);
    }
}
#[cfg(feature = "pool-sv2")]
mod mining_pool_sv2 {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::mining::pool::stratum::sv2::{
        AuthorityKeypair, CloseReason, Connection, Error, Event, FLAG_REQUIRES_STANDARD_JOBS,
        FLAG_REQUIRES_VERSION_ROLLING, FLAG_REQUIRES_WORK_SELECTION, Limits,
        SUCCESS_FLAG_REQUIRES_FIXED_VERSION, ServerConfig, SessionError, TransportError,
        target_difficulty,
    };
    use crate::mining::pool::{
        BIP320_VERSION_MASK, Extranonce, ExtranonceLayout, Installed, Job, JobBook, JobBookConfig,
        JobId, ShareClass, ShareError, ShareTarget,
    };
    use crate::mining::{
        BlockTemplateRequest, BlockTemplateResult, BlockValidationResult, Candidate,
        CandidateContext, CoinbaseBudget, GenerateRequest, GeneratedBlock, MiningControl,
        MiningControlError, MiningInfo, STALE_PARENT_REASON, assemble_candidate,
    };
    use binary_sv2::{B064K, B0255, Decodable, Encodable, GetSize, Seq0255, Str0255, U256};
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_consensus::header_rules::compact_is_met_by;
    use bitcoin_rs_consensus::primitives::{
        Amount, BlockImage, CompactTarget, Hash256, Header, LockTime, Network, OutPoint, Script,
        Sequence, Tx, TxIn, TxOut, Txid, Witness, encode::double_sha256,
    };
    use bitcoin_rs_consensus::script::VerifyFlags;
    use bitcoin_rs_mempool::{
        AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, Mempool, MempoolGateway,
        MempoolLimits, SubmitOutcome,
    };
    use codec_sv2::{
        Decoded, Decrypted, Handshake, InitiatorSent, MessageFrame, NoiseDecoder, NoiseEncoder,
        TransportDecryptState, TransportEncryptState,
    };
    use common_messages_sv2::{
        MESSAGE_TYPE_RECONNECT, MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
        MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, Protocol, SetupConnection, SetupConnectionError,
        SetupConnectionSuccess,
    };
    use mining_sv2::{
        CloseChannel, MESSAGE_TYPE_CLOSE_CHANNEL, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
        MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB, MESSAGE_TYPE_NEW_MINING_JOB,
        MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
        MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, MESSAGE_TYPE_SET_CUSTOM_MINING_JOB,
        MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR, MESSAGE_TYPE_SET_TARGET,
        MESSAGE_TYPE_SUBMIT_SHARES_ERROR, MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
        MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
        MESSAGE_TYPE_UPDATE_CHANNEL, MESSAGE_TYPE_UPDATE_CHANNEL_ERROR, NewExtendedMiningJob,
        NewMiningJob, OpenExtendedMiningChannel, OpenExtendedMiningChannelSuccess,
        OpenMiningChannelError, OpenStandardMiningChannel, OpenStandardMiningChannelSuccess,
        SetCustomMiningJob, SetCustomMiningJobError, SetNewPrevHash, SetTarget, SubmitSharesError,
        SubmitSharesExtended, SubmitSharesStandard, SubmitSharesSuccess, UpdateChannel,
        UpdateChannelError,
    };
    use noise_sv2::{ELLSWIFT_ENCODING_SIZE, INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE, Initiator};
    use parking_lot::RwLock;
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    const PAYOUT: &[u8] = &[0x51];
    const ALL_ONES: [u8; 32] = [0xff; 32];
    const WHOLE: usize = 1 << 20;

    use crate::support::mining::TestError;

    type TestResult<T = ()> = Result<T, TestError>;

    fn context(height: u32, parent: u8) -> CandidateContext {
        CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[parent; 32]),
            height,
            version: 0x2000_0000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            min_time: 1_700_000_001,
            current_time: 1_700_000_600,
            locktime_cutoff: 1_700_000_000,
            staged_parent_mtp: 1_700_000_000,
            network: Network::Regtest,
            csv_active: true,
            segwit_active: true,
            max_weight: 4_000_000,
            max_size: 4_000_000,
            max_sigops: 80_000,
        }
    }

    const COIN_VALUE_SAT: u64 = 1_000_000;
    const ADMISSION_TIME: u64 = 1_700_000_000;

    fn wsh_true_script() -> Vec<u8> {
        let program: [u8; 32] = Sha256::digest([0x51_u8]).into();
        let mut script = vec![0x00, 0x20];
        script.extend_from_slice(&program);
        script
    }

    fn p2wpkh_script(label: u8) -> Vec<u8> {
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&[label; 20]);
        script
    }

    fn coin_outpoint(label: u8) -> OutPoint {
        let mut bytes = [0xc0_u8; 32];
        bytes[0] = label;
        OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), 0)
    }

    fn spend(label: u8) -> Tx {
        let mut tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: coin_outpoint(label),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![vec![0x51]]),
            }],
            outputs: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: Script::from_bytes(p2wpkh_script(label)),
            }],
            lock_time: LockTime::ZERO,
        };
        let fee = tx.vsize() * (2 + u64::from(label));
        tx.outputs[0].value = Amount::from_sat(COIN_VALUE_SAT - fee);
        tx
    }

    struct Coins(HashMap<OutPoint, TxOut>);

    impl AdmissionChain for Coins {
        fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
            let prevouts = tx
                .inputs
                .iter()
                .filter_map(|input| {
                    self.0
                        .get(&input.previous_output)
                        .map(|output| (input.previous_output, output.clone()))
                })
                .collect();
            Some(ChainAdmissionSnapshot {
                prevouts,
                height: 1,
                locktime_cutoff: 0,
                csv_active: false,
                next_block_script_flags: VerifyFlags::STANDARD,
                confirmed: false,
                ..ChainAdmissionSnapshot::default()
            })
        }
    }

    fn admitted_gateway(count: u8) -> MempoolGateway {
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            None,
        );
        let script = wsh_true_script();
        let coins = Coins(
            (1..=count)
                .map(|label| {
                    (
                        coin_outpoint(label),
                        TxOut {
                            value: Amount::from_sat(COIN_VALUE_SAT),
                            script_pubkey: Script::from_bytes(script.clone()),
                        },
                    )
                })
                .collect(),
        );
        for label in 1..=count {
            let outcome = gateway
                .submit_transaction(
                    Arc::new(spend(label)),
                    AdmissionOrigin::Rpc,
                    None,
                    ADMISSION_TIME,
                    &coins,
                )
                .unwrap_or_else(|error| {
                    panic!("gateway accepts the fixture submission: {error:?}")
                });
            assert!(
                matches!(outcome, SubmitOutcome::Committed(_)),
                "fixture transaction {label} was not committed: {outcome:?}"
            );
        }
        gateway
    }

    fn candidate(height: u32, parent: u8, txs: u8) -> Arc<Candidate> {
        let gateway = admitted_gateway(txs);
        let candidate = assemble_candidate(&context(height, parent), &gateway.read(), PAYOUT)
            .unwrap_or_else(|error| panic!("candidate assembles: {error:?}"));
        assert_eq!(candidate.transactions.len(), usize::from(txs));
        assert!(
            candidate
                .transactions
                .iter()
                .all(|entry| Hash256::from(entry.txid) != Hash256::from(entry.wtxid)),
            "fixture transactions carry witness data"
        );
        Arc::new(candidate)
    }

    fn book_config(version_mask: u32) -> JobBookConfig {
        JobBookConfig {
            budget: CoinbaseBudget {
                additional_size: 200,
                additional_sigops: 100,
            },
            extranonce: ExtranonceLayout::new(4, 4),
            coinbase_tag: b"/pool/".to_vec(),
            version_mask,
            ntime_forward_secs: 600,
            max_jobs: 8,
            max_sessions: 16,
            max_shares_per_job: 64,
        }
    }

    fn server_config() -> ServerConfig {
        ServerConfig::new(
            ShareTarget::from_le_bytes(ALL_ONES)
                .unwrap_or_else(|error| panic!("nonzero target: {error:?}")),
        )
    }

    fn fresh_authority() -> AuthorityKeypair {
        let secp = secp256k1::Secp256k1::new();
        let keypair = secp256k1::Keypair::new(&secp, &mut rand::thread_rng());
        AuthorityKeypair::from_bytes(
            keypair.x_only_public_key().0.serialize(),
            Zeroizing::new(keypair.secret_bytes()),
        )
    }

    #[derive(Debug)]
    struct Received {
        msg_type: u8,
        channel_msg: bool,
        payload: Vec<u8>,
    }

    fn parse<'a, T: Decodable<'a>>(received: &'a mut Received) -> T {
        binary_sv2::from_bytes(&mut received.payload)
            .unwrap_or_else(|error| panic!("message decodes: {error:?}"))
    }

    fn take_type(frames: &mut Vec<Received>, msg_type: u8) -> Received {
        let at = frames
            .iter()
            .position(|frame| frame.msg_type == msg_type)
            .unwrap_or_else(|| panic!("frame of that type present"));
        frames.remove(at)
    }

    fn types(frames: &[Received]) -> Vec<u8> {
        frames.iter().map(|frame| frame.msg_type).collect()
    }

    struct Client {
        enc: TransportEncryptState,
        dec: Option<TransportDecryptState>,
        encoder: NoiseEncoder,
        decoder: NoiseDecoder,
        inbuf: Vec<u8>,
    }

    impl Client {
        fn seal<T: Encodable + GetSize>(
            &mut self,
            msg_type: u8,
            channel_msg: bool,
            msg: T,
        ) -> Vec<u8> {
            self.seal_ext(msg_type, 0, channel_msg, msg)
        }

        fn seal_ext<T: Encodable + GetSize>(
            &mut self,
            msg_type: u8,
            extension_type: u16,
            channel_msg: bool,
            msg: T,
        ) -> Vec<u8> {
            let frame = MessageFrame::from_message(msg, msg_type, extension_type, channel_msg)
                .unwrap_or_else(|error| panic!("frame fits: {error:?}"));
            let encrypted = self
                .encoder
                .encode_transport(frame, &mut self.enc)
                .unwrap_or_else(|error| panic!("client encrypts: {error:?}"));
            let bytes: &[u8] = encrypted.as_ref();
            bytes.to_vec()
        }

        fn open(&mut self, bytes: &[u8]) -> Vec<Received> {
            self.inbuf.extend_from_slice(bytes);
            let mut out = Vec::new();
            loop {
                let state = self
                    .dec
                    .take()
                    .unwrap_or_else(|| panic!("decrypt state present"));
                match self
                    .decoder
                    .next_transport_frame(state)
                    .unwrap_or_else(|error| {
                        panic!("server frames authenticate and decode: {error:?}")
                    }) {
                    Decrypted::Frame(mut frame, state) => {
                        self.dec = Some(state);
                        let header = frame.header();
                        out.push(Received {
                            msg_type: header.msg_type(),
                            channel_msg: header.channel_msg(),
                            payload: frame.payload().to_vec(),
                        });
                    }
                    Decrypted::Incomplete(state) => {
                        self.dec = Some(state);
                        let want = self.decoder.read_len();
                        if self.inbuf.len() < want {
                            break;
                        }
                        let window = self.decoder.read_buf();
                        window.copy_from_slice(&self.inbuf[..want]);
                        self.inbuf.drain(..want);
                        self.decoder
                            .advance(want)
                            .unwrap_or_else(|error| panic!("feed window respected: {error:?}"));
                    }
                }
            }
            out
        }
    }

    fn handshake(
        server: &mut Connection,
        book: &mut JobBook,
        pinned: [u8; 32],
        chunk: usize,
    ) -> Result<Client, TestError> {
        let initiator = Handshake::initiator(Initiator::from_raw_k(pinned)?);
        let (act1, initiator) = initiator.step_0()?;
        let mut encoder = NoiseEncoder::new();
        let wire = encoder.encode_handshake(act1);
        let wire: &[u8] = wire.as_ref();
        assert_eq!(wire.len(), ELLSWIFT_ENCODING_SIZE);
        for piece in wire.chunks(chunk) {
            server.feed(piece, book)?;
        }
        let reply = server.take_transmit();
        assert_eq!(reply.len(), INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE);

        let mut decoder = NoiseDecoder::new();
        let mut offset = 0;
        let act2 = loop {
            match decoder.next_handshake_frame::<InitiatorSent>()? {
                Decoded::Frame(frame) => break frame,
                Decoded::Incomplete => {
                    let window = decoder.read_buf();
                    let end = offset + window.len();
                    window.copy_from_slice(&reply[offset..end]);
                    let len = window.len();
                    offset = end;
                    decoder
                        .advance(len)
                        .unwrap_or_else(|error| panic!("feed window respected: {error:?}"));
                }
            }
        };
        let act2: [u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] = act2
            .payload()
            .try_into()
            .map_err(|_| TestError::Missing("act 2 length"))?;
        let transport = initiator.step_2(act2)?;
        let (enc, dec) = transport.split();
        Ok(Client {
            enc,
            dec: Some(dec),
            encoder,
            decoder: NoiseDecoder::new(),
            inbuf: Vec::new(),
        })
    }

    #[derive(Clone, Copy)]
    struct ShareWork {
        job_id: u32,
        nonce: u32,
        ntime: u32,
        version: u32,
    }

    struct Wire {
        conn: Connection,
        book: JobBook,
        client: Client,
        chunk: usize,
    }

    impl Wire {
        fn with(chunk: usize, config: ServerConfig, version_mask: u32) -> Self {
            let authority = fresh_authority();
            let mut book = JobBook::new(book_config(version_mask))
                .unwrap_or_else(|error| panic!("book config: {error:?}"));
            let mut conn =
                Connection::accept(&authority, Duration::from_secs(3_600), config, &book)
                    .unwrap_or_else(|error| panic!("connection config: {error:?}"));
            let client = handshake(&mut conn, &mut book, *authority.public(), chunk)
                .unwrap_or_else(|error| panic!("handshake with the pinned authority: {error:?}"));
            Self {
                conn,
                book,
                client,
                chunk,
            }
        }

        fn new() -> Self {
            Self::with(WHOLE, server_config(), BIP320_VERSION_MASK)
        }

        fn try_exchange<T: Encodable + GetSize>(
            &mut self,
            msg_type: u8,
            channel_msg: bool,
            msg: T,
        ) -> Result<Vec<Received>, Error> {
            let bytes = self.client.seal(msg_type, channel_msg, msg);
            for piece in bytes.chunks(self.chunk) {
                self.conn.feed(piece, &mut self.book)?;
            }
            Ok(self.drain())
        }

        fn exchange<T: Encodable + GetSize>(
            &mut self,
            msg_type: u8,
            channel_msg: bool,
            msg: T,
        ) -> Vec<Received> {
            self.try_exchange(msg_type, channel_msg, msg)
                .unwrap_or_else(|error| panic!("server accepts the frame: {error:?}"))
        }

        fn drain(&mut self) -> Vec<Received> {
            let bytes = self.conn.take_transmit();
            self.client.open(&bytes)
        }

        fn events(&mut self) -> Vec<Event> {
            let mut out = Vec::new();
            while let Some(event) = self.conn.poll_event() {
                out.push(event);
            }
            out
        }

        fn setup(&mut self, protocol: Protocol, min: u16, max: u16, flags: u32) -> Vec<Received> {
            let msg = SetupConnection {
                protocol,
                min_version: min,
                max_version: max,
                flags,
                endpoint_host: Str0255::try_from("pool.invalid")
                    .unwrap_or_else(|error| panic!("short: {error:?}")),
                endpoint_port: 3333,
                vendor: Str0255::try_from("test-miner")
                    .unwrap_or_else(|error| panic!("short: {error:?}")),
                hardware_version: Str0255::try_from("sim-1")
                    .unwrap_or_else(|error| panic!("short: {error:?}")),
                firmware: Str0255::try_from("fw-0")
                    .unwrap_or_else(|error| panic!("short: {error:?}")),
                device_id: Str0255::try_from("").unwrap_or_else(|error| panic!("empty: {error:?}")),
            };
            self.exchange(MESSAGE_TYPE_SETUP_CONNECTION, false, msg)
        }

        fn setup_mining(&mut self, flags: u32) -> u32 {
            let mut frames = self.setup(Protocol::MiningProtocol, 2, 2, flags);
            assert_eq!(types(&frames), vec![MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS]);
            let mut frame = take_type(&mut frames, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS);
            assert!(!frame.channel_msg);
            let success: SetupConnectionSuccess = parse(&mut frame);
            assert_eq!(success.used_version, 2);
            success.flags
        }

        fn open_standard(
            &mut self,
            request_id: u32,
            user: &str,
            max_target: [u8; 32],
        ) -> Vec<Received> {
            let msg = OpenStandardMiningChannel {
                request_id,
                user_identity: Str0255::try_from(user)
                    .unwrap_or_else(|error| panic!("short: {error:?}")),
                nominal_hash_rate: 1.0e12,
                max_target: U256::from(&max_target),
            };
            self.exchange(MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, false, msg)
        }

        fn open_extended(
            &mut self,
            request_id: u32,
            user: &str,
            max_target: [u8; 32],
            min_extranonce_size: u16,
        ) -> Vec<Received> {
            let msg = OpenExtendedMiningChannel {
                request_id,
                user_identity: Str0255::try_from(user)
                    .unwrap_or_else(|error| panic!("short: {error:?}")),
                nominal_hash_rate: 5.0e12,
                max_target: U256::from(&max_target),
                min_extranonce_size,
            };
            self.exchange(MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, false, msg)
        }

        fn submit_standard(
            &mut self,
            channel_id: u32,
            sequence_number: u32,
            job_id: u32,
            nonce: u32,
            ntime: u32,
            version: u32,
        ) -> Vec<Received> {
            let msg = SubmitSharesStandard {
                channel_id,
                sequence_number,
                job_id,
                nonce,
                ntime,
                version,
            };
            self.exchange(MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, true, msg)
        }

        fn submit_extended(
            &mut self,
            channel_id: u32,
            sequence_number: u32,
            work: ShareWork,
            extranonce: &[u8],
        ) -> Vec<Received> {
            let msg = SubmitSharesExtended {
                channel_id,
                sequence_number,
                job_id: work.job_id,
                nonce: work.nonce,
                ntime: work.ntime,
                version: work.version,
                extranonce: binary_sv2::B032::new(extranonce)
                    .unwrap_or_else(|error| panic!("at most 32 bytes: {error:?}")),
            };
            self.exchange(MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, true, msg)
        }

        fn job(&self, job_id: u32) -> Arc<Job> {
            Arc::clone(
                self.book
                    .job(JobId::new(job_id))
                    .unwrap_or_else(|| panic!("owner retains the job")),
            )
        }
    }

    struct Opened {
        channel_id: u32,
        group_id: u32,
        prefix: Vec<u8>,
        target: [u8; 32],
        extranonce_size: Option<u16>,
    }

    fn read_open_standard(frames: &mut Vec<Received>) -> Opened {
        let mut frame = take_type(frames, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS);
        assert!(!frame.channel_msg);
        let ok: OpenStandardMiningChannelSuccess = parse(&mut frame);
        Opened {
            channel_id: ok.channel_id,
            group_id: ok.group_channel_id,
            prefix: ok.extranonce_prefix.as_bytes().to_vec(),
            target: *ok.target.as_array(),
            extranonce_size: None,
        }
    }

    fn read_open_extended(frames: &mut Vec<Received>) -> Opened {
        let mut frame = take_type(frames, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS);
        assert!(!frame.channel_msg);
        let ok: OpenExtendedMiningChannelSuccess = parse(&mut frame);
        Opened {
            channel_id: ok.channel_id,
            group_id: ok.group_channel_id,
            prefix: ok.extranonce_prefix.as_bytes().to_vec(),
            target: *ok.target.as_array(),
            extranonce_size: Some(ok.extranonce_size),
        }
    }

    struct StdJob {
        channel_id: u32,
        job_id: u32,
        ntime_start: Option<u32>,
        version: u32,
        merkle_root: [u8; 32],
    }

    fn read_std_job(frames: &mut Vec<Received>) -> StdJob {
        let mut frame = take_type(frames, MESSAGE_TYPE_NEW_MINING_JOB);
        assert!(frame.channel_msg);
        let msg: NewMiningJob = parse(&mut frame);
        StdJob {
            channel_id: msg.channel_id,
            job_id: msg.job_id,
            version: msg.version,
            merkle_root: *msg.merkle_root.as_array(),
            ntime_start: msg.ntime_start.into_inner(),
        }
    }

    struct ExtJob {
        channel_id: u32,
        job_id: u32,
        ntime_start: Option<u32>,
        version: u32,
        rolling_allowed: bool,
        path: Vec<[u8; 32]>,
        prefix: Vec<u8>,
        suffix: Vec<u8>,
    }

    fn read_ext_job(frames: &mut Vec<Received>) -> ExtJob {
        let mut frame = take_type(frames, MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB);
        assert!(frame.channel_msg);
        let msg: NewExtendedMiningJob = parse(&mut frame);
        ExtJob {
            channel_id: msg.channel_id,
            job_id: msg.job_id,
            version: msg.version,
            rolling_allowed: msg.version_rolling_allowed,
            path: msg
                .merkle_path
                .into_inner()
                .iter()
                .map(|hash| *hash.as_array())
                .collect(),
            prefix: msg.coinbase_tx_prefix.as_bytes().to_vec(),
            suffix: msg.coinbase_tx_suffix.as_bytes().to_vec(),
            ntime_start: msg.ntime_start.into_inner(),
        }
    }

    struct PrevHash {
        channel_id: u32,
        job_id: u32,
        prev: [u8; 32],
        ntime_start: u32,
        nbits: u32,
    }

    fn read_prev_hash(frames: &mut Vec<Received>) -> PrevHash {
        let mut frame = take_type(frames, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH);
        assert!(frame.channel_msg);
        let msg: SetNewPrevHash = parse(&mut frame);
        PrevHash {
            channel_id: msg.channel_id,
            job_id: msg.job_id,
            prev: *msg.prev_hash.as_array(),
            ntime_start: msg.ntime_start,
            nbits: msg.nbits,
        }
    }

    fn share_error(frames: &mut Vec<Received>) -> (u32, u32, String) {
        let mut frame = take_type(frames, MESSAGE_TYPE_SUBMIT_SHARES_ERROR);
        assert!(frame.channel_msg);
        let msg: SubmitSharesError = parse(&mut frame);
        (
            msg.channel_id,
            msg.sequence_number,
            msg.error_code.as_utf8_or_hex(),
        )
    }

    fn accepted(events: Vec<Event>) -> crate::mining::pool::stratum::sv2::ShareEvent {
        events
            .into_iter()
            .find_map(|event| match event {
                Event::ShareAccepted(share) => Some(share),
                _ => None,
            })
            .unwrap_or_else(|| panic!("a share was accepted"))
    }

    fn find_nonce(job: &Job, extranonce_prefix: &[u8], version: u32, class: ShareClass) -> u32 {
        let (session, rolled) = extranonce_prefix.split_at(job.extranonce_layout().session_len());
        (0..u32::MAX)
            .find(|nonce| {
                let header = job
                    .header(Extranonce { session, rolled }, job.ntime(), version, *nonce)
                    .unwrap_or_else(|error| panic!("header builds: {error:?}"));
                let is_block = compact_is_met_by(job.bits(), Hash256::from(header.compute_hash()));
                is_block == (class == ShareClass::Block)
            })
            .unwrap_or_else(|| panic!("a nonce of the wanted class exists"))
    }

    fn share_nonce(job: &Job, extranonce_prefix: &[u8], version: u32) -> u32 {
        find_nonce(job, extranonce_prefix, version, ShareClass::Share)
    }

    fn block_nonce(job: &Job, extranonce_prefix: &[u8], version: u32) -> u32 {
        find_nonce(job, extranonce_prefix, version, ShareClass::Block)
    }

    struct Standard {
        wire: Wire,
        opened: Opened,
        job: Arc<Job>,
    }

    fn standard_with_job() -> Standard {
        let mut wire = Wire::new();
        let installed = wire
            .book
            .install(candidate(100, 0xab, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        wire.setup_mining(FLAG_REQUIRES_STANDARD_JOBS);
        let mut frames = wire.open_standard(7, "alice.rig1", ALL_ONES);
        let opened = read_open_standard(&mut frames);
        let job = read_std_job(&mut frames);
        assert_eq!(job.job_id, installed.job.id().get());
        read_prev_hash(&mut frames);
        wire.events();
        Standard {
            wire,
            opened,
            job: installed.job,
        }
    }

    #[test]
    fn a_miner_pinning_another_authority_rejects_the_server_certificate() -> TestResult {
        let authority = fresh_authority();
        let impostor = fresh_authority();
        let mut book = JobBook::new(book_config(BIP320_VERSION_MASK))?;
        let mut conn =
            Connection::accept(&authority, Duration::from_secs(60), server_config(), &book)?;
        let outcome = handshake(&mut conn, &mut book, *impostor.public(), WHOLE);
        assert!(
            outcome.is_err(),
            "certificate signed by another authority must not verify"
        );
        Ok(())
    }

    #[test]
    fn a_mismatched_authority_key_pair_is_refused_at_accept() -> TestResult {
        let authority = fresh_authority();
        let other = fresh_authority();
        let mismatched =
            AuthorityKeypair::from_bytes(*authority.public(), Zeroizing::new([0x42; 32]));
        let book = JobBook::new(book_config(BIP320_VERSION_MASK))?;
        assert!(
            Connection::accept(&mismatched, Duration::from_secs(60), server_config(), &book)
                .is_err()
        );
        assert!(Connection::accept(&other, Duration::ZERO, server_config(), &book).is_err());
        Ok(())
    }

    #[test]
    fn byte_at_a_time_delivery_is_decoded_like_whole_reads() -> TestResult {
        let mut wire = Wire::with(1, server_config(), BIP320_VERSION_MASK);
        wire.book.install(candidate(100, 0xab, 2), Vec::new())?;
        wire.setup_mining(0);
        let mut frames = wire.open_standard(1, "carol", ALL_ONES);
        assert_eq!(
            types(&frames),
            vec![
                MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
                MESSAGE_TYPE_NEW_MINING_JOB,
                MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH
            ]
        );
        let opened = read_open_standard(&mut frames);
        assert_eq!(opened.prefix.len(), 8);
        Ok(())
    }

    #[test]
    fn a_flipped_ciphertext_bit_fails_the_mac_and_kills_the_connection() -> TestResult {
        let mut wire = Wire::new();
        wire.setup_mining(0);
        let mut bytes = wire.client.seal(
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
            false,
            OpenStandardMiningChannel {
                request_id: 1,
                user_identity: Str0255::try_from("mallory")?,
                nominal_hash_rate: 1.0,
                max_target: U256::from(&ALL_ONES),
            },
        );
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let outcome = wire.conn.feed(&bytes, &mut wire.book);
        assert!(
            matches!(outcome, Err(Error::Transport(TransportError::Decrypt(_)))),
            "tampered frame must fail authentication: {outcome:?}"
        );
        assert!(wire.conn.is_closing());
        assert!(matches!(
            wire.conn.feed(&[0], &mut wire.book),
            Err(Error::Closed)
        ));
        assert_eq!(wire.conn.session().channel_count(), 0);
        Ok(())
    }

    #[test]
    fn a_flipped_header_bit_also_fails_authentication() -> TestResult {
        let mut wire = Wire::new();
        wire.setup_mining(0);
        let mut bytes = wire.client.seal(
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
            false,
            OpenStandardMiningChannel {
                request_id: 1,
                user_identity: Str0255::try_from("mallory")?,
                nominal_hash_rate: 1.0,
                max_target: U256::from(&ALL_ONES),
            },
        );
        bytes[3] ^= 0x80;
        let outcome = wire.conn.feed(&bytes, &mut wire.book);
        assert!(matches!(
            outcome,
            Err(Error::Transport(TransportError::Decrypt(_)))
        ));
        Ok(())
    }

    #[test]
    fn a_replayed_ciphertext_does_not_authenticate_under_the_next_nonce() -> TestResult {
        let mut wire = Wire::new();
        wire.setup_mining(0);
        let bytes = wire.client.seal(
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
            false,
            OpenStandardMiningChannel {
                request_id: 1,
                user_identity: Str0255::try_from("replay")?,
                nominal_hash_rate: 1.0,
                max_target: U256::from(&ALL_ONES),
            },
        );
        wire.conn.feed(&bytes, &mut wire.book)?;
        assert_eq!(wire.conn.session().channel_count(), 1);
        let replay = wire.conn.feed(&bytes, &mut wire.book);
        assert!(matches!(
            replay,
            Err(Error::Transport(TransportError::Decrypt(_)))
        ));
        Ok(())
    }

    #[test]
    fn an_oversize_declaration_is_refused_before_it_is_buffered() -> TestResult {
        let mut config = server_config();
        config.limits = Limits {
            max_frame_payload: 128,
            ..Limits::DEFAULT
        };
        let mut wire = Wire::with(WHOLE, config, BIP320_VERSION_MASK);
        let long = "a".repeat(100);
        let oversize = SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host: Str0255::try_from(long.as_str())?,
            endpoint_port: 1,
            vendor: Str0255::try_from(long.as_str())?,
            hardware_version: Str0255::try_from(long.as_str())?,
            firmware: Str0255::try_from(long.as_str())?,
            device_id: Str0255::try_from(long.as_str())?,
        };
        let outcome = wire.try_exchange(MESSAGE_TYPE_SETUP_CONNECTION, false, oversize);
        assert!(
            matches!(
                outcome,
                Err(Error::Transport(TransportError::FrameTooLarge {
                    limit: 128
                }))
            ),
            "{outcome:?}"
        );
        Ok(())
    }

    #[test]
    fn limits_beyond_the_u24_wire_field_are_refused() {
        let mut config = server_config();
        config.limits = Limits {
            max_frame_payload: 0x0100_0000,
            ..Limits::DEFAULT
        };
        let authority = fresh_authority();
        let book = JobBook::new(book_config(BIP320_VERSION_MASK))
            .unwrap_or_else(|error| panic!("book: {error:?}"));
        assert!(
            Connection::accept(&authority, Duration::from_secs(60), config, &book).is_err(),
            "msg_length is a U24"
        );
    }

    #[test]
    fn setup_succeeds_and_advertises_only_what_it_supports() {
        let mut wire = Wire::new();
        let flags = wire.setup_mining(FLAG_REQUIRES_STANDARD_JOBS);
        assert_eq!(flags, 0, "rolling is available, so no fixed-version flag");
        let events = wire.events();
        assert!(matches!(
            events.as_slice(),
            [Event::SetupCompleted {
                flags: FLAG_REQUIRES_STANDARD_JOBS
            }]
        ));

        let mut fixed = Wire::with(WHOLE, server_config(), 0);
        let flags = fixed.setup_mining(0);
        assert_eq!(
            flags, SUCCESS_FLAG_REQUIRES_FIXED_VERSION,
            "an owner without a version mask tells miners the version is fixed"
        );
    }

    #[test]
    fn unsupported_flags_report_the_full_unsupported_set_and_close() {
        let mut wire = Wire::new();
        let mut frames = wire.setup(
            Protocol::MiningProtocol,
            2,
            2,
            FLAG_REQUIRES_WORK_SELECTION | FLAG_REQUIRES_STANDARD_JOBS,
        );
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_SETUP_CONNECTION_ERROR);
        let error: SetupConnectionError = parse(&mut frame);
        assert_eq!(error.flags, FLAG_REQUIRES_WORK_SELECTION);
        assert_eq!(
            error.error_code.as_utf8_or_hex(),
            "unsupported-feature-flags"
        );
        assert!(wire.conn.is_closing());
        assert!(matches!(
            wire.events().as_slice(),
            [Event::SetupRejected {
                code: "unsupported-feature-flags"
            }]
        ));

        let mut fixed = Wire::with(WHOLE, server_config(), 0);
        let mut frames = fixed.setup(
            Protocol::MiningProtocol,
            2,
            2,
            FLAG_REQUIRES_VERSION_ROLLING,
        );
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_SETUP_CONNECTION_ERROR);
        let error: SetupConnectionError = parse(&mut frame);
        assert_eq!(
            error.flags,
            FLAG_REQUIRES_WORK_SELECTION | FLAG_REQUIRES_VERSION_ROLLING
        );
    }

    #[test]
    fn job_declaration_and_template_distribution_are_not_served() {
        for protocol in [
            Protocol::JobDeclarationProtocol,
            Protocol::TemplateDistributionProtocol,
        ] {
            let mut wire = Wire::new();
            let mut frames = wire.setup(protocol, 2, 2, 0);
            let mut frame = take_type(&mut frames, MESSAGE_TYPE_SETUP_CONNECTION_ERROR);
            let error: SetupConnectionError = parse(&mut frame);
            assert_eq!(error.error_code.as_utf8_or_hex(), "unsupported-protocol");
            assert!(wire.conn.is_closing());
        }
    }

    #[test]
    fn a_version_range_without_two_is_refused() {
        let mut wire = Wire::new();
        let mut frames = wire.setup(Protocol::MiningProtocol, 3, 4, 0);
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_SETUP_CONNECTION_ERROR);
        let error: SetupConnectionError = parse(&mut frame);
        assert_eq!(
            error.error_code.as_utf8_or_hex(),
            "protocol-version-mismatch"
        );
    }

    #[test]
    fn nothing_but_setup_may_open_a_connection() {
        let mut wire = Wire::new();
        let outcome = wire.try_exchange(
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
            false,
            OpenStandardMiningChannel {
                request_id: 1,
                user_identity: Str0255::try_from("early")
                    .unwrap_or_else(|error| panic!("short: {error:?}")),
                nominal_hash_rate: 1.0,
                max_target: U256::from(&ALL_ONES),
            },
        );
        assert!(matches!(
            outcome,
            Err(Error::Session(SessionError::SetupRequired { .. }))
        ));
    }

    #[test]
    fn a_second_setup_and_a_wrong_channel_bit_are_protocol_violations() {
        let mut wire = Wire::new();
        wire.setup_mining(0);
        let again = wire.try_exchange(
            MESSAGE_TYPE_SETUP_CONNECTION,
            false,
            SetupConnection {
                protocol: Protocol::MiningProtocol,
                min_version: 2,
                max_version: 2,
                flags: 0,
                endpoint_host: Str0255::try_from("h")
                    .unwrap_or_else(|error| panic!("short: {error:?}")),
                endpoint_port: 1,
                vendor: Str0255::try_from("v").unwrap_or_else(|error| panic!("short: {error:?}")),
                hardware_version: Str0255::try_from("h")
                    .unwrap_or_else(|error| panic!("short: {error:?}")),
                firmware: Str0255::try_from("f").unwrap_or_else(|error| panic!("short: {error:?}")),
                device_id: Str0255::try_from("").unwrap_or_else(|error| panic!("empty: {error:?}")),
            },
        );
        assert!(matches!(
            again,
            Err(Error::Session(SessionError::DuplicateSetup))
        ));

        let mut wire = Wire::new();
        wire.setup_mining(0);
        let wrong_bit = wire.try_exchange(
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
            true,
            OpenStandardMiningChannel {
                request_id: 1,
                user_identity: Str0255::try_from("bit")
                    .unwrap_or_else(|error| panic!("short: {error:?}")),
                nominal_hash_rate: 1.0,
                max_target: U256::from(&ALL_ONES),
            },
        );
        assert!(matches!(
            wrong_bit,
            Err(Error::Session(SessionError::ChannelBit { .. }))
        ));
    }

    // POOL-09
    #[test]
    fn frames_of_an_unnegotiated_extension_are_discarded() {
        let mut wire = Wire::new();
        wire.setup_mining(0);
        let bytes = wire.client.seal_ext(
            MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
            0x4001,
            true,
            SubmitSharesStandard {
                channel_id: 1,
                sequence_number: 1,
                job_id: 1,
                nonce: 0,
                ntime: 0,
                version: 0,
            },
        );
        wire.conn
            .feed(&bytes, &mut wire.book)
            .unwrap_or_else(|error| panic!("ignored, not fatal: {error:?}"));
        assert!(wire.drain().is_empty());
        assert_eq!(wire.conn.session().ignored_extension_frames(), 1);
    }

    #[test]
    fn standard_channel_gets_a_future_job_then_the_prev_hash_that_activates_it() {
        let mut wire = Wire::new();
        let installed = wire
            .book
            .install(candidate(100, 0xab, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        wire.setup_mining(0);
        let mut frames = wire.open_standard(7, "alice.rig1", ALL_ONES);
        assert_eq!(
            types(&frames),
            vec![
                MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
                MESSAGE_TYPE_NEW_MINING_JOB,
                MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH
            ],
            "the first message after open is a future job, then its prev hash"
        );
        let opened = read_open_standard(&mut frames);
        let job = read_std_job(&mut frames);
        let prev = read_prev_hash(&mut frames);
        let owned = &installed.job;

        assert_ne!(opened.group_id, opened.channel_id);
        assert_eq!(opened.target, ALL_ONES);
        assert_eq!(
            opened.prefix.len(),
            8,
            "session prefix plus pool-fixed rolled bytes"
        );
        assert_eq!(job.channel_id, opened.channel_id);
        assert_eq!(job.job_id, owned.id().get());
        assert_eq!(job.ntime_start, None, "future job: ntime_start unset");
        assert_eq!(job.version, owned.version());
        let (session, rolled) = opened.prefix.split_at(4);
        let root = owned
            .merkle_root(Extranonce { session, rolled })
            .unwrap_or_else(|error| panic!("owner projects the merkle root: {error:?}"));
        assert_eq!(job.merkle_root, *root.as_byte_array());

        assert_eq!(prev.channel_id, opened.channel_id);
        assert_eq!(prev.job_id, owned.id().get());
        assert_eq!(prev.prev, *owned.previous_block_hash().as_bytes());
        assert_eq!(prev.nbits, 0x207f_ffff);
        assert_eq!(prev.ntime_start, owned.ntime());

        let events = wire.events();
        assert!(events.iter().any(|event| matches!(
            event,
            Event::ChannelOpened { channel_id, .. } if *channel_id == opened.channel_id
        )));
        assert_eq!(wire.book.session_count(), 1);
    }

    #[test]
    fn extended_channel_job_rebuilds_the_owners_merkle_root_from_the_wire_fields() {
        let mut wire = Wire::new();
        let installed = wire
            .book
            .install(candidate(100, 0xab, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        wire.setup_mining(0);
        let mut frames = wire.open_extended(9, "bob.farm", ALL_ONES, 4);
        let opened = read_open_extended(&mut frames);
        assert_eq!(opened.extranonce_size, Some(4));
        assert_eq!(opened.prefix.len(), 4);
        let job = read_ext_job(&mut frames);
        let prev = read_prev_hash(&mut frames);
        assert_eq!(job.channel_id, opened.channel_id);
        assert_eq!(job.ntime_start, None);
        assert_eq!(job.version, installed.job.version());
        assert!(job.rolling_allowed, "the owner has a version mask");
        assert_eq!(job.path.len(), 2, "coinbase plus two transactions");
        assert_eq!(prev.job_id, job.job_id);

        let rolled = [9_u8, 9, 9, 9];
        let mut coinbase = job.prefix.clone();
        coinbase.extend_from_slice(&opened.prefix);
        coinbase.extend_from_slice(&rolled);
        coinbase.extend_from_slice(&job.suffix);
        let mut root = double_sha256(&coinbase);
        for leaf in &job.path {
            let mut joined = root.as_byte_array().to_vec();
            joined.extend_from_slice(leaf);
            root = double_sha256(&joined);
        }
        let owned = installed
            .job
            .merkle_root(Extranonce {
                session: &opened.prefix,
                rolled: &rolled,
            })
            .unwrap_or_else(|error| panic!("owner root: {error:?}"));
        assert_eq!(
            root, owned,
            "wire coinbase halves and path reproduce the owner's root"
        );
    }

    #[test]
    fn extended_share_is_validated_by_the_owner_and_extranonce_length_is_enforced() {
        let mut wire = Wire::new();
        let installed = wire
            .book
            .install(candidate(100, 0xab, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        wire.setup_mining(0);
        let mut frames = wire.open_extended(9, "bob.farm", ALL_ONES, 4);
        let opened = read_open_extended(&mut frames);
        let job = installed.job;
        let rolled = [9_u8, 9, 9, 9];
        let mut full = opened.prefix.clone();
        full.extend_from_slice(&rolled);
        let nonce = share_nonce(&job, &full, job.version());

        let mut frames = wire.submit_extended(
            opened.channel_id,
            1,
            ShareWork {
                job_id: job.id().get(),
                nonce,
                ntime: job.ntime(),
                version: job.version(),
            },
            &rolled,
        );
        assert!(frames.is_empty(), "no Success before the ledger confirms");
        let share = accepted(wire.events());
        assert_eq!(share.channel_id, opened.channel_id);
        assert_eq!(share.outcome.extranonce, full);

        let mut short = wire.submit_extended(
            opened.channel_id,
            2,
            ShareWork {
                job_id: job.id().get(),
                nonce,
                ntime: job.ntime(),
                version: job.version(),
            },
            &rolled[..3],
        );
        let (_, sequence, code) = share_error(&mut short);
        assert_eq!((sequence, code.as_str()), (2, "bad-extranonce-size"));
        frames.clear();
    }

    #[test]
    fn min_extranonce_size_beyond_the_owners_rolled_length_is_refused() {
        let mut wire = Wire::new();
        wire.setup_mining(0);
        let mut frames = wire.open_extended(3, "greedy", ALL_ONES, 5);
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR);
        let error: OpenMiningChannelError = parse(&mut frame);
        assert_eq!(error.request_id, 3);
        assert_eq!(
            error.error_code.as_utf8_or_hex(),
            "min-extranonce-size-too-large"
        );
        assert_eq!(
            wire.book.session_count(),
            0,
            "a refused open holds no session"
        );
    }

    #[test]
    fn open_refusals_use_official_codes_and_hold_no_session() {
        let mut wire = Wire::new();
        wire.setup_mining(FLAG_REQUIRES_STANDARD_JOBS);
        let mut frames = wire.open_extended(1, "ext", ALL_ONES, 0);
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR);
        let error: OpenMiningChannelError = parse(&mut frame);
        assert_eq!(
            error.error_code.as_utf8_or_hex(),
            "extended-channels-not-supported-for-standard-jobs"
        );

        let mut frames = wire.open_standard(2, "", ALL_ONES);
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR);
        let error: OpenMiningChannelError = parse(&mut frame);
        assert_eq!(error.error_code.as_utf8_or_hex(), "invalid-user-identity");

        let mut frames = wire.open_standard(3, "zero", [0; 32]);
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR);
        let error: OpenMiningChannelError = parse(&mut frame);
        assert_eq!(error.error_code.as_utf8_or_hex(), "max-target-out-of-range");
        assert_eq!(wire.book.session_count(), 0);
    }

    #[test]
    fn channel_capacity_is_bounded_by_the_connection_and_by_the_owner() {
        let mut config = server_config();
        config.limits = Limits {
            max_channels: 2,
            ..Limits::DEFAULT
        };
        let mut wire = Wire::with(WHOLE, config, BIP320_VERSION_MASK);
        wire.setup_mining(0);
        for request_id in 0..2 {
            let mut frames = wire.open_standard(request_id, "w", ALL_ONES);
            read_open_standard(&mut frames);
        }
        let mut frames = wire.open_standard(9, "w", ALL_ONES);
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR);
        let error: OpenMiningChannelError = parse(&mut frame);
        assert_eq!(
            error.error_code.as_utf8_or_hex(),
            "channel-capacity-exhausted"
        );
        assert_eq!(wire.book.session_count(), 2);
    }

    #[test]
    fn channel_ids_are_unique_and_distinct_from_the_group_id() {
        let mut wire = Wire::new();
        wire.setup_mining(0);
        let mut seen = Vec::new();
        let mut group = None;
        for request_id in 0..4 {
            let mut frames = wire.open_standard(request_id, "w", ALL_ONES);
            let opened = read_open_standard(&mut frames);
            assert!(!seen.contains(&opened.channel_id));
            assert_ne!(opened.channel_id, opened.group_id);
            assert_eq!(*group.get_or_insert(opened.group_id), opened.group_id);
            seen.push(opened.channel_id);
        }
        assert!(group.is_some_and(|id| !seen.contains(&id)));
        assert_eq!(wire.conn.session().channel_count(), 4);
        assert_eq!(wire.book.session_count(), 4);
    }

    #[test]
    fn accepted_share_is_held_until_the_ledger_confirms_then_acknowledged() {
        let mut s = standard_with_job();
        let version = s.job.version();
        let nonce = share_nonce(&s.job, &s.opened.prefix, version);
        let frames = s.wire.submit_standard(
            s.opened.channel_id,
            1,
            s.job.id().get(),
            nonce,
            s.job.ntime(),
            version,
        );
        assert!(
            frames.is_empty(),
            "no Success before the ledger records the share"
        );
        let share = accepted(s.wire.events());
        let hash = share.outcome.hash;
        assert_eq!(share.outcome.class, ShareClass::Share);
        assert_eq!(share.sequence_number, 1);
        assert_eq!(s.wire.conn.session().pending_acks(), 1);
        let work = share.outcome.work.as_u128();
        assert_eq!(work, Some(1), "an all-ones target is one hash per share");

        assert!(
            s.wire
                .conn
                .confirm_share(share.ticket)
                .unwrap_or_else(|error| panic!("flushes: {error:?}"))
        );
        assert_eq!(s.wire.conn.session().pending_acks(), 0);
        let mut frames = s.wire.drain();
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS);
        assert!(frame.channel_msg);
        let ok: SubmitSharesSuccess = parse(&mut frame);
        assert_eq!(ok.channel_id, s.opened.channel_id);
        assert_eq!(ok.last_sequence_number, 1);
        assert_eq!(ok.new_submits_accepted_count, 1);
        assert_eq!(
            ok.new_shares_sum, 1,
            "new_shares_sum carries assigned difficulty (clamped to 1 for all-ones), NOT raw work (scaled by 2^32)"
        );
        assert_eq!(
            hash,
            share.outcome.header.compute_hash(),
            "the header hash is the ledger idempotency key"
        );

        assert!(
            !s.wire
                .conn
                .confirm_share(share.ticket)
                .unwrap_or_else(|error| panic!("no-op: {error:?}"))
        );
        assert!(s.wire.drain().is_empty());
    }

    #[test]
    fn target_difficulty_converts_share_targets_to_integer_difficulty_without_raw_hash_scaling()
    -> TestResult {
        assert_eq!(target_difficulty(ShareTarget::from_pool_difficulty(1)?), 1);
        assert_eq!(
            target_difficulty(ShareTarget::from_pool_difficulty(42)?),
            42
        );
        assert_eq!(
            target_difficulty(ShareTarget::from_pool_difficulty(16_384)?),
            16_384
        );
        assert_eq!(
            target_difficulty(ShareTarget::from_pool_difficulty(1_000_000)?),
            1_000_000
        );
        assert_eq!(
            target_difficulty(ShareTarget::from_le_bytes(ALL_ONES)?),
            1,
            "sub-1 target difficulty floors at 1 unit of acknowledged work"
        );
        Ok(())
    }

    #[test]
    fn the_host_can_refuse_to_credit_a_share() {
        let mut s = standard_with_job();
        let version = s.job.version();
        let nonce = share_nonce(&s.job, &s.opened.prefix, version);
        s.wire.submit_standard(
            s.opened.channel_id,
            1,
            s.job.id().get(),
            nonce,
            s.job.ntime(),
            version,
        );
        let share = accepted(s.wire.events());
        assert!(
            s.wire
                .conn
                .reject_share(
                    share.ticket,
                    crate::mining::pool::stratum::sv2::ERROR_CODE_SHARE_NOT_RECORDED
                )
                .unwrap_or_else(|error| panic!("flushes: {error:?}"))
        );
        let mut frames = s.wire.drain();
        let (channel, sequence, code) = share_error(&mut frames);
        assert_eq!(
            (channel, sequence, code.as_str()),
            (s.opened.channel_id, 1, "share-not-recorded")
        );
    }

    #[test]
    fn a_block_candidate_carries_the_owners_full_block_for_the_node_submit_path() {
        let mut s = standard_with_job();
        let version = s.job.version();
        let nonce = block_nonce(&s.job, &s.opened.prefix, version);
        s.wire.submit_standard(
            s.opened.channel_id,
            1,
            s.job.id().get(),
            nonce,
            s.job.ntime(),
            version,
        );
        let pending = s
            .wire
            .events()
            .into_iter()
            .find_map(|event| match event {
                Event::BlockFound(pending) => Some(pending),
                _ => None,
            })
            .unwrap_or_else(|| panic!("a block is surfaced as pending host work"));
        let found = pending.found_block();
        assert_eq!(found.share.class, ShareClass::Block);
        assert_eq!(found.share.hash, found.block.header.compute_hash());
        assert_eq!(found.block.header.nonce, nonce);
        assert!(found.raw.len() > 80, "serialized block, not a bare header");
        assert_eq!(found.coinbase_value, s.job.coinbase_value());
        assert!(matches!(
            s.wire.conn.confirm_share(pending.ticket()),
            Err(Error::Session(SessionError::BlockRequiresSubmission))
        ));
        assert!(s.wire.drain().is_empty());
    }

    #[test]
    fn duplicate_share_is_refused_with_the_official_code() {
        let mut s = standard_with_job();
        let version = s.job.version();
        let nonce = share_nonce(&s.job, &s.opened.prefix, version);
        let job_id = s.job.id().get();
        s.wire.submit_standard(
            s.opened.channel_id,
            1,
            job_id,
            nonce,
            s.job.ntime(),
            version,
        );
        accepted(s.wire.events());
        let mut frames = s.wire.submit_standard(
            s.opened.channel_id,
            2,
            job_id,
            nonce,
            s.job.ntime(),
            version,
        );
        let (_, sequence, code) = share_error(&mut frames);
        assert_eq!((sequence, code.as_str()), (2, "duplicate-share"));
        let events = s.wire.events();
        assert!(matches!(
            events.as_slice(),
            [Event::ShareRejected {
                code: "duplicate-share",
                cause: Some(ShareError::Duplicate { .. }),
                ..
            }]
        ));
    }

    #[test]
    fn a_share_above_the_channel_target_is_difficulty_too_low() {
        let mut wire = Wire::new();
        let installed = wire
            .book
            .install(candidate(100, 0xab, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        wire.setup_mining(0);
        let mut tight = [0_u8; 32];
        tight[8] = 1;
        let mut frames = wire.open_standard(1, "tight", tight);
        let opened = read_open_standard(&mut frames);
        assert_eq!(
            opened.target, tight,
            "the channel never starts easier than max_target"
        );
        let job = installed.job;
        let nonce = share_nonce(&job, &opened.prefix, job.version());
        let mut frames = wire.submit_standard(
            opened.channel_id,
            1,
            job.id().get(),
            nonce,
            job.ntime(),
            job.version(),
        );
        let (_, _, code) = share_error(&mut frames);
        assert_eq!(code, "difficulty-too-low");
    }

    #[test]
    fn stale_jobs_unknown_jobs_and_closed_channels_use_official_codes() {
        let mut s = standard_with_job();
        let job_id = s.job.id().get();
        let version = s.job.version();
        let nonce = share_nonce(&s.job, &s.opened.prefix, version);

        let mut frames =
            s.wire
                .submit_standard(s.opened.channel_id, 1, 999, nonce, s.job.ntime(), version);
        assert_eq!(share_error(&mut frames).2, "invalid-job-id");

        let mut frames = s
            .wire
            .submit_standard(4242, 1, job_id, nonce, s.job.ntime(), version);
        assert_eq!(share_error(&mut frames).2, "invalid-channel-id");

        let installed = s
            .wire
            .book
            .install(candidate(101, 0xcd, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        assert!(installed.fresh && installed.clean_jobs);
        assert!(installed.invalidated.contains(&s.job.id()));
        s.wire
            .conn
            .announce(&installed)
            .unwrap_or_else(|error| panic!("announce: {error:?}"));
        let mut frames = s.wire.drain();
        assert_eq!(
            types(&frames),
            vec![
                MESSAGE_TYPE_NEW_MINING_JOB,
                MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH
            ]
        );
        let mut frames_stale = s.wire.submit_standard(
            s.opened.channel_id,
            2,
            job_id,
            nonce,
            s.job.ntime(),
            version,
        );
        let (_, _, code) = share_error(&mut frames_stale);
        assert_eq!(code, "stale-share");
        frames.clear();
    }

    #[test]
    fn clean_jobs_send_a_future_job_and_a_prev_hash_but_a_refresh_does_not() {
        let mut s = standard_with_job();
        let old_job = s.job.id().get();
        let version = s.job.version();
        let nonce = share_nonce(&s.job, &s.opened.prefix, version);

        let refresh_candidate = candidate(100, 0xab, 1);
        let refreshed = s
            .wire
            .book
            .install(Arc::clone(&refresh_candidate), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        assert!(refreshed.fresh);
        assert!(!refreshed.clean_jobs);
        s.wire
            .conn
            .announce(&refreshed)
            .unwrap_or_else(|error| panic!("announce: {error:?}"));
        let mut frames = s.wire.drain();
        assert_eq!(types(&frames), vec![MESSAGE_TYPE_NEW_MINING_JOB]);
        let job = read_std_job(&mut frames);
        assert_eq!(job.job_id, refreshed.job.id().get());
        assert_eq!(
            job.ntime_start,
            Some(refreshed.job.ntime()),
            "active: ntime_start set"
        );

        s.wire.submit_standard(
            s.opened.channel_id,
            1,
            old_job,
            nonce,
            s.job.ntime(),
            version,
        );
        accepted(s.wire.events());

        s.wire
            .conn
            .announce(&refreshed)
            .unwrap_or_else(|error| panic!("announce: {error:?}"));
        assert!(s.wire.drain().is_empty());

        let unchanged = s
            .wire
            .book
            .install(refresh_candidate, Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        assert!(!unchanged.fresh);
        s.wire
            .conn
            .announce(&unchanged)
            .unwrap_or_else(|error| panic!("announce: {error:?}"));
        assert!(s.wire.drain().is_empty());
    }

    #[test]
    fn sequence_numbers_must_increase_per_channel() {
        let mut s = standard_with_job();
        let ntime = s.job.ntime();
        let version = s.job.version();
        let channel = s.opened.channel_id;

        let mut frames = s.wire.submit_standard(channel, 5, 999, 0, ntime, version);
        assert_eq!(share_error(&mut frames).2, "invalid-job-id");
        for stale_sequence in [5, 4, 0] {
            let mut frames =
                s.wire
                    .submit_standard(channel, stale_sequence, 999, 0, ntime, version);
            let (_, sequence, code) = share_error(&mut frames);
            assert_eq!(
                (sequence, code.as_str()),
                (stale_sequence, "invalid-sequence-number")
            );
        }
        let mut frames = s.wire.submit_standard(channel, 6, 999, 0, ntime, version);
        assert_eq!(share_error(&mut frames).2, "invalid-job-id");
    }

    #[test]
    fn ntime_below_the_announced_start_is_refused() {
        let mut s = standard_with_job();
        let version = s.job.version();
        let nonce = share_nonce(&s.job, &s.opened.prefix, version);
        let mut frames = s.wire.submit_standard(
            s.opened.channel_id,
            1,
            s.job.id().get(),
            nonce,
            s.job.ntime() - 1,
            version,
        );
        assert_eq!(share_error(&mut frames).2, "invalid-share");
    }

    #[test]
    fn version_rolling_is_accepted_inside_the_mask_and_refused_outside_it() {
        let mut s = standard_with_job();
        let job_id = s.job.id().get();
        let rolled_version = s.job.version() | 0x0000_2000;
        let nonce = share_nonce(&s.job, &s.opened.prefix, rolled_version);
        s.wire.submit_standard(
            s.opened.channel_id,
            1,
            job_id,
            nonce,
            s.job.ntime(),
            rolled_version,
        );
        let share = accepted(s.wire.events());
        assert_eq!(
            share.outcome.header.version,
            i32::from_le_bytes(rolled_version.to_le_bytes())
        );

        let outside = s.job.version() | 0x0000_0001;
        let mut frames = s.wire.submit_standard(
            s.opened.channel_id,
            2,
            job_id,
            nonce,
            s.job.ntime(),
            outside,
        );
        assert_eq!(
            share_error(&mut frames).2,
            "invalid-non-rollable-version-bit"
        );
    }

    #[test]
    fn a_fixed_version_owner_refuses_any_version_change() {
        let mut wire = Wire::with(WHOLE, server_config(), 0);
        let installed = wire
            .book
            .install(candidate(100, 0xab, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        wire.setup_mining(0);
        let mut frames = wire.open_standard(1, "fixed", ALL_ONES);
        let opened = read_open_standard(&mut frames);
        let job = installed.job;
        let mut frames = wire.submit_standard(
            opened.channel_id,
            1,
            job.id().get(),
            0,
            job.ntime(),
            job.version() | 0x2000,
        );
        assert_eq!(share_error(&mut frames).2, "version-rolling-not-allowed");
    }

    #[test]
    fn unconfirmed_shares_are_bounded_and_a_busy_refusal_is_not_recorded() {
        let mut config = server_config();
        config.limits = Limits {
            max_pending_acks: 1,
            ..Limits::DEFAULT
        };
        let mut wire = Wire::with(WHOLE, config, BIP320_VERSION_MASK);
        let installed = wire
            .book
            .install(candidate(100, 0xab, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        wire.setup_mining(0);
        let mut frames = wire.open_standard(1, "busy", ALL_ONES);
        let opened = read_open_standard(&mut frames);
        wire.events();
        let job = installed.job;
        let version = job.version();
        let first = share_nonce(&job, &opened.prefix, version);
        let (session, rolled) = opened.prefix.split_at(4);
        let second = (first + 1..u32::MAX)
            .find(|nonce| {
                let header = job
                    .header(Extranonce { session, rolled }, job.ntime(), version, *nonce)
                    .unwrap_or_else(|error| panic!("header: {error:?}"));
                !compact_is_met_by(job.bits(), Hash256::from(header.compute_hash()))
            })
            .unwrap_or_else(|| panic!("second nonce"));

        wire.submit_standard(
            opened.channel_id,
            1,
            job.id().get(),
            first,
            job.ntime(),
            version,
        );
        let share = accepted(wire.events());
        let mut frames = wire.submit_standard(
            opened.channel_id,
            2,
            job.id().get(),
            second,
            job.ntime(),
            version,
        );
        assert_eq!(share_error(&mut frames).2, "pool-busy");

        wire.conn
            .confirm_share(share.ticket)
            .unwrap_or_else(|error| panic!("confirm: {error:?}"));
        wire.drain();
        wire.submit_standard(
            opened.channel_id,
            3,
            job.id().get(),
            second,
            job.ntime(),
            version,
        );
        accepted(wire.events());
    }

    #[test]
    fn expired_tickets_unburn_for_retry() {
        let mut config = server_config();
        config.limits = Limits {
            pending_ack_timeout: Duration::ZERO,
            ..Limits::DEFAULT
        };
        let mut wire = Wire::with(WHOLE, config, BIP320_VERSION_MASK);
        let installed = wire
            .book
            .install(candidate(100, 0xab, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        wire.setup_mining(0);
        let mut frames = wire.open_standard(1, "expiry", ALL_ONES);
        let opened = read_open_standard(&mut frames);
        wire.events();
        let job = installed.job;
        let version = job.version();
        let nonce = share_nonce(&job, &opened.prefix, version);
        wire.submit_standard(
            opened.channel_id,
            1,
            job.id().get(),
            nonce,
            job.ntime(),
            version,
        );
        let share = accepted(wire.events());
        let expired = wire
            .conn
            .session_mut()
            .expire_tickets(&mut wire.book, Instant::now());
        assert_eq!(expired, vec![share.ticket]);
        assert_eq!(wire.conn.session().pending_acks(), 0);
        wire.submit_standard(
            opened.channel_id,
            2,
            job.id().get(),
            nonce,
            job.ntime(),
            version,
        );
        accepted(wire.events());
    }

    #[test]
    fn peer_close_releases_the_session_and_cancels_pending_acknowledgements() {
        let mut s = standard_with_job();
        let version = s.job.version();
        let nonce = share_nonce(&s.job, &s.opened.prefix, version);
        s.wire.submit_standard(
            s.opened.channel_id,
            1,
            s.job.id().get(),
            nonce,
            s.job.ntime(),
            version,
        );
        let share = accepted(s.wire.events());
        assert_eq!(s.wire.book.session_count(), 1);

        let frames = s.wire.exchange(
            MESSAGE_TYPE_CLOSE_CHANNEL,
            true,
            CloseChannel {
                channel_id: s.opened.channel_id,
                reason_code: Str0255::try_from("shutdown")
                    .unwrap_or_else(|error| panic!("short: {error:?}")),
            },
        );
        assert!(frames.is_empty());
        assert_eq!(
            s.wire.book.session_count(),
            0,
            "the owner's session is released"
        );
        assert_eq!(s.wire.conn.session().channel_count(), 0);
        assert_eq!(s.wire.conn.session().pending_acks(), 0);
        assert!(matches!(
            s.wire.events().as_slice(),
            [Event::ChannelClosed {
                reason: CloseReason::Peer,
                ..
            }]
        ));

        assert!(
            !s.wire
                .conn
                .confirm_share(share.ticket)
                .unwrap_or_else(|error| panic!("no-op: {error:?}"))
        );
        assert!(s.wire.drain().is_empty());
        let mut frames = s.wire.submit_standard(
            s.opened.channel_id,
            2,
            s.job.id().get(),
            nonce,
            s.job.ntime(),
            version,
        );
        assert_eq!(share_error(&mut frames).2, "invalid-channel-id");
    }

    #[test]
    fn closing_the_group_channel_closes_every_member() {
        let mut wire = Wire::new();
        wire.setup_mining(0);
        let mut frames = wire.open_standard(1, "a", ALL_ONES);
        let first = read_open_standard(&mut frames);
        let mut frames = wire.open_extended(2, "b", ALL_ONES, 4);
        let second = read_open_extended(&mut frames);
        assert_eq!(first.group_id, second.group_id);
        assert_eq!(wire.book.session_count(), 2);

        wire.exchange(
            MESSAGE_TYPE_CLOSE_CHANNEL,
            true,
            CloseChannel {
                channel_id: first.group_id,
                reason_code: Str0255::try_from("group-down")
                    .unwrap_or_else(|error| panic!("short: {error:?}")),
            },
        );
        assert_eq!(wire.conn.session().channel_count(), 0);
        assert_eq!(wire.book.session_count(), 0);
    }

    #[test]
    fn host_close_tells_the_miner_and_release_is_idempotent() {
        let mut wire = Wire::new();
        wire.setup_mining(0);
        let mut frames = wire.open_standard(1, "a", ALL_ONES);
        let opened = read_open_standard(&mut frames);
        wire.conn
            .close_channel(&mut wire.book, opened.channel_id, "pool-maintenance")
            .unwrap_or_else(|error| panic!("close: {error:?}"));
        let mut frames = wire.drain();
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_CLOSE_CHANNEL);
        let close: CloseChannel = parse(&mut frame);
        assert_eq!(close.channel_id, opened.channel_id);
        assert_eq!(close.reason_code.as_utf8_or_hex(), "pool-maintenance");
        assert_eq!(wire.book.session_count(), 0);

        wire.conn.release(&mut wire.book);
        wire.conn.release(&mut wire.book);
        assert_eq!(wire.book.session_count(), 0);
    }

    #[test]
    fn a_dropped_connection_releases_every_owner_session() {
        let mut wire = Wire::new();
        wire.setup_mining(0);
        for request_id in 0..3 {
            wire.open_standard(request_id, "w", ALL_ONES);
        }
        assert_eq!(wire.book.session_count(), 3);
        wire.conn.release(&mut wire.book);
        assert_eq!(wire.book.session_count(), 0);
    }

    #[test]
    fn update_channel_reflects_a_smaller_max_target_in_a_set_target() {
        let mut s = standard_with_job();
        let mut smaller = [0_u8; 32];
        smaller[10] = 1;
        let frames = s.wire.exchange(
            MESSAGE_TYPE_UPDATE_CHANNEL,
            true,
            UpdateChannel {
                channel_id: s.opened.channel_id,
                nominal_hash_rate: 2.0e12,
                max_target: U256::from(&smaller),
            },
        );
        let mut frames = frames;
        assert_eq!(types(&frames), vec![MESSAGE_TYPE_SET_TARGET]);
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_SET_TARGET);
        assert!(frame.channel_msg);
        let target: SetTarget = parse(&mut frame);
        assert_eq!(target.channel_id, s.opened.channel_id);
        assert_eq!(*target.target.as_array(), smaller);

        let frames = s.wire.exchange(
            MESSAGE_TYPE_UPDATE_CHANNEL,
            true,
            UpdateChannel {
                channel_id: s.opened.channel_id,
                nominal_hash_rate: 2.0e12,
                max_target: U256::from(&ALL_ONES),
            },
        );
        assert!(frames.is_empty());

        let mut frames = s.wire.exchange(
            MESSAGE_TYPE_UPDATE_CHANNEL,
            true,
            UpdateChannel {
                channel_id: 31_337,
                nominal_hash_rate: 1.0,
                max_target: U256::from(&ALL_ONES),
            },
        );
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_UPDATE_CHANNEL_ERROR);
        let error: UpdateChannelError = parse(&mut frame);
        assert_eq!(error.error_code.as_utf8_or_hex(), "invalid-channel-id");
    }

    #[test]
    fn a_host_retarget_is_sent_and_never_exceeds_the_miners_max_target() {
        let mut wire = Wire::new();
        wire.setup_mining(0);
        let mut max_target = [0_u8; 32];
        max_target[9] = 0x10;
        let mut frames = wire.open_standard(1, "vardiff", max_target);
        let opened = read_open_standard(&mut frames);
        assert_eq!(opened.target, max_target);

        let easier = ShareTarget::from_le_bytes(ALL_ONES)
            .unwrap_or_else(|error| panic!("nonzero: {error:?}"));
        assert!(matches!(
            wire.conn.set_target(opened.channel_id, easier),
            Err(Error::Session(SessionError::TargetAboveMaximum { .. }))
        ));

        let mut harder = [0_u8; 32];
        harder[2] = 1;
        wire.conn
            .set_target(
                opened.channel_id,
                ShareTarget::from_le_bytes(harder)
                    .unwrap_or_else(|error| panic!("nonzero: {error:?}")),
            )
            .unwrap_or_else(|error| panic!("harder target accepted: {error:?}"));
        let mut frames = wire.drain();
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_SET_TARGET);
        assert!(frame.channel_msg);
        let msg: SetTarget = parse(&mut frame);
        assert_eq!(msg.channel_id, opened.channel_id);
        assert_eq!(*msg.target.as_array(), harder);
        let info = wire
            .conn
            .session()
            .channel(opened.channel_id)
            .unwrap_or_else(|| panic!("channel open"));
        assert_eq!(info.target.to_le_bytes(), harder);
        assert_eq!(info.max_target.to_le_bytes(), max_target);

        assert!(matches!(
            wire.conn.set_target(9_999, easier),
            Err(Error::Session(SessionError::UnknownChannel(9_999)))
        ));
        assert!(!wire.conn.is_closing());
    }

    #[test]
    fn reconnect_is_sent_and_new_channels_are_refused_afterwards() {
        let mut wire = Wire::new();
        wire.setup_mining(0);
        wire.conn
            .request_reconnect("pool2.invalid", 3334)
            .unwrap_or_else(|error| panic!("reconnect: {error:?}"));
        let mut frames = wire.drain();
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_RECONNECT);
        assert!(!frame.channel_msg);
        let reconnect: common_messages_sv2::Reconnect = parse(&mut frame);
        assert_eq!(reconnect.new_host.as_utf8_or_hex(), "pool2.invalid");
        assert_eq!(reconnect.new_port, 3334);

        let mut frames = wire.open_standard(1, "late", ALL_ONES);
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR);
        let error: OpenMiningChannelError = parse(&mut frame);
        assert_eq!(error.error_code.as_utf8_or_hex(), "reconnect-requested");
    }

    #[test]
    fn a_connection_without_standard_jobs_gets_one_group_addressed_job() {
        let mut wire = Wire::new();
        wire.setup_mining(0);
        let mut frames = wire.open_standard(1, "std", ALL_ONES);
        let standard = read_open_standard(&mut frames);
        let mut frames = wire.open_extended(2, "ext", ALL_ONES, 4);
        let extended = read_open_extended(&mut frames);
        assert_eq!(standard.group_id, extended.group_id);
        let group = standard.group_id;

        let installed = wire
            .book
            .install(candidate(100, 0xab, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        wire.conn
            .announce(&installed)
            .unwrap_or_else(|error| panic!("announce: {error:?}"));
        let mut frames = wire.drain();
        assert_eq!(
            types(&frames),
            vec![
                MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
                MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH
            ],
            "one broadcast for the whole group, not one per channel"
        );
        let job = read_ext_job(&mut frames);
        let prev = read_prev_hash(&mut frames);
        assert_eq!(job.channel_id, group);
        assert_eq!(prev.channel_id, group);
        assert_eq!(job.job_id, prev.job_id);
        assert_eq!(job.ntime_start, None);

        let owned = wire.job(job.job_id);
        let nonce = share_nonce(&owned, &standard.prefix, owned.version());
        wire.submit_standard(
            standard.channel_id,
            1,
            job.job_id,
            nonce,
            owned.ntime(),
            owned.version(),
        );
        assert_eq!(accepted(wire.events()).channel_id, standard.channel_id);

        let rolled = [1_u8, 2, 3, 4];
        let mut full = extended.prefix.clone();
        full.extend_from_slice(&rolled);
        let nonce = share_nonce(&owned, &full, owned.version());
        wire.submit_extended(
            extended.channel_id,
            1,
            ShareWork {
                job_id: job.job_id,
                nonce,
                ntime: owned.ntime(),
                version: owned.version(),
            },
            &rolled,
        );
        assert_eq!(accepted(wire.events()).channel_id, extended.channel_id);

        let refreshed = wire
            .book
            .install(candidate(100, 0xab, 1), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        wire.conn
            .announce(&refreshed)
            .unwrap_or_else(|error| panic!("announce: {error:?}"));
        let mut frames = wire.drain();
        assert_eq!(types(&frames), vec![MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB]);
        let job = read_ext_job(&mut frames);
        assert_eq!(job.channel_id, group);
        assert_eq!(job.ntime_start, Some(refreshed.job.ntime()));
    }

    #[test]
    fn a_connection_requiring_standard_jobs_gets_one_job_per_channel() {
        let mut wire = Wire::new();
        wire.setup_mining(FLAG_REQUIRES_STANDARD_JOBS);
        let mut frames = wire.open_standard(1, "a", ALL_ONES);
        let a = read_open_standard(&mut frames);
        let mut frames = wire.open_standard(2, "b", ALL_ONES);
        let b = read_open_standard(&mut frames);
        assert_ne!(
            a.prefix, b.prefix,
            "every channel has a unique extranonce prefix"
        );

        let installed = wire
            .book
            .install(candidate(100, 0xab, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        wire.conn
            .announce(&installed)
            .unwrap_or_else(|error| panic!("announce: {error:?}"));
        let mut frames = wire.drain();
        assert_eq!(
            types(&frames),
            vec![
                MESSAGE_TYPE_NEW_MINING_JOB,
                MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
                MESSAGE_TYPE_NEW_MINING_JOB,
                MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH
            ]
        );
        let first = read_std_job(&mut frames);
        let second = read_std_job(&mut frames);
        assert_eq!(first.job_id, second.job_id);
        assert_ne!(first.channel_id, second.channel_id);
        assert_ne!(
            first.merkle_root, second.merkle_root,
            "different extranonce, different merkle root"
        );
        assert_eq!(first.version, second.version);
    }

    #[test]
    fn custom_jobs_are_answered_with_the_official_code_not_pretended() {
        let mut s = standard_with_job();
        let mut frames = s.wire.exchange(
            MESSAGE_TYPE_SET_CUSTOM_MINING_JOB,
            true,
            SetCustomMiningJob {
                channel_id: s.opened.channel_id,
                request_id: 5,
                token: B0255::new(&[1, 2, 3]).unwrap_or_else(|error| panic!("short: {error:?}")),
                version: 0x2000_0000,
                prev_hash: U256::from(&ALL_ONES),
                ntime_start: 1,
                nbits: 0x207f_ffff,
                coinbase_tx_version: 2,
                coinbase_prefix: B0255::new(&[0x03, 0x64, 0x00, 0x00])
                    .unwrap_or_else(|error| panic!("short: {error:?}")),
                coinbase_tx_input_n_sequence: u32::MAX,
                coinbase_tx_outputs: B064K::new(&[0])
                    .unwrap_or_else(|error| panic!("short: {error:?}")),
                coinbase_tx_locktime: 0,
                merkle_path: Seq0255::new(Vec::new())
                    .unwrap_or_else(|error| panic!("empty: {error:?}")),
            },
        );
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR);
        let error: SetCustomMiningJobError = parse(&mut frame);
        assert_eq!(error.channel_id, s.opened.channel_id);
        assert_eq!(error.request_id, 5);
        assert_eq!(error.error_code.as_utf8_or_hex(), "jd-not-supported");
    }

    #[test]
    fn the_installed_fact_set_is_what_the_adapter_consumes() {
        fn contract(installed: &Installed) -> (bool, bool, usize, JobId) {
            (
                installed.fresh,
                installed.clean_jobs,
                installed.invalidated.len(),
                installed.job.id(),
            )
        }
        let mut book = JobBook::new(book_config(BIP320_VERSION_MASK))
            .unwrap_or_else(|error| panic!("book: {error:?}"));
        let installed = book
            .install(candidate(100, 0xab, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        let (fresh, clean, invalidated, id) = contract(&installed);
        assert!(fresh && clean && invalidated == 0);
        assert!(book.current().is_some_and(|job| job.id() == id));
    }

    #[test]
    fn accepted_block_retirement_makes_second_same_job_submit_stale() {
        let mut s = standard_with_job();
        let version = s.job.version();
        let first = block_nonce(&s.job, &s.opened.prefix, version);
        s.wire.submit_standard(
            s.opened.channel_id,
            1,
            s.job.id().get(),
            first,
            s.job.ntime(),
            version,
        );
        let pending = s
            .wire
            .events()
            .into_iter()
            .find_map(|event| match event {
                Event::BlockFound(pending) => Some(pending),
                _ => None,
            })
            .unwrap_or_else(|| panic!("first winning nonce is a block candidate"));
        s.wire.book.invalidate_active();
        drop(pending);
        let (session, rolled) = s
            .opened
            .prefix
            .split_at(s.job.extranonce_layout().session_len());
        let second = (first + 1..u32::MAX)
            .find(|nonce| {
                let header = s
                    .job
                    .header(
                        Extranonce { session, rolled },
                        s.job.ntime(),
                        version,
                        *nonce,
                    )
                    .unwrap_or_else(|error| panic!("header builds: {error:?}"));
                compact_is_met_by(s.job.bits(), Hash256::from(header.compute_hash()))
            })
            .unwrap_or_else(|| panic!("a second winning nonce exists"));
        let mut frames = s.wire.submit_standard(
            s.opened.channel_id,
            2,
            s.job.id().get(),
            second,
            s.job.ntime(),
            version,
        );
        let (_, sequence, code) = share_error(&mut frames);
        assert_eq!((sequence, code.as_str()), (2, "stale-share"));
        let events = s.wire.events();
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, Event::BlockFound(_))),
            "stale share is never resubmitted to the node"
        );
        assert!(matches!(
            events.as_slice(),
            [Event::ShareRejected {
                code: "stale-share",
                ..
            }]
        ));
        let installed = s
            .wire
            .book
            .install(candidate(101, 0xcd, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        s.wire
            .conn
            .announce(&installed)
            .unwrap_or_else(|error| panic!("announce: {error:?}"));
        s.wire.drain();
        let nonce = share_nonce(&installed.job, &s.opened.prefix, installed.job.version());
        s.wire.submit_standard(
            s.opened.channel_id,
            3,
            installed.job.id().get(),
            nonce,
            installed.job.ntime(),
            installed.job.version(),
        );
        assert!(matches!(
            s.wire.events().as_slice(),
            [Event::ShareAccepted(_)]
        ));
    }

    fn unused_backend() -> MiningControlError {
        MiningControlError::Unavailable("not used by this test".into())
    }

    struct StaleParentControl;

    impl MiningControl for StaleParentControl {
        fn get_block_template(
            &self,
            _request: BlockTemplateRequest,
        ) -> Result<BlockTemplateResult, MiningControlError> {
            Err(unused_backend())
        }

        fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
            Err(unused_backend())
        }

        fn network_hash_ps(&self, _lookup: i64, _height: i64) -> Result<f64, MiningControlError> {
            Err(unused_backend())
        }

        fn submit_block(
            &self,
            _payload: BlockImage,
        ) -> Result<BlockValidationResult, MiningControlError> {
            Ok(BlockValidationResult::Rejected(STALE_PARENT_REASON.into()))
        }

        fn submit_header(&self, _header: Header) -> Result<(), MiningControlError> {
            Err(unused_backend())
        }

        fn publish_generation(&self) {}

        fn publish_fee_delta_generation(&self, _fee_delta_sequence: u64) {}

        fn generate(
            &self,
            _request: GenerateRequest,
        ) -> Result<Vec<GeneratedBlock>, MiningControlError> {
            Err(unused_backend())
        }
    }

    #[test]
    fn stale_sibling_receipt_sends_stale_error_without_closing() {
        let mut s = standard_with_job();
        let version = s.job.version();
        let nonce = block_nonce(&s.job, &s.opened.prefix, version);
        s.wire.submit_standard(
            s.opened.channel_id,
            1,
            s.job.id().get(),
            nonce,
            s.job.ntime(),
            version,
        );
        let pending = s
            .wire
            .events()
            .into_iter()
            .find_map(|event| match event {
                Event::BlockFound(pending) => Some(pending),
                _ => None,
            })
            .unwrap_or_else(|| panic!("a block is surfaced as pending host work"));
        let control = StaleParentControl;
        let submission = pending
            .submit(&control)
            .unwrap_or_else(|error| panic!("fake backend answers: {error:?}"));
        assert!(matches!(
            &submission.receipt().result,
            BlockValidationResult::Rejected(reason)
                if reason.as_str() == STALE_PARENT_REASON
        ));
        let sent = s
            .wire
            .conn
            .reject_block(&submission, "stale-share")
            .unwrap_or_else(|error| panic!("stale error queues: {error:?}"));
        assert!(sent, "stale ticket produces one error frame");
        assert!(
            !s.wire.conn.is_closing(),
            "stale sibling keeps the connection usable"
        );
        let mut frames = s.wire.drain();
        let (_, sequence, code) = share_error(&mut frames);
        assert_eq!((sequence, code.as_str()), (1, "stale-share"));
        let retired = s
            .wire
            .conn
            .reject_block(&submission, "stale-share")
            .unwrap_or_else(|error| panic!("repeat reject: {error:?}"));
        assert!(!retired, "block ticket retires with the error frame");
        let installed = s
            .wire
            .book
            .install(candidate(101, 0xcd, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        s.wire
            .conn
            .announce(&installed)
            .unwrap_or_else(|error| panic!("announce: {error:?}"));
        let announced = s.wire.drain();
        assert!(!announced.is_empty(), "new parent job announced");
        let nonce = share_nonce(&installed.job, &s.opened.prefix, installed.job.version());
        s.wire.submit_standard(
            s.opened.channel_id,
            2,
            installed.job.id().get(),
            nonce,
            installed.job.ntime(),
            installed.job.version(),
        );
        assert!(matches!(
            s.wire.events().as_slice(),
            [Event::ShareAccepted(_)]
        ));
    }

    #[test]
    fn malformed_reject_code_preserves_the_pending_ticket() {
        let mut s = standard_with_job();
        let version = s.job.version();
        let nonce = share_nonce(&s.job, &s.opened.prefix, version);
        s.wire.submit_standard(
            s.opened.channel_id,
            1,
            s.job.id().get(),
            nonce,
            s.job.ntime(),
            version,
        );
        let share = accepted(s.wire.events());
        let pending_before = s.wire.conn.session().pending_acks();
        assert_eq!(pending_before, 1);
        assert!(matches!(
            s.wire.conn.reject_share(share.ticket, "bad\ncode"),
            Err(Error::Session(SessionError::BadErrorCode))
        ));
        assert_eq!(
            s.wire.conn.session().pending_acks(),
            1,
            "malformed code leaves the ticket pending"
        );
        assert!(
            s.wire
                .conn
                .reject_share(
                    share.ticket,
                    crate::mining::pool::stratum::sv2::ERROR_CODE_SHARE_NOT_RECORDED
                )
                .unwrap_or_else(|error| panic!("valid refusal sends: {error:?}"))
        );
        let mut frames = s.wire.drain();
        let (channel, sequence, code) = share_error(&mut frames);
        assert_eq!(
            (channel, sequence, code.as_str()),
            (s.opened.channel_id, 1, "share-not-recorded")
        );
    }

    #[test]
    fn full_event_queue_fails_before_share_validation_without_orphan_ticket() {
        let mut config = server_config();
        config.limits.max_pending_events = 2;
        config.limits.max_pending_acks = 8;
        let mut wire = Wire::with(WHOLE, config, BIP320_VERSION_MASK);
        let installed = wire
            .book
            .install(candidate(100, 0xab, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        wire.setup_mining(FLAG_REQUIRES_STANDARD_JOBS);
        let mut frames = wire.open_standard(7, "alice.rig1", ALL_ONES);
        let opened = read_open_standard(&mut frames);
        let job = read_std_job(&mut frames);
        assert_eq!(job.job_id, installed.job.id().get());
        read_prev_hash(&mut frames);
        assert_eq!(wire.conn.session().pending_acks(), 0);
        let version = installed.job.version();
        let nonce = share_nonce(&installed.job, &opened.prefix, version);
        let msg = SubmitSharesStandard {
            channel_id: opened.channel_id,
            sequence_number: 1,
            job_id: installed.job.id().get(),
            nonce,
            ntime: installed.job.ntime(),
            version,
        };
        assert!(matches!(
            wire.try_exchange(MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, true, msg),
            Err(Error::Session(SessionError::Backlog { queue: "event", .. }))
        ));
        assert_eq!(
            wire.conn.session().pending_acks(),
            0,
            "no orphan ticket is inserted when the event queue is full"
        );
    }

    use crate::mining::pool::stratum::sv2::{Frame, ProtocolSession};

    fn open_test_session(book: &mut JobBook) -> ProtocolSession {
        let mut cfg = server_config();
        cfg.limits.max_outbound_frames = 3;
        let mut session =
            ProtocolSession::new(cfg, book).unwrap_or_else(|error| panic!("session: {error:?}"));
        let setup = SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_STANDARD_JOBS,
            endpoint_host: Str0255::try_from("pool.invalid")
                .unwrap_or_else(|error| panic!("short: {error:?}")),
            endpoint_port: 3333,
            vendor: Str0255::try_from("test-miner")
                .unwrap_or_else(|error| panic!("short: {error:?}")),
            hardware_version: Str0255::try_from("sim-1")
                .unwrap_or_else(|error| panic!("short: {error:?}")),
            firmware: Str0255::try_from("fw-0").unwrap_or_else(|error| panic!("short: {error:?}")),
            device_id: Str0255::try_from("").unwrap_or_else(|error| panic!("empty: {error:?}")),
        };
        let payload =
            binary_sv2::to_bytes(setup).unwrap_or_else(|error| panic!("encode: {error:?}"));
        session
            .handle(
                book,
                Frame {
                    extension_type: 0,
                    msg_type: MESSAGE_TYPE_SETUP_CONNECTION,
                    channel_msg: false,
                    payload,
                },
            )
            .unwrap_or_else(|error| panic!("setup: {error:?}"));
        assert!(session.is_open());
        session.take_frames();
        session
    }

    fn open_test_standard_channel(
        session: &mut ProtocolSession,
        book: &mut JobBook,
        id: u32,
        user: &str,
    ) -> Opened {
        let msg = OpenStandardMiningChannel {
            request_id: id,
            user_identity: Str0255::try_from(user)
                .unwrap_or_else(|error| panic!("short: {error:?}")),
            nominal_hash_rate: 1.0e12,
            max_target: U256::from(&ALL_ONES),
        };
        let payload = binary_sv2::to_bytes(msg).unwrap_or_else(|error| panic!("encode: {error:?}"));
        session
            .handle(
                book,
                Frame {
                    extension_type: 0,
                    msg_type: MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
                    channel_msg: false,
                    payload,
                },
            )
            .unwrap_or_else(|error| panic!("open: {error:?}"));
        let mut received: Vec<Received> = session
            .take_frames()
            .into_iter()
            .map(|frame| Received {
                msg_type: frame.msg_type,
                channel_msg: frame.channel_msg,
                payload: frame.payload,
            })
            .collect();
        read_open_standard(&mut received)
    }

    #[test]
    fn active_refresh_upgrades_a_channel_that_missed_its_parent_to_future() {
        let mut book = JobBook::new(book_config(BIP320_VERSION_MASK))
            .unwrap_or_else(|error| panic!("book: {error:?}"));
        let mut session = open_test_session(&mut book);
        let opened_a = open_test_standard_channel(&mut session, &mut book, 7, "alice.rig1");
        let opened_b = open_test_standard_channel(&mut session, &mut book, 8, "bob.rig1");
        let first = book
            .install(candidate(100, 0xab, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        assert!(session.announce(&first).is_err());
        let missed = session.take_frames();
        assert_eq!(missed.len(), 3);
        let second = book
            .install(candidate(100, 0xab, 3), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        assert!(!second.clean_jobs);
        assert!(
            second.job.id().get() != first.job.id().get(),
            "second install must be a new job"
        );
        session
            .announce(&second)
            .unwrap_or_else(|error| panic!("announce: {error:?}"));
        let announced = session.take_frames();
        let detail: Vec<(u8, Vec<u8>)> = announced
            .iter()
            .map(|frame| (frame.msg_type, frame.payload.clone()))
            .collect();
        assert_eq!(announced.len(), 3, "second announce frames: {detail:?}");
        let mut received: Vec<Received> = announced
            .into_iter()
            .map(|frame| Received {
                msg_type: frame.msg_type,
                channel_msg: frame.channel_msg,
                payload: frame.payload,
            })
            .collect();
        let mut jobs = Vec::new();
        while received
            .iter()
            .any(|frame| frame.msg_type == MESSAGE_TYPE_NEW_MINING_JOB)
        {
            jobs.push(read_std_job(&mut received));
        }
        assert_eq!(jobs.len(), 2);
        let prev = read_prev_hash(&mut received);
        assert!(received.is_empty());
        let active = jobs
            .iter()
            .find(|job| job.ntime_start.is_some())
            .unwrap_or_else(|| panic!("one channel gets Active"));
        let future = jobs
            .iter()
            .find(|job| job.ntime_start.is_none())
            .unwrap_or_else(|| panic!("stale channel gets Future"));
        assert_eq!(active.job_id, second.job.id().get());
        assert_eq!(future.job_id, second.job.id().get());
        assert_eq!(prev.job_id, second.job.id().get());
        assert_eq!(future.channel_id, opened_b.channel_id);
        assert_eq!(prev.channel_id, opened_b.channel_id);
        assert_eq!(active.channel_id, opened_a.channel_id);
    }

    #[test]
    fn announce_without_fresh_still_delivers_a_missing_job_and_parent() {
        let mut wire = Wire::new();
        wire.setup_mining(FLAG_REQUIRES_STANDARD_JOBS);
        let mut frames = wire.open_standard(7, "late.rig1", ALL_ONES);
        let opened = read_open_standard(&mut frames);
        assert!(wire.drain().is_empty());
        let first = wire
            .book
            .install(candidate(100, 0xab, 2), Vec::new())
            .unwrap_or_else(|error| panic!("install: {error:?}"));
        assert!(first.fresh);
        let second = wire
            .book
            .install(candidate(100, 0xab, 2), Vec::new())
            .unwrap_or_else(|error| panic!("reinstall: {error:?}"));
        assert!(!second.fresh);
        wire.conn
            .announce(&second)
            .unwrap_or_else(|error| panic!("announce: {error:?}"));
        let mut announced = wire.drain();
        let job = read_std_job(&mut announced);
        assert_eq!(job.job_id, first.job.id().get());
        let prev = read_prev_hash(&mut announced);
        assert_eq!(prev.job_id, first.job.id().get());
        assert_eq!(opened.channel_id, prev.channel_id);
    }
}
mod mining_raw_sigops {
    use crate::support::mining::fixtures as common;

    use crate::support::mining::TestError;

    use crate::mining::{
        CandidateContext, GenerateSelection, GenerateTx, MiningError, assemble_ordered_candidate,
    };
    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Sequence, Tx, TxIn, TxOut, Txid, consensus_bytes,
    };
    use bitcoin_rs_consensus::script::push_data;
    use bitcoin_rs_mempool::{Mempool, MempoolLimits};
    use bitcoin_rs_node::mining::snapshot_for_selection;
    use common::{context, insert, oracle_transaction, p2pkh, zero_fee_pool};

    type TestResult = Result<(), TestError>;

    struct RawCase {
        previous_script: Vec<u8>,
        script_sig: Vec<u8>,
        witness: Vec<Vec<u8>>,
        active_cost: u32,
        inactive_cost: u32,
    }

    #[test]
    fn raw_consensus_costs_obey_exact_ordered_limits() -> TestResult {
        let pool = Mempool::new(MempoolLimits::default());
        for case in cases() {
            let tx = raw_tx(&case);
            let prevout = previous_output(&case);
            assert_eq!(oracle_cost(&tx, &prevout)?, case.active_cost);
            for segwit_active in [false, true] {
                let expected = if segwit_active {
                    case.active_cost
                } else {
                    case.inactive_cost
                };
                let selection = GenerateSelection::Ordered(vec![GenerateTx::Raw(tx.clone())]);
                let snapshot = snapshot_for_selection(
                    pool.mining_snapshot(),
                    &selection,
                    &[(tx.inputs[0].previous_output, prevout.clone())],
                    segwit_active,
                )?;
                assert_eq!(snapshot.entries[0].sigop_cost, expected);
                let mut context = CandidateContext {
                    segwit_active,
                    max_sigops: u64::from(expected) + 4,
                    ..context()
                };
                let candidate = assemble_ordered_candidate(&context, &snapshot, &p2pkh())?;
                assert_eq!(
                    candidate
                        .transactions
                        .iter()
                        .map(|tx| u64::from(tx.sigop_cost))
                        .sum::<u64>(),
                    u64::from(expected)
                );
                context.max_sigops -= 1;
                assert!(matches!(
                    assemble_ordered_candidate(&context, &snapshot, &p2pkh()),
                    Err(MiningError::CapacityExhausted { field: "sigops" })
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn raw_children_resolve_only_earlier_selected_outputs() -> TestResult {
        for case in cases().into_iter().skip(1) {
            let mut parent = raw_tx(&cases()[0]);
            parent.outputs = vec![previous_output(&case)];
            let mut child = raw_tx(&case);
            child.inputs[0].previous_output = OutPoint::new(parent.txid(), 0);
            let mut pool = zero_fee_pool();
            insert(&mut pool, parent.clone(), 200, 1_000, 1, 1)?;
            let admitted = pool.mining_snapshot().entries[0].clone();
            for parent_selection in [
                GenerateTx::Raw(parent.clone()),
                GenerateTx::Mempool(parent.txid()),
                GenerateTx::ResolvedMempool(admitted),
            ] {
                let selection = GenerateSelection::Ordered(vec![
                    parent_selection,
                    GenerateTx::Raw(child.clone()),
                ]);
                let snapshot =
                    snapshot_for_selection(pool.mining_snapshot(), &selection, &[], true)?;
                assert_eq!(snapshot.entries[1].sigop_cost, case.active_cost);
            }
            for items in [
                vec![GenerateTx::Raw(child.clone())],
                vec![GenerateTx::Raw(child.clone()), GenerateTx::Raw(parent)],
            ] {
                let snapshot = snapshot_for_selection(
                    pool.mining_snapshot(),
                    &GenerateSelection::Ordered(items),
                    &[],
                    true,
                )?;
                assert_eq!(snapshot.entries[0].sigop_cost, 4);
            }
        }
        Ok(())
    }

    fn cases() -> Vec<RawCase> {
        let redeem = vec![0x51, 0xae];
        let witness_script = vec![0xac];
        let witness_program = bitcoin::ScriptBuf::from_bytes(witness_script.clone()).to_p2wsh();
        vec![
            RawCase {
                previous_script: vec![0x51],
                script_sig: vec![],
                witness: vec![],
                active_cost: 4,
                inactive_cost: 4,
            },
            RawCase {
                previous_script: bitcoin::ScriptBuf::from_bytes(redeem.clone())
                    .to_p2sh()
                    .into_bytes(),
                script_sig: push_data(&redeem),
                witness: vec![],
                active_cost: 8,
                inactive_cost: 8,
            },
            RawCase {
                previous_script: witness_program.clone().into_bytes(),
                script_sig: vec![],
                witness: vec![vec![], witness_script.clone()],
                active_cost: 5,
                inactive_cost: 4,
            },
            RawCase {
                previous_script: witness_program.to_p2sh().into_bytes(),
                script_sig: push_data(witness_program.as_bytes()),
                witness: vec![vec![], witness_script],
                active_cost: 5,
                inactive_cost: 4,
            },
        ]
    }

    fn oracle_cost(tx: &Tx, prevout: &TxOut) -> Result<u32, TestError> {
        let oracle = oracle_transaction(tx)?;
        let prevout: bitcoin::TxOut = bitcoin::consensus::deserialize(&consensus_bytes(prevout))?;
        Ok(u32::try_from(
            oracle.total_sigop_cost(|_| Some(prevout.clone())),
        )?)
    }

    fn previous_output(case: &RawCase) -> TxOut {
        TxOut {
            value: Amount::from_sat(2_000),
            script_pubkey: case.previous_script.clone().into(),
        }
    }

    fn raw_tx(case: &RawCase) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[1; 32])), 0),
                script_sig: case.script_sig.clone().into(),
                sequence: Sequence::MAX,
                witness: case.witness.clone().into(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: p2pkh().into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }
}
mod mining_template_shape {
    use crate::support::mining::fixtures as common;

    use crate::support::mining::TestError;

    use crate::mining::{
        CandidateContext, WITNESS_RESERVED_VALUE, assemble_candidate, assemble_ordered_candidate,
        solve_block,
    };
    use bitcoin::Wtxid as OracleWtxid;
    use bitcoin::hashes::{Hash as _, HashEngine as _, sha256d};
    use bitcoin_rs_consensus::primitives::{CompactTarget, Hash256, Network, Txid};
    use common::{PAYOUT, context, insert, selected_fees, tx, zero_fee_pool};

    fn txids(transactions: &[crate::mining::CandidateTransaction]) -> Vec<Txid> {
        transactions.iter().map(|tx| tx.txid).collect()
    }

    #[test]
    fn candidate_scalars_and_depends_match_selected_transactions() -> Result<(), TestError> {
        let mut mempool = zero_fee_pool();
        let parent = tx(1, 50_000, None);
        let parent_txid = parent.txid();
        insert(&mut mempool, parent, 150, 1_500, 1, 100)?;
        insert(
            &mut mempool,
            tx(2, 40_000, Some(parent_txid)),
            150,
            2_500,
            2,
            100,
        )?;
        for index in 3_u8..12 {
            insert(
                &mut mempool,
                tx(index, 1_000, None),
                120,
                1_000 + u64::from(index),
                u64::from(index),
                100,
            )?;
        }

        let snapshot = mempool.mining_snapshot();
        assert_eq!(snapshot.sequence, mempool.sequence_number());
        assert_eq!(
            snapshot.fee_delta_sequence,
            mempool.fee_delta_sequence_number(),
            "snapshot fee sequence comes from the same pool state"
        );
        let context = CandidateContext {
            height: 250,
            version: 0x2000_0001,
            bits: CompactTarget::from_consensus(0x1d00_ffff),
            min_time: 10,
            current_time: 20,
            locktime_cutoff: 10,
            ..context()
        };
        let candidate = assemble_candidate(&context, &mempool, PAYOUT)?;

        let mut expected_id = context.previous_block_hash.to_string_be();
        expected_id.push_str(&snapshot.sequence.to_string());
        if snapshot.fee_delta_sequence != 0 {
            expected_id.push(':');
            expected_id.push_str(&snapshot.fee_delta_sequence.to_string());
        }
        assert_eq!(candidate.template_id.as_str(), expected_id);
        assert_eq!(candidate.previous_block_hash, context.previous_block_hash);
        assert_eq!(candidate.height, context.height);
        assert_eq!(candidate.version, context.version);
        assert_eq!(candidate.bits, context.bits);
        assert_eq!(candidate.mempool_sequence, snapshot.sequence);
        assert_eq!(candidate.csv_active, context.csv_active);
        assert_eq!(candidate.segwit_active, context.segwit_active);

        let mut fees = 0_u64;
        let mut positions = std::collections::BTreeMap::new();
        for (offset, tx) in candidate.transactions.iter().enumerate() {
            positions.insert(tx.txid, u32::try_from(offset + 1)?);
            fees = fees.checked_add(tx.fee).ok_or("fee")?;
            assert_eq!(tx.txid, tx.tx.txid());
            assert_eq!(tx.wtxid, tx.tx.wtxid());
        }
        for tx in &candidate.transactions {
            let mut expected = tx
                .tx
                .inputs
                .iter()
                .filter_map(|input| positions.get(&input.previous_output.txid).copied())
                .collect::<Vec<_>>();
            expected.sort_unstable();
            expected.dedup();
            assert_eq!(tx.depends, expected);
            for &depend in &tx.depends {
                assert!(depend >= 1);
                assert!(usize::try_from(depend)? <= candidate.transactions.len());
            }
        }
        let block = candidate.into_unsolved_block()?;
        let oracle: bitcoin::Block = bitcoin::consensus::deserialize(
            &bitcoin_rs_consensus::primitives::encode::consensus_bytes(&block),
        )?;
        assert_eq!(candidate.weight, oracle.weight().to_wu());
        assert_eq!(
            candidate.coinbase_value,
            bitcoin_rs_consensus::block_subsidy(250, Network::Regtest.subsidy_halving_interval())
                + fees
        );

        let mut leaves = vec![OracleWtxid::all_zeros()];
        leaves.extend(
            candidate
                .transactions
                .iter()
                .map(|tx| OracleWtxid::from_byte_array(*tx.wtxid.as_bytes())),
        );
        let root = bitcoin::merkle_tree::calculate_root(leaves.into_iter()).ok_or("root")?;
        let root = Hash256::from_le_bytes(root.as_byte_array());
        let mut engine = sha256d::Hash::engine();
        engine.input(root.as_byte_array());
        engine.input(&WITNESS_RESERVED_VALUE);
        assert_eq!(
            candidate.witness_commitment,
            Some(Hash256::from_le_bytes(
                sha256d::Hash::from_engine(engine).as_byte_array()
            ))
        );
        Ok(())
    }

    #[test]
    fn equal_fee_ties_follow_snapshot_order_deterministically() -> Result<(), TestError> {
        let mut mempool = zero_fee_pool();
        for label in 1_u8..=5 {
            insert(
                &mut mempool,
                tx(label, 1_000, None),
                200,
                2_000,
                u64::from(label),
                100,
            )?;
        }
        let snapshot = mempool.mining_snapshot();
        let legacy = CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[0x22; 32]),
            height: 10,
            version: 1,
            csv_active: false,
            segwit_active: false,
            ..context()
        };
        let first = assemble_candidate(&legacy, &mempool, PAYOUT)?;
        let second = assemble_candidate(&legacy, &mempool, PAYOUT)?;
        assert_eq!(txids(&first.transactions), txids(&second.transactions));
        assert_eq!(
            txids(&first.transactions),
            snapshot
                .entries
                .iter()
                .map(|entry| entry.txid)
                .collect::<Vec<_>>()
        );
        assert!(first.witness_commitment.is_none());
        Ok(())
    }

    #[test]
    fn currentblocktx_counts_exclude_the_coinbase() -> Result<(), TestError> {
        let context = CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[0x44; 32]),
            version: 1,
            ..context()
        };
        let empty = zero_fee_pool();
        let zero = assemble_candidate(&context, &empty, PAYOUT)?;
        assert_eq!(
            zero.transactions.len(),
            0,
            "coinbase-only candidate has zero non-coinbase txs"
        );

        let mut one_pool = zero_fee_pool();
        insert(&mut one_pool, tx(1, 1_000, None), 120, 1_000, 1, 100)?;
        let one = assemble_candidate(&context, &one_pool, PAYOUT)?;
        assert_eq!(one.transactions.len(), 1);
        Ok(())
    }

    #[test]
    fn assembly_copies_deployment_boundary_flags() -> Result<(), TestError> {
        let empty = zero_fee_pool();
        for (csv_active, segwit_active) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let candidate = assemble_candidate(
                &CandidateContext {
                    previous_block_hash: Hash256::from_le_bytes(&[0x55; 32]),
                    height: 432,
                    version: 1,
                    csv_active,
                    segwit_active,
                    ..context()
                },
                &empty,
                PAYOUT,
            )?;
            assert_eq!(candidate.csv_active, csv_active);
            assert_eq!(candidate.segwit_active, segwit_active);
        }
        Ok(())
    }

    #[test]
    fn candidate_solves_an_unsolved_regtest_header() -> Result<(), TestError> {
        let context = CandidateContext {
            height: 1,
            version: 1,
            ..context()
        };
        let empty = zero_fee_pool();
        let candidate = assemble_candidate(&context, &empty, PAYOUT)?;
        let unsolved = candidate.into_unsolved_block()?;
        assert_eq!(unsolved.txs.len(), 1);
        assert_eq!(unsolved.header.nonce, 0);
        assert_eq!(unsolved.header.bits, context.bits);
        let mut solved = candidate.into_unsolved_block()?;
        solve_block(&mut solved, 1_000_000)?;
        assert_eq!(solved.txs.len(), 1);
        assert_eq!(solved.header.prev_blockhash.0, context.previous_block_hash);
        assert!(
            bitcoin_rs_consensus::header_rules::compact_is_met_by(
                solved.header.bits,
                Hash256::from(solved.block_hash())
            ),
            "solve_block must return a header whose hash meets its compact target"
        );
        Ok(())
    }

    #[test]
    fn ordered_assembly_keeps_snapshot_order() -> Result<(), TestError> {
        let mut mempool = zero_fee_pool();
        insert(&mut mempool, tx(1, 10_000, None), 150, 1_000, 1, 100)?;
        insert(&mut mempool, tx(2, 10_000, None), 150, 1_000, 1, 100)?;
        let snapshot = mempool.mining_snapshot();
        let context = CandidateContext {
            height: 1,
            version: 1,
            ..context()
        };
        let candidate = assemble_ordered_candidate(&context, &snapshot, PAYOUT)?;
        assert_eq!(selected_fees(&candidate), 2_000);
        assert_eq!(candidate.coinbase_value, 5_000_000_000);
        assert_eq!(
            txids(&candidate.transactions),
            snapshot
                .entries
                .iter()
                .map(|entry| entry.txid)
                .collect::<Vec<_>>()
        );
        Ok(())
    }
}
mod mining_witness_commitment_vector {
    use crate::support::mining::fixtures as common;

    use crate::support::mining::TestError;

    use crate::mining::{
        CandidateContext, WITNESS_RESERVED_VALUE, assemble_candidate, witness_commitment_script,
    };
    use bitcoin::consensus::encode::serialize as bitcoin_serialize;
    use bitcoin::hashes::{Hash as _, HashEngine as _, sha256d};
    use bitcoin::opcodes::all::{OP_PUSHBYTES_36, OP_RETURN};
    use bitcoin::{block, pow};
    use bitcoin_rs_consensus::primitives::{Amount, Hash256, Tx};
    use bitcoin_rs_mempool::{Mempool, MempoolLimits};
    use common::{PAYOUT, insert, oracle_transaction, witnessed_tx};

    fn context() -> CandidateContext {
        CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[0xab; 32]),
            height: 1,
            min_time: 1_700_000_001,
            current_time: 1_700_000_600,
            locktime_cutoff: 1_700_000_000,
            ..common::context()
        }
    }

    const VECTOR_COMMITMENT: [u8; 32] = [
        0xd2, 0x31, 0x9f, 0x64, 0x3d, 0x27, 0xbc, 0x0e, 0xcb, 0xa4, 0xf0, 0xc8, 0xb6, 0x90, 0xef,
        0x3e, 0xb6, 0x4f, 0x69, 0x21, 0x65, 0xec, 0x29, 0x41, 0xf2, 0x3e, 0xac, 0xb0, 0x64, 0x76,
        0xec, 0xe6,
    ];

    #[test]
    fn witness_commitment_matches_pinned_vector_and_rust_bitcoin_root() -> Result<(), TestError> {
        let parent = witnessed_tx(1, 50_000, None);
        let child = witnessed_tx(2, 40_000, Some(parent.txid()));
        let pool = pool_with(&[parent.clone(), child.clone()], &[2_000, 3_000])?;

        let candidate = assemble_candidate(&context(), &pool, PAYOUT)?;
        let commitment = candidate
            .witness_commitment
            .ok_or("segwit-active candidate must carry a commitment")?;

        assert_eq!(
            commitment.as_byte_array(),
            &VECTOR_COMMITMENT,
            "assembled commitment diverges from the pinned BIP141 vector"
        );

        let oracle_block = block::Block {
            header: block::Header {
                version: block::Version::from_consensus(0x2000_0000),
                prev_blockhash: block::BlockHash::from_byte_array([0xab; 32]),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_700_000_600,
                bits: pow::CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![
                oracle_transaction(&candidate.coinbase)?,
                oracle_transaction(&parent)?,
                oracle_transaction(&child)?,
            ],
        };
        let oracle_root = oracle_block
            .witness_root()
            .ok_or("oracle block must yield a witness root")?;

        let mut engine = sha256d::Hash::engine();
        engine.input(bitcoin_serialize(&oracle_root).as_slice());
        engine.input(&WITNESS_RESERVED_VALUE);
        let recomputed = sha256d::Hash::from_engine(engine);
        assert_eq!(
            bitcoin_serialize(&recomputed),
            commitment.as_byte_array().to_vec(),
            "commitment is not dSHA256(witness_root || reserved_value)"
        );

        let script = witness_commitment_script(&commitment);
        assert_eq!(
            script,
            commitment_script_bytes(&VECTOR_COMMITMENT),
            "commitment output script diverges from the pinned BIP141 script bytes"
        );

        let commitment_output = candidate
            .coinbase
            .outputs
            .iter()
            .find(|output| output.script_pubkey == script)
            .ok_or("coinbase must carry the commitment output script")?;
        assert_eq!(commitment_output.value, Amount::ZERO);
        assert_eq!(
            candidate.coinbase.inputs[0].witness,
            vec![WITNESS_RESERVED_VALUE.to_vec()],
            "coinbase witness must be exactly the 32-byte reserved value"
        );

        let legacy_pool = pool_with(&[witnessed_tx(1, 50_000, None)], &[2_000])?;
        let legacy = assemble_candidate(
            &CandidateContext {
                segwit_active: false,
                ..context()
            },
            &legacy_pool,
            PAYOUT,
        )?;
        assert!(legacy.witness_commitment.is_none());
        assert!(
            !legacy
                .coinbase
                .outputs
                .iter()
                .any(|output| output.script_pubkey.first() == Some(&0x6a))
        );
        assert!(legacy.coinbase.inputs[0].witness.is_empty());
        Ok(())
    }

    fn pool_with(txs: &[Tx], fees: &[u64]) -> Result<Mempool, TestError> {
        assert_eq!(txs.len(), fees.len());
        let mut pool = Mempool::new(MempoolLimits::default());
        for (tx, &fee) in txs.iter().zip(fees) {
            insert(&mut pool, tx.clone(), u32::try_from(tx.vsize())?, fee, 0, 0)?;
        }
        Ok(pool)
    }

    fn commitment_script_bytes(commitment: &[u8; 32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(38);
        bytes.push(OP_RETURN.to_u8());
        bytes.push(OP_PUSHBYTES_36.to_u8());
        bytes.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]);
        bytes.extend_from_slice(commitment);
        bytes
    }
}

mod mining_fixture {
    extern crate alloc;

    use alloc::sync::Arc;

    use crate::mining::{
        BlockTemplate, Candidate, MiningCapability, MiningInfo, TemplateId, TemplateMutation,
    };
    use bitcoin_rs_consensus::primitives::{
        CompactTarget, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, Witness,
    };

    pub(crate) fn canned_template(
        capabilities: Vec<MiningCapability>,
        mutable: Vec<TemplateMutation>,
    ) -> BlockTemplate {
        let previous_block_hash = Hash256::default();
        BlockTemplate {
            candidate: Arc::new(Candidate {
                template_id: TemplateId::new(&previous_block_hash, 0),
                previous_block_hash,
                height: 0,
                version: 0x2000_0000,
                bits: CompactTarget::from_consensus(0x1d00_ffff),
                min_time: 0,
                current_time: 0,
                csv_active: false,
                segwit_active: false,
                max_weight: 4_000_000,
                max_size: 4_000_000,
                max_sigops: 80_000,
                mempool_sequence: 0,
                coinbase: Tx {
                    version: 1,
                    lock_time: LockTime::ZERO,
                    inputs: vec![TxIn {
                        previous_output: OutPoint::null(),
                        script_sig: Script::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    }],
                    outputs: Vec::new(),
                },
                coinbase_value: 0,
                weight: 0,
                transactions: Vec::new(),
                witness_commitment: None,
            }),
            rules: Vec::new(),
            version_bits_available: Vec::new(),
            version_bits_required: 0,
            capabilities,
            mutable,
            submit_old: None,
            signet: None,
        }
    }

    pub(crate) fn canned_info() -> MiningInfo {
        MiningInfo {
            blocks: 0,
            last_candidate: None,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            difficulty: 1.0,
            network_hashes_per_second: 0.0,
            pooled_transactions: 0,
            network: Network::Regtest,
            next_bits: CompactTarget::from_consensus(0x207f_ffff),
            next_difficulty: 1.0,
            minimum_fee_rate: 1_000,
            signet: None,
            warnings: Vec::new(),
        }
    }
}
#[allow(dead_code)]
mod support {
    pub(crate) mod chain {
        use super::{GateResult, fail};
        use bitcoin_rs_consensus::primitives::{
            Amount, Block, CompactTarget, Hash256, LockTime, OutPoint, Sequence, Tx, TxIn, TxOut,
            Witness,
        };
        use bitcoin_rs_consensus::script::push_int;
        use bitcoin_rs_execution::chain::regtest_fixture;
        use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};

        pub(crate) const SEED_BASE_TIME: u32 = 1_296_688_603;
        pub(crate) const SEED_BLOCK_INTERVAL: u32 = 600;
        pub(crate) const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;

        pub(crate) fn apply_genesis(state: &NodeState) -> GateResult<()> {
            let genesis = Network::Regtest.genesis_block();
            state
                .apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                    genesis,
                ))
                .map_err(fail)?;
            Ok(())
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(crate) struct SeedChain {
            pub tip_height: u32,
            pub tip_hash: Hash256,
        }

        pub(crate) fn seed_chain(state: &NodeState, count: u32) -> GateResult<SeedChain> {
            let mut tip = current_tip(state)?;
            for height in 1..=count {
                let coinbase = Tx {
                    version: 2,
                    inputs: vec![TxIn {
                        previous_output: OutPoint::null(),
                        script_sig: [push_int(i64::from(height)), push_int(0)].concat().into(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    }],
                    outputs: vec![TxOut {
                        value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
                        script_pubkey: vec![0x51].into(),
                    }],
                    lock_time: LockTime::ZERO,
                };
                let mut block = Block {
                    header: bitcoin_rs_consensus::primitives::Header {
                        version: 0x2000_0000,
                        prev_blockhash: bitcoin_rs_consensus::primitives::BlockHash::from(tip.hash),
                        merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                        time: SEED_BASE_TIME
                            .saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
                        bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
                        nonce: 0,
                    },
                    txs: vec![coinbase],
                };
                block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
                    .ok_or_else(|| fail("seed block must have a merkle root"))?;
                regtest_fixture::mine_block_to_declared_target(&mut block).map_err(fail)?;
                state
                    .apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                        block,
                    ))
                    .map_err(fail)?;
                tip = current_tip(state)?;
                if tip.height != height {
                    return Err(fail(format!(
                        "seed block must become the tip at height {height}"
                    )));
                }
            }
            Ok(SeedChain {
                tip_height: tip.height,
                tip_hash: tip.hash,
            })
        }

        pub(crate) fn current_tip(
            state: &NodeState,
        ) -> GateResult<bitcoin_rs_execution::chain::TipSnapshot> {
            let Some(tip) = state.chainstate().applied_tip_snapshot() else {
                return Err(fail("applied tip must exist"));
            };
            Ok((*tip).clone())
        }

        #[must_use]
        pub(crate) fn regtest_config(dir: &std::path::Path) -> NodeConfig {
            let mut config = NodeConfig::default_for_network(Network::Regtest);
            config.data_dir = dir.to_path_buf();
            config.p2p.listen.clear();
            config
        }
    }
    pub(crate) mod compare {
        use sonic_rs::{
            JsonContainerTrait as _, JsonValueMutTrait as _, JsonValueTrait as _, Value,
        };

        use super::fixture::{
            BodyCheck, BodyForm, Checks, Fixture, HeaderCheck, HeaderClass, HttpTuple, Relation,
        };

        pub(crate) fn json_value<'de, D>(deserializer: D) -> Result<Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct JsonSeed;

            impl<'de> serde::de::DeserializeSeed<'de> for JsonSeed {
                type Value = Value;

                fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    deserializer.deserialize_any(JsonVisitor)
                }
            }

            struct JsonVisitor;

            impl<'de> serde::de::Visitor<'de> for JsonVisitor {
                type Value = Value;

                fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    formatter.write_str("any JSON value")
                }

                fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
                    Ok(Value::from(value))
                }

                fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
                    Ok(Value::from(value))
                }

                fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
                    Ok(Value::from(value))
                }

                fn visit_f64<E>(self, value: f64) -> Result<Value, E>
                where
                    E: serde::de::Error,
                {
                    sonic_rs::Number::from_f64(value)
                        .map(Value::from)
                        .ok_or_else(|| E::custom("non-finite float in fixture"))
                }

                fn visit_str<E>(self, value: &str) -> Result<Value, E> {
                    Ok(Value::from(value))
                }

                fn visit_string<E>(self, value: String) -> Result<Value, E> {
                    Ok(Value::from(value.as_str()))
                }

                fn visit_unit<E>(self) -> Result<Value, E> {
                    Ok(Value::from(()))
                }

                fn visit_none<E>(self) -> Result<Value, E> {
                    Ok(Value::from(()))
                }

                fn visit_some<D>(self, deserializer: D) -> Result<Value, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    deserializer.deserialize_any(self)
                }

                fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Value, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    deserializer.deserialize_any(self)
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    let mut array = sonic_rs::Array::with_capacity(seq.size_hint().unwrap_or(0));
                    while let Some(element) = seq.next_element_seed(JsonSeed)? {
                        array.push(element);
                    }
                    Ok(array.into_value())
                }

                fn visit_map<A>(self, mut map: A) -> Result<Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    let mut object = sonic_rs::Object::new();
                    while let Some((key, value)) =
                        map.next_entry_seed(core::marker::PhantomData::<String>, JsonSeed)?
                    {
                        object.insert(&key, value);
                    }
                    Ok(object.into_value())
                }
            }

            serde::de::DeserializeSeed::deserialize(JsonSeed, deserializer)
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(crate) struct LiveChain {
            pub(crate) blocks: u64,
            pub(crate) headers: u64,
            pub(crate) best_block_hash: String,
        }

        #[derive(Debug)]
        pub(crate) struct Mismatch {
            pub(crate) fixture: String,
            pub(crate) position: String,
            pub(crate) why: String,
        }

        impl core::fmt::Display for Mismatch {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "[{}] {}: {}", self.fixture, self.position, self.why)
            }
        }

        impl std::error::Error for Mismatch {}

        #[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "snake_case")]
        pub(crate) enum EnvelopeVersion {
            V2,
            Legacy,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "snake_case")]
        pub(crate) enum Outcome {
            Success,
            Error,
        }

        #[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct ResultCheck {
            pub(crate) typed_chaininfo: bool,
            pub(crate) exact_keys: Vec<String>,
            pub(crate) f64_bits_keys: Vec<String>,
            pub(crate) chain_bound_keys: Vec<String>,
            pub(crate) volatile_keys: Vec<String>,
            pub(crate) gap_keys: Vec<String>,
        }

        impl ResultCheck {
            pub(crate) fn classes(&self) -> [(&'static str, &[String]); 5] {
                [
                    ("exact", &self.exact_keys),
                    ("f64-bits", &self.f64_bits_keys),
                    ("chain-bound", &self.chain_bound_keys),
                    ("volatile", &self.volatile_keys),
                    ("gap", &self.gap_keys),
                ]
            }
        }

        #[derive(Clone, Debug, PartialEq, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct EnvelopeCheck {
            pub(crate) version: EnvelopeVersion,
            pub(crate) outcome: Outcome,
            #[serde(deserialize_with = "json_value")]
            pub(crate) id: Value,
            pub(crate) error_code: Option<i64>,
            pub(crate) result: ResultCheck,
        }

        impl EnvelopeCheck {
            #[must_use]
            pub(crate) fn member_names(&self) -> Vec<&'static str> {
                match (self.version, self.outcome) {
                    (EnvelopeVersion::V2, Outcome::Success) => vec!["jsonrpc", "result", "id"],
                    (EnvelopeVersion::V2, Outcome::Error) => vec!["jsonrpc", "error", "id"],
                    (EnvelopeVersion::Legacy, _) => vec!["result", "error", "id"],
                }
            }

            #[must_use]
            pub(crate) fn jsonrpc_member(&self) -> Option<&'static str> {
                match self.version {
                    EnvelopeVersion::V2 => Some("2.0"),
                    EnvelopeVersion::Legacy => None,
                }
            }
        }

        pub(crate) fn compare(
            fixture: &Fixture,
            live: &HttpTuple,
            chain: &LiveChain,
        ) -> Result<(), Mismatch> {
            match &fixture.relation {
                Relation::Exact => compare_tuple(
                    &fixture.id,
                    "core",
                    &fixture.core,
                    live,
                    &fixture.checks,
                    chain,
                ),
                Relation::KnownGap => {
                    let current = fixture.current.as_ref().ok_or_else(|| Mismatch {
                        fixture: fixture.id.clone(),
                        position: "relation".into(),
                        why: "known gap without a pinned current tuple".into(),
                    })?;
                    if fixture.gap.as_deref().unwrap_or_default().trim().is_empty() {
                        return Err(Mismatch {
                            fixture: fixture.id.clone(),
                            position: "relation".into(),
                            why: "known gap without a concrete gap identifier".into(),
                        });
                    }
                    assert_divergence_exactly_at(fixture, current)?;
                    compare_tuple(
                        &fixture.id,
                        "current",
                        current,
                        live,
                        &fixture.checks,
                        chain,
                    )
                }
            }
        }

        #[must_use]
        pub(crate) fn structural_diff_paths(core: &HttpTuple, current: &HttpTuple) -> Vec<String> {
            let mut paths = Vec::new();
            if core.status != current.status {
                paths.push("status".to_owned());
            }
            let normalize = |pairs: &[(String, String)]| -> Vec<(String, String)> {
                let mut normalized: Vec<(String, String)> = pairs
                    .iter()
                    .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
                    .filter(|(name, _)| name != "date" && name != "connection")
                    .collect();
                normalized.sort();
                normalized
            };
            let core_headers = normalize(&core.headers);
            let current_headers = normalize(&current.headers);
            let names: std::collections::BTreeSet<&str> = core_headers
                .iter()
                .map(|(name, _)| name.as_str())
                .chain(current_headers.iter().map(|(name, _)| name.as_str()))
                .collect();
            for name in names {
                let core_value = core_headers
                    .iter()
                    .find(|(candidate, _)| candidate == name)
                    .map(|(_, value)| value);
                let current_value = current_headers
                    .iter()
                    .find(|(candidate, _)| candidate == name)
                    .map(|(_, value)| value);
                if core_value != current_value {
                    paths.push(format!("headers.{name}"));
                }
            }
            match (&core.body, &current.body) {
                (BodyForm::Json { value: a }, BodyForm::Json { value: b }) => {
                    value_diff_paths(a, b, "body", &mut paths);
                }
                (BodyForm::Text { text: a }, BodyForm::Text { text: b }) => {
                    if a != b {
                        paths.push("body".to_owned());
                    }
                }
                (BodyForm::Empty, BodyForm::Empty) => {}
                _ => paths.push("body".to_owned()),
            }
            paths
        }

        fn value_diff_paths(core: &Value, current: &Value, prefix: &str, paths: &mut Vec<String>) {
            if let (Some(core_object), Some(current_object)) =
                (core.as_object(), current.as_object())
            {
                let names: std::collections::BTreeSet<&str> = core_object
                    .iter()
                    .map(|(key, _)| key)
                    .chain(current_object.iter().map(|(key, _)| key))
                    .collect();
                for name in names {
                    let child = format!("{prefix}.{name}");
                    match (core_object.get(&name), current_object.get(&name)) {
                        (Some(core_value), Some(current_value)) => {
                            value_diff_paths(core_value, current_value, &child, paths);
                        }
                        _ => paths.push(child),
                    }
                }
                return;
            }
            if let (Some(core_array), Some(current_array)) = (core.as_array(), current.as_array()) {
                if core_array.len() != current_array.len() {
                    paths.push(prefix.to_owned());
                    return;
                }
                for (index, (core_value, current_value)) in
                    core_array.iter().zip(current_array.iter()).enumerate()
                {
                    value_diff_paths(
                        core_value,
                        current_value,
                        &format!("{prefix}[{index}]"),
                        paths,
                    );
                }
                return;
            }
            if !value_equal(core, current) {
                paths.push(prefix.to_owned());
            }
        }

        fn assert_divergence_exactly_at(
            fixture: &Fixture,
            current: &HttpTuple,
        ) -> Result<(), Mismatch> {
            let mut observed = structural_diff_paths(&fixture.core, current);
            observed.sort();
            let mut declared = fixture.gap_paths.clone();
            declared.sort();
            if observed.is_empty() {
                return Err(Mismatch {
                    fixture: fixture.id.clone(),
                    position: "relation".into(),
                    why: "known gap no longer holds: the pinned Core tuple and the pinned current \
                  tuple are structurally identical, so the gap must be reclassified"
                        .into(),
                });
            }
            if observed != declared {
                return Err(Mismatch {
                    fixture: fixture.id.clone(),
                    position: "relation".into(),
                    why: format!(
                        "known gap diverges at {observed:?} but the fixture declares exactly \
                 {declared:?}"
                    ),
                });
            }
            Ok(())
        }

        fn compare_tuple(
            fixture: &str,
            side: &str,
            expected: &HttpTuple,
            live: &HttpTuple,
            checks: &Checks,
            chain: &LiveChain,
        ) -> Result<(), Mismatch> {
            let need = |position: String, why: String| Mismatch {
                fixture: fixture.to_owned(),
                position: format!("{side}.{position}"),
                why,
            };

            if checks.http_status && expected.status != live.status {
                return Err(need(
                    "status".into(),
                    format!(
                        "expected HTTP {} but replay answered {}",
                        expected.status, live.status
                    ),
                ));
            }
            check_tuple_content_length(fixture, side, expected)?;
            check_tuple_content_length(fixture, side, live)?;
            compare_headers(fixture, side, expected, live, &checks.headers)?;

            match (&expected.body, &checks.body, &live.body) {
                (BodyForm::Empty, BodyCheck::Empty, BodyForm::Empty) => {}
                (BodyForm::Empty, BodyCheck::Empty, live_form) => {
                    return Err(need(
                        "body".into(),
                        format!("expected an empty body but replay answered {live_form:?}"),
                    ));
                }
                (BodyForm::Text { text }, BodyCheck::Text, BodyForm::Text { text: live_text }) => {
                    if text.as_bytes() != live_text.as_bytes() {
                        return Err(need(
                            "body".into(),
                            format!(
                                "expected plain-text body {text:?} but replay answered {live_text:?}"
                            ),
                        ));
                    }
                }
                (BodyForm::Text { text }, BodyCheck::Text, live_form) => {
                    return Err(need(
                        "body".into(),
                        format!(
                            "expected plain-text body {text:?} but replay answered {live_form:?}"
                        ),
                    ));
                }
                (
                    BodyForm::Json {
                        value: expected_value,
                    },
                    BodyCheck::Single { envelope },
                    BodyForm::Json { value: live_value },
                ) => {
                    compare_envelope(fixture, side, envelope, live_value, expected_value, chain)?;
                }
                (
                    BodyForm::Json {
                        value: expected_value,
                    },
                    BodyCheck::Batch { elements },
                    BodyForm::Json { value: live_value },
                ) => {
                    compare_batch(fixture, side, elements, live_value, expected_value, chain)?;
                }
                _ => {
                    return Err(need(
                        "body".into(),
                        "fixture check form does not match the pinned body form".into(),
                    ));
                }
            }
            Ok(())
        }

        fn header_value<'a>(tuple: &'a HttpTuple, name: &str) -> Option<&'a str> {
            tuple
                .headers
                .iter()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }

        fn check_tuple_content_length(
            fixture: &str,
            side: &str,
            tuple: &HttpTuple,
        ) -> Result<(), Mismatch> {
            let fail = |why: String| Mismatch {
                fixture: fixture.to_owned(),
                position: format!("{side}.header Content-Length"),
                why,
            };
            let declared: Vec<&str> = tuple
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.as_str())
                .collect();
            if declared.len() > 1 {
                return Err(fail("duplicate Content-Length headers".into()));
            }
            if tuple.status == 204 {
                if tuple.body_len != Some(0) {
                    return Err(fail("204 response must have an empty body".into()));
                }
                if let Some(value) = declared.first() {
                    if *value != "0" || declared.len() != 1 {
                        return Err(fail(
                            "204 Content-Length must be absent or exactly \"0\"".into(),
                        ));
                    }
                }
                return Ok(());
            }
            let Some(length) = tuple.body_len else {
                return Ok(());
            };
            let Some(value) = declared.first() else {
                return Err(fail(format!(
                    "response must carry exactly one Content-Length header for its {length} \
             body bytes"
                )));
            };
            let parsed: Option<u64> = (*value)
                .parse()
                .ok()
                .filter(|_| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()));
            match parsed {
                Some(parsed) if parsed == length => Ok(()),
                Some(parsed) => Err(fail(format!(
                    "Content-Length {parsed} does not equal the body's actual {length} bytes"
                ))),
                None => Err(fail("Content-Length must be ASCII digits only".into())),
            }
        }

        fn compare_headers(
            fixture: &str,
            side: &str,
            expected: &HttpTuple,
            live: &HttpTuple,
            headers: &HeaderCheck,
        ) -> Result<(), Mismatch> {
            let need = |name: &str, why: String| Mismatch {
                fixture: fixture.to_owned(),
                position: format!("{side}.header {name}"),
                why,
            };
            let mut names: std::collections::BTreeMap<String, String> =
                std::collections::BTreeMap::new();
            for (name, _) in expected.headers.iter().chain(live.headers.iter()) {
                names
                    .entry(name.to_ascii_lowercase())
                    .or_insert_with(|| name.clone());
            }
            for name in &headers.volatile {
                names
                    .entry(name.to_ascii_lowercase())
                    .or_insert_with(|| name.clone());
            }
            for (lower, display) in names {
                if headers.body_length && lower == "content-length" {
                    continue;
                }
                let Some(class) = headers.class_of(&lower) else {
                    return Err(need(
                        &display,
                        "header name is not classified; every pinned and live header must be \
                 classified exactly once as exact, volatile or gap"
                            .into(),
                    ));
                };
                let expected_value = header_value(expected, &lower);
                let live_value = header_value(live, &lower);
                match class {
                    HeaderClass::Exact => {
                        let (Some(expected_value), Some(live_value)) = (expected_value, live_value)
                        else {
                            return Err(need(
                                &display,
                                format!(
                                    "exact header must be present on both sides (pinned: {}, live: {})",
                                    expected_value.is_some(),
                                    live_value.is_some()
                                ),
                            ));
                        };
                        if expected_value != live_value {
                            return Err(need(
                                &display,
                                format!(
                                    "expected {expected_value:?} but replay answered {live_value:?}"
                                ),
                            ));
                        }
                    }
                    HeaderClass::Volatile => {
                        if live_value.is_none() {
                            return Err(need(
                                &display,
                                format!(
                                    "volatile header must be present on the live reply (pinned: {})",
                                    expected_value.is_some()
                                ),
                            ));
                        }
                    }
                    HeaderClass::Gap => {
                        let (Some(expected_value), Some(live_value)) = (expected_value, live_value)
                        else {
                            return Err(need(
                                &display,
                                "gap header must be present on both sides so its divergence is \
                         provable"
                                    .into(),
                            ));
                        };
                        if expected_value == live_value {
                            return Err(need(
                                &display,
                                "gap header is classified gap but both sides carry the same \
                         value, so nothing diverges there"
                                    .into(),
                            ));
                        }
                    }
                }
            }
            Ok(())
        }

        fn compare_batch(
            fixture: &str,
            side: &str,
            elements: &[EnvelopeCheck],
            live: &Value,
            core: &Value,
            chain: &LiveChain,
        ) -> Result<(), Mismatch> {
            let need = |position: String, why: String| Mismatch {
                fixture: fixture.to_owned(),
                position: format!("{side}.{position}"),
                why,
            };
            let Some(core_rows) = core.as_array() else {
                return Err(need(
                    "body".into(),
                    "pinned Core batch is not a JSON array".into(),
                ));
            };
            let Some(live_rows) = live.as_array() else {
                return Err(need(
                    "body".into(),
                    "expected a JSON array batch response".into(),
                ));
            };
            if core_rows.len() != elements.len() || live_rows.len() != elements.len() {
                return Err(need(
                    "body".into(),
                    format!(
                        "expected {} batch elements but core pinned {} and replay answered {}",
                        elements.len(),
                        core_rows.len(),
                        live_rows.len()
                    ),
                ));
            }
            for (index, ((core_row, live_row), envelope)) in core_rows
                .iter()
                .zip(live_rows.iter())
                .zip(elements)
                .enumerate()
            {
                let Some(core_id) = core_row.get("id") else {
                    return Err(need(
                        "body".into(),
                        format!("pinned Core batch element {index} carries no id"),
                    ));
                };
                let Some(live_id) = live_row.get("id") else {
                    return Err(need(
                        "body".into(),
                        format!("replay batch element {index} carries no id"),
                    ));
                };
                if !value_equal(core_id, live_id) {
                    return Err(need(
                        format!("body[{index}].id"),
                        format!(
                            "batch order diverges: core pinned id {} at position {index} but replay \
                     answered {}",
                            value_repr(core_id),
                            value_repr(live_id)
                        ),
                    ));
                }
                compare_envelope(fixture, side, envelope, live_row, core_row, chain)?;
            }
            Ok(())
        }

        fn value_repr(value: &Value) -> String {
            sonic_rs::to_string(value).unwrap_or_else(|_| "<unserializable>".to_owned())
        }

        fn compare_envelope(
            fixture: &str,
            side: &str,
            envelope: &EnvelopeCheck,
            live: &Value,
            core: &Value,
            chain: &LiveChain,
        ) -> Result<(), Mismatch> {
            let need = |position: String, why: String| Mismatch {
                fixture: fixture.to_owned(),
                position: format!("{side}.{position}"),
                why,
            };

            let expected_members = envelope.member_names();
            let Some(object) = live.as_object() else {
                return Err(need(
                    "envelope".into(),
                    "response element is not a JSON object".into(),
                ));
            };
            let live_members: Vec<&str> = object.iter().map(|(key, _)| key).collect();
            if live_members.len() != expected_members.len() {
                return Err(need(
                    "envelope".into(),
                    format!(
                        "expected envelope members {expected_members:?} but replay answered \
                 {live_members:?}"
                    ),
                ));
            }
            for member in &expected_members {
                if live.get(*member).is_none() {
                    return Err(need(
                        "envelope".into(),
                        format!("envelope is missing the {member:?} member"),
                    ));
                }
            }

            if let Some(jsonrpc) = envelope.jsonrpc_member() {
                if live.get("jsonrpc").and_then(Value::as_str) != Some(jsonrpc) {
                    return Err(need(
                        "envelope.jsonrpc".into(),
                        format!("expected {jsonrpc:?}"),
                    ));
                }
            }

            let live_id = live.get("id").ok_or_else(|| {
                need("envelope.id".into(), "envelope carries no id member".into())
            })?;
            if !value_equal(live_id, &envelope.id) {
                return Err(need(
                    "envelope.id".into(),
                    format!(
                        "expected identifier to be echoed exactly as {:?}",
                        envelope.id
                    ),
                ));
            }

            match envelope.outcome {
                Outcome::Success => {
                    let Some(result) = live.get("result") else {
                        return Err(need(
                            "envelope".into(),
                            "success envelope carries no result".into(),
                        ));
                    };
                    let core_result = core.get("result").ok_or_else(|| {
                        need(
                            "envelope".into(),
                            "pinned Core success envelope carries no result".into(),
                        )
                    })?;
                    compare_result(fixture, side, &envelope.result, result, core_result, chain)?;
                    if envelope.version == EnvelopeVersion::Legacy
                        && !live.get("error").is_some_and(Value::is_null)
                    {
                        return Err(need(
                            "envelope.error".into(),
                            "legacy success envelope must carry an explicit null error member"
                                .into(),
                        ));
                    }
                }
                Outcome::Error => {
                    compare_error(fixture, side, envelope, live, core)?;
                }
            }
            Ok(())
        }

        fn compare_error(
            fixture: &str,
            side: &str,
            envelope: &EnvelopeCheck,
            live: &Value,
            core: &Value,
        ) -> Result<(), Mismatch> {
            compare_error_code(fixture, side, envelope, live)?;
            compare_error_members(fixture, side, live, core)?;
            compare_error_dialect(fixture, side, envelope, live)?;
            Ok(())
        }

        fn compare_error_code(
            fixture: &str,
            side: &str,
            envelope: &EnvelopeCheck,
            live: &Value,
        ) -> Result<(), Mismatch> {
            let need = |position: String, why: String| Mismatch {
                fixture: fixture.to_owned(),
                position: format!("{side}.{position}"),
                why,
            };
            let Some(expected_code) = envelope.error_code else {
                return Err(need(
                    "error.code".into(),
                    "fixture check must pin an error code for an error envelope".into(),
                ));
            };
            let Some(error) = live.get("error") else {
                return Err(need(
                    "envelope".into(),
                    "error envelope carries no error member".into(),
                ));
            };
            let Some(code) = error.get("code").and_then(Value::as_i64) else {
                return Err(need(
                    "error.code".into(),
                    "error carries no numeric code".into(),
                ));
            };
            if code != expected_code {
                return Err(need(
                    "error.code".into(),
                    format!("expected {expected_code} but replay answered {code}"),
                ));
            }
            Ok(())
        }

        fn compare_error_members(
            fixture: &str,
            side: &str,
            live: &Value,
            core: &Value,
        ) -> Result<(), Mismatch> {
            let need = |position: String, why: String| Mismatch {
                fixture: fixture.to_owned(),
                position: format!("{side}.{position}"),
                why,
            };
            let Some(pinned_error) = core.get("error") else {
                return Err(need(
                    "error".into(),
                    "pinned Core error envelope carries no error member".into(),
                ));
            };
            let Some(pinned_object) = pinned_error.as_object() else {
                return Err(need(
                    "error".into(),
                    "pinned Core error must be a JSON object".into(),
                ));
            };
            let Some(live_object) = live.get("error").and_then(Value::as_object) else {
                return Err(need("error".into(), "error must be a JSON object".into()));
            };
            let pinned_members: Vec<&str> = pinned_object.iter().map(|(key, _)| key).collect();
            let live_members: Vec<&str> = live_object.iter().map(|(key, _)| key).collect();
            if live_members.len() != pinned_members.len() {
                return Err(need(
                    "error".into(),
                    format!(
                        "expected error members {pinned_members:?} but replay answered {live_members:?}"
                    ),
                ));
            }
            for key in pinned_members {
                compare_error_member(fixture, side, key, pinned_error, live)?;
            }
            Ok(())
        }

        fn compare_error_member(
            fixture: &str,
            side: &str,
            key: &str,
            pinned_error: &Value,
            live: &Value,
        ) -> Result<(), Mismatch> {
            let need = |position: String, why: String| Mismatch {
                fixture: fixture.to_owned(),
                position: format!("{side}.{position}"),
                why,
            };
            let Some(pinned_value) = pinned_error.get(key) else {
                return Err(need(
                    format!("error.{key}"),
                    "check expects a pinned member the Core error does not carry".into(),
                ));
            };
            let Some(live_value) = live.get("error").and_then(|error| error.get(key)) else {
                return Err(need(
                    format!("error.{key}"),
                    format!("error is missing the pinned member {key:?}"),
                ));
            };
            if !value_equal(live_value, pinned_value) {
                return Err(need(
                    format!("error.{key}"),
                    format!(
                        "expected {} but replay answered {}",
                        value_repr(pinned_value),
                        value_repr(live_value)
                    ),
                ));
            }
            Ok(())
        }

        fn compare_error_dialect(
            fixture: &str,
            side: &str,
            envelope: &EnvelopeCheck,
            live: &Value,
        ) -> Result<(), Mismatch> {
            let need = |position: String, why: String| Mismatch {
                fixture: fixture.to_owned(),
                position: format!("{side}.{position}"),
                why,
            };
            match envelope.version {
                EnvelopeVersion::V2 => {
                    if live.get("result").is_some() {
                        return Err(need(
                            "envelope".into(),
                            "error envelope must not also carry a result member".into(),
                        ));
                    }
                }
                EnvelopeVersion::Legacy => {
                    if !live.get("result").is_some_and(Value::is_null) {
                        return Err(need(
                            "envelope.result".into(),
                            "legacy error envelope must carry an explicit null result member"
                                .into(),
                        ));
                    }
                }
            }
            Ok(())
        }

        fn compare_result(
            fixture: &str,
            side: &str,
            checks: &ResultCheck,
            live: &Value,
            core: &Value,
            chain: &LiveChain,
        ) -> Result<(), Mismatch> {
            let need = |position: String, why: String| Mismatch {
                fixture: fixture.to_owned(),
                position: format!("{side}.{position}"),
                why,
            };

            if live.as_object().is_none() {
                return Err(need("result".into(), "result must be a JSON object".into()));
            }
            let live_keys: Vec<String> = live
                .as_object()
                .map(|object| object.iter().map(|(key, _)| key.to_owned()).collect())
                .unwrap_or_default();

            let classified: std::collections::BTreeSet<&str> = checks
                .classes()
                .iter()
                .flat_map(|(_, keys)| keys.iter().map(String::as_str))
                .collect();
            for key in &live_keys {
                if !classified.contains(key.as_str()) {
                    return Err(need(
                        format!("result.{key}"),
                        format!("result carries the unclassified key {key:?}"),
                    ));
                }
            }

            compare_classified_keys(fixture, side, checks, live, core)?;
            compare_chain_bound_keys(fixture, side, checks, live, chain)?;
            Ok(())
        }

        fn compare_classified_keys(
            fixture: &str,
            side: &str,
            checks: &ResultCheck,
            live: &Value,
            core: &Value,
        ) -> Result<(), Mismatch> {
            let need = |position: String, why: String| Mismatch {
                fixture: fixture.to_owned(),
                position: format!("{side}.{position}"),
                why,
            };
            for (class, keys) in checks.classes() {
                for key in keys {
                    if class == "chain-bound" {
                        continue;
                    }
                    let Some(core_value) = core.get(key.as_str()) else {
                        return Err(need(
                            format!("result.{key}"),
                            format!(
                                "check classifies {key:?} but the compared side does not carry it"
                            ),
                        ));
                    };
                    let Some(live_value) = live.get(key.as_str()) else {
                        return Err(need(
                            format!("result.{key}"),
                            format!("result is missing the classified key {key:?}"),
                        ));
                    };
                    compare_classified_key(fixture, side, class, key, live_value, core_value)?;
                }
            }
            Ok(())
        }

        fn compare_classified_key(
            fixture: &str,
            side: &str,
            class: &str,
            key: &str,
            live_value: &Value,
            core_value: &Value,
        ) -> Result<(), Mismatch> {
            let need = |position: String, why: String| Mismatch {
                fixture: fixture.to_owned(),
                position: format!("{side}.{position}"),
                why,
            };
            match class {
                "exact" => {
                    if !value_equal(live_value, core_value) {
                        return Err(need(
                            format!("result.{key}"),
                            format!(
                                "expected {} but replay answered {}",
                                value_repr(core_value),
                                value_repr(live_value)
                            ),
                        ));
                    }
                }
                "f64-bits" => {
                    let Some(core_bits) = core_value.as_f64() else {
                        return Err(need(
                            format!("result.{key}"),
                            "classified f64 key is not a number on the compared side".into(),
                        ));
                    };
                    let Some(live_bits) = live_value.as_f64() else {
                        return Err(need(
                            format!("result.{key}"),
                            format!("result must carry {key:?} as a JSON number"),
                        ));
                    };
                    if core_bits.to_bits() != live_bits.to_bits() {
                        return Err(need(
                            format!("result.{key}"),
                            format!(
                                "f64 bits diverge: compared side {:#016x} vs live {:#016x}",
                                core_bits.to_bits(),
                                live_bits.to_bits()
                            ),
                        ));
                    }
                }
                "volatile" => {
                    if json_kind(live_value) != json_kind(core_value) {
                        return Err(need(
                            format!("result.{key}"),
                            format!(
                                "volatile key {key:?} must keep the pinned JSON type, expected \
                         kind {} but replay answered kind {}",
                                json_kind(core_value),
                                json_kind(live_value)
                            ),
                        ));
                    }
                }
                "gap" => {
                    if !value_equal(live_value, core_value) {
                        return Err(need(
                            format!("result.{key}"),
                            format!(
                                "declared gap key {key:?} must equal the pinned current value: \
                         expected {} but replay answered {}",
                                value_repr(core_value),
                                value_repr(live_value)
                            ),
                        ));
                    }
                }
                _ => {
                    return Err(need(
                        format!("result.{key}"),
                        format!("unsupported classification {class:?}"),
                    ));
                }
            }
            Ok(())
        }

        fn compare_chain_bound_keys(
            fixture: &str,
            side: &str,
            checks: &ResultCheck,
            live: &Value,
            chain: &LiveChain,
        ) -> Result<(), Mismatch> {
            let need = |position: String, why: String| Mismatch {
                fixture: fixture.to_owned(),
                position: format!("{side}.{position}"),
                why,
            };
            for key in &checks.chain_bound_keys {
                let Some(live_value) = live.get(key.as_str()) else {
                    return Err(need(
                        format!("result.{key}"),
                        format!("result is missing the chain-bound key {key:?}"),
                    ));
                };
                let diverged = match key.as_str() {
                    "blocks" => live_value.as_u64() != Some(chain.blocks),
                    "headers" => live_value.as_u64() != Some(chain.headers),
                    "bestblockhash" => live_value.as_str() != Some(chain.best_block_hash.as_str()),
                    other => {
                        return Err(need(
                    format!("result.{other}"),
                    "unsupported chain-bound key: the comparator only binds blocks, headers \
                     and bestblockhash"
                        .into(),
                ));
                    }
                };
                if diverged {
                    return Err(need(
                        format!("result.{key}"),
                        format!(
                            "chain-bound value diverges from the live node state: expected \
                     {chain:?} binding but replay answered {}",
                            value_repr(live_value)
                        ),
                    ));
                }
            }
            Ok(())
        }

        fn json_kind(value: &Value) -> u8 {
            if value.is_null() {
                0
            } else if value.is_boolean() {
                1
            } else if value.is_number() {
                2
            } else if value.is_str() {
                3
            } else if value.is_array() {
                4
            } else {
                5
            }
        }

        const CHAININFO_EXTENSION_KEYS: [&str; 2] = ["is_closed_for_recovery", "is_apply_halted"];

        pub(crate) fn typed_getblockchain_info(
            body: &[u8],
        ) -> Result<corepc_types::v31::GetBlockchainInfo, sonic_rs::Error> {
            let mut value: sonic_rs::Value = sonic_rs::from_slice(body)?;
            if let Some(object) = value.as_object_mut() {
                object.retain(|key, _| !CHAININFO_EXTENSION_KEYS.contains(&key));
            }
            sonic_rs::from_slice(sonic_rs::to_string(&value)?.as_bytes())
        }

        #[must_use]
        pub(crate) fn value_equal(a: &Value, b: &Value) -> bool {
            if let (Some(a), Some(b)) = (a.as_object(), b.as_object()) {
                return a.len() == b.len()
                    && a.iter().all(|(key, value)| {
                        b.get(&key).is_some_and(|other| value_equal(value, other))
                    });
            }
            if let (Some(a), Some(b)) = (a.as_array(), b.as_array()) {
                return a.len() == b.len()
                    && a.iter()
                        .zip(b.iter())
                        .all(|(left, right)| value_equal(left, right));
            }
            if let (Some(a), Some(b)) = (a.as_str(), b.as_str()) {
                return a == b;
            }
            if let (Some(a), Some(b)) = (a.as_bool(), b.as_bool()) {
                return a == b;
            }
            if a.is_null() && b.is_null() {
                return true;
            }
            if let (Some(a), Some(b)) = (a.as_i64(), b.as_i64()) {
                return a == b;
            }
            match (a.as_f64(), b.as_f64()) {
                (Some(a), Some(b)) => a.to_bits() == b.to_bits(),
                _ => false,
            }
        }
    }
    pub(crate) mod error {
        #[derive(Debug, thiserror::Error)]
        pub(crate) enum TestError {
            #[error(transparent)]
            Load(#[from] super::fixture::LoadError),
            #[error(transparent)]
            Mismatch(#[from] super::compare::Mismatch),
            #[error(transparent)]
            Http(#[from] super::http::HttpError),
            #[error(transparent)]
            Failure(#[from] super::Failure),
            #[error(transparent)]
            Io(#[from] std::io::Error),
            #[error(transparent)]
            Sonic(#[from] sonic_rs::Error),
            #[error(transparent)]
            Rpc(#[from] bitcoin_rs_serving::RpcError),
            #[error(transparent)]
            Auth(#[from] bitcoin_rs_serving::auth::AuthError),
            #[error(transparent)]
            AddrParse(#[from] std::net::AddrParseError),
            #[error(transparent)]
            FromUtf8(#[from] std::string::FromUtf8Error),
            #[error(transparent)]
            Chain(#[from] bitcoin_rs_execution::chain::ChainError),
            #[error(transparent)]
            RegtestFixture(
                #[from] bitcoin_rs_execution::chain::regtest_fixture::RegtestFixtureError,
            ),
            #[error(transparent)]
            Mempool(#[from] bitcoin_rs_mempool::MempoolError),
            #[error(transparent)]
            Rbf(#[from] bitcoin_rs_mempool::RbfError),
            #[error(transparent)]
            ChainChange(#[from] bitcoin_rs_mempool::ChainChangeError),
            #[error(transparent)]
            Utxo(#[from] bitcoin_rs_storage::utxo::UtxoError),
            #[error(transparent)]
            UtxoScan(#[from] bitcoin_rs_storage::utxo::scan::UtxoScanError),
            #[error(transparent)]
            NodeOpen(#[from] bitcoin_rs_node::NodeOpenError),
            #[error(transparent)]
            ConnectMutation(#[from] bitcoin_rs_node::ConnectMutationError),
            #[error(transparent)]
            ConsensusEncode(#[from] bitcoin::consensus::encode::Error),
            #[error(transparent)]
            Psbt(#[from] bitcoin::psbt::Error),
            #[error(transparent)]
            HexToBytes(#[from] bitcoin::hex::HexToBytesError),
            #[error(transparent)]
            Decode(#[from] bitcoin_rs_consensus::primitives::DecodeError),
            #[error(transparent)]
            TryFromInt(#[from] std::num::TryFromIntError),
            #[error(transparent)]
            TryFromSlice(#[from] std::array::TryFromSliceError),
            #[error(transparent)]
            ParseInt(#[from] std::num::ParseIntError),
            #[error(transparent)]
            Reference(#[from] bitcoin_rs_e2e::reference_set::ReferenceError),
            #[error(transparent)]
            E2e(#[from] bitcoin_rs_e2e::error::Error),
            #[error("missing {0}")]
            Missing(&'static str),
            #[error("{0}")]
            Message(String),
        }

        impl From<&'static str> for TestError {
            fn from(s: &'static str) -> Self {
                Self::Missing(s)
            }
        }

        impl From<String> for TestError {
            fn from(s: String) -> Self {
                Self::Message(s)
            }
        }
    }
    pub(crate) mod fixture {
        use std::collections::BTreeMap;
        use std::path::{Path, PathBuf};

        use bitcoin::hex::DisplayHex as _;
        use bitcoin_rs_serving::manifest::{MANIFEST, SurfaceKind};
        use serde::Deserialize;
        use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

        use super::compare::EnvelopeCheck;
        use super::limits::{
            MAX_CORPUS_BYTES, MAX_FIXTURE_BYTES, MAX_FIXTURE_COUNT, MAX_JSON_DEPTH,
        };
        use super::manifest_check;

        use bitcoin_rs_e2e::reference_set;

        fn len_u64(len: usize) -> u64 {
            u64::try_from(len).unwrap_or(u64::MAX)
        }

        #[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "snake_case")]
        pub(crate) enum Relation {
            Exact,
            #[serde(rename = "known_gap")]
            KnownGap,
        }

        #[derive(Clone, Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct Provenance {
            pub core_version: String,
            pub core_source_commit: String,
            pub core_binary_sha256: String,
            pub network: String,
            pub tip_height: u64,
            pub tip_hash: String,
            pub evidence: String,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "snake_case")]
        pub(crate) enum RequestAuth {
            Valid,
            Invalid,
            Absent,
        }

        #[derive(Clone, Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct RequestSpec {
            pub auth: RequestAuth,
            pub body: String,
            pub methods: Vec<String>,
            pub expect_methods_in_manifest: bool,
            pub fragment_at: Option<usize>,
        }

        #[derive(Clone, Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct HttpTuple {
            pub status: u16,
            pub headers: Vec<(String, String)>,
            #[serde(default)]
            pub body_len: Option<u64>,
            pub body: BodyForm,
        }

        #[derive(Clone, Debug, Deserialize)]
        #[serde(tag = "form", rename_all = "snake_case")]
        pub(crate) enum BodyForm {
            Empty,
            Text {
                text: String,
            },
            Json {
                #[serde(deserialize_with = "super::compare::json_value")]
                value: Value,
            },
        }

        #[derive(Clone, Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct Fixture {
            pub id: String,
            pub case_ordinal: String,
            pub description: String,
            pub provenance: Provenance,
            pub request: RequestSpec,
            pub core: HttpTuple,
            #[serde(default)]
            pub current: Option<HttpTuple>,
            pub relation: Relation,
            #[serde(default)]
            pub gap: Option<String>,
            #[serde(default)]
            pub gap_paths: Vec<String>,
            pub checks: Checks,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum HeaderClass {
            Exact,
            Volatile,
            Gap,
        }

        #[derive(Clone, Debug, Default, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct HeaderCheck {
            #[serde(default)]
            pub(crate) exact: Vec<String>,
            #[serde(default)]
            pub(crate) volatile: Vec<String>,
            #[serde(default)]
            pub(crate) gap: Vec<String>,
            #[serde(default)]
            pub(crate) body_length: bool,
        }

        impl HeaderCheck {
            #[must_use]
            pub(crate) fn class_of(&self, lower_name: &str) -> Option<HeaderClass> {
                let matches = |list: &[String]| {
                    list.iter()
                        .any(|name| name.eq_ignore_ascii_case(lower_name))
                };
                if matches(&self.exact) {
                    Some(HeaderClass::Exact)
                } else if matches(&self.volatile) {
                    Some(HeaderClass::Volatile)
                } else if matches(&self.gap) {
                    Some(HeaderClass::Gap)
                } else {
                    None
                }
            }

            #[must_use]
            pub(crate) fn classes(&self) -> [&[String]; 3] {
                [&self.exact, &self.volatile, &self.gap]
            }
        }

        #[derive(Clone, Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct Checks {
            pub http_status: bool,
            pub headers: HeaderCheck,
            pub body: BodyCheck,
        }

        #[derive(Clone, Debug, Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        pub(crate) enum BodyCheck {
            Empty,
            Text,
            Single { envelope: EnvelopeCheck },
            Batch { elements: Vec<EnvelopeCheck> },
        }

        pub(crate) const PINNED_NETWORK: &str = "regtest";

        #[derive(Debug)]
        pub(crate) enum LoadError {
            Violation(String),
            Io(std::io::Error),
        }

        impl core::fmt::Display for LoadError {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    Self::Violation(why) => write!(f, "corpus violation: {why}"),
                    Self::Io(error) => write!(f, "corpus io error: {error}"),
                }
            }
        }

        pub(crate) const PINNED_TIP_HEIGHT: u64 = 0;

        pub(crate) const PINNED_TIP_HASH: &str =
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
        impl std::error::Error for LoadError {}

        pub(crate) fn load_corpus() -> Result<BTreeMap<String, Fixture>, LoadError> {
            let reference = reference_set::reference_set()
                .map_err(|error| LoadError::Violation(error.to_string()))?;
            load_corpus_from(&corpus_dir(), &reference.release)
        }

        fn load_corpus_from(
            dir: &Path,
            release: &reference_set::ReleaseIdentity,
        ) -> Result<BTreeMap<String, Fixture>, LoadError> {
            let corpus_dir = corpus_io::open(dir)?;
            let entries = corpus_io::entries(&corpus_dir, dir)?;
            let mut fixture_count = 0_usize;
            let mut corpus_bytes = 0_u64;
            let mut fixtures = BTreeMap::new();
            for name in entries {
                let name = name?;
                fixture_count += 1;
                if fixture_count > MAX_FIXTURE_COUNT {
                    return Err(LoadError::Violation(format!(
                        "corpus holds more than the ceiling of {MAX_FIXTURE_COUNT} entries"
                    )));
                }
                let path = dir.join(&name);
                if path
                    .extension()
                    .is_none_or(|ext| ext.to_string_lossy() != "json")
                {
                    return Err(LoadError::Violation(format!(
                        "{}: the corpus carries fixtures only; non-JSON entries are refused",
                        path.display()
                    )));
                }
                let bytes = corpus_io::read_regular_bounded(&corpus_dir, &name, &path)?;
                let actual = len_u64(bytes.len());
                corpus_bytes += actual;
                if corpus_bytes > MAX_CORPUS_BYTES {
                    return Err(LoadError::Violation(format!(
                        "corpus exceeds the total ceiling of {MAX_CORPUS_BYTES} actual bytes"
                    )));
                }
                let text = String::from_utf8(bytes).map_err(|error| {
                    LoadError::Violation(format!("{}: not valid utf-8: {error}", path.display()))
                })?;
                enforce_depth(&text, &path)?;
                let mut fixture: Fixture = sonic_rs::from_str(&text).map_err(|error| {
                    LoadError::Violation(format!("{}: {error}", path.display()))
                })?;
                settle_body_lengths(&mut fixture);
                validate_fixture(&fixture, &path, release)?;
                if fixtures.insert(fixture.id.clone(), fixture).is_some() {
                    return Err(LoadError::Violation(format!(
                        "duplicate fixture id in {}",
                        path.display()
                    )));
                }
            }
            if fixtures.is_empty() {
                return Err(LoadError::Violation("corpus is empty".to_owned()));
            }
            Ok(fixtures)
        }

        #[cfg(unix)]
        mod corpus_io {
            use std::io::Read as _;
            use std::path::Path;

            use super::{LoadError, MAX_FIXTURE_BYTES, len_u64};

            pub(super) type CorpusDir = rustix::fd::OwnedFd;

            pub(super) fn open(dir: &Path) -> Result<CorpusDir, LoadError> {
                rustix::fs::open(
                    dir,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC
                        | rustix::fs::OFlags::DIRECTORY,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|error| {
                    LoadError::Violation(format!(
                        "{}: corpus directory could not be opened no-follow: {error}",
                        dir.display()
                    ))
                })
            }

            pub(super) fn entries<'a>(
                dir: &'a CorpusDir,
                path: &'a Path,
            ) -> Result<Box<dyn Iterator<Item = Result<String, LoadError>> + 'a>, LoadError>
            {
                let inner = rustix::fs::Dir::read_from(dir).map_err(|error| {
                    LoadError::Violation(format!(
                        "{}: corpus directory could not be enumerated: {error}",
                        path.display()
                    ))
                })?;
                Ok(Box::new(inner.filter_map(move |entry| match entry {
                    Err(error) => Some(Err(LoadError::Violation(format!(
                        "{}: corpus directory entry could not be read: {error}",
                        path.display()
                    )))),
                    Ok(entry) => {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        (!matches!(name.as_str(), "." | "..")).then_some(Ok(name))
                    }
                })))
            }

            pub(super) fn read_regular_bounded(
                dir: &CorpusDir,
                name: &str,
                path: &Path,
            ) -> Result<Vec<u8>, LoadError> {
                let refuse = |why: &str| {
                    LoadError::Violation(format!(
                        "{}: only regular files may carry fixtures; symlinks and directories are \
                 refused ({why})",
                        path.display()
                    ))
                };
                let file_fd = rustix::fs::openat(
                    dir,
                    name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::NONBLOCK
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|error| {
                    if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::MLINK {
                        refuse("is a symbolic link")
                    } else {
                        LoadError::Violation(format!(
                            "{}: could not be opened: {error}",
                            path.display()
                        ))
                    }
                })?;
                let stat = rustix::fs::fstat(&file_fd).map_err(|error| {
                    LoadError::Violation(format!("{}: fstat failed: {error}", path.display()))
                })?;
                if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                    != rustix::fs::FileType::RegularFile
                {
                    return Err(refuse("is not a regular file"));
                }
                let mut bytes = Vec::new();
                std::fs::File::from(file_fd)
                    .take(MAX_FIXTURE_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(LoadError::Io)?;
                if len_u64(bytes.len()) > MAX_FIXTURE_BYTES {
                    return Err(LoadError::Violation(format!(
                        "{} is above the per-fixture ceiling of {MAX_FIXTURE_BYTES} bytes",
                        path.display()
                    )));
                }
                Ok(bytes)
            }
        }

        #[cfg(windows)]
        mod corpus_io {
            use std::io::Read as _;
            use std::path::Path;

            use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
            use cap_std::fs::{Dir, OpenOptions};

            use super::{LoadError, MAX_FIXTURE_BYTES, len_u64};

            pub(super) type CorpusDir = Dir;

            pub(super) fn open(dir: &Path) -> Result<CorpusDir, LoadError> {
                use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};

                const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

                let file = std::fs::File::options()
                    .read(true)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(dir)
                    .map_err(|error| {
                        LoadError::Violation(format!(
                            "{}: corpus directory could not be opened no-follow: {error}",
                            dir.display()
                        ))
                    })?;
                let metadata = file.metadata().map_err(|error| {
                    LoadError::Violation(format!(
                        "{}: corpus directory could not be opened no-follow: {error}",
                        dir.display()
                    ))
                })?;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                    || !metadata.is_dir()
                {
                    return Err(LoadError::Violation(format!(
                        "{}: corpus directory could not be opened no-follow: not a directory",
                        dir.display()
                    )));
                }
                Ok(Dir::from_std_file(file))
            }

            pub(super) fn entries<'a>(
                dir: &'a CorpusDir,
                path: &'a Path,
            ) -> Result<Box<dyn Iterator<Item = Result<String, LoadError>> + 'a>, LoadError>
            {
                let inner = dir.entries().map_err(|error| {
                    LoadError::Violation(format!(
                        "{}: corpus directory could not be enumerated: {error}",
                        path.display()
                    ))
                })?;
                Ok(Box::new(inner.map(move |entry| {
                    entry
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                        .map_err(|error| {
                            LoadError::Violation(format!(
                                "{}: corpus directory entry could not be read: {error}",
                                path.display()
                            ))
                        })
                })))
            }

            pub(super) fn read_regular_bounded(
                dir: &CorpusDir,
                name: &str,
                path: &Path,
            ) -> Result<Vec<u8>, LoadError> {
                let refuse = |why: &str| {
                    LoadError::Violation(format!(
                        "{}: only regular files may carry fixtures; symlinks and directories are \
                 refused ({why})",
                        path.display()
                    ))
                };
                let metadata = dir.symlink_metadata(name).map_err(|error| {
                    LoadError::Violation(format!(
                        "{}: could not be opened: {error}",
                        path.display()
                    ))
                })?;
                if metadata.file_type().is_symlink() {
                    return Err(refuse("is a symbolic link"));
                }
                if !metadata.is_file() {
                    return Err(refuse("is not a regular file"));
                }
                let mut options = OpenOptions::new();
                options.read(true).follow(FollowSymlinks::No);
                let file = dir.open_with(name, &options).map_err(|error| {
                    LoadError::Violation(format!(
                        "{}: could not be opened: {error}",
                        path.display()
                    ))
                })?;
                if !file
                    .metadata()
                    .map_err(|error| {
                        LoadError::Violation(format!("{}: fstat failed: {error}", path.display()))
                    })?
                    .is_file()
                {
                    return Err(refuse("is not a regular file"));
                }
                let mut bytes = Vec::new();
                file.take(MAX_FIXTURE_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(LoadError::Io)?;
                if len_u64(bytes.len()) > MAX_FIXTURE_BYTES {
                    return Err(LoadError::Violation(format!(
                        "{} is above the per-fixture ceiling of {MAX_FIXTURE_BYTES} bytes",
                        path.display()
                    )));
                }
                Ok(bytes)
            }
        }

        #[must_use]
        pub(crate) fn corpus_dir() -> PathBuf {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/serving/corpus/core-31.1")
        }

        fn enforce_depth(text: &str, path: &Path) -> Result<(), LoadError> {
            let mut depth = 0_usize;
            let mut in_string = false;
            let mut escaped = false;
            for byte in text.bytes() {
                match byte {
                    b'\\' if in_string => escaped = !escaped,
                    b'"' if !escaped => in_string = !in_string,
                    b'{' | b'[' if !in_string => {
                        depth += 1;
                        if depth > MAX_JSON_DEPTH {
                            return Err(LoadError::Violation(format!(
                                "{} exceeds the nesting ceiling of {MAX_JSON_DEPTH}",
                                path.display()
                            )));
                        }
                    }
                    b'}' | b']' if !in_string => depth = depth.saturating_sub(1),
                    _ => {}
                }
                if byte != b'\\' {
                    escaped = false;
                }
            }
            Ok(())
        }

        fn settle_body_lengths(fixture: &mut Fixture) {
            let settle = |tuple: &mut HttpTuple| match &tuple.body {
                BodyForm::Empty => tuple.body_len = Some(0),
                BodyForm::Text { text } => tuple.body_len = Some(len_u64(text.len())),
                BodyForm::Json { .. } => tuple.body_len = None,
            };
            settle(&mut fixture.core);
            if let Some(current) = fixture.current.as_mut() {
                settle(current);
            }
        }

        fn validate_tuple_content_length(
            tuple: &HttpTuple,
            label: &str,
            path: &Path,
        ) -> Result<(), LoadError> {
            let declared: Vec<&str> = tuple
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.as_str())
                .collect();
            let fail =
                |why: String| LoadError::Violation(format!("{}: {label}: {why}", path.display()));
            if declared.len() > 1 {
                return Err(fail("duplicate Content-Length headers".to_owned()));
            }
            if tuple.status == 204 {
                if tuple.body_len != Some(0) {
                    return Err(fail("204 response must have an empty body".to_owned()));
                }
                if let Some(value) = declared.first() {
                    if *value != "0" || declared.len() != 1 {
                        return Err(fail(
                            "204 Content-Length must be absent or exactly \"0\"".to_owned(),
                        ));
                    }
                }
                return Ok(());
            }
            match (declared.first(), tuple.body_len) {
                (None, _) => Ok(()),
                (Some(_), None) => Err(fail(String::from(
                    "Content-Length is pinned on a JSON-body tuple, but that wire length is \
             derived framing; remove the literal and rely on the live invariant",
                ))),
                (Some(value), Some(length)) => {
                    let parsed: Option<u64> = (*value).parse().ok().filter(|_| {
                        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                    });
                    match parsed {
                        Some(parsed) if parsed == length => Ok(()),
                        Some(parsed) => Err(fail(format!(
                            "Content-Length {parsed} does not equal the body's actual {length} bytes"
                        ))),
                        None => Err(fail("Content-Length must be ASCII digits only".to_owned())),
                    }
                }
            }
        }

        fn validate_fixture(
            fixture: &Fixture,
            path: &Path,
            release: &reference_set::ReleaseIdentity,
        ) -> Result<(), LoadError> {
            let stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .ok_or_else(|| {
                    LoadError::Violation(format!("{}: unreadable file stem", path.display()))
                })?;
            if stem != fixture.id {
                return Err(LoadError::Violation(format!(
                    "{}: id {:?} does not match the file stem",
                    path.display(),
                    fixture.id
                )));
            }
            if fixture.description.trim().is_empty() {
                return Err(LoadError::Violation(format!(
                    "{}: every fixture must describe what its case proves",
                    path.display()
                )));
            }

            let derived = derive_request_methods(&fixture.request.body, fixture.core.status)
                .map_err(|why| LoadError::Violation(format!("{}: {why}", path.display())))?;
            if derived != fixture.request.methods {
                return Err(LoadError::Violation(format!(
                    "{}: request methods {:?} do not match the methods derived from the body {:?}",
                    path.display(),
                    fixture.request.methods,
                    derived
                )));
            }

            validate_provenance(&fixture.provenance, path, release)?;
            match (
                &fixture.relation,
                &fixture.current,
                &fixture.gap,
                &fixture.gap_paths,
            ) {
                (Relation::Exact, None, None, paths) if paths.is_empty() => {}
                (Relation::Exact, _, _, _) => {
                    return Err(LoadError::Violation(format!(
                        "{}: an exact relation must not pin a current tuple, a gap id or gap paths",
                        path.display()
                    )));
                }
                (Relation::KnownGap, Some(_), Some(gap), paths)
                    if !gap.trim().is_empty() && !paths.is_empty() => {}
                (Relation::KnownGap, _, _, _) => {
                    return Err(LoadError::Violation(format!(
                        "{}: a known gap must pin the current tuple, one concrete gap id and at \
                 least one gap path",
                        path.display()
                    )));
                }
            }
            manifest_check::check_fixture_methods(fixture, MANIFEST, SurfaceKind::Rpc)
                .map_err(|why| LoadError::Violation(format!("{}: {why}", path.display())))?;
            validate_tuple_content_length(&fixture.core, "core", path)?;
            if let Some(current) = fixture.current.as_ref() {
                validate_tuple_content_length(current, "current", path)?;
            }
            validate_header_partition(fixture, path)?;
            validate_result_partition(fixture, path)
        }

        fn validate_provenance(
            provenance: &Provenance,
            path: &Path,
            release: &reference_set::ReleaseIdentity,
        ) -> Result<(), LoadError> {
            if provenance.core_version != format!("{}.0", release.core_version)
                || format!(
                    "Bitcoin Core daemon version v{} bitcoind",
                    provenance.core_version
                ) != release.version_output
            {
                return Err(LoadError::Violation(format!(
                    "{}: pinned version {:?} does not match selected release {:?}",
                    path.display(),
                    provenance.core_version,
                    release.version_output
                )));
            }
            if provenance.core_source_commit != release.source_commit {
                return Err(LoadError::Violation(format!(
                    "{}: pinned source commit does not match the selected Core release",
                    path.display()
                )));
            }
            if provenance.tip_height != PINNED_TIP_HEIGHT || provenance.tip_hash != PINNED_TIP_HASH
            {
                return Err(LoadError::Violation(format!(
                    "{}: pinned tip identity does not match the captured regtest genesis",
                    path.display()
                )));
            }
            if provenance.evidence.trim().is_empty() {
                return Err(LoadError::Violation(format!(
                    "{}: every fixture must cite the probe evidence it was transcribed from",
                    path.display()
                )));
            }
            if provenance.core_binary_sha256
                != release.capture_bitcoind_sha256().to_lower_hex_string()
            {
                return Err(LoadError::Violation(format!(
                    "{}: pinned binary digest does not match the selected Core release",
                    path.display()
                )));
            }
            if provenance.network != PINNED_NETWORK {
                return Err(LoadError::Violation(format!(
                    "{}: capture network {:?} is not {PINNED_NETWORK}",
                    path.display(),
                    provenance.network
                )));
            }
            Ok(())
        }

        fn validate_header_partition(fixture: &Fixture, path: &Path) -> Result<(), LoadError> {
            let fail = |why: String| LoadError::Violation(format!("{}: {why}", path.display()));
            let pinned = match (&fixture.relation, &fixture.current) {
                (Relation::Exact, _) => &fixture.core,
                (Relation::KnownGap, Some(current)) => current,
                (Relation::KnownGap, None) => {
                    return Err(fail("known gap without a pinned current tuple".to_owned()));
                }
            };
            if fixture.checks.headers.body_length
                && fixture.checks.headers.class_of("content-length").is_some()
            {
                return Err(fail(
                    "header Content-Length is owned by the derived body_length class and \
             must not also be classified exact, volatile or gap"
                        .to_owned(),
                ));
            }
            let headers = &fixture.checks.headers;
            let mut claimed: std::collections::BTreeMap<String, &str> =
                std::collections::BTreeMap::new();
            for (index, class) in headers.classes().into_iter().enumerate() {
                let class_name = ["exact", "volatile", "gap"][index];
                for name in class {
                    let lower = name.to_ascii_lowercase();
                    if let Some(previous) = claimed.insert(lower.clone(), class_name) {
                        return Err(fail(format!(
                            "header {name:?} is classified both {previous:?} and {class_name:?}"
                        )));
                    }
                    if class_name != "volatile"
                        && pinned
                            .headers
                            .iter()
                            .all(|(candidate, _)| !candidate.eq_ignore_ascii_case(&lower))
                    {
                        return Err(fail(format!(
                            "header {name:?} is classified {class_name:?} but the pinned tuple \
                     does not carry it, so nothing can be compared there"
                        )));
                    }
                    if class_name == "gap" {
                        let declared = format!("headers.{lower}");
                        if !fixture.gap_paths.contains(&declared) {
                            return Err(fail(format!(
                                "gap header {name:?} must be declared as {declared:?} in gap_paths"
                            )));
                        }
                    }
                }
            }
            if matches!(fixture.relation, Relation::Exact) && !headers.gap.is_empty() {
                return Err(fail(
                    "an exact relation must not classify any header as gap".to_owned(),
                ));
            }
            Ok(())
        }

        fn validate_result_partition(fixture: &Fixture, path: &Path) -> Result<(), LoadError> {
            let fail = |why: String| LoadError::Violation(format!("{}: {why}", path.display()));
            let pairs: Vec<(usize, &EnvelopeCheck, Option<&Value>)> =
                match (&fixture.checks.body, &fixture.core.body) {
                    (BodyCheck::Single { envelope }, BodyForm::Json { value }) => {
                        vec![(0_usize, envelope, Some(value))]
                    }
                    (BodyCheck::Batch { elements }, BodyForm::Json { value }) => {
                        let Some(rows) = value.as_array() else {
                            return Err(fail(
                                "pinned Core batch body is not a JSON array".to_owned(),
                            ));
                        };
                        if rows.len() != elements.len() {
                            return Err(fail(format!(
                                "batch checks cover {} elements but the pinned Core body holds {}",
                                elements.len(),
                                rows.len()
                            )));
                        }
                        rows.iter()
                            .zip(elements)
                            .enumerate()
                            .map(|(index, (value, envelope))| (index, envelope, Some(value)))
                            .collect()
                    }
                    (BodyCheck::Empty | BodyCheck::Text, _) => Vec::new(),
                    _ => {
                        return Err(fail(
                            "check form does not match the pinned Core body form".to_owned(),
                        ));
                    }
                };
            for (envelope_index, envelope, core_envelope) in pairs {
                let Some(result) = core_envelope.and_then(|row| row.get("result")) else {
                    continue;
                };
                let Some(result_object) = result.as_object() else {
                    continue;
                };
                let mut claimed: std::collections::BTreeMap<&str, &str> =
                    std::collections::BTreeMap::new();
                for (class, keys) in envelope.result.classes() {
                    for key in keys {
                        if let Some(previous) = claimed.insert(key.as_str(), class) {
                            return Err(fail(format!(
                                "result key {key:?} is classified both {previous:?} and {class:?}"
                            )));
                        }
                        if class == "gap" {
                            if fixture.relation != Relation::KnownGap {
                                return Err(fail(
                                    "gap classification requires a known-gap relation".to_owned(),
                                ));
                            }
                            let Some(current_result) =
                                pinned_current_result(fixture, envelope_index)
                            else {
                                return Err(fail(
                                    "gap classification requires a pinned current tuple".to_owned(),
                                ));
                            };
                            let current_value = current_result.get(key.as_str());
                            let Some(current_value) = current_value else {
                                return Err(fail(format!(
                                    "result key {key:?} is classified \"gap\" but the pinned current \
                             result does not carry the live shape"
                                )));
                            };
                            let Some(core_value) = result_object.get(key) else {
                                continue;
                            };
                            if super::compare::value_equal(core_value, current_value) {
                                return Err(fail(format!(
                                    "result key {key:?} is classified \"gap\" but the pinned Core and \
                             current values are identical, so nothing diverges there"
                                )));
                            }
                            continue;
                        }
                        if !result_object.contains_key(key) {
                            return Err(fail(format!(
                                "result key {key:?} is classified {class:?} but the pinned Core result \
                         does not carry it"
                            )));
                        }
                    }
                }
                for (key, _) in result_object {
                    if !claimed.contains_key(&key) {
                        return Err(fail(format!(
                            "pinned Core result key {key:?} is not classified exactly once"
                        )));
                    }
                }
            }
            Ok(())
        }

        fn derive_request_methods(body: &str, status: u16) -> Result<Vec<String>, String> {
            let parsed: Value = match sonic_rs::from_str(body) {
                Ok(parsed) => parsed,
                Err(_) if status == 500 => return Ok(Vec::new()),
                Err(_) => {
                    return Err(
                "request body is not valid JSON; only the parse-error case may send malformed              bytes"
                    .to_owned(),
            );
                }
            };
            if let Some(request) = parsed.as_object() {
                return Ok(vec![request_method(request, "request")?]);
            }
            if let Some(requests) = parsed.as_array() {
                let mut methods = Vec::with_capacity(requests.len());
                for (index, request) in requests.iter().enumerate() {
                    let Some(request) = request.as_object() else {
                        return Err(format!(
                            "batch element {index} is not a JSON-RPC request object"
                        ));
                    };
                    methods.push(request_method(request, &format!("batch element {index}"))?);
                }
                return Ok(methods);
            }
            Err("request body must be a JSON-RPC object or a batch array".to_owned())
        }

        fn request_method(request: &sonic_rs::Object, what: &str) -> Result<String, String> {
            let Some(method) = request.get(&"method") else {
                return Err(format!("{what} carries no method member"));
            };
            let Some(method) = method.as_str() else {
                return Err(format!("{what} method member is not a string"));
            };
            Ok(method.to_owned())
        }

        fn pinned_current_result(fixture: &Fixture, envelope_index: usize) -> Option<&Value> {
            let current = &fixture.current.as_ref()?.body;
            let BodyForm::Json { value } = current else {
                return None;
            };
            if let Some(rows) = value.as_array() {
                rows.get(envelope_index)?.get("result")
            } else {
                value.get("result")
            }
        }

        #[cfg(test)]
        mod tests {
            use sonic_rs::{JsonValueMutTrait as _, JsonValueTrait as _, Value};

            use super::super::TestError;
            use super::{load_corpus_from, reference_set};

            const FIXTURE_NAME: &str = "01_getblockchaininfo_v2_positional.json";
            const CAPTURED_FIXTURE: &str = include_str!(
                "../../testdata/serving/corpus/core-31.1/01_getblockchaininfo_v2_positional.json"
            );

            fn captured_fixture() -> Result<Value, sonic_rs::Error> {
                sonic_rs::from_str(CAPTURED_FIXTURE)
            }

            fn assert_reference_rejected(fixture: &Value, reason: &str) -> Result<(), TestError> {
                let dir = tempfile::tempdir()?;
                std::fs::write(dir.path().join(FIXTURE_NAME), sonic_rs::to_vec(fixture)?)?;
                let Err(error) =
                    load_corpus_from(dir.path(), &reference_set::reference_set()?.release)
                else {
                    return Err(TestError::Missing("invalid Core reference was accepted"));
                };
                let message = error.to_string();
                assert!(message.contains(FIXTURE_NAME), "{message}");
                assert!(message.contains(reason), "expected {reason:?}: {message}");
                Ok(())
            }

            // API-07
            #[test]
            fn corpus_rejects_missing_core_reference_fields() -> Result<(), TestError> {
                for field in ["core_version", "core_source_commit", "core_binary_sha256"] {
                    let mut fixture = captured_fixture()?;
                    fixture["provenance"]
                        .as_object_mut()
                        .ok_or(TestError::Missing("captured provenance must be an object"))?
                        .remove(&field);
                    assert_reference_rejected(&fixture, &format!("missing field `{field}`"))?;
                }
                Ok(())
            }

            #[test]
            fn corpus_rejects_non_pinned_core_version() -> Result<(), TestError> {
                for version in ["31.0.0", "31.99.0", ""] {
                    let mut fixture = captured_fixture()?;
                    fixture["provenance"]["core_version"] = Value::from(version);
                    assert_reference_rejected(&fixture, "pinned version")?;
                }
                Ok(())
            }

            // API-07
            #[test]
            fn corpus_rejects_mismatched_or_empty_core_digest() -> Result<(), TestError> {
                let original = captured_fixture()?;
                let digest = original["provenance"]["core_binary_sha256"]
                    .as_str()
                    .ok_or(TestError::Missing(
                        "captured binary digest must be a string",
                    ))?;
                let mut changed = digest.to_owned();
                changed.replace_range(..1, if digest.starts_with('0') { "1" } else { "0" });
                for digest in [changed.as_str(), ""] {
                    let mut fixture = original.clone();
                    fixture["provenance"]["core_binary_sha256"] = Value::from(digest);
                    assert_reference_rejected(&fixture, "pinned binary digest")?;
                }
                Ok(())
            }

            #[test]
            fn exact_401_tuple_checks_volatile_presence_on_the_live_reply_only()
            -> Result<(), TestError> {
                use super::super::compare::{LiveChain, compare};
                use super::{BodyForm, Fixture, HttpTuple};

                const AUTH_401: &str =
                    include_str!("../../testdata/serving/corpus/core-31.1/17_auth_absent.json");
                let fixture: Fixture = sonic_rs::from_str(AUTH_401)?;
                let chain = LiveChain {
                    blocks: 0,
                    headers: 0,
                    best_block_hash: String::new(),
                };
                let live = |headers: &[(&str, &str)]| HttpTuple {
                    status: 401,
                    headers: headers
                        .iter()
                        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                        .collect(),
                    body_len: Some(0),
                    body: BodyForm::Empty,
                };
                let full = live(&[
                    ("WWW-Authenticate", "Basic realm=\"jsonrpc\""),
                    ("Content-Length", "0"),
                    ("Content-Type", "text/html; charset=ISO-8859-1"),
                    ("Connection", "close"),
                ]);
                compare(&fixture, &full, &chain)
                    .map_err(|mismatch| format!("full 401 tuple rejected: {mismatch}"))?;

                let mut without_connection = full.clone();
                without_connection
                    .headers
                    .retain(|(name, _)| !name.eq_ignore_ascii_case("connection"));
                let mut without_challenge = full.clone();
                without_challenge
                    .headers
                    .retain(|(name, _)| !name.eq_ignore_ascii_case("www-authenticate"));
                let mut wrong_type = full;
                wrong_type
                    .headers
                    .iter_mut()
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                    .ok_or("live tuple must carry a content type")?
                    .1 = "application/json".to_owned();
                for (label, tuple) in [
                    ("declared volatile header", without_connection),
                    ("exact challenge", without_challenge),
                    ("exact content type", wrong_type),
                ] {
                    assert!(
                        compare(&fixture, &tuple, &chain).is_err(),
                        "a live reply with a bad {label} must be rejected"
                    );
                }
                Ok(())
            }

            #[test]
            fn corpus_rejects_stale_fixture_after_reference_changes() -> Result<(), TestError> {
                let dir = tempfile::tempdir()?;
                std::fs::write(dir.path().join(FIXTURE_NAME), CAPTURED_FIXTURE)?;
                let reference =
                    reference_set::load_reference_set(bitcoin_rs_serving::manifest::MANIFEST_TOML)?;
                for (field, reason) in [
                    ("core_version", "pinned version"),
                    ("source_commit", "pinned source commit"),
                    ("bitcoind_sha256", "pinned binary digest"),
                    ("version_output", "pinned version"),
                ] {
                    let mut edited = reference.release.clone();
                    match field {
                        "core_version" => edited.core_version = "31.2".to_owned(),
                        "source_commit" => {
                            edited.source_commit =
                                "0000000000000000000000000000000000000000".to_owned();
                        }
                        "bitcoind_sha256" => edited.canonical.bitcoind_sha256 = [0; 32],
                        "version_output" => {
                            edited.version_output =
                                "Bitcoin Core daemon version v31.2.0".to_owned();
                        }
                        _ => unreachable!(),
                    }
                    let Err(error) = load_corpus_from(dir.path(), &edited) else {
                        return Err(
                            format!("old fixture was accepted after changing {field}").into()
                        );
                    };
                    let message = error.to_string();
                    assert!(message.contains(FIXTURE_NAME), "{message}");
                    assert!(message.contains(reason), "{message}");
                }
                Ok(())
            }
        }
    }
    pub(crate) mod harness {
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::thread::JoinHandle;

        use bitcoin_rs_node::state::NodeState;
        use bitcoin_rs_serving::context::{
            ChainHandles, Context, ContextHandles, IndexHandles, MempoolHandles, NetworkHandles,
        };
        use bitcoin_rs_serving::{Auth, Handler, RpcServer};
        use tempfile::TempDir;

        use super::chain::{SeedChain, apply_genesis, current_tip, regtest_config, seed_chain};
        use super::compare::LiveChain;
        use super::fixture::RequestAuth;
        use super::http::{Connection, RawRequest, RawResponse, base64, wait_for_server};
        use super::limits::{SERVER_IDLE_TIMEOUT, SERVER_MAX_CONNECTIONS};
        use super::{GateResult, fail};

        pub(crate) const REPLAY_USER: &str = "parity";
        pub(crate) const REPLAY_PASSWORD: &str = "parity-secret";

        /// Field order is load-bearing: `state` closes its storage handles before
        /// `_datadir` deletes the directory.
        pub(crate) struct NodeHarness {
            pub state: NodeState,
            _datadir: TempDir,
        }

        impl NodeHarness {
            pub(crate) fn open() -> GateResult<Self> {
                let datadir = tempfile::tempdir()?;
                let config = regtest_config(&datadir.path().join("node"));
                let state = NodeState::open(config, None).map_err(fail)?;
                apply_genesis(&state)?;
                Ok(Self {
                    state,
                    _datadir: datadir,
                })
            }

            pub(crate) fn seed(&self, blocks: u32) -> GateResult<SeedChain> {
                seed_chain(&self.state, blocks)
            }

            pub(crate) fn live_chain(&self) -> GateResult<LiveChain> {
                let applied = current_tip(&self.state)?;
                let headers = self
                    .state
                    .chainstate()
                    .header_tip()
                    .map_or(applied.height, |header| header.height);
                Ok(LiveChain {
                    blocks: u64::from(applied.height),
                    headers: u64::from(headers),
                    best_block_hash: applied.hash.to_string_be(),
                })
            }
        }

        pub(crate) struct ServerHarness {
            address: SocketAddr,
            shutdown: bitcoin_rs_consensus::latch::LatchWriter,
            join: Option<JoinHandle<()>>,
            transition: bitcoin_rs_execution::chain::StableRead,
        }

        impl ServerHarness {
            pub(crate) fn start(node: &NodeHarness) -> GateResult<Self> {
                let state = &node.state;
                let chainstate = state.chainstate();
                let transition = state.stable_read();
                let ctx = Context::from_handles(ContextHandles {
                    chain: ChainHandles {
                        chain_tip: chainstate.header_tip_reader(),
                        applied_tip: chainstate.applied_tip_reader(),
                        active_tip_wait: Some(chainstate.clone()),
                        progress: chainstate.chain_progress_reader(),
                        blocks: state.block_log_reader(),
                        utxo: chainstate.utxo_reader(),
                        coin_stats: chainstate.coin_stats_handle(),
                        block_tree: chainstate.block_tree_reader(),
                        chain_network: state.config().network,
                        closed_for_recovery: chainstate.closed_for_recovery_reader(),
                        chain_transition: transition.clone(),
                        ..ChainHandles::default()
                    },
                    mempool: MempoolHandles {
                        gateway: state.mempool_gateway(),
                    },
                    indexes: IndexHandles {
                        derived_index: state.derived_index_query(),
                        script_index: state.script_index_query(),
                        compact_filters: state.compact_filter_query(),
                        esplora_tx_index: None,
                        derived_index_status: Some(state.derived_index_status()),
                    },
                    network: NetworkHandles {
                        overlay: bitcoin_rs_wire::overlay::OverlayConfig::default(),
                        peer_table: state.peer_table(),
                        p2p: state.p2p(),
                        local_services: state.p2p().local_services().to_u64(),
                        user_agent: state.p2p().user_agent().to_owned(),
                        v2_transport: state.config().p2p.v2_transport,
                    },
                    mining: bitcoin_rs_serving::context::MiningHandles {
                        mining_control: None,
                    },
                    ..ContextHandles::default()
                });
                let handler = Arc::new(Handler::new(Arc::new(ctx)));
                let auth = Arc::new(Auth::basic(REPLAY_USER, REPLAY_PASSWORD));
                let server = RpcServer::bind(
                    "127.0.0.1:0",
                    auth,
                    handler,
                    SERVER_MAX_CONNECTIONS,
                    SERVER_IDLE_TIMEOUT,
                    false,
                )?;
                let address = server.local_addr()?;
                let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
                let flag = shutdown.reader();
                let join = std::thread::spawn(move || {
                    let _ignored = server.serve_with_shutdown(flag);
                });
                wait_for_server(address)?;
                Ok(Self {
                    address,
                    shutdown,
                    join: Some(join),
                    transition,
                })
            }

            #[must_use]
            pub(crate) fn address(&self) -> SocketAddr {
                self.address
            }

            #[must_use]
            pub(crate) fn chain_transition(&self) -> bitcoin_rs_execution::chain::StableRead {
                self.transition.clone()
            }

            #[must_use]
            pub(crate) fn basic_token() -> String {
                base64(format!("{REPLAY_USER}:{REPLAY_PASSWORD}").as_bytes())
            }

            #[must_use]
            pub(crate) fn wrong_token() -> String {
                base64(b"parity:not-the-password")
            }

            pub(crate) fn replay(
                &self,
                auth: RequestAuth,
                body: &str,
                fragment_at: Option<usize>,
            ) -> GateResult<RawResponse> {
                let authorization = match auth {
                    RequestAuth::Valid => Some(Self::basic_token()),
                    RequestAuth::Invalid => Some(Self::wrong_token()),
                    RequestAuth::Absent => None,
                };
                let request = RawRequest {
                    path: "/",
                    authorization,
                    body: body.to_owned(),
                    keep_alive: true,
                };
                let bytes = request.bytes();
                let mut connection = Connection::connect(self.address)?;
                connection.send_request_fragmented(&bytes, fragment_at)?;
                Ok(connection.read_response()?)
            }
        }

        impl Drop for ServerHarness {
            fn drop(&mut self) {
                self.shutdown.trigger();
                if let Some(join) = self.join.take() {
                    let _ignored = join.join();
                }
            }
        }
    }
    pub(crate) mod http {
        use core::time::Duration;
        use std::io::{ErrorKind, Read, Write};
        use std::net::{SocketAddr, TcpStream};
        use std::time::Instant;

        use super::limits::{
            CONNECT_TIMEOUT, IO_TIMEOUT, MAX_HEADER_LINE_BYTES, MAX_RESPONSE_BODY_BYTES,
            MAX_RESPONSE_HEADERS, MAX_STATUS_LINE_BYTES,
        };

        const READ_BUFFER_CAPACITY: usize = 8 * 1024;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub(crate) struct RawResponse {
            pub(crate) version: String,
            pub(crate) status: u16,
            pub(crate) reason: String,
            pub(crate) headers: Vec<(String, String)>,
            pub(crate) body: Vec<u8>,
        }

        #[derive(Debug)]
        pub(crate) enum HttpError {
            Io(std::io::Error),
            Framing(&'static str),
            DeadlineExceeded,
        }

        impl From<std::io::Error> for HttpError {
            fn from(value: std::io::Error) -> Self {
                Self::Io(value)
            }
        }

        impl core::fmt::Display for HttpError {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    Self::Io(error) => write!(f, "io error: {error}"),
                    Self::Framing(why) => write!(f, "framing violation: {why}"),
                    Self::DeadlineExceeded => write!(f, "absolute connection deadline exceeded"),
                }
            }
        }

        impl std::error::Error for HttpError {}

        pub(crate) struct RawRequest {
            pub(crate) path: &'static str,
            pub(crate) authorization: Option<String>,
            pub(crate) body: String,
            pub(crate) keep_alive: bool,
        }

        impl RawRequest {
            #[must_use]
            pub(crate) fn bytes(&self) -> Vec<u8> {
                let mut out = Vec::new();
                let connection = if self.keep_alive {
                    "keep-alive"
                } else {
                    "close"
                };
                let auth_line = self
                    .authorization
                    .as_deref()
                    .map(|token| format!("Authorization: Basic {token}\r\n"))
                    .unwrap_or_default();
                let head = format!(
                    "POST {} HTTP/1.1\r\nHost: localhost\r\n{auth_line}Content-Type: \
             application/json\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
                    self.path,
                    self.body.len()
                );
                out.extend_from_slice(head.as_bytes());
                out.extend_from_slice(self.body.as_bytes());
                out
            }
        }

        #[must_use]
        pub(crate) fn base64(input: &[u8]) -> String {
            const ALPHABET: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
            for chunk in input.chunks(3) {
                let b0 = u32::from(chunk[0]);
                let b1 = chunk.get(1).map_or(0, |b| u32::from(*b));
                let b2 = chunk.get(2).map_or(0, |b| u32::from(*b));
                let triple = (b0 << 16) | (b1 << 8) | b2;
                let index = |bits: u32| usize::try_from(bits).unwrap_or_default();
                out.push(char::from(ALPHABET[index((triple >> 18) & 0x3f)]));
                out.push(char::from(ALPHABET[index((triple >> 12) & 0x3f)]));
                out.push(if chunk.len() > 1 {
                    char::from(ALPHABET[index((triple >> 6) & 0x3f)])
                } else {
                    '='
                });
                out.push(if chunk.len() > 2 {
                    char::from(ALPHABET[index(triple & 0x3f)])
                } else {
                    '='
                });
            }
            out
        }

        pub(crate) struct Connection {
            stream: TcpStream,
            buffer: Box<[u8; READ_BUFFER_CAPACITY]>,
            buffered_start: usize,
            buffered_end: usize,
            deadline: Instant,
            outstanding_requests: u32,
        }

        impl Connection {
            pub(crate) fn connect(address: SocketAddr) -> Result<Self, HttpError> {
                Self::connect_with_deadline(address, IO_TIMEOUT)
            }

            pub(crate) fn connect_with_deadline(
                address: SocketAddr,
                deadline: Duration,
            ) -> Result<Self, HttpError> {
                let stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)?;
                stream.set_read_timeout(Some(deadline))?;
                stream.set_write_timeout(Some(deadline))?;
                Ok(Self {
                    stream,
                    buffer: Box::new([0_u8; READ_BUFFER_CAPACITY]),
                    buffered_start: 0,
                    buffered_end: 0,
                    deadline: Instant::now() + deadline,
                    outstanding_requests: 0_u32,
                })
            }

            fn remaining(&self) -> Result<Duration, HttpError> {
                self.deadline
                    .checked_duration_since(Instant::now())
                    .ok_or(HttpError::DeadlineExceeded)
            }

            fn rearm_write(&self) -> Result<(), HttpError> {
                self.stream
                    .set_write_timeout(Some(self.remaining()?))
                    .map_err(HttpError::Io)
            }

            fn rearm_read(&self) -> Result<(), HttpError> {
                self.stream
                    .set_read_timeout(Some(self.remaining()?))
                    .map_err(HttpError::Io)
            }

            fn fill(&mut self) -> Result<(), HttpError> {
                self.rearm_read()?;
                let chunk = self.stream.read(self.buffer.as_mut_slice());
                match chunk {
                    Ok(0) => Err(HttpError::Framing(
                        "connection closed before the response was fully framed",
                    )),
                    Ok(n) => {
                        self.buffered_start = 0;
                        self.buffered_end = n;
                        Ok(())
                    }
                    Err(error)
                        if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                    {
                        Err(HttpError::DeadlineExceeded)
                    }
                    Err(error) => Err(HttpError::Io(error)),
                }
            }

            fn take_buffered(&mut self, target: &mut [u8]) -> Result<usize, HttpError> {
                if self.buffered_start == self.buffered_end {
                    self.fill()?;
                }
                let available = self.buffered_end - self.buffered_start;
                let taken = available.min(target.len());
                target[..taken].copy_from_slice(
                    &self.buffer[self.buffered_start..self.buffered_start + taken],
                );
                self.buffered_start += taken;
                Ok(taken)
            }

            fn read_exact_deadlined(&mut self, target: &mut [u8]) -> Result<(), HttpError> {
                let mut filled = 0;
                while filled < target.len() {
                    let taken = self.take_buffered(&mut target[filled..])?;
                    filled += taken;
                }
                Ok(())
            }

            fn read_byte(&mut self) -> Result<u8, HttpError> {
                let mut one = [0_u8; 1];
                self.read_exact_deadlined(&mut one)?;
                Ok(one[0])
            }

            fn write_all_deadlined(&mut self, bytes: &[u8]) -> Result<(), HttpError> {
                let mut rest = bytes;
                while !rest.is_empty() {
                    self.rearm_write()?;
                    let written = self.stream.write(rest).map_err(|error| {
                        if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
                            HttpError::DeadlineExceeded
                        } else {
                            HttpError::Io(error)
                        }
                    })?;
                    if written == 0 {
                        return Err(HttpError::Framing("write made no progress"));
                    }
                    rest = &rest[written..];
                }
                self.rearm_write()?;
                self.stream.flush()?;
                Ok(())
            }

            pub(crate) fn round_trip(
                &mut self,
                request: &RawRequest,
            ) -> Result<RawResponse, HttpError> {
                let bytes = request.bytes();
                self.send_request_fragmented(&bytes, None)?;
                self.read_response()
            }

            pub(crate) fn send_fragmented(
                &mut self,
                bytes: &[u8],
                split_at: Option<usize>,
            ) -> Result<(), HttpError> {
                match split_at {
                    Some(split) if split > 0 && split < bytes.len() => {
                        self.write_all_deadlined(&bytes[..split])?;
                        self.write_all_deadlined(&bytes[split..])?;
                    }
                    _ => self.write_all_deadlined(bytes)?,
                }
                Ok(())
            }

            pub(crate) fn send_request_fragmented(
                &mut self,
                bytes: &[u8],
                split_at: Option<usize>,
            ) -> Result<(), HttpError> {
                self.send_fragmented(bytes, split_at)?;
                self.outstanding_requests = self.outstanding_requests.saturating_add(1);
                Ok(())
            }

            pub(crate) fn read_response(&mut self) -> Result<RawResponse, HttpError> {
                if self.outstanding_requests == 0 {
                    return Err(HttpError::Framing(
                        "no request is outstanding on this connection",
                    ));
                }
                let status_line = self.read_bounded_line(MAX_STATUS_LINE_BYTES)?;
                let (version, status, reason) = parse_status_line(&status_line)?;
                let mut headers = Vec::new();
                loop {
                    if headers.len() >= MAX_RESPONSE_HEADERS {
                        return Err(HttpError::Framing("too many response headers"));
                    }
                    let line = self.read_bounded_line(MAX_HEADER_LINE_BYTES)?;
                    if line.is_empty() {
                        break;
                    }
                    let Some((name, value)) = line.split_once(':') else {
                        return Err(HttpError::Framing("malformed header line"));
                    };
                    headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
                }
                if headers.iter().any(|(name, _)| name == "transfer-encoding") {
                    return Err(HttpError::Framing(
                        "transfer-encoding is refused; only Content-Length framing is accepted",
                    ));
                }
                let content_length = parse_content_length(&headers, status)?;
                let mut body = vec![0_u8; content_length];
                self.read_exact_deadlined(&mut body)?;
                self.outstanding_requests -= 1;
                Ok(RawResponse {
                    version: version.to_owned(),
                    status,
                    reason,
                    headers,
                    body,
                })
            }

            fn read_bounded_line(&mut self, ceiling: u64) -> Result<String, HttpError> {
                let mut line = Vec::new();
                loop {
                    let byte = self.read_byte()?;
                    if byte == b'\n' {
                        if line.last() != Some(&b'\r') {
                            return Err(HttpError::Framing("lines must end with CRLF"));
                        }
                        line.pop();
                        return String::from_utf8(line)
                            .map_err(|_| HttpError::Framing("header block is not valid utf-8"));
                    }
                    if u64::try_from(line.len()).unwrap_or(u64::MAX) >= ceiling {
                        return Err(HttpError::Framing(
                            "line exceeded the declared byte ceiling",
                        ));
                    }
                    line.push(byte);
                }
            }
        }

        fn parse_status_line(line: &str) -> Result<(&'static str, u16, String), HttpError> {
            const VERSION: &str = "HTTP/1.1";
            let Some(rest) = line.strip_prefix(VERSION) else {
                return Err(HttpError::Framing("only HTTP/1.1 responses are accepted"));
            };
            let Some(rest) = rest.strip_prefix(' ') else {
                return Err(HttpError::Framing("malformed status line separator"));
            };
            let (code, reason) = rest
                .split_once(' ')
                .ok_or(HttpError::Framing("malformed status line"))?;
            if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(HttpError::Framing("status code must be three ASCII digits"));
            }
            let status = code
                .parse::<u16>()
                .map_err(|_| HttpError::Framing("status code must be three ASCII digits"))?;
            Ok((VERSION, status, reason.to_owned()))
        }

        fn parse_content_length(
            headers: &[(String, String)],
            status: u16,
        ) -> Result<usize, HttpError> {
            let declared: Vec<&str> = headers
                .iter()
                .filter(|(name, _)| name == "content-length")
                .map(|(_, value)| value.as_str())
                .collect();
            if status == 204 {
                return match declared.as_slice() {
                    [] => Ok(0),
                    [single] if *single == "0" => Ok(0),
                    _ => Err(HttpError::Framing(
                        "204 Content-Length must be absent or exactly \"0\"",
                    )),
                };
            }
            match declared.as_slice() {
                [] => Err(HttpError::Framing(
                    "response without a Content-Length header",
                )),
                [single] => {
                    if single.is_empty() || !single.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err(HttpError::Framing(
                            "Content-Length must be ASCII digits only",
                        ));
                    }
                    let length: usize = single
                        .parse()
                        .map_err(|_| HttpError::Framing("Content-Length above addressable size"))?;
                    if length > MAX_RESPONSE_BODY_BYTES {
                        return Err(HttpError::Framing(
                            "Content-Length above the production body ceiling",
                        ));
                    }
                    Ok(length)
                }
                [..] => Err(HttpError::Framing("duplicate Content-Length headers")),
            }
        }

        pub(crate) fn wait_for_server(address: SocketAddr) -> Result<(), HttpError> {
            let deadline = std::time::Instant::now() + CONNECT_TIMEOUT;
            loop {
                match TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
                    Ok(stream) => {
                        drop(stream);
                        return Ok(());
                    }
                    Err(_) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(HttpError::Io(error)),
                }
            }
        }

        #[cfg(test)]
        #[expect(clippy::expect_used)]
        mod decoder_refusal_tests {
            use std::net::TcpListener;

            use super::{Connection, HttpError, parse_content_length, parse_status_line};

            #[test]
            fn status_line_table() {
                let (_, status, reason) =
                    parse_status_line("HTTP/1.1 200 OK").expect("valid status line parses");
                assert_eq!((status, reason.as_str()), (200, "OK"));
                for bad in [
                    "HTTP/1.0 200 OK",
                    "HTTP/1.1200 OK",
                    "HTTP/1.1 20 OK",
                    "HTTP/1.1 20X OK",
                    "HTTP/1.1 200",
                ] {
                    assert!(parse_status_line(bad).is_err(), "accepted {bad:?}");
                }
            }

            #[test]
            fn content_length_table() {
                let headers = |pairs: &[(&str, &str)]| {
                    pairs
                        .iter()
                        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                        .collect::<Vec<_>>()
                };
                assert_eq!(
                    parse_content_length(&[], 204).expect("absent 204 length parses"),
                    0
                );
                assert_eq!(
                    parse_content_length(&headers(&[("content-length", "0")]), 204)
                        .expect("zero 204 length parses"),
                    0
                );
                assert!(parse_content_length(&headers(&[("content-length", "5")]), 204).is_err());
                assert_eq!(
                    parse_content_length(&headers(&[("content-length", "12")]), 200)
                        .expect("decimal length parses"),
                    12
                );
                for bad in [
                    &[][..],
                    &[("content-length", "")][..],
                    &[("content-length", "1a")][..],
                ] {
                    assert!(parse_content_length(&headers(bad), 200).is_err());
                }
                assert!(
                    parse_content_length(
                        &headers(&[("content-length", "12"), ("content-length", "12")]),
                        200
                    )
                    .is_err()
                );
                assert!(
                    parse_content_length(&headers(&[("content-length", "16777217")]), 200).is_err()
                );
            }

            #[test]
            fn response_without_outstanding_request_is_refused() {
                let listener = TcpListener::bind("127.0.0.1:0").expect("loopback binds");
                let address = listener.local_addr().expect("bound socket has an address");
                std::thread::spawn(move || listener.accept().ok());
                let mut connection = Connection::connect(address).expect("loopback connects");
                let error = connection
                    .read_response()
                    .expect_err("unsolicited response is refused");
                assert!(matches!(error, HttpError::Framing(_)));
            }

            fn serve_once(canned: &[u8]) -> std::net::SocketAddr {
                let listener = TcpListener::bind("127.0.0.1:0").expect("loopback binds");
                let address = listener.local_addr().expect("bound socket has an address");
                let canned = canned.to_owned();
                std::thread::spawn(move || {
                    let (mut stream, _) = listener.accept().ok()?;
                    let mut discard = [0_u8; 4096];
                    let _ = std::io::Read::read(&mut stream, &mut discard);
                    std::io::Write::write_all(&mut stream, &canned).ok()
                });
                address
            }

            #[test]
            fn wire_level_refusals_and_framed_read() {
                let address = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
                let mut connection = Connection::connect(address).expect("loopback connects");
                connection
                    .send_request_fragmented(b"GET /", None)
                    .expect("request sends");
                let response = connection.read_response().expect("framed response decodes");
                assert_eq!(response.status, 200);
                assert_eq!(response.body, b"hello");

                let mut cases: Vec<Vec<u8>> = vec![
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
                    b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n".to_vec(),
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n".to_vec(),
                ];
                let mut long_status = b"HTTP/1.1 200 ".to_vec();
                long_status.extend(std::iter::repeat_n(b'A', 2000));
                long_status.extend_from_slice(b"\r\n");
                cases.push(long_status);
                for canned in &cases {
                    let address = serve_once(canned);
                    let mut connection = Connection::connect(address).expect("loopback connects");
                    connection
                        .send_request_fragmented(b"GET /", None)
                        .expect("request sends");
                    let error = connection
                        .read_response()
                        .expect_err("wire violation is refused");
                    assert!(
                        matches!(error, HttpError::Framing(_)),
                        "unexpected error: {error:?}"
                    );
                }
            }
        }
    }
    pub(crate) mod limits {
        use core::time::Duration;

        pub(crate) const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1_024 * 1_024;

        pub(crate) const MAX_FIXTURE_BYTES: u64 = 64 * 1_024;

        pub(crate) const MAX_FIXTURE_COUNT: usize = 64;

        pub(crate) const MAX_CORPUS_BYTES: u64 = 1_024 * 1_024;

        pub(crate) const MAX_JSON_DEPTH: usize = 32;

        pub(crate) const MAX_RESPONSE_HEADERS: usize = 64;

        pub(crate) const MAX_HEADER_LINE_BYTES: u64 = 8 * 1_024;

        pub(crate) const MAX_STATUS_LINE_BYTES: u64 = 1_024;

        pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

        pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(20);

        pub(crate) const SERVER_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

        pub(crate) const SERVER_MAX_CONNECTIONS: usize = 8;

        pub(crate) const SEED_CHAIN_BLOCKS: u32 = 2;
    }
    pub(crate) mod manifest_check {
        use bitcoin_rs_serving::manifest::{Entry, SurfaceKind};

        use super::fixture::Fixture;

        #[must_use]
        pub(crate) fn is_shipped_rpc_method(method: &str, manifest: &[Entry]) -> bool {
            manifest.iter().any(|entry| {
                entry.kind == SurfaceKind::Rpc && entry.name == method && entry.shipped()
            })
        }

        pub(crate) fn check_fixture_methods(
            fixture: &Fixture,
            manifest: &[Entry],
            kind: SurfaceKind,
        ) -> Result<(), String> {
            for method in &fixture.request.methods {
                let declared = manifest
                    .iter()
                    .find(|entry| entry.kind == kind && entry.name == method);
                match (fixture.request.expect_methods_in_manifest, declared) {
                    (true, Some(entry)) if entry.shipped() => {}
                    (true, Some(entry)) => {
                        return Err(format!(
                            "method {method:?} is declared in the manifest but not shipped \
                     (status {:?}, since {:?})",
                            entry.status, entry.since
                        ));
                    }
                    (true, None) => {
                        return Err(format!(
                            "fixture expects {method:?} to be a declared manifest method, but no row \
                     names it"
                        ));
                    }
                    (false, Some(_)) => {
                        return Err(format!(
                            "fixture expects {method:?} to be absent from the manifest, but a row \
                     names it; the unknown-method case must stay unknown"
                        ));
                    }
                    (false, None) => {}
                }
            }
            Ok(())
        }
    }
    pub(crate) mod mining {
        pub(crate) mod error {
            #[derive(Debug, thiserror::Error)]
            pub(crate) enum TestError {
                #[error(transparent)]
                Mining(#[from] crate::mining::MiningError),
                #[error(transparent)]
                MiningControl(#[from] crate::mining::MiningControlError),
                #[error(transparent)]
                Mempool(#[from] bitcoin_rs_mempool::MempoolError),
                #[error(transparent)]
                Prioritise(#[from] bitcoin_rs_mempool::PrioritiseError),
                #[error(transparent)]
                Submit(#[from] bitcoin_rs_mempool::SubmitError),
                #[error(transparent)]
                ChainChange(#[from] bitcoin_rs_mempool::ChainChangeError),
                #[error(transparent)]
                Rbf(#[from] bitcoin_rs_mempool::RbfError),
                #[error(transparent)]
                Consensus(#[from] bitcoin_rs_consensus::ConsensusError),
                #[cfg(feature = "pool")]
                #[error(transparent)]
                Job(#[from] crate::mining::pool::JobError),
                #[cfg(feature = "pool")]
                #[error(transparent)]
                Share(#[from] crate::mining::pool::ShareError),
                #[cfg(feature = "pool")]
                #[error(transparent)]
                SessionOpen(#[from] crate::mining::pool::SessionOpenError),
                #[cfg(feature = "pool")]
                #[error(transparent)]
                Sv1Config(#[from] crate::mining::pool::stratum::sv1::ConfigError),
                #[cfg(feature = "pool-sv2")]
                #[error(transparent)]
                Sv2Config(#[from] crate::mining::pool::stratum::sv2::ConfigError),
                #[cfg(feature = "pool-sv2")]
                #[error(transparent)]
                Sv2Transport(#[from] crate::mining::pool::stratum::sv2::TransportError),
                #[cfg(feature = "pool-sv2")]
                #[error(transparent)]
                Sv2(#[from] crate::mining::pool::stratum::sv2::Error),
                #[cfg(feature = "pool-sv2")]
                #[error(transparent)]
                Session(#[from] crate::mining::pool::stratum::sv2::SessionError),
                #[cfg(feature = "pool-sv2")]
                #[error("codec sv2 error: {0:?}")]
                Codec(codec_sv2::Error),
                #[cfg(feature = "pool-sv2")]
                #[error("noise sv2 error: {0:?}")]
                Noise(noise_sv2::Error),
                #[cfg(feature = "pool-sv2")]
                #[error("binary sv2 error: {0:?}")]
                BinarySv2(binary_sv2::Error),
                #[error(transparent)]
                Utf8(#[from] std::str::Utf8Error),
                #[error(transparent)]
                BitcoinDecode(#[from] bitcoin::consensus::encode::Error),
                #[error(transparent)]
                Json(#[from] sonic_rs::Error),
                #[cfg(feature = "pool")]
                #[error("fixture transaction {label} was not committed")]
                Uncommitted { label: u8 },
                #[error(transparent)]
                Io(#[from] std::io::Error),
                #[error(transparent)]
                TryFromInt(#[from] core::num::TryFromIntError),
                #[error(transparent)]
                ParseInt(#[from] std::num::ParseIntError),
                #[error(transparent)]
                SystemTime(#[from] std::time::SystemTimeError),
                #[error(transparent)]
                TryFromSlice(#[from] core::array::TryFromSliceError),
                #[error("missing expected value: {0}")]
                Missing(&'static str),
                #[error(transparent)]
                Support(Box<crate::support::error::TestError>),
            }

            impl From<crate::support::error::TestError> for TestError {
                fn from(error: crate::support::error::TestError) -> Self {
                    Self::Support(Box::new(error))
                }
            }

            impl From<&'static str> for TestError {
                fn from(msg: &'static str) -> Self {
                    Self::Missing(msg)
                }
            }
            #[cfg(feature = "pool-sv2")]
            impl From<codec_sv2::Error> for TestError {
                fn from(err: codec_sv2::Error) -> Self {
                    Self::Codec(err)
                }
            }

            #[cfg(feature = "pool-sv2")]
            impl From<noise_sv2::Error> for TestError {
                fn from(err: noise_sv2::Error) -> Self {
                    Self::Noise(err)
                }
            }

            #[cfg(feature = "pool-sv2")]
            impl From<binary_sv2::Error> for TestError {
                fn from(err: binary_sv2::Error) -> Self {
                    Self::BinarySv2(err)
                }
            }
        }
        pub(crate) mod fixtures {
            #![allow(dead_code)]

            use std::sync::Arc;

            use bitcoin_rs_consensus::primitives::{
                Amount, CompactTarget, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx,
                TxIn, TxOut, Txid, Witness, encode::consensus_bytes,
            };
            use bitcoin_rs_consensus::script::VerifyFlags;
            use bitcoin_rs_consensus::transaction_sigop_cost;
            use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits, SnapshotEntry};
            use bitcoin_rs_serving::mining::{Candidate, CandidateContext};

            pub(crate) const PAYOUT: &[u8] = &[0x51];

            pub(crate) fn p2pkh() -> Vec<u8> {
                [vec![0x76, 0xa9, 0x14], vec![0x11; 20], vec![0x88, 0xac]].concat()
            }

            pub(crate) fn context() -> CandidateContext {
                CandidateContext {
                    previous_block_hash: Hash256::from_le_bytes(&[0x11; 32]),
                    height: 100,
                    version: 0x2000_0000,
                    bits: CompactTarget::from_consensus(0x207f_ffff),
                    min_time: 1,
                    current_time: 2,
                    locktime_cutoff: 1,
                    staged_parent_mtp: 1,
                    network: Network::Regtest,
                    csv_active: true,
                    segwit_active: true,
                    max_weight: 4_000_000,
                    max_size: 4_000_000,
                    max_sigops: 80_000,
                }
            }

            pub(crate) fn zero_fee_pool() -> Mempool {
                Mempool::new(MempoolLimits {
                    min_relay_fee_sat_per_kvb: 0,
                    ..MempoolLimits::default()
                })
            }

            pub(crate) fn insert(
                pool: &mut Mempool,
                tx: Tx,
                vsize: u32,
                fee: u64,
                time: u64,
                height: u32,
            ) -> Result<(), crate::support::TestError> {
                insert_with_cost(pool, tx, vsize, fee, time, height, 0)
            }

            pub(crate) fn insert_with_cost(
                pool: &mut Mempool,
                tx: Tx,
                vsize: u32,
                fee: u64,
                time: u64,
                height: u32,
                sigop_cost: u32,
            ) -> Result<(), crate::support::TestError> {
                pool.insert_entry(MempoolEntry::new(
                    Arc::new(tx),
                    vsize,
                    fee,
                    time,
                    height,
                    sigop_cost,
                ))?;
                Ok(())
            }

            #[derive(Clone, Copy, Debug)]
            pub(crate) struct Forged {
                pub(crate) vsize: u32,
                pub(crate) fee: u64,
                pub(crate) weight: u64,
                pub(crate) size: u32,
                pub(crate) sigop_cost: u32,
            }

            impl Forged {
                pub(crate) const fn new(fee: u64, weight: u64, size: u32) -> Self {
                    Self {
                        vsize: 100,
                        fee,
                        weight,
                        size,
                        sigop_cost: 0,
                    }
                }

                pub(crate) const fn with_vsize(mut self, vsize: u32) -> Self {
                    self.vsize = vsize;
                    self
                }

                pub(crate) const fn with_sigops(mut self, sigop_cost: u32) -> Self {
                    self.sigop_cost = sigop_cost;
                    self
                }
            }

            pub(crate) fn insert_forged(
                pool: &mut Mempool,
                tx: Tx,
                forged: Forged,
            ) -> Result<(), crate::support::TestError> {
                let mut entry = MempoolEntry::new(
                    Arc::new(tx),
                    forged.vsize,
                    forged.fee,
                    1,
                    100,
                    forged.sigop_cost,
                );
                entry.weight = forged.weight;
                entry.size = forged.size;
                pool.insert_entry(entry)?;
                Ok(())
            }

            pub(crate) fn measured_entry(
                tx: &Arc<Tx>,
                fee: u64,
                fee_delta: i64,
                ancestors: Vec<u32>,
            ) -> SnapshotEntry {
                let size = u32::try_from(tx.total_size()).unwrap_or(u32::MAX);
                let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
                let mut entry = forged_entry(
                    Arc::clone(tx),
                    fee,
                    fee_delta,
                    tx.weight(),
                    size,
                    0,
                    ancestors,
                );
                entry.vsize = vsize;
                entry.bip141_vsize = vsize;
                entry.ancestor_size = u64::from(vsize);
                entry
            }

            pub(crate) fn forged_entry(
                tx: Arc<Tx>,
                fee: u64,
                fee_delta: i64,
                weight: u64,
                size: u32,
                sigop_cost: u32,
                ancestors: Vec<u32>,
            ) -> SnapshotEntry {
                let vsize = size.max(1);
                SnapshotEntry {
                    txid: tx.txid(),
                    wtxid: tx.wtxid(),
                    vsize,
                    bip141_vsize: vsize,
                    size,
                    weight,
                    sigop_cost,
                    fee,
                    fee_delta,
                    time: 0,
                    height: 0,
                    ancestor_size: u64::from(vsize),
                    ancestor_fee: fee,
                    ancestor_fee_delta: i128::from(fee_delta),
                    ancestors,
                    tx,
                }
            }

            pub(crate) fn tx(label: u8, value: u64, parent: Option<Txid>) -> Tx {
                build_tx(label, value, parent, Witness::new())
            }

            pub(crate) fn witnessed_tx(label: u8, value: u64, parent: Option<Txid>) -> Tx {
                build_tx(label, value, parent, vec![vec![label; 32]].into())
            }

            fn build_tx(label: u8, value: u64, parent: Option<Txid>, witness: Witness) -> Tx {
                let mut bytes = [0_u8; 32];
                bytes[0] = label;
                Tx {
                    version: 2,
                    inputs: vec![TxIn {
                        previous_output: OutPoint::new(
                            parent.unwrap_or_else(|| Txid(Hash256::from_le_bytes(&bytes))),
                            0,
                        ),
                        script_sig: Script::new(),
                        sequence: Sequence::MAX,
                        witness,
                    }],
                    outputs: vec![TxOut {
                        value: Amount::from_sat(value),
                        script_pubkey: vec![0x51, label].into(),
                    }],
                    lock_time: LockTime::ZERO,
                }
            }

            pub(crate) fn oracle_transaction(
                tx: &Tx,
            ) -> Result<bitcoin::Transaction, crate::support::TestError> {
                Ok(bitcoin::consensus::deserialize(&consensus_bytes(tx))?)
            }

            pub(crate) fn oracle_sigop_cost(tx: &Tx) -> Result<u64, crate::support::TestError> {
                Ok(u64::try_from(
                    oracle_transaction(tx)?.total_sigop_cost(|_| None),
                )?)
            }

            pub(crate) fn selected_fees(candidate: &Candidate) -> u64 {
                candidate.transactions.iter().map(|tx| tx.fee).sum()
            }

            #[expect(clippy::expect_used)]
            pub(crate) fn serialized_size(candidate: &Candidate) -> u64 {
                u64::try_from(
                    candidate
                        .into_unsolved_block()
                        .expect("assembly must serialize")
                        .total_size(),
                )
                .expect("size fits u64")
            }

            pub(crate) fn total_sigop_cost(candidate: &Candidate) -> u64 {
                u64::from(transaction_sigop_cost(
                    &candidate.coinbase,
                    &[],
                    VerifyFlags::NONE,
                )) + candidate
                    .transactions
                    .iter()
                    .map(|tx| u64::from(tx.sigop_cost))
                    .sum::<u64>()
            }
        }
        pub(crate) use error::TestError;
    }
    pub(crate) use error::TestError;

    use std::fmt;

    #[derive(Debug)]
    pub(crate) struct Failure(pub(crate) String);

    impl fmt::Display for Failure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for Failure {}

    #[must_use]
    pub(crate) fn fail(message: impl fmt::Display) -> Failure {
        Failure(message.to_string())
    }

    pub(crate) type GateResult<T> = Result<T, Failure>;

    impl From<std::io::Error> for Failure {
        fn from(value: std::io::Error) -> Self {
            fail(value)
        }
    }

    impl From<sonic_rs::Error> for Failure {
        fn from(value: sonic_rs::Error) -> Self {
            fail(value)
        }
    }

    impl From<fixture::LoadError> for Failure {
        fn from(value: fixture::LoadError) -> Self {
            fail(value)
        }
    }

    impl From<compare::Mismatch> for Failure {
        fn from(value: compare::Mismatch) -> Self {
            fail(value)
        }
    }

    impl From<http::HttpError> for Failure {
        fn from(value: http::HttpError) -> Self {
            fail(value)
        }
    }
}

pub use bitcoin_rs_serving::mining;
