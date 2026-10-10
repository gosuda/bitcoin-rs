//! Worker admission and RPC-only cancellation use the real chain wait owner.

#![expect(clippy::expect_used)]

use super::*;
use crate::context::Context;
use bitcoin_rs_chainstate::Chainstate;
use bitcoin_rs_primitives::Network;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

fn context() -> (Arc<Context>, Arc<Chainstate>) {
    let chainstate = Arc::new(Chainstate::new(
        Network::Regtest,
        Arc::new(arc_swap::ArcSwapOption::empty()),
        Arc::new(arc_swap::ArcSwapOption::empty()),
        Arc::new(parking_lot::RwLock::new(bitcoin_rs_chain::BlockTree::new())),
        Arc::new(bitcoin_rs_utxo::UtxoSet::new()),
        Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        )),
        Arc::new(bitcoin_rs_chainstate::events::ChainEventPublisher::detached(0)),
    ));
    chainstate
        .apply_block(&Network::Regtest.genesis_block(), None)
        .expect("genesis");
    let mut ctx = Context::new();
    ctx.chain.applied_tip = chainstate.applied_tip_reader();
    ctx.chain.active_tip_wait = Some(chainstate.clone());
    (Arc::new(ctx), chainstate)
}

fn send(address: SocketAddr, body: &Value) -> TcpStream {
    let body = sonic_rs::to_string(body).expect("JSON");
    let mut stream = TcpStream::connect(address).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("deadline");
    write!(stream, "POST / HTTP/1.1\r\nHost: {address}\r\nAuthorization: Basic cGFyaXR5OnBhcml0eQ==\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}", body.len()).expect("send");
    stream
}

fn read(mut stream: TcpStream) -> (String, Value) {
    // Blocking calls close keep-alive on success and quota refusal.
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

fn await_waiter(handler: &Handler) {
    let deadline = Instant::now() + Duration::from_secs(1);
    while handler.reserve_blocking_request().is_ok() {
        assert!(
            Instant::now() < deadline,
            "request must enter the bounded wait quota"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

// EOF can precede ConnectionPermit::drop. Retry only the observable 503
// admission refusal; an RPC/JSON/transport error is never treated as busy.
fn ordinary_rpc(address: SocketAddr) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(2);
    let body = serde_json::to_vec(&serde_json::json!({
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

#[test]
fn wait_quota_preserves_ordinary_http_and_server_only_shutdown_returns_tip() {
    let (ctx, chainstate) = context();
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
    let handler = Arc::clone(&server.handler);
    let address = server.local_addr().expect("address");
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&shutdown);
    let server_thread = std::thread::spawn(move || server.serve_with_shutdown(signal));
    let waiting = send(
        address,
        &json!({"id":1,"method":"waitforblockheight","params":[1]}),
    );
    await_waiter(&handler);
    let (head, denied) = read(send(
        address,
        &json!({"id":3,"method":"waitfornewblock","params":[]}),
    ));
    assert!(head.contains("Connection: close"));
    assert_eq!(denied["error"]["code"].as_i64(), Some(-1));
    let ordinary = ordinary_rpc(address);
    assert_eq!(ordinary["result"], serde_json::json!(0));
    shutdown.store(true, Ordering::Release);
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
fn mixed_batch_and_notification_waits_share_admission_and_cancellation() {
    for notification_only in [false, true] {
        let (ctx, _) = context();
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
        let handler = Arc::clone(&server.handler);
        let address = server.local_addr().expect("address");
        let shutdown = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&shutdown);
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
        await_waiter(&handler);
        let ordinary = bitcoin_rs_e2e::rpc::Connection::new(address)
            .rpc(
                &serde_json::json!({"id":3,"method":"getblockcount","params":[]}),
                ("parity", "parity"),
                Instant::now() + Duration::from_secs(1),
            )
            .expect("ordinary RPC");
        assert_eq!(ordinary["result"], serde_json::json!(0));
        shutdown.store(true, Ordering::Release);
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
fn one_worker_rejects_waits_and_direct_dispatch_cannot_bypass_budget() {
    let (ctx, _) = context();
    let handler = Arc::new(Handler::new(Arc::clone(&ctx)));
    handler.configure_blocking_admission(1);
    assert!(
        handler
            .dispatch("waitforblockheight", &json!([-1]))
            .is_err()
    );
    assert_eq!(
        handler
            .dispatch("getblockcount", &json!([]))
            .expect("ordinary")
            .as_u64(),
        Some(0)
    );
    handler.configure_blocking_admission(2);
    let waiter = Arc::clone(&handler);
    let task = std::thread::spawn(move || waiter.dispatch("waitforblockheight", &json!([1])));
    await_waiter(&handler);
    assert!(handler.dispatch("waitfornewblock", &json!([1])).is_err());
    assert_eq!(
        handler
            .dispatch("getblockcount", &json!([]))
            .expect("ordinary")
            .as_u64(),
        Some(0)
    );
    handler.stop();
    assert_eq!(
        task.join().expect("waiter").expect("cancel returns tip")["height"].as_u64(),
        Some(0)
    );
}

#[test]
fn scan_start_is_blocking_but_status_abort_and_gbt_are_outside_this_budget() {
    for params in [
        json!(["start", []]),
        json!({"action":"start","scanobjects":[]}),
        json!({"args":["start",[]]}),
    ] {
        assert!(crate::registry::blocking_request(
            &json!({"method":"scantxoutset","params":params})
        ));
    }
    for params in [
        json!(["status"]),
        json!(["abort"]),
        json!({"action":"status"}),
    ] {
        assert!(!crate::registry::blocking_request(
            &json!({"method":"scantxoutset","params":params})
        ));
    }
    assert!(!crate::registry::blocking_request(
        &json!({"method":"getblocktemplate","params":[{"longpollid":"x"}]})
    ));
}

#[test]
fn rebinding_context_keeps_old_and_new_cancellation_and_budgets_separate() {
    let (ctx, _) = context();
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
    let old_handler = Arc::clone(&old.handler);
    let old_addr = old.local_addr().expect("old address");
    let old_shutdown = Arc::new(AtomicBool::new(false));
    let old_signal = Arc::clone(&old_shutdown);
    let old_thread = std::thread::spawn(move || old.serve_with_shutdown(old_signal));
    let old_wait = send(
        old_addr,
        &json!({"id":1,"method":"waitforblockheight","params":[1]}),
    );
    await_waiter(&old_handler);

    // Bind/start the replacement BEFORE the old server's stop guard runs.
    let new = RpcServer::bind(
        "127.0.0.1:0",
        Arc::new(Auth::basic("parity", "parity")),
        supplied,
        2,
        Duration::from_secs(3),
        false,
    )
    .expect("new bind over same context");
    let new_handler = Arc::clone(&new.handler);
    let new_addr = new.local_addr().expect("new address");
    let new_shutdown = Arc::new(AtomicBool::new(false));
    let new_signal = Arc::clone(&new_shutdown);
    let new_thread = std::thread::spawn(move || new.serve_with_shutdown(new_signal));
    let new_wait = send(
        new_addr,
        &json!({"id":2,"method":"waitforblockheight","params":[1]}),
    );
    await_waiter(&new_handler);
    old_shutdown.store(true, Ordering::Release);
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
            &serde_json::json!({"id":3,"method":"getblockcount","params":[]}),
            ("parity", "parity"),
            Instant::now() + Duration::from_secs(1),
        )
        .expect("replacement ordinary RPC");
    assert_eq!(ordinary["result"], serde_json::json!(0));
    new_shutdown.store(true, Ordering::Release);
    new_thread.join().expect("new server").expect("new exit");
    assert_eq!(read(new_wait).1["result"]["height"].as_u64(), Some(0));
}

#[test]
fn one_connection_server_rejects_waits_before_they_can_occupy_the_only_worker() {
    let (ctx, _) = context();
    let mut server = RpcServer::bind(
        "127.0.0.1:0",
        Arc::new(Auth::basic("parity", "parity")),
        Arc::new(Handler::new(ctx)),
        4,
        Duration::from_secs(3),
        false,
    )
    .expect("bind");
    // The public connection setting can change after bind; serve must enforce
    // its actual value, including a server assembled through public fields.
    server.max_connections = 1;
    let address = server.local_addr().expect("address");
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&shutdown);
    let task = std::thread::spawn(move || server.serve_with_shutdown(signal));
    let (head, answer) = read(send(
        address,
        &json!({"id":1,"method":"waitfornewblock","params":[]}),
    ));
    assert!(head.contains("Connection: close"));
    assert_eq!(answer["error"]["code"].as_i64(), Some(-1));
    let ordinary = ordinary_rpc(address);
    assert_eq!(ordinary["result"], serde_json::json!(0));
    shutdown.store(true, Ordering::Release);
    task.join().expect("server").expect("exit");
}
