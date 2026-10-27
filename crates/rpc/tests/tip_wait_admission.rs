//! Worker admission and RPC-only cancellation HTTP integration tests.
//!
//! CONTRACT: docs/contracts/external-api.md#API-34 — Active-tip waits

#![expect(clippy::expect_used)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bitcoin_rs_chain::{ActiveTipWait, LatchReader, TipSnapshot, TipWaitCondition};
use bitcoin_rs_chainstate::Chainstate;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_rpc::{Auth, Handler, RpcServer, context::Context};
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
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&shutdown);
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

/// A template long-poll holds a blocking worker: with the one slot held it
/// is refused like any other wait, while the same call without a longpoll
/// id waits on nothing and is admitted.
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
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&shutdown);
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
    // No mining control is attached here, so the admitted call answers
    // method-not-found: anything but the quota error proves admission. The
    // denied long-poll's EOF can precede its permit release, so a plain call
    // racing the release is refused with 503: retry the refusal exactly like
    // `ordinary_rpc` instead of asserting the first answer.
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
    shutdown.store(true, Ordering::Release);
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
        observable.wait_for_waiters(1);
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
    let old_shutdown = Arc::new(AtomicBool::new(false));
    let old_signal = Arc::clone(&old_shutdown);
    let old_thread = std::thread::spawn(move || old.serve_with_shutdown(old_signal));
    let old_wait = send(
        old_addr,
        &json!({"id":1,"method":"waitforblockheight","params":[1]}),
    );
    observable.wait_for_waiters(1);

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
    let new_addr = new.local_addr().expect("new address");
    let new_shutdown = Arc::new(AtomicBool::new(false));
    let new_signal = Arc::clone(&new_shutdown);
    let new_thread = std::thread::spawn(move || new.serve_with_shutdown(new_signal));
    let new_wait = send(
        new_addr,
        &json!({"id":2,"method":"waitforblockheight","params":[1]}),
    );
    observable.wait_for_waiters(2);
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
