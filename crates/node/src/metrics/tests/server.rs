use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use parking_lot::Mutex;

use super::super::{EvidenceIdentity, MetricsServer, Sha256Hex, start_metrics};
use super::super::prometheus::PROMETHEUS_HANDLE;

// MetricsServer::bind installs a process-global recorder. Serialize only
// these server tests so another test cannot change the recorder between
// the occupied-bind precondition and its assertion. Production is unchanged.
static SERVER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn unused_ephemeral() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

/// Identity every test process serves; one recorder, one identity.
fn identity() -> EvidenceIdentity {
    EvidenceIdentity {
        binary_sha256: Sha256Hex([1; 32]),
        version: "test".into(),
        config_sha256: Sha256Hex([2; 32]),
        corpus: None,
        backend: "memory".into(),
        durability: "checkpoint-only".into(),
        hardware: "test x1".into(),
    }
}

fn scrape(addr: SocketAddr) -> (u16, String) {
    let mut last = None;
    for _ in 0..50 {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
            Ok(mut stream) => {
                stream
                    .write_all(b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                    .unwrap_or_else(|error| panic!("write scrape request: {error}"));
                stream
                    .flush()
                    .unwrap_or_else(|error| panic!("flush scrape request: {error}"));
                let mut body = String::new();
                stream
                    .read_to_string(&mut body)
                    .unwrap_or_else(|error| panic!("read scrape response: {error}"));
                let status = body
                    .split_whitespace()
                    .nth(1)
                    .and_then(|token| token.parse().ok())
                    .unwrap_or(0);
                return (status, body);
            }
            Err(error) => last = Some(error),
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("scrape connect failed: {last:?}");
}

#[test]
fn occupied_address_bind_errors_and_in_process_retry_succeeds() {
    let _guard = SERVER_TEST_LOCK.lock();
    let shutdown = Arc::new(AtomicBool::new(false));
    let occupied = TcpListener::bind(unused_ephemeral())
        .unwrap_or_else(|error| panic!("occupy port: {error}"));
    let addr = occupied
        .local_addr()
        .unwrap_or_else(|error| panic!("occupied local addr: {error}"));
    let installed_before = PROMETHEUS_HANDLE.lock().is_some();

    let first = start_metrics(Some(addr), Arc::clone(&shutdown), &identity());
    assert!(first.is_err(), "occupied bind must fail");
    assert_eq!(
        PROMETHEUS_HANDLE.lock().is_some(),
        installed_before,
        "failed bind must not install the process recorder"
    );

    drop(occupied);
    let server = start_metrics(Some(unused_ephemeral()), shutdown, &identity())
        .unwrap_or_else(|error| panic!("retry after occupied bind: {error}"))
        .unwrap_or_else(|| panic!("metrics server"));
    metrics::counter!("node_metrics_retry_probe").increment(1);
    let (status, body) = scrape(server.local_addr());
    assert_eq!(status, 200);
    assert!(
        body.contains("node_metrics_retry_probe"),
        "retry scrape missing recorded metric: {body}"
    );
    server.join();
}

#[test]
fn scrape_returns_prometheus_text_with_recorded_metrics() {
    let _guard = SERVER_TEST_LOCK.lock();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server = MetricsServer::bind(unused_ephemeral(), shutdown, &identity())
        .unwrap_or_else(|error| panic!("bind metrics: {error}"));
    metrics::counter!("node_metrics_scrape_probe").increment(1);
    let (status, body) = scrape(server.local_addr());
    assert_eq!(status, 200);
    assert!(
        body.contains("text/plain"),
        "content-type must be prometheus text: {body}"
    );
    assert!(
        body.contains("node_metrics_scrape_probe"),
        "body must include recorded metric: {body}"
    );
    server.join();
}

#[test]
fn two_sequential_servers_in_one_process_both_serve() {
    let _guard = SERVER_TEST_LOCK.lock();
    let shutdown = Arc::new(AtomicBool::new(false));
    let first = MetricsServer::bind(unused_ephemeral(), Arc::clone(&shutdown), &identity())
        .unwrap_or_else(|error| panic!("first: {error}"));
    metrics::counter!("node_metrics_sequential_probe").increment(1);
    let (status, body) = scrape(first.local_addr());
    assert_eq!(status, 200);
    assert!(body.contains("node_metrics_sequential_probe"));
    first.join();

    let second = MetricsServer::bind(unused_ephemeral(), shutdown, &identity())
        .unwrap_or_else(|error| panic!("second: {error}"));
    metrics::counter!("node_metrics_sequential_probe").increment(1);
    let (status, body) = scrape(second.local_addr());
    assert_eq!(status, 200);
    assert!(body.contains("node_metrics_sequential_probe"));
    second.join();
}

#[test]
fn shutdown_exits_the_listener_thread() {
    let _guard = SERVER_TEST_LOCK.lock();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server = MetricsServer::bind(unused_ephemeral(), Arc::clone(&shutdown), &identity())
        .unwrap_or_else(|error| panic!("bind metrics: {error}"));
    let addr = server.local_addr();
    shutdown.store(true, Ordering::Release);
    server.join();
    TcpListener::bind(addr)
        .unwrap_or_else(|error| panic!("port released after listener join: {error}"));
}

#[test]
fn run_retries_metrics_bind_after_occupied_address() {
    let _guard = SERVER_TEST_LOCK.lock();
    let shutdown = Arc::new(AtomicBool::new(false));
    let occupied =
        TcpListener::bind(unused_ephemeral()).unwrap_or_else(|error| panic!("occupy: {error}"));
    let busy = occupied
        .local_addr()
        .unwrap_or_else(|error| panic!("busy addr: {error}"));
    assert!(
        start_metrics(Some(busy), Arc::clone(&shutdown), &identity()).is_err(),
        "run-path bind must fail on an occupied address"
    );
    drop(occupied);
    let server = start_metrics(Some(unused_ephemeral()), shutdown, &identity())
        .unwrap_or_else(|error| panic!("run-path retry: {error}"))
        .unwrap_or_else(|| panic!("server"));
    let (status, _) = scrape(server.local_addr());
    assert_eq!(status, 200);
    server.join();
}
