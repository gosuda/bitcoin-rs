//! Header backpressure, cancellation, and body/header ordering at ingress.

use super::*;
use crate::test_support::TestResult;

#[test]
fn full_header_ingress_preserves_responses_and_body_first_order() -> TestResult {
    let (headers_tx, headers_rx) = crossbeam_channel::bounded(1);
    let (blocks_tx, blocks_rx) = crossbeam_channel::bounded(1);
    let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(tx);
    let addr = PeerEndpoint::from((std::net::Ipv4Addr::LOCALHOST, 18_450));
    let source = lease.source(Some(addr));
    shared.send_headers_response(&lease, source, Vec::new());
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let payload = bitcoin_rs_primitives::BlockPayload::from_raw(bytes::Bytes::from(
        bitcoin::consensus::serialize(&genesis),
    ))?;
    let expected = payload.block().header;
    let (done_tx, done_rx) = crossbeam_channel::bounded(1);
    let worker = std::thread::spawn(move || {
        shared.send_block(&lease, addr, payload, None);
        let _ = done_tx.send(());
    });

    // The body is available while its paired header is still backpressured.
    let body = blocks_rx.recv_timeout(Duration::from_secs(3))?;
    assert_eq!(body.payload().block().header, expected);
    assert!(done_rx.recv_timeout(Duration::from_millis(30)).is_err());
    let response = headers_rx.recv()?;
    assert!(response.wire_response);
    assert!(
        response.headers.is_empty(),
        "empty wire responses cannot be lost"
    );
    let carried = headers_rx.recv_timeout(Duration::from_secs(3))?;
    assert_eq!(carried.source, Some(source));
    assert_eq!(carried.headers, vec![expected]);
    assert!(!carried.wire_response);
    done_rx.recv_timeout(Duration::from_secs(3))?;
    worker
        .join()
        .map_err(|_| crate::test_support::TestError::Panicked("header forward panicked"))?;
    Ok(())
}

#[test]
fn full_header_ingress_observes_session_and_lease_cancellation() -> TestResult {
    for cancel_session in [false, true] {
        let (headers_tx, headers_rx) = crossbeam_channel::bounded(1);
        let (blocks_tx, _blocks_rx) = crossbeam_channel::bounded(1);
        let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);
        let session_cancel = shared.session_cancel.clone();
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        let source = lease.source(None);
        shared.send_headers_response(&lease, source, Vec::new());
        let stop = lease.clone();
        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let worker = std::thread::spawn(move || {
            shared.send_headers_response(&lease, source, Vec::new());
            let _ = done_tx.send(());
        });
        assert!(done_rx.recv_timeout(Duration::from_millis(30)).is_err());
        if cancel_session {
            session_cancel.store(true);
        } else {
            stop.cancel();
        }
        done_rx.recv_timeout(Duration::from_secs(3))?;
        worker
            .join()
            .map_err(|_| crate::test_support::TestError::Panicked("header forward panicked"))?;
        assert_eq!(headers_rx.len(), 1, "cancelled wait must not enqueue");
    }
    Ok(())
}

#[test]
fn disconnected_header_ingress_releases_the_sender() -> TestResult {
    let (headers_tx, headers_rx) = crossbeam_channel::bounded(1);
    let (blocks_tx, _blocks_rx) = crossbeam_channel::bounded(1);
    let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(tx);
    let source = lease.source(None);
    shared.send_headers_response(&lease, source, Vec::new());
    let (done_tx, done_rx) = crossbeam_channel::bounded(1);
    let worker = std::thread::spawn(move || {
        shared.send_headers_response(&lease, source, Vec::new());
        let _ = done_tx.send(());
    });
    assert!(done_rx.recv_timeout(Duration::from_millis(30)).is_err());
    drop(headers_rx);
    done_rx.recv_timeout(Duration::from_secs(3))?;
    worker
        .join()
        .map_err(|_| crate::test_support::TestError::Panicked("header forward panicked"))?;
    Ok(())
}

/// Exercise the actual send paths against real sync ticks, with a producer
/// kept ahead of the consumer. The payload estimate excludes channel/Vec
/// metadata, in-flight senders, bodies, allocator overhead and process RSS.
#[test]
fn sustained_wire_and_body_header_ingress_stays_bounded() -> TestResult {
    run_sustained_wire_headers_case()?;
    run_sustained_body_headers_case()?;
    Ok(())
}

fn run_sustained_wire_headers_case() -> TestResult {
    run_sustained_ingress_case(HeaderDelivery::WireResponse)
}

fn run_sustained_body_headers_case() -> TestResult {
    run_sustained_ingress_case(HeaderDelivery::EmbeddedBlock)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeaderDelivery {
    WireResponse,
    EmbeddedBlock,
}

fn run_sustained_ingress_case(delivery: HeaderDelivery) -> TestResult {
    use crate::sync::test_support::{TestChain, mined_chain};
    use crate::test_support::{connect_peer, synthetic_peer, test_addr};
    use arc_swap::ArcSwapOption;
    use parking_lot::RwLock;

    const CAPACITY: usize = 64;
    const BATCHES: usize = 128;
    let (mut tree, blocks) = mined_chain(u32::try_from(BATCHES)?, 0)?;
    let tip = tree.tip_handle();
    let tree = Arc::new(RwLock::new(tree));
    let applied = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(crate::PeerTable::new());
    let (headers_tx, headers_rx) = crossbeam_channel::bounded(CAPACITY);
    let (blocks_tx, blocks_rx) = crossbeam_channel::bounded(256);
    let sync = Arc::new(crate::sync::BlockSync::new(
        Arc::new(TestChain::new(tip, Arc::clone(&applied), tree)),
        Arc::clone(&peers),
        headers_rx.clone(),
        blocks_rx.clone(),
        crate::sync::syncing_ibd_latch(),
    ));
    sync.tick();
    let addr = test_addr(9792, 0)?;
    let _outbound_rx = connect_peer(&peers, synthetic_peer(addr, i32::try_from(BATCHES)?));
    let lease = peers
        .lease(addr)
        .ok_or(crate::test_support::TestError::Missing(
            "missing load-test connection",
        ))?;
    let mut shared = test_shared(peers, headers_tx, blocks_tx);
    shared.block_sync = Some(Arc::clone(&sync));
    let stop = shared.session_cancel.clone();
    let (producer, filled_rx) =
        spawn_ingress_producer(blocks, delivery, shared, lease, addr, Arc::clone(&sync));
    filled_rx.recv_timeout(Duration::from_secs(3))?;
    let started = Instant::now();
    let metrics = drain_sustained_ingress(
        &sync,
        producer,
        &headers_rx,
        &blocks_rx,
        &stop,
        started,
        headers_rx.len(),
    )?;
    let peak_depth = metrics.peak_depth;
    let ticks = metrics.ticks;
    let max_tick = metrics.max_tick;
    assert!(
        headers_rx.is_empty() && blocks_rx.is_empty(),
        "ingress must make progress"
    );
    assert!(peak_depth <= CAPACITY);
    if delivery == HeaderDelivery::EmbeddedBlock {
        assert_eq!(
            applied
                .load_full()
                .ok_or(crate::test_support::TestError::Missing("no applied tip"))?
                .height,
            u32::try_from(BATCHES)?
        );
    }
    let headers_per_batch = if delivery == HeaderDelivery::WireResponse {
        crate::wire::MAX_HEADERS_MESSAGE_COUNT
    } else {
        1
    };
    let payload_bytes = peak_depth * headers_per_batch * size_of::<bitcoin_rs_primitives::Header>();
    let delivery_label = match delivery {
        HeaderDelivery::WireResponse => "wire_response",
        HeaderDelivery::EmbeddedBlock => "embedded_block",
    };
    eprintln!(
        "delivery={delivery_label}, batches={BATCHES}, peak_queue={peak_depth}, queued_header_payload_bytes={payload_bytes}, ticks={ticks}, max_tick={max_tick:?}, elapsed={:?}",
        started.elapsed()
    );
    Ok(())
}

struct IngressDrainMetrics {
    peak_depth: usize,
    ticks: usize,
    max_tick: Duration,
}

fn drain_sustained_ingress(
    sync: &crate::sync::BlockSync,
    producer: std::thread::JoinHandle<()>,
    headers_rx: &crossbeam_channel::Receiver<crate::InboundHeaders>,
    blocks_rx: &crossbeam_channel::Receiver<crate::InboundBlock>,
    stop: &bitcoin_rs_chain::LatchReader,
    started: Instant,
    initial_peak: usize,
) -> Result<IngressDrainMetrics, crate::test_support::TestError> {
    let mut peak_depth = initial_peak;
    let mut max_tick = Duration::ZERO;
    let mut ticks = 0;
    while (!producer.is_finished() || !headers_rx.is_empty() || !blocks_rx.is_empty())
        && started.elapsed() < Duration::from_secs(10)
    {
        peak_depth = peak_depth.max(headers_rx.len());
        let tick_start = Instant::now();
        sync.tick();
        max_tick = max_tick.max(tick_start.elapsed());
        ticks += 1;
        std::thread::yield_now();
    }
    stop.store(true);
    producer
        .join()
        .map_err(|_| crate::test_support::TestError::Panicked("load producer panicked"))?;
    Ok(IngressDrainMetrics {
        peak_depth,
        ticks,
        max_tick,
    })
}

fn spawn_ingress_producer(
    blocks: Vec<bitcoin_rs_primitives::Block>,
    delivery: HeaderDelivery,
    shared: ConnectionShared,
    lease: crate::PeerLease,
    addr: crate::PeerRemote,
    sync: Arc<crate::sync::BlockSync>,
) -> (std::thread::JoinHandle<()>, crossbeam_channel::Receiver<()>) {
    let source = lease.source(addr.endpoint());
    let (filled_tx, filled_rx) = crossbeam_channel::bounded(1);
    let producer = std::thread::spawn(move || {
        for (n, block) in blocks.into_iter().enumerate() {
            if delivery == HeaderDelivery::WireResponse {
                shared.send_headers_response(
                    &lease,
                    source,
                    vec![block.header; crate::wire::MAX_HEADERS_MESSAGE_COUNT],
                );
            } else {
                let hash = bitcoin_rs_primitives::Hash256::from(block.block_hash());
                assert!(sync.enqueue_owned_body_fetch(source, hash, || true));
                shared.send_block(
                    &lease,
                    addr,
                    bitcoin_rs_primitives::BlockPayload::from_local(block),
                    None,
                );
            }
            if n + 1 == 64 {
                let _ = filled_tx.send(());
            }
        }
    });
    (producer, filled_rx)
}
