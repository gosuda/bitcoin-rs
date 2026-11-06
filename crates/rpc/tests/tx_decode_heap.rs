//! A separate executable owns the process-global counting allocator; the normal
//! RPC suite must not share this allocator's measurement window.
#![expect(clippy::expect_used, reason = "independent heap evidence")]

use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_primitives::{Tx, deserialize, layout::decode_reservation};
use bitcoin_rs_rpc::{Auth, Handler, RpcServer, RpcSurface, context::Context};
use sonic_rs::{JsonContainerTrait as _, json};
use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

struct CountingAllocator;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::SeqCst) + bytes;
    PEAK.fetch_max(live, Ordering::SeqCst);
}

// SAFETY: every call forwards to `System` with the caller's layout; the counters only observe sizes.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract for `layout`.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            grow(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc_zeroed` contract for `layout`.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            grow(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        // SAFETY: the caller passes a pointer and layout from a matching `alloc` call.
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::realloc` contract.
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if !moved.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
            grow(new_size);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

// Construct wire independently of the native materializer: one input/output,
// a canonical large CompactSize witness count, and one empty item per byte.
fn witness_wire(items: u32) -> Vec<u8> {
    let mut wire = vec![2, 0, 0, 0, 0, 1, 1];
    wire.extend_from_slice(&[0; 36]);
    wire.push(0);
    wire.extend_from_slice(&[0xff; 4]);
    wire.push(1);
    wire.extend_from_slice(&[0; 9]);
    wire.push(0xfe);
    wire.extend_from_slice(&items.to_le_bytes());
    wire.resize(wire.len() + usize::try_from(items).expect("count fits"), 0);
    wire.extend_from_slice(&[0; 4]);
    wire
}

fn begin() -> usize {
    let baseline = LIVE.load(Ordering::SeqCst);
    PEAK.store(baseline, Ordering::SeqCst);
    baseline
}

#[test]
fn raw_transaction_heap_is_bounded_for_single_and_concurrent_inspection() {
    let wire = witness_wire(500_001);
    let baseline = begin();
    let tx = deserialize::<Tx>(&wire).expect("witness transaction");
    let peak = PEAK.load(Ordering::SeqCst).saturating_sub(baseline) + wire.len();
    let retained = tx.retained_heap_bytes() + wire.len();
    assert!(peak <= decode_reservation(wire.len()), "native peak {peak}");
    assert!(
        retained <= decode_reservation(wire.len()),
        "native retained {retained}"
    );
    eprintln!(
        "native: wire={}, retained={retained}, peak={peak}, reservation={}",
        wire.len(),
        decode_reservation(wire.len())
    );
    drop(tx);

    let handler = Arc::new(Handler::new(Arc::new(Context::new())));
    let params = Arc::new(json!([wire.to_lower_hex_string()]));
    let baseline = begin();
    let response = handler
        .dispatch("decoderawtransaction", &params)
        .expect("inspection exceeds broadcast standardness");
    let single_peak = PEAK.load(Ordering::SeqCst).saturating_sub(baseline);
    let single_retained = LIVE.load(Ordering::SeqCst).saturating_sub(baseline);
    assert_eq!(
        response["vin"][0]["txinwitness"]
            .as_array()
            .expect("witness")
            .len(),
        500_001
    );
    // This independent evidence ceiling includes projection, not just the
    // primitive decoder reservation. It is not a whole-process RSS claim.
    assert!(
        single_peak < 64 * wire.len(),
        "inspection peak {single_peak}"
    );
    eprintln!("inspection: retained={single_retained}, peak={single_peak}");
    drop(response);

    let server = RpcServer::bind(
        "127.0.0.1:0",
        Arc::new(Auth::basic("alice", "secret")),
        Arc::clone(&handler),
        32,
        std::time::Duration::from_secs(10),
        false,
    )
    .expect("public listener");
    let address = server.local_addr().expect("address");
    let shutdown = bitcoin_rs_chain::LatchWriter::new();
    let stop = shutdown.reader();
    let server_thread =
        std::thread::spawn(move || server.serve_surface_with_shutdown(stop, RpcSurface::Shared));
    let body = sonic_rs::to_string(
        &json!({"jsonrpc":"2.0","id":1,"method":"decoderawtransaction","params":params.as_ref()}),
    )
    .expect("request JSON");
    let request = Arc::new(format!(
        "POST / HTTP/1.1\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    let barrier = Arc::new(Barrier::new(9));
    let baseline = begin();
    let workers = (0..8)
        .map(|_| {
            let request = Arc::clone(&request);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut stream = TcpStream::connect(address).expect("inspection connection");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(20)))
                    .expect("inspection timeout");
                barrier.wait();
                stream
                    .write_all(request.as_bytes())
                    .expect("inspection request");
                let mut response = String::new();
                stream
                    .read_to_string(&mut response)
                    .expect("inspection response");
                assert!(response.starts_with("HTTP/1.1 200"), "{response}");
                assert!(
                    response.contains("\"txinwitness\":[\"\""),
                    "inspection must return witness"
                );
                response
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let responses = workers
        .into_iter()
        .map(|worker| worker.join().expect("inspection worker"))
        .collect::<Vec<_>>();
    let aggregate_peak = PEAK.load(Ordering::SeqCst).saturating_sub(baseline);
    let aggregate_retained = LIVE.load(Ordering::SeqCst).saturating_sub(baseline);
    assert!(
        aggregate_peak < 64 * wire.len() * 8,
        "aggregate peak {aggregate_peak}"
    );
    assert_eq!(responses.len(), 8);
    eprintln!(
        "eight concurrent HTTP inspections: retained={aggregate_retained}, peak={aggregate_peak}"
    );
    drop(responses);

    let oversized = json!(["00".repeat(8 * 1_024 * 1_024 + 1)]);
    let baseline = begin();
    let error = handler
        .dispatch("decoderawtransaction", &oversized)
        .expect_err("predecode cap");
    let refused_peak = PEAK.load(Ordering::SeqCst).saturating_sub(baseline);
    assert_eq!(error.code(), -22);
    assert!(
        refused_peak < 64 * 1_024,
        "refusal allocated {refused_peak}"
    );
    eprintln!("oversize refusal: peak={refused_peak}");

    let raw = wire.to_lower_hex_string();
    let mut stream = TcpStream::connect(address).expect("public connection");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("timeout");
    let head = format!(
        "POST /api/tx HTTP/1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        raw.len()
    );
    let baseline = begin();
    stream.write_all(head.as_bytes()).expect("head");
    stream.write_all(raw.as_bytes()).expect("body");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("response");
    let public_peak = PEAK.load(Ordering::SeqCst).saturating_sub(baseline);
    shutdown.trigger();
    server_thread
        .join()
        .expect("listener join")
        .expect("listener exit");
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(response.contains("transaction hex exceeds the broadcast size limit"));
    // Includes the real HTTP body buffer, but excludes native materialization.
    assert!(
        public_peak < raw.len() * 2 + 64 * 1_024,
        "public refusal peak {public_peak}"
    );
    eprintln!(
        "public HTTP oversize refusal: body={}, peak={public_peak}",
        raw.len()
    );
}
