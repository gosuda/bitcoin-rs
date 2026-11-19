//! A separate executable owns the process-global counting allocator; the normal
//! RPC suite must not share this allocator's measurement window.
#![expect(clippy::expect_used, reason = "independent heap evidence")]

use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_consensus::primitives::{Tx, deserialize, layout::decode_reservation};
use bitcoin_rs_wire::{Auth, Handler, RpcServer, RpcSurface, context::Context};
use metrics::{
    Counter, Gauge, GaugeFn, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
};
use parking_lot::{Condvar, Mutex};
use sonic_rs::{JsonContainerTrait as _, json};
use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

struct CountingAllocator;

static CHARGED: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn charge(bytes: usize) {
    let charged = CHARGED.fetch_add(bytes, Ordering::SeqCst) + bytes;
    PEAK.fetch_max(charged, Ordering::SeqCst);
}

// SAFETY: every call forwards to `System` with the caller's layout; the counters only observe sizes.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        charge(layout.size());
        // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract for `layout`.
        let ptr = unsafe { System.alloc(layout) };
        if ptr.is_null() {
            CHARGED.fetch_sub(layout.size(), Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        charge(layout.size());
        // SAFETY: the caller upholds the `GlobalAlloc::alloc_zeroed` contract for `layout`.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if ptr.is_null() {
            CHARGED.fetch_sub(layout.size(), Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller passes a pointer and layout from a matching `alloc` call.
        unsafe { System.dealloc(ptr, layout) };
        CHARGED.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        charge(new_size);
        // SAFETY: the caller upholds the `GlobalAlloc::realloc` contract.
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if moved.is_null() {
            CHARGED.fetch_sub(new_size, Ordering::SeqCst);
        } else {
            CHARGED.fetch_sub(layout.size(), Ordering::SeqCst);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Clone, Copy, Default)]
struct AdmissionState {
    active: f64,
    arrivals: usize,
    held: bool,
}

#[derive(Default)]
struct AdmissionGate {
    state: Mutex<AdmissionState>,
    changed: Condvar,
}

impl AdmissionGate {
    fn hold(&self) -> AdmissionRelease<'_> {
        let mut state = self.state.lock();
        assert_eq!(state.active.to_bits(), 0.0_f64.to_bits());
        state.arrivals = 0;
        state.held = true;
        AdmissionRelease(self)
    }

    fn wait_for_eight(&self) -> AdmissionState {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut state = self.state.lock();
        while state.arrivals < 8 {
            if self.changed.wait_until(&mut state, deadline).timed_out() {
                break;
            }
        }
        *state
    }
}

struct AdmissionRelease<'a>(&'a AdmissionGate);

impl Drop for AdmissionRelease<'_> {
    fn drop(&mut self) {
        self.0.state.lock().held = false;
        self.0.changed.notify_all();
    }
}

impl GaugeFn for AdmissionGate {
    fn increment(&self, value: f64) {
        let mut state = self.state.lock();
        state.active += value;
        if state.held {
            state.arrivals += 1;
            self.changed.notify_all();
            if state.arrivals <= 8 {
                while state.held {
                    self.changed.wait(&mut state);
                }
            }
        }
    }

    fn decrement(&self, value: f64) {
        self.state.lock().active -= value;
    }

    fn set(&self, value: f64) {
        self.state.lock().active = value;
    }
}

struct AdmissionRecorder {
    gate: Arc<AdmissionGate>,
}

impl Recorder for AdmissionRecorder {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

    fn register_counter(&self, _: &Key, _: &Metadata<'_>) -> Counter {
        Counter::noop()
    }

    fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
        if key.name() == "rpc.tx_decode.active" {
            Gauge::from_arc(Arc::clone(&self.gate))
        } else {
            Gauge::noop()
        }
    }

    fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
        Histogram::noop()
    }
}

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
    PEAK.store(0, Ordering::SeqCst);
    let baseline = CHARGED.load(Ordering::SeqCst);
    PEAK.fetch_max(baseline, Ordering::SeqCst);
    baseline
}

// API-10
#[test]
fn raw_transaction_heap_is_bounded_for_single_and_concurrent_inspection() {
    let baseline = begin();
    let mut allocation = Vec::<u8>::with_capacity(1_024);
    std::hint::black_box(&mut allocation).reserve_exact(2_048);
    assert!(PEAK.load(Ordering::SeqCst).saturating_sub(baseline) >= 3_072);
    drop(allocation);

    let wire = witness_wire(500_001);
    let baseline = begin();
    let tx = deserialize::<Tx>(&wire).expect("witness transaction");
    let peak = PEAK.load(Ordering::SeqCst).saturating_sub(baseline) + wire.capacity();
    let retained = tx.retained_heap_bytes() + wire.capacity();
    assert!(peak <= decode_reservation(wire.len()), "native peak {peak}");
    assert!(
        retained <= decode_reservation(wire.len()),
        "native retained {retained}"
    );
    eprintln!(
        "native: wire={}, capacity={}, retained={retained}, conservative_peak={peak}, reservation={}",
        wire.len(),
        wire.capacity(),
        decode_reservation(wire.len())
    );
    drop(tx);

    let gate = Arc::new(AdmissionGate::default());
    assert!(
        metrics::set_global_recorder(AdmissionRecorder {
            gate: Arc::clone(&gate),
        })
        .is_ok(),
        "isolated heap recorder"
    );
    let handler = Arc::new(Handler::new(Arc::new(Context::new())));
    let params = Arc::new(json!([wire.to_lower_hex_string()]));
    let baseline = begin();
    let response = handler
        .dispatch("decoderawtransaction", &params)
        .expect("inspection exceeds broadcast standardness");
    let single_peak = PEAK.load(Ordering::SeqCst).saturating_sub(baseline);
    let single_retained = CHARGED.load(Ordering::SeqCst).saturating_sub(baseline);
    assert_eq!(
        response["vin"][0]["txinwitness"]
            .as_array()
            .expect("witness")
            .len(),
        500_001
    );
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
    let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
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
    let baseline = begin();
    let (admission, ninth, outcomes) = std::thread::scope(|scope| {
        let release = gate.hold();
        let workers = (0..8)
            .map(|_| {
                let request = Arc::clone(&request);
                scope.spawn(move || -> std::io::Result<String> {
                    let timeout = Duration::from_secs(20);
                    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
                    stream.set_read_timeout(Some(timeout))?;
                    stream.set_write_timeout(Some(timeout))?;
                    stream.write_all(request.as_bytes())?;
                    let mut response = String::new();
                    stream.read_to_string(&mut response)?;
                    Ok(response)
                })
            })
            .collect::<Vec<_>>();
        let admission = gate.wait_for_eight();
        let ninth = (admission.arrivals == 8)
            .then(|| handler.dispatch("decoderawtransaction", &json!(["00"])));
        drop(release);
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join())
            .collect::<Vec<_>>();
        (admission, ninth, outcomes)
    });
    assert_eq!(
        admission.arrivals, 8,
        "eight server requests must enter admission"
    );
    assert_eq!(admission.active.to_bits(), 8.0_f64.to_bits());
    assert_eq!(
        ninth
            .expect("ninth inspection attempted")
            .expect_err("ninth inspection must be refused while all eight are held")
            .code(),
        -1
    );
    let responses = outcomes
        .into_iter()
        .map(|outcome| {
            outcome
                .expect("inspection worker")
                .expect("inspection response")
        })
        .collect::<Vec<_>>();
    for response in &responses {
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response.contains("\"txinwitness\":[\"\""),
            "inspection must return witness"
        );
    }
    let aggregate_peak = PEAK.load(Ordering::SeqCst).saturating_sub(baseline);
    let aggregate_retained = CHARGED.load(Ordering::SeqCst).saturating_sub(baseline);
    assert!(
        aggregate_peak < 64 * wire.len() * 8,
        "aggregate peak {aggregate_peak}"
    );
    assert_eq!(responses.len(), 8);
    assert_eq!(gate.state.lock().active.to_bits(), 0.0_f64.to_bits());
    eprintln!(
        "eight overlapping admitted HTTP requests: retained={aggregate_retained}, conservative_peak={aggregate_peak}"
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
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(10)).expect("public connection");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .expect("public write timeout");
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
    assert!(
        public_peak < raw.len() * 2 + 64 * 1_024,
        "public refusal peak {public_peak}"
    );
    eprintln!(
        "public HTTP oversize refusal: body={}, peak={public_peak}",
        raw.len()
    );
}
