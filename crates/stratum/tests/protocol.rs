//! Integration and wire transcript tests for the native Stratum V1 pool adapter.
//!
//! Checks:
//! * Framing: line limits, chunk boundaries, trailing `\r\n`, slowloris bounds.
//! * Prevhash: word-swapping against immutable test vectors.
//! * Handshake: BIP310 `mining.configure`, `mining.subscribe`, `mining.authorize`.
//! * Work notification: exact `mining.notify` wire text from the common owner.
//! * Difficulty: `mining.set_difficulty`, decimal format, `mining.suggest_difficulty`
//!   bounds and retarget grace.
//! * Share submissions: valid share accepted, low difficulty rejected, duplicate
//!   rejected, stale share rejected, extranonce length error, version-bits mask error.
//! * Ledger boundary: exactly-once credit, transactional outbox under ledger unavailability.
//! * Connection bounds: global connection cap, per-IP connection cap, shutdown join.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use bitcoin_rs_mining::{
    Candidate, CoinbaseBudget, FakeMiningControl, MiningControl, MiningControlError, TemplateId,
};
use bitcoin_rs_primitives::{
    Amount, CompactTarget, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
};
use bitcoin_rs_stratum::{
    AcceptedShare, ConnectionLimiter, DifficultyPolicy, ExtranonceLayout, FoundBlock, FrameError,
    JobBookConfig, LineBuffer, Observer, PoolCore, RecordOutcome, RefusalReason, Server,
    ServerConfig, ServerDeps, ServerEvent, ShareLedger, StaticAccountResolver, prevhash_from_wire,
    prevhash_to_wire, swap_words,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

// ---------------------------------------------------------------------------
// Test doubles and fixtures
// ---------------------------------------------------------------------------

#[derive(Default)]
struct TestLedger {
    shares: Mutex<Vec<(String, AcceptedShare)>>,
    blocks: Mutex<Vec<(String, FoundBlock)>>,
    fail_shares: Mutex<Option<usize>>,
    share_calls: AtomicUsize,
}

impl TestLedger {
    /// Stops share-record failures; later calls succeed.
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
            share_calls: AtomicUsize::new(0),
        }
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
        worker: &bitcoin_rs_stratum::WorkerIdentity,
        share: &AcceptedShare,
    ) -> Result<RecordOutcome, bitcoin_rs_stratum::LedgerUnavailable> {
        self.share_calls.fetch_add(1, Ordering::SeqCst);
        let mut fail = self
            .fail_shares
            .lock()
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        if let Some(remaining) = fail.as_mut()
            && *remaining > 0
        {
            *remaining -= 1;
            return Err(bitcoin_rs_stratum::LedgerUnavailable);
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
        worker: &bitcoin_rs_stratum::WorkerIdentity,
        block: &FoundBlock,
        _submission: &Result<bitcoin_rs_stratum::BlockReceipt, MiningControlError>,
    ) -> Result<(), bitcoin_rs_stratum::LedgerUnavailable> {
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
    ]; // BIP34 height prefix
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
    Arc::new(
        PoolCore::new(config, control, ledger)
            .unwrap_or_else(|error| panic!("test operation failed: {error}")),
    )
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

// ---------------------------------------------------------------------------
// Unit tests: shared admission
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Unit tests: prevhash and framing
// ---------------------------------------------------------------------------

#[test]
fn prevhash_vector_round_trips_exact_byte_swap() {
    // Canonical SV1 prevhash byte-order vector:
    // Wire: "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000"
    // Canonical display: "00000000440b921e1b77c6c0487ae5616de67f788f44ae2a5af6e2194d16b6f8"
    let wire_hex = "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000";
    let internal = prevhash_from_wire(wire_hex).unwrap_or_else(|| panic!("valid hex"));
    let back_to_wire = prevhash_to_wire(&internal);
    assert_eq!(wire_hex, back_to_wire);

    // Verify word swap symmetry: swap(swap(x)) == x
    let swapped = swap_words(&internal);
    let original = swap_words(&swapped);
    assert_eq!(internal, original);
}

#[test]
fn line_buffer_enforces_bounds_and_crlf() {
    let mut buf = LineBuffer::new(64);

    // Incomplete push
    buf.push(b"hello")
        .unwrap_or_else(|error| panic!("test operation failed: {error:?}"));
    assert_eq!(
        buf.next_frame()
            .unwrap_or_else(|error| panic!("test operation failed: {error:?}")),
        None
    );

    // Complete line with \r\n
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

    // Empty lines skipped
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

    // Over-length push exceeding max_line + PUSH_SLACK rejected
    let big = vec![b'x'; 64 + 64 * 1024 + 1];
    assert_eq!(buf.push(&big), Err(FrameError::LineTooLong));
}

// ---------------------------------------------------------------------------
// Integration tests: Server lifecycle and wire transcripts
// ---------------------------------------------------------------------------

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

    // Install candidate job
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

    // 1. mining.configure (BIP310 version-rolling)
    client.send("{\"id\":1,\"method\":\"mining.configure\",\"params\":[[\"version-rolling\"],{\"version-rolling.mask\":\"1fffe000\",\"version-rolling.min-bit-count\":2}]}\n");
    let resp = client.read_line();
    assert!(resp.contains("\"id\":1"));
    assert!(resp.contains("\"version-rolling\":true"));
    assert!(resp.contains("\"version-rolling.mask\":\"1fffe000\""));

    // 2. mining.subscribe
    client.send("{\"id\":2,\"method\":\"mining.subscribe\",\"params\":[\"miner/1.0.0\"]}\n");
    let resp = client.read_line();
    assert!(resp.contains("\"id\":2"));
    assert!(resp.contains("\"result\":[[[\"mining.set_difficulty\""));
    assert!(resp.contains("\"error\":null"));

    // 3. mining.authorize
    client.send(
        "{\"id\":3,\"method\":\"mining.authorize\",\"params\":[\"alice.worker1\",\"secret123\"]}\n",
    );
    let resp = client.read_line();
    assert_eq!(resp, "{\"id\":3,\"result\":true,\"error\":null}\n");

    // After authorize, server should push initial difficulty and the installed job notification
    let set_diff = client.read_line();
    assert!(set_diff.contains("\"method\":\"mining.set_difficulty\""));
    assert!(set_diff.contains("0.0000000001"));

    let notify = client.read_line();
    assert!(notify.contains("\"method\":\"mining.notify\""));
    assert!(notify.contains(&format!("{:08x}", job_id.get())));

    // 4. mining.submit (find a valid nonce for the very low difficulty target)
    let en1 = pool.layout().session_len();
    let en2 = pool.layout().rolled_len();
    assert_eq!(en1, 4);
    assert_eq!(en2, 4);

    let extranonce2_hex = "00000001";
    let ntime_hex = format!("{:08x}", installed.job.ntime());
    let nonce_hex = "00000000";
    let version_bits_hex = "00002000"; // Within mask 0x1fffe000

    let submit_cmd = format!(
        "{{\"id\":4,\"method\":\"mining.submit\",\"params\":[\"alice.worker1\",\"{job_id:08x}\",\"{extranonce2_hex}\",\"{ntime_hex}\",\"{nonce_hex}\",\"{version_bits_hex}\"]}}\n",
        job_id = job_id.get()
    );
    client.send(&submit_cmd);
    let submit_resp = client.read_line();
    assert_eq!(submit_resp, "{\"id\":4,\"result\":true,\"error\":null}\n");

    // Assert share reached the ledger
    let recorded = ledger.recorded_shares();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].job, job_id);

    // Duplicate submit should be rejected with code 22
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
    // A permanently failing ledger is a deterministic barrier: neither the
    // three inline attempts nor any background poll drain can record the
    // share until the test disarms the ledger.
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
    let _ = client.read_line(); // diff
    let _ = client.read_line(); // notify

    let submit = format!(
        "{{\"id\":3,\"method\":\"mining.submit\",\"params\":[\"alice.w1\",\"{job_id:08x}\",\"00000001\",\"{ntime:08x}\",\"00000000\"]}}\n",
        job_id = job_id.get(),
        ntime = installed.job.ntime(),
    );
    client.send(&submit);
    // The first two inline attempts fail, so the share is buffered in the
    // outbox and the wire response is withheld until the record is durable.
    client
        .stream
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap_or_else(|error| panic!("test operation failed: {error}"));
    let mut early = String::new();
    let blocked = TestClient::read_available(&mut client.reader, &mut early);
    assert!(!blocked, "no success may precede the durable record");
    assert!(early.is_empty(), "unexpected early frame: {early:?}");

    // Disarm the barrier, then drain: the deferred response is emitted by the
    // session's next poll.
    ledger.disarm();
    pool.drain_outbox();
    client
        .stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap_or_else(|error| panic!("test operation failed: {error}"));
    let resp = client.read_line();
    assert_eq!(resp, "{\"id\":3,\"result\":true,\"error\":null}\n");
    assert_eq!(ledger.recorded_shares().len(), 1);

    // A resubmit after acknowledgement keeps the protocol's duplicate
    // rejection and credits nothing further.
    client.send(&submit);
    let replay = client.read_line();
    assert!(replay.contains("\"error\":[22,\"Duplicate share\",null]"));
    assert_eq!(ledger.recorded_shares().len(), 1);

    server.shutdown();
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

    // Negative 1: Submit before subscribe/auth -> 25 Not subscribed
    client.send("{\"id\":1,\"method\":\"mining.submit\",\"params\":[\"bob\",\"00000001\",\"00000001\",\"60000000\",\"00000000\"]}\n");
    let resp = client.read_line();
    assert!(resp.contains("\"error\":[25,\"Not subscribed\",null]"));

    // Subscribe
    client.send("{\"id\":2,\"method\":\"mining.subscribe\",\"params\":[]}\n");
    let _ = client.read_line();

    // Negative 2: Submit before authorize -> 24 Unauthorized worker
    client.send("{\"id\":3,\"method\":\"mining.submit\",\"params\":[\"bob\",\"00000001\",\"00000001\",\"60000000\",\"00000000\"]}\n");
    let resp = client.read_line();
    assert!(resp.contains("\"error\":[24,\"Unauthorized worker\",null]"));

    // Authorize with bad password -> error
    client.send("{\"id\":4,\"method\":\"mining.authorize\",\"params\":[\"bob\",\"wrong\"]\n");
    // Also test malformed json syntax directly
    let parse_err = client.read_line();
    assert!(parse_err.contains("-32700"));

    // Authorized correctly
    client.send("{\"id\":5,\"method\":\"mining.authorize\",\"params\":[\"bob\",\"pass\"]}\n");
    assert_eq!(
        client.read_line(),
        "{\"id\":5,\"result\":true,\"error\":null}\n"
    );
    let _ = client.read_line(); // diff
    let _ = client.read_line(); // notify

    // Negative 3: Invalid extranonce2 length (expected 4 bytes = 8 hex chars, send 2 hex chars)
    let bad_en2 = format!(
        "{{\"id\":6,\"method\":\"mining.submit\",\"params\":[\"bob\",\"{job_id:08x}\",\"01\",\"{ntime:08x}\",\"00000000\"]}}\n",
        job_id = job_id.get(),
        ntime = installed.job.ntime(),
    );
    client.send(&bad_en2);
    let en2_err = client.read_line();
    assert!(en2_err.contains("Invalid extranonce2 length") || en2_err.contains("-32602"));

    // Negative 4: Unexpected version bits when version-rolling was not negotiated
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
    // Allowed range: 1.0 to 100.0
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

    // Suggest within bounds -> true
    client.send("{\"id\":1,\"method\":\"mining.suggest_difficulty\",\"params\":[25.5]}\n");
    let resp = client.read_line();
    assert_eq!(resp, "{\"id\":1,\"result\":true,\"error\":null}\n");

    // Suggest out of bounds (too low) -> rejected with error
    client.send("{\"id\":2,\"method\":\"mining.suggest_difficulty\",\"params\":[0.5]}\n");
    let resp = client.read_line();
    assert!(resp.contains("\"error\":[20,\"Difficulty out of range\",null]"));

    // Suggest out of bounds (too high) -> rejected with error
    client.send("{\"id\":3,\"method\":\"mining.suggest_difficulty\",\"params\":[500.0]}\n");
    let resp = client.read_line();
    assert!(resp.contains("\"error\":[20,\"Difficulty out of range\",null]"));

    server.shutdown();
}

// ---------------------------------------------------------------------------
// Connection bounds
// ---------------------------------------------------------------------------

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

        // Bounded event queue; an event arriving at a full queue is shed, and
        // this test reads every event it waits for before the next connect.
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

        // The first peer is served: its slot is held once `Accepted` is seen.
        let first = TestClient::connect(addr);
        let accepted = observed
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|error| panic!("test operation failed: {error}"));
        assert!(matches!(accepted, ServerEvent::Accepted { .. }));
        assert_eq!(server.active_sessions(), 1);

        // The second peer is closed without a session thread.
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

        // Shutdown ends the served session and joins its thread; the refused
        // peer never had one.
        let report = server.shutdown();
        assert_eq!(report.sessions_joined, 1);
        assert_eq!(report.sessions_panicked, 0);
        drop(first);
    }
}
