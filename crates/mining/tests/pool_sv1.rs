use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use bitcoin_rs_chain::compact_is_met_by;
use bitcoin_rs_mining::pool::stratum::sv1::{
    ConnectionLimiter, DifficultyPolicy, FrameError, LineBuffer, Observer, RefusalReason, Server,
    ServerConfig, ServerDeps, ServerEvent, StaticAccountResolver, prevhash_from_wire,
    prevhash_to_wire, swap_words,
};
use bitcoin_rs_mining::pool::{
    AcceptedShare, Extranonce, ExtranonceLayout, FoundBlock, Job, JobBookConfig, PoolCore,
    RecordOutcome, ShareLedger,
};
use bitcoin_rs_mining::{
    BlockValidationResult, Candidate, CoinbaseBudget, FakeMiningControl, MiningControl,
    MiningControlError, STALE_PARENT_REASON, TemplateId,
};
use bitcoin_rs_primitives::{
    Amount, CompactTarget, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
        worker: &bitcoin_rs_mining::pool::WorkerIdentity,
        share: &AcceptedShare,
    ) -> Result<RecordOutcome, bitcoin_rs_mining::pool::LedgerUnavailable> {
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
            return Err(bitcoin_rs_mining::pool::LedgerUnavailable);
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
        worker: &bitcoin_rs_mining::pool::WorkerIdentity,
        block: &FoundBlock,
        _submission: &Result<bitcoin_rs_mining::pool::BlockReceipt, MiningControlError>,
    ) -> Result<(), bitcoin_rs_mining::pool::LedgerUnavailable> {
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
        client.send("{\"id\":2,\"method\":\"mining.subscribe\",\"params\":[\"miner/1.0.0\"]}\n");
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
        client.send("{\"id\":2,\"method\":\"mining.subscribe\",\"params\":[\"miner/1.0.0\"]}\n");
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

/// Journal backpressure (`Inconclusive`) retains bounded submission-recovery
/// work instead of dropping the block: the node is re-queried a bounded
/// number of times, the share stays acknowledged, and the block record stays
/// durable for chain reconciliation.
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

/// An already-validated share whose block the node rejects as a stale parent
/// is a `STALE_SHARE` protocol error, not success: the ledger record stays
/// durable, nothing else is submitted, and the connection remains usable.
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
        response.contains("\"error\":[20,") && response.contains("Share accounting unavailable"),
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
