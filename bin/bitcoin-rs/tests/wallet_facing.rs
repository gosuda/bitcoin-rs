//! Wallet-facing consumer: spawn the public `bitcoin-rs` binary and talk
//! only HTTP (Esplora + JSON-RPC) using rust-bitcoin.
//!
//! This is the executable proof of `docs/contracts/wallet-facing.md`. It
//! lives in the binary package so it can spawn `CARGO_BIN_EXE_bitcoin-rs`.
//! `source_does_not_import_node_internals` enforces `WF-01` on this
//! source. The named out-of-repo consumer is `gosuda/bitcoin-wallet`
//! (`btcw -u`).

#![allow(missing_docs)]

use std::cell::RefCell;
use std::error::Error;
use std::io::{BufRead as _, BufReader, Read};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use bitcoin_rs_e2e::helpers::assemble_block_from_template;
use bitcoin_rs_e2e::node::HttpResponse;
use bitcoin_rs_e2e::rpc::Connection;

use bitcoin::absolute::LockTime;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::constants::{COINBASE_MATURITY, genesis_block};
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256;
use bitcoin::opcodes::all::OP_PUSHNUM_1;
use bitcoin::script::Builder;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    WPubkeyHash, Witness,
};
use parking_lot::Mutex;
use serde_json::{Value, json};

const RPC_USER: &str = "bitcoin-rs";
const RPC_PASSWORD: &str = "bitcoin-rs";
const FEE_SATS: u64 = 10_000;
const REGTEST_SUBSIDY_SATS: u64 = 5_000_000_000;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const INDEX_TIMEOUT: Duration = Duration::from_mins(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Lossy body text of a shared HTTP response, for diagnostics.
trait BodyText {
    fn body_text(&self) -> String;
}

impl BodyText for HttpResponse {
    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[test]
fn external_wallet_can_scan_estimate_and_broadcast() -> TestResult {
    let workspace = tempfile::tempdir()?;
    let node = NodeProcess::spawn(workspace.path())?;
    let client = Client {
        logs: Arc::clone(&node.logs),
        conn: RefCell::new(Connection::new(node.addr)),
    };
    let p2wpkh = p2wpkh_script();
    let address = Address::from_script(&p2wpkh, Network::Regtest)
        .map_err(|error| format!("p2wpkh fixture must be a standard address: {error}"))?
        .to_string();

    let genesis_hex = serialize_hex(&genesis_block(Network::Regtest));
    let genesis = client.rpc("submitblock", &json!([genesis_hex]))?;
    if !genesis.is_null() {
        return Err(format!("submitblock(genesis) rejected: {genesis}").into());
    }
    for _ in 0..COINBASE_MATURITY {
        client.mine(Coinbase::AnyoneCanSpend)?;
    }
    client.mine(Coinbase::P2wpkh(&p2wpkh))?;

    let height = client.esplora_text("/api/blocks/tip/height")?;
    assert_eq!(
        height.trim(),
        COINBASE_MATURITY.saturating_add(1).to_string(),
        "tip height after genesis + {} mined blocks",
        COINBASE_MATURITY.saturating_add(1)
    );
    let tip_hash = client.esplora_text("/api/blocks/tip/hash")?;
    let genesis_hash = client.esplora_text("/api/block-height/0")?;
    assert_eq!(
        genesis_hash.trim(),
        genesis_block(Network::Regtest).block_hash().to_string(),
        "GET /api/block-height/0 must return the regtest genesis hash"
    );
    assert_ne!(
        tip_hash.trim(),
        genesis_hash.trim(),
        "tip must have moved past genesis"
    );

    // API-26: coinbase-only blocks leave the estimator with no observations,
    // so targets are honestly omitted until real wallet traffic confirms.
    let fees = client.esplora_json("/api/fee-estimates")?;
    assert!(
        fees.get("6").is_none(),
        "with no confirmed wallet traffic the 6-block target must be omitted, not fabricated: {fees}"
    );
    assert_esplora_namespace(&client, &height, &tip_hash, &genesis_hash)?;

    client.wait_for_scriptindex(&address)?;
    assert_script_activity(&client, &address, &p2wpkh)?;

    let spend_hex = spend_anyone_can_spend(&client, 1, &p2wpkh)?;
    let broadcast = client.esplora_post("/api/tx", spend_hex.as_bytes())?;
    assert_eq!(
        broadcast.status,
        200,
        "POST /api/tx: {}",
        broadcast.body_text()
    );
    let txid = broadcast.body_text();
    assert_eq!(
        txid.trim().len(),
        64,
        "broadcast must return a txid: {txid}"
    );

    let mempool_tx = client.esplora_json(&format!("/api/tx/{}", txid.trim()))?;
    assert_eq!(
        mempool_tx
            .get("status")
            .and_then(|status| status.get("confirmed"))
            .and_then(Value::as_bool),
        Some(false),
        "broadcast transaction must be visible as unconfirmed: {mempool_tx}"
    );
    let tx_status = client.esplora_json(&format!("/api/tx/{}/status", txid.trim()))?;
    assert_eq!(
        tx_status.get("confirmed").and_then(Value::as_bool),
        Some(false),
        "GET /api/tx/{{id}}/status must report unconfirmed: {tx_status}"
    );
    // Confirming the first spend matures the height-2 coinbase, so a second
    // spend confirms in the next block. API-26 needs more than a lone fresh
    // observation (one sample decays below the minimum), and two
    // confirmations at full success rate honestly qualify the estimate.
    client.mine(Coinbase::AnyoneCanSpend)?;
    wait_for_confirmation(&client, txid.trim())?;
    let second_hex = spend_anyone_can_spend(&client, 2, &p2wpkh)?;
    let second_broadcast = client.esplora_post("/api/tx", second_hex.as_bytes())?;
    assert_eq!(
        second_broadcast.status,
        200,
        "POST /api/tx: {}",
        second_broadcast.body_text()
    );
    client.mine(Coinbase::AnyoneCanSpend)?;
    wait_for_confirmation(&client, second_broadcast.body_text().trim())?;
    let fees = client.esplora_json("/api/fee-estimates")?;
    assert!(
        fees.get("6").and_then(Value::as_f64).is_some(),
        "two confirmed spends must qualify the 6-block target wallets use: {fees}"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn startup_child_kills_the_process_unless_handed_off() -> TestResult {
    let failed = spawn_held_child()?;
    let failed_pid = failed.id();
    drop(StartupChild::new(failed));
    assert!(
        wait_until_dead(failed_pid),
        "drop before handoff must kill and reap the child (pid {failed_pid})"
    );

    let started = spawn_held_child()?;
    let started_pid = started.id();
    let mut live = StartupChild::new(started).into_inner()?;
    assert!(
        pid_is_alive(started_pid),
        "handoff must leave the child running (pid {started_pid})"
    );
    let _ignored = live.kill();
    let _ignored = live.wait();
    Ok(())
}

#[cfg(unix)]
fn spawn_held_child() -> TestResult<Child> {
    Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("failed to spawn sleep: {error}").into())
}

#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(unix)]
fn wait_until_dead(pid: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if !pid_is_alive(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return !pid_is_alive(pid);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn source_does_not_import_node_internals() {
    let source = include_str!("wallet_facing.rs");
    let code = uncommented_except_guard(source);
    // Executable identifier tokens for WF-01. Both proof functions are
    // removed from `code` before the scan, so their lists can name the
    // identifiers they forbid. Matching is at whole-identifier
    // granularity: the shared test-support crate `bitcoin_rs_e2e` is a
    // distinct name, not an occurrence of `bitcoin_rs`; the `_node` /
    // `_storage` / … tokens are the other workspace crates.
    let names = identifiers(&code);
    for banned in [
        "bitcoin_rs",
        "bitcoin_rs_node",
        "bitcoin_rs_storage",
        "bitcoin_rs_primitives",
        "bitcoin_rs_index",
        "bitcoin_rs_utxo",
        "NodeState",
        "UtxoSet",
    ] {
        assert!(
            !names.contains(banned),
            "wallet-facing proof must not name {banned} (WF-01)"
        );
    }
}

/// The WF-01 check matches whole identifier tokens: the shared harness
/// crate name passes, and every banned identifier still trips at word
/// granularity.
#[test]
fn wf_01_check_tolerates_the_shared_test_support_crate_name() {
    let permitted = identifiers(&strip_rust_comments("use bitcoin_rs_e2e::ProcessNode;\n"));
    assert!(permitted.contains("bitcoin_rs_e2e"));
    assert!(!permitted.contains("bitcoin_rs"));
    let tripped = identifiers(&strip_rust_comments("use bitcoin_rs::node::NodeState;\n"));
    assert!(tripped.contains("bitcoin_rs"));
    assert!(tripped.contains("NodeState"));
}

/// Split stripped source into maximal identifier tokens.
fn identifiers(code: &str) -> std::collections::HashSet<String> {
    code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Drop `//` and `/* */` comments, then drop this file's WF-01 guard
/// functions so their token lists are not scored as consumer imports.
fn uncommented_except_guard(source: &str) -> String {
    strip_fn(
        &strip_fn(
            &strip_rust_comments(source),
            "fn source_does_not_import_node_internals() {",
        ),
        "fn wf_01_check_tolerates_the_shared_test_support_crate_name() {",
    )
}

fn strip_rust_comments(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '"' || (chars[i] == 'b' && chars.get(i + 1) == Some(&'"')) {
            if chars[i] == 'b' {
                out.push('b');
                i += 1;
            }
            out.push('"');
            i += 1;
            while i < chars.len() {
                let next = chars[i];
                out.push(next);
                i += 1;
                if next == '\\' {
                    if i < chars.len() {
                        out.push(chars[i]);
                        i += 1;
                    }
                } else if next == '"' {
                    break;
                }
            }
            continue;
        }
        if chars[i] == '/' && chars.get(i + 1) == Some(&'/') {
            i += 2;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = i.saturating_add(2);
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn strip_fn(source: &str, signature: &str) -> String {
    let Some(start) = source.find(signature) else {
        panic!("wallet-facing proof must contain {signature}");
    };
    let Some(rel_brace) = source[start..].find('{') else {
        panic!("wallet-facing proof guard is missing a body");
    };
    let brace = start + rel_brace;
    let mut depth = 0_u32;
    let mut end = None;
    for (offset, next) in source[brace..].char_indices() {
        match next {
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    end = Some(brace + offset + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(end) = end else {
        panic!("wallet-facing proof guard is missing a closing brace");
    };
    let mut out = String::with_capacity(source.len() - (end - start));
    out.push_str(&source[..start]);
    out.push_str(&source[end..]);
    out
}

/// Coinbase output the miner pays, besides the witness commitment.
enum Coinbase<'a> {
    AnyoneCanSpend,
    P2wpkh(&'a ScriptBuf),
}

impl Coinbase<'_> {
    fn script_pubkey(self) -> ScriptBuf {
        match self {
            Self::AnyoneCanSpend => Builder::new().push_opcode(OP_PUSHNUM_1).into_script(),
            Self::P2wpkh(script) => script.clone(),
        }
    }
}

struct NodeProcess {
    addr: SocketAddr,
    logs: Arc<Mutex<String>>,
    child: Child,
}

/// Kills the daemon if startup fails before [`NodeProcess`] takes ownership.
struct StartupChild {
    child: Option<Child>,
}

impl StartupChild {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> TestResult<&mut Child> {
        self.child
            .as_mut()
            .ok_or("startup child already taken")
            .map_err(Into::into)
    }

    fn into_inner(mut self) -> TestResult<Child> {
        self.child
            .take()
            .ok_or("startup child already taken")
            .map_err(Into::into)
    }
}

impl Drop for StartupChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ignored = child.kill();
            let _ignored = child.wait();
        }
    }
}

impl NodeProcess {
    fn spawn(root: &Path) -> TestResult<Self> {
        let data_dir = root.join("node");
        let config_path = root.join("node.toml");
        std::fs::write(&config_path, "p2p_listen = []\ndns_seeds_enabled = false\n")?;

        let spawned = Command::new(env!("CARGO_BIN_EXE_bitcoin-rs"))
            .arg("--config")
            .arg(&config_path)
            .arg("--network")
            .arg("regtest")
            .arg("--scriptindex")
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--rpc-bind")
            .arg("127.0.0.1:0")
            .arg("--rpc-user")
            .arg(RPC_USER)
            .arg("--rpc-password")
            .arg(RPC_PASSWORD)
            .arg("--dbcache-mb")
            .arg("64")
            .arg("--log-level")
            .arg("info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("failed to spawn bitcoin-rs: {error}"))?;
        let mut child = StartupChild::new(spawned);

        let stderr = child
            .child_mut()?
            .stderr
            .take()
            .ok_or("bitcoin-rs stderr was not piped")?;
        let logs = Arc::new(Mutex::new(String::new()));
        let (addr_tx, addr_rx) = mpsc::channel();
        let log_buffer = Arc::clone(&logs);
        thread::spawn(move || {
            collect_startup_logs(stderr, &log_buffer, &addr_tx);
        });

        let addr = addr_rx.recv_timeout(STARTUP_TIMEOUT).map_err(|_| {
            format!(
                "timed out waiting for rpc listener bind\n{}",
                locked_string(&logs)
            )
        })?;
        Ok(Self {
            addr,
            logs,
            child: child.into_inner()?,
        })
    }
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ignored = self.child.kill();
        let _ignored = self.child.wait();
    }
}

fn collect_startup_logs(
    stderr: impl Read,
    logs: &Mutex<String>,
    addr_tx: &mpsc::Sender<SocketAddr>,
) {
    let reader = BufReader::new(stderr);
    let mut sent = false;
    for line in reader.lines() {
        let Ok(line) = line else {
            break;
        };
        {
            let mut buffer = logs.lock();
            buffer.push_str(&line);
            buffer.push('\n');
        }
        if sent || !line.contains("rpc listener bound") {
            continue;
        }
        if let Some(addr) = parse_rpc_addr(&line) {
            sent = addr_tx.send(addr).is_ok();
        }
    }
}

fn parse_rpc_addr(line: &str) -> Option<SocketAddr> {
    const MARKER: &str = "127.0.0.1:";
    let start = line.find(MARKER)?;
    let rest = line.get(start..)?;
    let end = rest
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.' || ch == ':'))
        .unwrap_or(rest.len());
    rest.get(..end)?.parse().ok()
}

fn locked_string(logs: &Mutex<String>) -> String {
    logs.lock().clone()
}

struct Client {
    logs: Arc<Mutex<String>>,
    // The shared keep-alive transport from the harness crate: a request
    // that reached the server is never resent, which matters because the
    // POST /api/tx broadcast is not idempotent.
    conn: RefCell<Connection>,
}

impl Client {
    fn mine(&self, coinbase: Coinbase<'_>) -> TestResult {
        let template = self.rpc("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
        let block = assemble_block_from_template(&template, &coinbase.script_pubkey())?;
        let hex = serialize_hex(&block);
        let result = self.rpc("submitblock", &json!([hex]))?;
        if !result.is_null() {
            return Err(format!("submitblock rejected: {result}").into());
        }
        Ok(())
    }

    fn wait_for_scriptindex(&self, address: &str) -> TestResult {
        let path = format!("/api/address/{address}/utxo");
        let deadline = Instant::now() + INDEX_TIMEOUT;
        loop {
            let response = self.esplora_get(&path)?;
            if response.status == 200 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "scriptindex did not answer {path} within {:?}: {} {}\n{}",
                    INDEX_TIMEOUT,
                    response.status,
                    response.body_text(),
                    locked_string(&self.logs)
                )
                .into());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn esplora_text(&self, path: &str) -> TestResult<String> {
        let response = self.esplora_get(path)?;
        if response.status != 200 {
            return Err(
                format!("GET {path} -> {} {}", response.status, response.body_text()).into(),
            );
        }
        Ok(response.body_text())
    }

    fn esplora_json(&self, path: &str) -> TestResult<Value> {
        let response = self.esplora_get(path)?;
        if response.status != 200 {
            return Err(
                format!("GET {path} -> {} {}", response.status, response.body_text()).into(),
            );
        }
        Ok(response.json()?)
    }

    /// Esplora surfaces 503 while the transaction index crosses a snapshot
    /// boundary mid-query ("changed during query; retry"), which the daemon
    /// answers asynchronously after each mined block: poll again inside the
    /// same index deadline the scriptindex wait already allows.
    fn esplora_get(&self, path: &str) -> TestResult<HttpResponse> {
        let deadline = Instant::now() + INDEX_TIMEOUT;
        loop {
            let response = self.exchange("GET", path, false, b"")?;
            if response.status != 503 || Instant::now() >= deadline {
                return Ok(response);
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn esplora_post(&self, path: &str, body: &[u8]) -> TestResult<HttpResponse> {
        self.exchange("POST", path, false, body)
    }

    fn rpc(&self, method: &str, params: &Value) -> TestResult<Value> {
        let request = json!({
            "jsonrpc": "1.0",
            "id": "wallet-facing",
            "method": method,
            "params": params,
        });
        let value = self.conn.borrow_mut().rpc(
            &request,
            (RPC_USER, RPC_PASSWORD),
            Instant::now() + REQUEST_TIMEOUT,
        )?;
        if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
            return Err(format!("{method} RPC error: {error}").into());
        }
        Ok(value.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Sends one request through the shared keep-alive connection.
    fn exchange(
        &self,
        method: &str,
        path: &str,
        auth: bool,
        body: &[u8],
    ) -> TestResult<HttpResponse> {
        Ok(self.conn.borrow_mut().http(
            method,
            path,
            body,
            if auth {
                Some((RPC_USER, RPC_PASSWORD))
            } else {
                None
            },
            Instant::now() + REQUEST_TIMEOUT,
        )?)
    }
}

fn p2wpkh_script() -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([2; 20]))
}

fn assert_esplora_namespace(
    client: &Client,
    height: &str,
    tip_hash: &str,
    genesis_hash: &str,
) -> TestResult {
    let unprefixed = client.esplora_get("/blocks/tip/height")?;
    assert_eq!(
        unprefixed.status,
        404,
        "unprefixed GET /blocks/tip/height must 404: {}",
        unprefixed.body_text()
    );
    let mempool_v1 = client.esplora_get("/api/v1/block-height/0")?;
    assert_eq!(
        mempool_v1.status,
        404,
        "GET /api/v1/block-height/0 is Mempool's prefix, not Esplora: {}",
        mempool_v1.body_text()
    );
    assert_eq!(
        client.esplora_text("/api/blocks/tip/hash")?.trim(),
        tip_hash.trim()
    );
    assert_eq!(
        client.esplora_text("/api/blocks/tip/height")?.trim(),
        height.trim()
    );
    assert_eq!(
        client.esplora_text("/api/block-height/0")?.trim(),
        genesis_hash.trim()
    );
    let header = client.esplora_text(&format!("/api/block/{}/header", tip_hash.trim()))?;
    assert_eq!(
        header.trim().len(),
        160,
        "GET /api/block/{{hash}}/header must return 80-byte header hex: {header}"
    );
    // API-26 (see above): no confirmed wallet traffic exists yet at this
    // point, so the 6-block target must still be omitted here.
    let fees = client.esplora_json("/api/fee-estimates")?;
    assert!(
        fees.get("6").is_none(),
        "GET /api/fee-estimates must omit the 6-block target without history: {fees}"
    );

    let leaked = client.esplora_post("/api/not-esplora", b"{}")?;
    assert_eq!(
        leaked.status,
        404,
        "POST under /api must stay Esplora (404), not fall through to JSON-RPC (401): {}",
        leaked.body_text()
    );
    let unprefixed_tx = client.esplora_post("/tx", b"00")?;
    assert_eq!(
        unprefixed_tx.status,
        401,
        "unprefixed POST /tx must be JSON-RPC (401 without auth), not Esplora: {}",
        unprefixed_tx.body_text()
    );
    let backend = client.esplora_get("/api/internal/mempool/txs")?;
    assert_eq!(
        backend.status,
        404,
        "GET /api/internal/* is not wallet-facing: {}",
        backend.body_text()
    );
    let head_tx = client.exchange("HEAD", "/api/tx", false, b"")?;
    assert_eq!(
        head_tx.status,
        404,
        "HEAD /api/tx must not run POST /tx: {}",
        head_tx.body_text()
    );
    let put_root = client.exchange("PUT", "/", false, b"")?;
    assert_eq!(
        put_root.status,
        404,
        "PUT / is not JSON-RPC: {}",
        put_root.body_text()
    );
    assert_eq!(
        client.esplora_text("/esplora/blocks/tip/height")?.trim(),
        height.trim(),
        "/esplora is a superset of public electrs"
    );
    let backend_internal = client.esplora_get("/esplora/internal/mempool/txs")?;
    assert_eq!(
        backend_internal.status,
        200,
        "GET /esplora/internal/* is the mempool-backend path: {}",
        backend_internal.body_text()
    );
    Ok(())
}

fn assert_script_activity(client: &Client, address: &str, script: &ScriptBuf) -> TestResult {
    let summary = client.esplora_json(&format!("/api/address/{address}"))?;
    assert!(
        summary.get("chain_stats").is_some(),
        "address summary must include chain_stats: {summary}"
    );

    let address_utxos = client.esplora_json(&format!("/api/address/{address}/utxo"))?;
    let utxos = address_utxos
        .as_array()
        .ok_or("address UTXO response must be a JSON array")?;
    assert!(
        !utxos.is_empty(),
        "P2WPKH coinbase must be visible on /address/{{addr}}/utxo: {address_utxos}"
    );

    let history = client.esplora_json(&format!("/api/address/{address}/txs"))?;
    assert!(
        history
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        "address history must list the funding transaction: {history}"
    );

    let script_hash = sha256::Hash::hash(script.as_bytes()).to_string();
    let twin = client.esplora_json(&format!("/api/scripthash/{script_hash}"))?;
    assert!(
        twin.get("chain_stats").is_some(),
        "scripthash summary must include chain_stats: {twin}"
    );
    let twin_utxos = client.esplora_json(&format!("/api/scripthash/{script_hash}/utxo"))?;
    assert_eq!(
        twin_utxos, address_utxos,
        "scripthash UTXOs must match the address twin"
    );
    let twin_history = client.esplora_json(&format!("/api/scripthash/{script_hash}/txs"))?;
    assert!(
        twin_history
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        "scripthash history must list the funding transaction: {twin_history}"
    );
    Ok(())
}

fn spend_anyone_can_spend(client: &Client, height: u32, payout: &ScriptBuf) -> TestResult<String> {
    // The coinbase at `height` is anyone-can-spend (`OP_TRUE`) and must be
    // mature under the current tip. The default binary's portable interpreter
    // verifies that class; it does not verify P2WPKH, and the node holds no
    // keys. A wallet would sign here. Broadcast still goes through the public
    // `POST /api/tx` path, paying a standard P2WPKH so policy accepts the output.
    let block_hash = client.esplora_text(&format!("/api/block-height/{height}"))?;
    let txid_hex = client.esplora_text(&format!("/api/block/{}/txid/0", block_hash.trim()))?;
    let txid: Txid = txid_hex.trim().parse()?;
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(txid, 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS.saturating_sub(FEE_SATS)),
            script_pubkey: payout.clone(),
        }],
    };
    Ok(serialize_hex(&spend))
}

/// Polls `/api/tx/{txid}/status` past the post-mine index settle (the
/// endpoint answers 503 until the new tip is queryable) until the spend
/// confirms or the index timeout expires.
fn wait_for_confirmation(client: &Client, txid: &str) -> TestResult<()> {
    let deadline = Instant::now() + INDEX_TIMEOUT;
    loop {
        let response = client.esplora_get(&format!("/api/tx/{txid}/status"))?;
        if response.status == 200 {
            let status = response.json()?;
            if status.get("confirmed").and_then(Value::as_bool) == Some(true) {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(format!("the mined block must confirm the broadcast spend {txid}").into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}
