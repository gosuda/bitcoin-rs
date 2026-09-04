//! Wallet-facing consumer: spawn the public `bitcoin-rs` binary and talk
//! only HTTP (Esplora + JSON-RPC) using rust-bitcoin.
//!
//! This is the executable proof of `docs/contracts/wallet-facing.md`. It
//! lives in the binary package so it can spawn `CARGO_BIN_EXE_bitcoin-rs`.
//! `source_does_not_import_node_internals` enforces `WF-01` on this
//! source. The named out-of-repo consumer is `gosuda/bitcoin-wallet`
//! (`btcw -u`).

#![allow(missing_docs)]

use std::error::Error;
use std::io::{BufRead as _, BufReader, Read, Write as _};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version as BlockVersion};
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::constants::{COINBASE_MATURITY, genesis_block};
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256;
use bitcoin::opcodes::all::OP_PUSHNUM_1;
use bitcoin::script::Builder;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Address, Amount, Block, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, Target,
    Transaction, TxIn, TxMerkleNode, TxOut, Txid, WPubkeyHash, Witness,
};
use parking_lot::Mutex;
use serde_json::{Value, json};

const RPC_USER: &str = "bitcoin-rs";
const RPC_PASSWORD: &str = "bitcoin-rs";
const FEE_SATS: u64 = 10_000;
const REGTEST_SUBSIDY_SATS: u64 = 5_000_000_000;
const WITNESS_RESERVED: [u8; 32] = [0_u8; 32];
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const INDEX_TIMEOUT: Duration = Duration::from_mins(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn external_wallet_can_scan_estimate_and_broadcast() -> TestResult {
    let workspace = tempfile::tempdir()?;
    let node = NodeProcess::spawn(workspace.path())?;
    let client = Client {
        addr: node.addr,
        logs: Arc::clone(&node.logs),
    };
    let p2wpkh = p2wpkh_script();
    let address = Address::from_script(&p2wpkh, Network::Regtest)
        .map_err(|error| format!("p2wpkh fixture must be a standard address: {error}"))?
        .to_string();

    client.submit_genesis()?;
    for _ in 0..COINBASE_MATURITY {
        client.mine(Coinbase::AnyoneCanSpend)?;
    }
    client.mine(Coinbase::P2wpkh(&p2wpkh))?;

    let height = client.esplora_text("/blocks/tip/height")?;
    assert_eq!(
        height.trim(),
        COINBASE_MATURITY.saturating_add(1).to_string(),
        "tip height after genesis + {} mined blocks",
        COINBASE_MATURITY.saturating_add(1)
    );
    let tip_hash = client.esplora_text("/blocks/tip/hash")?;
    let genesis_hash = client.esplora_text("/block-height/0")?;
    assert_eq!(
        genesis_hash.trim(),
        genesis_block(Network::Regtest).block_hash().to_string(),
        "GET /block-height/0 must return the regtest genesis hash"
    );
    assert_ne!(
        tip_hash.trim(),
        genesis_hash.trim(),
        "tip must have moved past genesis"
    );

    let fees = client.esplora_json("/fee-estimates")?;
    assert!(
        fees.get("6").and_then(Value::as_f64).is_some(),
        "fee estimates must include the 6-block target wallets use: {fees}"
    );
    assert_prefixed_chain_view(&client, &height, &tip_hash, &genesis_hash)?;

    client.wait_for_scriptindex(&address)?;
    assert_script_activity(&client, &address, &p2wpkh)?;

    let spend_hex = spend_first_anyone_can_spend(&client, &p2wpkh)?;
    let broadcast = client.esplora_post("/api/v1/tx", spend_hex.as_bytes())?;
    assert_eq!(
        broadcast.status,
        200,
        "POST /api/v1/tx: {}",
        broadcast.text()
    );
    let txid = broadcast.text();
    assert_eq!(
        txid.trim().len(),
        64,
        "broadcast must return a txid: {txid}"
    );

    let mempool_tx = client.esplora_json(&format!("/tx/{}", txid.trim()))?;
    assert_eq!(
        mempool_tx
            .get("status")
            .and_then(|status| status.get("confirmed"))
            .and_then(Value::as_bool),
        Some(false),
        "broadcast transaction must be visible as unconfirmed: {mempool_tx}"
    );
    let tx_status = client.esplora_json(&format!("/tx/{}/status", txid.trim()))?;
    assert_eq!(
        tx_status.get("confirmed").and_then(Value::as_bool),
        Some(false),
        "GET /tx/{{id}}/status must report unconfirmed: {tx_status}"
    );
    Ok(())
}

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

fn spawn_held_child() -> TestResult<Child> {
    Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("failed to spawn sleep: {error}").into())
}

fn pid_is_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

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
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    // Executable tokens for WF-01. Reconstruct so this function does not
    // contain the names it forbids. The contract owns the rule; this list
    // is the proof, not a second policy.
    for banned in [
        concat!("bitcoin_rs", "::"),
        concat!("bitcoin_rs", "_node"),
        concat!("bitcoin_rs", "_storage"),
        concat!("bitcoin_rs", "_primitives"),
        concat!("bitcoin_rs", "_index"),
        concat!("bitcoin_rs", "_utxo"),
        concat!("Node", "State"),
        concat!("Utxo", "Set"),
    ] {
        assert!(
            !code.contains(banned),
            "wallet-facing proof must not name {banned} (WF-01)"
        );
    }
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
    addr: SocketAddr,
    logs: Arc<Mutex<String>>,
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl HttpResponse {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> TestResult<Value> {
        serde_json::from_slice(&self.body).map_err(|error| {
            format!(
                "invalid JSON (status {}): {error}: {}",
                self.status,
                self.text()
            )
            .into()
        })
    }
}

impl Client {
    fn submit_genesis(&self) -> TestResult {
        let hex = serialize_hex(&genesis_block(Network::Regtest));
        let result = self.rpc("submitblock", &json!([hex]))?;
        if !result.is_null() {
            return Err(format!("submitblock(genesis) rejected: {result}").into());
        }
        Ok(())
    }

    fn mine(&self, coinbase: Coinbase<'_>) -> TestResult {
        let template = self.rpc("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
        let block = assemble_from_template(&template, coinbase)?;
        let hex = serialize_hex(&block);
        let result = self.rpc("submitblock", &json!([hex]))?;
        if !result.is_null() {
            return Err(format!("submitblock rejected: {result}").into());
        }
        Ok(())
    }

    fn wait_for_scriptindex(&self, address: &str) -> TestResult {
        let path = format!("/address/{address}/utxo");
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
                    response.text(),
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
            return Err(format!("GET {path} -> {} {}", response.status, response.text()).into());
        }
        Ok(response.text())
    }

    fn esplora_json(&self, path: &str) -> TestResult<Value> {
        let response = self.esplora_get(path)?;
        if response.status != 200 {
            return Err(format!("GET {path} -> {} {}", response.status, response.text()).into());
        }
        response.json()
    }

    fn esplora_get(&self, path: &str) -> TestResult<HttpResponse> {
        self.exchange("GET", path, None, b"")
    }

    fn esplora_post(&self, path: &str, body: &[u8]) -> TestResult<HttpResponse> {
        self.exchange("POST", path, None, body)
    }

    fn rpc(&self, method: &str, params: &Value) -> TestResult<Value> {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "1.0",
            "id": "wallet-facing",
            "method": method,
            "params": params,
        }))?;
        let token = basic_token();
        let response = self.exchange("POST", "/", Some(token.as_str()), &body)?;
        let value = response.json()?;
        if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
            return Err(format!("{method} RPC error: {error}").into());
        }
        Ok(value.get("result").cloned().unwrap_or(Value::Null))
    }

    fn exchange(
        &self,
        method: &str,
        path: &str,
        authorization: Option<&str>,
        body: &[u8],
    ) -> TestResult<HttpResponse> {
        let mut stream = TcpStream::connect_timeout(&self.addr, REQUEST_TIMEOUT)?;
        stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
        stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
        let auth_line = authorization
            .map(|token| format!("Authorization: Basic {token}\r\n"))
            .unwrap_or_default();
        let content_type = if authorization.is_some() {
            "application/json"
        } else {
            "text/plain"
        };
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: {}\r\n{auth_line}Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.addr,
            body.len()
        )?;
        stream.write_all(body)?;
        stream.flush()?;
        let _ignored = stream.shutdown(Shutdown::Write);
        read_http_response(stream)
    }
}

fn p2wpkh_script() -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([2; 20]))
}

fn assert_prefixed_chain_view(
    client: &Client,
    height: &str,
    tip_hash: &str,
    genesis_hash: &str,
) -> TestResult {
    let prefixed_height = client.esplora_text("/api/v1/block-height/0")?;
    assert_eq!(
        prefixed_height.trim(),
        genesis_hash.trim(),
        "GET /api/v1/block-height/0 must alias GET /block-height/0"
    );
    let prefixed_tip = client.esplora_text("/api/blocks/tip/hash")?;
    assert_eq!(
        prefixed_tip.trim(),
        tip_hash.trim(),
        "GET /api/blocks/tip/hash must alias GET /blocks/tip/hash"
    );
    let prefixed_tip_height = client.esplora_text("/api/v1/blocks/tip/height")?;
    assert_eq!(
        prefixed_tip_height.trim(),
        height.trim(),
        "GET /api/v1/blocks/tip/height must alias GET /blocks/tip/height"
    );
    let header = client.esplora_text(&format!("/block/{}/header", tip_hash.trim()))?;
    assert_eq!(
        header.trim().len(),
        160,
        "GET /block/{{hash}}/header must return 80-byte header hex: {header}"
    );
    let prefixed_fees = client.esplora_json("/api/v1/fee-estimates")?;
    assert!(
        prefixed_fees.get("6").and_then(Value::as_f64).is_some(),
        "GET /api/v1/fee-estimates must alias GET /fee-estimates: {prefixed_fees}"
    );
    Ok(())
}

fn assert_script_activity(client: &Client, address: &str, script: &ScriptBuf) -> TestResult {
    let summary = client.esplora_json(&format!("/address/{address}"))?;
    assert!(
        summary.get("chain_stats").is_some(),
        "address summary must include chain_stats: {summary}"
    );

    let address_utxos = client.esplora_json(&format!("/address/{address}/utxo"))?;
    let utxos = address_utxos
        .as_array()
        .ok_or("address UTXO response must be a JSON array")?;
    assert!(
        !utxos.is_empty(),
        "P2WPKH coinbase must be visible on /address/{{addr}}/utxo: {address_utxos}"
    );

    let history = client.esplora_json(&format!("/address/{address}/txs"))?;
    assert!(
        history
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        "address history must list the funding transaction: {history}"
    );

    let script_hash = sha256::Hash::hash(script.as_bytes()).to_string();
    let twin = client.esplora_json(&format!("/scripthash/{script_hash}"))?;
    assert!(
        twin.get("chain_stats").is_some(),
        "scripthash summary must include chain_stats: {twin}"
    );
    let twin_utxos = client.esplora_json(&format!("/scripthash/{script_hash}/utxo"))?;
    assert_eq!(
        twin_utxos, address_utxos,
        "scripthash UTXOs must match the address twin"
    );
    let twin_history = client.esplora_json(&format!("/scripthash/{script_hash}/txs"))?;
    assert!(
        twin_history
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        "scripthash history must list the funding transaction: {twin_history}"
    );
    Ok(())
}

fn spend_first_anyone_can_spend(client: &Client, payout: &ScriptBuf) -> TestResult<String> {
    // Height-1 coinbase is anyone-can-spend (`OP_TRUE`). The default binary's
    // portable interpreter verifies that class; it does not verify P2WPKH, and
    // the node holds no keys. A wallet would sign here. Broadcast still goes
    // through the public `POST /tx` path, paying a standard P2WPKH so policy
    // accepts the output.
    let block_hash = client.esplora_text("/block-height/1")?;
    let txid_hex = client.esplora_text(&format!("/block/{}/txid/0", block_hash.trim()))?;
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

fn assemble_from_template(template: &Value, coinbase: Coinbase<'_>) -> TestResult<Block> {
    let prev_hex = required_str(template, "previousblockhash")?;
    let height = u32::try_from(required_u64(template, "height")?)?;
    let coinbase_value = required_u64(template, "coinbasevalue")?;
    let bits = CompactTarget::from_unprefixed_hex(required_str(template, "bits")?)?;
    let curtime = u32::try_from(required_u64(template, "curtime")?)?;
    let version = i32::try_from(required_u64(template, "version")?)?;
    let commitment = ScriptBuf::from_hex(required_str(template, "default_witness_commitment")?)?;

    let mut txs = Vec::new();
    if let Some(entries) = template.get("transactions").and_then(Value::as_array) {
        for entry in entries {
            let data = entry
                .get("data")
                .and_then(Value::as_str)
                .ok_or("template transaction missing data hex")?;
            txs.push(deserialize_hex::<Transaction>(data)?);
        }
    }

    let coinbase_tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script_sig(height),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[&WITNESS_RESERVED]),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(coinbase_value),
                script_pubkey: coinbase.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: commitment,
            },
        ],
    };

    let mut txdata = Vec::with_capacity(txs.len().saturating_add(1));
    txdata.push(coinbase_tx);
    txdata.extend(txs);
    let mut block = Block {
        header: Header {
            version: BlockVersion::from_consensus(version),
            prev_blockhash: prev_hex.parse()?,
            merkle_root: TxMerkleNode::all_zeros(),
            time: curtime,
            bits,
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or("block must have a merkle root")?;
    grind_pow(&mut block.header)?;
    Ok(block)
}

fn coinbase_script_sig(height: u32) -> ScriptBuf {
    let mut builder = Builder::new().push_int(i64::from(height));
    // Coinbase scriptSig must be at least two bytes (Core bad-cb-length).
    // Heights 1..=16 encode as a single OP_N.
    if builder.len() < 2 {
        builder = builder.push_int(0);
    }
    builder.into_script()
}

fn grind_pow(header: &mut Header) -> TestResult {
    let target = Target::from(header.bits);
    loop {
        if target.is_met_by(header.block_hash()) {
            return Ok(());
        }
        header.nonce = header
            .nonce
            .checked_add(1)
            .ok_or("nonce exhausted while grinding block")?;
    }
}

fn required_str<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("template missing string {key}").into())
}

fn required_u64(value: &Value, key: &str) -> TestResult<u64> {
    let entry = value
        .get(key)
        .ok_or_else(|| format!("template missing {key}"))?;
    entry
        .as_u64()
        .or_else(|| entry.as_i64().and_then(|n| u64::try_from(n).ok()))
        .ok_or_else(|| format!("template field {key} is not an integer: {entry}").into())
}

fn basic_token() -> String {
    encode_base64(format!("{RPC_USER}:{RPC_PASSWORD}").as_bytes())
}

fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3).saturating_mul(4));
    for chunk in input.chunks(3) {
        let byte0 = chunk[0];
        let byte1 = chunk.get(1).copied().unwrap_or(0);
        let byte2 = chunk.get(2).copied().unwrap_or(0);
        out.push(char::from(ALPHABET[usize::from(byte0 >> 2)]));
        out.push(char::from(
            ALPHABET[usize::from(((byte0 & 0x03) << 4) | (byte1 >> 4))],
        ));
        if chunk.len() > 1 {
            out.push(char::from(
                ALPHABET[usize::from(((byte1 & 0x0f) << 2) | (byte2 >> 6))],
            ));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(ALPHABET[usize::from(byte2 & 0x3f)]));
        } else {
            out.push('=');
        }
    }
    out
}

fn read_http_response(stream: TcpStream) -> TestResult<HttpResponse> {
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("invalid HTTP status line: {status_line}"))?
        .parse::<u16>()?;
    let mut content_length = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(value.trim().parse::<usize>()?);
        }
    }
    let length = content_length.ok_or("response missing Content-Length")?;
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body)?;
    Ok(HttpResponse { status, body })
}
