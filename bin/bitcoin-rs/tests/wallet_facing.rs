//! Wallet-facing consumer: spawn the public `bitcoin-rs` binary and talk
//! only HTTP (Esplora + JSON-RPC).
//!
//! This is the executable proof of `docs/contracts/wallet-facing.md`. It
//! does not import `NodeState`, `UtxoSet`, or index types. The named
//! out-of-repo consumer is `gosuda/bitcoin-wallet` (`btcw -u`); this test
//! issues the BDK/esplora-client operations that wallet uses: tip, block
//! height, headers, scripthash history, fee estimates, and `POST /tx`,
//! including the `/api` and `/api/v1` prefixes wallets copy from
//! mempool.space.

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

use bitcoin_rs_primitives::encode::{consensus_bytes, double_sha256};
use bitcoin_rs_primitives::{
    Block, Hash256, Network, OutPoint, Tx, TxIn, TxOut, Txid, deserialize,
};
use parking_lot::Mutex;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const RPC_USER: &str = "bitcoin-rs";
const RPC_PASSWORD: &str = "bitcoin-rs";
const MATURE_AFTER: u32 = 100;
const FEE_SATS: u64 = 10_000;
const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;
const WITNESS_RESERVED: [u8; 32] = [0_u8; 32];
const OP_TRUE: [u8; 1] = [0x51];
/// P2WPKH for key hash `[2; 20]`, the same fixture the Esplora unit tests use.
const P2WPKH_SCRIPT: [u8; 22] = [
    0x00, 0x14, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
];
/// BIP173 `bcrt1` encoding of `P2WPKH_SCRIPT`.
const P2WPKH_ADDRESS: &str = "bcrt1qqgpqyqszqgpqyqszqgpqyqszqgpqyqszazmwwa";
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

    client.submit_genesis()?;
    for _ in 0..MATURE_AFTER {
        client.mine(Coinbase::AnyoneCanSpend)?;
    }
    client.mine(Coinbase::P2wpkh)?;

    let height = client.esplora_text("/blocks/tip/height")?;
    assert_eq!(
        height.trim(),
        MATURE_AFTER.saturating_add(1).to_string(),
        "tip height after genesis + {} mined blocks",
        MATURE_AFTER.saturating_add(1)
    );
    let tip_hash = client.esplora_text("/blocks/tip/hash")?;
    let genesis_hash = client.esplora_text("/block-height/0")?;
    assert_eq!(
        genesis_hash.trim(),
        Network::Regtest.genesis_block().block_hash().to_string(),
        "GET /block-height/0 must return the regtest genesis hash"
    );
    assert_ne!(
        tip_hash.trim(),
        genesis_hash.trim(),
        "tip must have moved past genesis"
    );
    assert_eq!(
        client.esplora_text("/api/v1/block-height/0")?.trim(),
        genesis_hash.trim(),
        "BDK/mempool.space /api/v1 prefix must alias /block-height"
    );
    assert_eq!(
        client.esplora_text("/api/blocks/tip/hash")?.trim(),
        tip_hash.trim(),
        "/api prefix must alias /blocks/tip/hash"
    );

    let header = client.esplora_text(&format!("/block/{}/header", tip_hash.trim()))?;
    assert_eq!(
        header.trim().len(),
        160,
        "GET /block/{{hash}}/header must be an 80-byte header as hex: {header}"
    );

    let fees = client.esplora_json("/api/fee-estimates")?;
    assert!(
        fees.get("6").and_then(Value::as_f64).is_some(),
        "fee estimates must include the 6-block target wallets use: {fees}"
    );

    client.wait_for_scriptindex(P2WPKH_ADDRESS)?;

    let address_utxos = client.esplora_json(&format!("/address/{P2WPKH_ADDRESS}/utxo"))?;
    let utxos = address_utxos
        .as_array()
        .ok_or("address UTXO response must be a JSON array")?;
    assert!(
        !utxos.is_empty(),
        "P2WPKH coinbase must be visible on /address/{{addr}}/utxo: {address_utxos}"
    );

    let history = client.esplora_json(&format!("/address/{P2WPKH_ADDRESS}/txs"))?;
    assert!(
        history
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        "address history must list the funding transaction: {history}"
    );

    // BDK talks scripthash, not address. Empty scripthash history is a silent
    // wallet-sync failure: balance stays 0 and no HTTP error is returned.
    let scripthash = p2wpkh_scripthash();
    let script_utxos = client.esplora_json(&format!("/scripthash/{scripthash}/utxo"))?;
    assert!(
        script_utxos
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        "P2WPKH coinbase must be visible on /scripthash/{{h}}/utxo: {script_utxos}"
    );
    let script_history = client.esplora_json(&format!("/scripthash/{scripthash}/txs"))?;
    assert!(
        script_history
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        "scripthash history must list the funding transaction: {script_history}"
    );

    let spend_hex = spend_first_anyone_can_spend(&client)?;
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
        "GET /tx/{{id}}/status is the confirmation record BDK syncs: {tx_status}"
    );
    Ok(())
}

fn p2wpkh_scripthash() -> String {
    hex_encode(Sha256::digest(P2WPKH_SCRIPT).as_slice())
}

/// Coinbase output the miner pays, besides the witness commitment.
#[derive(Clone, Copy)]
enum Coinbase {
    AnyoneCanSpend,
    P2wpkh,
}

impl Coinbase {
    fn script_pubkey(self) -> Vec<u8> {
        match self {
            Self::AnyoneCanSpend => OP_TRUE.to_vec(),
            Self::P2wpkh => P2WPKH_SCRIPT.to_vec(),
        }
    }
}

struct NodeProcess {
    addr: SocketAddr,
    logs: Arc<Mutex<String>>,
    child: Child,
}

struct StartupChild(Child);

impl Drop for StartupChild {
    fn drop(&mut self) {
        let _ignored = self.0.kill();
        let _ignored = self.0.wait();
    }
}

impl NodeProcess {
    fn spawn(root: &Path) -> TestResult<Self> {
        let data_dir = root.join("node");
        let config_path = root.join("node.toml");
        std::fs::write(&config_path, "p2p_listen = []\ndns_seeds_enabled = false\n")?;

        let mut child = Command::new(env!("CARGO_BIN_EXE_bitcoin-rs"))
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
        let mut child = StartupChild(child);

        let stderr = child
            .0
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
                logs.lock().clone()
            )
        })?;
        Ok(Self {
            addr,
            logs,
            child: child.0,
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
        let hex = hex_encode(&consensus_bytes(&Network::Regtest.genesis_block()));
        let result = self.rpc("submitblock", &json!([hex]))?;
        if !result.is_null() {
            return Err(format!("submitblock(genesis) rejected: {result}").into());
        }
        Ok(())
    }

    fn mine(&self, coinbase: Coinbase) -> TestResult {
        let template = self.rpc("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
        let block = assemble_from_template(&template, coinbase)?;
        let hex = hex_encode(&consensus_bytes(&block));
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
                    self.logs.lock().clone()
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

fn spend_first_anyone_can_spend(client: &Client) -> TestResult<String> {
    // Height-1 coinbase is anyone-can-spend (`OP_TRUE`), the one script class
    // the portable interpreter verifies. The node holds no keys; a wallet
    // would sign here. Broadcast still goes through the public `POST /tx`
    // path, paying a standard P2WPKH so policy accepts the output.
    let block_hash = client.esplora_text("/block-height/1")?;
    let txid_hex = client.esplora_text(&format!("/block/{}/txid/0", block_hash.trim()))?;
    let txid: Txid = txid_hex.trim().parse()?;
    let spend = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(txid, 0),
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: REGTEST_SUBSIDY_SATS.saturating_sub(FEE_SATS),
            script_pubkey: P2WPKH_SCRIPT.to_vec(),
        }],
        lock_time: 0,
    };
    Ok(hex_encode(&consensus_bytes(&spend)))
}

fn assemble_from_template(template: &Value, coinbase: Coinbase) -> TestResult<Block> {
    let prev_hex = required_str(template, "previousblockhash")?;
    let height = u32::try_from(required_u64(template, "height")?)?;
    let coinbase_value = required_u64(template, "coinbasevalue")?;
    let bits = u32::from_str_radix(required_str(template, "bits")?, 16)?;
    let curtime = u32::try_from(required_u64(template, "curtime")?)?;
    let version = i32::try_from(required_u64(template, "version")?)?;
    let commitment_script = hex_decode(required_str(template, "default_witness_commitment")?)?;

    let mut txs = Vec::new();
    if let Some(entries) = template.get("transactions").and_then(Value::as_array) {
        for entry in entries {
            let data = entry
                .get("data")
                .and_then(Value::as_str)
                .ok_or("template transaction missing data hex")?;
            txs.push(deserialize::<Tx>(&hex_decode(data)?)?);
        }
    }

    let coinbase_tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: coinbase_script_sig(height),
            sequence: 0xffff_ffff,
            witness: vec![WITNESS_RESERVED.to_vec()],
        }],
        outputs: vec![
            TxOut {
                value: coinbase_value,
                script_pubkey: coinbase.script_pubkey(),
            },
            TxOut {
                value: 0,
                script_pubkey: commitment_script,
            },
        ],
        lock_time: 0,
    };

    let mut block_txs = Vec::with_capacity(txs.len().saturating_add(1));
    block_txs.push(coinbase_tx);
    block_txs.extend(txs);
    let merkle_root = merkle_root(&block_txs).ok_or("block must have a merkle root")?;
    let mut block = Block {
        header: bitcoin_rs_primitives::Header {
            version,
            prev_blockhash: prev_hex.parse()?,
            merkle_root,
            time: curtime,
            bits,
            nonce: 0,
        },
        txs: block_txs,
    };
    grind_pow(&mut block)?;
    Ok(block)
}

fn coinbase_script_sig(height: u32) -> Vec<u8> {
    let mut script = script_push_int(i64::from(height));
    // Coinbase scriptSig must be at least two bytes (Core bad-cb-length).
    // Heights 1..=16 encode as a single OP_N.
    script.extend(script_push_int(0));
    script
}

fn script_push_int(value: i64) -> Vec<u8> {
    match value {
        0 => vec![0x00],
        1..=16 => vec![0x50_u8.saturating_add(u8::try_from(value).unwrap_or_default())],
        _ => {
            let mut payload = Vec::new();
            let mut magnitude = value.unsigned_abs();
            while magnitude > 0 {
                payload.push(u8::try_from(magnitude & 0xff).unwrap_or_default());
                magnitude >>= 8;
            }
            let mut out = Vec::with_capacity(payload.len().saturating_add(1));
            out.push(u8::try_from(payload.len()).unwrap_or_default());
            out.extend(payload);
            out
        }
    }
}

fn merkle_root(txs: &[Tx]) -> Option<Hash256> {
    if txs.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pos in 0..level.len().div_ceil(2) {
            let left = level[2 * pos];
            let right = level[(2 * pos + 1).min(level.len().saturating_sub(1))];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(*double_sha256(&pair).as_byte_array());
        }
        level = next;
    }
    Some(Hash256::from_le_bytes(level.first()?))
}

fn grind_pow(block: &mut Block) -> TestResult {
    loop {
        if pow_is_met(block.header.bits, &block.header.compute_hash().into()) {
            return Ok(());
        }
        let Some(next) = block.header.nonce.checked_add(1) else {
            return Err("nonce exhausted while grinding block".into());
        };
        block.header.nonce = next;
    }
}

fn pow_is_met(bits: u32, hash: &Hash256) -> bool {
    let exponent = usize::try_from(bits >> 24).unwrap_or(usize::MAX);
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 || mantissa & 0x0080_0000 != 0 || exponent > 32 {
        return false;
    }
    let shift = exponent.saturating_sub(3);
    let mantissa_le = mantissa.to_le_bytes();
    let mut target = [0_u8; 32];
    for (offset, byte) in mantissa_le.iter().take(3).enumerate() {
        let position = shift.saturating_add(offset);
        if let Some(slot) = target.get_mut(position) {
            *slot = *byte;
        }
    }
    let hash_le = hash.to_le_bytes();
    for index in (0..32).rev() {
        match hash_le[index].cmp(&target[index]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn hex_decode(hex: &str) -> TestResult<Vec<u8>> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err("hex string must have even length".into());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0]).ok_or("invalid hex")?;
        let lo = hex_nibble(pair[1]).ok_or("invalid hex")?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn basic_token() -> String {
    base64(format!("{RPC_USER}:{RPC_PASSWORD}").as_bytes())
}

fn base64(input: &[u8]) -> String {
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
