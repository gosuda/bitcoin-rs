//! Public-process custody for the pinned regtest differential lane.

use std::fmt;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::Hash as _;
use bitcoin::{Address, Block, Network, OutPoint, PrivateKey};
use serde_json::{Value, json};
use tempfile::TempDir;

// Cold storage initialization needs more time than a single loopback request.
const START_TIMEOUT: Duration = Duration::from_secs(30);
// A failed graceful shutdown must not retain a test child indefinitely.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE: usize = 16 * 1024 * 1024;
const MAX_TRANSCRIPT: u64 = 64 * 1024 * 1024;
const MOCK_TIME: u64 = 1_780_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NodeBinary {
    BitcoinRs,
    ReferenceCore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClockControl {
    Mock(u64),
    None,
}

#[derive(Debug)]
pub(crate) enum HarnessError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Reference {
        path: PathBuf,
        expected: String,
        detail: String,
    },
    Protocol(String),
    Deadline {
        operation: &'static str,
        evidence: PathBuf,
        detail: String,
    },
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "io: {error}"),
            Self::Json(error) => write!(f, "json: {error}"),
            Self::Reference {
                path,
                expected,
                detail,
            } => write!(
                f,
                "reference binary {} must have SHA256 {expected}: {detail}",
                path.display()
            ),
            Self::Protocol(detail) => write!(f, "protocol: {detail}"),
            Self::Deadline {
                operation,
                evidence,
                detail,
            } => write!(
                f,
                "{operation} deadline; evidence {}: {detail}",
                evidence.display()
            ),
        }
    }
}
impl std::error::Error for HarnessError {}
impl From<std::io::Error> for HarnessError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<serde_json::Error> for HarnessError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub(crate) struct ProcessNode {
    child: Child,
    _datadir: TempDir,
    addr: SocketAddr,
    binary: NodeBinary,
    pub(crate) clock: ClockControl,
    pub(crate) evidence: PathBuf,
    journal: File,
    journal_bytes: u64,
    started: Instant,
}

pub(crate) fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn executable(binary: NodeBinary) -> Result<PathBuf, HarnessError> {
    match binary {
        NodeBinary::BitcoinRs => Ok(PathBuf::from(env!("CARGO_BIN_EXE_bitcoin-rs"))),
        NodeBinary::ReferenceCore => {
            let path = std::env::var_os("BITCOIN_RS_REFERENCE_BITCOIND").map_or_else(
                || workspace().join("target/reference-core-31.1/bitcoin-31.1/bin/bitcoind"),
                PathBuf::from,
            );
            verify_reference_binary(&path)?;
            Ok(path)
        }
    }
}

fn launch(
    binary: NodeBinary,
    datadir: &Path,
    addr: SocketAddr,
) -> Result<(Command, ClockControl), HarnessError> {
    let mut command = Command::new(executable(binary)?);
    let clock = match binary {
        NodeBinary::ReferenceCore => {
            command
                .args([
                    "-regtest",
                    "-server",
                    "-listen=0",
                    "-connect=0",
                    "-dnsseed=0",
                    "-disablewallet",
                    "-rpcuser=parity",
                    "-rpcpassword=parity",
                ])
                .arg(format!("-datadir={}", datadir.display()))
                .arg(format!("-rpcport={}", addr.port()))
                .arg(format!("-mocktime={MOCK_TIME}"));
            ClockControl::Mock(MOCK_TIME)
        }
        NodeBinary::BitcoinRs => {
            let config_path = datadir.join("node.toml");
            fs::write(&config_path, "p2p_listen = []\ndns_seeds_enabled = false\n")?;
            command
                .arg("--config")
                .arg(config_path)
                .args([
                    "--network",
                    "regtest",
                    "--storage-backend",
                    "fjall",
                    "--rpc-user",
                    "parity",
                    "--rpc-password",
                    "parity",
                    "--dbcache-mb",
                    "64",
                ])
                .arg("--data-dir")
                .arg(datadir.join("node"))
                .arg("--rpc-bind")
                .arg(addr.to_string());
            // No public clock input exists in the current CLI.
            ClockControl::None
        }
    };
    Ok((command, clock))
}

impl ProcessNode {
    pub(crate) fn start(binary: NodeBinary) -> Result<Self, HarnessError> {
        let datadir = tempfile::tempdir()?;
        let evidence_root = workspace().join("target/process-harness");
        fs::create_dir_all(&evidence_root)?;
        let evidence = tempfile::Builder::new()
            .prefix("run-")
            .tempdir_in(evidence_root)?
            .keep();
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        drop(listener);
        let journal = File::create(evidence.join("transcript.jsonl"))?;
        let stdout = File::create(evidence.join("stdout.log"))?;
        let stderr = File::create(evidence.join("stderr.log"))?;
        let (mut command, clock) = launch(binary, datadir.path(), addr)?;
        let child = command
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()?;
        let mut node = Self {
            child,
            _datadir: datadir,
            addr,
            binary,
            clock,
            evidence,
            journal,
            journal_bytes: 0,
            started: Instant::now(),
        };
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            if let Some(status) = node.child.try_wait()? {
                return Err(HarnessError::Deadline {
                    operation: "startup",
                    evidence: node.evidence.clone(),
                    detail: status.to_string(),
                });
            }
            match node.rpc_until("getblockchaininfo", &json!([]), deadline) {
                Ok(_) => return Ok(node),
                Err(error) if Instant::now() >= deadline => {
                    return Err(HarnessError::Deadline {
                        operation: "readiness",
                        evidence: node.evidence.clone(),
                        detail: error.to_string(),
                    });
                }
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }

    pub(crate) fn rpc(&mut self, method: &str, params: &Value) -> Result<Value, HarnessError> {
        self.rpc_until(method, params, Instant::now() + REQUEST_TIMEOUT)
    }

    fn rpc_until(
        &mut self,
        method: &str,
        params: &Value,
        deadline: Instant,
    ) -> Result<Value, HarnessError> {
        let request =
            json!({"jsonrpc": "1.0", "id": "process-harness", "method": method, "params": params});
        let response = exchange(self.addr, &request, deadline);
        let reply = match &response {
            Ok(reply) => reply.clone(),
            Err(error) => json!({"transport_error": error.to_string()}),
        };
        let at_micros = self.started.elapsed().as_micros();
        let encoded = serde_json::to_vec(
            &json!({"request": request, "reply": reply, "at_micros": at_micros}),
        )?;
        let next_size = self
            .journal_bytes
            .saturating_add(
                u64::try_from(encoded.len())
                    .map_err(|error| HarnessError::Protocol(error.to_string()))?,
            )
            .saturating_add(1);
        if next_size > MAX_TRANSCRIPT {
            return Err(HarnessError::Protocol(
                "transcript capacity exceeded".into(),
            ));
        }
        self.journal.write_all(&encoded)?;
        self.journal.write_all(b"\n")?;
        self.journal.flush()?;
        self.journal_bytes = next_size;
        let reply = response?;
        if let Some(error) = reply.get("error").filter(|error| !error.is_null()) {
            return Err(HarnessError::Protocol(format!(
                "{method}: {error}; transcript {}",
                self.evidence.display()
            )));
        }
        reply
            .get("result")
            .cloned()
            .ok_or_else(|| HarnessError::Protocol("missing RPC result".into()))
    }

    pub(crate) fn stop(mut self) -> Result<(), HarnessError> {
        let deadline = Instant::now() + STOP_TIMEOUT;
        if self.binary == NodeBinary::ReferenceCore {
            // Even a lost stop reply must converge on a reaped child.
            if let Err(error) = self.rpc_until("stop", &json!([]), deadline) {
                self.journal.write_all(format!("{error}\n").as_bytes())?;
            }
            while Instant::now() < deadline {
                if self.child.try_wait()?.is_some() {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
        }
        self.child.wait()?;
        Ok(())
    }
}

impl Drop for ProcessNode {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            // Wait still runs if kill races an already exiting child.
            let _kill_result = self.child.kill();
            let _wait_result = self.child.wait();
        }
    }
}

fn exchange(addr: SocketAddr, request: &Value, deadline: Instant) -> Result<Value, HarnessError> {
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| HarnessError::Protocol("RPC deadline reached".into()))
    };
    let mut stream = TcpStream::connect_timeout(&addr, remaining()?.min(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(remaining()?))?;
    let body = serde_json::to_vec(request)?;
    // Fixed test-only credentials avoid another authentication implementation.
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Basic cGFyaXR5OnBhcml0eQ==\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        stream.set_read_timeout(Some(remaining()?))?;
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        if bytes.len().saturating_add(count) > MAX_RESPONSE {
            return Err(HarnessError::Protocol("RPC response bound exceeded".into()));
        }
        bytes.extend_from_slice(
            chunk
                .get(..count)
                .ok_or_else(|| HarnessError::Protocol("invalid read size".into()))?,
        );
    }
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| HarnessError::Protocol("missing HTTP header terminator".into()))?;
    let payload = bytes
        .get(split.saturating_add(4)..)
        .ok_or_else(|| HarnessError::Protocol("missing HTTP body".into()))?;
    Ok(serde_json::from_slice(payload)?)
}

pub(crate) struct CommonFunds {
    pub(crate) common_block_bytes: Vec<Vec<u8>>,
    pub(crate) common_outpoints: Vec<OutPoint>,
}

pub(crate) fn mine_common_chain(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    blocks: u32,
) -> Result<CommonFunds, HarnessError> {
    if blocks == 0 || blocks > 102 {
        return Err(HarnessError::Protocol(
            "common funding bound is 1..=102 blocks".into(),
        ));
    }
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&[1_u8; 32])
        .map_err(|error| HarnessError::Protocol(error.to_string()))?;
    let private = PrivateKey::new(secret, Network::Regtest);
    let public = private.public_key(&bitcoin::secp256k1::Secp256k1::new());
    let address = Address::p2pkh(public, Network::Regtest);
    // Startup anchors the tip at genesis but applies the block only on the
    // first one-second sync tick (BlockSync::tick calls ensure_genesis_tip),
    // so no synchronous genesis apply exists to rely on here. A submit that
    // races the tick supplies the apply; one after it returns a duplicate
    // result string. Both orders converge on one applied genesis.
    let genesis = bitcoin::constants::genesis_block(Network::Regtest);
    node.rpc("submitblock", &json!([serialize_hex(&genesis)]))?;
    let hashes = core.rpc("generatetoaddress", &json!([blocks, address.to_string()]))?;
    let hashes = hashes
        .as_array()
        .ok_or_else(|| HarnessError::Protocol("mining result is not an array".into()))?;
    if hashes.len()
        != usize::try_from(blocks).map_err(|error| HarnessError::Protocol(error.to_string()))?
    {
        return Err(HarnessError::Protocol(
            "mining returned the wrong block count".into(),
        ));
    }
    let mut funds = CommonFunds {
        common_block_bytes: Vec::new(),
        common_outpoints: Vec::new(),
    };
    for hash in hashes {
        let hex = core.rpc("getblock", &json!([hash, 0]))?;
        let hex = hex
            .as_str()
            .ok_or_else(|| HarnessError::Protocol("getblock did not return hex".into()))?;
        let block: Block =
            deserialize_hex(hex).map_err(|error| HarnessError::Protocol(error.to_string()))?;
        if Value::String(block.block_hash().to_string()) != *hash {
            return Err(HarnessError::Protocol(
                "block hash differs from mining result".into(),
            ));
        }
        let accepted = node.rpc("submitblock", &json!([hex]))?;
        if !accepted.is_null() {
            return Err(HarnessError::Protocol(format!(
                "submitblock rejected: {accepted}"
            )));
        }
        let coinbase = block
            .txdata
            .first()
            .ok_or_else(|| HarnessError::Protocol("block has no coinbase".into()))?;
        funds
            .common_outpoints
            .push(OutPoint::new(coinbase.compute_txid(), 0));
        funds
            .common_block_bytes
            .push(bitcoin::consensus::serialize(&block));
    }
    Ok(funds)
}
