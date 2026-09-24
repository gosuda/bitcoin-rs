//! Process custody for `bitcoin-rs` and pinned Bitcoin Core nodes.

use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{Read, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::hashes::{Hash as _, sha256};
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::error::{Error, Result};
use crate::rpc::Connection;

/// Cold storage initialization needs more time than a single loopback request.
pub const START_TIMEOUT: Duration = Duration::from_mins(1);
/// Graceful shutdown budget before the harness reaps the child.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
/// Single request deadline.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Bound on retained child output.
const MAX_OUTPUT: u64 = 4 * 1024 * 1024;
/// Fixed test credentials; both node kinds share them.
const AUTH_USER: &str = "parity";
const AUTH_PASSWORD: &str = "parity";

/// Mock clock for Core regtest nodes.
///
/// Runs ~24h behind the host clock so generated blocks are valid under
/// the node's unmocked wall time; a pinned epoch would future-date
/// blocks on any host clocked earlier than it.
pub fn mock_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1_700_000_000, |d| d.as_secs().saturating_sub(86_400))
}
/// Spawn retries for when a reserved port is stolen before the child binds.
const MAX_SPAWN_ATTEMPTS: u32 = 3;

/// Which binary a [`ProcessNode`] wraps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// The `bitcoin-rs` daemon under test.
    BitcoinRs,
    /// The pinned Bitcoin Core reference node.
    Core,
}

/// The clock a spawned node's blocks are stamped with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockControl {
    /// Core runs under `-mocktime` pinned to this epoch second.
    Mock(u64),
    /// The daemon clocks blocks from the host wall clock; its CLI exposes
    /// no mock-time input.
    None,
}

/// Options applied on top of the default launch profile.
#[derive(Clone, Debug, Default)]
pub struct SpawnOptions<'a> {
    /// Extra command-line arguments appended after the harness defaults.
    pub extra_args: &'a [&'a str],
    /// Extra TOML lines appended to `node.toml` (bitcoin-rs only).
    pub toml_extra: &'a str,
    /// Full replacement for `node.toml` contents (bitcoin-rs only).
    /// When set, the default regtest profile is not written.
    pub toml_override: Option<&'a str>,
    /// Readiness deadline; defaults to [`START_TIMEOUT`].
    pub timeout: Option<Duration>,
    /// Replacement `--rpc-bind` address (bitcoin-rs only); overrides the
    /// reserved loopback port so bind-failure scenarios exercise a real
    /// `bind()` error rather than a duplicate CLI flag.
    pub rpc_bind: Option<SocketAddr>,
}

/// A decoded HTTP response from the node's RPC/REST/Esplora listener.
#[derive(Debug)]
pub struct HttpResponse {
    /// Numeric status code.
    pub status: u16,
    /// Response headers (lower-cased names).
    pub headers: Vec<(String, String)>,
    /// Raw body bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Parse the body as JSON.
    pub fn json(&self) -> Result<Value> {
        serde_json::from_slice(&self.body).map_err(Error::Json)
    }

    /// Interpret the body as UTF-8 text.
    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone())
            .map_err(|e| Error::Assertion(format!("response is not utf-8: {e}")))
    }

    /// Look up a header value by name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A spawned node process with its RPC endpoint and evidence files.
#[derive(Debug)]
pub struct ProcessNode {
    kind: Kind,
    child: Child,
    datadir: Option<TempDir>,
    /// RPC/HTTP loopback address the child is bound to.
    pub rpc_addr: SocketAddr,
    /// P2P loopback address the child is bound to.
    pub p2p_addr: SocketAddr,
    /// The clock this node's blocks are stamped with.
    pub clock: ClockControl,
    /// Directory that receives launch.json, stdout.log, stderr.log, transcript.
    pub evidence: PathBuf,
    journal: File,
    started: Instant,
    output: Vec<JoinHandle<()>>,
    conn: Connection,
}

/// Workspace root, derived from this crate's manifest location.
#[must_use]
pub fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Resolve the `bitcoin-rs` binary under test.
///
/// `BITCOIN_RS_NODE` wins when set. Otherwise the candidates are the `debug`
/// and `release` profiles under `CARGO_TARGET_DIR` (falling back to the
/// workspace `target/` when it is unset or relative to elsewhere), and the
/// *newest* existing artifact is chosen — a fixed debug-first order would
/// silently test a stale daemon while a freshly built one sits next to it.
/// The suite has no Cargo dependency edge to the binary package, so callers
/// must build it themselves (`cargo build --bin bitcoin-rs`).
pub fn bitcoin_rs_binary() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("BITCOIN_RS_NODE") {
        return Ok(PathBuf::from(path));
    }
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map_or_else(
            || workspace().join("target"),
            |dir| {
                if dir.is_absolute() {
                    dir
                } else {
                    workspace().join(dir)
                }
            },
        );
    let newest = ["debug", "release"]
        .iter()
        .map(|profile| target_dir.join(profile).join("bitcoin-rs"))
        .filter(|path| path.is_file())
        .max_by_key(|path| {
            path.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        });
    newest.ok_or_else(|| {
        Error::Assertion(
            "bitcoin-rs binary not found; run `cargo build --bin bitcoin-rs` first".into(),
        )
    })
}

/// The pinned bitcoind is hashed once per process; later Core spawns
/// reuse the verified path instead of re-reading hundreds of megabytes.
static VERIFIED_CORE: OnceLock<PathBuf> = OnceLock::new();

fn core_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("BITCOIN_RS_REFERENCE_BITCOIND") {
        return PathBuf::from(path);
    }
    if let Some(home) = std::env::var_os("HOME") {
        let path = Path::new(&home).join("bitcoin-core-31.1/bin/bitcoind");
        if path.is_file() {
            return path;
        }
    }
    workspace().join("target/reference-core-31.1/bitcoin-31.1/bin/bitcoind")
}

/// Verify the resolved bitcoind matches the pinned digest in the compiled
/// `core-compat.toml` manifest. Returns the binary path on success.
pub fn verified_core_binary() -> Result<PathBuf> {
    if let Some(path) = VERIFIED_CORE.get() {
        return Ok(path.clone());
    }
    let path = core_binary();
    let table: toml::Table = bitcoin_rs_rpc::manifest::MANIFEST_TOML
        .parse()
        .map_err(|e| Error::Assertion(format!("cannot parse core-compat.toml: {e}")))?;
    let expected = table
        .get("reference")
        .and_then(|r| r.get("release"))
        .and_then(|r| r.get("bitcoind_sha256"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Assertion("bitcoind_sha256 missing in core-compat.toml".into()))?
        .to_owned();
    let mut file = File::open(&path).map_err(|e| {
        Error::Assertion(format!(
            "pinned bitcoind {} not readable (install via scripts/install-bitcoind.sh): {e}",
            path.display()
        ))
    })?;
    let mut engine = sha256::Hash::engine();
    std::io::copy(&mut file, &mut engine)?;
    let actual = sha256::Hash::from_engine(engine).to_string();
    if actual != expected {
        return Err(Error::Assertion(format!(
            "bitcoind sha256 mismatch: expected {expected}, got {actual}"
        )));
    }
    let _ = VERIFIED_CORE.set(path.clone());
    Ok(path)
}

/// Reserve two loopback ports; callers drop the listeners right before spawn.
fn loopback_addresses() -> Result<(SocketAddr, SocketAddr, TcpListener, TcpListener)> {
    let rpc = TcpListener::bind("127.0.0.1:0")?;
    let p2p = TcpListener::bind("127.0.0.1:0")?;
    Ok((rpc.local_addr()?, p2p.local_addr()?, rpc, p2p))
}

fn launch_command(
    kind: Kind,
    datadir: &Path,
    rpc_addr: SocketAddr,
    p2p_addr: SocketAddr,
    options: &SpawnOptions<'_>,
) -> Result<(Command, ClockControl)> {
    let mut command = match kind {
        Kind::BitcoinRs => Command::new(bitcoin_rs_binary()?),
        Kind::Core => Command::new(verified_core_binary()?),
    };
    // Host configuration must not leak into the isolated regtest profile.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("BITCOIN_RS_") {
            command.env_remove(key);
        }
    }
    let clock = match kind {
        Kind::Core => {
            let mock = mock_time();
            command
                .args([
                    "-regtest",
                    "-server",
                    "-listen=1",
                    "-listenonion=0",
                    "-connect=0",
                    "-dnsseed=0",
                    "-disablewallet",
                    "-rpcuser=parity",
                    "-rpcpassword=parity",
                ])
                .arg(format!("-datadir={}", datadir.display()))
                .arg(format!("-bind={p2p_addr}"))
                .arg(format!("-rpcport={}", rpc_addr.port()))
                .arg(format!("-mocktime={mock}"));
            ClockControl::Mock(mock)
        }
        Kind::BitcoinRs => {
            let config_path = datadir.join("node.toml");
            let base = options.toml_override.map_or_else(
                || {
                    format!(
                        "network = \"regtest\"\np2p_listen = [\"{p2p_addr}\"]\ndns_seeds_enabled = false\n"
                    )
                },
                |text| format!("{text}\n"),
            );
            fs::write(&config_path, format!("{base}{}", options.toml_extra))?;
            command
                .arg("--config")
                .arg(config_path)
                .args([
                    "--storage-backend",
                    "fjall",
                    "--rpc-user",
                    AUTH_USER,
                    "--rpc-password",
                    AUTH_PASSWORD,
                    "--dbcache-mb",
                    "64",
                ])
                .arg("--data-dir")
                .arg(datadir.join("node"))
                .arg("--rpc-bind")
                .arg(rpc_addr.to_string());
            ClockControl::None
        }
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    Ok((command, clock))
}

impl ProcessNode {
    /// Spawn a node with the default launch profile.
    pub fn spawn(kind: Kind) -> Result<Self> {
        Self::spawn_with(kind, &SpawnOptions::default())
    }

    /// Spawn a node with extra arguments / config lines.
    pub fn spawn_with(kind: Kind, options: &SpawnOptions<'_>) -> Result<Self> {
        let datadir = tempfile::tempdir()?;
        Self::spawn_in_datadir(kind, options, datadir)
    }

    /// Spawn over an existing datadir (restart scenarios).
    ///
    /// A reserved port can still be stolen between `loopback_addresses`
    /// dropping its listeners and the child binding, so an immediate child
    /// exit is retried with fresh ports a bounded number of times.
    pub fn spawn_in_datadir(
        kind: Kind,
        options: &SpawnOptions<'_>,
        datadir: TempDir,
    ) -> Result<Self> {
        let mut last_error = None;
        for attempt in 0..MAX_SPAWN_ATTEMPTS {
            match Self::spawn_in_datadir_once(kind, options, &datadir) {
                Ok(mut node) => {
                    node.datadir = Some(datadir);
                    return Ok(node);
                }
                Err(error @ Error::ChildExit { .. }) if attempt + 1 < MAX_SPAWN_ATTEMPTS => {
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(|| Error::Assertion("spawn attempts exhausted".into())))
    }

    /// One spawn attempt over `datadir`.
    fn spawn_in_datadir_once(
        kind: Kind,
        options: &SpawnOptions<'_>,
        datadir: &TempDir,
    ) -> Result<Self> {
        let evidence_root = workspace().join("target/process-harness/e2e");
        fs::create_dir_all(&evidence_root)?;
        let evidence = tempfile::Builder::new()
            .prefix("run-")
            .tempdir_in(evidence_root)?
            .keep();
        let (rpc_addr, p2p_addr, rpc_listener, p2p_listener) = loopback_addresses()?;
        let rpc_addr = options.rpc_bind.unwrap_or(rpc_addr);
        let journal = File::create(evidence.join("transcript.jsonl"))?;
        let (mut command, clock) = launch_command(kind, datadir.path(), rpc_addr, p2p_addr, options)?;
        command.args(options.extra_args);
        fs::write(
            evidence.join("launch.json"),
            serde_json::to_vec_pretty(&json!({
                "kind": format!("{kind:?}"),
                "program": command.get_program(),
                "argv": command.get_args().map(|a| a.to_string_lossy()).collect::<Vec<_>>(),
                "datadir": datadir.path(),
                "rpc_address": rpc_addr.to_string(),
                "p2p_address": p2p_addr.to_string(),
            }))?,
        )?;
        drop((rpc_listener, p2p_listener));
        let child = command.spawn()?;
        let mut node = Self {
            kind,
            child,
            datadir: None,
            rpc_addr,
            p2p_addr,
            clock,
            evidence,
            journal,
            started: Instant::now(),
            output: Vec::new(),
            conn: Connection::new(rpc_addr),
        };
        let stdout = node
            .child
            .stdout
            .take()
            .ok_or_else(|| Error::Assertion("piped stdout missing".into()))?;
        let stderr = node
            .child
            .stderr
            .take()
            .ok_or_else(|| Error::Assertion("piped stderr missing".into()))?;
        node.output
            .push(capture_output(stdout, node.evidence.join("stdout.log")));
        node.output
            .push(capture_output(stderr, node.evidence.join("stderr.log")));
        node.wait_ready(options.timeout.unwrap_or(START_TIMEOUT))?;
        Ok(node)
    }

    /// Child process id.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Which binary this process wraps.
    #[must_use]
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Move datadir custody out for a restart.
    pub fn take_datadir(&mut self) -> Result<TempDir> {
        self.datadir
            .take()
            .ok_or_else(|| Error::Assertion("datadir custody already moved".into()))
    }

    fn wait_ready(&mut self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Err(Error::ChildExit {
                    pid: self.pid(),
                    status,
                    evidence: self.evidence.clone(),
                });
            }
            match self.rpc_until("getblockchaininfo", &json!([]), deadline) {
                Ok(_) => return Ok(()),
                Err(error) if Instant::now() >= deadline => {
                    return Err(Error::Timeout {
                        pid: self.pid(),
                        operation: "readiness",
                        evidence: self.evidence.clone(),
                        detail: error.to_string(),
                    });
                }
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }

    /// JSON-RPC call; the reply's `result` is returned, an `error` becomes
    /// [`Error::Rpc`].
    pub fn rpc(&mut self, method: &str, params: &Value) -> Result<Value> {
        self.rpc_until(method, params, Instant::now() + REQUEST_TIMEOUT)
    }

    /// JSON-RPC call bounded by `deadline`: the transport obeys the same
    /// deadline as the polling loop, so a startup wait cannot be renewed
    /// by a per-request budget.
    pub fn rpc_until(
        &mut self,
        method: &str,
        params: &Value,
        deadline: Instant,
    ) -> Result<Value> {
        let request = json!({"jsonrpc": "1.0", "id": "e2e", "method": method, "params": params});
        self.record(&request)?;
        let response = self.conn.rpc(&request, (AUTH_USER, AUTH_PASSWORD), deadline);
        self.record(&match &response {
            Ok(value) => value.clone(),
            Err(error) => json!({"transport_error": error.to_string()}),
        })?;
        let reply = response?;
        if let Some(error) = reply.get("error").filter(|error| !error.is_null()) {
            return Err(Error::Rpc {
                method: method.to_owned(),
                code: error.get("code").and_then(Value::as_i64).ok_or_else(|| {
                    Error::Protocol("RPC error lacks a numeric code".into())
                })?,
                message: error
                    .get("message")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::Protocol("RPC error lacks a message".into()))?
                    .to_owned(),
            });
        }
        reply
            .get("result")
            .cloned()
            .ok_or_else(|| Error::Protocol("missing RPC result".into()))
    }

    /// Low-level JSON-RPC call returning the full parsed envelope (or the
    /// parsed error reply); never converts a structured error into
    /// [`Error::Rpc`].
    pub fn rpc_raw(&mut self, request: &Value) -> Result<Value> {
        let response = self.http("POST", "/", serde_json::to_vec(request)?.as_slice(), true)?;
        response.json()
    }

    /// HTTP request against the node's listener; `auth` toggles the
    /// parity:parity Basic header.
    pub fn http(
        &mut self,
        method: &str,
        path: &str,
        body: &[u8],
        auth: bool,
    ) -> Result<HttpResponse> {
        self.http_auth(
            method,
            path,
            body,
            if auth {
                Some((AUTH_USER, AUTH_PASSWORD))
            } else {
                None
            },
        )
    }

    /// HTTP request with explicit Basic-auth credentials (or none),
    /// journaled like [`ProcessNode::http`]. Lets negative-auth tests send
    /// credentials other than the harness pair.
    pub fn http_auth(
        &mut self,
        method: &str,
        path: &str,
        body: &[u8],
        auth: Option<(&str, &str)>,
    ) -> Result<HttpResponse> {
        self.record(&json!({
            "http_request": {
                "method": method,
                "path": path,
                "body_bytes": body.len(),
                "auth_user": auth.map(|(user, _)| user),
            }
        }))?;
        let response =
            self.conn.http(method, path, body, auth, Instant::now() + REQUEST_TIMEOUT)?;
        self.record(&json!({
            "http_response": {
                "status": response.status,
                "body_bytes": response.body.len(),
                "body_head": String::from_utf8_lossy(
                    &response.body[..response.body.len().min(512)]
                )
                .into_owned(),
            }
        }))?;
        Ok(response)
    }

    /// GET helper for REST/Esplora surfaces.
    pub fn http_get(&mut self, path: &str) -> Result<HttpResponse> {
        self.http("GET", path, &[], false)
    }

    /// GET one `/api/` explorer path and return its parsed JSON body.
    ///
    /// PRE: `path` names a resource under the `/api/` namespace.
    /// POST: the reply carried status 200 and a JSON body.
    pub fn http_get_json(&mut self, path: &str) -> Result<Value> {
        if !path.starts_with("/api/") || path.bytes().any(|byte| byte <= b' ' || byte == 127) {
            return Err(Error::Protocol("invalid explorer HTTP path".into()));
        }
        let response = self.http_get(path)?;
        if response.status != 200 {
            return Err(Error::Protocol(
                "explorer HTTP response was not 200".into(),
            ));
        }
        response.json()
    }

    /// Common monotonic clock for RPC and P2P evidence.
    #[must_use]
    pub const fn evidence_clock(&self) -> Instant {
        self.started
    }

    fn record(&mut self, entry: &Value) -> Result<()> {
        let line = serde_json::to_vec(&json!({
            "at_micros": self.started.elapsed().as_micros(),
            "entry": entry,
        }))?;
        self.journal.write_all(&line)?;
        self.journal.write_all(b"\n")?;
        self.journal.flush()?;
        Ok(())
    }

    /// Poll `condition` until it returns `Some` or the deadline passes.
    pub fn wait_for<T>(
        &mut self,
        operation: &'static str,
        timeout: Duration,
        mut condition: impl FnMut(&mut Self) -> Result<Option<T>>,
    ) -> Result<T> {
        let deadline = Instant::now() + timeout;
        let mut detail = String::new();
        loop {
            match condition(self) {
                Ok(Some(value)) => return Ok(value),
                Ok(None) => {}
                Err(error) => detail = error.to_string(),
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout {
                    pid: self.pid(),
                    operation,
                    evidence: self.evidence.clone(),
                    detail,
                });
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Wait until `getblockcount` reports at least `height`.
    pub fn wait_block_count(&mut self, height: u64, timeout: Duration) -> Result<u64> {
        self.wait_for("block count", timeout, move |node| {
            let count = node
                .rpc("getblockcount", &json!([]))?
                .as_u64()
                .ok_or_else(|| Error::Assertion("getblockcount is not a number".into()))?;
            Ok((count >= height).then_some(count))
        })
    }

    /// Graceful stop: `stop` RPC for Core, SIGTERM for bitcoin-rs.
    pub fn stop(mut self) -> Result<()> {
        self.stop_process()?;
        self.finish_output();
        Ok(())
    }

    /// Graceful stop that keeps the datadir alive for a restart: the node
    /// exits first (no shared storage), then custody of the `TempDir` moves
    /// to the caller.
    pub fn stop_keep_datadir(mut self) -> Result<TempDir> {
        self.stop_process()?;
        self.finish_output();
        self.take_datadir()
    }

    fn stop_process(&mut self) -> Result<()> {
        match self.kind {
            Kind::Core => {
                if let Err(error) = self.rpc("stop", &json!([])) {
                    eprintln!("core stop rpc: {error}");
                }
            }
            Kind::BitcoinRs => self.send_sigterm(),
        }
        let deadline = Instant::now() + STOP_TIMEOUT;
        while Instant::now() < deadline {
            if self.child.try_wait()?.is_some() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        self.child.kill()?;
        self.child.wait()?;
        Ok(())
    }

    /// Ask the process for its current exit status.
    pub fn exited(&mut self) -> Result<Option<std::process::ExitStatus>> {
        self.child.try_wait().map_err(Error::Io)
    }

    /// Send SIGTERM to the child.
    pub fn send_sigterm(&self) {
        let pid = self.pid().to_string();
        let _ = Command::new("kill").args(["-TERM", pid.as_str()]).status();
    }

    /// Send SIGKILL to the child.
    pub fn send_sigkill(&self) {
        let pid = self.pid().to_string();
        let _ = Command::new("kill").args(["-KILL", pid.as_str()]).status();
    }

    fn finish_output(&mut self) {
        for reader in self.output.drain(..) {
            let _ = reader.join();
        }
    }
}

impl Drop for ProcessNode {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.finish_output();
    }
}

/// Retains the newest `MAX_OUTPUT` bytes of a child's stream — the tail is
/// where a late crash or error loop actually shows up; the head is least
/// diagnostic. The tail is materialized to `file` at EOF.
fn capture_output(mut reader: impl Read + Send + 'static, file: PathBuf) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let Ok(mut file) = File::create(&file) else {
            return;
        };
        let mut tail: VecDeque<u8> = VecDeque::new();
        let limit = usize::try_from(MAX_OUTPUT).unwrap_or(usize::MAX);
        let mut buffer = [0_u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    tail.extend(buffer[..count].iter().copied());
                    let excess = tail.len().saturating_sub(limit);
                    if excess > 0 {
                        tail.drain(..excess);
                    }
                }
            }
        }
        let _ = file.write_all(tail.make_contiguous());
        let _ = file.flush();
    })
}
