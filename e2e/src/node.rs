//! Process custody for `bitcoin-rs` and pinned Bitcoin Core nodes.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::hashes::{Hash as _, sha256};
use sonic_rs::{JsonValueTrait as _, Value, json};
use tempfile::TempDir;

use crate::error::{Error, Result};
use crate::rpc::Connection;

pub const START_TIMEOUT: Duration = Duration::from_mins(1);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_OUTPUT: u64 = 4 * 1024 * 1024;
const MAX_TRANSCRIPT: u64 = 64 * 1024 * 1024;
const AUTH_USER: &str = "parity";
const AUTH_PASSWORD: &str = "parity";

pub fn mock_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1_700_000_000, |d| d.as_secs().saturating_sub(86_400))
}
const MAX_SPAWN_ATTEMPTS: u32 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    BitcoinRs,
    Core,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockControl {
    Mock(u64),
    None,
}

#[derive(Clone, Debug, Default)]
pub struct SpawnOptions<'a> {
    pub extra_args: &'a [&'a str],
    pub toml_extra: &'a str,
    pub toml_override: Option<&'a str>,
    pub timeout: Option<Duration>,
    pub rpc_bind: Option<SocketAddr>,
    pub binary: Option<&'a Path>,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json(&self) -> Result<Value> {
        sonic_rs::from_slice(&self.body).map_err(Error::Json)
    }

    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone())
            .map_err(|e| Error::Assertion(format!("response is not utf-8: {e}")))
    }
}

#[derive(Debug)]
pub struct ProcessNode {
    kind: Kind,
    child: Child,
    datadir: Option<TempDir>,
    pub rpc_addr: SocketAddr,
    pub p2p_addr: SocketAddr,
    pub clock: ClockControl,
    pub evidence: PathBuf,
    journal: File,
    journal_bytes: u64,
    started: Instant,
    output: Vec<JoinHandle<()>>,
    conn: Connection,
}

#[must_use]
pub fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

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
    let binary_name = format!("bitcoin-rs{}", std::env::consts::EXE_SUFFIX);
    let newest = ["debug", "release"]
        .iter()
        .map(|profile| target_dir.join(profile).join(&binary_name))
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

static VERIFIED_CORE: OnceLock<PathBuf> = OnceLock::new();

fn core_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("BITCOIN_RS_REFERENCE_BITCOIND") {
        return PathBuf::from(path);
    }
    let binary_name = format!("bitcoind{}", std::env::consts::EXE_SUFFIX);
    for home in [std::env::var_os("HOME"), std::env::var_os("USERPROFILE")]
        .into_iter()
        .flatten()
    {
        let path = Path::new(&home)
            .join("bitcoin-core-31.1/bin")
            .join(&binary_name);
        if path.is_file() {
            return path;
        }
    }
    workspace()
        .join("target/reference-core-31.1/bitcoin-31.1/bin")
        .join(&binary_name)
}

fn verified_core_binary() -> Result<PathBuf> {
    if let Some(path) = VERIFIED_CORE.get() {
        return Ok(path.clone());
    }
    let path = core_binary();
    let expected = manifest_reference_sha256()?;
    let actual = file_sha256(&path).map_err(|e| {
        Error::Assertion(format!(
            "pinned bitcoind {} not readable (install via scripts/install-bitcoind.sh, or install-bitcoind.ps1 on Windows): {e}",
            path.display()
        ))
    })?;
    if actual != expected {
        return Err(Error::Assertion(format!(
            "bitcoind sha256 mismatch: expected {expected}, got {actual}"
        )));
    }
    let _ = VERIFIED_CORE.set(path.clone());
    Ok(path)
}

pub(crate) fn manifest_reference_sha256() -> Result<String> {
    let target = crate::reference_set::current_platform_target().ok_or_else(|| {
        Error::Assertion(format!(
            "no pinned Core artifact for {}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ))
    })?;
    let table: toml::Table = bitcoin_rs_rpc::manifest::MANIFEST_TOML
        .parse()
        .map_err(|e| Error::Assertion(format!("cannot parse core-compat.toml: {e}")))?;
    let release = table
        .get("reference")
        .and_then(|r| r.get("release"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| Error::Assertion("reference.release missing in core-compat.toml".into()))?;
    let artifact = |row: &toml::Table| {
        row.get("bitcoind_sha256")
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Error::Assertion("bitcoind_sha256 missing in core-compat.toml".into()))
    };
    if release.get("target").and_then(toml::Value::as_str) == Some(target) {
        return artifact(release);
    }
    if let Some(rows) = release.get("platforms").and_then(toml::Value::as_array) {
        for row in rows.iter().filter_map(toml::Value::as_table) {
            if row.get("target").and_then(toml::Value::as_str) == Some(target) {
                return artifact(row);
            }
        }
    }
    Err(Error::Assertion(format!(
        "no pinned Core artifact for target {target} in core-compat.toml"
    )))
}

pub(crate) fn file_sha256(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut engine = sha256::Hash::engine();
    std::io::copy(&mut file, &mut engine)?;
    Ok(sha256::Hash::from_engine(engine).to_string())
}

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
    let mut command = match (kind, options.binary) {
        (Kind::BitcoinRs, Some(binary)) => Command::new(binary),
        (Kind::BitcoinRs, None) => Command::new(bitcoin_rs_binary()?),
        (Kind::Core, _) => Command::new(verified_core_binary()?),
    };
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
                .arg(format!("-rpcbind={rpc_addr}"))
                .arg(format!("-rpcallowip={}", rpc_addr.ip()))
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
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP);
    }
    Ok((command, clock))
}

fn exited_on_busy_port(evidence: &Path) -> bool {
    let Ok(stderr) = fs::read_to_string(evidence.join("stderr.log")) else {
        return false;
    };
    stderr.contains("Address already in use")
        || stderr.contains("os error 98")
        || stderr.contains("Unable to bind")
        || stderr.contains("Failed to bind")
        || stderr.contains("Only one usage of each socket address")
        || stderr.contains("os error 10048")
        || stderr.contains("An attempt was made to access a socket")
        || stderr.contains("os error 10013")
        || (stderr.contains("Unable to start HTTP server")
            && fs::read_to_string(evidence.join("stdout.log")).is_ok_and(|stdout| {
                stdout
                    .lines()
                    .any(|line| line.contains("Binding RPC on address") && line.contains("failed"))
            }))
}

fn rpc_bind_evidence_ready(kind: Kind, rpc_addr: SocketAddr, evidence: &Path) -> bool {
    match kind {
        Kind::Core => {
            let attempt = format!(
                "Binding RPC on address {} port {}",
                rpc_addr.ip(),
                rpc_addr.port()
            );
            let Ok(stdout) = fs::read_to_string(evidence.join("stdout.log")) else {
                return false;
            };
            stdout.lines().any(|line| line.contains(&attempt))
                && stdout
                    .lines()
                    .any(|line| line.contains("Starting HTTP server"))
                && !stdout
                    .lines()
                    .any(|line| line.contains("Binding RPC on address") && line.contains("failed"))
        }
        Kind::BitcoinRs => {
            let Ok(stderr) = fs::read_to_string(evidence.join("stderr.log")) else {
                return false;
            };
            stderr.lines().any(|line| {
                line.contains("rpc listener bound") && line.contains(&rpc_addr.to_string())
            })
        }
    }
}

impl ProcessNode {
    pub fn spawn(kind: Kind) -> Result<Self> {
        Self::spawn_with(kind, &SpawnOptions::default())
    }

    pub fn spawn_with(kind: Kind, options: &SpawnOptions<'_>) -> Result<Self> {
        let datadir = tempfile::tempdir()?;
        Self::spawn_in_datadir(kind, options, datadir)
    }

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
                Err(error) => {
                    let port_race = matches!(
                        &error,
                        Error::ChildExit { evidence, .. } if exited_on_busy_port(evidence)
                    );
                    if attempt + 1 < MAX_SPAWN_ATTEMPTS && port_race {
                        last_error = Some(error);
                    } else {
                        return Err(error);
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| Error::Assertion("spawn attempts exhausted".into())))
    }

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
        let (mut command, clock) =
            launch_command(kind, datadir.path(), rpc_addr, p2p_addr, options)?;
        command.args(options.extra_args);
        let executable = Path::new(command.get_program());
        let digest = file_sha256(executable)?;
        let config = match kind {
            Kind::BitcoinRs => Some(fs::read_to_string(datadir.path().join("node.toml"))?),
            Kind::Core => None,
        };
        fs::write(
            evidence.join("launch.json"),
            sonic_rs::to_vec_pretty(&json!({
                "binary": format!("{kind:?}"),
                "executable": executable,
                "executable_sha256": digest,
                "argv": command.get_args().map(|a| a.to_string_lossy()).collect::<Vec<_>>(),
                "config": config,
                "datadir": datadir.path(),
                "rpc_address": rpc_addr.to_string(),
                "p2p_address": p2p_addr.to_string(),
                "clock": format!("{clock:?}"),
                "startup_timeout_ms": options.timeout.unwrap_or(START_TIMEOUT).as_millis(),
                "request_timeout_ms": REQUEST_TIMEOUT.as_millis(),
                "output_limit_bytes": MAX_OUTPUT,
                "transcript_limit_bytes": MAX_TRANSCRIPT,
                "ci_commit": std::env::var("GITHUB_SHA").ok(),
                "ci_run_id": std::env::var("GITHUB_RUN_ID").ok(),
                "ci_run_attempt": std::env::var("GITHUB_RUN_ATTEMPT").ok(),
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
            journal_bytes: 0,
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

    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

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
            match self.rpc_until(
                "getblockchaininfo",
                &json!([]),
                deadline.min(Instant::now() + REQUEST_TIMEOUT),
            ) {
                Ok(_) => {
                    if let Some(status) = self.child.try_wait()? {
                        return Err(Error::ChildExit {
                            pid: self.pid(),
                            status,
                            evidence: self.evidence.clone(),
                        });
                    }
                    if !rpc_bind_evidence_ready(self.kind, self.rpc_addr, &self.evidence) {
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    return Ok(());
                }
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

    pub fn rpc(&mut self, method: &str, params: &Value) -> Result<Value> {
        self.rpc_until(method, params, Instant::now() + REQUEST_TIMEOUT)
    }

    pub fn rpc_until(&mut self, method: &str, params: &Value, deadline: Instant) -> Result<Value> {
        let request = json!({"jsonrpc": "1.0", "id": "e2e", "method": method, "params": params});
        let response = self
            .conn
            .rpc(&request, (AUTH_USER, AUTH_PASSWORD), deadline);
        self.record(
            &request,
            &match &response {
                Ok(value) => value.clone(),
                Err(error) => json!({"transport_error": error.to_string()}),
            },
        )?;
        let reply = response?;
        if let Some(error) = reply.get("error").filter(|error| !error.is_null()) {
            return Err(Error::Rpc {
                method: method.to_owned(),
                code: error
                    .get("code")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| Error::Protocol("RPC error lacks a numeric code".into()))?,
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

    pub fn rpc_raw(&mut self, request: &Value) -> Result<Value> {
        let response = self.http("POST", "/", sonic_rs::to_vec(request)?.as_slice(), true)?;
        response.json()
    }

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

    pub fn http_auth(
        &mut self,
        method: &str,
        path: &str,
        body: &[u8],
        auth: Option<(&str, &str)>,
    ) -> Result<HttpResponse> {
        let request = json!({
            "http_request": {
                "method": method,
                "path": path,
                "body_bytes": body.len(),
                "auth_user": auth.map(|(user, _)| user),
            }
        });
        let response = self
            .conn
            .http(method, path, body, auth, Instant::now() + REQUEST_TIMEOUT);
        self.record(
            &request,
            &match &response {
                Ok(response) => json!({
                    "http_response": {
                        "status": response.status,
                        "body_bytes": response.body.len(),
                        "body_head": String::from_utf8_lossy(
                            &response.body[..response.body.len().min(512)]
                        )
                        .into_owned(),
                    }
                }),
                Err(error) => json!({"transport_error": error.to_string()}),
            },
        )?;
        response
    }

    pub fn http_get(&mut self, path: &str) -> Result<HttpResponse> {
        self.http("GET", path, &[], false)
    }

    pub fn http_get_json(&mut self, path: &str) -> Result<Value> {
        if !path.starts_with("/api/") || path.bytes().any(|byte| byte <= b' ' || byte == 127) {
            return Err(Error::Protocol("invalid explorer HTTP path".into()));
        }
        let response = self.http_get(path)?;
        if response.status != 200 {
            return Err(Error::Protocol("explorer HTTP response was not 200".into()));
        }
        response.json()
    }

    pub(crate) const fn evidence_clock(&self) -> Instant {
        self.started
    }

    fn record(&mut self, request: &Value, reply: &Value) -> Result<()> {
        let encoded = sonic_rs::to_vec(&json!({
            "request": request,
            "reply": reply,
            "at_micros": self.started.elapsed().as_micros(),
        }))?;
        let next_size = self
            .journal_bytes
            .saturating_add(
                u64::try_from(encoded.len()).map_err(|error| Error::Protocol(error.to_string()))?,
            )
            .saturating_add(1);
        if next_size > MAX_TRANSCRIPT {
            return Err(Error::Protocol("transcript capacity exceeded".into()));
        }
        self.journal.write_all(&encoded)?;
        self.journal.write_all(b"\n")?;
        self.journal.flush()?;
        self.journal_bytes = next_size;
        Ok(())
    }

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

    pub fn wait_block_count(&mut self, height: u64, timeout: Duration) -> Result<u64> {
        self.wait_for("block count", timeout, move |node| {
            let count = node
                .rpc("getblockcount", &json!([]))?
                .as_u64()
                .ok_or_else(|| Error::Assertion("getblockcount is not a number".into()))?;
            Ok((count >= height).then_some(count))
        })
    }

    pub fn stop(mut self) -> Result<()> {
        self.stop_process()?;
        self.finish_output();
        Ok(())
    }

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

    #[cfg(unix)]
    fn send_sigterm(&self) {
        let pid = self.pid().to_string();
        let _ = Command::new("kill").args(["-TERM", pid.as_str()]).status();
    }

    #[cfg(windows)]
    fn send_sigterm(&mut self) {
        use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};
        // SAFETY: GenerateConsoleCtrlEvent is safe to call for any process
        let delivered = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, self.pid()) };
        if delivered == 0 {
            eprintln!(
                "CTRL_BREAK delivery failed for pid {} ({}); forcing terminate",
                self.pid(),
                std::io::Error::last_os_error()
            );
            self.send_sigkill();
        }
    }

    #[cfg(unix)]
    pub fn send_sigkill(&self) {
        let pid = self.pid().to_string();
        let _ = Command::new("kill").args(["-KILL", pid.as_str()]).status();
    }

    #[cfg(windows)]
    pub fn send_sigkill(&mut self) {
        let _ = self.child.kill();
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

fn capture_output(mut reader: impl Read + Send + 'static, file: PathBuf) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let path = file;
        let Ok(mut file) = File::create(&path) else {
            return;
        };
        let mut tail: VecDeque<u8> = VecDeque::new();
        let limit = usize::try_from(MAX_OUTPUT).unwrap_or(usize::MAX);
        let mut stale = 0_usize;
        let mut buffer = [0_u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    tail.extend(buffer[..count].iter().copied());
                    let _ = file.write_all(&buffer[..count]);
                    let excess = tail.len().saturating_sub(limit);
                    if excess > 0 {
                        tail.drain(..excess);
                        stale += excess;
                    }
                    if stale >= limit && publish_tail(&path, tail.make_contiguous()).is_ok() {
                        if let Ok(fresh) = OpenOptions::new().append(true).open(&path) {
                            file = fresh;
                        }
                        stale = 0;
                    }
                    let _ = file.flush();
                }
            }
        }
        if stale > 0 {
            let _ = publish_tail(&path, tail.make_contiguous());
        }
        let _ = file.flush();
    })
}

fn publish_tail(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let side = path.with_extension("tmp");
    {
        let mut tmp = File::create(&side)?;
        tmp.write_all(bytes)?;
        tmp.flush()?;
    }
    fs::rename(&side, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid_flag_runs() -> usize {
        let root = workspace().join("target/process-harness/e2e");
        let Ok(entries) = fs::read_dir(&root) else {
            return 0;
        };
        entries
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("run-"))
            .filter(|entry| {
                fs::read_to_string(entry.path().join("launch.json"))
                    .is_ok_and(|text| text.contains("--process-harness-invalid-option-retry-audit"))
            })
            .count()
    }

    #[test]
    fn spawn_retry_does_not_fire_on_a_non_port_bind_startup_failure() -> Result<()> {
        let datadir = tempfile::tempdir()?;
        let before = invalid_flag_runs();
        let error = ProcessNode::spawn_in_datadir(
            Kind::BitcoinRs,
            &SpawnOptions {
                extra_args: &["--process-harness-invalid-option-retry-audit"],
                ..Default::default()
            },
            datadir,
        )
        .err()
        .ok_or_else(|| {
            Error::Assertion("an unknown startup flag must not produce a ready node".into())
        })?;
        assert!(
            matches!(error, Error::ChildExit { .. }),
            "startup must report child exit: {error}"
        );
        assert_eq!(
            invalid_flag_runs() - before,
            1,
            "a non-bind startup failure must consume exactly one spawn attempt"
        );
        Ok(())
    }

    #[test]
    fn busy_port_detector_matches_only_the_core_rpc_steal_pair() -> Result<()> {
        fn evidence_with(stdout: &str, stderr: &str) -> Result<(tempfile::TempDir, PathBuf)> {
            let dir = tempfile::tempdir()?;
            fs::write(dir.path().join("stdout.log"), stdout)?;
            fs::write(dir.path().join("stderr.log"), stderr)?;
            let path = dir.path().to_path_buf();
            Ok((dir, path))
        }

        let (_keep, fatal) = evidence_with(
            "2026-10-26T01:19:20Z [warning] Binding RPC on address 127.0.0.1 port 36079 failed.\n",
            "Error: Unable to start HTTP server. See debug log for details.\n",
        )?;
        assert!(exited_on_busy_port(&fatal));

        let (_keep, lookup) = evidence_with(
            "2026-10-26T01:19:20Z Binding RPC on address 127.0.0.1 port 36079\n2026-10-26T01:19:20Z Could not bind RPC on address 127.0.0.1 port 36079: Address lookup failed.\n",
            "Error: Unable to start HTTP server. See debug log for details.\n",
        )?;
        assert!(
            !exited_on_busy_port(&lookup),
            "a lookup failure is not the port race"
        );

        let (_keep, other) = evidence_with(
            "error: unexpected argument '--bogus'\n",
            "error: unexpected argument '--bogus'\n",
        )?;
        assert!(
            !exited_on_busy_port(&other),
            "an unrelated startup failure must surface untouched"
        );
        Ok(())
    }

    #[test]
    fn readiness_requires_the_child_own_bind_evidence() -> Result<()> {
        fn evidence_with(stdout: &str, stderr: &str) -> Result<(tempfile::TempDir, PathBuf)> {
            let dir = tempfile::tempdir()?;
            fs::write(dir.path().join("stdout.log"), stdout)?;
            fs::write(dir.path().join("stderr.log"), stderr)?;
            let path = dir.path().to_path_buf();
            Ok((dir, path))
        }

        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 36079));
        let (_keep, core_bound) = evidence_with(
            "2026-10-26T01:19:20Z Binding RPC on address 127.0.0.1 port 36079\n2026-10-26T01:19:20Z Starting HTTP server with 16 worker threads\n",
            "",
        )?;
        assert!(rpc_bind_evidence_ready(Kind::Core, addr, &core_bound));

        let (_keep, core_attempt_only) = evidence_with(
            "2026-10-26T01:19:20Z Binding RPC on address 127.0.0.1 port 36079\n",
            "",
        )?;
        assert!(
            !rpc_bind_evidence_ready(Kind::Core, addr, &core_attempt_only),
            "an attempt without the started record must not adopt: the child may die next"
        );

        let (_keep, core_pending) =
            evidence_with("2026-10-26T01:19:20Z Bound to 127.0.0.1:37681\n", "")?;
        assert!(
            !rpc_bind_evidence_ready(Kind::Core, addr, &core_pending),
            "a pre-bind probe must keep polling, never adopt"
        );

        let (_keep, core_lost) = evidence_with(
            "2026-10-26T01:19:20Z Binding RPC on address 127.0.0.1 port 36079\n2026-10-26T01:19:20Z [warning] Binding RPC on address 127.0.0.1 port 36079 failed.\n",
            "",
        )?;
        assert!(
            !rpc_bind_evidence_ready(Kind::Core, addr, &core_lost),
            "a lost bind must never read as ready"
        );

        let (_keep, node_bound) = evidence_with(
            "",
            "2026-10-26T01:19:20Z INFO bitcoin_rs_node::lifecycle: rpc listener bound addr=127.0.0.1:36079\n",
        )?;
        assert!(rpc_bind_evidence_ready(Kind::BitcoinRs, addr, &node_bound));

        let (_keep, node_pending) =
            evidence_with("", "2026-10-26T01:19:20Z INFO startup: loading\n")?;
        assert!(
            !rpc_bind_evidence_ready(Kind::BitcoinRs, addr, &node_pending),
            "a pre-bind probe must keep polling, never adopt"
        );
        Ok(())
    }
}
