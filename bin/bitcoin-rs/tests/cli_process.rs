#![cfg(unix)]

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use sonic_rs::{JsonValueTrait as _, Value};

const STARTUP_DEADLINE: Duration = Duration::from_secs(30);
const EXIT_DEADLINE: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const RPC_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("process exited before it became ready: {status}; log:\n{log}")]
    EarlyExit { status: ExitStatus, log: String },
    #[error("process did not become ready within {0:?}; log:\n{1}")]
    StartupTimeout(Duration, String),
    #[error("process did not exit within {0:?}; log:\n{1}")]
    ExitTimeout(Duration, String),
    #[error("rpc reply is not a JSON-RPC result: HTTP {status} {body}")]
    RpcNotJson { status: u16, body: String },
    #[error("signal delivery failed: {0}")]
    Signal(ExitStatus),
}

struct Run {
    status: ExitStatus,
    log: String,
}

struct Node {
    child: Child,
    rpc: SocketAddr,
    data_dir: PathBuf,
    log: PathBuf,
}

fn build(
    root: &Path,
    rpc_bind: SocketAddr,
    args: &[OsString],
    log: &Path,
) -> std::io::Result<Command> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bitcoin-rs"));
    command
        .arg("--network")
        .arg("regtest")
        .arg("--data-dir")
        .arg(root.join("node"))
        .arg("--p2p-listen")
        .arg("127.0.0.1:0")
        .arg("--dns-seeds-enabled=false")
        .arg("--rpc-bind")
        .arg(rpc_bind.to_string())
        .arg("--dbcache-mb")
        .arg("32")
        .args(args);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("BITCOIN_RS_") {
            command.env_remove(key);
        }
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(File::create(log)?));
    Ok(command)
}

fn read_log(path: &Path) -> Result<String, TestError> {
    Ok(std::fs::read_to_string(path)?)
}

fn tail(text: &str) -> String {
    let mut start = text.len().saturating_sub(4000);
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    text[start..].to_owned()
}

fn await_exit(child: &mut Child, deadline: Duration) -> Result<Option<ExitStatus>, TestError> {
    let until = Instant::now() + deadline;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= until {
            return Ok(None);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn run_expecting_exit(
    root: &Path,
    rpc_bind: SocketAddr,
    args: &[OsString],
    deadline: Duration,
) -> Result<Run, TestError> {
    let log = root.join("expect.log");
    let mut child = build(root, rpc_bind, args, &log)?.spawn()?;
    let status = await_exit(&mut child, deadline)?;
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(TestError::ExitTimeout(deadline, tail(&read_log(&log)?)));
    };
    Ok(Run {
        status,
        log: read_log(&log)?,
    })
}

fn rpc_address(log: &str) -> Option<SocketAddr> {
    let line = log
        .lines()
        .find(|line| line.contains("rpc listener bound"))?;
    let rest = line.split_once("\"addr\":\"")?.1;
    rest.split_once('"')?.0.parse().ok()
}

impl Node {
    fn start(root: &Path, args: &[OsString]) -> Result<Self, TestError> {
        let rpc_bind = SocketAddr::from(([127, 0, 0, 1], 0));
        let log = root.join(format!("node-{}.log", rpc_bind.port()));
        let mut child = build(root, rpc_bind, args, &log)?.spawn()?;
        let until = Instant::now() + STARTUP_DEADLINE;
        loop {
            let text = read_log(&log)?;
            if let Some(rpc) = rpc_address(&text) {
                return Ok(Self {
                    child,
                    rpc,
                    data_dir: root.join("node"),
                    log,
                });
            }
            if let Some(status) = child.try_wait()? {
                return Err(TestError::EarlyExit {
                    status,
                    log: tail(&text),
                });
            }
            if Instant::now() >= until {
                let _ = child.kill();
                let _ = child.wait();
                return Err(TestError::StartupTimeout(STARTUP_DEADLINE, tail(&text)));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn cookie_credentials(&self) -> Result<String, TestError> {
        Ok(std::fs::read_to_string(self.data_dir.join(".cookie"))?
            .trim()
            .to_owned())
    }

    fn rpc(
        &self,
        method: &str,
        credentials: Option<(&str, &str)>,
    ) -> Result<(u16, String), TestError> {
        let body =
            format!("{{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"{method}\",\"params\":[]}}");
        let mut stream = TcpStream::connect_timeout(&self.rpc, RPC_TIMEOUT)?;
        stream.set_read_timeout(Some(RPC_TIMEOUT))?;
        stream.set_write_timeout(Some(RPC_TIMEOUT))?;
        let auth = credentials.map_or_else(String::new, |(user, password)| {
            format!(
                "Authorization: Basic {}\r\n",
                base64(format!("{user}:{password}").as_bytes())
            )
        });
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: {}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.rpc,
            body.len()
        )?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        let text = String::from_utf8(response)?;
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        let body = text
            .split_once("\r\n\r\n")
            .map_or(String::new(), |(_, body)| body.to_owned());
        Ok((status, body))
    }

    fn rpc_result(&self, credentials: Option<(&str, &str)>) -> Result<Value, TestError> {
        let (status, body) = self.rpc("getblockcount", credentials)?;
        let value: Value =
            sonic_rs::from_slice(body.as_bytes()).map_err(|_error| TestError::RpcNotJson {
                status,
                body: body.clone(),
            })?;
        value
            .get("result")
            .filter(|result| result.as_u64().is_some())
            .cloned()
            .ok_or(TestError::RpcNotJson { status, body })
    }

    fn terminate(&mut self) -> Result<ExitStatus, TestError> {
        self.send_sigterm()?;
        let Some(status) = await_exit(&mut self.child, EXIT_DEADLINE)? else {
            return Err(TestError::ExitTimeout(EXIT_DEADLINE, read_log(&self.log)?));
        };
        Ok(status)
    }

    fn send_sigterm(&self) -> Result<(), TestError> {
        let pid = self.child.id().to_string();
        let status = Command::new("kill")
            .args(["-TERM", pid.as_str()])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(TestError::Signal(status))
        }
    }

    fn stop(mut self) -> Result<(), TestError> {
        let status = self.terminate()?;
        let log = read_log(&self.log)?;
        assert_eq!(status.code(), Some(0), "clean stop log:\n{log}");
        Ok(())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in input.chunks(3) {
        let bytes = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let group = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
        let sextet = |shift: u32| usize::from(u8::try_from((group >> shift) & 63).unwrap_or(0));
        encoded.push(char::from(TABLE[sextet(18)]));
        encoded.push(char::from(TABLE[sextet(12)]));
        encoded.push(if chunk.len() > 1 {
            char::from(TABLE[sextet(6)])
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            char::from(TABLE[sextet(0)])
        } else {
            '='
        });
    }
    encoded
}

#[test]
fn bitcoin_conf_semicolon_credentials_authenticate_end_to_end() -> Result<(), TestError> {
    let root = tempfile::tempdir()?;
    let conf = root.path().join("bitcoin.conf");
    std::fs::write(&conf, "rpcuser=ab;cd\nrpcpassword=xy;z\n")?;
    let node = Node::start(
        root.path(),
        &[OsString::from("--bitcoin-conf"), conf.into_os_string()],
    )?;

    let result = node.rpc_result(Some(("ab;cd", "xy;z")))?;
    assert_eq!(
        result.as_u64(),
        Some(0),
        "configured credentials answer the RPC"
    );
    let (truncated, _) = node.rpc("getblockcount", Some(("ab", "xy")))?;
    assert_eq!(
        truncated, 401,
        "the node must not authenticate the value truncated at ';'"
    );
    node.stop()
}

#[test]
fn bitcoin_conf_refuses_a_hash_inside_rpcpassword() -> Result<(), TestError> {
    let root = tempfile::tempdir()?;
    let conf = root.path().join("bitcoin.conf");
    std::fs::write(&conf, "rpcpassword=ab#cd\n")?;

    let run = run_expecting_exit(
        root.path(),
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &[OsString::from("--bitcoin-conf"), conf.into_os_string()],
        EXIT_DEADLINE,
    )?;

    assert_eq!(
        run.status.code(),
        Some(1),
        "an ambiguous rpcpassword must refuse startup: {}",
        run.log
    );
    assert!(
        run.log.contains("rpcpassword"),
        "the refusal names the key: {}",
        run.log
    );
    Ok(())
}

// EMB-07
#[test]
fn a_second_process_refuses_the_locked_data_dir() -> Result<(), TestError> {
    let root = tempfile::tempdir()?;
    let first = Node::start(root.path(), &[])?;
    let cookie = first.cookie_credentials()?;
    let credentials = cookie.split_once(':').unwrap_or((cookie.as_str(), ""));
    assert!(first.rpc_result(Some(credentials)).is_ok());

    let run = run_expecting_exit(
        root.path(),
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &[],
        EXIT_DEADLINE,
    )?;
    assert_eq!(
        run.status.code(),
        Some(1),
        "a second process on a locked data dir must fail: {}",
        run.log
    );
    assert!(
        run.log.contains(first.data_dir.to_string_lossy().as_ref()),
        "the refusal names the contended directory: {}",
        run.log
    );

    assert!(
        first.rpc_result(Some(credentials)).is_ok(),
        "the running node keeps serving after the refusal"
    );

    let lock_path = first.data_dir.join(".lock");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)?;
    let held_outcome =
        rustix::fs::fcntl_lock(&held, rustix::fs::FlockOperation::NonBlockingLockExclusive);
    assert!(
        held_outcome.is_err(),
        "the live node's directory record lock must refuse a second lock while it runs"
    );
    drop(held);

    first.stop()?;

    let released = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)?;
    rustix::fs::fcntl_lock(
        &released,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .map_err(|error| TestError::Io(std::io::Error::from(error)))?;
    drop(released);
    Ok(())
}

// EMB-07
#[test]
fn sigterm_exits_zero_and_the_data_dir_restarts() -> Result<(), TestError> {
    let root = tempfile::tempdir()?;
    let mut first = Node::start(root.path(), &[])?;
    let status = first.terminate()?;
    let first_log = read_log(&first.log)?;
    assert_eq!(
        status.code(),
        Some(0),
        "SIGTERM is a clean shutdown: {first_log}"
    );
    drop(first);

    let mut second = Node::start(root.path(), &[])?;
    let cookie = second.cookie_credentials()?;
    let credentials = cookie.split_once(':').unwrap_or((cookie.as_str(), ""));
    assert!(second.rpc_result(Some(credentials)).is_ok());
    let status = second.terminate()?;
    let second_log = read_log(&second.log)?;
    assert_eq!(
        status.code(),
        Some(0),
        "the restarted node also stops cleanly: {second_log}"
    );
    Ok(())
}

#[test]
fn an_occupied_rpc_port_fails_fast_and_releases_the_data_dir() -> Result<(), TestError> {
    let root = tempfile::tempdir()?;
    let occupied_listener = TcpListener::bind("127.0.0.1:0")?;
    let occupied = occupied_listener.local_addr()?;

    let run = run_expecting_exit(root.path(), occupied, &[], EXIT_DEADLINE)?;
    assert_eq!(
        run.status.code(),
        Some(1),
        "an occupied RPC address must fail startup: {}",
        run.log
    );
    assert!(
        run.log.contains(&occupied.to_string()),
        "the refusal names the occupied address: {}",
        run.log
    );

    let lock = File::open(root.path().join("node").join(".lock"))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(error) => panic!("a failed startup must release the data dir lock: {error}"),
    }
    drop(lock);

    let node = Node::start(root.path(), &[])?;
    let cookie = node.cookie_credentials()?;
    let credentials = cookie.split_once(':').unwrap_or((cookie.as_str(), ""));
    assert!(node.rpc_result(Some(credentials)).is_ok());
    node.stop()
}

#[test]
fn an_unreadable_config_path_is_refused() -> Result<(), TestError> {
    let root = tempfile::tempdir()?;
    let directory = root.path().join("config-dir");
    std::fs::create_dir(&directory)?;
    let non_utf8 = root.path().join("non-utf8.toml");
    std::fs::write(&non_utf8, b"network = \"regtest\"\n#\xff\xfe\n")?;
    let nul = root.path().join("nul.toml");
    std::fs::write(&nul, b"network = \"regtest\"\n\x00\n")?;

    for path in [&directory, &non_utf8, &nul] {
        let run = run_expecting_exit(
            root.path(),
            SocketAddr::from(([127, 0, 0, 1], 0)),
            &[OsString::from("--config"), path.clone().into_os_string()],
            EXIT_DEADLINE,
        )?;
        assert_eq!(
            run.status.code(),
            Some(1),
            "{} must refuse startup: {}",
            path.display(),
            run.log
        );
        assert!(
            run.log.contains(path.to_string_lossy().as_ref()),
            "the refusal names {}: {}",
            path.display(),
            run.log
        );
    }
    Ok(())
}

#[test]
fn a_data_dir_that_is_a_file_is_refused_and_left_intact() -> Result<(), TestError> {
    let root = tempfile::tempdir()?;
    let blocker = root.path().join("node");
    std::fs::write(&blocker, b"operator bytes")?;

    let run = run_expecting_exit(
        root.path(),
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &[],
        EXIT_DEADLINE,
    )?;

    assert_eq!(
        run.status.code(),
        Some(1),
        "a data dir that is a regular file must refuse startup: {}",
        run.log
    );
    assert_eq!(std::fs::read(&blocker)?, b"operator bytes");
    Ok(())
}
