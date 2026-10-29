use super::*;

use crate::lifecycle::start_node;
use crate::state::data_dir_lock::{DataDirLock, DataDirLockError};
use std::net::SocketAddr;

const CHILD_DIR_ENV: &str = "BITCOIN_RS_TEST_DATA_DIR_LOCK_CHILD_DIR";
const CHILD_KIND_ENV: &str = "BITCOIN_RS_TEST_DATA_DIR_LOCK_CHILD_KIND";
const KIND_OPEN: &str = "open";
const KIND_NODE: &str = "node";
const CHILD_READY_DEADLINE: std::time::Duration = std::time::Duration::from_mins(1);
const BASIC_AUTH: &str = "dXNlcjpwYXNzd29yZA==";

fn lock_config(data_dir: &std::path::Path) -> crate::NodeConfig {
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.to_path_buf();
    config.rpc.bind = SocketAddr::from(([127, 0, 0, 1], 0));
    config.rpc.auth = crate::Auth::basic("user", "password");
    config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
    config.p2p.listen.clear();
    config.observability.metrics_bind = None;
    config
}

fn assert_directory_locked(data_dir: &std::path::Path) {
    match DataDirLock::acquire(data_dir) {
        Err(DataDirLockError::InUse { path }) => assert_eq!(path, data_dir),
        other => panic!("expected the directory to be locked, got: {other:?}"),
    }
}

fn assert_in_use(error: &anyhow::Error, expected_dir: &std::path::Path) {
    let Some(lock_error) = error.downcast_ref::<DataDirLockError>() else {
        panic!("expected DataDirLockError, got: {error:#}");
    };
    match lock_error {
        DataDirLockError::InUse { path } => {
            assert_eq!(
                path, expected_dir,
                "the refusal must name the contended dir"
            );
        }
        other => panic!("expected InUse, got: {other:?}"),
    }
}

#[test]
fn second_open_while_first_lives_refuses_and_reopen_succeeds_after_drop() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let config = lock_config(&data_dir);

    let first = NodeState::open(config.clone(), None)?;

    let Err(error) = NodeState::open(config.clone(), None) else {
        panic!("the held directory must refuse a second open");
    };
    assert_in_use(&error, &data_dir);

    drop(first);
    let reopened = NodeState::open(config, None)?;
    drop(reopened);
    Ok(())
}

#[test]
fn running_node_refuses_open_until_shutdown_releases() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let config = lock_config(&data_dir);

    let node = start_node(config.clone(), crate::RuntimeInputs::default(), false)?;

    let Err(error) = NodeState::open(config.clone(), None) else {
        panic!("the running node's directory must refuse a second open");
    };
    assert_in_use(&error, &data_dir);

    node.shutdown_blocking()?;
    let reopened = NodeState::open(config, None)?;
    drop(reopened);
    Ok(())
}

fn idle_keepalive_rpc_connection(addr: SocketAddr) -> anyhow::Result<std::net::TcpStream> {
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};

    let mut stream = std::net::TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
    let body = r#"{"jsonrpc":"1.0","id":"keepalive","method":"uptime","params":[]}"#;
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Basic {BASIC_AUTH}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: keep-alive\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut status = String::new();
    reader.read_line(&mut status)?;
    anyhow::ensure!(
        status.starts_with("HTTP/1.1 200"),
        "unexpected RPC status: {status}"
    );
    let mut content_length = None;
    let mut keep_alive = false;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_ascii_lowercase();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => content_length = Some(value.parse::<usize>()?),
            "connection" => keep_alive = value == "keep-alive",
            _ => {}
        }
    }
    anyhow::ensure!(
        keep_alive,
        "the server must keep the connection open for this proof"
    );
    let length =
        content_length.ok_or_else(|| anyhow::anyhow!("RPC response lacks Content-Length"))?;
    reader.read_exact(&mut vec![0_u8; length])?;
    drop(reader);
    Ok(stream)
}

#[test]
fn idle_keepalive_rpc_connection_keeps_the_directory_locked_after_shutdown() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = lock_config(&data_dir);
    let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
    config.rpc.bind = probe.local_addr()?;
    drop(probe);

    let node = start_node(config.clone(), crate::RuntimeInputs::default(), false)?;
    let client = idle_keepalive_rpc_connection(config.rpc.bind)?;
    node.shutdown_blocking()?;

    let Err(error) = NodeState::open(config.clone(), None) else {
        panic!("an idle keep-alive connection must keep the directory locked after shutdown");
    };
    assert_in_use(&error, &data_dir);

    drop(client);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match NodeState::open(config.clone(), None) {
            Ok(state) => {
                drop(state);
                return Ok(());
            }
            Err(error) => assert_in_use(&error, &data_dir),
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "the closed connection never released the data directory"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
fn retained_chainstate_handle_keeps_the_directory_locked_until_dropped() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let config = lock_config(&data_dir);

    let state = NodeState::open(config.clone(), None)?;
    let retained = state.chainstate();
    drop(state);

    let Err(error) = NodeState::open(config.clone(), None) else {
        panic!("a retained chainstate handle must keep the directory locked");
    };
    assert_in_use(&error, &data_dir);

    drop(retained);
    drop(NodeState::open(config, None)?);
    Ok(())
}

#[test]
fn retained_block_body_store_keeps_the_directory_locked_until_dropped() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let config = lock_config(&data_dir);

    let state = NodeState::open(config.clone(), None)?;
    let body_store = state.storage.block_body_store();
    drop(state);

    let Err(error) = NodeState::open(config.clone(), None) else {
        panic!("a retained block-body store must keep the directory locked");
    };
    assert_in_use(&error, &data_dir);

    drop(body_store);
    drop(NodeState::open(config, None)?);
    Ok(())
}

#[test]
fn block_files_alone_keep_the_directory_locked_until_dropped() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config = lock_config(dir.path());
    let guard: bitcoin_rs_storage::StoreGuard = Arc::new(DataDirLock::acquire(dir.path())?);

    let (storage, block_files) =
        crate::state::storage::NodeStorage::open(&config, 32 << 20, &guard)?;
    drop(storage);
    drop(guard);
    assert_directory_locked(dir.path());

    drop(block_files);
    drop(DataDirLock::acquire(dir.path())?);
    Ok(())
}

#[test]
fn retained_index_query_adapter_keeps_the_directory_locked_until_dropped() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = lock_config(&data_dir);
    config.indexes.txindex = true;

    let mut state = NodeState::open(config.clone(), None)?;
    state.start_index_workers()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while state.derived_index.lifecycle_is_opening() {
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "txindex lifecycle remained Opening"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    anyhow::ensure!(
        !state.derived_index.lifecycle_is_failed(),
        "the worker must publish its serving engine for this proof"
    );
    let adapter = state
        .derived_index
        .adapter()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("an enabled txindex has a query adapter"))?;
    state.bounded_index_shutdown(std::time::Duration::from_secs(5))?;
    drop(state);

    let Err(error) = NodeState::open(config.clone(), None) else {
        panic!("a retained index query adapter must keep the directory locked");
    };
    assert_in_use(&error, &data_dir);

    drop(adapter);
    let mut reopened = NodeState::open(config, None)?;
    reopened.start_index_workers()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while reopened.derived_index.lifecycle_is_opening() {
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "replacement txindex worker remained Opening"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    anyhow::ensure!(
        !reopened.derived_index.lifecycle_is_failed(),
        "the released index store must reopen without a backend lock error"
    );
    Ok(())
}

#[test]
fn index_open_spec_and_opened_store_each_keep_the_directory_locked() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = lock_config(dir.path());
    config.indexes.txindex = true;
    let guard: bitcoin_rs_storage::StoreGuard = Arc::new(DataDirLock::acquire(dir.path())?);

    let spec = crate::state::build_derived_index_open_spec(&config, 32 << 20, 1, &guard, None)?
        .ok_or_else(|| anyhow::anyhow!("an enabled txindex must yield an open spec"))?;
    drop(guard);
    assert_directory_locked(dir.path());

    let index_dir = dir.path().join("txindex");
    std::fs::create_dir_all(&index_dir)?;
    let opened = (spec.open_store)(&index_dir)
        .map_err(|error| anyhow::anyhow!("open txindex store: {error:?}"))?;
    drop(spec);
    assert_directory_locked(dir.path());

    drop(opened);
    drop(DataDirLock::acquire(dir.path())?);
    Ok(())
}

#[test]
fn symlinked_lock_file_refuses_start_without_following() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    std::fs::create_dir_all(&data_dir)?;
    let outside = dir.path().join("outside.lock");
    std::fs::write(&outside, b"")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, data_dir.join(".lock"))?;
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&outside, data_dir.join(".lock"))?;

    let Err(error) = NodeState::open(lock_config(&data_dir), None) else {
        panic!("a symlinked lock entry must refuse startup");
    };
    let lowered = error.to_string().to_lowercase();
    assert!(
        matches!(
            error.downcast_ref::<DataDirLockError>(),
            Some(DataDirLockError::Io { .. })
        ) || lowered.contains("cannot write to directory"),
        "expected the Io refusal for a symlinked lock, got: {error:#}"
    );
    Ok(())
}

#[test]
#[ignore = "spawned explicitly by the contender tests in this file"]
fn data_dir_lock_subprocess_contender() -> anyhow::Result<()> {
    let Some(data_dir) = std::env::var_os(CHILD_DIR_ENV) else {
        return Ok(());
    };
    let data_dir = std::path::PathBuf::from(data_dir);
    let kind = std::env::var(CHILD_KIND_ENV).unwrap_or_else(|_| KIND_OPEN.to_owned());
    let held_marker = data_dir.join("lock-child-held");
    let done_marker = data_dir.join("lock-parent-done");
    if kind == KIND_NODE {
        let node = start_node(
            lock_config(&data_dir),
            crate::RuntimeInputs::default(),
            false,
        )?;
        std::fs::write(&held_marker, b"node")?;
        let deadline = std::time::Instant::now() + CHILD_READY_DEADLINE;
        while !done_marker.exists() {
            if std::time::Instant::now() >= deadline {
                anyhow::bail!("lock child never saw the parent's release");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        node.shutdown_blocking()?;
    } else {
        let state = NodeState::open(lock_config(&data_dir), None)?;
        std::fs::write(&held_marker, b"open")?;
        let deadline = std::time::Instant::now() + CHILD_READY_DEADLINE;
        while !done_marker.exists() {
            if std::time::Instant::now() >= deadline {
                anyhow::bail!("lock child never saw the parent's release");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        drop(state);
    }
    std::process::exit(0);
}

fn wait_for_child_marker(
    child: &mut std::process::Child,
    marker: &std::path::Path,
    message: &str,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + CHILD_READY_DEADLINE;
    while !marker.exists() {
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("lock child died before {message}: {status}");
        }
        if std::time::Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait();
            anyhow::bail!("lock child never {message}");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    Ok(())
}

struct LockChild(std::process::Child);

impl LockChild {
    fn finish(&mut self) -> anyhow::Result<()> {
        use std::io::Read as _;
        let mut stderr = String::new();
        if let Some(mut pipe) = self.0.stderr.take() {
            pipe.read_to_string(&mut stderr)?;
        }
        let status = self.0.wait()?;
        anyhow::ensure!(status.success(), "lock child failed: {status}: {stderr}");
        Ok(())
    }
}

impl Drop for LockChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn second_process_is_refused_while_first_holds_its_node() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");

    let test_name = concat!(module_path!(), "::data_dir_lock_subprocess_contender")
        .split("::")
        .skip(1)
        .collect::<Vec<_>>()
        .join("::");
    let exe = std::env::current_exe()?;

    let mut child = LockChild(
        std::process::Command::new(&exe)
            .args(["--exact", &test_name, "--ignored"])
            .env(CHILD_DIR_ENV, &data_dir)
            .env(CHILD_KIND_ENV, KIND_NODE)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()?,
    );

    wait_for_child_marker(&mut child.0, &data_dir.join("lock-child-held"), "holding")?;

    let Err(error) = NodeState::open(lock_config(&data_dir), None) else {
        panic!("the child process's directory must refuse this open");
    };
    assert_in_use(&error, &data_dir);

    std::fs::write(data_dir.join("lock-parent-done"), b"")?;
    child.finish()?;

    drop(NodeState::open(lock_config(&data_dir), None)?);
    Ok(())
}
