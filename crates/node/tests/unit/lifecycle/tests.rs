use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_primitives::{BlockBodyMetadata, BlockPayload, Hash256};
use bitcoin_rs_storage::block_body::{BlockBodyReader, BlockBodyStore};
use bitcoin_rs_storage::{BlockFilePosition, BodyExtent, BoundedReadError, StorageError};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Condvar, Mutex};
use std::thread::{self, JoinHandle};

use super::*;
use crate::config::{NodeConfig, RuntimeInputs};
use crate::lifecycle::start_node;
use crate::run::run;

fn isolated_config(data_dir: &Path) -> NodeConfig {
    let mut config = NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.to_owned();
    config.rpc.bind = SocketAddr::from(([127, 0, 0, 1], 0));
    config.rpc.auth = crate::Auth::basic("user", "password");
    config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
    config.p2p.listen.clear();
    config.observability.metrics_bind = None;
    config
}

#[test]
fn split_rpc_listeners_start_and_join_through_node_services() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let management = std::net::TcpListener::bind("127.0.0.1:0")?;
    let public = std::net::TcpListener::bind("127.0.0.1:0")?;
    let management_address = management.local_addr()?;
    let public_address = public.local_addr()?;
    let mut config = isolated_config(dir.path());
    config.rpc.bind = management_address;
    config.rpc.public_bind = Some(public_address);
    drop((management, public));
    let node = start_node(config, RuntimeInputs::default(), false)?;
    assert_eq!(
        node.services
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing node services"))?
            .rpc_threads
            .len(),
        2
    );
    for (address, request, expected) in [
        (
            public_address,
            "OPTIONS /api/tx HTTP/1.1\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 204 No Content",
        ),
        (
            management_address,
            "POST / HTTP/1.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 401 Unauthorized",
        ),
    ] {
        let mut stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(WITNESS_BOUND))?;
        stream.write_all(request.as_bytes())?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        assert!(response.starts_with(expected), "{response}");
    }
    node.shutdown_blocking()?;
    let _management = std::net::TcpListener::bind(management_address)?;
    let _public = std::net::TcpListener::bind(public_address)?;
    Ok(())
}

#[test]
fn public_bind_failure_rolls_back_management_binding_and_node_state() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let management = std::net::TcpListener::bind("127.0.0.1:0")?;
    let public = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = management.local_addr()?;
    let mut config = isolated_config(dir.path());
    config.rpc.bind = address;
    config.rpc.public_bind = Some(public.local_addr()?);
    drop(management);
    let error = start_node(config.clone(), RuntimeInputs::default(), false)
        .err()
        .ok_or_else(|| anyhow::anyhow!("occupied public bind must fail startup"))?;
    assert_eq!(
        error.to_string(),
        format!(
            "failed to bind public HTTP listener at {}",
            public.local_addr()?
        )
    );
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::AddrInUse)
    );
    let _management = std::net::TcpListener::bind(address)?;
    let _reopened = NodeState::open(config, None)?;
    Ok(())
}

#[test]
fn timed_out_snapshot_worker_cannot_overwrite_the_next_runs_snapshot() -> anyhow::Result<()> {
    use bitcoin_rs_mempool::{Mempool, MempoolGateway, MempoolLimits, snapshot};
    use bitcoin_rs_primitives::{Hash256, Network, Txid};
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir()?;
    let gateway = Arc::new(MempoolGateway::new(
        Arc::new(parking_lot::RwLock::new(Mempool::new(
            MempoolLimits::default(),
        ))),
        None,
        ValidationEngine::Native,
        None,
    ));
    let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);
    let (release_tx, release_rx) = crossbeam_channel::bounded(1);
    let (result_tx, result_rx) = crossbeam_channel::bounded(1);
    let worker_gateway = Arc::clone(&gateway);
    let path = dir.path().to_path_buf();
    let worker = std::thread::spawn(move || {
        let staged = snapshot::prepare(
            &path,
            &worker_gateway,
            Network::Regtest,
            snapshot::DEFAULT_MAX_BYTES,
            Instant::now() + Duration::from_secs(10),
        );
        let _ = ready_tx.send(staged.is_ok());
        let _ = release_rx.recv();
        let _ = result_tx.send(staged);
    });
    let prepared = ready_rx.recv_timeout(Duration::from_secs(10))?;
    // Exercise the production timeout path while the old worker is parked.
    publish_mempool_snapshot(result_rx, Instant::now() + Duration::from_millis(2));
    gateway.prioritise(Txid(Hash256::from_le_bytes(&[7; 32])), 50)?;
    snapshot::save(
        dir.path(),
        &gateway,
        Network::Regtest,
        snapshot::DEFAULT_MAX_BYTES,
        Instant::now() + Duration::from_secs(10),
    )?;
    let file = dir.path().join("mempool-snapshot.dat");
    let newer = std::fs::read(&file)?;
    release_tx.send(())?;
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("snapshot worker panicked"))?;
    assert!(
        prepared,
        "the delayed worker must hold a valid old snapshot"
    );
    assert_eq!(std::fs::read(&file)?, newer);
    assert_eq!(std::fs::read_dir(dir.path())?.count(), 1);
    Ok(())
}

#[test]
fn rpc_network_handles_borrow_p2p_service_state() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let state = NodeState::open(isolated_config(dir.path()), None)?;
    let p2p = state.p2p();
    let handles = rpc_network_handles(&state);

    assert!(Arc::ptr_eq(&handles.peer_table, &p2p.table()));
    assert!(Arc::ptr_eq(&handles.p2p, &p2p));
    assert_eq!(handles.local_services, p2p.local_services().to_u64());
    Ok(())
}

#[test]
fn verifychain_arguments_select_the_check_core_asks_for() {
    for (check_level, level) in [
        (0, CheckLevel::ReadBodies),
        (1, CheckLevel::CheckBodies),
        (2, CheckLevel::CheckUndo),
        (3, CheckLevel::CheckUndo),
        (4, CheckLevel::CheckUndo),
    ] {
        let request = verify_request(check_level, 6);
        assert_eq!(request.level, level, "level {check_level}");
        assert_eq!(request.depth, NonZeroU32::new(6), "level {check_level}");
        assert!(
            request.cancellation.is_none(),
            "the latch travels with the call, not the mapping"
        );
    }
    assert_eq!(
        verify_request(3, 0).depth,
        None,
        "zero blocks is the whole chain"
    );
}

#[test]
fn verify_chain_accepts_an_intact_applied_chain_at_every_level_and_depth() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let state = NodeState::open(isolated_config(dir.path()), None)?;
    let genesis = BlockPayload::from_local(bitcoin_rs_primitives::Network::Regtest.genesis_block());
    state.apply_block(&genesis)?;
    let mut previous = genesis.block().block_hash();
    for height in 1..=3 {
        let block = BlockPayload::from_local(
            bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at(previous, height)?,
        );
        state.apply_block(&block)?;
        previous = block.block().block_hash();
    }
    let control = RpcChainControl {
        handles: state.chainstate(),
        followers: state.chain_followers(),
        sync: state.sync(),
        snapshots: Arc::clone(&state.snapshots),
    };
    let cancellation = bitcoin_rs_chain::LatchReader::new(Arc::new(AtomicBool::new(false)));
    for check_level in 0..=4 {
        for nblocks in [0, 2, 100] {
            assert!(
                matches!(
                    control.verify_chain(check_level, nblocks, &cancellation),
                    Ok(true)
                ),
                "level {check_level}, {nblocks} blocks"
            );
        }
    }
    Ok(())
}

/// An applied genesis tip is an empty verification window: the real verifier
/// answers it at every level and depth, not a handler shortcut.
#[test]
fn verify_chain_over_applied_genesis_is_answered_by_the_real_verifier() -> anyhow::Result<()> {
    use bitcoin_rs_rpc::context::ChainControlError;

    let dir = tempfile::tempdir()?;
    let state = NodeState::open(isolated_config(dir.path()), None)?;
    state.apply_block(&BlockPayload::from_local(
        bitcoin_rs_primitives::Network::Regtest.genesis_block(),
    ))?;
    assert_eq!(
        state
            .chainstate()
            .applied_tip_snapshot()
            .map(|tip| tip.height),
        Some(0),
        "the fixture must apply genesis and nothing above it"
    );
    let control = RpcChainControl {
        handles: state.chainstate(),
        followers: state.chain_followers(),
        sync: state.sync(),
        snapshots: Arc::clone(&state.snapshots),
    };
    let live = bitcoin_rs_chain::LatchReader::new(Arc::new(AtomicBool::new(false)));
    for check_level in 0..=4 {
        for nblocks in [0, 1, 6] {
            assert!(
                matches!(control.verify_chain(check_level, nblocks, &live), Ok(true)),
                "level {check_level}, {nblocks} blocks"
            );
        }
    }
    // The verifier itself refuses once the chainstate closes for recovery,
    // even over the empty window.
    state.chainstate().fail_closed_for_recovery();
    assert!(matches!(
        control.verify_chain(3, 6, &live),
        Err(ChainControlError::Unavailable)
    ));
    Ok(())
}

#[test]
fn verify_chain_reports_cancellation_and_recovery_closure() -> anyhow::Result<()> {
    use bitcoin_rs_rpc::context::ChainControlError;

    let dir = tempfile::tempdir()?;
    let state = NodeState::open(isolated_config(dir.path()), None)?;
    let control = RpcChainControl {
        handles: state.chainstate(),
        followers: state.chain_followers(),
        sync: state.sync(),
        snapshots: Arc::clone(&state.snapshots),
    };
    let live = bitcoin_rs_chain::LatchReader::new(Arc::new(AtomicBool::new(false)));
    assert!(
        matches!(control.verify_chain(3, 6, &live), Ok(true)),
        "an open chain must verify"
    );
    let fired = bitcoin_rs_chain::LatchReader::new(Arc::new(AtomicBool::new(true)));
    assert!(
        matches!(
            control.verify_chain(3, 6, &fired),
            Err(ChainControlError::Interrupted)
        ),
        "a cancelled request must interrupt, not fail as damage"
    );
    state.chainstate().fail_closed_for_recovery();
    assert!(
        matches!(
            control.verify_chain(3, 6, &live),
            Err(ChainControlError::Unavailable)
        ),
        "a closed chain must be unavailable, not verified"
    );
    Ok(())
}

fn seed_checkpoint(state: &NodeState) -> anyhow::Result<(PathBuf, Vec<u8>)> {
    state.apply_block(&BlockPayload::from_local(
        bitcoin_rs_primitives::Network::Regtest.genesis_block(),
    ))?;
    let _ = state.publish_checkpoint()?;
    let current = state
        .data_dir()
        .join("chainstate-checkpoints")
        .join("CURRENT");
    let previous = std::fs::read(&current)?;
    Ok((current, previous))
}

struct RestoreCheckpointRoot {
    root: PathBuf,
    displaced: PathBuf,
}

impl Drop for RestoreCheckpointRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.root);
        let _ = std::fs::rename(&self.displaced, &self.root);
    }
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn disabled_zmq_still_seals_the_observer_slot() {
    let pool = Arc::new(parking_lot::RwLock::new(bitcoin_rs_mempool::Mempool::new(
        bitcoin_rs_mempool::MempoolLimits::default(),
    )));
    let observer: Arc<dyn bitcoin_rs_mempool::MempoolObserver> =
        Arc::new(bitcoin_rs_mempool::CompositeObserver::new());
    let gateway = Arc::new(bitcoin_rs_mempool::MempoolGateway::new(
        pool,
        Some(observer),
        ValidationEngine::Native,
        None,
    ));
    assert!(
        gateway.has_observer(),
        "startup must seal the observer slot even without a ZMQ endpoint"
    );
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn clean_shutdown_publishes_checkpoint_and_returns_success() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let config = isolated_config(&temp.path().join("node-success"));
    let state = NodeState::open(config.clone(), None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    drop(state);

    let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
    shutdown_tx.send(())?;
    run(
        config.clone(),
        RuntimeInputs::default().with_shutdown(shutdown_rx),
    )?;
    assert_ne!(std::fs::read(current)?, previous);
    let resumed = NodeState::open(config, None)?;
    assert_eq!(
        resumed.resume_source(),
        crate::state::ResumeSource::Checkpoint
    );
    Ok(())
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn shutdown_checkpoint_io_failure_is_returned_and_preserves_current() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let mut config = isolated_config(&temp.path().join("node-checkpoint-failure"));
    config.p2p.connect = vec!["127.0.0.1:1".to_owned()];
    let state = NodeState::open(config.clone(), None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    drop(state);

    let checkpoint_root = current
        .parent()
        .ok_or_else(|| anyhow::anyhow!("checkpoint CURRENT has no parent"))?
        .to_path_buf();
    let displaced = checkpoint_root.with_extension("checkpoint-failure-backup");
    let restore = RestoreCheckpointRoot {
        root: checkpoint_root.clone(),
        displaced: displaced.clone(),
    };
    let injected = Arc::new(AtomicBool::new(false));
    inject_before_clean_checkpoint({
        let displaced = displaced.clone();
        let injected = Arc::clone(&injected);
        move || {
            injected.store(true, Ordering::Release);
            std::fs::rename(&checkpoint_root, &displaced)
                .unwrap_or_else(|error| panic!("move checkpoint root aside: {error}"));
            std::fs::write(&checkpoint_root, b"not a directory")
                .unwrap_or_else(|error| panic!("replace checkpoint root with file: {error}"));
        }
    });

    let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
    shutdown_tx.send(())?;
    let result = run(config, RuntimeInputs::default().with_shutdown(shutdown_rx));

    assert!(result.is_err());
    assert!(
        injected.load(Ordering::Acquire),
        "clean-checkpoint failure hook was not reached; run failed earlier: {result:?}"
    );
    assert_eq!(std::fs::read(displaced.join("CURRENT"))?, previous);
    assert!(
        bootstrap_drain_was_reached(),
        "checkpoint errors must not bypass the bootstrap-worker join"
    );
    drop(restore);
    Ok(())
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn teardown_join_failure_completes_cleanup_and_suppresses_checkpoint() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let config = isolated_config(&temp.path().join("node-join-failure"));
    let mut state = NodeState::open(config.clone(), None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    let panicker = std::thread::Builder::new()
        .name("bitcoin-rs-outbound-drain".to_owned())
        .spawn(|| panic!("injected worker panic"))?;
    let mut services = NodeServices::default();
    state.p2p().test_install_outbound_worker(panicker);

    assert!(
        services
            .teardown(Some(&mut state), TeardownMode::CleanShutdown)
            .is_err()
    );
    assert_eq!(shutdown::take_shutdown_stages_reached(), 1);
    assert_eq!(std::fs::read(current)?, previous);
    drop(services);
    drop(state);

    let resumed = NodeState::open(config, None)?;
    assert_eq!(
        resumed.resume_source(),
        crate::state::ResumeSource::Checkpoint
    );
    Ok(())
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn teardown_joins_bootstrap_worker_beyond_former_deadline() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let config = isolated_config(&temp.path().join("node-slow-bootstrap"));
    let mut state = NodeState::open(config, None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    let (_gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
    let (exited_tx, exited_rx) = std::sync::mpsc::channel();
    let worker = std::thread::Builder::new()
        .name("bitcoin-rs-p2p-bootstrap".to_owned())
        .spawn(move || {
            let _ = gate_rx.recv_timeout(std::time::Duration::from_secs(2));
            let _ = exited_tx.send(());
        })?;
    let mut services = NodeServices::default();
    state.p2p().test_install_bootstrap_worker(worker);
    let started = std::time::Instant::now();
    services.teardown(Some(&mut state), TeardownMode::CleanShutdown)?;
    let elapsed = started.elapsed();
    assert!(elapsed >= std::time::Duration::from_secs(2));
    assert!(
        exited_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .is_ok()
    );
    assert!(bootstrap_drain_was_reached());
    assert_ne!(std::fs::read(current)?, previous);
    drop(services);
    drop(state);
    Ok(())
}

#[test]
fn teardown_metrics_panic_reports_failure_and_preserves_checkpoint() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let mut state = NodeState::open(isolated_config(temp.path()), None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    let worker = std::thread::Builder::new()
        .name("bitcoin-rs-metrics".to_owned())
        .spawn(|| panic!("injected scrape worker panic"))?;
    let mut services = NodeServices::default();
    services.metrics = Some(crate::metrics::MetricsServer::with_worker_for_test(worker));

    let Err(error) = services.teardown(Some(&mut state), TeardownMode::CleanShutdown) else {
        anyhow::bail!("a metrics panic must fail teardown");
    };
    assert!(error.to_string().contains("metrics scrape thread panicked"));
    assert_eq!(shutdown::take_shutdown_stages_reached(), 1);
    assert!(bootstrap_drain_was_reached());
    assert_eq!(std::fs::read(&current)?, previous);
    assert!(services.metrics.is_none());
    services.teardown(Some(&mut state), TeardownMode::CleanShutdown)?;
    assert_eq!(shutdown::take_shutdown_stages_reached(), 0);
    assert_eq!(std::fs::read(current)?, previous);
    Ok(())
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn daemon_and_embedded_paths_share_one_teardown() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let daemon_config = isolated_config(&temp.path().join("daemon"));
    let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
    shutdown_tx.send(())?;
    let stages_before = shutdown::take_shutdown_stages_reached();
    run(
        daemon_config,
        RuntimeInputs::default().with_shutdown(shutdown_rx),
    )?;
    assert_eq!(shutdown::take_shutdown_stages_reached(), stages_before + 1);

    let embedded_config = isolated_config(&temp.path().join("embedded"));
    let installed_before = crate::signal::testing::installed_total();
    let closed_before = crate::signal::testing::closed_total();
    let node = start_node(embedded_config, RuntimeInputs::default(), true)?;
    node.shutdown_blocking()?;
    assert_eq!(shutdown::take_shutdown_stages_reached(), 1);
    assert_eq!(
        crate::signal::testing::installed_total(),
        installed_before + 1
    );
    assert_eq!(crate::signal::testing::closed_total(), closed_before + 1);
    Ok(())
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn repeated_teardown_and_drop_join_workers_once() -> anyhow::Result<()> {
    shutdown::take_shutdown_stages_reached();
    let joins = Arc::new(AtomicUsize::new(0));
    let worker_joins = Arc::clone(&joins);
    let mut services = NodeServices::default();
    services.tx_ingress = Some(std::thread::spawn(move || {
        worker_joins.fetch_add(1, Ordering::Release);
    }));
    services.teardown(None, TeardownMode::StartupAbort)?;
    services.teardown(None, TeardownMode::StartupAbort)?;
    drop(services);
    assert_eq!(joins.load(Ordering::Acquire), 1);
    assert_eq!(shutdown::take_shutdown_stages_reached(), 1);
    Ok(())
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn startup_rollback_joins_workers_and_preserves_checkpoint() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let config = isolated_config(&temp.path().join("startup-rollback"));
    let state = NodeState::open(config.clone(), None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    let shutdown_flag = state.chainstate().shutdown_handle();
    let exited = Arc::new(AtomicBool::new(false));
    let worker_exited = Arc::clone(&exited);
    let worker = std::thread::spawn(move || {
        while !shutdown_flag.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        worker_exited.store(true, Ordering::Release);
    });
    let mut guard = StartupGuard {
        state: Some(state),
        services: NodeServices::default(),
    };
    guard.services.tx_ingress = Some(worker);
    drop(guard);
    assert!(exited.load(Ordering::Acquire));
    assert_eq!(std::fs::read(current)?, previous);
    let resumed = NodeState::open(config, None)?;
    assert_eq!(
        resumed.resume_source(),
        crate::state::ResumeSource::Checkpoint
    );
    Ok(())
}

#[test]
// CONTRACT: docs/contracts/embedding.md EMB-01 — on explicit embedded
// shutdown the derived-index worker is stopped and joined before the clean
// checkpoint publishes and before chainstate closes.
fn explicit_shutdown_joins_index_worker_before_clean_checkpoint() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let mut config = isolated_config(&temp.path().join("node-index-join"));
    config.indexes.txindex = true;
    let node = start_node(config, RuntimeInputs::default(), true)?;
    // Wait until the worker's store is open (the lifecycle leaves Opening),
    // so shutdown exercises the live-worker join, not an open race.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while matches!(
        node.state.derived_index_status().capability().state,
        bitcoin_rs_index::CapabilityState::Opening
    ) {
        assert!(
            std::time::Instant::now() < deadline,
            "txindex lifecycle remained Opening"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // `worker_joined` flips only after the worker's join returns — a join
    // abandoned at the deadline never sets it — so the checkpoint-side
    // observation proves the join ran, not just that shutdown was requested.
    let joined = node.state.index_worker_joined();
    let worker_joined_before_checkpoint = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&worker_joined_before_checkpoint);
    inject_before_clean_checkpoint(move || {
        flag.store(joined.load(Ordering::Acquire), Ordering::Release);
    });

    node.shutdown_blocking()?;

    assert!(
        worker_joined_before_checkpoint.load(Ordering::Acquire),
        "the derived-index worker must be stopped and joined before the \
         clean checkpoint publishes"
    );
    Ok(())
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn a_queued_shutdown_wake_does_not_block_teardown() -> anyhow::Result<()> {
    let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
    wake_tx.send(())?;
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut services = NodeServices::default();
        services.event_loop_signal = Some(wake_tx);
        let result = services.teardown(None, TeardownMode::StartupAbort);
        let _ = done_tx.send(result);
    });
    let result = done_rx.recv_timeout(DRAIN_DEADLINE + Duration::from_secs(5));
    // Release a formerly blocking send even when the assertion will fail;
    // the regression must not leave a detached blocked thread behind.
    let _ = wake_rx.try_recv();
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("teardown worker panicked"))?;
    result.map_err(|_| anyhow::anyhow!("teardown blocked on an already queued wake"))??;
    Ok(())
}
const WITNESS_BOUND: Duration = Duration::from_secs(10);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

struct BodyGateState {
    armed: bool,
    entered: bool,
    released: bool,
}

struct BodyGate {
    state: Mutex<BodyGateState>,
    cvar: Condvar,
}

impl BodyGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(BodyGateState {
                armed: false,
                entered: false,
                released: false,
            }),
            cvar: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BodyGateState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn arm(&self) {
        let mut state = self.lock();
        state.armed = true;
        state.entered = false;
        state.released = false;
    }

    fn hold(&self) {
        let mut state = self.lock();
        if !state.armed {
            return;
        }
        state.entered = true;
        self.cvar.notify_all();
        while !state.released {
            state = self
                .cvar
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn wait_entered(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let mut state = self.lock();
        while !state.entered {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let (next, _) = self
                .cvar
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
        }
        state.entered
    }

    fn release(&self) {
        let mut state = self.lock();
        state.armed = false;
        state.released = true;
        self.cvar.notify_all();
    }
}

struct HoldingBodies {
    inner: Arc<dyn BlockBodyStore>,
    gate: Arc<BodyGate>,
}

impl BlockBodyStore for HoldingBodies {
    fn load_staged_body(
        &self,
        height: u32,
        hash: Hash256,
        position: Option<BlockFilePosition>,
    ) -> std::result::Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_staged_body(height, hash, position)
    }

    fn stage_block_body(
        &self,
        height: u32,
        hash: Hash256,
        body: &[u8],
    ) -> std::result::Result<Option<BlockFilePosition>, StorageError> {
        self.inner.stage_block_body(height, hash, body)
    }

    fn persist_block_body(
        &self,
        height: u32,
        hash: Hash256,
        body: &[u8],
    ) -> std::result::Result<(), StorageError> {
        self.inner.persist_block_body(height, hash, body)
    }

    fn persist_block_body_value(
        &self,
        height: u32,
        hash: Hash256,
        body: bytes::Bytes,
    ) -> std::result::Result<(), StorageError> {
        self.inner.persist_block_body_value(height, hash, body)
    }

    fn load_block_body(
        &self,
        height: u32,
        hash: Hash256,
    ) -> std::result::Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_block_body(height, hash)
    }

    fn load_block_body_for_verification(
        &self,
        height: u32,
        hash: Hash256,
    ) -> std::result::Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_block_body_for_verification(height, hash)
    }

    fn load_block_body_for_verification_bounded(
        &self,
        height: u32,
        hash: Hash256,
        max_bytes: usize,
    ) -> std::result::Result<Option<Vec<u8>>, BoundedReadError> {
        self.gate.hold();
        self.inner
            .load_block_body_for_verification_bounded(height, hash, max_bytes)
    }

    fn load_block_body_bounded(
        &self,
        height: u32,
        hash: Hash256,
        max_bytes: usize,
    ) -> std::result::Result<Option<Vec<u8>>, BoundedReadError> {
        self.inner.load_block_body_bounded(height, hash, max_bytes)
    }

    fn reader(&self) -> std::result::Result<Box<dyn BlockBodyReader + '_>, StorageError> {
        self.inner.reader()
    }

    fn undo_record(
        &self,
        height: u32,
        hash: Hash256,
    ) -> std::result::Result<Option<Vec<u8>>, StorageError> {
        self.inner.undo_record(height, hash)
    }

    fn load_block_body_range(
        &self,
        height: u32,
        hash: Hash256,
        offset: u32,
        len: u32,
    ) -> std::result::Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_block_body_range(height, hash, offset, len)
    }

    fn block_body_metadata(
        &self,
        height: u32,
        hash: Hash256,
    ) -> std::result::Result<Option<BlockBodyMetadata>, StorageError> {
        self.inner.block_body_metadata(height, hash)
    }

    fn append_cursor(&self) -> Option<BodyExtent> {
        self.inner.append_cursor()
    }

    fn block_position(
        &self,
        height: u32,
        hash: Hash256,
    ) -> std::result::Result<Option<BlockFilePosition>, StorageError> {
        self.inner.block_position(height, hash)
    }

    fn disk_usage(&self) -> Option<u64> {
        self.inner.disk_usage()
    }

    fn sync(&self) -> std::result::Result<(), StorageError> {
        self.inner.sync()
    }

    fn flush_index(&self) -> std::result::Result<(), StorageError> {
        self.inner.flush_index()
    }
}

struct BoundedThread<T> {
    name: &'static str,
    handle: JoinHandle<T>,
    done: Receiver<()>,
}

impl<T: Send + 'static> BoundedThread<T> {
    fn spawn(
        name: &'static str,
        body: impl FnOnce() -> T + Send + 'static,
    ) -> anyhow::Result<Self> {
        let (done_tx, done) = mpsc::channel();
        let handle = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                let output = body();
                let _ = done_tx.send(());
                output
            })?;
        Ok(Self { name, handle, done })
    }

    fn finish(self) -> anyhow::Result<T> {
        let name = self.name;
        match self.done.recv_timeout(WITNESS_BOUND) {
            Err(RecvTimeoutError::Timeout) => {
                anyhow::bail!("{name} did not stop within {WITNESS_BOUND:?}")
            }
            Ok(()) | Err(RecvTimeoutError::Disconnected) => self
                .handle
                .join()
                .map_err(|_| anyhow::anyhow!("{name} panicked")),
        }
    }
}

struct ServedWitness {
    stop: Arc<AtomicBool>,
    gate: Option<Arc<BodyGate>>,
    server: Option<BoundedThread<std::io::Result<()>>>,
    client: Option<BoundedThread<anyhow::Result<String>>>,
    client_socket: Option<TcpStream>,
}

impl ServedWitness {
    fn new(stop: Arc<AtomicBool>, gate: Option<Arc<BodyGate>>) -> Self {
        Self {
            stop,
            gate,
            server: None,
            client: None,
            client_socket: None,
        }
    }

    fn serve(
        &mut self,
        server: RpcServer,
        shutdown: bitcoin_rs_chain::LatchReader,
    ) -> anyhow::Result<()> {
        self.server = Some(BoundedThread::spawn("verifychain-rpc-server", move || {
            server.serve_with_shutdown(shutdown)
        })?);
        Ok(())
    }

    fn send(&mut self, addr: SocketAddr) -> anyhow::Result<()> {
        let socket = TcpStream::connect(addr)?;
        socket.set_read_timeout(Some(SOCKET_TIMEOUT))?;
        socket.set_write_timeout(Some(SOCKET_TIMEOUT))?;
        self.client_socket = Some(socket.try_clone()?);
        self.client = Some(BoundedThread::spawn("verifychain-client", move || {
            send_verifychain(socket)
        })?);
        Ok(())
    }

    fn finish_server(&mut self) -> anyhow::Result<()> {
        let Some(server) = self.server.take() else {
            anyhow::bail!("the RPC server was never started");
        };
        server.finish()??;
        Ok(())
    }

    fn finish_client(&mut self) -> anyhow::Result<String> {
        let Some(client) = self.client.take() else {
            anyhow::bail!("the verifychain request was never sent");
        };
        client.finish()?
    }
}

impl Drop for ServedWitness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(server) = self.server.take() {
            let _ = server.finish();
        }
        if let Some(gate) = &self.gate {
            gate.release();
        }
        if let Some(socket) = &self.client_socket {
            let _ = socket.shutdown(Shutdown::Both);
        }
        if let Some(client) = self.client.take() {
            let _ = client.finish();
        }
    }
}

fn send_verifychain(mut socket: TcpStream) -> anyhow::Result<String> {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"verifychain","params":[0,1]}"#;
    write!(
        socket,
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic dXNlcjpwYXNzd29yZA==\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    socket.shutdown(Shutdown::Write)?;
    let mut response = String::new();
    socket.read_to_string(&mut response)?;
    Ok(response)
}

fn assert_socket_error(response: &str, message: &str) -> anyhow::Result<()> {
    use sonic_rs::JsonValueTrait;

    anyhow::ensure!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "a JSON-RPC 2.0 error answers HTTP 200: {response}"
    );
    let (_, payload) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("the reply has no HTTP body: {response}"))?;
    let value: sonic_rs::Value = sonic_rs::from_str(payload)?;
    anyhow::ensure!(
        value.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0"),
        "the reply is not a JSON-RPC 2.0 envelope: {payload}"
    );
    anyhow::ensure!(
        value.get("id").and_then(JsonValueTrait::as_i64) == Some(1),
        "the reply does not echo id 1: {payload}"
    );
    anyhow::ensure!(
        value.get("result").is_none(),
        "the reply carries a result: {payload}"
    );
    let error = value
        .get("error")
        .ok_or_else(|| anyhow::anyhow!("the reply carries no error: {payload}"))?;
    anyhow::ensure!(
        error.get("code").and_then(JsonValueTrait::as_i64) == Some(-1),
        "the error is not Core's misc code -1: {payload}"
    );
    anyhow::ensure!(
        error.get("message").and_then(|v| v.as_str()) == Some(message),
        "the error message is not exactly '{message}': {payload}"
    );
    Ok(())
}

fn apply_regtest_chain(state: &NodeState) -> anyhow::Result<()> {
    let genesis = BlockPayload::from_local(bitcoin_rs_primitives::Network::Regtest.genesis_block());
    state.apply_block(&genesis)?;
    let mut previous = genesis.block().block_hash();
    for height in 1..=3 {
        let block = BlockPayload::from_local(
            bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at(previous, height)?,
        );
        state.apply_block(&block)?;
        previous = block.block().block_hash();
    }
    Ok(())
}

fn bind_test_rpc(state: &NodeState) -> anyhow::Result<RpcServer> {
    let coordinator = Arc::new(crate::MiningCoordinator::new(
        state.mempool_reader(),
        state.chainstate(),
        state.stable_read(),
        state.chain_followers(),
        state.config().mining.payout_script.clone(),
    ));
    let mining_control: Arc<dyn bitcoin_rs_mining::MiningControl> = coordinator;
    let mut bindings = bind_rpc(state, &mining_control, state.block_body_source()?)?;
    assert_eq!(bindings.listeners.len(), 1);
    Ok(bindings.listeners.remove(0).0)
}

#[test]
fn verifychain_socket_cancels_in_flight_walk_on_node_shutdown() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let gate = Arc::new(BodyGate::new());
    let state = NodeState::open_with_body_store(isolated_config(dir.path()), None, {
        let gate = Arc::clone(&gate);
        move |store| {
            let wrapped: Arc<dyn BlockBodyStore> = Arc::new(HoldingBodies { inner: store, gate });
            wrapped
        }
    })?;
    apply_regtest_chain(&state)?;
    let server = bind_test_rpc(&state)?;
    let addr = server.local_addr()?;

    gate.arm();
    let mut witness = ServedWitness::new(
        state.chainstate().shutdown_handle(),
        Some(Arc::clone(&gate)),
    );
    witness.serve(server, state.shutdown_reader())?;
    witness.send(addr)?;

    anyhow::ensure!(
        gate.wait_entered(WITNESS_BOUND),
        "the verifier never reached the held body read"
    );
    state.request_shutdown();
    witness.finish_server()?;
    gate.release();
    let response = witness.finish_client()?;
    assert_socket_error(&response, "Block verification interrupted")
}

#[test]
fn verifychain_socket_reports_recovery_closure() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let state = NodeState::open(isolated_config(dir.path()), None)?;
    apply_regtest_chain(&state)?;
    let server = bind_test_rpc(&state)?;
    let addr = server.local_addr()?;

    let latch = Arc::new(AtomicBool::new(false));
    let mut witness = ServedWitness::new(Arc::clone(&latch), None);
    witness.serve(
        server,
        bitcoin_rs_chain::LatchReader::new(Arc::clone(&latch)),
    )?;
    state.chainstate().fail_closed_for_recovery();
    witness.send(addr)?;
    let response = witness.finish_client()?;
    latch.store(true, Ordering::Release);
    witness.finish_server()?;
    assert_socket_error(&response, "Chainstate is unavailable for verification")
}
