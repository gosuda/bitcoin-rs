use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::*;
use crate::config::{NodeConfig, RuntimeInputs};
use crate::lifecycle::startup::start_node;
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

fn seed_checkpoint(state: &NodeState) -> anyhow::Result<(PathBuf, Vec<u8>)> {
    state.apply_block(&bitcoin_rs_primitives::Network::Regtest.genesis_block())?;
    state.write_clean_checkpoint()?;
    let current = state
        .data_dir()
        .join("chainstate-checkpoints")
        .join("CURRENT");
    let previous = std::fs::read(&current)?;
    Ok((current, previous))
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn disabled_zmq_still_seals_the_observer_slot() {
    let pool = Arc::new(parking_lot::RwLock::new(bitcoin_rs_mempool::Mempool::new(
        bitcoin_rs_mempool::MempoolLimits::default(),
    )));
    let observer: Arc<dyn bitcoin_rs_mempool::MempoolObserver> =
        Arc::new(bitcoin_rs_mempool::CompositeObserver::new());
    let gateway = bitcoin_rs_mempool::MempoolGateway::shared_with(pool, observer);
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
    let mut config = isolated_config(&temp.path().join("node"));
    config.p2p.connect = vec!["127.0.0.1:1".to_owned()];
    let state = NodeState::open(config.clone(), None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    drop(state);

    let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
    shutdown_tx.send(())?;
    crate::checkpoint::inject_next_checkpoint_failpoint(
        crate::checkpoint::CheckpointFailpoint::ManifestWrite,
    );
    assert!(run(config, RuntimeInputs::default().with_shutdown(shutdown_rx)).is_err());
    assert_eq!(std::fs::read(current)?, previous);
    assert!(
        bootstrap_drain_was_reached(),
        "checkpoint errors must not bypass the bootstrap-worker join"
    );
    Ok(())
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn teardown_join_failure_completes_cleanup_and_suppresses_checkpoint() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let config = isolated_config(&temp.path().join("node-join-failure"));
    let state = NodeState::open(config.clone(), None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    let panicker = std::thread::Builder::new()
        .name("bitcoin-rs-outbound-drain".to_owned())
        .spawn(|| panic!("injected worker panic"))?;
    let mut services = NodeServices::default();
    services.outbound_worker = Some(panicker);

    assert!(
        services
            .teardown(Some(&state), TeardownMode::CleanShutdown)
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
    let state = NodeState::open(config, None)?;
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
    services.bootstrap_worker = Some(worker);
    let started = std::time::Instant::now();
    services.teardown(Some(&state), TeardownMode::CleanShutdown)?;
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
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn late_bootstrap_panic_suppresses_checkpoint() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let config = isolated_config(&temp.path().join("node-late-failure"));
    let state = NodeState::open(config, None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    let panicker = std::thread::Builder::new()
        .name("bitcoin-rs-p2p-bootstrap".to_owned())
        .spawn(|| panic!("injected bootstrap panic"))?;
    let mut services = NodeServices::default();
    services.bootstrap_worker = Some(panicker);
    crate::checkpoint::inject_next_checkpoint_failpoint(
        crate::checkpoint::CheckpointFailpoint::ManifestWrite,
    );
    assert!(
        services
            .teardown(Some(&state), TeardownMode::CleanShutdown)
            .is_err()
    );
    assert!(bootstrap_drain_was_reached());
    assert_eq!(std::fs::read(current)?, previous);
    assert!(state.write_clean_checkpoint().is_err());
    drop(services);
    drop(state);
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

    let reopen_config = isolated_config(&temp.path().join("embedded"));
    let node = start_node(reopen_config, RuntimeInputs::default(), true)?;
    node.shutdown_blocking()?;
    assert_eq!(
        crate::signal::testing::installed_total(),
        installed_before + 2
    );
    assert_eq!(crate::signal::testing::closed_total(), closed_before + 2);
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
    let shutdown_flag = state.shutdown();
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

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn startup_returns_an_owned_node_not_detached_parts() {
    let _: fn(NodeConfig, RuntimeInputs, bool) -> anyhow::Result<crate::embed::Node> = start_node;
}
