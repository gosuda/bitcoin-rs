use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::*;
use crate::config::{NodeConfig, RuntimeInputs};
use crate::run::{run, start_node};

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
fn shutdown_checkpoint_io_failure_is_returned_and_preserves_current() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let mut config = isolated_config(&temp.path().join("node"));
    // Exercise the real P2pService bootstrap join, not a copied DNS loop.
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
fn teardown_joins_bootstrap_worker_beyond_former_deadline() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let config = isolated_config(&temp.path().join("node-slow-bootstrap"));
    let state = NodeState::open(config, None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    // Keep the gate sender alive: timeout is twice the former abandon limit.
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
    // A failed join must not even attempt checkpoint publication.
    assert!(state.write_clean_checkpoint().is_err());
    drop(services);
    drop(state);
    Ok(())
}

#[test]
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
    let (state, services, context) = start_node(embedded_config, RuntimeInputs::default(), true)?;
    let node = crate::embed::node_from_parts(state, services, context);
    node.shutdown_blocking()?;
    assert_eq!(shutdown::take_shutdown_stages_reached(), 1);
    assert_eq!(
        crate::signal::testing::installed_total(),
        installed_before + 1
    );
    assert_eq!(crate::signal::testing::closed_total(), closed_before + 1);

    // A second lifecycle must neither leak nor reuse the first handler.
    let reopen_config = isolated_config(&temp.path().join("embedded"));
    let (state, services, context) = start_node(reopen_config, RuntimeInputs::default(), true)?;
    let node = crate::embed::node_from_parts(state, services, context);
    node.shutdown_blocking()?;
    assert_eq!(
        crate::signal::testing::installed_total(),
        installed_before + 2
    );
    assert_eq!(crate::signal::testing::closed_total(), closed_before + 2);
    Ok(())
}

#[test]
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
