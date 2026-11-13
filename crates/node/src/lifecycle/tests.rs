use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_consensus::primitives::{BlockBodyMetadata, BlockImage, Hash256};
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
use crate::run::{RunError, run};
use crate::test_support::TestError;

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
fn split_rpc_listeners_start_and_join_through_node_services() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut config = isolated_config(dir.path());
    config.rpc.bind = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    config.rpc.public_bind = Some(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    let node = start_node(config, RuntimeInputs::default(), false)?;
    let services = node
        .services
        .as_ref()
        .ok_or(TestError::Missing("node services"))?;
    assert_eq!(services.rpc_threads.len(), 2);
    let management_address = services
        .rpc_address(bitcoin_rs_serving::RpcSurface::Management)
        .ok_or(TestError::Missing("management address"))?;
    let public_address = services
        .rpc_address(bitcoin_rs_serving::RpcSurface::Public)
        .ok_or(TestError::Missing("public address"))?;
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
    Ok(())
}

#[test]
fn public_bind_failure_rolls_back_management_binding_and_node_state() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut config = isolated_config(dir.path());
    let public = std::net::TcpListener::bind("127.0.0.1:0")?;
    let public_address = public.local_addr()?;
    config.rpc.bind = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    config.rpc.public_bind = Some(public_address);
    let error = match start_node(config.clone(), RuntimeInputs::default(), false) {
        Ok(_) => {
            return Err(TestError::UnexpectedSuccess(
                "occupied public bind succeeded",
            ));
        }
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        format!("failed to bind public HTTP listener at {public_address}")
    );
    let RunError::PublicRpcBind { source, .. } = &error else {
        panic!("expected RunError::PublicRpcBind, got: {error:?}");
    };
    assert_eq!(source.kind(), std::io::ErrorKind::AddrInUse);
    let _reopened = NodeState::open(config, None)?;
    Ok(())
}

#[test]
fn timed_out_snapshot_worker_cannot_overwrite_the_next_runs_snapshot() -> Result<(), TestError> {
    use bitcoin_rs_consensus::primitives::{Hash256, Network, Txid};
    use bitcoin_rs_mempool::{Mempool, MempoolGateway, MempoolLimits, snapshot};
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
    let _ = release_tx.send(());
    worker.join().map_err(|_| TestError::ThreadPanicked)?;
    assert!(
        prepared,
        "the delayed worker must hold a valid old snapshot"
    );
    assert_eq!(std::fs::read(&file)?, newer);
    assert_eq!(std::fs::read_dir(dir.path())?.count(), 1);
    Ok(())
}

#[test]
fn rpc_network_handles_borrow_p2p_service_state() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let state = NodeState::open(isolated_config(dir.path()), None)?;
    let p2p = state.p2p();
    let handles = rpc_network_handles(&state);

    assert!(Arc::ptr_eq(&handles.peer_table, &p2p.table()));
    assert!(Arc::ptr_eq(&handles.p2p, &p2p));
    assert_eq!(handles.local_services, p2p.local_services().to_u64());
    assert_eq!(handles.v2_transport, state.config().p2p.v2_transport);
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
fn verify_chain_accepts_an_intact_applied_chain_at_every_level_and_depth() -> Result<(), TestError>
{
    let dir = tempfile::tempdir()?;
    let state = NodeState::open(isolated_config(dir.path()), None)?;
    let genesis =
        BlockImage::from_local(bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block());
    state.apply_block(&genesis)?;
    let mut previous = genesis.block_hash();
    for height in 1..=3 {
        let block = BlockImage::from_local(
            bitcoin_rs_execution::chain::regtest_fixture::mined_regtest_child_at(previous, height)?,
        );
        state.apply_block(&block)?;
        previous = block.block_hash();
    }
    let control = RpcChainControl {
        handles: state.chainstate(),
        followers: state.chain_followers(),
        sync: state.sync(),
        snapshots: Arc::clone(&state.snapshots),
    };
    let cancellation = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
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

#[test]
fn verify_chain_over_applied_genesis_is_answered_by_the_real_verifier() -> Result<(), TestError> {
    use bitcoin_rs_serving::context::ChainControlError;

    let dir = tempfile::tempdir()?;
    let state = NodeState::open(isolated_config(dir.path()), None)?;
    state.apply_block(&BlockImage::from_local(
        bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
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
    let live = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
    for check_level in 0..=4 {
        for nblocks in [0, 1, 6] {
            assert!(
                matches!(control.verify_chain(check_level, nblocks, &live), Ok(true)),
                "level {check_level}, {nblocks} blocks"
            );
        }
    }
    state.chainstate().fail_closed_for_recovery();
    assert!(matches!(
        control.verify_chain(3, 6, &live),
        Err(ChainControlError::Unavailable)
    ));
    Ok(())
}

#[test]
fn verify_chain_reports_cancellation_and_recovery_closure() -> Result<(), TestError> {
    use bitcoin_rs_serving::context::ChainControlError;

    let dir = tempfile::tempdir()?;
    let state = NodeState::open(isolated_config(dir.path()), None)?;
    let control = RpcChainControl {
        handles: state.chainstate(),
        followers: state.chain_followers(),
        sync: state.sync(),
        snapshots: Arc::clone(&state.snapshots),
    };
    let live = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
    assert!(
        matches!(control.verify_chain(3, 6, &live), Ok(true)),
        "an open chain must verify"
    );
    let fired = {
        let trigger = bitcoin_rs_consensus::latch::LatchWriter::new();
        trigger.trigger();
        trigger.reader()
    };
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

#[test]
fn rpc_load_txoutset_follows_core_import_behavior_independent_of_filename() -> Result<(), TestError>
{
    use bitcoin_rs_execution::manifest::{ARTIFACT_SLOTS, SnapshotManifest, UTXO_SLOT};
    use sha2::Digest;

    let pinned = bitcoin_rs_consensus::primitives::Network::Regtest
        .assume_utxo_for_height(200)
        .ok_or(TestError::Missing("regtest height-200 anchor"))?;
    let dir = tempfile::tempdir()?;
    let mut config = isolated_config(dir.path());
    config.data_dir = dir.path().join("node");
    let state = NodeState::open(config, None)?;
    state.apply_block(&BlockImage::from_local(
        bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
    ))?;
    let headers: Vec<bitcoin_rs_consensus::primitives::Header> = sonic_rs::from_str::<Vec<String>>(
        include_str!("../../../storage/tests/fixtures/core-v2/blocks200.json"),
    )?
    .iter()
    .map(|hex| {
        let block: bitcoin::Block = bitcoin::consensus::encode::deserialize_hex(hex)?;
        bitcoin_rs_consensus::primitives::deserialize(&bitcoin::consensus::serialize(&block.header))
            .map_err(TestError::from)
    })
    .collect::<Result<_, _>>()?;
    state.chainstate().admit_headers(&headers)?;
    let core_bytes =
        include_bytes!("../../../storage/tests/fixtures/core-v2/core200.dat").as_slice();

    let applied_tip = || {
        state
            .chainstate()
            .applied_tip_snapshot()
            .map(|tip| tip.height)
    };
    assert_eq!(applied_tip(), Some(0));

    let control = RpcChainControl {
        handles: state.chainstate(),
        followers: state.chain_followers(),
        sync: state.sync(),
        snapshots: Arc::clone(&state.snapshots),
    };

    let mut sizes = [0_u64; ARTIFACT_SLOTS];
    let mut hashes = [[0_u8; 32]; ARTIFACT_SLOTS];
    sizes[UTXO_SLOT] = u64::try_from(core_bytes.len()).map_err(std::io::Error::other)?;
    hashes[UTXO_SLOT] = sha2::Sha256::digest(core_bytes).into();
    let manifest = SnapshotManifest {
        manifest_version: 1,
        network: "regtest".to_string(),
        genesis: bitcoin_rs_consensus::primitives::Network::Regtest
            .genesis_block_hash()
            .to_le_bytes(),
        base_hash: pinned.block_hash.to_le_bytes(),
        base_height: pinned.height,
        schema: bitcoin_rs_projection::index_format_version(),
        utxo_commitment: pinned.hash_serialized.to_le_bytes(),
        index_commitments: [None; 4],
        coverage: [None; 4],
        sizes,
        hashes,
        historical_verified_height: 0,
    };
    let manifest_path = dir.path().join("snapshot_manifest.json");
    std::fs::write(&manifest_path, sonic_rs::to_vec_pretty(&manifest)?)?;

    assert!(
        control.load_txoutset(&manifest_path).is_err(),
        "a valid manifest JSON must not activate through the RPC surface"
    );
    assert_eq!(
        applied_tip(),
        Some(0),
        "the refused manifest attempt must install nothing"
    );

    let renamed = dir.path().join("core200.json");
    std::fs::write(&renamed, core_bytes)?;
    let imported = control.load_txoutset(&renamed)?;
    assert_eq!(imported.base_height, 200);
    assert_eq!(
        applied_tip(),
        Some(200),
        "a Core binary named .json must follow the same Core import behavior as extensionless"
    );
    Ok(())
}

fn seed_checkpoint(state: &NodeState) -> Result<(PathBuf, Vec<u8>), TestError> {
    state.apply_block(&BlockImage::from_local(
        bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
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
fn disabled_zmq_still_seals_the_observer_slot() {
    let pool = Arc::new(parking_lot::RwLock::new(bitcoin_rs_mempool::Mempool::new(
        bitcoin_rs_mempool::MempoolLimits::default(),
    )));
    let observer: Arc<dyn bitcoin_rs_mempool::MempoolObserver> =
        Arc::new(bitcoin_rs_mempool::CompositeObserver::new());
    let gateway = Arc::new(bitcoin_rs_mempool::MempoolGateway::new(
        pool,
        Some((observer, bitcoin_rs_mempool::BodyInterest::Metadata)),
        ValidationEngine::Native,
        None,
    ));
    assert!(
        gateway.has_observer(),
        "startup must seal the observer slot even without a ZMQ endpoint"
    );
}

#[test]
fn clean_shutdown_publishes_checkpoint_and_returns_success() -> Result<(), TestError> {
    let temp = tempfile::tempdir()?;
    let config = isolated_config(&temp.path().join("node-success"));
    let state = NodeState::open(config.clone(), None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    drop(state);

    let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
    let _ = shutdown_tx.send(());
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
fn shutdown_checkpoint_io_failure_is_returned_and_preserves_current() -> Result<(), TestError> {
    let temp = tempfile::tempdir()?;
    let mut config = isolated_config(&temp.path().join("node-checkpoint-failure"));
    config.p2p.connect = vec!["127.0.0.1:1".to_owned()];
    let state = NodeState::open(config.clone(), None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    drop(state);

    let checkpoint_root = current
        .parent()
        .ok_or(TestError::Missing("checkpoint parent directory"))?
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
    shutdown_tx
        .send(())
        .map_err(|_| TestError::ExpectationFailed("shutdown receiver is live"))?;
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

// EMB-01
#[test]
fn teardown_join_failure_completes_cleanup_and_suppresses_checkpoint() -> Result<(), TestError> {
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
fn teardown_joins_bootstrap_worker_beyond_former_deadline() -> Result<(), TestError> {
    let temp = tempfile::tempdir()?;
    let config = isolated_config(&temp.path().join("node-slow-bootstrap"));
    let mut state = NodeState::open(config, None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    let (_gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
    let (exited_tx, exited_rx) = std::sync::mpsc::channel();
    let worker = std::thread::Builder::new()
        .name("bitcoin-rs-wire-bootstrap".to_owned())
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
fn teardown_metrics_panic_reports_failure_and_preserves_checkpoint() -> Result<(), TestError> {
    let temp = tempfile::tempdir()?;
    let mut state = NodeState::open(isolated_config(temp.path()), None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    let worker = std::thread::Builder::new()
        .name("bitcoin-rs-metrics".to_owned())
        .spawn(|| panic!("injected scrape worker panic"))?;
    let mut services = NodeServices::default();
    services.metrics = Some(crate::metrics::MetricsServer::with_worker_for_test(worker));

    let Err(error) = services.teardown(Some(&mut state), TeardownMode::CleanShutdown) else {
        return Err(TestError::UnexpectedSuccess(
            "teardown with panicked metrics succeeded",
        ));
    };
    assert!(
        matches!(error, RunError::MetricsScrapeThreadPanicked),
        "{error:?}"
    );
    assert_eq!(shutdown::take_shutdown_stages_reached(), 1);
    assert!(bootstrap_drain_was_reached());
    assert_eq!(std::fs::read(&current)?, previous);
    assert!(services.metrics.is_none());
    services.teardown(Some(&mut state), TeardownMode::CleanShutdown)?;
    assert_eq!(shutdown::take_shutdown_stages_reached(), 0);
    assert_eq!(std::fs::read(current)?, previous);
    Ok(())
}

// EMB-01
#[test]
fn daemon_and_embedded_paths_share_one_teardown() -> Result<(), TestError> {
    let temp = tempfile::tempdir()?;
    let daemon_config = isolated_config(&temp.path().join("daemon"));
    let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
    let _ = shutdown_tx.send(());
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
fn repeated_teardown_and_drop_join_workers_once() -> Result<(), TestError> {
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
fn startup_rollback_joins_workers_and_preserves_checkpoint() -> Result<(), TestError> {
    let temp = tempfile::tempdir()?;
    let config = isolated_config(&temp.path().join("startup-rollback"));
    let state = NodeState::open(config.clone(), None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    let shutdown = state.chainstate().shutdown_reader();
    let exited = Arc::new(AtomicBool::new(false));
    let worker_exited = Arc::clone(&exited);
    let worker = std::thread::spawn(move || {
        while !shutdown.is_triggered() {
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
fn explicit_shutdown_joins_index_worker_before_clean_checkpoint() -> Result<(), TestError> {
    let temp = tempfile::tempdir()?;
    let mut config = isolated_config(&temp.path().join("node-index-join"));
    config.indexes.txindex = true;
    let node = start_node(config, RuntimeInputs::default(), true)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while matches!(
        node.state.derived_index_status().capability().state,
        bitcoin_rs_projection::CapabilityState::Opening
    ) {
        assert!(
            std::time::Instant::now() < deadline,
            "txindex lifecycle remained Opening"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
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

// EMB-09
#[test]
fn a_queued_shutdown_wake_does_not_block_teardown() -> Result<(), TestError> {
    let temp = tempfile::tempdir()?;
    let config = isolated_config(&temp.path().join("node-forwarder"));
    let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
    let node = start_node(
        config.clone(),
        RuntimeInputs::default().with_shutdown(shutdown_rx),
        false,
    )?;

    node.shutdown_blocking()?;

    let reopened = NodeState::open(config, None)?;
    drop(reopened);
    drop(shutdown_tx);
    Ok(())
}

// EMB-01
#[test]
fn recovery_closure_stops_the_node_run_loop() -> Result<(), TestError> {
    let temp = tempfile::tempdir()?;
    let config = isolated_config(&temp.path().join("node-recovery-exit"));
    let node = start_node(config, RuntimeInputs::default(), false)?;

    node.state.chainstate().fail_closed_for_recovery();

    let deadline = std::time::Instant::now() + WITNESS_BOUND;
    loop {
        let exited = node
            .services
            .as_ref()
            .and_then(|services| services.event_loop.as_ref())
            .is_some_and(|handle| handle.is_finished());
        if exited {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the event loop kept running after a chainstate recovery closure"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        node.state.shutdown_reader().is_triggered(),
        "a recovery closure must raise the node shutdown latch"
    );

    match node.shutdown_blocking() {
        Err(crate::embed::NodeError::ClosedForRecovery) => {}
        other => panic!("a recovery closure must not tear down as a clean shutdown: {other:?}"),
    }
    Ok(())
}

// SYNC-04
#[test]
fn fatal_settlement_teardown_skips_the_checkpoint_and_answers_an_error() -> Result<(), TestError> {
    type CloseChain = Box<dyn Fn(&bitcoin_rs_execution::Chainstate)>;
    let variants: Vec<(&str, CloseChain)> = vec![
        (
            "fatal-settlement",
            Box::new(|chain: &bitcoin_rs_execution::Chainstate| chain.fail_closed_for_recovery()),
        ),
        (
            "graceful-close",
            Box::new(|chain: &bitcoin_rs_execution::Chainstate| {
                drop(chain.close());
            }),
        ),
    ];
    for (variant, close) in variants {
        let temp = tempfile::tempdir()?;
        let config = isolated_config(&temp.path().join(variant));
        let state = NodeState::open(config.clone(), None)?;
        let (current, previous) = seed_checkpoint(&state)?;
        drop(state);

        let node = start_node(config.clone(), RuntimeInputs::default(), false)?;
        let chain = node.state.chainstate();
        close(&chain);
        drop(chain);
        let deadline = std::time::Instant::now() + WITNESS_BOUND;
        loop {
            let exited = node
                .services
                .as_ref()
                .and_then(|services| services.event_loop.as_ref())
                .is_some_and(|handle| handle.is_finished());
            if exited {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the event loop kept running after the chainstate closure"
            );
            thread::sleep(Duration::from_millis(10));
        }

        match node.shutdown_blocking() {
            Err(crate::embed::NodeError::ClosedForRecovery) => {}
            other => {
                panic!("a closed chainstate must not tear down as a clean shutdown: {other:?}")
            }
        }
        assert_eq!(
            std::fs::read(&current)?,
            previous,
            "the closed chainstate must not publish a fresh checkpoint"
        );
        let reopened = NodeState::open(config, None)?;
        assert_eq!(
            reopened.resume_source(),
            crate::state::ResumeSource::Checkpoint,
            "restart must replay from the checkpoint published before the closure"
        );
    }
    Ok(())
}

// SYNC-04
#[test]
fn recovery_closure_during_teardown_skips_the_checkpoint_and_answers_an_error()
-> Result<(), TestError> {
    let temp = tempfile::tempdir()?;
    let config = isolated_config(&temp.path().join("node-recovery-recheck"));
    let state = NodeState::open(config.clone(), None)?;
    let (current, previous) = seed_checkpoint(&state)?;
    let snapshot = state.data_dir().join("mempool-snapshot.dat");
    assert!(
        !snapshot.exists(),
        "the fixture must not start from a stored mempool snapshot"
    );
    drop(state);

    let node = start_node(config, RuntimeInputs::default(), false)?;
    let chain = node.state.chainstate();
    inject_before_recovery_recheck(move || chain.fail_closed_for_recovery());

    match node.shutdown_blocking() {
        Err(crate::embed::NodeError::ClosedForRecovery) => {}
        other => panic!(
            "a chainstate closed while teardown joins its workers must not exit cleanly: {other:?}"
        ),
    }
    assert_eq!(
        std::fs::read(&current)?,
        previous,
        "a chainstate closed during teardown must not publish a fresh checkpoint"
    );
    assert!(
        !snapshot.exists(),
        "a chainstate closed during teardown must not save the mempool snapshot"
    );
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
    ) -> Result<Self, TestError> {
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

    fn finish(self) -> Result<T, TestError> {
        let name = self.name;
        match self.done.recv_timeout(WITNESS_BOUND) {
            Err(RecvTimeoutError::Timeout) => Err(TestError::Timeout(name)),
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                self.handle.join().map_err(|_| TestError::ThreadPanicked)
            }
        }
    }
}

struct ServedWitness {
    stop: Box<dyn Fn() + Send>,
    gate: Option<Arc<BodyGate>>,
    server: Option<BoundedThread<std::io::Result<()>>>,
    client: Option<BoundedThread<Result<String, TestError>>>,
    client_socket: Option<TcpStream>,
}

impl ServedWitness {
    fn new(stop: impl Fn() + Send + 'static, gate: Option<Arc<BodyGate>>) -> Self {
        Self {
            stop: Box::new(stop),
            gate,
            server: None,
            client: None,
            client_socket: None,
        }
    }

    fn serve(
        &mut self,
        server: RpcServer,
        shutdown: bitcoin_rs_consensus::latch::LatchReader,
    ) -> Result<(), TestError> {
        self.server = Some(BoundedThread::spawn("verifychain-rpc-server", move || {
            server.serve_with_shutdown(shutdown)
        })?);
        Ok(())
    }

    fn send(&mut self, addr: SocketAddr) -> Result<(), TestError> {
        let socket = TcpStream::connect(addr)?;
        socket.set_read_timeout(Some(SOCKET_TIMEOUT))?;
        socket.set_write_timeout(Some(SOCKET_TIMEOUT))?;
        self.client_socket = Some(socket.try_clone()?);
        self.client = Some(BoundedThread::spawn("verifychain-client", move || {
            send_verifychain(socket)
        })?);
        Ok(())
    }

    fn finish_server(&mut self) -> Result<(), TestError> {
        let Some(server) = self.server.take() else {
            return Err(TestError::Missing("RPC server"));
        };
        server.finish()??;
        Ok(())
    }

    fn finish_client(&mut self) -> Result<String, TestError> {
        let Some(client) = self.client.take() else {
            return Err(TestError::Missing("verifychain request"));
        };
        client.finish()?
    }
}

impl Drop for ServedWitness {
    fn drop(&mut self) {
        (self.stop)();
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

fn send_verifychain(mut socket: TcpStream) -> Result<String, TestError> {
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

fn assert_socket_error(response: &str, message: &str) -> Result<(), TestError> {
    use sonic_rs::JsonValueTrait;

    if !response.starts_with("HTTP/1.1 200 OK\r\n") {
        return Err(TestError::ExpectationFailed(
            "a JSON-RPC 2.0 error answers HTTP 200",
        ));
    }
    let (_, payload) = response
        .split_once("\r\n\r\n")
        .ok_or(TestError::Missing("HTTP response body"))?;
    let value: sonic_rs::Value = sonic_rs::from_str(payload)?;
    if value.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return Err(TestError::ExpectationFailed(
            "the reply is not a JSON-RPC 2.0 envelope",
        ));
    }
    if value.get("id").and_then(JsonValueTrait::as_i64) != Some(1) {
        return Err(TestError::ExpectationFailed("the reply does not echo id 1"));
    }
    if value.get("result").is_some() {
        return Err(TestError::ExpectationFailed("the reply carries a result"));
    }
    let error = value
        .get("error")
        .ok_or(TestError::Missing("JSON-RPC error payload"))?;
    if error.get("code").and_then(JsonValueTrait::as_i64) != Some(-1) {
        return Err(TestError::ExpectationFailed(
            "the error is not Core's misc code -1",
        ));
    }
    if error.get("message").and_then(|v| v.as_str()) != Some(message) {
        return Err(TestError::ExpectationFailed(
            "the error message is not as expected",
        ));
    }
    Ok(())
}

fn apply_regtest_chain(state: &NodeState) -> Result<(), TestError> {
    let genesis =
        BlockImage::from_local(bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block());
    state.apply_block(&genesis)?;
    let mut previous = genesis.block_hash();
    for height in 1..=3 {
        let block = BlockImage::from_local(
            bitcoin_rs_execution::chain::regtest_fixture::mined_regtest_child_at(previous, height)?,
        );
        state.apply_block(&block)?;
        previous = block.block_hash();
    }
    Ok(())
}

fn bind_test_rpc(state: &NodeState) -> Result<RpcServer, TestError> {
    let coordinator = Arc::new(crate::MiningCoordinator::new(
        state.mempool_reader(),
        state.chainstate(),
        state.stable_read(),
        state.chain_followers(),
        super::final_payout_script(state.config()),
    ));
    let mining_control: Arc<dyn bitcoin_rs_serving::mining::MiningControl> = coordinator;
    let mut bindings = bind_rpc(state, &mining_control, state.block_body_source()?)?;
    assert_eq!(bindings.listeners.len(), 1);
    Ok(bindings.listeners.remove(0).0)
}
#[cfg(feature = "pool")]
#[test]
fn final_payout_script_prefers_pool_when_values_differ() {
    use crate::config::PoolConfig;

    let mut config = NodeConfig::default_for_network(crate::Network::Regtest);
    config.mining.payout_script = vec![0x51];
    let pool = PoolConfig {
        datadir: std::path::PathBuf::from("/tmp/btcrs-pool-regression"),
        v1_bind: None,
        sv2_bind: None,
        sv2_authority_key: None,
        allow_non_loopback: false,
        max_connections: 1,
        max_connections_per_ip: 1,
        share_difficulty: String::from("1"),
        share_target: bitcoin_rs_serving::mining::pool::ShareTarget::from_pool_difficulty_decimal(
            "1",
        )
        .unwrap_or_else(|error| panic!("fixed test difficulty parses: {error}")),
        window_work: 1,
        fee_bps: 0,
        reward_script: vec![0x52],
        maturity: 100,
        payout_confirmations: 1,
        reorg_watch_depth: 100,
        min_payout_sat: 546,
        max_payout_outputs: 1,
    };
    config.pool = Some(pool);
    assert_eq!(super::final_payout_script(&config), vec![0x52]);
    config.pool = None;
    assert_eq!(super::final_payout_script(&config), vec![0x51]);
}

#[test]
fn verifychain_socket_cancels_in_flight_walk_on_node_shutdown() -> Result<(), TestError> {
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
    let chainstate = state.chainstate();
    let mut witness = ServedWitness::new(
        move || chainstate.request_shutdown(),
        Some(Arc::clone(&gate)),
    );
    witness.serve(server, state.shutdown_reader())?;
    witness.send(addr)?;

    if !gate.wait_entered(WITNESS_BOUND) {
        return Err(TestError::Timeout(
            "the verifier never reached the held body read",
        ));
    }
    state.request_shutdown();
    gate.release();
    witness.finish_server()?;
    let response = witness.finish_client()?;
    assert_socket_error(&response, "Block verification interrupted")
}

#[test]
fn verifychain_socket_reports_recovery_closure() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let state = NodeState::open(isolated_config(dir.path()), None)?;
    apply_regtest_chain(&state)?;
    let server = bind_test_rpc(&state)?;
    let addr = server.local_addr()?;

    let stop = Arc::new(bitcoin_rs_consensus::latch::LatchWriter::new());
    let mut witness = ServedWitness::new(
        {
            let stop = Arc::clone(&stop);
            move || stop.trigger()
        },
        None,
    );
    witness.serve(server, stop.reader())?;
    state.chainstate().fail_closed_for_recovery();
    witness.send(addr)?;
    let response = witness.finish_client()?;
    stop.trigger();
    witness.finish_server()?;
    assert_socket_error(&response, "Chainstate is unavailable for verification")
}
