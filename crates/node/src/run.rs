//! Top-level orchestration: wire subsystems, spin the event loop, drain.

use crate as bitcoin_rs_node;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::Result;
use crossbeam_channel::{Receiver, bounded};

use crate::config::Config;
use crate::event_loop::EventLoop;
use crate::state::NodeState;
use crate::{crash_recovery, logging, shutdown};

const DRAIN_DEADLINE: Duration = Duration::from_secs(5);
const RPC_MAX_CONNECTIONS: usize = 128;
const RPC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

fn build_rpc_auth(node_auth: &crate::Auth) -> Result<bitcoin_rs_rpc::Auth> {
    match node_auth {
        crate::Auth::Basic { user, password } => {
            Ok(bitcoin_rs_rpc::Auth::basic(user.clone(), password))
        }
        crate::Auth::Cookie { path } => Ok(bitcoin_rs_rpc::Auth::cookie(path)?),
    }
}

fn spawn_electrum_listener(
    config: &bitcoin_rs_node::Config,
    shutdown: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> anyhow::Result<Option<std::thread::JoinHandle<Result<(), bitcoin_rs_electrum::ElectrumError>>>>
{
    let Some(addr) = config.electrum_bind else {
        return Ok(None);
    };

    if let Some(cert) = &config.electrum_tls_cert {
        tracing::warn!(
            cert = %cert.display(),
            "electrum TLS cert configured but TLS wiring deferred; serving plaintext"
        );
    }

    let index = bitcoin_rs_electrum::IndexHandle::new();
    let mempool = bitcoin_rs_electrum::MempoolHandle::default();
    let cfg = bitcoin_rs_electrum::ServerConfig::default();
    let server = bitcoin_rs_electrum::ElectrumServer::bind(addr, index, mempool, cfg)
        .map_err(anyhow::Error::from)?;
    let local_addr = server.local_addr()?;
    tracing::info!(addr = %local_addr, "electrum listener bound");

    let electrum_shutdown = Arc::clone(shutdown);
    Ok(Some(
        std::thread::Builder::new()
            .name("bitcoin-rs-electrum".into())
            .spawn(move || server.run_with_shutdown(electrum_shutdown))?,
    ))
}

fn spawn_p2p_listeners(
    config: &bitcoin_rs_node::Config,
    shutdown: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> anyhow::Result<Vec<std::thread::JoinHandle<Result<(), bitcoin_rs_p2p::listener::ListenerError>>>>
{
    let mut handles = Vec::with_capacity(config.p2p_listen.len());
    let magic = bitcoin::p2p::Magic::from_bytes(config.network.magic());
    for addr in &config.p2p_listen {
        let listener_addr = *addr;
        let listener_shutdown = std::sync::Arc::clone(shutdown);
        let handle = std::thread::Builder::new()
            .name(format!("bitcoin-rs-p2p-{listener_addr}"))
            .spawn(move || {
                bitcoin_rs_p2p::listener::serve_with_shutdown(
                    listener_addr,
                    listener_shutdown,
                    magic,
                )
            })?;
        tracing::info!(addr = %listener_addr, "p2p listener bound");
        handles.push(handle);
    }
    Ok(handles)
}

/// Boots the node from a resolved [`Config`] and runs until shutdown.
///
/// Flow:
/// 1. Install JSON tracing on stderr.
/// 2. Open / create the node data directory and resolve state.
/// 3. Run crash recovery against the persisted sidecar.
/// 4. Acquire a shutdown signal — either the in-process receiver wired via
///    [`Config::with_shutdown_receiver`] (tests) or a fresh SIGINT/SIGTERM
///    handler (production).
/// 5. Spin the event loop until shutdown is requested.
/// 6. Drain subsystems within [`DRAIN_DEADLINE`].
pub fn run(mut config: Config) -> Result<()> {
    logging::install_tracing(&config.log_level)?;

    let injected_shutdown = config.shutdown_signal.take();
    let state = NodeState::open(config)?;
    crash_recovery::recover_if_needed(&state)?;

    tracing::info!(
        network = ?state.config().network,
        data_dir = %state.data_dir().display(),
        storage_backend = %state.config().storage_backend,
        "bitcoin-rs node booting"
    );

    let shutdown_rx: Receiver<()> = if let Some(rx) = injected_shutdown {
        rx
    } else {
        let (tx, rx) = bounded(1);
        // Forwards process signals into our channel; the JoinHandle outlives `run`.
        let _signal_thread = crate::signal::install_shutdown_handler(tx)?;
        rx
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let loop_handle = EventLoop::new(shutdown_rx);
    let rpc_auth = Arc::new(build_rpc_auth(&state.config().rpc_auth)?);
    let rpc_context = bitcoin_rs_rpc::Context::from_handles(
        state.chain_tip(),
        state.mempool(),
        state.blocks(),
        state.transactions(),
        state.network(),
        state.mining_template_id(),
    );
    let rpc_handler = Arc::new(bitcoin_rs_rpc::Handler::new(Arc::new(rpc_context)));
    let rpc_server = bitcoin_rs_rpc::RpcServer::bind(
        state.config().rpc_bind,
        rpc_auth,
        rpc_handler,
        RPC_MAX_CONNECTIONS,
        RPC_IDLE_TIMEOUT,
    )?;
    let rpc_local_addr = rpc_server.local_addr()?;
    tracing::info!(addr = %rpc_local_addr, "rpc listener bound");
    // TODO(rpc_smoke): cover the RPC listener once the test ergonomics improve.
    let rpc_shutdown = Arc::clone(&shutdown);
    let rpc_thread = std::thread::Builder::new()
        .name("bitcoin-rs-rpc".into())
        .spawn(move || rpc_server.serve_with_shutdown(rpc_shutdown))?;
    let electrum_thread = spawn_electrum_listener(state.config(), &shutdown)?;
    let p2p_threads = spawn_p2p_listeners(state.config(), &shutdown)?;
    loop_handle.spin(&shutdown)?;
    if let Some(handle) = electrum_thread {
        match handle.join() {
            Ok(Ok(())) => tracing::info!("electrum listener exited cleanly"),
            Ok(Err(error)) => tracing::warn!(%error, "electrum listener exited with error"),
            Err(_) => tracing::error!("electrum listener panicked"),
        }
    }
    match rpc_thread.join() {
        Ok(Ok(())) => tracing::info!("rpc listener exited cleanly"),
        Ok(Err(error)) => tracing::warn!(%error, "rpc listener exited with i/o error"),
        Err(_) => tracing::error!("rpc listener panicked"),
    }
    for handle in p2p_threads {
        let thread_name = handle
            .thread()
            .name()
            .unwrap_or("bitcoin-rs-p2p")
            .to_owned();
        match handle.join() {
            Ok(Ok(())) => tracing::info!(thread = %thread_name, "p2p listener exited cleanly"),
            Ok(Err(error)) => {
                tracing::warn!(thread = %thread_name, %error, "p2p listener exited with error");
            }
            Err(_) => tracing::error!(thread = %thread_name, "p2p listener panicked"),
        }
    }

    shutdown::drain_and_shutdown(DRAIN_DEADLINE)?;
    tracing::info!("bitcoin-rs node exited cleanly");
    Ok(())
}
