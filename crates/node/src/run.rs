use std::io::IsTerminal as _;
use std::net::SocketAddr;

use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::config::{NodeConfig, RuntimeInputs};

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error(transparent)]
    Config(Box<crate::config::ConfigError>),
    #[error(transparent)]
    Open(Box<crate::state::open::NodeOpenError>),
    #[error(transparent)]
    IndexWorker(#[from] crate::state::IndexWorkerError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(transparent)]
    P2pStart(#[from] bitcoin_rs_p2p::P2pServiceError),
    #[error(transparent)]
    P2pJoin(#[from] bitcoin_rs_p2p::P2pJoinError),
    #[error(transparent)]
    Maintenance(#[from] bitcoin_rs_chainstate::MaintenanceError),
    #[error(transparent)]
    Checkpoint(Box<bitcoin_rs_chainstate::CheckpointError>),
    #[error("{0}")]
    Node(crate::embed::NodeError),
    #[error("failed to bind RPC listener at {address}")]
    RpcBind {
        address: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to bind public HTTP listener at {address}")]
    PublicRpcBind {
        address: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("running node has no block body store")]
    NoBlockBodyStore,
    #[error("pow-valid hook already installed")]
    PowValidHookInstalled,
    #[error("inbound tx receiver already taken")]
    InboundTxReceiverTaken,
    #[error("{0}")]
    GatewayObserverLeg(&'static str),
    #[error("failed to bootstrap genesis")]
    BootstrapGenesis {
        #[source]
        source: Box<crate::chain_effects::ConnectMutationError>,
    },
    #[error("install prometheus recorder: {error}")]
    MetricsInstall {
        error: metrics_exporter_prometheus::BuildError,
    },
    #[error("metrics recorder already serves a different evidence identity")]
    MetricsIdentityMismatch,
    #[error("metrics scrape thread panicked")]
    MetricsScrapeThreadPanicked,
    #[error("spawn readiness sampler: {error}")]
    SpawnReadinessSampler { error: std::io::Error },
    #[error("readiness sampler panicked")]
    ReadinessSamplerPanicked,
    #[error("signal forwarding thread panicked")]
    SignalForwardingPanicked,
    #[error("event loop thread panicked")]
    EventLoopPanicked,
    #[error("rpc listener thread panicked")]
    RpcListenerPanicked,
    #[error("tx ingress consumer panicked")]
    TxIngressPanicked,
    #[error("tx relay worker panicked")]
    TxRelayPanicked,
    #[error("block announce worker panicked")]
    BlockAnnouncePanicked,
    #[error("chainstate maintenance worker panicked")]
    MaintenanceWorkerPanicked,
    #[cfg(feature = "pool")]
    #[error("pool session bound overflow")]
    PoolSessionBoundOverflow,
    #[error(transparent)]
    TryFromInt(#[from] core::num::TryFromIntError),
    #[cfg(feature = "pool")]
    #[error("creating pool data directory")]
    PoolDataDirCreate {
        #[source]
        source: std::io::Error,
    },
    #[cfg(feature = "pool")]
    #[error(transparent)]
    PoolDirLock(#[from] crate::state::DataDirLockError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    PoolLedger(#[from] bitcoin_rs_mining::pool::ledger::LedgerError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    PoolCore(#[from] bitcoin_rs_mining::pool::JobError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    PoolChainView(#[from] bitcoin_rs_mining::pool::ledger::ChainViewError),
    #[cfg(feature = "pool")]
    #[error("initial pool template")]
    PoolInitialTemplate {
        #[source]
        source: bitcoin_rs_mining::pool::RefreshError,
    },
    #[cfg(feature = "pool")]
    #[error(transparent)]
    PoolLimiter(#[from] bitcoin_rs_mining::pool::stratum::sv1::ConfigError),
    #[cfg(feature = "pool")]
    #[error("invalid pool difficulty: {difficulty_debug}")]
    PoolDifficulty { difficulty_debug: String },
    #[cfg(feature = "pool-sv2")]
    #[error("loading SV2 authority key")]
    PoolSv2AuthorityKey {
        #[source]
        source: crate::pool::authority::AuthorityKeyError,
    },
    #[cfg(feature = "pool")]
    #[error("binding SV2 listener {bind}")]
    PoolSv2Bind {
        bind: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[cfg(feature = "pool")]
    #[error("setting SV2 listener nonblocking")]
    PoolSv2Nonblocking {
        #[source]
        source: std::io::Error,
    },
    #[cfg(feature = "pool")]
    #[error("spawning SV2 listener")]
    PoolSv2ListenerSpawn {
        #[source]
        source: std::io::Error,
    },
    #[cfg(feature = "pool")]
    #[error("SV2 start requires a listener address")]
    PoolSv2BindMissing,
    #[cfg(feature = "pool")]
    #[error("SV2 start requires an authority key")]
    PoolSv2AuthorityKeyMissing,
    #[cfg(feature = "pool")]
    #[error("SV2 listener thread panicked")]
    PoolSv2ListenerPanicked,
    #[cfg(feature = "pool")]
    #[error("timed out joining SV2 connection threads")]
    PoolSv2ConnectionJoinTimeout,
    #[cfg(feature = "pool")]
    #[error("SV2 connection thread panicked")]
    PoolSv2ConnectionPanicked,
    #[cfg(feature = "pool")]
    #[error("SV2 handshake timed out")]
    PoolSv2HandshakeTimeout,
    #[cfg(feature = "pool")]
    #[error("SV2 connection idle timed out")]
    PoolSv2IdleTimeout,
    #[cfg(feature = "pool")]
    #[error("SV2 buffered input length is missing")]
    PoolSv2BufferedInputMissing,
    #[cfg(feature = "pool-sv2")]
    #[error(transparent)]
    PoolSv2Protocol(#[from] bitcoin_rs_mining::pool::stratum::sv2::Error),
    #[cfg(feature = "pool-sv2")]
    #[error("creating authenticated SV2 connection")]
    PoolSv2ConnectionAccept {
        #[source]
        source: bitcoin_rs_mining::pool::stratum::sv2::ConfigError,
    },
    #[cfg(feature = "pool")]
    #[error("SV2 block channel has no admitted ledger account")]
    PoolSv2BlockChannelUnaccounted,
    #[cfg(feature = "pool")]
    #[error("SV2 block event has no host record reservation")]
    PoolSv2BlockReservationMissing,
    #[cfg(feature = "pool")]
    #[error("SV2 block lost its submission")]
    PoolSv2BlockSubmissionLost,
    #[cfg(feature = "pool")]
    #[error("SV2 durable recovery has no reservation")]
    PoolSv2DurableReservationMissing,
    #[cfg(feature = "pool")]
    #[error("SV2 queued recovery has no reservation")]
    PoolSv2QueuedReservationMissing,
    #[cfg(feature = "pool")]
    #[error("SV2 block cannot be represented by the durable ledger")]
    PoolSv2BlockUnrecordable,
    #[cfg(feature = "pool")]
    #[error("SV2 block submission failed")]
    PoolSv2BlockSubmissionFailed {
        #[source]
        source: bitcoin_rs_mining::MiningControlError,
    },
    #[cfg(feature = "pool")]
    #[error("SV2 Undetermined block lost its reservation")]
    PoolSv2UndeterminedReservationLost,
    #[cfg(feature = "pool")]
    #[error("node rejected submitted SV2 block")]
    PoolSv2BlockRejected,
    #[cfg(feature = "pool")]
    #[error("timed out draining SV2 connection output")]
    PoolSv2DrainTimeout,
    #[cfg(feature = "pool")]
    #[error("timed out joining {name}")]
    PoolSv2JoinTimeout { name: String },
    #[error("pool SV1 session panicked")]
    PoolSv1SessionPanicked,
    #[error("pool shutdown deadline exceeded")]
    PoolShutdownDeadlineExceeded,
    #[error("pool reconciliation worker panicked")]
    PoolReconciliationPanicked,
    #[error("pool shutdown left unrecorded found blocks")]
    PoolUnrecordedFoundBlocks,
    #[error("pool shutdown left unrecorded SV1 accounting work")]
    PoolUnrecordedAccountingWork,
}

impl From<crate::config::ConfigError> for RunError {
    fn from(error: crate::config::ConfigError) -> Self {
        Self::Config(Box::new(error))
    }
}

impl From<crate::state::open::NodeOpenError> for RunError {
    fn from(error: crate::state::open::NodeOpenError) -> Self {
        Self::Open(Box::new(error))
    }
}

impl From<bitcoin_rs_chainstate::CheckpointError> for RunError {
    fn from(error: bitcoin_rs_chainstate::CheckpointError) -> Self {
        Self::Checkpoint(Box::new(error))
    }
}

const DEFAULT_FILTER: &str = "info,fjall=warn,rocksdb=warn";

fn install_tracing(level: &str) {
    let filter_directive = build_filter_directive(level);
    let filter =
        EnvFilter::try_new(&filter_directive).unwrap_or_else(|_error| EnvFilter::new("info"));

    let subscriber = tracing_subscriber::registry().with(filter);
    if std::io::stderr().is_terminal() {
        let subscriber = subscriber.with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(true),
        );
        let _already_installed = subscriber.try_init();
    } else {
        let subscriber = subscriber.with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(std::io::stderr),
        );
        let _already_installed = subscriber.try_init();
    }
}

fn build_filter_directive(level: &str) -> String {
    if level.is_empty() || level == "info" {
        DEFAULT_FILTER.to_owned()
    } else if level.contains(',') || level.contains('=') {
        level.to_owned()
    } else {
        format!("{level},fjall=warn,rocksdb=warn")
    }
}

fn wait_for_shutdown(shutdown: &bitcoin_rs_chain::LatchReader) {
    if !shutdown.is_triggered() {
        let _ = shutdown.closed().recv();
    }
}

pub fn run(config: NodeConfig, runtime: RuntimeInputs) -> Result<(), RunError> {
    install_tracing(&config.observability.log_level);
    let node = crate::lifecycle::start_node(config, runtime, true)?;
    let shutdown_reader = node.state.shutdown_reader();
    wait_for_shutdown(&shutdown_reader);
    node.shutdown_blocking().map_err(RunError::Node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn explicit_directive_is_respected_as_is() {
        let level = "debug,bitcoin_rs_p2p=trace";
        let directive = build_filter_directive(level);
        assert_eq!(directive, level);
    }

    #[test]
    fn bare_levels_cap_storage_targets() {
        for (level, expected) in [
            ("", "info,fjall=warn,rocksdb=warn"),
            ("info", "info,fjall=warn,rocksdb=warn"),
            ("debug", "debug,fjall=warn,rocksdb=warn"),
            ("warn", "warn,fjall=warn,rocksdb=warn"),
            ("error", "error,fjall=warn,rocksdb=warn"),
            ("trace", "trace,fjall=warn,rocksdb=warn"),
            ("off", "off,fjall=warn,rocksdb=warn"),
        ] {
            let directive = build_filter_directive(level);
            assert_eq!(directive, expected, "bare level {level:?}");
            EnvFilter::try_new(&directive).unwrap_or_else(|error| {
                panic!("bare level {level:?} with per-target caps must parse: {error}")
            });
        }
    }

    #[test]
    fn wait_for_shutdown_wakes_promptly_on_trigger() {
        let writer = bitcoin_rs_chain::LatchWriter::new();
        let reader = writer.reader();
        let (tx, rx) = crossbeam_channel::bounded(1);
        let handle = std::thread::spawn(move || {
            wait_for_shutdown(&reader);
            let _ = tx.send(());
        });
        std::thread::sleep(Duration::from_millis(5));
        writer.trigger();
        let res = rx.recv_timeout(Duration::from_millis(25));
        assert!(
            res.is_ok(),
            "wait_for_shutdown did not wake promptly: timed out waiting for trigger"
        );
        assert!(handle.join().is_ok(), "thread panicked");
    }
}
