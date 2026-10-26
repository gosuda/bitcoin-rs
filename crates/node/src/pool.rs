//! Node-owned native pool lifecycle. No wallet or signing capability enters this module.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use bitcoin_rs_mining::{CoinbaseBudget, MiningControl};
use bitcoin_rs_storage::KvStore;
use bitcoin_rs_stratum::{
    ConnectionLimiter, DifficultyPolicy, ExtranonceLayout, JobBookConfig, PoolCore, Server,
    ServerConfig, ServerDeps,
};

#[cfg(feature = "pool-sv2")]
mod authority;
mod ledger;
#[cfg(feature = "pool-sv2")]
mod sv2;
#[cfg(test)]
mod tests;

/// Constructed before RPC; listeners are started only after RPC binds successfully.
pub(crate) struct PoolService {
    config: crate::config::PoolConfig,
    host: Arc<ledger::LedgerHost>,
    core: Arc<PoolCore>,
    #[cfg(feature = "pool-sv2")]
    control: Arc<dyn MiningControl>,
    chain: Arc<ledger::NodeChainView>,
    cancel: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    v1: Option<Server>,
    #[cfg(feature = "pool-sv2")]
    v2: Option<sv2::Sv2Service>,
}

struct LedgerComposer {
    config: pool_ledger::PoolConfig,
}
impl crate::storage_backend::StoreConsumer for LedgerComposer {
    type Output = (pool_ledger::Ledger, u32);
    type Error = anyhow::Error;
    fn consume<S: KvStore>(self, store: Arc<S>) -> Result<Self::Output> {
        let store: Arc<dyn KvStore> = store;
        let ledger = match pool_ledger::Ledger::create(Arc::clone(&store), self.config.clone()) {
            Ok(ledger) => ledger,
            Err(pool_ledger::LedgerError::PathExists) => {
                pool_ledger::Ledger::open(Arc::clone(&store), self.config)?
            }
            Err(error) => return Err(error.into()),
        };
        let epoch = ledger.allocate_run_epoch()?;
        Ok((ledger, epoch))
    }
}

impl PoolService {
    pub(crate) fn prepare(
        state: &crate::state::NodeState,
        control: Arc<dyn MiningControl>,
    ) -> Result<Option<Self>> {
        let Some(config) = state.config().pool.as_ref() else {
            return Ok(None);
        };
        std::fs::create_dir_all(&config.datadir).context("creating pool data directory")?;
        let guard = crate::state::lock_pool_directory(&config.datadir)?;
        let accounting = config.ledger_config();
        let (ledger, epoch) = crate::storage_backend::open_generic(
            "pool",
            state.config().storage.backend,
            &config.datadir.join("ledger"),
            None,
            &guard,
            LedgerComposer { config: accounting },
        )?;
        let host = Arc::new(ledger::LedgerHost::new(
            Arc::new(ledger),
            epoch,
            pool_ledger::PayoutPolicy {
                min_payout_sat: config.min_payout_sat,
                max_outputs: usize::try_from(config.max_payout_outputs)?,
            },
        ));
        let sessions = usize::try_from(config.max_connections)?
            .checked_mul(2)
            .context("pool session bound overflow")?;
        let core = Arc::new(
            PoolCore::new(
                JobBookConfig {
                    budget: CoinbaseBudget {
                        additional_size: 0,
                        additional_sigops: 0,
                    },
                    extranonce: ExtranonceLayout::new(4, 4),
                    coinbase_tag: b"/btcrs/".to_vec(),
                    version_mask: bitcoin_rs_stratum::BIP320_VERSION_MASK,
                    ntime_forward_secs: bitcoin_rs_stratum::MAX_NTIME_FORWARD_SECS,
                    max_jobs: 64,
                    max_sessions: sessions,
                    max_shares_per_job: 65_536,
                },
                Arc::clone(&control),
                host.clone(),
            )?
            .with_ledger_retry(1, Duration::ZERO)
            .with_outbox(1024, 8 * 1024 * 1024),
        );
        let chain = Arc::new(ledger::NodeChainView::new(
            state.chainstate(),
            state.stable_read(),
            state.mempool_reader(),
            state.derived_index_query(),
            state.script_index_query(),
        )?);
        Ok(Some(Self {
            config: config.clone(),
            host,
            core,
            #[cfg(feature = "pool-sv2")]
            control,
            chain,
            cancel: Arc::new(AtomicBool::new(false)),
            worker: None,
            v1: None,
            #[cfg(feature = "pool-sv2")]
            v2: None,
        }))
    }

    pub(crate) fn handles(&self) -> bitcoin_rs_rpc::context::PoolHandles {
        bitcoin_rs_rpc::context::PoolHandles {
            operator: Some(self.host.clone()),
        }
    }

    pub(crate) fn start(&mut self) -> Result<()> {
        // Never acknowledge work before there is a durably opened ledger and a template.
        self.core
            .refresh(None, Vec::new())
            .context("initial pool template")?;
        let limiter = Arc::new(ConnectionLimiter::new(
            usize::try_from(self.config.max_connections)?,
            usize::try_from(self.config.max_connections_per_ip)?,
        )?);
        if let Some(bind) = self.config.v1_bind {
            let text = &self.config.share_difficulty;
            let mut config = ServerConfig::new(
                DifficultyPolicy::new(text, text, text)
                    .map_err(|error| anyhow::anyhow!("invalid pool difficulty: {error:?}"))?,
            );
            config.max_connections = usize::try_from(self.config.max_connections)?;
            config.max_connections_per_ip = usize::try_from(self.config.max_connections_per_ip)?;
            self.v1 = Some(Server::bind_with_limiter(
                bind,
                config,
                ServerDeps {
                    pool: Arc::clone(&self.core),
                    accounts: self.host.clone(),
                    observer: None,
                },
                Arc::clone(&limiter),
            )?);
        }
        #[cfg(feature = "pool-sv2")]
        if self.config.sv2_bind.is_some() {
            self.v2 = Some(sv2::start(
                &self.config,
                Arc::clone(&self.core),
                Arc::clone(&self.host),
                Arc::clone(&self.control),
                Arc::clone(&self.cancel),
                Arc::clone(&limiter),
            )?);
        }
        let core = Arc::clone(&self.core);
        let host = Arc::clone(&self.host);
        let chain = Arc::clone(&self.chain);
        let cancel = Arc::clone(&self.cancel);
        self.worker = Some(
            std::thread::Builder::new()
                .name("pool-reconcile".into())
                .spawn(move || {
                    while !cancel.load(Ordering::Acquire) {
                        // No long-poll: shutdown never waits for a future mining generation.
                        if let Err(error) = core.refresh(None, Vec::new()) {
                            core.invalidate_active();
                            tracing::warn!(%error, "pool template refresh unavailable");
                        }
                        if let Err(error) = host.reconcile(&chain) {
                            tracing::error!(%error, "pool chain reconciliation failed");
                        }
                        core.drain_outbox();
                        std::thread::park_timeout(Duration::from_millis(250));
                    }
                    core.drain_outbox();
                    while matches!(host.drain_one_block_record(), Ok(true)) {}
                })?,
        );
        Ok(())
    }

    pub(crate) fn shutdown(&mut self, deadline: Instant) -> Result<()> {
        self.cancel.store(true, Ordering::Release);
        let mut failure = None;
        if let Some(server) = self.v1.as_mut() {
            match server.shutdown_until(deadline) {
                Ok(report) => {
                    if report.sessions_panicked != 0 {
                        failure = Some(anyhow::anyhow!("pool SV1 session panicked"));
                    }
                    self.v1.take();
                }
                Err(error) => failure = Some(error.into()),
            }
        }
        #[cfg(feature = "pool-sv2")]
        if let Some(server) = self.v2.as_mut() {
            match server.stop_join(deadline) {
                Ok(()) => {
                    self.v2.take();
                }
                Err(error) => failure = Some(error),
            }
        }
        if let Some(worker) = self.worker.as_ref() {
            worker.thread().unpark();
            while !worker.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            if !worker.is_finished() {
                failure = Some(anyhow::anyhow!("pool shutdown deadline exceeded"));
            } else if let Some(worker) = self.worker.take() {
                if worker.join().is_err() {
                    failure = Some(anyhow::anyhow!("pool reconciliation worker panicked"));
                }
            }
        }
        if Instant::now() < deadline {
            self.core.drain_outbox();
        }
        while Instant::now() < deadline {
            match self.host.drain_one_block_record() {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    failure = Some(error.into());
                    break;
                }
            }
        }
        if self.host.pending_block_records() != 0 {
            failure = Some(anyhow::anyhow!(
                "pool shutdown left unrecorded found blocks"
            ));
        }
        if self.core.pending_ledger_writes() != 0 {
            failure = Some(anyhow::anyhow!(
                "pool shutdown left unrecorded SV1 accounting work"
            ));
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    }
}

impl Drop for PoolService {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown(Instant::now() + Duration::from_secs(10)) {
            tracing::error!(%error, "pool shutdown failed");
        }
        // A failed deadline is not permission to detach a durable writer.
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            if worker.join().is_err() {
                tracing::error!("pool reconciliation worker panicked during final join");
            }
        }
    }
}
