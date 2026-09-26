//! Node runtime construction and subsystem wiring.

use super::INBOUND_BLOCK_CHANNEL_LIMIT;
use super::INBOUND_TX_CHANNEL_LIMIT;
use super::NodeState;
use super::P2P_OUTBOUND_QUEUE_LIMIT;
use super::TxIndexSpawn;
use super::build_derived_index_open_spec;
use super::derived_index_capabilities;
use super::storage::NodeStorage;
use super::storage::StoredBlockBodySource;
use crate::NodeConfig;
use anyhow::Context as _;
use anyhow::Result;
use anyhow::bail;
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_chainstate::ChainstateParts;
use bitcoin_rs_chainstate::events::{ChainEventPublisher, ChainSnapshot, initialize_data_dir};
use bitcoin_rs_chainstate::recovery::{
    InitialChainstate, ResumeSource, STALE_RESTORE_ERROR_THRESHOLD, open_journal_dir,
    prepare_initial_chainstate, requires_full_revalidation,
};
use bitcoin_rs_index::block_log::BlockLog;
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_mempool::MempoolLimits;
use bitcoin_rs_p2p::download_window::FAST_OUTBOUND_PEER_TARGET;
use bitcoin_rs_p2p::download_window::fast_sync_budget;
use bitcoin_rs_rpc::context::NetworkState;
use bitcoin_rs_storage::FlatFileBlockStore;
use hashbrown::HashMap;
use parking_lot::Mutex;
use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;

impl NodeState {
    /// Opens (or creates) the node's data directory and configured storage
    /// backend.
    /// Derived-index workers are constructed dormant (`Opening`) and started
    /// by [`Self::start_index_workers`] once crash recovery has made the
    /// applied tip authoritative; `start_node` performs both steps.
    #[allow(clippy::arc_with_non_send_sync)]
    #[allow(clippy::too_many_lines)]
    pub fn open(
        config: NodeConfig,
        mempool_observer: Option<&Arc<dyn bitcoin_rs_mempool::MempoolObserver>>,
    ) -> Result<Self> {
        config.validate()?;
        std::fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("create data_dir {}", config.data_dir.display()))?;
        // Allocate the process epoch before anything else can consume one:
        // durable, strictly greater than every earlier run of this data dir.
        let epoch = initialize_data_dir(&config.data_dir)?;

        // Divide the process cache budget across the persistent namespaces
        // that exist in this deployment. A disabled txindex share redistributes
        // to chainstate.
        let cache_budget = bitcoin_rs_storage::clamp_dbcache_bytes(config.storage.dbcache_mb);
        let cache_shares = bitcoin_rs_storage::split_cache_budget(
            cache_budget,
            !derived_index_capabilities(&config).is_empty(),
        );
        let chainstate_cache_bytes = cache_shares[0].bytes;
        let txindex_cache_bytes = cache_shares[1].bytes;
        let block_files =
            Arc::new(FlatFileBlockStore::open(&config.data_dir).map_err(anyhow::Error::new)?);
        let storage = NodeStorage::open(&config, chainstate_cache_bytes, Arc::clone(&block_files))?;
        let undo_store = storage.undo_store();
        let durable_head = storage.durable_head();
        // Before anything reads the chainstate, let alone serves or syncs it.
        // A node that starts on a torn chainstate builds on it, and every block
        // it adds makes the damage harder to find.
        if let Some(marker) = undo_store
            .load_disconnect_marker()
            .map_err(anyhow::Error::new)?
        {
            let force_full_revalidation = requires_full_revalidation(&config.data_dir);
            if marker.phase == bitcoin_rs_chainstate::DisconnectPhase::RolledBack
                && force_full_revalidation
            {
                undo_store.disarm_disconnect().map_err(anyhow::Error::new)?;
                tracing::warn!(
                    height = marker.height,
                    hash = %marker.hash,
                    "accepting completed deep reorg; full chain validation is required"
                );
            } else {
                // Names directories rather than a `-reindex` option, because this
                // node has no reindex. An instruction the operator cannot follow is
                // worse than none.
                //
                // Remove the authoritative views. The marker covers a disconnect
                // that did not reach a clean UTXO-and-tip checkpoint. TxIndex rows
                // are derived state outside this marker, but a retained TxIndex
                // watermark can stall rollback because wiping the chainstate
                // removes the body positions the index refers to. Include the txindex
                // path so the operator action is complete.
                bail!(
                    "refusing to start: a disconnect of block {hash} at height {height} did not \
                     reach a clean checkpoint, so the UTXO set and chain tip cannot be trusted \
                     together. The node cannot repair this in place. Remove or quarantine \
                     {chainstate}, {checkpoints}, and {txindex}, then resync.",
                    hash = marker.hash,
                    height = marker.height,
                    chainstate = config.data_dir.join("chainstate").display(),
                    checkpoints = config.data_dir.join("chainstate-checkpoints").display(),
                    txindex = config.data_dir.join("txindex").display(),
                );
            }
        }
        let block_body_store = storage.block_body_store();

        let zmq_endpoints = config.zmq_endpoints();
        #[cfg(feature = "zmq")]
        let zmq_publisher: Arc<dyn crate::ZmqPublisher> = if zmq_endpoints.is_empty() {
            Arc::new(crate::NoOpZmqPublisher)
        } else {
            Arc::new(crate::SocketZmqPublisher::bind(zmq_endpoints)?)
        };
        #[cfg(not(feature = "zmq"))]
        let zmq_publisher: Arc<dyn crate::ZmqPublisher> = {
            let _ = &zmq_endpoints;
            Arc::new(crate::NoOpZmqPublisher)
        };
        let InitialChainstate {
            utxo: mut utxo_set,
            coin_stats: initial_coin_stats,
            tree: mut block_tree_value,
            applied_tip: restored_applied_tip,
            chain_tx_count: restored_chain_tx_count,
            resume_source,
            journal_bootstrap,
        } = prepare_initial_chainstate(
            &config.data_dir,
            config.network,
            config.chainstate_journal,
        )?;
        if resume_source == ResumeSource::Checkpoint {
            tracing::info!(
                height = restored_applied_tip.as_ref().map_or(0, |tip| tip.height),
                hash = %restored_applied_tip
                    .as_ref()
                    .map_or_else(|| config.network.genesis_block_hash(), |tip| tip.hash),
                "restored chainstate checkpoint"
            );
        }
        // A2: one reporter routes every rollback fact of this process — the
        // checkpoint fallback detected here and the index-ahead rewinds the
        // txindex worker detects later — through one warning snapshot and one
        // event marker.
        let genesis_hex = config.network.genesis_block_hash().to_string_be();
        let recovery_reporter = Arc::new(crate::recovery_reporter::RecoveryReporter(
            bitcoin_rs_storage::recovery_evidence::RecoveryEvidencePublisher::new(
                config.data_dir.clone(),
                genesis_hex.clone(),
                epoch,
            ),
        ));
        let restored_height = restored_applied_tip.as_ref().map_or(0, |tip| tip.height);
        let restored_hash = restored_applied_tip
            .as_ref()
            .map_or_else(|| config.network.genesis_block_hash(), |tip| tip.hash)
            .to_string_be();
        if let Some(witness) =
            bitcoin_rs_storage::recovery_evidence::read_witness(&config.data_dir, &genesis_hex)
        {
            if bitcoin_rs_storage::recovery_evidence::checkpoint_fallback(
                &witness,
                epoch,
                restored_height,
            ) {
                let witness_height = witness.height;
                let source = match resume_source {
                    ResumeSource::Cold => "cold",
                    ResumeSource::Checkpoint => "checkpoint",
                    ResumeSource::Journal => "journal",
                };
                recovery_reporter
                    .0
                    .publish_checkpoint_fallback(
                        witness_height,
                        restored_height,
                        &restored_hash,
                        source,
                        &witness.block_hash,
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| d.as_secs()),
                    )
                    .context("write checkpoint-fallback event marker")?;
                let gap = witness_height.saturating_sub(restored_height);
                if gap > STALE_RESTORE_ERROR_THRESHOLD {
                    tracing::error!(
                        witness_height,
                        restored_height,
                        gap,
                        threshold = STALE_RESTORE_ERROR_THRESHOLD,
                        "stale checkpoint restore: chainstate is {gap} blocks behind \
                         the last durable applied-tip witness — no committed journal \
                         suffix covers the gap, so the node is proceeding with a valid \
                         but far-behind tip and the sync layer must re-fetch it"
                    );
                }
            }
        }
        // Anchor the initial snapshot before `restored_applied_tip` is moved
        // into the applied-tip slot: a restored node resumes at its restored
        // tip, a fresh one at genesis, both with an untouched sequence.
        let initial_snapshot = ChainSnapshot {
            epoch,
            sequence: 0,
            tip_hash: restored_applied_tip
                .as_ref()
                .map_or_else(|| config.network.genesis_block_hash(), |tip| tip.hash),
            tip_height: restored_applied_tip.as_ref().map_or(0, |tip| tip.height),
        };
        let coin_stats_listener =
            bitcoin_rs_utxo::stats::CoinStatsListener::new(initial_coin_stats);
        utxo_set.track_coin_stats(coin_stats_listener.clone());
        let journal = match journal_bootstrap {
            Some(bootstrap) => Some(
                storage
                    .deferred
                    .journal_writer(open_journal_dir(&config.data_dir)?, bootstrap)?,
            ),
            None => None,
        };
        let utxo = Arc::new(utxo_set);
        let coin_stats = Arc::new(coin_stats_listener);
        let mempool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        // Owner-local fee-estimator history: adopt the persisted
        // confirmation history before any admission can run. A corrupt or
        // unknown-version file degrades to insufficient data (docs/policies/db-migration.md).
        bitcoin_rs_mempool::fee_history::load(&config.data_dir, &mempool);
        // Extract the tip publication cell while the tree is still owned
        // here; sharing it is part of the tree's mutation authority.
        let chain_tip = block_tree_value.tip_handle();
        let block_tree = Arc::new(RwLock::new(block_tree_value));
        let applied_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
        if let Some(restored_applied_tip) = restored_applied_tip {
            applied_tip.store(Some(Arc::new(restored_applied_tip)));
        }
        let blocks = Arc::new(RwLock::new(BlockLog::new()));
        let chain_tx_count = Arc::new(AtomicU64::new(restored_chain_tx_count));
        let transactions = Arc::new(RwLock::new(HashMap::new()));
        // Created before the txindex worker spawn: the worker mirrors this
        // publisher's snapshot into its persisted consumer cursor.
        let chain_events_raw = ChainEventPublisher::new(initial_snapshot);
        let shutdown = Arc::new(AtomicBool::new(false));
        let chain_events = Arc::new(chain_events_raw);
        let mut chainstate = bitcoin_rs_chainstate::Chainstate::from_parts(ChainstateParts {
            network: config.network,
            chain_tip: Arc::clone(&chain_tip),
            applied_tip: Arc::clone(&applied_tip),
            chain_tx_count: Arc::clone(&chain_tx_count),
            block_tree: Arc::clone(&block_tree),
            utxo: Arc::clone(&utxo),
            coin_stats: Arc::clone(&coin_stats),
            chain_events: Arc::clone(&chain_events),
            block_body_store: Some(Arc::clone(&block_body_store)),
            undo_store,
            durable_head,
            shutdown: Arc::clone(&shutdown),
            assume_valid_height: config.validation.assume_valid_height,
            validation_mode: config.validation.mode,
            validation_engine: config.validation.engine,
            journal,
            capture_rawtx: false,
            capture_block_bytes: false,
        });
        let derived_index_open_spec =
            build_derived_index_open_spec(&config, txindex_cache_bytes, epoch)?;
        let (
            derived_index_runtime,
            derived_index_spawn,
            derived_index_lifecycle,
            derived_index_adapter,
        ) = match derived_index_open_spec {
            Some(mut spec) => {
                spec.utxo = Some(Arc::clone(&utxo));
                spec.chain_transition = Some(chainstate.read_fence());
                let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
                let runtime =
                    Arc::new(bitcoin_rs_index::runtime::DerivedIndexRuntime::new(wake_tx));
                let body_source: Arc<dyn BlockBodySource> =
                    Arc::new(StoredBlockBodySource::new(Arc::clone(&block_body_store)));
                let block_source =
                    bitcoin_rs_index::runtime::IndexBlockSource::new(Arc::clone(&blocks))
                        .with_block_body_source(Arc::clone(&body_source))
                        .with_block_tree(chainstate.block_tree_reader());
                let lifecycle: Arc<
                    arc_swap::ArcSwap<bitcoin_rs_index::runtime::DerivedIndexLifecycle>,
                > = Arc::new(arc_swap::ArcSwap::from_pointee(
                    bitcoin_rs_index::runtime::DerivedIndexLifecycle::Opening,
                ));
                let adapter = Arc::new(bitcoin_rs_index::runtime::DerivedIndexQueryAdapter::new(
                    Arc::clone(&lifecycle),
                ));
                let generation = bitcoin_rs_index::runtime::Generation::new(spec.epoch);
                (
                    Some(runtime),
                    Some(TxIndexSpawn {
                        spec,
                        generation,
                        block_source,
                        body_source,
                        wake_rx,
                        recovery_reporter: Arc::clone(&recovery_reporter),
                    }),
                    Some(lifecycle),
                    Some(adapter),
                )
            }
            None => (None, None, None, None),
        };
        let derived_index_status =
            Arc::new(bitcoin_rs_index::runtime::DerivedIndexCapability::new(
                derived_index_lifecycle.clone(),
                derived_index_runtime.clone(),
                derived_index_capabilities(&config),
            ));
        let network = Arc::new(RwLock::new(NetworkState::default()));
        // One active generation of outbound requests keeps the drain fed, so
        // the active and queue limits track the peer target.
        let outbound_target = if config.p2p.fast_sync {
            FAST_OUTBOUND_PEER_TARGET
        } else {
            P2P_OUTBOUND_QUEUE_LIMIT
        };
        let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
            bitcoin_rs_p2p::P2pServiceConfig {
                listen_addrs: config.p2p.listen.clone(),
                magic: bitcoin::p2p::Magic::from_bytes(config.p2p.magic),
                dns_seeds_enabled: config.p2p.dns_seeds_enabled,
                dns_seeds: config
                    .network
                    .dns_seeds()
                    .iter()
                    .map(|seed| (*seed).to_owned())
                    .collect(),
                dns_port: config.network.default_p2p_port(),
                fixed_peers: config.p2p.connect.clone(),
                outbound_active_limit: outbound_target,
                outbound_peer_target: outbound_target,
                outbound_queue_limit: outbound_target,
                inbound_block_queue_limit: INBOUND_BLOCK_CHANNEL_LIMIT,
            },
            Arc::clone(&shutdown),
        ));
        let network_active = p2p.network_active_handle();
        let banned = p2p.banned_handle();
        let peer_table = p2p.table();
        let p2p_outbound_tx = p2p.outbound_sender();
        let inbound_headers_rx = p2p.inbound_headers_receiver();
        let inbound_blocks_tx = p2p.inbound_blocks_sender();
        let inbound_blocks_rx = p2p.inbound_blocks_receiver();
        let (inbound_tx_tx, inbound_tx_rx_raw) =
            crossbeam_channel::bounded::<bitcoin_rs_p2p::InboundTx>(INBOUND_TX_CHANNEL_LIMIT);
        let inbound_tx_rx = Arc::new(Mutex::new(inbound_tx_rx_raw));
        // The template-coordinator wake exists from node birth so the apply
        // path and the gateway can fire it before `run` builds the
        // coordinator; the coordinator attaches itself once constructed.
        let mining_generation = Arc::new(crate::mining::MiningGenerationSignal::new());
        // One gateway per pool. Mempool owns fan-out: mining occupies the
        // observer slot, and ZMQ sequence (or a test observer) attaches as an
        // extra named leg. Admission/relay legs attach after construction.
        let mempool_gateway = {
            let publisher = Arc::clone(&zmq_publisher);
            let cloned_mining = Arc::clone(&mining_generation);
            let mining_leg: Arc<dyn bitcoin_rs_mempool::MempoolObserver> = cloned_mining;
            let gateway = bitcoin_rs_mempool::MempoolGateway::shared_with(
                Arc::clone(&mempool),
                mining_leg,
                config.validation.engine,
            )?;
            if publisher.wants_notifications() {
                gateway
                    .attach_observer_leg(
                        "sequence",
                        Arc::new(bitcoin_rs_rpc::zmq::MempoolSequenceObserver::new(publisher)),
                    )
                    .map_err(anyhow::Error::msg)?;
            } else if let Some(observer) = mempool_observer.cloned() {
                gateway
                    .attach_observer_leg("test", observer)
                    .map_err(anyhow::Error::msg)?;
            }
            gateway
        };
        // Construct followers before Chainstate so capture policy has one owner.
        let followers = crate::chain_effects::ChainFollowers::new(
            crate::chain_effects::ChainEffects::new(
                Arc::clone(&blocks),
                Arc::clone(&zmq_publisher),
                derived_index_runtime.clone(),
            ),
            Arc::clone(&mining_generation),
            Some(Arc::clone(&mempool_gateway)),
        );
        let (capture_rawtx, capture_block_bytes) = followers.capture_flags();
        chainstate.set_capture_flags(capture_rawtx, capture_block_bytes);
        // The durable head is the chain's commit point: an unreadable row
        // fails startup, and a committed-but-unpublished gap (crash between
        // the head batch and publication) is replayed here from the durable
        // bodies it certified, so ordinary operation starts on a state the
        // head fully names (#655). A gap that is not an ancestor prefix of
        // stored bodies fails startup closed.
        bitcoin_rs_chainstate::reconcile_at_boot(&chainstate).map_err(anyhow::Error::new)?;
        // A restored checkpoint is durable at its own height by definition, so
        // start there rather than at zero, which would refuse all undo pruning.
        let durable_tip_height = Arc::new(AtomicU32::new(
            applied_tip.load().as_ref().map_or(0, |tip| tip.height),
        ));
        chainstate.configure_checkpointing(&config.data_dir, Arc::clone(&durable_tip_height))?;
        let chainstate = Arc::new(chainstate);
        let sync = Arc::new(crate::sync::block_sync(
            Arc::clone(&chainstate),
            followers.clone(),
            Arc::clone(&peer_table),
            Arc::clone(&inbound_headers_rx),
            Arc::clone(&inbound_blocks_rx),
        ));
        if config.p2p.fast_sync {
            sync.install_budget(fast_sync_budget(config.network));
        }
        let prune_service = if config.storage.prune_target_mb > 0 {
            Some(storage.deferred.prune_service(
                Arc::clone(&block_files),
                Arc::clone(&block_body_store),
                Arc::clone(&blocks),
                Arc::clone(&transactions),
                chainstate.prune_authority(),
                Arc::clone(&durable_tip_height),
                chainstate.retention_handle(),
            )?)
        } else {
            None
        };
        tracing::info!(
            backend = storage.kind(),
            chainstate_dir = %config.data_dir.join("chainstate").display(),
            chainstate_cache_bytes,
            txindex_cache_bytes,
            total_cache_bytes = cache_budget,
            "opened storage backend with effective cache capacities"
        );
        Ok(Self {
            config,
            #[cfg(test)]
            resume_source,
            storage,
            derived_index_runtime,
            derived_index_spawn,
            derived_index_worker: None,
            derived_index_lifecycle,
            derived_index_adapter,
            derived_index_status,
            prune_service,
            zmq_publisher,
            mempool,
            mempool_gateway,
            mining_generation,
            blocks,
            transactions,
            network,
            network_active,
            p2p,
            peer_table,
            banned,
            p2p_outbound_tx,
            inbound_blocks_tx,
            inbound_tx_tx,
            inbound_tx_rx,
            chainstate,
            followers,
            sync,
            recovery_reporter,
        })
    }
}
