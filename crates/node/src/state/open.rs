//! Node runtime construction and subsystem wiring.

use super::INBOUND_BLOCK_CHANNEL_LIMIT;
use super::INBOUND_TX_CHANNEL_LIMIT;
use super::NodeState;
use super::P2P_OUTBOUND_QUEUE_LIMIT;
use super::events::ChainEventPublisher;
use super::events::ChainSnapshot;
use super::events::allocate_process_epoch;
use super::index::TxIndexSpawn;
use super::index::build_tx_index_open_spec;
use super::index::tx_index_capabilities;
use super::restore::InitialChainstate;
use super::restore::ResumeSource;
use super::restore::STALE_RESTORE_ERROR_THRESHOLD;
use super::restore::open_journal_dir;
use super::restore::prepare_initial_chainstate;
use super::restore::requires_full_revalidation;
use super::storage::NodeStorage;
use super::storage::StoredBlockBodySource;
use crate::NodeConfig;
use anyhow::Context as _;
use anyhow::Result;
use anyhow::bail;
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_mempool::MempoolLimits;
use bitcoin_rs_rpc::context::BlockLog;
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
        let checkpoint_data_dir = crate::checkpoint_fs::open_data_dir(&config.data_dir)
            .with_context(|| format!("open data_dir {}", config.data_dir.display()))?;
        crate::checkpoint_fs::ensure_current_schema(&checkpoint_data_dir).with_context(|| {
            format!(
                "validate CURRENT_SCHEMA for datadir {}",
                config.data_dir.display()
            )
        })?;
        // Allocate the process epoch before anything else can consume one:
        // durable, strictly greater than every earlier run of this data dir.
        let epoch = allocate_process_epoch(&checkpoint_data_dir)?;
        let checkpoint_config = crate::checkpoint::HeaderCheckpointConfig {
            network: config.network,
            genesis: config.network.genesis_block_hash(),
        };
        let checkpoint_load =
            crate::checkpoint::load_checkpoint_from_dir(&checkpoint_data_dir, checkpoint_config)?;

        // Divide the process cache budget across the persistent namespaces
        // that exist in this deployment. A disabled txindex share redistributes
        // to chainstate.
        let cache_budget = bitcoin_rs_storage::clamp_dbcache_bytes(config.storage.dbcache_mb);
        let cache_shares = bitcoin_rs_storage::split_cache_budget(
            cache_budget,
            !tx_index_capabilities(&config).is_empty(),
        );
        let chainstate_cache_bytes = cache_shares[0].bytes;
        let txindex_cache_bytes = cache_shares[1].bytes;
        let block_files =
            Arc::new(FlatFileBlockStore::open(&config.data_dir).map_err(anyhow::Error::new)?);
        let storage = NodeStorage::open(&config, chainstate_cache_bytes, Arc::clone(&block_files))?;
        let undo_store = storage.undo_store();
        // Before anything reads the chainstate, let alone serves or syncs it.
        // A node that starts on a torn chainstate builds on it, and every block
        // it adds makes the damage harder to find.
        if let Some(marker) = undo_store
            .load_disconnect_marker()
            .map_err(anyhow::Error::new)?
        {
            let force_full_revalidation = requires_full_revalidation(&config.data_dir);
            if marker.phase == crate::apply::DisconnectPhase::RolledBack && force_full_revalidation
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
            tree: block_tree_value,
            applied_tip: restored_applied_tip,
            chain_tx_count: restored_chain_tx_count,
            resume_source,
            journal_bootstrap,
        } = prepare_initial_chainstate(
            checkpoint_load,
            &checkpoint_data_dir,
            checkpoint_config,
            &config,
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
        // A2: Create the process-wide rollback-evidence warning store before
        // any detection or worker spawn. One ArcSwap holds the complete
        // immutable snapshot; getblockchaininfo loads one per request.
        let warning_store = Arc::new(crate::recovery_evidence::WarningStore::new());
        // A2: Read the durable applied-tip witness and detect checkpoint
        // fallback. Emit a structured WARN, update the warning snapshot, and
        // durably publish the event marker — only after all conditions hold:
        // valid format/bounds, matching genesis, older writer epoch, and
        // strictly greater witness height than the restored tip.
        let genesis_hex = config.network.genesis_block_hash().to_string_be();
        // One reporter routes every rollback fact of this process — the
        // checkpoint fallback detected here and the index-ahead rewinds the
        // txindex worker detects later — through the same warning store and
        // event marker.
        let recovery_reporter = Arc::new(crate::recovery_evidence::RecoveryReporter::new(
            Arc::clone(&warning_store),
            config.data_dir.clone(),
            genesis_hex.clone(),
            epoch,
        ));
        let restored_height = restored_applied_tip.as_ref().map_or(0, |tip| tip.height);
        let restored_hash = restored_applied_tip
            .as_ref()
            .map_or_else(|| config.network.genesis_block_hash(), |tip| tip.hash)
            .to_string_be();
        if let Some(witness) =
            crate::recovery_evidence::read_witness(&config.data_dir, &genesis_hex)
        {
            if let Some((witness_height, _)) = crate::recovery_evidence::detect_checkpoint_fallback(
                &witness,
                epoch,
                &genesis_hex,
                restored_height,
            ) {
                let source = match resume_source {
                    ResumeSource::Cold => "cold",
                    ResumeSource::Checkpoint => "checkpoint",
                    ResumeSource::Journal => "journal",
                };
                recovery_reporter
                    .report_checkpoint_fallback(
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
        utxo_set.set_listener(Box::new(coin_stats_listener.clone()));
        let journal = match journal_bootstrap {
            Some(bootstrap) => {
                Some(storage.journal_writer(open_journal_dir(&config.data_dir)?, bootstrap)?)
            }
            None => None,
        };
        let utxo = Arc::new(utxo_set);
        let coin_stats = Arc::new(coin_stats_listener);
        let mempool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        let block_tree = Arc::new(RwLock::new(block_tree_value));
        let chain_tip = block_tree.read().tip_handle();
        let applied_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
        if let Some(restored_applied_tip) = restored_applied_tip {
            applied_tip.store(Some(Arc::new(restored_applied_tip)));
        }
        let blocks = Arc::new(RwLock::new(BlockLog::new()));
        let chain_tx_count = Arc::new(AtomicU64::new(restored_chain_tx_count));
        let transactions = Arc::new(RwLock::new(HashMap::new()));
        // Created before the txindex worker spawn: the worker mirrors this
        // publisher's snapshot into its persisted consumer cursor.
        let (chain_events_raw, chain_event_hints_rx_raw) =
            ChainEventPublisher::new(epoch, initial_snapshot);
        let shutdown = Arc::new(AtomicBool::new(false));
        let chain_events = Arc::new(chain_events_raw);
        let chain_transition = Arc::new(parking_lot::Mutex::new(()));
        let tx_index_open_spec = build_tx_index_open_spec(&config, txindex_cache_bytes, epoch)?;
        let (tx_index_runtime, tx_index_spawn, tx_index_lifecycle, tx_index_adapter) =
            match tx_index_open_spec {
                Some(mut spec) => {
                    spec.utxo = Some(Arc::clone(&utxo));
                    spec.chain_transition = Some(Arc::clone(&chain_transition));
                    let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
                    let runtime = Arc::new(crate::txindex_worker::TxIndexRuntime::new(wake_tx));
                    let body_source: Arc<dyn BlockBodySource> =
                        Arc::new(StoredBlockBodySource::new(Arc::clone(&block_body_store)));
                    let block_source =
                        crate::txindex_worker::IndexBlockSource::new(Arc::clone(&blocks))
                            .with_block_body_source(Arc::clone(&body_source))
                            .with_block_tree(Arc::clone(&block_tree));
                    let lifecycle: Arc<arc_swap::ArcSwap<crate::txindex_worker::TxIndexLifecycle>> =
                        Arc::new(arc_swap::ArcSwap::from_pointee(
                            crate::txindex_worker::TxIndexLifecycle::Opening,
                        ));
                    let adapter = Arc::new(crate::txindex_worker::TxIndexQueryAdapter::new(
                        Arc::clone(&lifecycle),
                    ));
                    let generation = crate::txindex_worker::Generation::new(spec.epoch);
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
        let txindex_status = Arc::new(crate::txindex_worker::TxIndexCapability::new(
            tx_index_lifecycle.clone(),
            tx_index_runtime.clone(),
            tx_index_capabilities(&config),
        ));
        let network = Arc::new(RwLock::new(NetworkState::default()));
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
                outbound_active_limit: P2P_OUTBOUND_QUEUE_LIMIT,
                outbound_peer_target: P2P_OUTBOUND_QUEUE_LIMIT,
                outbound_queue_limit: P2P_OUTBOUND_QUEUE_LIMIT,
                inbound_block_queue_limit: INBOUND_BLOCK_CHANNEL_LIMIT,
                download_budget: bitcoin_rs_p2p::default_sync_budget(),
            },
            Arc::clone(&shutdown),
        ));
        let network_active = p2p.network_active_handle();
        let banned = p2p.banned_handle();
        let peer_table = p2p.table();
        let p2p_outbound_tx = p2p.outbound_sender();
        let p2p_outbound_rx = p2p.outbound_receiver();
        let inbound_headers_tx = p2p.inbound_headers_sender();
        let inbound_headers_rx = p2p.inbound_headers_receiver();
        let inbound_blocks_tx = p2p.inbound_blocks_sender();
        let inbound_blocks_rx = p2p.inbound_blocks_receiver();
        let (inbound_tx_tx, inbound_tx_rx_raw) =
            crossbeam_channel::bounded::<bitcoin_rs_p2p::InboundTx>(INBOUND_TX_CHANNEL_LIMIT);
        let inbound_tx_rx = Arc::new(Mutex::new(inbound_tx_rx_raw));
        let chain_event_hints_rx = Arc::new(Mutex::new(chain_event_hints_rx_raw));
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
            let gateway =
                bitcoin_rs_mempool::MempoolGateway::shared_with(Arc::clone(&mempool), mining_leg);
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
                tx_index_runtime.clone(),
            ),
            Arc::clone(&mining_generation),
            Some(Arc::clone(&mempool_gateway)),
        );
        let (capture_rawtx, capture_block_bytes) = followers.capture_flags();
        let mut apply_handles = crate::apply::Chainstate {
            network: config.network,
            chain_tip: Arc::clone(&chain_tip),
            applied_tip: Arc::clone(&applied_tip),
            chain_tx_count: Arc::clone(&chain_tx_count),
            applied_seq: Arc::new(AtomicU64::new(0)),
            block_tree: Arc::clone(&block_tree),
            utxo: Arc::clone(&utxo),
            coin_stats: Arc::clone(&coin_stats),
            mempool: Arc::clone(&mempool),
            mempool_gateway: Arc::clone(&mempool_gateway),
            chain_events: Arc::clone(&chain_events),
            block_body_store: Some(Arc::clone(&block_body_store)),
            undo_store,
            admission: Arc::new(crate::apply::ApplyAdmission::new()),
            shutdown: Arc::clone(&shutdown),
            chain_transition,
            assume_valid_height: config.validation.assume_valid_height,
            assume_valid_gate: Arc::new(crate::apply::AssumeValidGate::new(
                config.network,
                config.validation.assume_valid_height,
            )),
            journal,
            checkpoint_publisher: None,
            capture_rawtx,
            capture_block_bytes,
        };
        apply_handles.assume_valid_gate.evaluate(&block_tree.read());
        // A restored checkpoint is durable at its own height by definition, so
        // start there rather than at zero, which would refuse all undo pruning.
        let durable_tip_height = Arc::new(AtomicU32::new(
            applied_tip.load().as_ref().map_or(0, |tip| tip.height),
        ));
        apply_handles.checkpoint_publisher =
            Some(Arc::new(crate::checkpoint_worker::CheckpointPublisher {
                admission: Arc::clone(&apply_handles.admission),
                undo_store: Arc::clone(&apply_handles.undo_store),
                block_body_store: Arc::clone(&block_body_store),
                applied_tip: Arc::clone(&applied_tip),
                checkpoint_data_dir: crate::checkpoint_fs::open_data_dir(&config.data_dir)
                    .with_context(|| format!("open data_dir {}", config.data_dir.display()))?,
                network: config.network,
                genesis_hash: config.network.genesis_block_hash(),
                block_tree: Arc::clone(&block_tree),
                utxo: Arc::clone(&utxo),
                coin_stats: Arc::clone(&coin_stats),
                chain_tx_count: Arc::clone(&chain_tx_count),
                journal: apply_handles.journal.clone(),
                data_dir: config.data_dir.clone(),
                chain_events: Arc::clone(&chain_events),
                durable_tip_height: Arc::clone(&durable_tip_height),
            }));
        let sync = Arc::new(crate::BlockSync::new(
            apply_handles.clone(),
            followers.clone(),
            Arc::clone(&peer_table),
            Arc::clone(&inbound_headers_rx),
            Arc::clone(&inbound_blocks_rx),
        ));
        let prune_service = if config.storage.prune_target_mb > 0 {
            Some(storage.prune_service(
                &block_files,
                &block_body_store,
                Arc::clone(&blocks),
                Arc::clone(&transactions),
                apply_handles.prune_authority(),
                &durable_tip_height,
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
        let data_dir = config.data_dir.clone();
        Ok(Self {
            durable_tip_height,
            config,
            data_dir,
            #[cfg(test)]
            resume_source,
            storage,
            block_body_store,
            utxo,
            coin_stats,
            tx_index_runtime,
            tx_index_spawn,
            tx_index_worker: None,
            tx_index_lifecycle,
            tx_index_adapter,
            txindex_status,
            prune_service,
            zmq_publisher,
            mempool,
            mempool_gateway,
            mining_generation,
            chain_tip,
            applied_tip,
            chain_tx_count: Arc::clone(&chain_tx_count),
            block_tree,
            blocks,
            transactions,
            network,
            network_active,
            p2p,
            peer_table,
            banned,
            p2p_outbound_tx,
            p2p_outbound_rx,
            inbound_headers_tx,
            inbound_headers_rx,
            inbound_blocks_tx,
            inbound_blocks_rx,
            inbound_tx_tx,
            inbound_tx_rx,
            chain_events: Arc::clone(&chain_events),
            chain_event_hints_rx,
            apply_handles,
            followers,
            sync,
            warning_store,
        })
    }
}
