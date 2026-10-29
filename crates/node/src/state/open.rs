use super::INBOUND_BLOCK_CHANNEL_LIMIT;
use super::INBOUND_TX_CHANNEL_LIMIT;
use super::NodeState;
use super::P2P_OUTBOUND_BLOCK_RELAY_SLOTS;
use super::P2P_OUTBOUND_FULL_RELAY_SLOTS;
use super::PACKAGE_INGRESS_MAX_BYTES;
use super::TxIndexSpawn;
use super::build_derived_index_open_spec;
use super::derived_index_capabilities;
use super::storage::NodeStorage;
use super::storage::StoredBlockBodySource;
use crate::NodeConfig;
use anyhow::Context as _;
use anyhow::Result;

use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_chainstate::ChainstateParts;
use bitcoin_rs_chainstate::events::{ChainEventPublisher, ChainSnapshot, initialize_data_dir};
use bitcoin_rs_chainstate::recovery::{
    InitialChainstate, ResumeSource, STALE_RESTORE_ERROR_THRESHOLD, open_journal_dir,
    prepare_initial_chainstate,
};
use bitcoin_rs_chainstate::verify::{
    CheckLevel, STARTUP_VERIFY_DEPTH, VerifyOutcome, VerifyRequest, verify_recent_blocks,
};
use bitcoin_rs_consensus::{ScriptExecutionCache, ValidationEngine};
use bitcoin_rs_index::block_log::BlockLog;
use bitcoin_rs_mempool::BodyInterest;
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_mempool::MempoolLimits;
use bitcoin_rs_p2p::download_window::FAST_OUTBOUND_PEER_TARGET;
use bitcoin_rs_p2p::download_window::fast_sync_budget;
use parking_lot::Mutex;
use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

fn verify_startup_window(
    chainstate: &bitcoin_rs_chainstate::Chainstate,
    data_dir: &std::path::Path,
) -> Result<()> {
    let request = VerifyRequest {
        level: CheckLevel::CheckUndoAndCommitments,
        depth: Some(STARTUP_VERIFY_DEPTH),
        cancellation: None,
    };
    match verify_recent_blocks(chainstate, request) {
        Ok(VerifyOutcome::Passed { blocks }) => {
            tracing::debug!(blocks, "startup verification passed");
            Ok(())
        }
        Ok(VerifyOutcome::SkippedNoBlockData { height }) => {
            tracing::info!(
                height,
                "startup verification skipped blocks this node does not hold"
            );
            Ok(())
        }
        Err(error) => Err(anyhow::Error::new(error).context(format!(
            "startup verification of the last {STARTUP_VERIFY_DEPTH} applied blocks failed. \
             Verification repairs nothing, but recovery earlier in this startup may already \
             have changed the data directory. Restore it from a backup, or remove or quarantine \
             {}, {}, {}, and {}, then resync.",
            data_dir.join("blocks").display(),
            data_dir.join("chainstate").display(),
            data_dir.join("chainstate-checkpoints").display(),
            data_dir.join("txindex").display(),
        ))),
    }
}

impl NodeState {
    pub fn open(
        config: NodeConfig,
        mempool_observer: Option<&Arc<dyn bitcoin_rs_mempool::MempoolObserver>>,
    ) -> Result<Self> {
        Self::open_inner(config, mempool_observer, |store| store)
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn open_with_body_store<W>(
        config: NodeConfig,
        mempool_observer: Option<&Arc<dyn bitcoin_rs_mempool::MempoolObserver>>,
        wrap: W,
    ) -> Result<Self>
    where
        W: FnOnce(
            Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
        ) -> Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
    {
        Self::open_inner(config, mempool_observer, wrap)
    }

    #[expect(clippy::too_many_lines)]
    fn open_inner<W>(
        config: NodeConfig,
        mempool_observer: Option<&Arc<dyn bitcoin_rs_mempool::MempoolObserver>>,
        wrap: W,
    ) -> Result<Self>
    where
        W: FnOnce(
            Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
        ) -> Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
    {
        config.validate()?;
        std::fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("create data_dir {}", config.data_dir.display()))?;
        let data_dir_guard: bitcoin_rs_storage::StoreGuard = Arc::new(
            super::data_dir_lock::DataDirLock::acquire(&config.data_dir)?,
        );
        let epoch = initialize_data_dir(&config.data_dir)?;

        let cache_budget = bitcoin_rs_storage::clamp_dbcache_bytes(config.storage.dbcache_mb);
        let cache_shares = bitcoin_rs_storage::split_cache_budget(
            cache_budget,
            !derived_index_capabilities(&config).is_empty(),
        );
        let chainstate_cache_bytes = cache_shares[0].bytes;
        let txindex_cache_bytes = cache_shares[1].bytes;
        let (storage, block_files) =
            NodeStorage::open(&config, chainstate_cache_bytes, &data_dir_guard)?;
        let undo_store = storage.undo_store();
        let durable_head = storage.durable_head();

        let block_body_store = wrap(storage.block_body_store());

        let zmq_endpoints = &config.notifications.zmq;
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
            resume_source,
            journal_bootstrap,
            script_live_seed,
        } = prepare_initial_chainstate(
            &config.data_dir,
            config.network,
            config.chainstate_journal,
            durable_head.load()?.as_ref(),
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
        let genesis_hex = config.network.genesis_block_hash().to_string_be();
        let recovery_reporter = Arc::new(super::storage::RecoveryReporter(
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
                    ResumeSource::Snapshot => "snapshot",
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
        let script_cache = (config.validation.engine == ValidationEngine::Native)
            .then(|| Arc::new(ScriptExecutionCache::new()));
        bitcoin_rs_mempool::fee_history::load(&config.data_dir, &mempool);
        let blocks = Arc::new(RwLock::new(BlockLog::new()));
        let chain_events_raw = ChainEventPublisher::new(initial_snapshot);
        let transition = bitcoin_rs_chain::TransitionDomain::new();
        let chain_events = Arc::new(chain_events_raw);
        let mut chainstate = bitcoin_rs_chainstate::Chainstate::from_parts(ChainstateParts {
            network: config.network,
            block_tree: block_tree_value,
            restored_applied_tip,
            utxo: Arc::clone(&utxo),
            coin_stats: Arc::clone(&coin_stats),
            chain_events: Arc::clone(&chain_events),
            block_body_store: Some(Arc::clone(&block_body_store)),
            undo_store,
            durable_head,
            chain_transition: transition.authority(),
            assume_valid_height: config.validation.assume_valid_height,
            validation_mode: config.validation.mode,
            validation_engine: config.validation.engine,
            script_cache: script_cache.clone(),
            journal,
            capture_rawtx: false,
            capture_block_bytes: false,
            retention: storage.mandatory_retention(),
            history: storage.bounded_history(),
            role: bitcoin_rs_chainstate::ChainstateRole::Ordinary,
        });
        let seed_offer: Option<bitcoin_rs_utxo::SeedOfferCell> =
            if !derived_index_capabilities(&config).is_empty()
                && config.indexes.script_index.is_enabled()
            {
                Some(std::sync::Arc::new(bitcoin_rs_utxo::SeedSlot::new()))
            } else {
                None
            };
        let derived_index_open_spec = build_derived_index_open_spec(
            &config,
            txindex_cache_bytes,
            epoch,
            &data_dir_guard,
            seed_offer.clone(),
        )?;
        if let Some(cell) = seed_offer.as_ref() {
            cell.want();
            if let Some(artifact) = script_live_seed {
                let _ = cell.offer(artifact);
            }
        }
        let derived_index_parts = match derived_index_open_spec {
            Some(mut spec) => {
                spec.utxo = Some(bitcoin_rs_utxo::UtxoReader::new(Arc::clone(&utxo)));
                spec.chain_transition = Some(transition.stable_read());
                let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
                let runtime =
                    Arc::new(bitcoin_rs_index::runtime::DerivedIndexRuntime::new(wake_tx));
                let body_source: Arc<dyn BlockBodySource> =
                    Arc::new(StoredBlockBodySource::new(Arc::clone(&block_body_store)));
                let lifecycle: Arc<
                    arc_swap::ArcSwap<bitcoin_rs_index::runtime::DerivedIndexLifecycle>,
                > = Arc::new(arc_swap::ArcSwap::from_pointee(
                    bitcoin_rs_index::runtime::DerivedIndexLifecycle::Opening,
                ));
                let adapter = Arc::new(bitcoin_rs_index::runtime::DerivedIndexQueryAdapter::new(
                    Arc::clone(&lifecycle),
                ));
                let generation = bitcoin_rs_index::runtime::Generation::new(spec.epoch);
                Some((
                    runtime,
                    TxIndexSpawn {
                        spec,
                        generation,
                        body_source,
                        wake_rx,
                        recovery_reporter: Arc::clone(&recovery_reporter),
                    },
                    lifecycle,
                    adapter,
                ))
            }
            None => None,
        };
        let derived_index_status =
            Arc::new(bitcoin_rs_index::runtime::DerivedIndexCapability::new(
                derived_index_parts
                    .as_ref()
                    .map(|(_, _, lifecycle, _)| Arc::clone(lifecycle)),
                derived_index_parts
                    .as_ref()
                    .map(|(runtime, _, _, _)| Arc::clone(runtime)),
                derived_index_capabilities(&config),
            ));
        let outbound_full_relay_slots = if config.p2p.fast_sync {
            FAST_OUTBOUND_PEER_TARGET
        } else {
            P2P_OUTBOUND_FULL_RELAY_SLOTS
        };
        let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
            bitcoin_rs_p2p::P2pServiceConfig {
                overlay: bitcoin_rs_p2p::overlay::OverlayConfig {
                    identity_dir: config.data_dir.join(&config.p2p.overlay.identity_dir),
                    ..config.p2p.overlay.clone()
                },
                listen_addrs: config.p2p.listen.clone(),
                address_book_path: Some(config.data_dir.join("peers.dat")),
                asmap_path: config.p2p.asmap.clone(),
                allow_local_addresses: config.network == bitcoin_rs_primitives::Network::Regtest,
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
                noban_subnets: config.p2p.noban_subnets.clone(),
                outbound_full_relay_slots,
                outbound_block_relay_slots: P2P_OUTBOUND_BLOCK_RELAY_SLOTS,
                outbound_queue_limit: outbound_full_relay_slots,
                inbound_block_queue_limit: INBOUND_BLOCK_CHANNEL_LIMIT,
                local_services: {
                    let history = if config.storage.prune_target_mb > 0 {
                        bitcoin::p2p::ServiceFlags::WITNESS
                            | bitcoin::p2p::ServiceFlags::NETWORK_LIMITED
                    } else {
                        bitcoin::p2p::ServiceFlags::WITNESS | bitcoin::p2p::ServiceFlags::NETWORK
                    };
                    if config.p2p.v2_transport {
                        history | bitcoin::p2p::ServiceFlags::P2P_V2
                    } else {
                        history
                    }
                },
                v2_transport: config.p2p.v2_transport,
                relay_offers: config.p2p.relay_offers,
                ..bitcoin_rs_p2p::P2pServiceConfig::default()
            },
            chainstate.shutdown_reader(),
        ));
        let peer_table = p2p.table();
        let inbound_headers_rx = p2p
            .take_inbound_headers_receiver()
            .ok_or_else(|| anyhow::anyhow!("inbound headers receiver already taken"))?;
        let inbound_blocks_rx = p2p
            .take_inbound_blocks_receiver()
            .ok_or_else(|| anyhow::anyhow!("inbound blocks receiver already taken"))?;
        let (inbound_tx_tx, inbound_tx_rx_raw) =
            crossbeam_channel::bounded::<bitcoin_rs_p2p::InboundBody>(INBOUND_TX_CHANNEL_LIMIT);
        let inbound_tx_rx = Mutex::new(Some(inbound_tx_rx_raw));
        let package_capacity = bitcoin_rs_p2p::PackageCapacity::new(PACKAGE_INGRESS_MAX_BYTES);
        let mining_generation = Arc::new(crate::mining::MiningGenerationSignal::new());
        let staged_mining = Arc::clone(&mining_generation);
        let staged_ibd = chainstate.ibd_latch();
        let staged_network = config.network;
        chainstate
            .set_tip_staged(Arc::new(move |tip, block| {
                if !staged_ibd.is_active(bitcoin_rs_primitives::unix_time_secs(), staged_network) {
                    staged_mining.stage_tip(tip, block);
                }
            }))
            .map_err(|_| anyhow::anyhow!("staged-tip preparation hook already installed"))?;
        let mempool_gateway = {
            let cloned_mining = Arc::clone(&mining_generation);
            let mining_leg: Arc<dyn bitcoin_rs_mempool::MempoolObserver> = cloned_mining;
            Arc::new(bitcoin_rs_mempool::MempoolGateway::new(
                Arc::clone(&mempool),
                Some((mining_leg, BodyInterest::Metadata)),
                config.validation.engine,
                script_cache,
            ))
        };
        let (block_announce_queue, block_announce_rx) = bitcoin_rs_p2p::BlockAnnounceQueue::new();
        let followers = crate::chain_effects::ChainFollowers::new(
            Arc::clone(&blocks),
            Arc::clone(&zmq_publisher),
            derived_index_parts
                .as_ref()
                .map(|(runtime, _, _, _)| Arc::clone(runtime)),
            Arc::clone(&mining_generation),
            Some(Arc::clone(&mempool_gateway)),
        )
        .with_block_announcer(Some(block_announce_queue));
        chainstate.set_capture_flags(followers.needs_rawtx(), followers.needs_block_bytes());
        let durable_tip_height = Arc::new(AtomicU32::new(
            chainstate
                .applied_tip_reader()
                .load_full()
                .as_ref()
                .map_or(0, |tip| tip.height),
        ));
        chainstate.configure_checkpointing(
            &config.data_dir,
            Arc::clone(&durable_tip_height),
            seed_offer.clone(),
        )?;
        match bitcoin_rs_chainstate::recover_disconnect_marker(&chainstate) {
            Ok(()) => {}
            Err(error @ bitcoin_rs_chainstate::ApplyError::DurableHeadGapUnrecoverable { .. }) => {
                return Err(anyhow::Error::new(error).context(format!(
                    "The node cannot repair this in place. Remove or quarantine {}, {}, and {}, then resync.",
                    config.data_dir.join("chainstate").display(),
                    config.data_dir.join("chainstate-checkpoints").display(),
                    config.data_dir.join("txindex").display(),
                )));
            }
            Err(error) => return Err(anyhow::Error::new(error)),
        }
        let chainstate = Arc::new(chainstate);
        if config.persist_mempool {
            let started = std::time::Instant::now();
            let deadline = started
                .checked_add(std::time::Duration::from_secs(
                    config.mempool_snapshot_restore_timeout_secs,
                ))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "mempool snapshot restore timeout exceeds the platform clock range"
                    )
                })?;
            let chain = bitcoin_rs_rpc::context::ChainAdmissionView::new(
                chainstate.utxo_reader(),
                chainstate.applied_tip_reader(),
                chainstate.block_tree_reader(),
                config.network,
            );
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs());
            match bitcoin_rs_mempool::snapshot::restore(
                &config.data_dir,
                &mempool_gateway,
                config.network,
                &chain,
                now,
                config.mempool_snapshot_max_bytes,
                deadline,
            ) {
                Ok(Some(report)) => {
                    if report.limited != 0 {
                        tracing::warn!(
                            limited = report.limited,
                            package_attempts = report.package_attempts,
                            "mempool snapshot candidates not restored because bounded subset search did not complete"
                        );
                    }
                    if report.timed_out {
                        tracing::warn!(
                            candidates = report.candidates,
                            restored = report.restored,
                            skipped = report.skipped,
                            timeout_secs = config.mempool_snapshot_restore_timeout_secs,
                            "mempool snapshot restore deadline expired; consider raising --mempool-snapshot-restore-timeout-secs"
                        );
                    }
                    tracing::info!(
                        candidates = report.candidates,
                        restored = report.restored,
                        skipped = report.skipped,
                        timed_out = report.timed_out,
                        limited = report.limited,
                        package_attempts = report.package_attempts,
                        elapsed_ms = started.elapsed().as_millis(),
                        status = if report.skipped == 0 && !report.timed_out {
                            "restored"
                        } else {
                            "partially_restored"
                        },
                        "mempool snapshot revalidation finished"
                    );
                }
                Ok(None) => tracing::info!(
                    status = "missing",
                    "no mempool snapshot; starting with an empty pool"
                ),
                Err(error) => tracing::warn!(%error, status = "rejected",
                    "mempool snapshot rejected; leaving the file in place and starting with an empty pool"),
            }
        } else {
            tracing::info!(status = "disabled", "mempool snapshot persistence disabled");
        }
        if zmq_publisher.wants_notifications() {
            let interest = if zmq_publisher.wants_rawtx() {
                BodyInterest::Bodies
            } else {
                BodyInterest::Metadata
            };
            mempool_gateway
                .attach_observer_leg(
                    "sequence",
                    Arc::new(bitcoin_rs_rpc::zmq::MempoolSequenceObserver::new(
                        Arc::clone(&zmq_publisher),
                    )),
                    interest,
                )
                .map_err(anyhow::Error::msg)?;
        } else if let Some(observer) = mempool_observer.cloned() {
            mempool_gateway
                .attach_observer_leg("test", observer, BodyInterest::Bodies)
                .map_err(anyhow::Error::msg)?;
        }
        let ibd = chainstate.ibd_latch();
        let assumeutxo = Arc::new(
            bitcoin_rs_chainstate::AssumeUtxoManager::open(
                config.network,
                Arc::clone(&chainstate),
                config.data_dir.clone(),
            )
            .map_err(|err| anyhow::anyhow!("assumeutxo open failed: {err}"))?,
        );
        let sync = Arc::new(crate::sync::block_sync(
            Arc::clone(&chainstate),
            followers.clone(),
            Arc::clone(&peer_table),
            inbound_headers_rx,
            inbound_blocks_rx,
            Arc::clone(&ibd),
            Some(Arc::clone(&assumeutxo)),
        ));
        if config.p2p.fast_sync {
            sync.install_budget(fast_sync_budget(config.network));
        }
        let prune_service = if config.storage.prune_target_mb > 0 {
            Some(storage.deferred.prune_service(
                Arc::clone(&block_files),
                chainstate.prune_authority(),
                Arc::clone(&durable_tip_height),
                storage.retention(),
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
        let snapshots = Arc::new(crate::snapshot::SnapshotControl::new(
            assumeutxo,
            Arc::clone(&chainstate),
            followers.clone(),
            config.data_dir.clone(),
            config.network,
            seed_offer,
        ));
        verify_startup_window(&chainstate, &config.data_dir)?;
        Ok(Self {
            config,
            #[cfg(test)]
            resume_source,
            storage,
            derived_index: super::index::DerivedIndexHost::from_parts(
                derived_index_parts,
                derived_index_status,
            ),
            prune_service,
            mempool_gateway,
            p2p,
            inbound_tx_tx,
            inbound_tx_rx,
            package_capacity,
            transition,
            chainstate,
            followers,
            sync,
            recovery_reporter,
            snapshots,
            block_announce_rx: Mutex::new(Some(block_announce_rx)),
        })
    }
}
