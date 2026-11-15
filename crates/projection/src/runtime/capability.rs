use super::{
    Arc, ArcSwap, CapabilityState, CapabilityStatus, DerivedIndexCapabilitySource,
    DerivedIndexLifecycle, DerivedIndexQueryEngine, DerivedIndexRuntime, IndexCapabilities,
    IndexCapability, IndexProgress, TxQueryError, derived_index_status,
};

const PROGRESS_READ_ATTEMPTS: usize = 4;

pub struct DerivedIndexCapability {
    lifecycle: Option<Arc<ArcSwap<DerivedIndexLifecycle>>>,
    runtime: Option<Arc<DerivedIndexRuntime>>,
    enabled: IndexCapabilities,
}

impl DerivedIndexCapability {
    #[must_use]
    pub fn new(
        lifecycle: Option<Arc<ArcSwap<DerivedIndexLifecycle>>>,
        runtime: Option<Arc<DerivedIndexRuntime>>,
        enabled: IndexCapabilities,
    ) -> Self {
        Self {
            lifecycle,
            runtime,
            enabled,
        }
    }

    fn report(
        lifecycle: &DerivedIndexLifecycle,
        runtime: &DerivedIndexRuntime,
        enabled: IndexCapabilities,
    ) -> CapabilityState {
        if let Some(message) = runtime.failure_message() {
            return CapabilityState::Failed {
                reason: message.to_string(),
            };
        }
        let engine = match lifecycle {
            DerivedIndexLifecycle::Opening => return CapabilityState::Opening,
            DerivedIndexLifecycle::ShutdownAbandoned => return CapabilityState::ShutdownAbandoned,
            DerivedIndexLifecycle::Failed(reason) => {
                return CapabilityState::Failed {
                    reason: reason.to_string(),
                };
            }
            DerivedIndexLifecycle::Serving(engine) => engine,
        };
        let phase = runtime.phase();
        let tx_lookup_outage = runtime.tx_lookup_failure.read().clone();
        let compact_filter_outage = runtime.compact_filter_failure.read().clone();
        let script_live_outage = runtime.script_live_failure.read().clone();
        let script_history_outage = runtime.script_history_failure.read().clone();
        let unavailable = [
            (IndexCapability::TxLookup, tx_lookup_outage.is_some()),
            (
                IndexCapability::CompactFilters,
                compact_filter_outage.is_some(),
            ),
            (IndexCapability::ScriptLive, script_live_outage.is_some()),
            (
                IndexCapability::ScriptHistory,
                script_history_outage.is_some(),
            ),
        ]
        .into_iter()
        .filter_map(|(capability, down)| {
            (down && enabled.contains(capability)).then_some(capability)
        })
        .collect::<IndexCapabilities>();
        let observed = if unavailable.is_empty() {
            phase
        } else {
            phase.with_leg(unavailable, super::ReconcileLeg::Forward)
        };
        if let Some((from_height, to_height)) = observed.rolling_back() {
            return CapabilityState::RollingBack {
                from_height,
                to_height,
            };
        }
        let reason = enabled.iter().find_map(|capability| match capability {
            IndexCapability::TxLookup => tx_lookup_outage.clone(),
            IndexCapability::CompactFilters => compact_filter_outage.clone(),
            IndexCapability::ScriptLive => {
                script_live_outage.as_ref().map(|outage| outage.reason())
            }
            IndexCapability::ScriptHistory => script_history_outage.clone(),
        });
        if let Some(reason) = reason {
            let servable = enabled
                .iter()
                .filter(|capability| !unavailable.contains(*capability))
                .collect::<IndexCapabilities>();
            if servable.is_empty() {
                return CapabilityState::Failed {
                    reason: reason.to_string(),
                };
            }
            let rebuilding = phase
                .rebuilding()
                .iter()
                .filter(|capability| !unavailable.contains(*capability))
                .collect::<IndexCapabilities>();
            if rebuilding != IndexCapabilities::NONE {
                return match Self::progress(engine, rebuilding) {
                    Ok(progress) => CapabilityState::Rebuilding {
                        processed_height: progress.processed_height,
                        target_height: progress.target_height,
                    },
                    Err(error) => CapabilityState::Failed {
                        reason: error.to_string(),
                    },
                };
            }
            return match Self::progress(engine, servable) {
                Ok(progress) if progress.synced => CapabilityState::Ready,
                Ok(progress) => CapabilityState::CatchingUp {
                    processed_height: progress.processed_height,
                    target_height: progress.target_height,
                },
                Err(error) => CapabilityState::Failed {
                    reason: error.to_string(),
                },
            };
        }
        let rebuilding = phase.rebuilding();
        if rebuilding != IndexCapabilities::NONE {
            return match Self::progress(engine, rebuilding) {
                Ok(progress) => CapabilityState::Rebuilding {
                    processed_height: progress.processed_height,
                    target_height: progress.target_height,
                },
                Err(error) => CapabilityState::Failed {
                    reason: error.to_string(),
                },
            };
        }
        match Self::progress(engine, enabled) {
            Ok(progress) if progress.synced => CapabilityState::Ready,
            Ok(progress) => CapabilityState::CatchingUp {
                processed_height: progress.processed_height,
                target_height: progress.target_height,
            },
            Err(error) => CapabilityState::Failed {
                reason: error.to_string(),
            },
        }
    }

    fn progress(
        engine: &DerivedIndexQueryEngine,
        required: IndexCapabilities,
    ) -> Result<IndexProgress, TxQueryError> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            match engine.index_progress_for(required) {
                Err(TxQueryError::Retry(_)) if attempts < PROGRESS_READ_ATTEMPTS => {}
                result => return result,
            }
        }
    }

    /// SNP-09: one independent coverage value per enabled projection.
    #[must_use]
    pub fn capability_coverage(&self) -> [Option<u32>; 4] {
        let mut coverage = [None; 4];
        for capability in self.enabled.iter() {
            coverage[capability.index()] = self.coverage_of(capability);
        }
        coverage
    }

    fn coverage_of(&self, capability: IndexCapability) -> Option<u32> {
        let lifecycle = self.lifecycle.as_ref()?.load();
        let engine = match &**lifecycle {
            DerivedIndexLifecycle::Serving(engine) => engine,
            _ => return None,
        };
        let mut attempts = 0;
        loop {
            attempts += 1;
            match engine.index_coverage_for(capability) {
                Err(TxQueryError::Retry(_)) if attempts < PROGRESS_READ_ATTEMPTS => {}
                result => return result.ok().flatten(),
            }
        }
    }
}

impl DerivedIndexCapabilitySource for DerivedIndexCapability {
    fn capability(&self) -> CapabilityStatus {
        let enabled = !self.enabled.is_empty();
        let state = match (&self.lifecycle, &self.runtime) {
            (Some(lifecycle), Some(runtime)) if enabled => {
                Self::report(&lifecycle.load(), runtime, self.enabled)
            }
            _ => CapabilityState::Disabled,
        };
        derived_index_status(enabled, state)
    }

    fn capability_coverage(&self) -> [Option<u32>; 4] {
        self.capability_coverage()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconcile::ReconcileLeg;
    use crate::runtime::query::QueryEngineLive;
    use bitcoin_rs_consensus::primitives::Network;
    use bitcoin_rs_execution::chain::{BlockTree, ChainTxCount, NodeStatus, TipSnapshot};
    use bitcoin_rs_storage::RocksDbStore;

    #[test]
    fn coverage_distinguishes_absent_genesis_and_failed_projections()
    -> Result<(), crate::portable::TestError> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let mut writer = crate::IndexWriter::open(Arc::clone(&store), 1)?;
        let mut tree = BlockTree::new();
        let genesis = Network::Regtest.genesis_block();
        let id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let node = tree.node(id)?;
        let mark = crate::IndexWatermark {
            height: 0,
            hash: node.hash.to_le_bytes(),
        };
        let tip = TipSnapshot {
            tip_id: id,
            height: 0,
            hash: node.hash,
            chainwork: node.chainwork,
            chain_tx_count: ChainTxCount::established(1),
        };
        let applied = Arc::new(arc_swap::ArcSwapOption::from(Some(Arc::new(tip))));
        let (wake, _receiver) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake);
        let engine = Arc::new(DerivedIndexQueryEngine::new(
            Arc::clone(&runtime),
            Arc::new(crate::Indexer::new(Arc::clone(&store))),
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(parking_lot::RwLock::new(
                tree,
            ))),
            bitcoin_rs_execution::chain::TipReader::new(applied),
            None,
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(crate::runtime::Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        ));
        let lifecycle = Arc::new(ArcSwap::from_pointee(DerivedIndexLifecycle::Serving(
            engine,
        )));
        let status = DerivedIndexCapability::new(
            Some(Arc::clone(&lifecycle)),
            Some(Arc::clone(&runtime)),
            IndexCapabilities::ALL,
        );
        assert_eq!(status.capability_coverage(), [None; 4]);
        struct NoSpends;
        impl crate::SpentCoins for NoSpends {
            fn spent_coin(&self, _: &[u8; 32], _: u32) -> Option<crate::SpentCoin<'_>> {
                None
            }
        }
        let prepared = writer.prepare_block_with_spent_scripts(
            IndexCapabilities::ALL,
            0,
            mark.hash,
            &bitcoin_rs_consensus::primitives::consensus_bytes(&genesis),
            &NoSpends,
        )?;
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        batch.try_push(prepared).map_err(|_| "genesis batch")?;
        writer.commit_forward(batch)?;
        assert_eq!(status.capability_coverage(), [Some(0); 4]);
        assert_eq!(status.capability().state, CapabilityState::Ready);
        for capability in [IndexCapability::TxLookup, IndexCapability::CompactFilters] {
            let failure = match capability {
                IndexCapability::TxLookup => &runtime.tx_lookup_failure,
                _ => &runtime.compact_filter_failure,
            };
            *failure.write() = Some("projection unavailable".into());
            let mut expected = [Some(0); 4];
            expected[capability.index()] = None;
            assert_eq!(status.capability_coverage(), expected);
            assert_eq!(status.capability().state, CapabilityState::Ready);
            let single = DerivedIndexCapability::new(
                Some(Arc::clone(&lifecycle)),
                Some(Arc::clone(&runtime)),
                IndexCapabilities::NONE.insert(capability),
            );
            assert!(matches!(
                single.capability().state,
                CapabilityState::Failed { .. }
            ));
            *failure.write() = None;
        }
        runtime.publish_leg(IndexCapabilities::COMPACT_FILTERS, ReconcileLeg::Rebuilding);
        assert!(matches!(
            status.capability().state,
            CapabilityState::Rebuilding { .. }
        ));
        runtime.publish_leg(
            IndexCapabilities::COMPACT_FILTERS,
            ReconcileLeg::RollingBack {
                from_height: 1,
                to_height: 0,
            },
        );
        assert!(matches!(
            status.capability().state,
            CapabilityState::RollingBack { .. }
        ));
        Ok(())
    }
}
