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
        let phase = runtime.phase().with_leg(
            IndexCapabilities::COMPACT_FILTERS,
            super::ReconcileLeg::Forward,
        );
        let script_live_outage = runtime.script_live_failure.read().clone();
        let script_history_outage = runtime.script_history_failure.read().clone();
        let unavailable = [
            (IndexCapability::ScriptLive, script_live_outage.is_some()),
            (
                IndexCapability::ScriptHistory,
                script_history_outage.is_some(),
            ),
        ]
        .into_iter()
        .filter_map(|(capability, down)| down.then_some(capability))
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
        let reason = script_live_outage
            .map(|outage| outage.reason())
            .or(script_history_outage);
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
        Self::progress(engine, IndexCapabilities::NONE.insert(capability))
            .ok()
            .map(|progress| progress.processed_height)
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
