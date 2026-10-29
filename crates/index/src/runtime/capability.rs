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
            enabled: enabled.without(crate::IndexCapability::CompactFilters),
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
        let observed = if script_live_outage.is_some() {
            phase.with_leg(IndexCapabilities::SCRIPT_LIVE, super::ReconcileLeg::Forward)
        } else {
            phase
        };
        if let Some((from_height, to_height)) = observed.rolling_back() {
            return CapabilityState::RollingBack {
                from_height,
                to_height,
            };
        }
        if let Some(reason) = script_live_outage {
            let servable = enabled.without(IndexCapability::ScriptLive);
            if servable.is_empty() {
                return CapabilityState::Failed {
                    reason: reason.to_string(),
                };
            }
            let rebuilding = phase.rebuilding().without(IndexCapability::ScriptLive);
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
                Err(TxQueryError::Retry) if attempts < PROGRESS_READ_ATTEMPTS => {}
                result => return result,
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
}
