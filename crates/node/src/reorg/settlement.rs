//! Generation settlement and checkpoint debt after a coherent branch change.

use super::ReorgError;
use crate::apply::ChainTransition;
use crate::apply::Chainstate;

/// Settles a rolled-back disconnect marker once the reorg owner has released
/// its chain-transition proof.
///
/// A successful chainstate-journal rewind already disarms the marker, in which
/// case this is a no-op. Publication runs only when `RolledBack` debt remains.
pub(super) fn settle_disconnect_debt(handles: &Chainstate) -> core::result::Result<(), ReorgError> {
    match handles.checkpoint() {
        Ok(true) => {
            tracing::info!("published checkpoint after branch switch");
            Ok(())
        }
        Ok(false) => Ok(()),
        Err(error) => Err(ReorgError::CheckpointSettlement(anyhow::Error::new(error))),
    }
}

/// Completes a coherent reorg attempt before publishing its disconnect debt.
/// Potentially torn state retains the odd generation and never checkpoints.
pub(super) fn settle_reorg_transition(
    transition: ChainTransition<'_>,
    outcome: core::result::Result<(), ReorgError>,
) -> core::result::Result<(), ReorgError> {
    if outcome.as_ref().is_err_and(ReorgError::requires_recovery) {
        return outcome;
    }
    let handles = transition.chainstate();
    if let Err(source) = transition.finish() {
        handles.admission.close_permanently();
        handles
            .shutdown
            .store(true, std::sync::atomic::Ordering::Release);
        tracing::error!(
            original = ?outcome,
            finish = %source,
            "reorg generation could not be settled; admission remains closed"
        );
        return Err(ReorgError::TransitionSettlement {
            source: Box::new(source),
            original: outcome.err().map(Box::new),
        });
    }
    if let Err(settlement) = settle_disconnect_debt(handles) {
        tracing::error!(%settlement, "reorg checkpoint debt remains unsettled");
        outcome?;
        return Err(settlement);
    }
    outcome
}
