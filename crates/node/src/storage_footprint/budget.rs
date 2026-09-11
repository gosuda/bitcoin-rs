//! Explicit applicability and evaluation of the default unpruned storage budget.

use super::BudgetEvidence;
use super::DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES;
use super::EvidenceIdentity;
use bitcoin_rs_storage::PhysicalLedger;
use bitcoin_rs_storage::PhysicalObservationKind;

pub(super) fn budget_evidence(
    identity: &EvidenceIdentity,
    physical: &PhysicalLedger,
) -> BudgetEvidence {
    let applies = is_default_unpruned_mainnet(identity);
    let over_budget = physical.budget_bytes() > DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES;
    let conservative_high_water =
        physical.observation_kind == PhysicalObservationKind::ConservativeHighWater;
    let verdict = if !applies {
        "inapplicable"
    } else if over_budget {
        "fail"
    } else if !conservative_high_water {
        "snapshot_insufficient"
    } else if !identity.stop_pinned {
        "tip_unpinned"
    } else {
        "pass"
    };
    BudgetEvidence {
        default_unpruned_limit_bytes: DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES,
        applies_to_this_record: applies,
        verdict: verdict.to_owned(),
    }
}

pub(super) fn is_default_unpruned_mainnet(identity: &EvidenceIdentity) -> bool {
    identity.network == "mainnet"
        && identity.backend == "fjall"
        && identity.prune_target_mb == 0
        && !identity.txindex
        && identity.script_index == "disabled"
        && !identity.blockfilterindex
}
