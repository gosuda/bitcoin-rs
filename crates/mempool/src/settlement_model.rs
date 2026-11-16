//! Executable reference model for mempool settlement from committed facts and atomic mining template views.

#[cfg(kani)]
mod proofs;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SettlementError {
    #[error("mining template request is stale or mempool is unsettled")]
    TemplateStaleOrUnsettled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SettlementState {
    pub applied_epoch: u32,
    pub settled_at_epoch: u32,
    pub mempool_gen: u64,
    pub template_active: bool,
    pub template_epoch: u32,
    pub template_gen: u64,
    pub template_has_confirmed: bool,
    pub unsettled_confirmed_count: u32,
    pub facts_queue_len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    AdmitTx,
    CommitBlock,
    CommitReorg,
    SettleConnectFact { clears_confirmed: bool },
    SettleDisconnectFact,
    AssembleTemplate { req_epoch: u32, req_gen: u64 },
    MineBlock,
    Stutter,
}

impl SettlementState {
    #[must_use]
    pub(crate) const fn init() -> Self {
        Self {
            applied_epoch: 1,
            settled_at_epoch: 1,
            mempool_gen: 0,
            template_active: false,
            template_epoch: 0,
            template_gen: 0,
            template_has_confirmed: false,
            unsettled_confirmed_count: 0,
            facts_queue_len: 0,
        }
    }

    pub(crate) fn assemble_template(
        &mut self,
        req_epoch: u32,
        req_gen: u64,
    ) -> Result<(), SettlementError> {
        if req_epoch == self.applied_epoch
            && req_gen == self.mempool_gen
            && self.settled_at_epoch == self.applied_epoch
        {
            self.template_active = true;
            self.template_epoch = req_epoch;
            self.template_gen = req_gen;
            self.template_has_confirmed = self.unsettled_confirmed_count > 0;
            Ok(())
        } else {
            Err(SettlementError::TemplateStaleOrUnsettled)
        }
    }
}

// MPS-01, MPS-03
#[must_use]
pub(crate) fn step(s: &SettlementState, a: Action) -> SettlementState {
    let mut next = s.clone();
    match a {
        Action::AdmitTx => {
            next.mempool_gen = next.mempool_gen.saturating_add(1);
        }
        Action::CommitBlock => {
            next.applied_epoch = next.applied_epoch.saturating_add(1);
            next.facts_queue_len = next.facts_queue_len.saturating_add(1);
            next.unsettled_confirmed_count = next.unsettled_confirmed_count.saturating_add(1);
            next.template_active = false;
            next.template_has_confirmed = false;
        }
        Action::CommitReorg => {
            next.applied_epoch = next.applied_epoch.saturating_add(1);
            next.facts_queue_len = next.facts_queue_len.saturating_add(2);
            next.template_active = false;
            next.template_has_confirmed = false;
        }
        Action::SettleConnectFact { clears_confirmed } => {
            if next.facts_queue_len > 0 {
                let new_queue_len = next.facts_queue_len - 1;
                let new_confirmed = if clears_confirmed && next.unsettled_confirmed_count > 0 {
                    next.unsettled_confirmed_count - 1
                } else {
                    next.unsettled_confirmed_count
                };
                let new_settled = if new_queue_len == 0 {
                    next.applied_epoch
                } else {
                    next.settled_at_epoch
                };
                next.facts_queue_len = new_queue_len;
                next.mempool_gen = next.mempool_gen.saturating_add(1);
                next.unsettled_confirmed_count = if new_queue_len == 0 { 0 } else { new_confirmed };
                next.settled_at_epoch = new_settled;
            }
        }
        Action::SettleDisconnectFact => {
            if next.facts_queue_len > 0 {
                let new_queue_len = next.facts_queue_len - 1;
                let new_settled = if new_queue_len == 0 {
                    next.applied_epoch
                } else {
                    next.settled_at_epoch
                };
                next.facts_queue_len = new_queue_len;
                next.mempool_gen = next.mempool_gen.saturating_add(1);
                next.unsettled_confirmed_count = if new_queue_len == 0 {
                    0
                } else {
                    next.unsettled_confirmed_count
                };
                next.settled_at_epoch = new_settled;
            }
        }
        Action::AssembleTemplate { req_epoch, req_gen } => {
            let _ = next.assemble_template(req_epoch, req_gen);
        }
        Action::MineBlock => {
            if next.template_active && next.template_epoch == next.applied_epoch {
                next.template_active = false;
                next.template_has_confirmed = false;
            }
        }
        Action::Stutter => {}
    }
    next
}

// MPS-03
#[must_use]
pub(crate) fn step_mutant_unsettled_assembly(s: &SettlementState, a: Action) -> SettlementState {
    let mut next = s.clone();
    match a {
        Action::AssembleTemplate { req_epoch, req_gen } => {
            if req_epoch == next.applied_epoch && req_gen == next.mempool_gen {
                next.template_active = true;
                next.template_epoch = req_epoch;
                next.template_gen = req_gen;
                next.template_has_confirmed = next.unsettled_confirmed_count > 0;
            }
        }
        _ => return step(s, a),
    }
    next
}

/// Safety invariant for MempoolSettlement.
// MPS-01, MPS-03
#[must_use]
pub(crate) fn settlement_safety(s: &SettlementState) -> bool {
    s.settled_at_epoch <= s.applied_epoch
        && ((s.facts_queue_len == 0) == (s.settled_at_epoch == s.applied_epoch))
        && (s.settled_at_epoch != s.applied_epoch || s.unsettled_confirmed_count == 0)
        && (!s.template_active
            || (s.facts_queue_len == 0
                && s.template_epoch == s.applied_epoch
                && s.template_epoch == s.settled_at_epoch
                && !s.template_has_confirmed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashSet, VecDeque};

    // MPS-01, MPS-03
    #[test]
    fn settlement_init_is_safe() {
        let s = SettlementState::init();
        assert!(settlement_safety(&s));
        assert_eq!(s.applied_epoch, 1);
        assert_eq!(s.settled_at_epoch, 1);
        assert_eq!(s.facts_queue_len, 0);
        assert!(!s.template_active);
    }

    // MPS-01
    #[test]
    fn orderly_settlement_fifo_preserves_safety() {
        let mut s = SettlementState::init();
        s = step(&s, Action::CommitBlock);
        assert_eq!(s.applied_epoch, 2);
        assert_eq!(s.settled_at_epoch, 1);
        assert_eq!(s.facts_queue_len, 1);
        assert_eq!(s.unsettled_confirmed_count, 1);
        assert!(settlement_safety(&s));

        s = step(&s, Action::CommitBlock);
        assert_eq!(s.applied_epoch, 3);
        assert_eq!(s.settled_at_epoch, 1);
        assert_eq!(s.facts_queue_len, 2);
        assert_eq!(s.unsettled_confirmed_count, 2);
        assert!(settlement_safety(&s));

        s = step(
            &s,
            Action::SettleConnectFact {
                clears_confirmed: true,
            },
        );
        assert_eq!(s.applied_epoch, 3);
        assert_eq!(s.settled_at_epoch, 1);
        assert_eq!(s.facts_queue_len, 1);
        assert_eq!(s.unsettled_confirmed_count, 1);
        assert!(settlement_safety(&s));

        s = step(
            &s,
            Action::SettleConnectFact {
                clears_confirmed: true,
            },
        );
        assert_eq!(s.applied_epoch, 3);
        assert_eq!(s.settled_at_epoch, 3);
        assert_eq!(s.facts_queue_len, 0);
        assert_eq!(s.unsettled_confirmed_count, 0);
        assert!(settlement_safety(&s));
    }

    // MPS-03
    #[test]
    fn mining_template_matched_pair_enforcement() {
        let mut s = SettlementState::init();
        assert_eq!(s.assemble_template(1, 0), Ok(()));
        assert!(s.template_active);
        assert!(!s.template_has_confirmed);
        assert!(settlement_safety(&s));

        s = step(&s, Action::CommitBlock);
        assert!(!s.template_active);
        assert_eq!(
            s.assemble_template(s.applied_epoch, s.mempool_gen),
            Err(SettlementError::TemplateStaleOrUnsettled)
        );

        s = step(
            &s,
            Action::SettleConnectFact {
                clears_confirmed: true,
            },
        );
        assert_eq!(s.assemble_template(s.applied_epoch, s.mempool_gen), Ok(()));
        assert!(s.template_active);
        assert!(!s.template_has_confirmed);
        assert!(settlement_safety(&s));
    }

    // MPS-01, MPS-03
    #[test]
    fn reorg_unsettles_consistently() {
        let mut s = SettlementState::init();
        assert!(s.assemble_template(1, 0).is_ok());

        s = step(&s, Action::CommitReorg);
        assert!(!s.template_active);
        assert_eq!(s.facts_queue_len, 2);
        assert_eq!(s.settled_at_epoch, 1);
        assert_eq!(s.applied_epoch, 2);
        assert!(settlement_safety(&s));

        assert_eq!(
            s.assemble_template(s.applied_epoch, s.mempool_gen),
            Err(SettlementError::TemplateStaleOrUnsettled)
        );

        s = step(&s, Action::SettleDisconnectFact);
        assert_eq!(s.facts_queue_len, 1);
        assert_eq!(s.settled_at_epoch, 1);
        assert!(settlement_safety(&s));
        assert_eq!(
            s.assemble_template(s.applied_epoch, s.mempool_gen),
            Err(SettlementError::TemplateStaleOrUnsettled)
        );

        s = step(
            &s,
            Action::SettleConnectFact {
                clears_confirmed: false,
            },
        );
        assert_eq!(s.facts_queue_len, 0);
        assert_eq!(s.settled_at_epoch, 2);
        assert!(settlement_safety(&s));
        assert!(s.assemble_template(s.applied_epoch, s.mempool_gen).is_ok());
    }

    // MPS-01, MPS-03
    #[test]
    fn settlement_bfs_exhaustive_verification() {
        #[derive(Hash, PartialEq, Eq, Clone)]
        struct BfsState {
            applied_epoch: u32,
            settled_at_epoch: u32,
            mempool_gen_mod: u64,
            template_active: bool,
            template_epoch: u32,
            template_has_confirmed: bool,
            unsettled_confirmed_count: u32,
            facts_queue_len: u32,
        }

        fn to_bfs(s: &SettlementState) -> BfsState {
            BfsState {
                applied_epoch: s.applied_epoch,
                settled_at_epoch: s.settled_at_epoch,
                mempool_gen_mod: s.mempool_gen % 4,
                template_active: s.template_active,
                template_epoch: s.template_epoch,
                template_has_confirmed: s.template_has_confirmed,
                unsettled_confirmed_count: s.unsettled_confirmed_count,
                facts_queue_len: s.facts_queue_len,
            }
        }

        let max_epoch = 3;
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        let initial = SettlementState::init();
        assert!(settlement_safety(&initial));
        visited.insert(to_bfs(&initial));
        queue.push_back(initial);

        while let Some(curr) = queue.pop_front() {
            let actions = [
                Action::AdmitTx,
                Action::CommitBlock,
                Action::CommitReorg,
                Action::SettleConnectFact {
                    clears_confirmed: true,
                },
                Action::SettleConnectFact {
                    clears_confirmed: false,
                },
                Action::SettleDisconnectFact,
                Action::AssembleTemplate {
                    req_epoch: curr.applied_epoch,
                    req_gen: curr.mempool_gen,
                },
                Action::AssembleTemplate {
                    req_epoch: curr.settled_at_epoch,
                    req_gen: curr.mempool_gen,
                },
                Action::AssembleTemplate {
                    req_epoch: curr.applied_epoch.saturating_add(1),
                    req_gen: curr.mempool_gen,
                },
                Action::MineBlock,
                Action::Stutter,
            ];

            for a in actions {
                if matches!(a, Action::CommitBlock | Action::CommitReorg)
                    && curr.applied_epoch >= max_epoch
                {
                    continue;
                }
                let next = step(&curr, a);
                assert!(
                    settlement_safety(&next),
                    "inductive safety violated at state: {next:?}"
                );
                let repr = to_bfs(&next);
                if visited.insert(repr) {
                    queue.push_back(next);
                }
            }
        }
        assert!(visited.len() > 50);
    }

    // MPS-03
    #[test]
    fn negative_control_mutant_fails_safety_exhaustive() {
        let mut s = SettlementState::init();
        s = step(&s, Action::CommitBlock);
        assert_eq!(s.facts_queue_len, 1);
        assert_eq!(s.unsettled_confirmed_count, 1);
        assert_ne!(s.settled_at_epoch, s.applied_epoch);

        let mutant = step_mutant_unsettled_assembly(
            &s,
            Action::AssembleTemplate {
                req_epoch: s.applied_epoch,
                req_gen: s.mempool_gen,
            },
        );
        assert!(mutant.template_active);
        assert!(mutant.template_has_confirmed);
        assert!(
            !settlement_safety(&mutant),
            "mutant must violate settlement safety when assembling during in-flight commit"
        );
    }
}
