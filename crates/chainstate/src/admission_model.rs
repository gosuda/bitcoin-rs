//! Executable reference model for window-coalesced commit admission.
//!
//! Rust counterpart of the verified Phase 3.6 design models
//! `.outline/proofs/commit-window/Commit.tla` and
//! `.outline/proofs/commit-window/Safety.lean`, with the types, bounds, and
//! harness obligations of `.outline/proofs/commit-window/kani-spec.md`.
//! The model carries one atomic engine batch for head, undo rows, body
//! index, and coin replacements; resident cache install strictly after the
//! durable commit; publication that never leads durability; failure at
//! block j committing only the prefix 0..j-1; and admission closure after
//! an ambiguous durable outcome. This is a design model: it does not
//! establish implementation refinement of the chainstate window commit.

#[cfg(kani)]
mod proofs;

pub(crate) const MAX_ATTEMPTS: u32 = 4;
pub(crate) const JOB_SLOTS: u32 = 12;
pub(crate) const COUNTER_BOUND: u32 = 1_024;
pub(crate) const FRAME_BOUND: u32 = 72;

/// Commit sub-machine phase (TLA `PhaseDom`: 0 idle, 1 preparing, 2 proved,
/// 3 committed, 4 failed).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) enum Phase {
    #[default]
    Idle,
    Preparing,
    Proved,
    Committed,
    Failed,
}

/// Canonical coin role of the window-delta abstraction (TLA `CoinRoles`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum CoinRole {
    /// `c1`: external coin, alternates with `c2` across windows.
    C1,
    /// `c2`: external coin, alternates with `c1` across windows.
    C2,
    /// `c_int`: created and spent inside one prefix, never durable (WIN-04).
    Internal,
    /// `c_bip`: explicit BIP30 duplicate-overwrite target (WIN-07).
    Bip30,
}

impl CoinRole {
    #[must_use]
    pub(crate) const fn bit(self) -> u16 {
        1 << match self {
            Self::C1 => 0,
            Self::C2 => 1,
            Self::Internal => 2,
            Self::Bip30 => 3,
        }
    }

    #[must_use]
    pub(crate) const fn set(self) -> CoinSet {
        CoinSet(self.bit())
    }

    /// TLA `nextCoin`: the external pair alternates, every other role maps
    /// back to `c1`.
    #[must_use]
    pub(crate) const fn next_coin(self) -> Self {
        match self {
            Self::C1 => Self::C2,
            _ => Self::C1,
        }
    }
}

/// Set of [`CoinRole`]s as a fixed four-bit mask (TLA `SUBSET CoinRoles`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct CoinSet(u16);

impl CoinSet {
    pub(crate) const EMPTY: Self = Self(0);
    pub(crate) const ALL_ROLES: Self = Self(0b1111);
    /// TLA `Init`: the durable store starts with `c1` and the BIP30 target.
    pub(crate) const STORE_INIT: Self = Self(0b1001);

    #[must_use]
    pub(crate) const fn contains(self, role: CoinRole) -> bool {
        self.0 & role.bit() != 0
    }

    #[must_use]
    pub(crate) const fn insert(self, role: CoinRole) -> Self {
        Self(self.0 | role.bit())
    }

    #[must_use]
    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub(crate) const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    #[must_use]
    pub(crate) const fn equals(self, other: Self) -> bool {
        self.0 == other.0
    }

    #[must_use]
    pub(crate) const fn is_disjoint(self, other: Self) -> bool {
        self.0 & other.0 == 0
    }

    #[must_use]
    pub(crate) const fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    #[must_use]
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// TLA `\E c \in coinStore \ {"c_bip"}`: the lowest external or internal
    /// role present; the action is disabled when no such witness exists.
    #[must_use]
    pub(crate) const fn first_spendable(self) -> Option<CoinRole> {
        if self.contains(CoinRole::C1) {
            Some(CoinRole::C1)
        } else if self.contains(CoinRole::C2) {
            Some(CoinRole::C2)
        } else if self.contains(CoinRole::Internal) {
            Some(CoinRole::Internal)
        } else {
            None
        }
    }
}

/// One window's net coin effect (TLA `DeltaRecord`).
///
/// Invariant fields: `spent_internal` is disjoint from the durable store and
/// from `created` (WIN-04), `created` is disjoint from `spent` so one
/// replacement per coin record (WIN-05), and `bip30_overwrites` is a subset
/// of `created` (WIN-07).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct WindowDelta {
    /// Cumulative extent of the current proposal (kani-spec `window_delta`).
    pub len: u32,
    pub created: CoinSet,
    pub spent: CoinSet,
    pub spent_internal: CoinSet,
    pub bip30_overwrites: CoinSet,
}

impl WindowDelta {
    /// TLA `DeltaInit`.
    pub(crate) const INIT: Self = Self {
        len: 0,
        created: CoinSet::EMPTY,
        spent: CoinSet::EMPTY,
        spent_internal: CoinSet::EMPTY,
        bip30_overwrites: CoinSet::EMPTY,
    };

    /// Delta sets are dropped at window boundaries while the cumulative
    /// extent stays (kani-spec resets only through `Retry`).
    #[must_use]
    pub(crate) const fn clear_sets(self) -> Self {
        Self {
            len: self.len,
            created: CoinSet::EMPTY,
            spent: CoinSet::EMPTY,
            spent_internal: CoinSet::EMPTY,
            bip30_overwrites: CoinSet::EMPTY,
        }
    }
}

/// State of the window commit and admission machine.
///
/// Field names mirror the TLA variables (`Commit.tla`), the Lean record
/// (`Safety.lean`), and the kani-spec state; `jobs` through `cursor` are the
/// serving/observer fields of the pre-existing Lean mirror.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct State {
    /// Applied epochs published so far (CMT-05).
    pub epoch: u32,
    /// Sync-05: `generation == 2 * epoch`.
    pub generation: u32,
    pub prior_root: u32,
    /// Root reserved by the current job (RCV-02 batch target).
    pub proposed_root: u32,
    /// Root carried by the last atomic batch (`diskRoot`).
    pub disk_root: u32,
    /// Root visible to readers (`liveRoot`; SYNC-05).
    pub live_root: u32,
    /// Prefix body bytes appended (CMT-02 step 2).
    pub body_pos: u32,
    /// Prefix undo bytes appended (CMT-02 step 2).
    pub undo_pos: u32,
    pub sync_body: bool,
    pub sync_undo: bool,
    /// CMT-02 step 3: appended files are synced before their directory.
    pub file_sync: bool,
    pub dir_sync: bool,
    /// Refused windows and ambiguous outcomes against `MAX_ATTEMPTS`.
    pub attempts: u32,
    pub phase: Phase,
    /// Admission job slots held (Lean `jobs`).
    pub jobs: u32,
    /// Cumulative proposal counter (kani-spec `proposed`).
    pub proposed: u32,
    /// Cumulative committed extent (kani-spec `committed`).
    pub committed: u32,
    /// Cumulative published extent (kani-spec `published`).
    pub published: u32,
    pub writer: u32,
    pub reader: u32,
    pub subscribed: u32,
    pub cursor: u32,
    /// The one window delta coalescing the whole valid prefix (WIN-03).
    pub window_delta: WindowDelta,
    /// CMT-02 step 5: resident cache install after the durable commit.
    pub cache_installed: bool,
    /// CMT-04: ambiguous durable outcome closes mutation admission.
    pub admission_closed: bool,
    /// Evaluated blocks of the current window (TLA `blockIdx`).
    pub block_idx: u32,
    /// Valid prefix length the window commits (WIN-06, WIN-08).
    pub valid_prefix_len: u32,
    /// Failing block index; zero when no block failed (WIN-08).
    pub failed_block: u32,
    /// Canonical durable coin set (WIN-04; mutated only by the batch).
    pub coin_store: CoinSet,
    /// Resident cache image (CMT-01; synced at install).
    pub coin_cache: CoinSet,
}

impl Default for State {
    fn default() -> Self {
        Self::init()
    }
}

impl State {
    #[must_use]
    pub(crate) const fn init() -> Self {
        Self {
            epoch: 0,
            generation: 0,
            prior_root: 0,
            proposed_root: 0,
            disk_root: 0,
            live_root: 0,
            body_pos: 0,
            undo_pos: 0,
            sync_body: false,
            sync_undo: false,
            file_sync: false,
            dir_sync: false,
            attempts: 0,
            phase: Phase::Idle,
            jobs: 0,
            proposed: 0,
            committed: 0,
            published: 0,
            writer: 0,
            reader: 0,
            subscribed: 0,
            cursor: 0,
            window_delta: WindowDelta::INIT,
            cache_installed: false,
            admission_closed: false,
            block_idx: 0,
            valid_prefix_len: 0,
            failed_block: 0,
            coin_store: CoinSet::STORE_INIT,
            coin_cache: CoinSet::STORE_INIT,
        }
    }
}

/// Discrete actions of the window commit machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Reserve a window slot and propose a new root (TLA `StartJob`).
    StartJob,
    /// Release a job slot (Lean `finishJob`).
    FinishJob,
    /// Evaluate window block one (TLA `EvalBlock1`).
    EvalBlock1,
    /// Evaluate window block two (TLA `EvalBlock2`).
    EvalBlock2,
    /// Block j fails: j = 1 fails the window, j > 1 commits prefix 0..j-1
    /// (WIN-08; generalizes TLA `FailBlock1`/`FailBlock2`).
    FailBlockJ {
        j: u32,
    },
    /// Complete the evaluated window with one delta over the valid prefix
    /// (TLA `CompleteWindow`, Lean `prepare`).
    PrepareWindow {
        prefix_len: u32,
    },
    /// Append prefix body bytes (TLA `MarkBody`, CMT-02 step 2).
    MarkBody,
    /// Append prefix undo bytes (TLA `MarkUndo`, CMT-02 step 2).
    MarkUndo,
    /// Sync appended files (TLA `SyncFile`, CMT-02 step 3).
    SyncFile,
    /// Sync directory entries (TLA `SyncDirectory`, CMT-02 step 3).
    SyncDirectory,
    /// One atomic engine batch: head, undo, body index, coins
    /// (TLA `Commit`, RCV-02, CMT-01, CMT-02 step 4).
    CommitBatch,
    /// Install the resident cache after the durable commit
    /// (TLA `InstallCache`, CMT-02 step 5, CMT-03).
    InstallCache,
    /// Publish the applied epoch (TLA `PublishPrefix`, CMT-02 step 6,
    /// CMT-05).
    PublishPrefix,
    /// Ambiguous durable outcome closes admission (TLA `FailAmbiguous`,
    /// CMT-04).
    FailAmbiguous,
    /// Account one failed attempt (Lean `failBatch`).
    FailBatch,
    /// Reset a failed window for retry (TLA `Retry`, Lean `retry`).
    Retry,
    /// Subscribe an observer (Lean `subscribe`).
    Subscribe,
    /// Advance the observer cursor (Lean `observe`).
    Observe,
    AcquireWriter,
    ReleaseWriter,
    AcquireReader,
    ReleaseReader,
    Stutter,
}

#[must_use]
pub(crate) const fn step(state: &State, action: Action) -> Option<State> {
    match action {
        Action::StartJob => {
            if !matches!(state.phase, Phase::Idle)
                || state.admission_closed
                || state.jobs >= JOB_SLOTS
                || state.attempts >= MAX_ATTEMPTS
                || state.proposed >= COUNTER_BOUND
                || state.proposed_root >= COUNTER_BOUND
                || state.epoch >= COUNTER_BOUND
                || state.generation > COUNTER_BOUND - 2
            {
                return None;
            }
            Some(State {
                phase: Phase::Preparing,
                proposed_root: state.proposed_root + 1,
                jobs: state.jobs + 1,
                window_delta: state.window_delta.clear_sets(),
                cache_installed: false,
                block_idx: 0,
                valid_prefix_len: 0,
                failed_block: 0,
                ..*state
            })
        }
        Action::FinishJob => {
            if state.jobs == 0 {
                return None;
            }
            Some(State {
                jobs: state.jobs - 1,
                ..*state
            })
        }
        Action::EvalBlock1 => {
            if !matches!(state.phase, Phase::Preparing) || state.block_idx != 0 {
                return None;
            }
            Some(State {
                block_idx: 1,
                ..*state
            })
        }
        Action::EvalBlock2 => {
            if !matches!(state.phase, Phase::Preparing) || state.block_idx != 1 {
                return None;
            }
            Some(State {
                block_idx: 2,
                ..*state
            })
        }
        Action::FailBlockJ { j } => {
            if j == 0 || j > FRAME_BOUND || !matches!(state.phase, Phase::Preparing) {
                return None;
            }
            let evaluated = match j {
                1 => 0,
                2 => 1,
                _ => 2,
            };
            if state.block_idx != evaluated {
                return None;
            }
            if j == 1 {
                if state.attempts >= MAX_ATTEMPTS {
                    return None;
                }
                Some(State {
                    phase: Phase::Failed,
                    attempts: state.attempts + 1,
                    failed_block: 1,
                    valid_prefix_len: 0,
                    window_delta: WindowDelta {
                        len: state.committed,
                        ..state.window_delta
                    },
                    ..*state
                })
            } else {
                let witness = match state.coin_store.first_spendable() {
                    Some(coin) => coin,
                    None => return None,
                };
                if state.proposed >= COUNTER_BOUND {
                    return None;
                }
                let proposed = state.proposed + 1;
                Some(State {
                    phase: Phase::Proved,
                    failed_block: j,
                    valid_prefix_len: j - 1,
                    proposed,
                    window_delta: WindowDelta {
                        len: proposed,
                        created: witness.next_coin().set(),
                        spent: witness.set(),
                        spent_internal: CoinSet::EMPTY,
                        bip30_overwrites: CoinSet::EMPTY,
                    },
                    ..*state
                })
            }
        }
        Action::PrepareWindow { prefix_len } => {
            let witness = match state.coin_store.first_spendable() {
                Some(coin) => coin,
                None => return None,
            };
            if !matches!(state.phase, Phase::Preparing)
                || state.block_idx != 2
                || prefix_len == 0
                || prefix_len > FRAME_BOUND
                || state.proposed >= COUNTER_BOUND
            {
                return None;
            }
            let proposed = state.proposed + 1;
            Some(State {
                phase: Phase::Proved,
                proposed,
                window_delta: WindowDelta {
                    len: proposed,
                    created: witness.next_coin().set().insert(CoinRole::Bip30),
                    spent: witness.set(),
                    spent_internal: CoinRole::Internal.set(),
                    bip30_overwrites: CoinRole::Bip30.set(),
                },
                valid_prefix_len: prefix_len,
                failed_block: 0,
                ..*state
            })
        }
        Action::MarkBody => {
            if !matches!(state.phase, Phase::Proved) || state.file_sync || state.body_pos != 0 {
                return None;
            }
            Some(State {
                body_pos: state.valid_prefix_len,
                sync_body: true,
                ..*state
            })
        }
        Action::MarkUndo => {
            if !matches!(state.phase, Phase::Proved) || state.file_sync || state.undo_pos != 0 {
                return None;
            }
            Some(State {
                undo_pos: state.valid_prefix_len,
                sync_undo: true,
                ..*state
            })
        }
        Action::SyncFile => {
            if !matches!(state.phase, Phase::Proved)
                || !state.sync_body
                || !state.sync_undo
                || state.file_sync
            {
                return None;
            }
            Some(State {
                file_sync: true,
                ..*state
            })
        }
        Action::SyncDirectory => {
            if !matches!(state.phase, Phase::Proved) || !state.file_sync || state.dir_sync {
                return None;
            }
            Some(State {
                dir_sync: true,
                ..*state
            })
        }
        Action::CommitBatch => {
            if !matches!(state.phase, Phase::Proved)
                || !state.file_sync
                || !state.dir_sync
                || state.committed >= state.window_delta.len
            {
                return None;
            }
            Some(State {
                phase: Phase::Committed,
                committed: state.window_delta.len,
                disk_root: state.proposed_root,
                cache_installed: false,
                coin_store: state
                    .coin_store
                    .difference(state.window_delta.spent)
                    .union(state.window_delta.created),
                ..*state
            })
        }
        Action::InstallCache => {
            if !matches!(state.phase, Phase::Committed)
                || state.cache_installed
                || state.committed < state.window_delta.len
            {
                return None;
            }
            Some(State {
                cache_installed: true,
                coin_cache: state.coin_store,
                ..*state
            })
        }
        Action::PublishPrefix => {
            if !matches!(state.phase, Phase::Committed)
                || !state.cache_installed
                || state.published >= state.committed
                || state.epoch >= COUNTER_BOUND
                || state.generation > COUNTER_BOUND - 2
            {
                return None;
            }
            Some(State {
                phase: Phase::Idle,
                live_root: state.disk_root,
                prior_root: state.live_root,
                epoch: state.epoch + 1,
                generation: state.generation + 2,
                published: state.committed,
                body_pos: 0,
                undo_pos: 0,
                sync_body: false,
                sync_undo: false,
                file_sync: false,
                dir_sync: false,
                window_delta: state.window_delta.clear_sets(),
                cache_installed: false,
                block_idx: 0,
                valid_prefix_len: 0,
                failed_block: 0,
                ..*state
            })
        }
        Action::FailAmbiguous => {
            if !matches!(state.phase, Phase::Proved)
                || !state.file_sync
                || !state.dir_sync
                || state.admission_closed
                || state.attempts >= MAX_ATTEMPTS
            {
                return None;
            }
            Some(State {
                phase: Phase::Failed,
                attempts: state.attempts + 1,
                admission_closed: true,
                ..*state
            })
        }
        Action::FailBatch => {
            if state.attempts >= MAX_ATTEMPTS {
                return None;
            }
            Some(State {
                attempts: state.attempts + 1,
                ..*state
            })
        }
        Action::Retry => {
            if !matches!(state.phase, Phase::Failed)
                || state.admission_closed
                || state.attempts >= MAX_ATTEMPTS
            {
                return None;
            }
            Some(State {
                phase: Phase::Idle,
                body_pos: 0,
                undo_pos: 0,
                sync_body: false,
                sync_undo: false,
                file_sync: false,
                dir_sync: false,
                window_delta: WindowDelta {
                    len: state.committed,
                    ..state.window_delta.clear_sets()
                },
                cache_installed: false,
                coin_cache: state.coin_store,
                block_idx: 0,
                valid_prefix_len: 0,
                failed_block: 0,
                ..*state
            })
        }
        Action::Subscribe => Some(State {
            subscribed: 1,
            cursor: 0,
            ..*state
        }),
        Action::Observe => {
            if state.subscribed != 1 || state.cursor >= state.published {
                return None;
            }
            Some(State {
                cursor: state.cursor + 1,
                ..*state
            })
        }
        Action::AcquireWriter => {
            if state.reader != 0 {
                return None;
            }
            Some(State {
                writer: 1,
                ..*state
            })
        }
        Action::ReleaseWriter => Some(State {
            writer: 0,
            ..*state
        }),
        Action::AcquireReader => {
            if state.writer != 0 {
                return None;
            }
            Some(State {
                reader: 1,
                ..*state
            })
        }
        Action::ReleaseReader => Some(State {
            reader: 0,
            ..*state
        }),
        Action::Stutter => Some(*state),
    }
}

// RCV-02, SYNC-05, WIN-03, WIN-04, WIN-05, WIN-06, WIN-07, WIN-08, CMT-01, CMT-02, CMT-03, CMT-04, CMT-05
#[must_use]
pub(crate) const fn safety(state: &State) -> bool {
    state.attempts <= MAX_ATTEMPTS
        && state.jobs <= JOB_SLOTS
        && state.proposed <= COUNTER_BOUND
        && state.published <= state.committed
        && state.committed <= state.window_delta.len
        && state.window_delta.len <= state.proposed
        && state.valid_prefix_len <= FRAME_BOUND
        && state.failed_block <= FRAME_BOUND
        && state.body_pos <= FRAME_BOUND
        && state.undo_pos <= FRAME_BOUND
        && state.block_idx <= 2
        && state.subscribed <= 1
        && state.writer <= 1
        && state.reader <= 1
        && (state.writer == 0 || state.reader == 0)
        && state.cursor <= state.published
        && (state.subscribed == 1 || state.cursor == 0)
        && state.epoch <= COUNTER_BOUND
        && state.generation <= COUNTER_BOUND
        && state.generation == state.epoch * 2
        && state.prior_root <= COUNTER_BOUND
        && state.proposed_root <= COUNTER_BOUND
        && state.disk_root <= COUNTER_BOUND
        && state.live_root <= COUNTER_BOUND
        && (state.failed_block == 0 || state.valid_prefix_len == state.failed_block - 1)
        && (!state.cache_installed || state.committed == state.window_delta.len)
        && (!matches!(state.phase, Phase::Committed) || state.committed == state.window_delta.len)
        && (!matches!(state.phase, Phase::Committed) || state.disk_root == state.proposed_root)
        && (matches!(state.phase, Phase::Committed) || state.live_root == state.disk_root)
        && (!matches!(state.phase, Phase::Committed)
            || (state.file_sync && state.dir_sync && state.body_pos > 0 && state.undo_pos > 0))
        && (!state.file_sync || (state.sync_body && state.sync_undo))
        && (!state.dir_sync || state.file_sync)
        && (state.sync_body == (state.body_pos > 0))
        && (state.sync_undo == (state.undo_pos > 0))
        && (state.body_pos == 0 || state.body_pos == state.valid_prefix_len)
        && (state.undo_pos == 0 || state.undo_pos == state.valid_prefix_len)
        && (!state.cache_installed
            || (matches!(state.phase, Phase::Committed)
                && state.disk_root == state.proposed_root
                && state.coin_cache.equals(state.coin_store)))
        && (!state.admission_closed || matches!(state.phase, Phase::Failed))
        && (!matches!(state.phase, Phase::Idle) || state.coin_cache.equals(state.coin_store))
        && (!matches!(state.phase, Phase::Idle) && !matches!(state.phase, Phase::Preparing)
            || (state.body_pos == 0 && state.undo_pos == 0))
        && (!matches!(state.phase, Phase::Proved) || state.valid_prefix_len >= 1)
        && !state.coin_store.contains(CoinRole::Internal)
        && !state.window_delta.created.contains(CoinRole::Internal)
        && state
            .window_delta
            .spent_internal
            .is_disjoint(state.coin_store)
        && state
            .window_delta
            .created
            .is_disjoint(state.window_delta.spent)
        && state
            .window_delta
            .spent_internal
            .is_disjoint(state.window_delta.created)
        && (state.window_delta.bip30_overwrites.is_empty()
            || state
                .window_delta
                .bip30_overwrites
                .is_subset_of(state.window_delta.created))
}

/// TLA `TypeOK` with the repaired bounds (report 3.1: `MaxAttempts = 4`,
/// `CounterBound = 1024`, `FrameBound = 72`); the extent is cumulative, so
/// its bound is `COUNTER_BOUND` while per-window fields stay under
/// `FRAME_BOUND`.
#[must_use]
pub(crate) const fn type_ok(state: &State) -> bool {
    state.epoch <= COUNTER_BOUND
        && state.generation <= COUNTER_BOUND
        && state.prior_root <= COUNTER_BOUND
        && state.proposed_root <= COUNTER_BOUND
        && state.disk_root <= COUNTER_BOUND
        && state.live_root <= COUNTER_BOUND
        && state.body_pos <= FRAME_BOUND
        && state.undo_pos <= FRAME_BOUND
        && state.attempts <= MAX_ATTEMPTS
        && state.proposed <= COUNTER_BOUND
        && state.committed <= COUNTER_BOUND
        && state.published <= COUNTER_BOUND
        && state.jobs <= JOB_SLOTS
        && state.window_delta.len <= COUNTER_BOUND
        && state.valid_prefix_len <= FRAME_BOUND
        && state.failed_block <= FRAME_BOUND
        && state.block_idx <= 2
        && state.coin_store.is_subset_of(CoinSet::ALL_ROLES)
        && state.coin_cache.is_subset_of(CoinSet::ALL_ROLES)
        && state.writer <= 1
        && state.reader <= 1
        && state.subscribed <= 1
        && state.cursor <= COUNTER_BOUND
}

#[cfg(test)]
mod tests {
    use std::collections::{HashSet, VecDeque};
    use std::sync::Arc;

    use parking_lot::Mutex;

    use bitcoin_rs_consensus::primitives::{Block, BlockHash, BlockPayload, Network};
    use bitcoin_rs_utxo::UtxoSet;
    use proptest::prelude::*;
    use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};

    use super::{
        Action, COUNTER_BOUND, CoinRole, CoinSet, FRAME_BOUND, Phase, State, WindowDelta, safety,
        step, type_ok,
    };
    use crate::test_fixtures::{StagedFire, handles, seed_genesis, staging_recorder};

    const TEST_PROPOSAL_BOUND: u32 = 24;
    const TEST_EPOCH_BOUND: u32 = 8;
    const TEST_JOB_BOUND: u32 = 2;
    const TEST_CURSOR_BOUND: u32 = 4;
    const TEST_PREFIX_BOUND: u32 = 6;

    fn exhaustive_actions() -> Vec<Action> {
        let mut actions = vec![
            Action::StartJob,
            Action::FinishJob,
            Action::EvalBlock1,
            Action::EvalBlock2,
            Action::MarkBody,
            Action::MarkUndo,
            Action::SyncFile,
            Action::SyncDirectory,
            Action::CommitBatch,
            Action::InstallCache,
            Action::PublishPrefix,
            Action::FailAmbiguous,
            Action::FailBatch,
            Action::Retry,
            Action::Subscribe,
            Action::Observe,
            Action::AcquireWriter,
            Action::ReleaseWriter,
            Action::AcquireReader,
            Action::ReleaseReader,
            Action::Stutter,
        ];
        for prefix_len in [1, 2, TEST_PREFIX_BOUND, FRAME_BOUND, 0, FRAME_BOUND + 1] {
            actions.push(Action::PrepareWindow { prefix_len });
        }
        for j in [0, 1, 2, 3, 4, FRAME_BOUND, FRAME_BOUND + 1] {
            actions.push(Action::FailBlockJ { j });
        }
        actions
    }

    fn within_test_bounds(state: &State) -> bool {
        state.proposed_root <= TEST_PROPOSAL_BOUND
            && state.proposed <= TEST_PROPOSAL_BOUND
            && state.epoch <= TEST_EPOCH_BOUND
            && state.jobs <= TEST_JOB_BOUND
            && state.cursor <= TEST_CURSOR_BOUND
            && state.window_delta.len <= TEST_PROPOSAL_BOUND
            && state.valid_prefix_len <= TEST_PREFIX_BOUND
            && state.failed_block <= 4
    }

    fn drive(actions: &[Action]) -> State {
        let mut state = State::init();
        for action in actions {
            let next = step(&state, *action)
                .unwrap_or_else(|| panic!("the oracle trace admits {action:?}"));
            assert!(
                type_ok(&next) && safety(&next),
                "the oracle trace stays safe before the mutation: {action:?}"
            );
            state = next;
        }
        state
    }

    fn mutant_install_cache_before_commit(state: &State) -> Option<State> {
        if (!matches!(state.phase, Phase::Proved) && !matches!(state.phase, Phase::Committed))
            || state.cache_installed
        {
            return None;
        }
        Some(State {
            cache_installed: true,
            coin_cache: state.coin_store,
            ..*state
        })
    }

    fn mutant_publish_before_commit(state: &State) -> Option<State> {
        if (!matches!(state.phase, Phase::Proved) && !matches!(state.phase, Phase::Committed))
            || state.epoch >= COUNTER_BOUND
            || state.generation > COUNTER_BOUND - 2
        {
            return None;
        }
        Some(State {
            phase: Phase::Idle,
            live_root: state.proposed_root,
            epoch: state.epoch + 1,
            generation: state.generation + 2,
            prior_root: state.live_root,
            body_pos: 0,
            undo_pos: 0,
            sync_body: false,
            sync_undo: false,
            file_sync: false,
            dir_sync: false,
            window_delta: state.window_delta.clear_sets(),
            cache_installed: false,
            block_idx: 0,
            valid_prefix_len: 0,
            failed_block: 0,
            ..*state
        })
    }

    fn mutant_commit_with_internal_coin_created(state: &State) -> Option<State> {
        state.coin_store.first_spendable()?;
        if !matches!(state.phase, Phase::Proved)
            || !state.file_sync
            || !state.dir_sync
            || state.committed >= state.window_delta.len
        {
            return None;
        }
        Some(State {
            phase: Phase::Committed,
            committed: state.window_delta.len,
            disk_root: state.proposed_root,
            cache_installed: false,
            coin_store: state
                .coin_store
                .difference(state.window_delta.spent)
                .union(state.window_delta.created)
                .insert(CoinRole::Internal),
            ..*state
        })
    }

    fn mutant_fail_block_two_commits_full_window(state: &State) -> Option<State> {
        let witness = state.coin_store.first_spendable()?;
        if !matches!(state.phase, Phase::Preparing) || state.block_idx != 1 {
            return None;
        }
        Some(State {
            phase: Phase::Proved,
            failed_block: 2,
            valid_prefix_len: FRAME_BOUND,
            proposed: state.proposed + 1,
            window_delta: WindowDelta {
                len: FRAME_BOUND,
                created: witness.next_coin().set(),
                spent: witness.set(),
                spent_internal: CoinSet::EMPTY,
                bip30_overwrites: CoinSet::EMPTY,
            },
            ..*state
        })
    }

    #[test]
    fn safety_holds_from_init() {
        let state = State::init();
        assert!(safety(&state), "the initial state satisfies safety");
        assert!(type_ok(&state), "the initial state satisfies TypeOK");
    }

    #[test]
    fn blocked_actions_return_no_successor() {
        let state = State::init();
        assert_eq!(step(&state, Action::FinishJob), None);
        assert_eq!(step(&state, Action::EvalBlock1), None);
        assert_eq!(step(&state, Action::MarkBody), None);
        assert_eq!(step(&state, Action::CommitBatch), None);
        assert_eq!(step(&state, Action::InstallCache), None);
        assert_eq!(step(&state, Action::PublishPrefix), None);
        assert_eq!(step(&state, Action::Observe), None);
        assert_eq!(step(&state, Action::Retry), None);
        assert_eq!(step(&state, Action::FailAmbiguous), None);
        assert_eq!(step(&state, Action::FailBlockJ { j: 1 }), None);
        let Some(started) = step(&state, Action::StartJob) else {
            panic!("admission is open at init");
        };
        assert_eq!(started.phase, Phase::Preparing);
        assert_eq!(
            step(&started, Action::PrepareWindow { prefix_len: 1 }),
            None,
            "the window completes only after both blocks are evaluated"
        );
        let Some(failed_window) = step(&started, Action::FailBlockJ { j: 1 }) else {
            panic!("the first block may fail");
        };
        assert_eq!(failed_window.phase, Phase::Failed);
        assert_eq!(failed_window.attempts, 1);
        assert_eq!(failed_window.failed_block, 1);
        assert_eq!(
            step(&failed_window, Action::StartJob),
            None,
            "a failed window retries before a new job starts"
        );
        let reserved = State { writer: 1, ..state };
        assert_eq!(step(&reserved, Action::AcquireReader), None);
    }

    #[test]
    fn window_and_block_payloads_honor_frame_bound() {
        let evaluated = drive(&[Action::StartJob, Action::EvalBlock1, Action::EvalBlock2]);
        assert_eq!(
            step(
                &evaluated,
                Action::PrepareWindow {
                    prefix_len: FRAME_BOUND
                }
            )
            .map(|next| next.valid_prefix_len),
            Some(FRAME_BOUND),
            "a full-frame window is admissible"
        );
        assert_eq!(
            step(&evaluated, Action::PrepareWindow { prefix_len: 0 }),
            None
        );
        assert_eq!(
            step(
                &evaluated,
                Action::PrepareWindow {
                    prefix_len: FRAME_BOUND + 1
                }
            ),
            None
        );
        let half_evaluated = drive(&[Action::StartJob, Action::EvalBlock1]);
        assert_eq!(
            step(&half_evaluated, Action::FailBlockJ { j: FRAME_BOUND }),
            None,
            "a block past the evaluated window never fails the prefix"
        );
        assert_eq!(
            step(&half_evaluated, Action::FailBlockJ { j: 2 }).map(|next| next.valid_prefix_len),
            Some(1),
            "failure at block two commits exactly the one-block prefix"
        );
    }

    #[test]
    fn exhaustive_reachable_transitions_preserve_invariants() {
        let actions = exhaustive_actions();
        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();
        seen.insert(State::init());
        queue.push_back(State::init());
        let mut states = 0_u64;
        let mut edges = 0_u64;
        while let Some(state) = queue.pop_front() {
            states += 1;
            for action in &actions {
                let Some(next) = step(&state, *action) else {
                    continue;
                };
                edges += 1;
                assert!(
                    type_ok(&next),
                    "TypeOK breaks after {action:?} from {state:?}"
                );
                assert!(
                    safety(&next),
                    "safety breaks after {action:?} from {state:?}"
                );
                if within_test_bounds(&next) && seen.insert(next) {
                    queue.push_back(next);
                }
            }
        }
        assert!(
            states > 500,
            "the explored fragment must cover the machine: {states}"
        );
        assert!(
            edges > 5_000,
            "every explored state tries every action: {edges}"
        );
        assert!(
            seen.iter()
                .any(|s| s.phase == Phase::Committed && s.cache_installed),
            "the commit and cache install path is reachable in the fragment"
        );
        assert!(
            seen.iter().any(|s| s.admission_closed),
            "the ambiguous failure path is reachable in the fragment"
        );
        assert!(
            seen.iter()
                .any(|s| s.failed_block > 1 && s.phase == Phase::Proved),
            "the WIN-08 prefix commit path is reachable in the fragment"
        );
    }

    #[test]
    fn every_frame_and_block_payload_preserves_invariants() {
        let actions = exhaustive_actions();
        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();
        seen.insert(State::init());
        queue.push_back(State::init());
        let mut edges = 0_u64;
        while let Some(state) = queue.pop_front() {
            for action in &actions {
                let Some(next) = step(&state, *action) else {
                    continue;
                };
                edges += 1;
                assert!(
                    type_ok(&next),
                    "TypeOK breaks after {action:?} from {state:?}"
                );
                assert!(
                    safety(&next),
                    "safety breaks after {action:?} from {state:?}"
                );
                let shallow_counters = next.proposed_root <= 2
                    && next.proposed <= 3
                    && next.epoch <= 2
                    && next.jobs <= 3
                    && next.cursor <= 2;
                if shallow_counters && seen.insert(next) {
                    queue.push_back(next);
                }
            }
        }
        for prefix_len in 1..=FRAME_BOUND {
            let staged = drive(&[
                Action::StartJob,
                Action::EvalBlock1,
                Action::EvalBlock2,
                Action::PrepareWindow { prefix_len },
            ]);
            assert_eq!(
                staged.valid_prefix_len, prefix_len,
                "the window commits the requested prefix"
            );
            assert_eq!(staged.window_delta.len, staged.proposed);
        }
        for j in 1..=FRAME_BOUND {
            let evaluated = match j {
                1 => drive(&[Action::StartJob]),
                2 => drive(&[Action::StartJob, Action::EvalBlock1]),
                _ => drive(&[Action::StartJob, Action::EvalBlock1, Action::EvalBlock2]),
            };
            let Some(next) = step(&evaluated, Action::FailBlockJ { j }) else {
                panic!("failure at block {j} is admissible from {evaluated:?}");
            };
            assert_eq!(next.failed_block, j);
            assert_eq!(next.valid_prefix_len, j - 1);
            assert!(
                type_ok(&next) && safety(&next),
                "block {j} failure stays safe"
            );
        }
        assert!(
            edges > 10_000,
            "the payload sweep exercises every action: {edges}"
        );
    }

    #[test]
    fn random_soak_preserves_the_invariants() {
        let actions = exhaustive_actions();
        let actions_len = u64::try_from(actions.len()).unwrap_or(u64::MAX);
        let mut rng: u64 = 0x243F_6A88_85A3_08D3;
        let mut state = State::init();
        for _ in 0..100_000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let index = usize::try_from(rng % actions_len).unwrap_or_default();
            let action = actions[index];
            if let Some(next) = step(&state, action) {
                assert!(
                    type_ok(&next) && safety(&next),
                    "{action:?} from {state:?} breaks the invariants"
                );
                state = next;
            }
        }
    }

    #[test]
    fn negative_control_install_cache_before_commit_violates_cmt_03() {
        let staged = drive(&[
            Action::StartJob,
            Action::EvalBlock1,
            Action::FailBlockJ { j: 2 },
        ]);
        assert_eq!(staged.phase, Phase::Proved);
        assert!(!staged.cache_installed);
        let Some(mutant) = mutant_install_cache_before_commit(&staged) else {
            panic!("the mutant installs the cache at phase 2");
        };
        assert!(mutant.cache_installed);
        assert_ne!(mutant.phase, Phase::Committed);
        assert_ne!(mutant.disk_root, mutant.proposed_root);
        assert!(
            !safety(&mutant),
            "CMT-03 must reject a cache install before the durable commit"
        );
    }

    #[test]
    fn negative_control_publish_without_commit_violates_sync_05() {
        let staged = drive(&[
            Action::StartJob,
            Action::EvalBlock1,
            Action::FailBlockJ { j: 2 },
        ]);
        let Some(mutant) = mutant_publish_before_commit(&staged) else {
            panic!("the mutant publishes at phase 2");
        };
        assert_eq!(mutant.phase, Phase::Idle);
        assert_ne!(
            mutant.live_root, mutant.disk_root,
            "the mutant exposes the proposed root as the live root"
        );
        assert!(
            !safety(&mutant),
            "an uncommitted disk root must never become the live root"
        );
    }

    #[test]
    fn negative_control_internal_coin_leaks_into_the_coin_store_violates_win_04() {
        let staged = drive(&[
            Action::StartJob,
            Action::EvalBlock1,
            Action::EvalBlock2,
            Action::PrepareWindow { prefix_len: 4 },
            Action::MarkBody,
            Action::MarkUndo,
            Action::SyncFile,
            Action::SyncDirectory,
        ]);
        assert!(!staged.coin_store.contains(CoinRole::Internal));
        let Some(committed) = mutant_commit_with_internal_coin_created(&staged) else {
            panic!("the mutant commits the leaking delta");
        };
        assert!(
            committed.coin_store.contains(CoinRole::Internal),
            "the mutant carries the internal coin into the durable store"
        );
        assert!(
            committed
                .window_delta
                .spent_internal
                .contains(CoinRole::Internal)
        );
        assert!(
            !safety(&committed),
            "create-and-spend coins inside the prefix must never become durable"
        );
    }

    #[test]
    fn negative_control_full_window_commit_on_failure_violates_win_08() {
        let staged = drive(&[Action::StartJob, Action::EvalBlock1]);
        let Some(mutant) = mutant_fail_block_two_commits_full_window(&staged) else {
            panic!("the mutant commits past the failed block");
        };
        assert_eq!(mutant.phase, Phase::Proved);
        assert_eq!(mutant.failed_block, 2);
        assert_eq!(mutant.valid_prefix_len, FRAME_BOUND);
        assert_ne!(
            mutant.valid_prefix_len,
            mutant.failed_block - 1,
            "the mutant commits the full window instead of the prefix 0..1"
        );
        assert!(
            !safety(&mutant),
            "failure at block j must commit only the prefix 0..j-1"
        );
    }

    struct Admissions {
        chainstate: crate::Chainstate,
        parent: BlockHash,
        next_height: u32,
        prepared: Option<Block>,
        proposals: u32,
        attempts: u32,
        delivered: u32,
        hook_installed: bool,
        fires: Arc<Mutex<Vec<StagedFire>>>,
    }

    fn next_block(parent: BlockHash, height: u32) -> Block {
        match bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at(parent, height) {
            Ok(block) => block,
            Err(e) => panic!("a regtest child mines at every height: {e}"),
        }
    }

    fn false_coinbase(block: &Block) -> Block {
        let mut broken = block.clone();
        let Some(coinbase) = broken.txs.first_mut() else {
            return broken;
        };
        let Some(output) = coinbase.outputs.first_mut() else {
            return broken;
        };
        output.value = bitcoin_rs_consensus::primitives::Amount::from_sat(1);
        broken
    }

    impl Admissions {
        fn new() -> Self {
            let chainstate = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let tip = match seed_genesis(&chainstate) {
                Ok(tip) => tip,
                Err(e) => panic!("the genesis tip seeds: {e}"),
            };
            Self {
                chainstate,
                parent: BlockHash::from(tip.hash),
                next_height: 1,
                prepared: None,
                proposals: 0,
                attempts: 0,
                delivered: 0,
                hook_installed: false,
                fires: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn tip_height(&self) -> u32 {
            self.chainstate
                .applied_tip_snapshot()
                .map_or(0, |tip| tip.height)
        }

        fn take_prepared(&mut self) -> Block {
            let height = self.next_height;
            self.prepared
                .take()
                .unwrap_or_else(|| next_block(self.parent, height))
        }

        fn committed(&self) -> u32 {
            match self.chainstate.durable_head.load() {
                Ok(head) => head.map_or(0, |h| h.height),
                Err(e) => panic!("the in-memory durable head reads: {e}"),
            }
        }

        fn pending_fires(&self) -> usize {
            self.fires.lock().len()
        }
    }

    fn proptest_action(index: u8) -> Action {
        match index {
            0 => Action::StartJob,
            1 => Action::FinishJob,
            2 => Action::EvalBlock1,
            3 => Action::EvalBlock2,
            4 => Action::PrepareWindow { prefix_len: 1 },
            5 => Action::PrepareWindow { prefix_len: 4 },
            6 => Action::FailBlockJ { j: 1 },
            7 => Action::FailBlockJ { j: 2 },
            8 => Action::MarkBody,
            9 => Action::MarkUndo,
            10 => Action::SyncFile,
            11 => Action::SyncDirectory,
            12 => Action::CommitBatch,
            13 => Action::InstallCache,
            14 => Action::PublishPrefix,
            15 => Action::FailAmbiguous,
            16 => Action::FailBatch,
            17 => Action::Retry,
            18 => Action::Subscribe,
            19 => Action::Observe,
            20 => Action::AcquireWriter,
            21 => Action::ReleaseWriter,
            22 => Action::AcquireReader,
            23 => Action::ReleaseReader,
            _ => Action::Stutter,
        }
    }

    struct AdmissionReference;

    impl ReferenceStateMachine for AdmissionReference {
        type State = State;
        type Transition = Action;

        fn init_state() -> BoxedStrategy<State> {
            Just(State::init()).boxed()
        }

        fn transitions(_state: &State) -> BoxedStrategy<Action> {
            (0_u8..25).prop_map(proptest_action).boxed()
        }

        fn preconditions(state: &State, transition: &Action) -> bool {
            let subscribed_once = match transition {
                Action::Subscribe => state.subscribed == 0 && state.committed == 0,
                _ => true,
            };
            subscribed_once && step(state, *transition).is_some()
        }

        fn apply(mut state: State, transition: &Action) -> State {
            if let Some(next) = step(&state, *transition) {
                state = next;
            }
            state
        }
    }

    struct AdmissionMachine;

    impl StateMachineTest for AdmissionMachine {
        type SystemUnderTest = Admissions;
        type Reference = AdmissionReference;

        fn init_test(_ref_state: &State) -> Self::SystemUnderTest {
            Admissions::new()
        }

        fn apply(
            mut sut: Self::SystemUnderTest,
            ref_state: &State,
            transition: <Self::Reference as ReferenceStateMachine>::Transition,
        ) -> Self::SystemUnderTest {
            match transition {
                Action::StartJob | Action::AcquireWriter => {
                    let reservation = match sut.chainstate.lock_transition() {
                        Ok(r) => r,
                        Err(e) => panic!("admission is open for a transition: {e}"),
                    };
                    drop(reservation);
                }
                Action::AcquireReader => {
                    assert!(
                        sut.chainstate.applied_tip_snapshot().is_some(),
                        "the applied tip is readable whenever the model admits a reader"
                    );
                }
                Action::EvalBlock1 | Action::EvalBlock2 => {}
                Action::PrepareWindow { .. } => {
                    sut.prepared = Some(next_block(sut.parent, sut.next_height));
                    sut.proposals += 1;
                }
                Action::FailBlockJ { j } => {
                    if j == 1 {
                        let block = sut.take_prepared();
                        let error = match sut
                            .chainstate
                            .apply_block(&BlockPayload::from_local(false_coinbase(&block)))
                        {
                            Err(e) => e,
                            Ok(_) => panic!("a block with a broken proof of work is refused"),
                        };
                        assert!(
                            matches!(error, crate::ApplyError::Consensus(_)),
                            "the refusal must be the predicted consensus failure: {error:?}"
                        );
                        sut.attempts += 1;
                    } else {
                        sut.proposals += 1;
                    }
                }
                Action::MarkBody
                | Action::MarkUndo
                | Action::SyncFile
                | Action::SyncDirectory
                | Action::InstallCache
                | Action::FinishJob
                | Action::Retry => {}
                Action::FailBatch | Action::FailAmbiguous => {
                    sut.attempts += 1;
                }
                Action::CommitBatch => {
                    let block = sut.take_prepared();
                    let outcome = match sut
                        .chainstate
                        .apply_block(&BlockPayload::from_local(block.clone()))
                    {
                        Ok(o) => o,
                        Err(e) => panic!("a valid regtest block commits: {e}"),
                    };
                    assert_eq!(
                        outcome.tip.height, ref_state.committed,
                        "the real applied height must equal the model's committed counter"
                    );
                    sut.parent = block.block_hash();
                    sut.next_height += 1;
                }
                Action::PublishPrefix => {
                    assert_eq!(
                        sut.tip_height(),
                        ref_state.committed,
                        "publication is atomic with the commit, so the applied tip is the committed height"
                    );
                }
                Action::Subscribe => {
                    if !sut.hook_installed {
                        let recorder = staging_recorder(&sut.chainstate, &sut.fires);
                        assert!(
                            sut.chainstate.set_tip_staged(recorder).is_ok(),
                            "the staged hook installs once"
                        );
                        sut.hook_installed = true;
                    }
                }
                Action::Observe => {
                    let fire = sut.fires.lock().remove(0);
                    assert_eq!(
                        fire.staged_height, ref_state.cursor,
                        "each delivered fire is the next published height"
                    );
                    assert_eq!(
                        fire.published.map(|(_, height)| height),
                        fire.staged_height.checked_sub(1),
                        "the staging notification reports the parent tip, before publication"
                    );
                    sut.delivered += 1;
                }
                Action::ReleaseWriter | Action::ReleaseReader | Action::Stutter => {}
            }
            sut
        }

        fn check_invariants(sut: &Self::SystemUnderTest, ref_state: &State) {
            assert!(
                safety(ref_state),
                "the ordered-commit safety predicate must hold after every step: {ref_state:?}"
            );
            assert_eq!(
                sut.committed(),
                ref_state.committed,
                "the durable head height is the model's committed counter"
            );
            assert_eq!(
                sut.tip_height(),
                ref_state.committed,
                "the applied tip is the durable head height: publication is atomic with the commit"
            );
            assert_eq!(
                sut.proposals, ref_state.proposed,
                "every window proposal event counts exactly one proposal"
            );
            assert_eq!(
                sut.attempts, ref_state.attempts,
                "every failed window is one refused attempt"
            );
            assert_eq!(
                sut.delivered, ref_state.cursor,
                "every Observe action consumes exactly one published tip"
            );
            if ref_state.subscribed == 1 {
                assert_eq!(
                    sut.pending_fires(),
                    match usize::try_from(ref_state.committed - ref_state.cursor) {
                        Ok(expected) => expected,
                        Err(e) => panic!("the undelivered count fits usize: {e}"),
                    },
                    "the observer queue holds exactly the applied tips not yet served"
                );
            }
        }
    }

    // RCV-02, SYNC-05
    prop_state_machine! {
        #![proptest_config(ProptestConfig {
            cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(256),
            ..ProptestConfig::default()
        })]
        #[test]
        fn chain_admission_matches_the_reference_model(sequential 1..20 => AdmissionMachine);
    }
}
