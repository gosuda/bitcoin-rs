//! The authoritative backend-neutral ledger.
//!
//! Every mutation buffers all logical table effects against one coherent snapshot, then commits
//! one durable batch guarded by that snapshot's revision. A local mutex serializes this handle;
//! the revision comparison rejects stale writes from other handles. Reads use coherent snapshots.
//! Authoritative chain observations are fetched
//! before the write transaction (no external call is made while the write lock is held) and each
//! applied observation is re-validated against the stored record inside the transaction. Every
//! mutating call is idempotent: replaying it after a crash or a lost reply changes nothing the
//! second time, because the identity it keys on (header hash, block hash, idempotency key, txid,
//! round or batch state) is checked inside the same transaction that would apply it.

use crate::kv::{Database, Table, TableDefinition, WriteTransaction};
use bitcoin_rs_storage::KvStore;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
#[cfg(feature = "test-seam")]
use std::sync::Mutex;

use crate::codec::{Dec, Enc};
use crate::{
    AuditKind, AuditRecord, Balance, BatchState, BatchTransition, BlockFound, BlockRecorded,
    CancelBasis, ChainView, Closure, Confirmation, ExternalSigner, Hash32, LedgerError,
    MAX_BATCH_OUTPUTS, MAX_EXTRANONCE_LEN, MAX_MONEY_SAT, MAX_SCRIPT_LEN, MinerId,
    ObservedCoinbase, OutPoint, PayoutBatch, PayoutOutput, PayoutPolicy, PayoutReceipt,
    PayoutRequest, PoolConfig, ReceiptError, Round, RoundState, RoundTransition, ShareCredit,
    ShareReceipt, SignedTx, TxStatus, WindowAccumulator, compute_batch_id, parse_transaction,
    split_pool_fee, split_reward, verify_payout_transaction,
};

/// Most signed transactions (RBF replacements) recorded for one batch.
pub const MAX_SIGNED_TXS_PER_BATCH: usize = 32;
const MAX_INPUTS_PER_TX: usize = 100_000;
const SCHEMA_VERSION: u64 = 1;
const AUDIT_DOMAIN: &[u8] = b"btcrs.pool.audit.v1";
const AUDIT_BODY_LEN: usize = 1 + 8 + 32 + 32 + 24;
const ZERO_HASH: Hash32 = [0u8; 32];

type U64Bytes = TableDefinition<'static, u64, &'static [u8]>;
type BytesBytes = TableDefinition<'static, &'static [u8], &'static [u8]>;
type BytesU64 = TableDefinition<'static, &'static [u8], u64>;
type BytesU128 = TableDefinition<'static, &'static [u8], u128>;
type U64Unit = TableDefinition<'static, u64, ()>;

const META_U64: TableDefinition<'static, &'static str, u64> =
    TableDefinition::new("pplns_meta_u64_v1");
const META_BYTES: TableDefinition<'static, &'static str, &'static [u8]> =
    TableDefinition::new("pplns_meta_bytes_v1");
const SHARES: U64Bytes = TableDefinition::new("pplns_shares_v1");
const SHARE_HASHES: BytesBytes = TableDefinition::new("pplns_share_hashes_v1");
const SHARE_TUPLES: BytesBytes = TableDefinition::new("pplns_share_tuples_v1");
const RETIRED_JOBS: U64Unit = TableDefinition::new("pplns_retired_jobs_v1");
const ROUNDS: U64Bytes = TableDefinition::new("pplns_rounds_v1");
const ROUND_BY_BLOCK: BytesU64 = TableDefinition::new("pplns_round_by_block_v1");
const ROUND_WEIGHTS: BytesU128 = TableDefinition::new("pplns_round_weights_v1");
const ROUND_ALLOCS: BytesU64 = TableDefinition::new("pplns_round_allocs_v1");
const OPEN_ROUNDS: U64Unit = TableDefinition::new("pplns_open_rounds_v1");
const BALANCES: U64Bytes = TableDefinition::new("pplns_balances_v1");
const SCRIPTS: U64Bytes = TableDefinition::new("pplns_scripts_v1");
const BATCHES: BytesBytes = TableDefinition::new("pplns_batches_v1");
const ACTIVE_BATCHES: U64Bytes = TableDefinition::new("pplns_active_batches_v1");
const BATCH_IDEM: BytesBytes = TableDefinition::new("pplns_batch_idem_v1");
const BATCH_TXIDS: BytesBytes = TableDefinition::new("pplns_batch_txids_v1");
const AUDIT: U64Bytes = TableDefinition::new("pplns_audit_v1");

const M_SCHEMA: &str = "schema";
const M_NEXT_RUN_EPOCH: &str = "next_run_epoch";
const M_NEXT_SHARE: &str = "next_share_seq";
const M_NEXT_ROUND: &str = "next_round_id";
const M_NEXT_BATCH: &str = "next_batch_seq";
const M_NEXT_AUDIT: &str = "next_audit_seq";
const M_PRUNED_BELOW: &str = "pruned_below_seq";
const M_CONFIG: &str = "config";
const M_AUDIT_HEAD: &str = "audit_head";

/// Operation name of [`Ledger::record_share`] for fail plans.
pub const OP_RECORD_SHARE: &str = "record_share";
/// Operation name of [`Ledger::retire_job`] for fail plans.
pub const OP_RETIRE_JOB: &str = "retire_job";
/// Operation name of [`Ledger::prune_shares`] for fail plans.
pub const OP_PRUNE_SHARES: &str = "prune_shares";
/// Operation name of [`Ledger::record_found_block`] for fail plans.
pub const OP_RECORD_BLOCK: &str = "record_found_block";
/// Operation name of [`Ledger::reconcile_rounds`] for fail plans.
pub const OP_RECONCILE_ROUNDS: &str = "reconcile_rounds";
/// Operation name of [`Ledger::set_payout_script`] for fail plans.
pub const OP_SET_SCRIPT: &str = "set_payout_script";
/// Operation name of [`Ledger::prepare_payout_batch`] for fail plans.
pub const OP_PREPARE_PAYOUT: &str = "prepare_payout_batch";
/// Operation name of [`Ledger::record_signed`] for fail plans.
pub const OP_RECORD_SIGNED: &str = "record_signed";
/// Operation name of [`Ledger::record_broadcast`] for fail plans.
pub const OP_RECORD_BROADCAST: &str = "record_broadcast";
/// Operation name of [`Ledger::cancel_prepared`] for fail plans.
pub const OP_CANCEL_PREPARED: &str = "cancel_prepared";
/// Operation name of [`Ledger::reconcile_payouts`] for fail plans.
pub const OP_RECONCILE_PAYOUTS: &str = "reconcile_payouts";

// ---------------------------------------------------------------------------------------------
// Fail plan (test seam for crash and power-loss interruption)
// ---------------------------------------------------------------------------------------------

/// Where in an operation the fail plan fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(feature = "test-seam")]
pub enum FailPoint {
    /// After every table change, immediately before durable commit (the change is lost).
    BeforeCommit,
    /// Immediately after durable commit (the change is durable but the caller sees no result).
    AfterCommit,
}

/// What the fail plan does when it fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(feature = "test-seam")]
pub enum FailAction {
    /// Return [`LedgerError::Injected`].
    ReturnError,
    /// Abort the whole process (SIGABRT), as a power loss would: no destructor runs.
    AbortProcess,
}

/// A one-shot interruption of the named operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(feature = "test-seam")]
pub struct FailPlan {
    /// One of the `OP_*` constants.
    pub op: &'static str,
    /// Where the plan fires.
    pub point: FailPoint,
    /// What it does.
    pub action: FailAction,
}

// ---------------------------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------------------------

/// A round that needs operator attention and was left unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundAnomaly {
    /// Round id.
    pub round: u64,
    /// Why the round was not advanced.
    pub reason: &'static str,
}

/// Result of [`Ledger::reconcile_rounds`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoundReconcileReport {
    /// State changes applied.
    pub transitions: Vec<RoundTransition>,
    /// Rounds left unchanged because the chain contradicts the job owner's claim.
    pub anomalies: Vec<RoundAnomaly>,
}

/// Totals verified by [`Ledger::check_invariants`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InvariantReport {
    /// Accounts with a balance or any credited allocation.
    pub accounts: usize,
    /// Rounds.
    pub rounds: usize,
    /// Batches.
    pub batches: usize,
    /// Sum of allocations of Matured rounds.
    pub credited_sat: u128,
    /// Sum of `available_sat`.
    pub available_sat: u128,
    /// Sum of `reserved_sat`.
    pub reserved_sat: u128,
    /// Sum of `paid_sat`.
    pub paid_sat: u128,
    /// Sum of `deficit_sat`.
    pub deficit_sat: u128,
}

// ---------------------------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------------------------

/// Durable PPLNS accounting over a node-owned backend-neutral store.
pub struct Ledger {
    db: Database,
    config: PoolConfig,
    #[cfg(feature = "test-seam")]
    fail_plan: Mutex<Option<FailPlan>>,
}

struct Tables<'t> {
    meta_u64: Table<'t, &'static str, u64>,
    meta_bytes: Table<'t, &'static str, &'static [u8]>,
    shares: Table<'t, u64, &'static [u8]>,
    share_hashes: Table<'t, &'static [u8], &'static [u8]>,
    share_tuples: Table<'t, &'static [u8], &'static [u8]>,
    retired_jobs: Table<'t, u64, ()>,
    rounds: Table<'t, u64, &'static [u8]>,
    round_by_block: Table<'t, &'static [u8], u64>,
    round_weights: Table<'t, &'static [u8], u128>,
    round_allocs: Table<'t, &'static [u8], u64>,
    open_rounds: Table<'t, u64, ()>,
    balances: Table<'t, u64, &'static [u8]>,
    scripts: Table<'t, u64, &'static [u8]>,
    batches: Table<'t, &'static [u8], &'static [u8]>,
    active_batches: Table<'t, u64, &'static [u8]>,
    batch_idem: Table<'t, &'static [u8], &'static [u8]>,
    batch_txids: Table<'t, &'static [u8], &'static [u8]>,
    audit: Table<'t, u64, &'static [u8]>,
}

impl<'t> Tables<'t> {
    fn open(txn: &'t WriteTransaction<'_>) -> Result<Self, LedgerError> {
        Ok(Self {
            meta_u64: txn.open_table(META_U64)?,
            meta_bytes: txn.open_table(META_BYTES)?,
            shares: txn.open_table(SHARES)?,
            share_hashes: txn.open_table(SHARE_HASHES)?,
            share_tuples: txn.open_table(SHARE_TUPLES)?,
            retired_jobs: txn.open_table(RETIRED_JOBS)?,
            rounds: txn.open_table(ROUNDS)?,
            round_by_block: txn.open_table(ROUND_BY_BLOCK)?,
            round_weights: txn.open_table(ROUND_WEIGHTS)?,
            round_allocs: txn.open_table(ROUND_ALLOCS)?,
            open_rounds: txn.open_table(OPEN_ROUNDS)?,
            balances: txn.open_table(BALANCES)?,
            scripts: txn.open_table(SCRIPTS)?,
            batches: txn.open_table(BATCHES)?,
            active_batches: txn.open_table(ACTIVE_BATCHES)?,
            batch_idem: txn.open_table(BATCH_IDEM)?,
            batch_txids: txn.open_table(BATCH_TXIDS)?,
            audit: txn.open_table(AUDIT)?,
        })
    }
}

impl Ledger {
    /// Create a ledger in an empty ledger namespace of the supplied store.
    ///
    /// # Errors
    /// Returns [`LedgerError::PathExists`] if the ledger namespace is occupied.
    /// Existing data is never migrated, overwritten or reset implicitly.
    pub fn create(store: Arc<dyn KvStore>, config: PoolConfig) -> Result<Self, LedgerError> {
        config.validate()?;
        let encoded = config.encode()?;
        let db = Database::new(store);
        let txn = db.begin_write()?;
        if !txn.namespace_is_empty()? {
            return Err(LedgerError::PathExists);
        }
        {
            let tables = Tables::open(&txn)?;
            tables.meta_bytes.insert(M_CONFIG, encoded.as_slice())?;
            tables.meta_u64.insert(M_SCHEMA, SCHEMA_VERSION)?;
        }
        txn.commit()?;
        Ok(Self {
            db,
            config,
            #[cfg(feature = "test-seam")]
            fail_plan: Mutex::new(None),
        })
    }

    /// Reopen an existing ledger. The stored configuration must equal `config`.
    ///
    /// # Errors
    /// Returns [`LedgerError::NotALedger`] if the store holds no valid ledger,
    /// [`LedgerError::ConfigMismatch`] if the stored configuration differs, or a storage error.
    pub fn open(store: Arc<dyn KvStore>, config: PoolConfig) -> Result<Self, LedgerError> {
        config.validate()?;
        let encoded = config.encode()?;
        let db = Database::new(store);
        {
            let read = db.begin_read()?;
            let bytes_table = read.open_table(META_BYTES)?;
            let counter_table = read.open_table(META_U64)?;
            let schema = counter_table.get(M_SCHEMA)?.map(|guard| guard.value());
            if schema != Some(SCHEMA_VERSION) || !read.has_revision() {
                return Err(LedgerError::NotALedger);
            }
            let stored = bytes_table
                .get(M_CONFIG)?
                .map(|guard| guard.value().to_vec());
            match stored {
                Some(existing) if existing == encoded => {}
                Some(_) => return Err(LedgerError::ConfigMismatch),
                None => return Err(LedgerError::NotALedger),
            }
        }
        Ok(Self {
            db,
            config,
            #[cfg(feature = "test-seam")]
            fail_plan: Mutex::new(None),
        })
    }

    /// The immutable accounting configuration.
    #[must_use]
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// Allocate a durable, nonzero namespace for one pool runtime's wire-job identifiers.
    ///
    /// Combine this epoch with a 32-bit wire id as `(u64::from(epoch) << 32) | wire_id`.
    /// Epochs are never reused, including after an ambiguous durability error; a caller must
    /// allocate again rather than assume a failed allocation did not commit.
    ///
    /// # Errors
    /// Returns a revision conflict, storage error, or overflow once the epoch space is exhausted.
    pub fn allocate_run_epoch(&self) -> Result<u32, LedgerError> {
        let txn = self.db.begin_write()?;
        let epoch = {
            let tables = Tables::open(&txn)?;
            let epoch = bump(&tables.meta_u64, M_NEXT_RUN_EPOCH, 1)?;
            u32::try_from(epoch).map_err(|_| LedgerError::Overflow("pool run epoch"))?
        };
        self.commit(txn, "allocate_run_epoch")?;
        Ok(epoch)
    }

    /// Arm a one-shot interruption (test seam). Replaces any armed plan.
    #[cfg(feature = "test-seam")]
    pub fn arm_fail_plan(&self, plan: FailPlan) {
        let mut slot = self
            .fail_plan
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = Some(plan);
    }

    /// Remove any armed plan.
    #[cfg(feature = "test-seam")]
    pub fn disarm_fail_plan(&self) {
        let mut slot = self
            .fail_plan
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = None;
    }

    #[cfg(feature = "test-seam")]
    fn inject(&self, op: &'static str, point: FailPoint) -> Result<(), LedgerError> {
        let fired = {
            let mut slot = self
                .fail_plan
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match *slot {
                Some(plan) if plan.op == op && plan.point == point => {
                    *slot = None;
                    Some(plan)
                }
                _ => None,
            }
        };
        match fired {
            None => Ok(()),
            Some(plan) => match plan.action {
                FailAction::ReturnError => Err(LedgerError::Injected(op)),
                FailAction::AbortProcess => std::process::abort(),
            },
        }
    }

    /// Commit with the fail plan hooks. Returning early drops (rolls back) the transaction.
    fn commit(&self, txn: WriteTransaction<'_>, op: &'static str) -> Result<(), LedgerError> {
        let _ = self;
        #[cfg(feature = "test-seam")]
        self.inject(op, FailPoint::BeforeCommit)?;
        txn.commit()?;
        #[cfg(feature = "test-seam")]
        self.inject(op, FailPoint::AfterCommit)?;
        let _ = op;
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // Shares
    // -----------------------------------------------------------------------------------------

    /// Credit one accepted share. Idempotent on the header hash.
    ///
    /// # Errors
    /// Returns [`LedgerError::JobRetired`], [`LedgerError::ShareConflict`],
    /// [`LedgerError::ShareIdentityConflict`] or an input/storage error.
    pub fn record_share(&self, share: &ShareCredit) -> Result<ShareReceipt, LedgerError> {
        share.validate()?;
        let txn = self.db.begin_write()?;
        let receipt = {
            let tables = Tables::open(&txn)?;
            credit_share(&tables, share)?
        };
        if matches!(receipt, ShareReceipt::Credited { .. }) {
            self.commit(txn, OP_RECORD_SHARE)?;
        }
        Ok(receipt)
    }

    /// Retire a job: later shares for it are refused and its identity index rows are deleted so
    /// the index stays bounded. Call only after the job's found block (if any) is recorded.
    /// Returns the number of index rows removed.
    ///
    /// # Errors
    /// Returns a storage error.
    pub fn retire_job(&self, job: u64) -> Result<usize, LedgerError> {
        let txn = self.db.begin_write()?;
        let removed = {
            let tables = Tables::open(&txn)?;
            if tables.retired_jobs.get(job)?.is_some() {
                return Ok(0);
            }
            let start = job.to_be_bytes();
            let upper = job.checked_add(1).map(u64::to_be_bytes);
            let mut rows: Vec<(Vec<u8>, Hash32)> = Vec::new();
            {
                let iter = match upper.as_ref() {
                    Some(end) => tables
                        .share_tuples
                        .range(start.as_slice()..end.as_slice())?,
                    None => tables.share_tuples.range(start.as_slice()..)?,
                };
                for item in iter {
                    let (key, value) = item?;
                    rows.push((key.value().to_vec(), hash_from(value.value())?));
                }
            }
            for (key, hash) in &rows {
                tables.share_tuples.remove(key.as_slice())?;
                tables.share_hashes.remove(hash.as_slice())?;
            }
            tables.retired_jobs.insert(job, ())?;
            rows.len()
        };
        self.commit(txn, OP_RETIRE_JOB)?;
        Ok(removed)
    }

    /// Delete the oldest shares, keeping the newest shares that hold at least `keep_work` work.
    /// `keep_work` must cover the PPLNS window. A block found later for an older solving share
    /// fails with [`LedgerError::WindowPruned`] instead of using a short window.
    /// Returns the number of shares deleted.
    ///
    /// # Errors
    /// Returns [`LedgerError::InvalidInput`] if `keep_work` is below the window, or an
    /// overflow/storage error.
    pub fn prune_shares(&self, keep_work: u128) -> Result<u64, LedgerError> {
        if keep_work < self.config.window_work {
            return Err(LedgerError::InvalidInput(
                "keep_work must cover the PPLNS window",
            ));
        }
        let txn = self.db.begin_write()?;
        let removed = {
            let tables = Tables::open(&txn)?;
            let mut cumulative: u128 = 0;
            let mut boundary: Option<u64> = None;
            for item in tables.shares.rows_iter()?.rev() {
                let (key, value) = item?;
                let (_, work) = decode_share(value.value())?;
                cumulative = cumulative
                    .checked_add(work)
                    .ok_or(LedgerError::Overflow("retained share work"))?;
                if cumulative >= keep_work {
                    boundary = Some(key.value());
                    break;
                }
            }
            let Some(boundary) = boundary else {
                return Ok(0);
            };
            let doomed: Vec<u64> = tables
                .shares
                .range(..boundary)?
                .map(|item| item.map(|(key, _)| key.value()))
                .collect::<Result<Vec<u64>, LedgerError>>()?;
            if doomed.is_empty() {
                return Ok(0);
            }
            for seq in &doomed {
                tables.shares.remove(*seq)?;
            }
            let previous = meta_u64(&tables.meta_u64, M_PRUNED_BELOW)?;
            if boundary > previous {
                tables.meta_u64.insert(M_PRUNED_BELOW, boundary)?;
            }
            let removed =
                u64::try_from(doomed.len()).map_err(|_| LedgerError::Overflow("count"))?;
            append_audit(
                &tables,
                AuditKind::SharesPruned,
                0,
                &ZERO_HASH,
                &ZERO_HASH,
                [boundary, removed, low64(cumulative)],
            )?;
            removed
        };
        self.commit(txn, OP_PRUNE_SHARES)?;
        Ok(removed)
    }

    /// The PPLNS window ending at the newest share: `(account, work)` ascending by account.
    ///
    /// # Errors
    /// Returns a storage or overflow error.
    pub fn current_window(&self) -> Result<Vec<(MinerId, u128)>, LedgerError> {
        let read = self.db.begin_read()?;
        let shares = read.open_table(SHARES)?;
        let meta = read.open_table(META_U64)?;
        let newest = shares.last()?.map(|(key, _)| key.value());
        let Some(newest) = newest else {
            return Ok(Vec::new());
        };
        let pruned_below = meta_u64(&meta, M_PRUNED_BELOW)?;
        let window = collect_window(&shares, pruned_below, newest, self.config.window_work)?;
        Ok(window.into_weights())
    }

    /// Sequence number and work of the credited share with this header hash.
    ///
    /// # Errors
    /// Returns a storage or codec error.
    pub fn share_by_hash(&self, header_hash: &Hash32) -> Result<Option<(u64, u128)>, LedgerError> {
        let read = self.db.begin_read()?;
        let hashes = read.open_table(SHARE_HASHES)?;
        let entry = match hashes.get(header_hash.as_slice())? {
            Some(guard) => Some(decode_hash_entry(guard.value())?),
            None => None,
        };
        Ok(entry.map(|(seq, work, _)| (seq, work)))
    }

    /// Number of shares currently stored (pruned shares are not counted).
    ///
    /// # Errors
    /// Returns a storage error.
    pub fn share_count(&self) -> Result<u64, LedgerError> {
        let read = self.db.begin_read()?;
        read.open_table(SHARES)?.len()
    }

    // -----------------------------------------------------------------------------------------
    // Found blocks and rounds
    // -----------------------------------------------------------------------------------------

    /// Record a found block: credit its share and snapshot the PPLNS window, in one transaction.
    /// The round starts Pending; no money exists until [`Ledger::reconcile_rounds`] observes the
    /// block on the active chain. Idempotent on the block hash.
    ///
    /// # Errors
    /// Returns [`LedgerError::BlockConflict`] if the block is already recorded with a different
    /// claim, [`LedgerError::WindowPruned`], or any share-crediting error.
    pub fn record_found_block(&self, found: &BlockFound) -> Result<BlockRecorded, LedgerError> {
        found.share.validate()?;
        let block_hash = found.share.header_hash;
        let txn = self.db.begin_write()?;
        let (recorded, newly) = {
            let tables = Tables::open(&txn)?;
            let existing = round_id_for_block(&tables.round_by_block, &block_hash)?;
            if let Some(id) = existing {
                let round = load_round(&tables.rounds, id)?
                    .ok_or_else(|| LedgerError::Corrupt("round index points at no round".into()))?;
                if round.height != found.height
                    || round.coinbase_txid != found.coinbase_txid
                    || round.claimed_coinbase_value_sat != found.claimed_coinbase_value_sat
                {
                    return Err(LedgerError::BlockConflict);
                }
                let seq = round.solving_seq;
                return Ok(BlockRecorded {
                    round,
                    share: ShareReceipt::Duplicate { seq },
                    newly_recorded: false,
                });
            }
            let share_receipt = credit_share(&tables, &found.share)?;
            let solving_seq = share_receipt.seq();
            let pruned_below = meta_u64(&tables.meta_u64, M_PRUNED_BELOW)?;
            let window = collect_window(
                &tables.shares,
                pruned_below,
                solving_seq,
                self.config.window_work,
            )?;
            let window_total = window.total();
            let weights = window.into_weights();
            let id = bump(&tables.meta_u64, M_NEXT_ROUND, 1)?;
            let round = Round {
                id,
                block_hash,
                height: found.height,
                solving_seq,
                coinbase_txid: found.coinbase_txid,
                claimed_coinbase_value_sat: found.claimed_coinbase_value_sat,
                window_work_total: window_total,
                reward_fixed: false,
                gross_sat: 0,
                pool_fee_sat: 0,
                net_sat: 0,
                state: RoundState::Pending,
            };
            store_round(&tables.rounds, &round)?;
            tables.round_by_block.insert(block_hash.as_slice(), id)?;
            for (account, weight) in &weights {
                tables
                    .round_weights
                    .insert(round_key(id, *account).as_slice(), *weight)?;
            }
            tables.open_rounds.insert(id, ())?;
            append_audit(
                &tables,
                AuditKind::RoundRecorded,
                id,
                &block_hash,
                &ZERO_HASH,
                [u64::from(found.height), low64(window_total), solving_seq],
            )?;
            (
                BlockRecorded {
                    round,
                    share: share_receipt,
                    newly_recorded: true,
                },
                true,
            )
        };
        if newly {
            self.commit(txn, OP_RECORD_BLOCK)?;
        }
        Ok(recorded)
    }

    /// Advance every monitored round from authoritative chain observations: fix the reward from
    /// the observed coinbase, mature it, orphan it on a reorg, and reverse credits when a matured
    /// block is displaced. Safe to call as often as desired.
    ///
    /// # Errors
    /// Returns a chain-observer error (nothing is changed) or a storage/overflow error.
    pub fn reconcile_rounds(
        &self,
        chain: &dyn ChainView,
    ) -> Result<RoundReconcileReport, LedgerError> {
        let open = self.open_round_list()?;
        let mut report = RoundReconcileReport::default();
        if open.is_empty() {
            return Ok(report);
        }
        let tip = chain.tip_height()?;
        let mut observations = Vec::with_capacity(open.len());
        for round in &open {
            let canon = match chain.block_location(&round.block_hash, round.height)? {
                crate::BlockLocation::Canonical { height } if height == round.height => {
                    Canon::Canonical
                }
                crate::BlockLocation::Canonical { .. } | crate::BlockLocation::Side => {
                    Canon::Displaced
                }
                crate::BlockLocation::Unknown => Canon::Unknown,
            };
            let coinbase = if canon == Canon::Canonical && !round.reward_fixed {
                chain.coinbase_of(&round.block_hash)?
            } else {
                None
            };
            observations.push(RoundObservation {
                id: round.id,
                block_hash: round.block_hash,
                canon,
                coinbase,
            });
        }
        let txn = self.db.begin_write()?;
        let mut dirty = false;
        {
            let tables = Tables::open(&txn)?;
            for observation in &observations {
                let outcome = apply_round_observation(&tables, &self.config, observation, tip)?;
                dirty |= outcome.dirty;
                if let Some(transition) = outcome.transition {
                    report.transitions.push(transition);
                }
                if let Some(reason) = outcome.anomaly {
                    report.anomalies.push(RoundAnomaly {
                        round: observation.id,
                        reason,
                    });
                }
            }
        }
        if dirty {
            self.commit(txn, OP_RECONCILE_ROUNDS)?;
        }
        Ok(report)
    }

    fn open_round_list(&self) -> Result<Vec<Round>, LedgerError> {
        let read = self.db.begin_read()?;
        let open = read.open_table(OPEN_ROUNDS)?;
        let rounds = read.open_table(ROUNDS)?;
        let mut list = Vec::new();
        for item in open.rows_iter()? {
            let (key, _) = item?;
            if let Some(round) = load_round(&rounds, key.value())? {
                list.push(round);
            }
        }
        Ok(list)
    }

    /// The round with this id.
    ///
    /// # Errors
    /// Returns a storage or codec error.
    pub fn round(&self, id: u64) -> Result<Option<Round>, LedgerError> {
        let read = self.db.begin_read()?;
        load_round(&read.open_table(ROUNDS)?, id)
    }

    /// The round recorded for this block hash.
    ///
    /// # Errors
    /// Returns a storage or codec error.
    pub fn round_for_block(&self, block_hash: &Hash32) -> Result<Option<Round>, LedgerError> {
        let read = self.db.begin_read()?;
        let index = read.open_table(ROUND_BY_BLOCK)?;
        match round_id_for_block(&index, block_hash)? {
            Some(id) => load_round(&read.open_table(ROUNDS)?, id),
            None => Ok(None),
        }
    }

    /// Stored allocations of a round (empty until the reward is fixed).
    ///
    /// # Errors
    /// Returns a storage error.
    pub fn round_allocations(&self, id: u64) -> Result<Vec<(MinerId, u64)>, LedgerError> {
        let read = self.db.begin_read()?;
        load_allocs(&read.open_table(ROUND_ALLOCS)?, id)
    }

    /// The PPLNS window weights snapshotted for a round.
    ///
    /// # Errors
    /// Returns a storage error.
    pub fn round_weights(&self, id: u64) -> Result<Vec<(MinerId, u128)>, LedgerError> {
        let read = self.db.begin_read()?;
        load_weights(&read.open_table(ROUND_WEIGHTS)?, id)
    }

    // -----------------------------------------------------------------------------------------
    // Accounts
    // -----------------------------------------------------------------------------------------

    /// Balance of an account (all zero if unknown).
    ///
    /// # Errors
    /// Returns a storage or codec error.
    pub fn balance(&self, account: MinerId) -> Result<Balance, LedgerError> {
        let read = self.db.begin_read()?;
        load_balance(&read.open_table(BALANCES)?, account)
    }

    /// The payout script of an account, if one is registered.
    ///
    /// # Errors
    /// Returns a storage error.
    pub fn payout_script(&self, account: MinerId) -> Result<Option<Vec<u8>>, LedgerError> {
        let read = self.db.begin_read()?;
        let scripts = read.open_table(SCRIPTS)?;
        Ok(scripts.get(account.0)?.map(|guard| guard.value().to_vec()))
    }

    /// Register or change the payout script of an account. Batches already prepared keep the
    /// script they snapshotted. Authenticating the account owner is the pool server's job.
    ///
    /// # Errors
    /// Returns [`LedgerError::InvalidInput`] for an empty, oversized or `OP_RETURN` script.
    pub fn set_payout_script(&self, account: MinerId, script: &[u8]) -> Result<(), LedgerError> {
        crate::validate_script(script)?;
        let txn = self.db.begin_write()?;
        let changed = {
            let tables = Tables::open(&txn)?;
            let same = match tables.scripts.get(account.0)? {
                Some(guard) => guard.value() == script,
                None => false,
            };
            if same {
                false
            } else {
                tables.scripts.insert(account.0, script)?;
                append_audit(
                    &tables,
                    AuditKind::PayoutScriptSet,
                    account.0,
                    &crate::sha256(script),
                    &ZERO_HASH,
                    [0, 0, 0],
                )?;
                true
            }
        };
        if changed {
            self.commit(txn, OP_SET_SCRIPT)?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // Payout batches
    // -----------------------------------------------------------------------------------------

    /// Reserve available balances into a new immutable payout batch (or return the batch already
    /// created for `idempotency_key`). Returns `None` when no account qualifies.
    ///
    /// # Errors
    /// Returns [`LedgerError::InvalidInput`] for a policy below the dust limit or out of range.
    pub fn prepare_payout_batch(
        &self,
        idempotency_key: Hash32,
        policy: PayoutPolicy,
    ) -> Result<Option<PayoutBatch>, LedgerError> {
        if policy.min_payout_sat < self.config.dust_limit_sat
            || policy.min_payout_sat > MAX_MONEY_SAT
        {
            return Err(LedgerError::InvalidInput(
                "min_payout_sat below the dust limit",
            ));
        }
        if policy.max_outputs == 0 || policy.max_outputs > MAX_BATCH_OUTPUTS {
            return Err(LedgerError::InvalidInput("max_outputs out of range"));
        }
        let txn = self.db.begin_write()?;
        let created = {
            let tables = Tables::open(&txn)?;
            let existing = match tables.batch_idem.get(idempotency_key.as_slice())? {
                Some(guard) => Some(hash_from(guard.value())?),
                None => None,
            };
            if let Some(id) = existing {
                let batch = load_batch(&tables.batches, &id)?.ok_or_else(|| {
                    LedgerError::Corrupt("idempotency index points at no batch".into())
                })?;
                return Ok(Some(batch));
            }
            let mut picks: Vec<PayoutOutput> = Vec::new();
            for item in tables.balances.rows_iter()? {
                let (key, value) = item?;
                let balance = decode_balance(value.value())?;
                if balance.available_sat < policy.min_payout_sat {
                    continue;
                }
                let account = MinerId(key.value());
                let script = match tables.scripts.get(account.0)? {
                    Some(guard) => guard.value().to_vec(),
                    None => continue,
                };
                picks.push(PayoutOutput {
                    account,
                    script_pubkey: script,
                    amount_sat: balance.available_sat,
                });
                if picks.len() == policy.max_outputs {
                    break;
                }
            }
            if picks.is_empty() {
                return Ok(None);
            }
            let total = crate::check_outputs(&picks)?;
            let id = compute_batch_id(&idempotency_key, &picks)?;
            let seq = bump(&tables.meta_u64, M_NEXT_BATCH, 1)?;
            for pick in &picks {
                let mut balance = load_balance(&tables.balances, pick.account)?;
                balance.available_sat = balance
                    .available_sat
                    .checked_sub(pick.amount_sat)
                    .ok_or(LedgerError::Overflow("reserve exceeds available"))?;
                balance.reserved_sat = balance
                    .reserved_sat
                    .checked_add(pick.amount_sat)
                    .ok_or(LedgerError::Overflow("reserved balance"))?;
                store_balance(&tables.balances, pick.account, &balance)?;
            }
            let batch = PayoutBatch {
                id,
                seq,
                idempotency_key,
                state: BatchState::Prepared,
                rev: 1,
                outputs: picks,
                total_sat: total,
                transactions: Vec::new(),
                broadcast_txid: None,
                confirmation: None,
                closure: None,
            };
            store_batch(&tables.batches, &batch)?;
            tables.active_batches.insert(seq, id.as_slice())?;
            tables
                .batch_idem
                .insert(idempotency_key.as_slice(), id.as_slice())?;
            let outputs =
                u64::try_from(batch.outputs.len()).map_err(|_| LedgerError::Overflow("count"))?;
            append_audit(
                &tables,
                AuditKind::BatchPrepared,
                seq,
                &id,
                &ZERO_HASH,
                [total, outputs, 0],
            )?;
            batch
        };
        self.commit(txn, OP_PREPARE_PAYOUT)?;
        Ok(Some(created))
    }

    /// The batch with this id.
    ///
    /// # Errors
    /// Returns a storage or codec error.
    pub fn batch(&self, id: &Hash32) -> Result<Option<PayoutBatch>, LedgerError> {
        let read = self.db.begin_read()?;
        load_batch(&read.open_table(BATCHES)?, id)
    }

    /// The batch created for an idempotency key.
    ///
    /// # Errors
    /// Returns a storage or codec error.
    pub fn batch_for_idempotency_key(
        &self,
        key: &Hash32,
    ) -> Result<Option<PayoutBatch>, LedgerError> {
        let read = self.db.begin_read()?;
        let index = read.open_table(BATCH_IDEM)?;
        let id = match index.get(key.as_slice())? {
            Some(guard) => Some(hash_from(guard.value())?),
            None => None,
        };
        match id {
            Some(id) => load_batch(&read.open_table(BATCHES)?, &id),
            None => Ok(None),
        }
    }

    /// Batches still reserving funds or inside the reorg watch window, oldest first.
    ///
    /// # Errors
    /// Returns a storage or codec error.
    pub fn active_batches(&self) -> Result<Vec<PayoutBatch>, LedgerError> {
        let read = self.db.begin_read()?;
        let active = read.open_table(ACTIVE_BATCHES)?;
        let batches = read.open_table(BATCHES)?;
        let mut list = Vec::new();
        for item in active.rows_iter()? {
            let (_, value) = item?;
            let id = hash_from(value.value())?;
            if let Some(batch) = load_batch(&batches, &id)? {
                list.push(batch);
            }
        }
        Ok(list)
    }

    /// The canonical unsigned instructions for an open batch.
    ///
    /// # Errors
    /// Returns [`LedgerError::UnknownBatch`] or [`LedgerError::IllegalTransition`] for a batch
    /// that no longer awaits payment.
    pub fn request_for(&self, id: &Hash32) -> Result<PayoutRequest, LedgerError> {
        let batch = self.batch(id)?.ok_or(LedgerError::UnknownBatch(*id))?;
        if !batch.state.holds_reservation() {
            return Err(LedgerError::IllegalTransition {
                batch: *id,
                from: batch.state,
                action: "export a payout request",
            });
        }
        Ok(PayoutRequest {
            batch_id: batch.id,
            outputs: batch.outputs,
            total_sat: batch.total_sat,
            allowed_change_scripts: self.config.change_scripts.clone(),
        })
    }

    /// Ask `signer` to sign the batch and record its receipt.
    ///
    /// # Errors
    /// Returns the signer's error, or any [`Ledger::record_signed`] error.
    pub fn sign_via(
        &self,
        id: &Hash32,
        signer: &dyn ExternalSigner,
    ) -> Result<PayoutBatch, LedgerError> {
        let request = self.request_for(id)?;
        let receipt = signer.sign(&request)?;
        if receipt.batch_id != *id {
            return Err(LedgerError::InvalidInput(
                "signer answered for a different batch",
            ));
        }
        self.record_signed(&receipt)
    }

    /// Record a signed transaction for a batch after verifying that it pays exactly the batch
    /// outputs (plus at most one allowed change output) and that its recomputed txid equals the
    /// claimed one. A replacement transaction must share an input with every earlier signed
    /// transaction of the batch so at most one of them can ever confirm. Idempotent per txid.
    ///
    /// # Errors
    /// Returns [`LedgerError::Receipt`] when the transaction is refused,
    /// [`LedgerError::UnknownBatch`] or [`LedgerError::IllegalTransition`].
    pub fn record_signed(&self, receipt: &PayoutReceipt) -> Result<PayoutBatch, LedgerError> {
        let parsed = parse_transaction(&receipt.raw_tx).map_err(ReceiptError::from)?;
        if parsed.txid != receipt.txid {
            return Err(ReceiptError::TxidMismatch.into());
        }
        let txn = self.db.begin_write()?;
        let batch = {
            let tables = Tables::open(&txn)?;
            let mut batch = load_batch(&tables.batches, &receipt.batch_id)?
                .ok_or(LedgerError::UnknownBatch(receipt.batch_id))?;
            if batch.transactions.iter().any(|tx| tx.txid == parsed.txid) {
                return Ok(batch);
            }
            if !batch.state.holds_reservation() {
                return Err(LedgerError::IllegalTransition {
                    batch: batch.id,
                    from: batch.state,
                    action: "record a signed transaction",
                });
            }
            if batch.transactions.len() >= MAX_SIGNED_TXS_PER_BATCH {
                return Err(LedgerError::InvalidInput(
                    "too many signed transactions for one batch",
                ));
            }
            if tables.batch_txids.get(parsed.txid.as_slice())?.is_some() {
                return Err(ReceiptError::TxidInOtherBatch.into());
            }
            verify_payout_transaction(&batch.outputs, &self.config.change_scripts, &parsed)?;
            let new_inputs: BTreeSet<OutPoint> = parsed.inputs.iter().copied().collect();
            for existing in &batch.transactions {
                if !existing
                    .inputs
                    .iter()
                    .any(|input| new_inputs.contains(input))
                {
                    return Err(ReceiptError::NotConflicting {
                        existing_txid: existing.txid,
                    }
                    .into());
                }
            }
            let input_count =
                u64::try_from(parsed.inputs.len()).map_err(|_| LedgerError::Overflow("count"))?;
            batch.transactions.push(SignedTx {
                txid: parsed.txid,
                inputs: parsed.inputs.clone(),
            });
            if batch.state == BatchState::Prepared {
                batch.state = BatchState::ExternallySigned;
            }
            batch.rev = next_rev(batch.rev)?;
            store_batch(&tables.batches, &batch)?;
            tables
                .batch_txids
                .insert(parsed.txid.as_slice(), batch.id.as_slice())?;
            append_audit(
                &tables,
                AuditKind::BatchSigned,
                batch.seq,
                &batch.id,
                &parsed.txid,
                [input_count, 0, 0],
            )?;
            batch
        };
        self.commit(txn, OP_RECORD_SIGNED)?;
        Ok(batch)
    }

    /// Mark a batch Broadcast after the chain observer sees one of its signed transactions in the
    /// mempool or in a block. Nothing is inferred from the signer or from a "sent" claim.
    ///
    /// # Errors
    /// Returns [`LedgerError::NotObserved`] if the observer does not know the transaction.
    pub fn record_broadcast(
        &self,
        batch_id: &Hash32,
        txid: &Hash32,
        chain: &dyn ChainView,
    ) -> Result<PayoutBatch, LedgerError> {
        let current = self
            .batch(batch_id)?
            .ok_or(LedgerError::UnknownBatch(*batch_id))?;
        if !current.transactions.iter().any(|tx| tx.txid == *txid) {
            return Err(LedgerError::InvalidInput(
                "txid is not a signed transaction of this batch",
            ));
        }
        if chain.tx_status(txid)? == TxStatus::Unknown {
            return Err(LedgerError::NotObserved(*txid));
        }
        let txn = self.db.begin_write()?;
        let (batch, changed) = {
            let tables = Tables::open(&txn)?;
            let mut batch = load_batch(&tables.batches, batch_id)?
                .ok_or(LedgerError::UnknownBatch(*batch_id))?;
            if !batch.transactions.iter().any(|tx| tx.txid == *txid) {
                return Err(LedgerError::InvalidInput(
                    "txid is not a signed transaction of this batch",
                ));
            }
            let changed = match batch.state {
                BatchState::ExternallySigned => {
                    batch.state = BatchState::Broadcast;
                    batch.broadcast_txid = Some(*txid);
                    true
                }
                BatchState::Broadcast => {
                    if batch.broadcast_txid == Some(*txid) {
                        false
                    } else {
                        batch.broadcast_txid = Some(*txid);
                        true
                    }
                }
                BatchState::Confirmed => false,
                other => {
                    return Err(LedgerError::IllegalTransition {
                        batch: batch.id,
                        from: other,
                        action: "record a broadcast",
                    });
                }
            };
            if changed {
                batch.rev = next_rev(batch.rev)?;
                store_batch(&tables.batches, &batch)?;
                append_audit(
                    &tables,
                    AuditKind::BatchBroadcast,
                    batch.seq,
                    &batch.id,
                    txid,
                    [0, 0, 0],
                )?;
            }
            (batch, changed)
        };
        if changed {
            self.commit(txn, OP_RECORD_BROADCAST)?;
        }
        Ok(batch)
    }

    /// Cancel a Prepared batch and release its reservation. The ledger cannot verify the
    /// operator's attestation about the signer; it is recorded in the audit trail. A batch with a
    /// signed transaction can never be cancelled, only failed by chain evidence.
    ///
    /// # Errors
    /// Returns [`LedgerError::IllegalTransition`] unless the batch is Prepared (or already
    /// Cancelled with the same basis).
    pub fn cancel_prepared(
        &self,
        id: &Hash32,
        basis: CancelBasis,
    ) -> Result<PayoutBatch, LedgerError> {
        let txn = self.db.begin_write()?;
        let (batch, changed) = {
            let tables = Tables::open(&txn)?;
            let mut batch =
                load_batch(&tables.batches, id)?.ok_or(LedgerError::UnknownBatch(*id))?;
            match batch.state {
                BatchState::Prepared => {}
                BatchState::Cancelled if batch.closure == Some(Closure::Cancelled(basis)) => {
                    return Ok(batch);
                }
                other => {
                    return Err(LedgerError::IllegalTransition {
                        batch: batch.id,
                        from: other,
                        action: "cancel",
                    });
                }
            }
            release_reservation(&tables, &batch)?;
            batch.state = BatchState::Cancelled;
            batch.closure = Some(Closure::Cancelled(basis));
            batch.rev = next_rev(batch.rev)?;
            store_batch(&tables.batches, &batch)?;
            tables.active_batches.remove(batch.seq)?;
            append_audit(
                &tables,
                AuditKind::BatchCancelled,
                batch.seq,
                &batch.id,
                &ZERO_HASH,
                [u64::from(basis.code()), batch.total_sat, 0],
            )?;
            (batch, true)
        };
        if changed {
            self.commit(txn, OP_CANCEL_PREPARED)?;
        }
        Ok(batch)
    }

    /// Advance every active batch from authoritative chain observations: Broadcast/Signed to
    /// Confirmed at `payout_confirmations` depth, Confirmed back to Broadcast when its block is
    /// reorged out, and Failed (reservation released) only when every signed transaction was
    /// conclusively double-spent at `abandon_confirmations` depth.
    ///
    /// # Errors
    /// Returns a chain-observer error (nothing is changed) or a storage/overflow error.
    pub fn reconcile_payouts(
        &self,
        chain: &dyn ChainView,
    ) -> Result<Vec<BatchTransition>, LedgerError> {
        let active = self.active_batches()?;
        let mut observations = Vec::new();
        let mut tip: Option<u32> = None;
        for batch in &active {
            if !batch.state_is_observable() {
                continue;
            }
            let tip_height = if let Some(height) = tip {
                height
            } else {
                let height = chain.tip_height()?;
                tip = Some(height);
                height
            };
            observations.push(observe_batch(chain, &self.config, batch, tip_height)?);
        }
        let mut transitions = Vec::new();
        if observations.is_empty() {
            return Ok(transitions);
        }
        let tip = tip.unwrap_or(0);
        let txn = self.db.begin_write()?;
        let mut dirty = false;
        {
            let tables = Tables::open(&txn)?;
            for observation in &observations {
                let Some(mut batch) = load_batch(&tables.batches, &observation.id)? else {
                    continue;
                };
                if batch.rev != observation.rev {
                    continue;
                }
                dirty |= apply_batch_decision(
                    &tables,
                    &mut batch,
                    observation,
                    &self.config,
                    &mut transitions,
                )?;
                if batch.state == BatchState::Confirmed
                    && let Some(confirmation) = batch.confirmation
                    && u64::from(tip)
                        >= u64::from(confirmation.height) + u64::from(self.config.reorg_watch_depth)
                {
                    tables.active_batches.remove(batch.seq)?;
                    dirty = true;
                }
            }
        }
        if dirty {
            self.commit(txn, OP_RECONCILE_PAYOUTS)?;
        }
        Ok(transitions)
    }

    // -----------------------------------------------------------------------------------------
    // Audit and integrity
    // -----------------------------------------------------------------------------------------

    /// Audit records with `seq >= from_seq`, at most `limit`.
    ///
    /// # Errors
    /// Returns a storage or codec error.
    pub fn audit_records(
        &self,
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, LedgerError> {
        let read = self.db.begin_read()?;
        let audit = read.open_table(AUDIT)?;
        let end = from_seq.saturating_add(u64::try_from(limit).unwrap_or(u64::MAX));
        let mut records = Vec::new();
        for item in audit.range(from_seq..end)?.take(limit) {
            let (key, value) = item?;
            records.push(decode_audit(key.value(), value.value())?);
        }
        Ok(records)
    }

    /// Return up to `limit` newest audit records in ascending sequence order.
    ///
    /// Uses the audit counter and rows from one coherent snapshot; does not verify the full chain.
    ///
    /// # Errors
    /// Returns a storage or codec error.
    pub fn audit_tail(&self, limit: usize) -> Result<Vec<AuditRecord>, LedgerError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let read = self.db.begin_read()?;
        let counters = read.open_table(META_U64)?;
        let next = meta_u64(&counters, M_NEXT_AUDIT)?;
        let count = u64::try_from(limit).unwrap_or(u64::MAX);
        let start = next.saturating_sub(count);
        let audit = read.open_table(AUDIT)?;
        let mut records = Vec::new();
        for item in audit.range(start..next)?.take(limit) {
            let (key, value) = item?;
            records.push(decode_audit(key.value(), value.value())?);
        }
        Ok(records)
    }

    /// Recompute the whole audit hash chain and compare it with the stored head.
    ///
    /// # Errors
    /// Returns [`LedgerError::Invariant`] on any gap, mismatch or truncation.
    pub fn verify_audit_chain(&self) -> Result<u64, LedgerError> {
        let read = self.db.begin_read()?;
        verify_audit_tables(
            &read.open_table(AUDIT)?,
            &read.open_table(META_U64)?,
            &read.open_table(META_BYTES)?,
        )
    }

    /// Verify the conservation invariants over the whole ledger:
    /// per account `available + reserved + paid - deficit == credited allocations of Matured
    /// rounds`, `reserved == outputs of batches holding a reservation`, `paid == outputs of
    /// Confirmed batches`; per round `fee + net == gross` and `sum(allocations) == net`; and the
    /// audit chain.
    ///
    /// # Errors
    /// Returns [`LedgerError::Invariant`] describing the first violation.
    pub fn check_invariants(&self) -> Result<InvariantReport, LedgerError> {
        let read = self.db.begin_read()?;
        verify_audit_tables(
            &read.open_table(AUDIT)?,
            &read.open_table(META_U64)?,
            &read.open_table(META_BYTES)?,
        )?;
        let rounds = read.open_table(ROUNDS)?;
        let allocs = read.open_table(ROUND_ALLOCS)?;
        let batches = read.open_table(BATCHES)?;
        let balances = read.open_table(BALANCES)?;
        let mut report = InvariantReport::default();
        let mut credited: BTreeMap<u64, u128> = BTreeMap::new();
        for item in rounds.rows_iter()? {
            let (_, value) = item?;
            let round = decode_round(value.value())?;
            report.rounds += 1;
            let list = load_allocs(&allocs, round.id)?;
            let mut sum: u64 = 0;
            for (_, amount) in &list {
                sum = sum
                    .checked_add(*amount)
                    .ok_or(LedgerError::Overflow("allocation sum"))?;
            }
            if round.reward_fixed {
                if round.gross_sat.checked_sub(round.pool_fee_sat) != Some(round.net_sat) {
                    return Err(LedgerError::Invariant(format!(
                        "round {} fee + net != gross",
                        round.id
                    )));
                }
                if sum != round.net_sat {
                    return Err(LedgerError::Invariant(format!(
                        "round {} allocations differ from net",
                        round.id
                    )));
                }
            } else if !list.is_empty() || round.state == RoundState::Matured {
                return Err(LedgerError::Invariant(format!(
                    "round {} has allocations without a fixed reward",
                    round.id
                )));
            }
            if round.state == RoundState::Matured {
                for (account, amount) in &list {
                    let entry = credited.entry(account.0).or_insert(0);
                    *entry += u128::from(*amount);
                    report.credited_sat += u128::from(*amount);
                }
            }
        }
        let mut reserved: BTreeMap<u64, u128> = BTreeMap::new();
        let mut paid: BTreeMap<u64, u128> = BTreeMap::new();
        for item in batches.rows_iter()? {
            let (_, value) = item?;
            let batch = decode_batch(value.value())?;
            report.batches += 1;
            let mut sum: u64 = 0;
            for output in &batch.outputs {
                sum = sum
                    .checked_add(output.amount_sat)
                    .ok_or(LedgerError::Overflow("batch total"))?;
            }
            if sum != batch.total_sat {
                return Err(LedgerError::Invariant(
                    "batch total differs from outputs".into(),
                ));
            }
            if batch.state == BatchState::Confirmed && batch.confirmation.is_none() {
                return Err(LedgerError::Invariant(
                    "confirmed batch without confirmation".into(),
                ));
            }
            let target = if batch.state.holds_reservation() {
                Some(&mut reserved)
            } else if batch.state == BatchState::Confirmed {
                Some(&mut paid)
            } else {
                None
            };
            if let Some(target) = target {
                for output in &batch.outputs {
                    *target.entry(output.account.0).or_insert(0) += u128::from(output.amount_sat);
                }
            }
        }
        verify_account_conservation(&balances, &credited, &reserved, &paid, &mut report)?;
        Ok(report)
    }
}

fn verify_audit_tables(
    audit: &Table<'_, u64, &'static [u8]>,
    counters: &Table<'_, &'static str, u64>,
    meta_bytes: &Table<'_, &'static str, &'static [u8]>,
) -> Result<u64, LedgerError> {
    let mut previous = ZERO_HASH;
    let mut expected_seq = 0u64;
    for item in audit.rows_iter()? {
        let (key, value) = item?;
        let seq = key.value();
        if seq != expected_seq {
            return Err(LedgerError::Invariant(format!(
                "audit gap at {expected_seq}"
            )));
        }
        let bytes = value.value();
        if bytes.len() != AUDIT_BODY_LEN + 32 {
            return Err(LedgerError::Invariant(format!(
                "audit record {seq} has a bad length"
            )));
        }
        let (body, stored) = bytes.split_at(AUDIT_BODY_LEN);
        let chain = audit_chain_hash(&previous, seq, body);
        if stored != chain.as_slice() {
            return Err(LedgerError::Invariant(format!(
                "audit chain broken at {seq}"
            )));
        }
        previous = chain;
        expected_seq = expected_seq
            .checked_add(1)
            .ok_or(LedgerError::Overflow("audit seq"))?;
    }
    if meta_u64(counters, M_NEXT_AUDIT)? != expected_seq {
        return Err(LedgerError::Invariant(
            "audit counter differs from records".into(),
        ));
    }
    let head = match meta_bytes.get(M_AUDIT_HEAD)? {
        Some(guard) => hash_from(guard.value())?,
        None => ZERO_HASH,
    };
    if head != previous {
        return Err(LedgerError::Invariant(
            "audit head differs from records".into(),
        ));
    }
    Ok(expected_seq)
}

fn verify_account_conservation(
    balances: &Table<'_, u64, &'static [u8]>,
    credited: &BTreeMap<u64, u128>,
    reserved: &BTreeMap<u64, u128>,
    paid: &BTreeMap<u64, u128>,
    report: &mut InvariantReport,
) -> Result<(), LedgerError> {
    let mut accounts = BTreeSet::new();
    accounts.extend(credited.keys().copied());
    accounts.extend(reserved.keys().copied());
    accounts.extend(paid.keys().copied());
    for item in balances.rows_iter()? {
        let (key, _) = item?;
        accounts.insert(key.value());
    }
    for account in &accounts {
        let balance = load_balance(balances, MinerId(*account))?;
        let want_credited = credited.get(account).copied().unwrap_or(0);
        let want_reserved = reserved.get(account).copied().unwrap_or(0);
        let want_paid = paid.get(account).copied().unwrap_or(0);
        if u128::from(balance.reserved_sat) != want_reserved {
            return Err(LedgerError::Invariant(format!(
                "account {account} reserved differs from open batches"
            )));
        }
        if u128::from(balance.paid_sat) != want_paid {
            return Err(LedgerError::Invariant(format!(
                "account {account} paid differs from confirmed batches"
            )));
        }
        let positive = u128::from(balance.available_sat)
            + u128::from(balance.reserved_sat)
            + u128::from(balance.paid_sat);
        if positive.checked_sub(u128::from(balance.deficit_sat)) != Some(want_credited) {
            return Err(LedgerError::Invariant(format!(
                "account {account} balance does not equal credited allocations"
            )));
        }
        report.available_sat += u128::from(balance.available_sat);
        report.reserved_sat += u128::from(balance.reserved_sat);
        report.paid_sat += u128::from(balance.paid_sat);
        report.deficit_sat += u128::from(balance.deficit_sat);
    }
    report.accounts = accounts.len();
    Ok(())
}

impl PayoutBatch {
    /// True for states a chain observer can still move.
    fn state_is_observable(&self) -> bool {
        matches!(
            self.state,
            BatchState::ExternallySigned | BatchState::Broadcast | BatchState::Confirmed
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Share crediting and the PPLNS window
// ---------------------------------------------------------------------------------------------

fn credit_share(tables: &Tables<'_>, share: &ShareCredit) -> Result<ShareReceipt, LedgerError> {
    if tables.retired_jobs.get(share.job)?.is_some() {
        return Err(LedgerError::JobRetired(share.job));
    }
    let tuple = share.tuple_key();
    let existing = match tables.share_hashes.get(share.header_hash.as_slice())? {
        Some(guard) => Some(decode_hash_entry(guard.value())?),
        None => None,
    };
    if let Some((seq, work, stored_tuple)) = existing {
        if work != share.work || stored_tuple != tuple {
            return Err(LedgerError::ShareConflict { seq });
        }
        return Ok(ShareReceipt::Duplicate { seq });
    }
    let owner = match tables.share_tuples.get(tuple.as_slice())? {
        Some(guard) => Some(hash_from(guard.value())?),
        None => None,
    };
    if let Some(owner_hash) = owner {
        let seq = match tables.share_hashes.get(owner_hash.as_slice())? {
            Some(guard) => decode_hash_entry(guard.value())?.0,
            None => {
                return Err(LedgerError::Corrupt(
                    "share tuple index points at no share".into(),
                ));
            }
        };
        return Err(LedgerError::ShareIdentityConflict { seq });
    }
    let seq = bump(&tables.meta_u64, M_NEXT_SHARE, 0)?;
    tables
        .shares
        .insert(seq, encode_share(share.account, share.work)?.as_slice())?;
    tables.share_hashes.insert(
        share.header_hash.as_slice(),
        encode_hash_entry(seq, share.work, &tuple)?.as_slice(),
    )?;
    tables
        .share_tuples
        .insert(tuple.as_slice(), share.header_hash.as_slice())?;
    Ok(ShareReceipt::Credited { seq })
}

/// Walk shares newest first from `end_seq`, filling a window of `target` work.
fn collect_window(
    shares: &Table<'_, u64, &'static [u8]>,
    pruned_below: u64,
    end_seq: u64,
    target: u128,
) -> Result<WindowAccumulator, LedgerError> {
    let mut window = WindowAccumulator::new(target);
    for item in shares.range(..=end_seq)?.rev() {
        let (_, value) = item?;
        let (account, work) = decode_share(value.value())?;
        window.push_older(account, work)?;
        if window.is_full() {
            return Ok(window);
        }
    }
    if pruned_below > 0 {
        return Err(LedgerError::WindowPruned);
    }
    Ok(window)
}

// ---------------------------------------------------------------------------------------------
// Rounds
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Canon {
    Canonical,
    Displaced,
    Unknown,
}

fn apply_batch_decision(
    tables: &Tables<'_>,
    batch: &mut PayoutBatch,
    observation: &BatchObservation,
    config: &PoolConfig,
    transitions: &mut Vec<BatchTransition>,
) -> Result<bool, LedgerError> {
    let from = batch.state;
    let (kind, hash, fields) = match decide(batch, observation, config) {
        Decision::None => return Ok(false),
        Decision::Confirm(confirmation) => {
            settle_paid(tables, batch)?;
            batch.state = BatchState::Confirmed;
            batch.broadcast_txid = Some(confirmation.txid);
            batch.confirmation = Some(confirmation);
            (
                AuditKind::BatchConfirmed,
                confirmation.txid,
                [u64::from(confirmation.height), 0, 0],
            )
        }
        Decision::Reconfirm(confirmation) => {
            batch.broadcast_txid = Some(confirmation.txid);
            batch.confirmation = Some(confirmation);
            (
                AuditKind::BatchConfirmed,
                confirmation.txid,
                [u64::from(confirmation.height), 1, 0],
            )
        }
        Decision::Revert => {
            unsettle_paid(tables, batch)?;
            batch.state = BatchState::Broadcast;
            batch.confirmation = None;
            (
                AuditKind::BatchReverted,
                ZERO_HASH,
                [
                    u64::from(BatchState::Confirmed.code()),
                    u64::from(BatchState::Broadcast.code()),
                    0,
                ],
            )
        }
        Decision::Fail(conflicting_txid) => {
            release_reservation(tables, batch)?;
            batch.state = BatchState::Failed;
            batch.closure = Some(Closure::Failed { conflicting_txid });
            tables.active_batches.remove(batch.seq)?;
            (
                AuditKind::BatchFailed,
                conflicting_txid,
                [batch.total_sat, 0, 0],
            )
        }
    };
    batch.rev = next_rev(batch.rev)?;
    store_batch(&tables.batches, batch)?;
    append_audit(tables, kind, batch.seq, &batch.id, &hash, fields)?;
    transitions.push(BatchTransition {
        batch_id: batch.id,
        from,
        to: batch.state,
    });
    Ok(true)
}

struct RoundObservation {
    id: u64,
    block_hash: Hash32,
    canon: Canon,
    coinbase: Option<ObservedCoinbase>,
}

struct RoundOutcome {
    transition: Option<RoundTransition>,
    anomaly: Option<&'static str>,
    dirty: bool,
}

impl RoundOutcome {
    fn unchanged() -> Self {
        Self {
            transition: None,
            anomaly: None,
            dirty: false,
        }
    }
}

fn confirmations(tip: u32, height: u32) -> u64 {
    tip.checked_sub(height)
        .map_or(0, |depth| u64::from(depth) + 1)
}

fn apply_round_observation(
    tables: &Tables<'_>,
    config: &PoolConfig,
    observation: &RoundObservation,
    tip: u32,
) -> Result<RoundOutcome, LedgerError> {
    let Some(mut round) = load_round(&tables.rounds, observation.id)? else {
        return Ok(RoundOutcome::unchanged());
    };
    if round.block_hash != observation.block_hash {
        return Ok(RoundOutcome::unchanged());
    }
    let from = round.state;
    let was_fixed = round.reward_fixed;
    let depth = confirmations(tip, round.height);
    let mut outcome = RoundOutcome::unchanged();
    let mut credited_sat = 0;
    let mut reversed_sat = 0;
    let mut deficit_created_sat = 0;
    match (from, observation.canon) {
        (RoundState::Matured, Canon::Displaced) => {
            let (reversed, deficit) = reverse_round_credits(tables, round.id)?;
            reversed_sat = reversed;
            deficit_created_sat = deficit;
            round.state = RoundState::Orphaned;
            append_audit(
                tables,
                AuditKind::RoundOrphaned,
                round.id,
                &round.block_hash,
                &ZERO_HASH,
                [reversed, deficit, 1],
            )?;
        }
        (RoundState::Matured, _) | (_, Canon::Unknown) => {}
        (_, Canon::Displaced) => {
            if from != RoundState::Orphaned {
                round.state = RoundState::Orphaned;
                append_audit(
                    tables,
                    AuditKind::RoundOrphaned,
                    round.id,
                    &round.block_hash,
                    &ZERO_HASH,
                    [0, 0, 0],
                )?;
            }
        }
        (_, Canon::Canonical) => {
            match apply_canonical_round(tables, config, &mut round, observation, depth)? {
                CanonicalApply::Applied(credited) => credited_sat = credited,
                CanonicalApply::Anomaly(reason) => {
                    outcome.anomaly = Some(reason);
                    return Ok(outcome);
                }
                CanonicalApply::MissingCoinbase => return Ok(RoundOutcome::unchanged()),
            }
        }
    }
    let settled = u64::from(tip) >= u64::from(round.height) + u64::from(config.reorg_watch_depth)
        && (observation.canon != Canon::Canonical || round.reward_fixed);
    if settled {
        if matches!(round.state, RoundState::Pending | RoundState::Immature) {
            round.state = RoundState::Orphaned;
            append_audit(
                tables,
                AuditKind::RoundOrphaned,
                round.id,
                &round.block_hash,
                &ZERO_HASH,
                [0, 0, 0],
            )?;
        }
        tables.open_rounds.remove(round.id)?;
        outcome.dirty = true;
    }
    if round.state != from || settled || round.reward_fixed != was_fixed {
        store_round(&tables.rounds, &round)?;
        outcome.dirty = true;
    }
    if round.state != from {
        outcome.transition = Some(RoundTransition {
            round: round.id,
            from,
            to: round.state,
            credited_sat,
            reversed_sat,
            deficit_created_sat,
        });
    }
    Ok(outcome)
}

/// Read the actual coinbase value from the chain, fix fee, net and allocations. Returns a reason
/// when the chain contradicts the job owner's claim (the round is left unchanged).
enum CanonicalApply {
    MissingCoinbase,
    Anomaly(&'static str),
    Applied(u64),
}

fn apply_canonical_round(
    tables: &Tables<'_>,
    config: &PoolConfig,
    round: &mut Round,
    observation: &RoundObservation,
    depth: u64,
) -> Result<CanonicalApply, LedgerError> {
    let from = round.state;
    if !round.reward_fixed {
        let Some(coinbase) = observation.coinbase.as_ref() else {
            return Ok(CanonicalApply::MissingCoinbase);
        };
        if let Some(reason) = fix_reward(tables, config, round, coinbase)? {
            return Ok(CanonicalApply::Anomaly(reason));
        }
    }
    if depth >= u64::from(config.coinbase_maturity) {
        let credited = credit_round_allocations(tables, round.id)?;
        round.state = RoundState::Matured;
        append_audit(
            tables,
            AuditKind::RoundMatured,
            round.id,
            &round.block_hash,
            &ZERO_HASH,
            [credited, 0, 0],
        )?;
        return Ok(CanonicalApply::Applied(credited));
    }
    if from != RoundState::Immature {
        round.state = RoundState::Immature;
        if from == RoundState::Orphaned {
            append_audit(
                tables,
                AuditKind::RoundRevived,
                round.id,
                &round.block_hash,
                &ZERO_HASH,
                [0, 0, 0],
            )?;
        }
    }
    Ok(CanonicalApply::Applied(0))
}

fn fix_reward(
    tables: &Tables<'_>,
    config: &PoolConfig,
    round: &mut Round,
    coinbase: &ObservedCoinbase,
) -> Result<Option<&'static str>, LedgerError> {
    if coinbase.txid != round.coinbase_txid {
        return Ok(Some("observed coinbase txid differs from the claimed txid"));
    }
    let mut total: u64 = 0;
    let mut pool: u64 = 0;
    for output in &coinbase.outputs {
        let Some(next_total) = total.checked_add(output.value_sat) else {
            return Ok(Some("observed coinbase total overflows"));
        };
        total = next_total;
        if output.script_pubkey == config.pool_coinbase_script {
            let Some(next_pool) = pool.checked_add(output.value_sat) else {
                return Ok(Some("observed pool coinbase output total overflows"));
            };
            pool = next_pool;
        }
    }
    if total > MAX_MONEY_SAT {
        return Ok(Some("observed coinbase exceeds the money supply"));
    }
    if total != round.claimed_coinbase_value_sat {
        return Ok(Some(
            "observed coinbase total differs from the claimed value",
        ));
    }
    let (fee, net) = split_pool_fee(pool, config.pool_fee_bps)?;
    let weights = load_weights(&tables.round_weights, round.id)?;
    let allocations = split_reward(net, &weights)?;
    for (account, amount) in &allocations {
        tables
            .round_allocs
            .insert(round_key(round.id, *account).as_slice(), *amount)?;
    }
    round.reward_fixed = true;
    round.gross_sat = pool;
    round.pool_fee_sat = fee;
    round.net_sat = net;
    append_audit(
        tables,
        AuditKind::RewardFixed,
        round.id,
        &round.block_hash,
        &ZERO_HASH,
        [pool, fee, net],
    )?;
    Ok(None)
}

fn credit_round_allocations(tables: &Tables<'_>, round_id: u64) -> Result<u64, LedgerError> {
    let allocations = load_allocs(&tables.round_allocs, round_id)?;
    let mut total: u64 = 0;
    for (account, amount) in allocations {
        let mut balance = load_balance(&tables.balances, account)?;
        let offset = balance.deficit_sat.min(amount);
        balance.deficit_sat -= offset;
        balance.available_sat = balance
            .available_sat
            .checked_add(amount - offset)
            .ok_or(LedgerError::Overflow("available balance"))?;
        store_balance(&tables.balances, account, &balance)?;
        total = total
            .checked_add(amount)
            .ok_or(LedgerError::Overflow("credited total"))?;
    }
    Ok(total)
}

/// Remove a matured round's credits. Returns `(reversed_total, deficit_created)`.
fn reverse_round_credits(tables: &Tables<'_>, round_id: u64) -> Result<(u64, u64), LedgerError> {
    let allocations = load_allocs(&tables.round_allocs, round_id)?;
    let mut reversed: u64 = 0;
    let mut deficit_total: u64 = 0;
    for (account, amount) in allocations {
        let mut balance = load_balance(&tables.balances, account)?;
        let take = balance.available_sat.min(amount);
        balance.available_sat -= take;
        let shortfall = amount - take;
        balance.deficit_sat = balance
            .deficit_sat
            .checked_add(shortfall)
            .ok_or(LedgerError::Overflow("deficit balance"))?;
        store_balance(&tables.balances, account, &balance)?;
        reversed = reversed
            .checked_add(amount)
            .ok_or(LedgerError::Overflow("reversed total"))?;
        deficit_total = deficit_total
            .checked_add(shortfall)
            .ok_or(LedgerError::Overflow("deficit total"))?;
    }
    Ok((reversed, deficit_total))
}

// ---------------------------------------------------------------------------------------------
// Payout reconciliation
// ---------------------------------------------------------------------------------------------

struct TxObservation {
    txid: Hash32,
    status: TxStatus,
    canonical: bool,
    confirmations: u64,
    dead_by: Option<Hash32>,
}

struct BatchObservation {
    id: Hash32,
    rev: u64,
    txs: Vec<TxObservation>,
}

enum Decision {
    None,
    Confirm(Confirmation),
    Reconfirm(Confirmation),
    Revert,
    Fail(Hash32),
}

fn observe_batch(
    chain: &dyn ChainView,
    config: &PoolConfig,
    batch: &PayoutBatch,
    tip: u32,
) -> Result<BatchObservation, LedgerError> {
    let mut txs = Vec::with_capacity(batch.transactions.len());
    for tx in &batch.transactions {
        let status = chain.tx_status(&tx.txid)?;
        let (canonical, depth) = match status {
            TxStatus::Confirmed { block_hash, height } => (
                matches!(chain.block_location(&block_hash, height)?, crate::BlockLocation::Canonical { height: observed } if observed == height),
                confirmations(tip, height),
            ),
            _ => (false, 0),
        };
        let confirmed_here = canonical && matches!(status, TxStatus::Confirmed { .. });
        let dead_by = if confirmed_here || status == TxStatus::InMempool {
            None
        } else {
            find_dead_spend(chain, config, batch, tx, tip)?
        };
        txs.push(TxObservation {
            txid: tx.txid,
            status,
            canonical,
            confirmations: depth,
            dead_by,
        });
    }
    Ok(BatchObservation {
        id: batch.id,
        rev: batch.rev,
        txs,
    })
}

/// A confirmed spend of one of `tx`'s inputs by a transaction outside the batch, buried at least
/// `abandon_confirmations` deep on the active chain.
fn find_dead_spend(
    chain: &dyn ChainView,
    config: &PoolConfig,
    batch: &PayoutBatch,
    tx: &SignedTx,
    tip: u32,
) -> Result<Option<Hash32>, LedgerError> {
    for input in &tx.inputs {
        let Some(spend) = chain.confirmed_spender(input)? else {
            continue;
        };
        if batch
            .transactions
            .iter()
            .any(|known| known.txid == spend.spender_txid)
        {
            continue;
        }
        let canonical = matches!(chain.block_location(&spend.block_hash, spend.height)?, crate::BlockLocation::Canonical { height } if height == spend.height);
        if canonical && confirmations(tip, spend.height) >= u64::from(config.abandon_confirmations)
        {
            return Ok(Some(spend.spender_txid));
        }
    }
    Ok(None)
}

fn decide(batch: &PayoutBatch, observation: &BatchObservation, config: &PoolConfig) -> Decision {
    let enough = observation
        .txs
        .iter()
        .find(|tx| tx.canonical && tx.confirmations >= u64::from(config.payout_confirmations))
        .and_then(|tx| match tx.status {
            TxStatus::Confirmed { block_hash, height } => Some(Confirmation {
                txid: tx.txid,
                block_hash,
                height,
            }),
            _ => None,
        });
    match batch.state {
        BatchState::ExternallySigned | BatchState::Broadcast => {
            if let Some(confirmation) = enough {
                return Decision::Confirm(confirmation);
            }
            if !observation.txs.is_empty()
                && observation.txs.iter().all(|tx| tx.dead_by.is_some())
                && let Some(conflicting) = observation.txs.iter().find_map(|tx| tx.dead_by)
            {
                return Decision::Fail(conflicting);
            }
            Decision::None
        }
        BatchState::Confirmed => {
            let still_confirmed = batch.confirmation.is_some_and(|recorded| {
                observation.txs.iter().any(|tx| {
                    tx.txid == recorded.txid
                        && tx.canonical
                        && matches!(
                            tx.status,
                            TxStatus::Confirmed { block_hash, height }
                                if block_hash == recorded.block_hash && height == recorded.height
                        )
                })
            });
            if still_confirmed {
                Decision::None
            } else if let Some(confirmation) = enough {
                Decision::Reconfirm(confirmation)
            } else {
                Decision::Revert
            }
        }
        _ => Decision::None,
    }
}

fn settle_paid(tables: &Tables<'_>, batch: &PayoutBatch) -> Result<(), LedgerError> {
    for output in &batch.outputs {
        let mut balance = load_balance(&tables.balances, output.account)?;
        balance.reserved_sat = balance
            .reserved_sat
            .checked_sub(output.amount_sat)
            .ok_or_else(|| {
                LedgerError::Corrupt("confirming a payout exceeds the reservation".into())
            })?;
        balance.paid_sat = balance
            .paid_sat
            .checked_add(output.amount_sat)
            .ok_or(LedgerError::Overflow("paid balance"))?;
        store_balance(&tables.balances, output.account, &balance)?;
    }
    Ok(())
}

fn unsettle_paid(tables: &Tables<'_>, batch: &PayoutBatch) -> Result<(), LedgerError> {
    for output in &batch.outputs {
        let mut balance = load_balance(&tables.balances, output.account)?;
        balance.paid_sat = balance
            .paid_sat
            .checked_sub(output.amount_sat)
            .ok_or_else(|| {
                LedgerError::Corrupt("reverting a payout exceeds the paid balance".into())
            })?;
        balance.reserved_sat = balance
            .reserved_sat
            .checked_add(output.amount_sat)
            .ok_or(LedgerError::Overflow("reserved balance"))?;
        store_balance(&tables.balances, output.account, &balance)?;
    }
    Ok(())
}

fn release_reservation(tables: &Tables<'_>, batch: &PayoutBatch) -> Result<(), LedgerError> {
    for output in &batch.outputs {
        let mut balance = load_balance(&tables.balances, output.account)?;
        balance.reserved_sat = balance
            .reserved_sat
            .checked_sub(output.amount_sat)
            .ok_or_else(|| {
                LedgerError::Corrupt("releasing a payout exceeds the reservation".into())
            })?;
        balance.available_sat = balance
            .available_sat
            .checked_add(output.amount_sat)
            .ok_or(LedgerError::Overflow("available balance"))?;
        store_balance(&tables.balances, output.account, &balance)?;
    }
    Ok(())
}

fn next_rev(rev: u64) -> Result<u64, LedgerError> {
    rev.checked_add(1)
        .ok_or(LedgerError::Overflow("batch revision"))
}

// ---------------------------------------------------------------------------------------------
// Counters, audit
// ---------------------------------------------------------------------------------------------

fn meta_u64(meta: &Table<'_, &'static str, u64>, key: &'static str) -> Result<u64, LedgerError> {
    Ok(meta.get(key)?.map_or(0, |guard| guard.value()))
}

/// Return the current counter value (or `first` when unset) and store the next one.
fn bump(
    meta: &Table<'_, &'static str, u64>,
    key: &'static str,
    first: u64,
) -> Result<u64, LedgerError> {
    let current = meta.get(key)?.map_or(first, |guard| guard.value());
    let next = current
        .checked_add(1)
        .ok_or(LedgerError::Overflow("counter"))?;
    meta.insert(key, next)?;
    Ok(current)
}

fn low64(value: u128) -> u64 {
    u64::try_from(value & u128::from(u64::MAX)).unwrap_or(u64::MAX)
}

fn audit_chain_hash(previous: &Hash32, seq: u64, body: &[u8]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_DOMAIN);
    hasher.update(previous);
    hasher.update(seq.to_be_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

fn append_audit(
    tables: &Tables<'_>,
    kind: AuditKind,
    subject: u64,
    hash: &Hash32,
    hash2: &Hash32,
    values: [u64; 3],
) -> Result<(), LedgerError> {
    let seq = bump(&tables.meta_u64, M_NEXT_AUDIT, 0)?;
    let previous = match tables.meta_bytes.get(M_AUDIT_HEAD)? {
        Some(guard) => hash_from(guard.value())?,
        None => ZERO_HASH,
    };
    let mut body = Enc::new();
    body.u8(kind.code());
    body.u64(subject);
    body.hash(hash);
    body.hash(hash2);
    for value in values {
        body.u64(value);
    }
    let body = body.finish()?;
    let chain = audit_chain_hash(&previous, seq, &body);
    let mut record = body;
    record.extend_from_slice(&chain);
    tables.audit.insert(seq, record.as_slice())?;
    tables.meta_bytes.insert(M_AUDIT_HEAD, chain.as_slice())?;
    Ok(())
}

fn decode_audit(seq: u64, bytes: &[u8]) -> Result<AuditRecord, LedgerError> {
    let mut dec = Dec::new(bytes);
    let kind = AuditKind::from_code(dec.u8()?).ok_or(LedgerError::Codec("unknown audit kind"))?;
    let subject = dec.u64()?;
    let hash = dec.hash()?;
    let hash2 = dec.hash()?;
    let values = [dec.u64()?, dec.u64()?, dec.u64()?];
    let chain = dec.hash()?;
    dec.finish()?;
    Ok(AuditRecord {
        seq,
        kind,
        subject,
        hash,
        hash2,
        values,
        chain,
    })
}

// ---------------------------------------------------------------------------------------------
// Row encoding and loading
// ---------------------------------------------------------------------------------------------

fn hash_from(bytes: &[u8]) -> Result<Hash32, LedgerError> {
    bytes
        .try_into()
        .map_err(|_| LedgerError::Corrupt("stored hash has the wrong length".into()))
}

fn round_key(round: u64, account: MinerId) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&round.to_be_bytes());
    key[8..].copy_from_slice(&account.0.to_be_bytes());
    key
}

fn encode_share(account: MinerId, work: u128) -> Result<Vec<u8>, LedgerError> {
    let mut enc = Enc::new();
    enc.u64(account.0);
    enc.u128(work);
    enc.finish()
}

fn decode_share(bytes: &[u8]) -> Result<(MinerId, u128), LedgerError> {
    let mut dec = Dec::new(bytes);
    let account = MinerId(dec.u64()?);
    let work = dec.u128()?;
    dec.finish()?;
    Ok((account, work))
}

fn encode_hash_entry(seq: u64, work: u128, tuple: &[u8]) -> Result<Vec<u8>, LedgerError> {
    let mut enc = Enc::new();
    enc.u64(seq);
    enc.u128(work);
    enc.bytes(tuple);
    enc.finish()
}

fn decode_hash_entry(bytes: &[u8]) -> Result<(u64, u128, Vec<u8>), LedgerError> {
    let mut dec = Dec::new(bytes);
    let seq = dec.u64()?;
    let work = dec.u128()?;
    let tuple = dec.bytes(MAX_EXTRANONCE_LEN + 20)?.to_vec();
    dec.finish()?;
    Ok((seq, work, tuple))
}

fn encode_balance(balance: &Balance) -> Result<Vec<u8>, LedgerError> {
    let mut enc = Enc::new();
    enc.u64(balance.available_sat);
    enc.u64(balance.reserved_sat);
    enc.u64(balance.paid_sat);
    enc.u64(balance.deficit_sat);
    enc.finish()
}

fn decode_balance(bytes: &[u8]) -> Result<Balance, LedgerError> {
    let mut dec = Dec::new(bytes);
    let balance = Balance {
        available_sat: dec.u64()?,
        reserved_sat: dec.u64()?,
        paid_sat: dec.u64()?,
        deficit_sat: dec.u64()?,
    };
    dec.finish()?;
    Ok(balance)
}

fn load_balance(
    balances: &Table<'_, u64, &'static [u8]>,
    account: MinerId,
) -> Result<Balance, LedgerError> {
    match balances.get(account.0)? {
        Some(guard) => decode_balance(guard.value()),
        None => Ok(Balance::default()),
    }
}

fn store_balance(
    balances: &Table<'_, u64, &'static [u8]>,
    account: MinerId,
    balance: &Balance,
) -> Result<(), LedgerError> {
    balances.insert(account.0, encode_balance(balance)?.as_slice())?;
    Ok(())
}

fn encode_round(round: &Round) -> Result<Vec<u8>, LedgerError> {
    let mut enc = Enc::new();
    enc.u64(round.id);
    enc.hash(&round.block_hash);
    enc.u32(round.height);
    enc.u64(round.solving_seq);
    enc.hash(&round.coinbase_txid);
    enc.u64(round.claimed_coinbase_value_sat);
    enc.u128(round.window_work_total);
    enc.u8(u8::from(round.reward_fixed));
    enc.u64(round.gross_sat);
    enc.u64(round.pool_fee_sat);
    enc.u64(round.net_sat);
    enc.u8(round.state.code());
    enc.finish()
}

fn decode_round(bytes: &[u8]) -> Result<Round, LedgerError> {
    let mut dec = Dec::new(bytes);
    let id = dec.u64()?;
    let block_hash = dec.hash()?;
    let height = dec.u32()?;
    let solving_seq = dec.u64()?;
    let coinbase_txid = dec.hash()?;
    let claimed_coinbase_value_sat = dec.u64()?;
    let window_work_total = dec.u128()?;
    let reward_fixed = match dec.u8()? {
        0 => false,
        1 => true,
        _ => return Err(LedgerError::Codec("bad reward_fixed flag")),
    };
    let gross_sat = dec.u64()?;
    let pool_fee_sat = dec.u64()?;
    let net_sat = dec.u64()?;
    let state = RoundState::from_code(dec.u8()?).ok_or(LedgerError::Codec("bad round state"))?;
    dec.finish()?;
    Ok(Round {
        id,
        block_hash,
        height,
        solving_seq,
        coinbase_txid,
        claimed_coinbase_value_sat,
        window_work_total,
        reward_fixed,
        gross_sat,
        pool_fee_sat,
        net_sat,
        state,
    })
}

fn load_round(
    rounds: &Table<'_, u64, &'static [u8]>,
    id: u64,
) -> Result<Option<Round>, LedgerError> {
    match rounds.get(id)? {
        Some(guard) => Ok(Some(decode_round(guard.value())?)),
        None => Ok(None),
    }
}

fn store_round(rounds: &Table<'_, u64, &'static [u8]>, round: &Round) -> Result<(), LedgerError> {
    rounds.insert(round.id, encode_round(round)?.as_slice())?;
    Ok(())
}

fn round_id_for_block(
    index: &Table<'_, &'static [u8], u64>,
    block_hash: &Hash32,
) -> Result<Option<u64>, LedgerError> {
    Ok(index.get(block_hash.as_slice())?.map(|guard| guard.value()))
}

fn load_allocs(
    allocs: &Table<'_, &'static [u8], u64>,
    round: u64,
) -> Result<Vec<(MinerId, u64)>, LedgerError> {
    let start = round_key(round, MinerId(0));
    let end = round_key(round, MinerId(u64::MAX));
    let mut list = Vec::new();
    for item in allocs.range(start.as_slice()..=end.as_slice())? {
        let (key, value) = item?;
        list.push((account_from_round_key(key.value())?, value.value()));
    }
    Ok(list)
}

fn load_weights(
    weights: &Table<'_, &'static [u8], u128>,
    round: u64,
) -> Result<Vec<(MinerId, u128)>, LedgerError> {
    let start = round_key(round, MinerId(0));
    let end = round_key(round, MinerId(u64::MAX));
    let mut list = Vec::new();
    for item in weights.range(start.as_slice()..=end.as_slice())? {
        let (key, value) = item?;
        list.push((account_from_round_key(key.value())?, value.value()));
    }
    Ok(list)
}

fn account_from_round_key(key: &[u8]) -> Result<MinerId, LedgerError> {
    let tail: [u8; 8] = key
        .get(8..)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| LedgerError::Corrupt("round key has the wrong length".into()))?;
    Ok(MinerId(u64::from_be_bytes(tail)))
}

fn encode_batch(batch: &PayoutBatch) -> Result<Vec<u8>, LedgerError> {
    let mut enc = Enc::new();
    enc.hash(&batch.id);
    enc.u64(batch.seq);
    enc.hash(&batch.idempotency_key);
    enc.u8(batch.state.code());
    enc.u64(batch.rev);
    enc.u64(batch.total_sat);
    enc.len32(batch.outputs.len());
    for output in &batch.outputs {
        enc.u64(output.account.0);
        enc.u64(output.amount_sat);
        enc.bytes(&output.script_pubkey);
    }
    enc.len32(batch.transactions.len());
    for tx in &batch.transactions {
        enc.hash(&tx.txid);
        enc.len32(tx.inputs.len());
        for input in &tx.inputs {
            enc.hash(&input.txid);
            enc.u32(input.vout);
        }
    }
    match batch.broadcast_txid {
        Some(txid) => {
            enc.u8(1);
            enc.hash(&txid);
        }
        None => enc.u8(0),
    }
    match batch.confirmation {
        Some(confirmation) => {
            enc.u8(1);
            enc.hash(&confirmation.txid);
            enc.hash(&confirmation.block_hash);
            enc.u32(confirmation.height);
        }
        None => enc.u8(0),
    }
    match batch.closure {
        None => enc.u8(0),
        Some(Closure::Cancelled(basis)) => {
            enc.u8(1);
            enc.u8(basis.code());
        }
        Some(Closure::Failed { conflicting_txid }) => {
            enc.u8(2);
            enc.hash(&conflicting_txid);
        }
    }
    enc.finish()
}

fn decode_batch(bytes: &[u8]) -> Result<PayoutBatch, LedgerError> {
    let mut dec = Dec::new(bytes);
    let id = dec.hash()?;
    let seq = dec.u64()?;
    let idempotency_key = dec.hash()?;
    let state = BatchState::from_code(dec.u8()?).ok_or(LedgerError::Codec("bad batch state"))?;
    let rev = dec.u64()?;
    let total_sat = dec.u64()?;
    let output_count = dec.count(MAX_BATCH_OUTPUTS, 20)?;
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let account = MinerId(dec.u64()?);
        let amount_sat = dec.u64()?;
        let script_pubkey = dec.bytes(MAX_SCRIPT_LEN)?.to_vec();
        outputs.push(PayoutOutput {
            account,
            script_pubkey,
            amount_sat,
        });
    }
    let tx_count = dec.count(MAX_SIGNED_TXS_PER_BATCH, 36)?;
    let mut transactions = Vec::with_capacity(tx_count);
    for _ in 0..tx_count {
        let txid = dec.hash()?;
        let input_count = dec.count(MAX_INPUTS_PER_TX, 36)?;
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let outpoint_txid = dec.hash()?;
            let vout = dec.u32()?;
            inputs.push(OutPoint {
                txid: outpoint_txid,
                vout,
            });
        }
        transactions.push(SignedTx { txid, inputs });
    }
    let broadcast_txid = match dec.u8()? {
        0 => None,
        1 => Some(dec.hash()?),
        _ => return Err(LedgerError::Codec("bad broadcast flag")),
    };
    let confirmation = match dec.u8()? {
        0 => None,
        1 => Some(Confirmation {
            txid: dec.hash()?,
            block_hash: dec.hash()?,
            height: dec.u32()?,
        }),
        _ => return Err(LedgerError::Codec("bad confirmation flag")),
    };
    let closure = match dec.u8()? {
        0 => None,
        1 => Some(Closure::Cancelled(
            CancelBasis::from_code(dec.u8()?).ok_or(LedgerError::Codec("bad cancel basis"))?,
        )),
        2 => Some(Closure::Failed {
            conflicting_txid: dec.hash()?,
        }),
        _ => return Err(LedgerError::Codec("bad closure tag")),
    };
    dec.finish()?;
    Ok(PayoutBatch {
        id,
        seq,
        idempotency_key,
        state,
        rev,
        outputs,
        total_sat,
        transactions,
        broadcast_txid,
        confirmation,
        closure,
    })
}

fn load_batch(
    batches: &Table<'_, &'static [u8], &'static [u8]>,
    id: &Hash32,
) -> Result<Option<PayoutBatch>, LedgerError> {
    match batches.get(id.as_slice())? {
        Some(guard) => Ok(Some(decode_batch(guard.value())?)),
        None => Ok(None),
    }
}

fn store_batch(
    batches: &Table<'_, &'static [u8], &'static [u8]>,
    batch: &PayoutBatch,
) -> Result<(), LedgerError> {
    batches.insert(batch.id.as_slice(), encode_batch(batch)?.as_slice())?;
    Ok(())
}
