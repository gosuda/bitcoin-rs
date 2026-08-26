//! Canonical transaction admission pipeline.
//!
//! [`admit_transaction`] is the sole production validator. The caller must hold
//! exclusion against chain transitions for the whole call so verification and
//! commit observe one coherent state.

use alloc::sync::Arc;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::hashes::Hash as _;
use bitcoin::{FeeRate, OutPoint as BitcoinOutPoint, Transaction, TxOut, Txid};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_consensus::bip68::sequence_lock_satisfied;
use bitcoin_rs_consensus::verify_transaction;
use bitcoin_rs_mempool::ReplacementCandidate;
use bitcoin_rs_mempool::standardness::{
    AcceptanceRejectReason, PackageAcceptanceFacts, PackageTxContext, StandardnessPolicy,
    evaluate_package_acceptance,
};
use bitcoin_rs_primitives::{Hash256, OutPoint};
use bitcoin_rs_script::VerifyFlags;
use hashbrown::{HashMap, HashSet};
use parking_lot::{Mutex, RwLock};

use crate::context::{TransactionAdmission, TransactionAdmissionError};

/// Distinguishes a newly committed admission from an idempotent known submit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionCommit {
    /// The transaction was already in the mempool.
    Duplicate(Txid),
    /// The transaction was evaluated and inserted.
    Admitted(Txid),
}

impl AdmissionCommit {
    /// Transaction id accepted by the pipeline.
    #[must_use]
    pub const fn txid(self) -> Txid {
        match self {
            Self::Duplicate(txid) | Self::Admitted(txid) => txid,
        }
    }
}

/// Bitcoin Core incremental relay fee default: 1000 sat/kvB.
pub(crate) const DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB: u64 = 1_000;

/// Shared handles required by the canonical admission pipeline.
pub struct AdmissionHandles {
    /// Mempool mutated by successful admission.
    pub mempool: Arc<RwLock<bitcoin_rs_mempool::Mempool>>,
    /// Live UTXO set consulted for prevout resolution.
    pub utxo: Arc<bitcoin_rs_utxo::UtxoSet>,
    /// Best-applied tip used for height and median-time-past.
    pub applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    /// Block tree used to compute median-time-past.
    pub block_tree: Arc<parking_lot::RwLock<bitcoin_rs_chain::BlockTree>>,
    /// Transaction map updated on successful admission.
    pub transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
}

/// Deterministic admission authority installed by [`crate::context::Context::new`].
pub struct LocalAdmission {
    handles: AdmissionHandles,
    transition: Mutex<()>,
}

impl LocalAdmission {
    /// Builds a local admission authority over the supplied handle Arcs.
    #[must_use]
    pub fn new(handles: AdmissionHandles) -> Self {
        Self {
            handles,
            transition: Mutex::new(()),
        }
    }
}

impl TransactionAdmission for LocalAdmission {
    fn submit_transaction(
        &self,
        tx: &Transaction,
        max_feerate_sat_per_kvb: Option<u64>,
    ) -> Result<Txid, TransactionAdmissionError> {
        let _guard = self.transition.lock();
        admit_transaction(&self.handles, tx, max_feerate_sat_per_kvb)
    }

    fn test_transactions(
        &self,
        txs: &[Transaction],
        max_feerate_sat_per_kvb: Option<u64>,
    ) -> Result<PackageAcceptanceFacts, TransactionAdmissionError> {
        let _guard = self.transition.lock();
        Ok(evaluate_admission(
            &self.handles,
            txs,
            max_feerate_sat_per_kvb,
        ))
    }
}

/// Runs canonical admission and reports whether the mempool was mutated.
pub fn admit_transaction_commit(
    handles: &AdmissionHandles,
    tx: &Transaction,
    max_feerate_sat_per_kvb: Option<u64>,
) -> Result<AdmissionCommit, TransactionAdmissionError> {
    let txid = tx.compute_txid();

    {
        let pool = handles.mempool.read();
        if pool.contains_txid(&txid) {
            return Ok(AdmissionCommit::Duplicate(txid));
        }
    }

    admit_unknown_transaction(handles, tx, txid, max_feerate_sat_per_kvb)
        .map(AdmissionCommit::Admitted)
}

/// Runs the canonical admission pipeline against `handles`.
///
/// Repeated RPC submissions are idempotent when the transaction is already in
/// the mempool. The transaction cache is lookup and relay only.
///
/// Caller contract: the caller must hold exclusion against chain transitions for
/// the whole call so every state read and the final mutation observe one tip.
pub fn admit_transaction(
    handles: &AdmissionHandles,
    tx: &Transaction,
    max_feerate_sat_per_kvb: Option<u64>,
) -> Result<Txid, TransactionAdmissionError> {
    admit_transaction_commit(handles, tx, max_feerate_sat_per_kvb).map(AdmissionCommit::txid)
}

fn admit_unknown_transaction(
    handles: &AdmissionHandles,
    tx: &Transaction,
    txid: Txid,
    max_feerate_sat_per_kvb: Option<u64>,
) -> Result<Txid, TransactionAdmissionError> {
    let facts = evaluate_admission(handles, std::slice::from_ref(tx), max_feerate_sat_per_kvb);
    if let Some(error) = facts.package_error {
        return Err(TransactionAdmissionError::Reject(error));
    }
    let fact = facts.results.into_iter().next().ok_or_else(|| {
        TransactionAdmissionError::Internal("package acceptance returned no rows".into())
    })?;
    if let Some(reason) = fact.reject_reason {
        return Err(match reason {
            AcceptanceRejectReason::ScriptVerify => {
                TransactionAdmissionError::Consensus("script verification failed".into())
            }
            other => TransactionAdmissionError::Reject(other),
        });
    }
    if fact.allowed != Some(true) {
        return Err(TransactionAdmissionError::Internal(
            "package acceptance returned an unvalidated row".into(),
        ));
    }

    let applied_height = handles
        .applied_tip
        .load_full()
        .as_ref()
        .map_or(0, |tip| tip.height);
    let fee = fact.base_fee.unwrap_or(0);
    let time = unix_time_secs();
    let candidate = ReplacementCandidate::new(
        Arc::new(tx.clone()),
        fact.vsize,
        fee,
        DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB,
    );
    {
        let mut pool = handles.mempool.write();
        pool.replace_transaction(candidate, time, applied_height, fact.sigop_cost)
            .map_err(TransactionAdmissionError::Commit)?;
    }
    handles.transactions.write().insert(txid, tx.clone());
    Ok(txid)
}

/// Dry-run the canonical admission pipeline without mutating the mempool.
///
/// Runs package policy, next-block BIP68 sequence locks, and consensus script
/// verification against one coherent tip read. Used by `testmempoolaccept`.
#[must_use]
pub fn evaluate_admission(
    handles: &AdmissionHandles,
    txs: &[Transaction],
    max_feerate_sat_per_kvb: Option<u64>,
) -> PackageAcceptanceFacts {
    let pool = handles.mempool.read();
    let resolved = resolve_package_transactions(&handles.utxo, &pool, txs);
    let contexts: Vec<PackageTxContext> = resolved.iter().map(|row| row.context).collect();
    let mut facts = evaluate_package_acceptance(
        &pool,
        &standardness_policy(),
        txs,
        &contexts,
        max_feerate_sat_per_kvb,
        DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB,
    );
    if facts.package_error.is_some() {
        return facts;
    }
    let (next_height, locktime_cutoff) = next_block_lock_context(handles);
    let mut package_failed = false;
    for ((tx, resolution), fact) in txs
        .iter()
        .zip(resolved.iter())
        .zip(facts.results.iter_mut())
    {
        if package_failed {
            fact.allowed = None;
            fact.base_fee = None;
            fact.reject_reason = None;
            continue;
        }
        if fact.allowed != Some(true) {
            package_failed = fact.allowed == Some(false);
            continue;
        }
        if let Err(reason) = verify_for_next_block(
            handles,
            &pool,
            tx,
            &resolution.prevouts,
            &resolution.prior_package_txids,
            next_height,
            locktime_cutoff,
        ) {
            fact.allowed = Some(false);
            fact.reject_reason = Some(reason);
            package_failed = true;
        }
    }
    facts
}

fn next_block_lock_context(handles: &AdmissionHandles) -> (u32, u32) {
    let tip = handles.applied_tip.load_full();
    let applied_height = tip.as_ref().map_or(0, |tip| tip.height);
    let next_height = applied_height.saturating_add(1);
    let locktime_cutoff = tip
        .as_ref()
        .and_then(|tip| {
            let tree = handles.block_tree.read();
            let node_id = tree.lookup(tip.hash)?;
            tree.median_time_past_at(node_id, 11)
        })
        .unwrap_or(0);
    (next_height, locktime_cutoff)
}

fn verify_for_next_block(
    handles: &AdmissionHandles,
    pool: &bitcoin_rs_mempool::Mempool,
    tx: &Transaction,
    prevouts: &BTreeMap<BitcoinOutPoint, TxOut>,
    prior_package_txids: &HashSet<Txid>,
    next_height: u32,
    locktime_cutoff: u32,
) -> Result<(), AcceptanceRejectReason> {
    if prevouts.len() != tx.input.len() {
        return Err(AcceptanceRejectReason::MissingInputs);
    }
    if !next_block_sequence_locks_final(
        handles,
        pool,
        tx,
        prior_package_txids,
        next_height,
        locktime_cutoff,
    ) {
        return Err(AcceptanceRejectReason::NonBip68Final);
    }
    if verify_transaction(
        tx,
        prevouts,
        next_height,
        locktime_cutoff,
        VerifyFlags::STANDARD,
    )
    .is_err()
    {
        return Err(AcceptanceRejectReason::ScriptVerify);
    }
    Ok(())
}

fn next_block_sequence_locks_final(
    handles: &AdmissionHandles,
    pool: &bitcoin_rs_mempool::Mempool,
    tx: &Transaction,
    prior_package_txids: &HashSet<Txid>,
    next_height: u32,
    locktime_cutoff: u32,
) -> bool {
    if tx.version.0 < 2 {
        return true;
    }
    let tip = handles.applied_tip.load_full();
    tx.input.iter().all(|input| {
        let sequence = input.sequence.to_consensus_u32();
        let parent_txid = input.previous_output.txid;
        let unconfirmed = pool.transaction_by_txid(&parent_txid).is_some()
            || prior_package_txids.contains(&parent_txid);
        let (prevout_height, prevout_mtp) = if unconfirmed {
            (next_height, locktime_cutoff)
        } else {
            let utxo_outpoint = OutPoint::new(
                Hash256::from_le_bytes(parent_txid.as_byte_array()),
                input.previous_output.vout,
            );
            let Some(live) = handles.utxo.get_entry(&utxo_outpoint) else {
                return false;
            };
            let prevout_mtp = tip
                .as_ref()
                .and_then(|tip| prevout_median_time_past(handles, tip, live.height))
                .unwrap_or(locktime_cutoff);
            (live.height, prevout_mtp)
        };
        sequence_lock_satisfied(
            tx.version.0,
            sequence,
            prevout_height,
            prevout_mtp,
            next_height,
            locktime_cutoff,
        )
    })
}

fn prevout_median_time_past(
    handles: &AdmissionHandles,
    tip: &TipSnapshot,
    prevout_height: u32,
) -> Option<u32> {
    let tree = handles.block_tree.read();
    let mtp_height = prevout_height.saturating_sub(1);
    let prev_block_node = tree.node_at_height_from(tip.tip_id, mtp_height)?;
    tree.median_time_past_at(prev_block_node, 11)
}

pub(crate) fn standardness_policy() -> StandardnessPolicy {
    StandardnessPolicy {
        dust_relay_fee: FeeRate::DUST,
        max_datacarrier_bytes: Some(83),
    }
}

pub(crate) fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Ordered package prevout resolver.
///
/// Walks the submitted transactions in input order and retains complete
/// prior-package `TxOut` prevouts (value and script) plus the set of
/// prior-package parent txids. Those facts feed fee, sigop, script
/// verification, and BIP68. Package parents are unconfirmed for relative locks.
struct ResolvedPackageTx {
    context: PackageTxContext,
    prevouts: BTreeMap<BitcoinOutPoint, TxOut>,
    prior_package_txids: HashSet<Txid>,
}

fn resolve_package_transactions(
    utxo: &bitcoin_rs_utxo::UtxoSet,
    pool: &bitcoin_rs_mempool::Mempool,
    txs: &[Transaction],
) -> Vec<ResolvedPackageTx> {
    let mut package_outputs: HashMap<(Txid, u32), TxOut> = HashMap::new();
    let mut prior_package_txids: HashSet<Txid> = HashSet::new();
    let mut resolved = Vec::with_capacity(txs.len());

    for tx in txs {
        let mut missing_inputs = false;
        let mut input_value = 0_u64;
        let mut prevouts: BTreeMap<BitcoinOutPoint, TxOut> = BTreeMap::new();

        for input in &tx.input {
            if input.previous_output.is_null() {
                missing_inputs = true;
                continue;
            }
            let key = (input.previous_output.txid, input.previous_output.vout);
            if let Some(output) = package_outputs.get(&key) {
                input_value = input_value.saturating_add(output.value.to_sat());
                prevouts.insert(input.previous_output, output.clone());
                continue;
            }
            if let Some(parent) = pool.transaction_by_txid(&input.previous_output.txid)
                && let Some(output) = usize::try_from(input.previous_output.vout)
                    .ok()
                    .and_then(|vout| parent.output.get(vout))
            {
                input_value = input_value.saturating_add(output.value.to_sat());
                prevouts.insert(input.previous_output, output.clone());
                continue;
            }
            let utxo_outpoint = OutPoint::new(
                Hash256::from_le_bytes(input.previous_output.txid.as_byte_array()),
                input.previous_output.vout,
            );
            if let Some(live) = utxo.get_entry(&utxo_outpoint) {
                input_value = input_value.saturating_add(live.txout.value.to_sat());
                prevouts.insert(input.previous_output, live.txout);
                continue;
            }
            missing_inputs = true;
        }

        let output_value = tx.output.iter().fold(0_u64, |sum, output| {
            sum.saturating_add(output.value.to_sat())
        });
        let fee = input_value.saturating_sub(output_value);
        let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
        let sigop_cost =
            u32::try_from(tx.total_sigop_cost(|outpoint| prevouts.get(outpoint).cloned()))
                .unwrap_or(u32::MAX);

        resolved.push(ResolvedPackageTx {
            context: PackageTxContext {
                fee,
                vsize,
                sigop_cost,
                missing_inputs,
            },
            prevouts,
            prior_package_txids: prior_package_txids.clone(),
        });

        let txid = tx.compute_txid();
        prior_package_txids.insert(txid);
        for (vout, output) in tx.output.iter().enumerate() {
            let vout = u32::try_from(vout).unwrap_or(u32::MAX);
            package_outputs.insert((txid, vout), output.clone());
        }
    }

    resolved
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};

    fn empty_handles() -> AdmissionHandles {
        AdmissionHandles {
            mempool: Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            utxo: Arc::new(bitcoin_rs_utxo::UtxoSet::new()),
            applied_tip: Arc::new(arc_swap::ArcSwapOption::empty()),
            block_tree: Arc::new(parking_lot::RwLock::new(bitcoin_rs_chain::BlockTree::new())),
            transactions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn dummy_tx() -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        }
    }

    #[test]
    fn cache_only_admission_evaluates_instead_of_short_circuiting() {
        let handles = empty_handles();
        let tx = dummy_tx();
        let txid = tx.compute_txid();
        handles.transactions.write().insert(txid, tx.clone());

        let commit = admit_transaction_commit(&handles, &tx, None);
        assert!(
            !matches!(commit, Ok(AdmissionCommit::Duplicate(_))),
            "the transaction cache must not be a duplicate gate, got {commit:?}"
        );
        if commit.is_err() {
            assert!(
                !handles.mempool.read().contains_txid(&txid),
                "a rejected cache-only submit must not land in the mempool"
            );
        }
    }

    #[test]
    fn mempool_membership_is_the_sole_duplicate_authority() {
        let handles = empty_handles();
        let tx = dummy_tx();
        let txid = tx.compute_txid();
        handles
            .mempool
            .write()
            .insert_entry(MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 0))
            .unwrap_or_else(|err| panic!("fixture mempool insert: {err}"));

        assert_eq!(
            admit_transaction_commit(&handles, &tx, None)
                .unwrap_or_else(|err| panic!("known mempool tx must stay idempotent: {err}")),
            AdmissionCommit::Duplicate(txid)
        );
        assert!(handles.mempool.read().contains_txid(&txid));
    }
}
