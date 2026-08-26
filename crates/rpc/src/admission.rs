//! Canonical transaction admission pipeline.
//!
//! [`admit_transaction`] is the single validator used by production RPC and by
//! deterministic tests. The caller must hold exclusion against chain transitions
//! for the whole call so verification and commit observe one coherent state.

use alloc::sync::Arc;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, FeeRate, OutPoint as BitcoinOutPoint, ScriptBuf, Transaction, TxOut, Txid};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_consensus::verify_transaction;
use bitcoin_rs_mempool::ReplacementCandidate;
use bitcoin_rs_mempool::standardness::{
    AcceptanceRejectReason, PackageTxContext, StandardnessPolicy, evaluate_package_acceptance,
};
use bitcoin_rs_primitives::{Hash256, OutPoint};
use bitcoin_rs_script::VerifyFlags;
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};

use crate::context::{TransactionAdmission, TransactionAdmissionError};

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
}

/// Runs the canonical admission pipeline against `handles`.
///
/// Caller contract: the caller must hold exclusion against chain transitions for
/// the whole call so every state read and the final mutation observe one tip.
pub fn admit_transaction(
    handles: &AdmissionHandles,
    tx: &Transaction,
    max_feerate_sat_per_kvb: Option<u64>,
) -> Result<Txid, TransactionAdmissionError> {
    let txid = tx.compute_txid();

    {
        let pool = handles.mempool.read();
        if pool.contains_txid(&txid) {
            return Ok(txid);
        }
    }
    if handles.transactions.read().contains_key(&txid) {
        return Ok(txid);
    }

    let fact = {
        let pool = handles.mempool.read();
        let contexts = package_contexts(&handles.utxo, &pool, std::slice::from_ref(tx));
        let facts = evaluate_package_acceptance(
            &pool,
            &standardness_policy(),
            std::slice::from_ref(tx),
            &contexts,
            max_feerate_sat_per_kvb,
            DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB,
        );
        if let Some(error) = facts.package_error {
            return Err(TransactionAdmissionError::Reject(error));
        }
        facts.results.into_iter().next().ok_or_else(|| {
            TransactionAdmissionError::Internal("package acceptance returned no rows".into())
        })?
    };

    if let Some(reason) = fact.reject_reason {
        return Err(TransactionAdmissionError::Reject(reason));
    }

    let tip = handles.applied_tip.load_full();
    let height = tip.as_ref().map_or(0, |tip| tip.height);
    let locktime_cutoff = tip
        .as_ref()
        .and_then(|tip| {
            let tree = handles.block_tree.read();
            let node_id = tree.lookup(tip.hash)?;
            tree.median_time_past_at(node_id, 11)
        })
        .unwrap_or(0);
    let fee = fact.base_fee.unwrap_or(0);
    let time = unix_time_secs();
    {
        let pool = handles.mempool.read();
        let prevouts = resolved_prevouts(&handles.utxo, &pool, tx)?;
        verify_transaction(
            tx,
            &prevouts,
            height,
            locktime_cutoff,
            VerifyFlags::STANDARD,
        )
        .map_err(|error| TransactionAdmissionError::Consensus(error.to_string().into()))?;
    }

    let candidate = ReplacementCandidate::new(
        Arc::new(tx.clone()),
        fact.vsize,
        fee,
        DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB,
    );
    {
        let mut pool = handles.mempool.write();
        pool.replace_transaction(candidate, time, height, fact.sigop_cost)
            .map_err(TransactionAdmissionError::Commit)?;
    }
    handles.transactions.write().insert(txid, tx.clone());
    Ok(txid)
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

pub(crate) fn package_contexts(
    utxo: &bitcoin_rs_utxo::UtxoSet,
    pool: &bitcoin_rs_mempool::Mempool,
    txs: &[Transaction],
) -> Vec<PackageTxContext> {
    let mut package_outputs: HashMap<(Txid, u32), Amount> = HashMap::new();
    let mut contexts = Vec::with_capacity(txs.len());

    for tx in txs {
        let mut missing_inputs = false;
        let mut input_value = 0_u64;
        let mut prevouts: HashMap<BitcoinOutPoint, TxOut> = HashMap::new();

        for input in &tx.input {
            if input.previous_output.is_null() {
                missing_inputs = true;
                continue;
            }
            let key = (input.previous_output.txid, input.previous_output.vout);
            if let Some(value) = package_outputs.get(&key) {
                input_value = input_value.saturating_add(value.to_sat());
                prevouts.insert(
                    input.previous_output,
                    TxOut {
                        value: *value,
                        script_pubkey: ScriptBuf::new(),
                    },
                );
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

        contexts.push(PackageTxContext {
            fee,
            vsize,
            sigop_cost,
            missing_inputs,
        });

        let txid = tx.compute_txid();
        for (vout, output) in tx.output.iter().enumerate() {
            let vout = u32::try_from(vout).unwrap_or(u32::MAX);
            package_outputs.insert((txid, vout), output.value);
        }
    }

    contexts
}

pub(crate) fn resolved_prevouts(
    utxo: &bitcoin_rs_utxo::UtxoSet,
    pool: &bitcoin_rs_mempool::Mempool,
    tx: &Transaction,
) -> Result<BTreeMap<BitcoinOutPoint, TxOut>, TransactionAdmissionError> {
    let mut prevouts = BTreeMap::new();
    for input in &tx.input {
        if input.previous_output.is_null() {
            return Err(TransactionAdmissionError::Reject(
                AcceptanceRejectReason::MissingInputs,
            ));
        }
        if let Some(parent) = pool.transaction_by_txid(&input.previous_output.txid)
            && let Some(output) = usize::try_from(input.previous_output.vout)
                .ok()
                .and_then(|vout| parent.output.get(vout))
        {
            prevouts.insert(input.previous_output, output.clone());
            continue;
        }
        let utxo_outpoint = OutPoint::new(
            Hash256::from_le_bytes(input.previous_output.txid.as_byte_array()),
            input.previous_output.vout,
        );
        if let Some(live) = utxo.get_entry(&utxo_outpoint) {
            prevouts.insert(input.previous_output, live.txout);
            continue;
        }
        return Err(TransactionAdmissionError::Reject(
            AcceptanceRejectReason::MissingInputs,
        ));
    }
    Ok(prevouts)
}
