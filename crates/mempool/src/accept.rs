//! Mempool acceptance, the gate Bitcoin Core calls `AcceptToMemoryPool`.
//!
//! Every policy piece this needs already existed in this crate — standardness,
//! BIP125 replacement, ancestor and descendant limits, size eviction — and
//! nothing called any of it: no production path inserted into the mempool at
//! all. This module is the ignition, not a new engine.
//!
//! The order below follows Core's `MemPoolAccept::PreChecks`: cheap
//! non-contextual rejections first, then standardness, then prevout
//! resolution, then full consensus verification, and only then the policy
//! checks that need to see the rest of the pool.
//!
//! One thing is computed here rather than anywhere else: **sigop cost**. P2SH
//! sigops cannot be counted from a transaction alone — the spent
//! `scriptPubKey` says how many there are — so the only place that can count
//! them without a second UTXO pass is the place that has already resolved the
//! prevouts. Core stores `sigOpCost` on the entry at acceptance for exactly
//! this reason, and `MempoolEntry::sigop_cost` is the same decision.

use alloc::sync::Arc;
use alloc::vec::Vec;

use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_consensus::{ConsensusError, verify_transaction};
use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, Txid};
use bitcoin_rs_script::VerifyFlags;
use bitcoin_rs_script::script::{Instruction, instructions, is_p2sh, is_witness_program, opcode};
use bitcoin_rs_script::sigops::{count_segwit, count_tx_legacy};
use thiserror::Error;

use crate::rbf::{RbfError, ReplacementCandidate};
use crate::standardness::{StandardnessError, StandardnessPolicy, is_standard_tx};
use crate::{EntryId, Mempool, MempoolError};

/// Relay limit on one transaction's sigop cost.
///
/// Bitcoin Core's `MAX_STANDARD_TX_SIGOPS_COST`, a fifth of the block limit:
/// a single transaction may not consume more than one fifth of a block's
/// sigop budget.
pub const MAX_STANDARD_TX_SIGOPS_COST: u32 = 16_000;

/// Chain and policy state for one acceptance attempt.
#[derive(Clone, Copy, Debug)]
pub struct AcceptContext {
    /// Height the transaction is evaluated at.
    ///
    /// This is the height of the **next** block, not the tip: Core evaluates
    /// finality against `tip->nHeight + 1`, because a transaction entering the
    /// mempool is a candidate for the block being built, not for one already
    /// mined.
    pub height: u32,
    /// Timestamp `nLockTime` is compared against.
    ///
    /// The tip's median time past after BIP113, which is what makes a
    /// timelocked transaction enter the mempool at the same moment it would
    /// become valid in a block.
    pub locktime_cutoff: u32,
    /// Acceptance time recorded on the entry, in seconds.
    pub time: u64,
    /// Relay standardness policy.
    pub standardness: StandardnessPolicy,
    /// Whether to enforce standardness.
    ///
    /// Core's `-acceptnonstdtxn`, which defaults to off (that is, standardness
    /// enforced) everywhere except regtest.
    pub require_standard: bool,
    /// Absolute fee ceiling for this submission, in satoshis.
    ///
    /// `None` means no ceiling. Bitcoin Core derives one from
    /// `sendrawtransaction`'s `maxfeerate` and the transaction's vsize, checks
    /// it against the fee a test-accept computed, and only then submits. The
    /// ceiling lives here so that check happens inside the same operation that
    /// admits the transaction: computing the fee, comparing it, and mutating
    /// the pool must not be three separately-locked steps.
    pub max_fee: Option<u64>,
}

/// Reason a transaction was not accepted.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AcceptError {
    /// The transaction is already in the mempool.
    #[error("transaction already in mempool")]
    AlreadyInPool,
    /// A coinbase transaction can only arrive inside a block.
    #[error("coinbase transaction is not accepted to the mempool")]
    Coinbase,
    /// The transaction is valid but not relayed under standardness policy.
    #[error("non-standard transaction: {0}")]
    Standardness(#[from] StandardnessError),
    /// One or more prevouts were resolved by neither the chain nor the mempool.
    ///
    /// Core reports `bad-txns-inputs-missingorspent` and cannot distinguish
    /// "never existed" from "already spent" either. The outpoints are returned
    /// so the caller can decide whether this is an orphan worth holding.
    #[error("missing or spent inputs")]
    MissingInputs(Vec<OutPoint>),
    /// The transaction failed consensus verification.
    #[error("consensus check failed: {0}")]
    Consensus(#[from] ConsensusError),
    /// Input values summed past the satoshi range.
    #[error("input value overflows satoshi range")]
    InputValueOverflow,
    /// Output values summed past the satoshi range.
    #[error("output value overflows satoshi range")]
    OutputValueOverflow,
    /// Virtual size did not fit the entry field width.
    #[error("transaction vsize does not fit in u32")]
    VsizeOverflow,
    /// The fee is above the ceiling the submitter set.
    ///
    /// Not a policy rejection: the transaction is acceptable and the caller
    /// asked not to send it anyway. Bitcoin Core's
    /// "Fee exceeds maximum configured by user".
    #[error("fee {fee} exceeds the configured maximum {max_fee}")]
    FeeExceedsMaximum {
        /// Fee the transaction pays, in satoshis.
        fee: u64,
        /// Ceiling the submitter set, in satoshis.
        max_fee: u64,
    },
    /// Sigop cost exceeds what relay policy allows for a single transaction.
    #[error("sigop cost {cost} exceeds the standard maximum {max}")]
    TooManySigops {
        /// Sigop cost counted against the resolved prevouts.
        cost: u32,
        /// Relay policy maximum.
        max: u32,
    },
    /// BIP125 replacement was rejected.
    #[error("replacement rejected: {0}")]
    Rbf(#[from] RbfError),
    /// Insertion failed a mempool policy limit.
    #[error("mempool rejected the entry: {0}")]
    Mempool(#[from] MempoolError),
}

/// Everything acceptance determined, before anything was inserted.
///
/// Split out from insertion so `testmempoolaccept` can answer with the real
/// verdict instead of guessing. Core makes the same split with its
/// `test_accept` flag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptChecks {
    /// Transaction id of the checked transaction.
    pub txid: Txid,
    /// Fee in satoshis, derived from the resolved prevouts.
    pub fee: u64,
    /// Virtual size in vbytes.
    pub vsize: u32,
    /// BIP141 sigop cost against the resolved prevouts.
    pub sigop_cost: u32,
    /// Transactions a BIP125 replacement would evict, empty for a plain accept.
    pub replaced: Vec<Txid>,
}

/// What acceptance produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptResult {
    /// Identifier of the inserted entry.
    pub id: EntryId,
    /// The checks that admitted it.
    pub checks: AcceptChecks,
}

/// Chain UTXO set with the mempool's unconfirmed outputs layered on top.
///
/// Bitcoin Core's `CCoinsViewMemPool`. Mempool first: a txid present in the
/// pool is by definition unconfirmed, so the chain cannot hold the same
/// outpoint, and consulting the pool first is what lets a child spend its
/// unconfirmed parent.
///
/// Deliberately does **not** hide outputs another mempool transaction spends.
/// Detecting that is the replacement path's job, and hiding them here would
/// turn every RBF attempt into a missing-inputs rejection.
pub struct MempoolUtxoView<'a, V> {
    pool: &'a Mempool,
    chain: &'a V,
}

impl<'a, V> MempoolUtxoView<'a, V> {
    /// Layers `pool`'s unconfirmed outputs over `chain`.
    #[must_use]
    pub const fn new(pool: &'a Mempool, chain: &'a V) -> Self {
        Self { pool, chain }
    }
}

impl<V> UtxoView for MempoolUtxoView<'_, V>
where
    V: UtxoView,
{
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        if let Some(entry) = self.pool.entry_by_txid(&outpoint.txid) {
            let vout = usize::try_from(outpoint.vout).ok()?;
            return entry.tx.outputs.get(vout).cloned();
        }
        self.chain.lookup(outpoint)
    }
}

/// Runs every acceptance check against `pool` without modifying it.
///
/// `chain` supplies confirmed outputs; unconfirmed parents already in `pool`
/// are layered over it, so a child arriving before its parent confirms is
/// checked against that parent rather than reported as missing its inputs.
///
/// # Errors
///
/// Returns [`AcceptError`] describing the first check that rejected the
/// transaction. [`AcceptError::MissingInputs`] carries the unresolved
/// outpoints so the caller can route the transaction to an orphan pool.
pub fn check_acceptance<V>(
    pool: &Mempool,
    tx: &Arc<Tx>,
    chain: &V,
    ctx: &AcceptContext,
) -> Result<AcceptChecks, AcceptError>
where
    V: UtxoView,
{
    let txid = tx.txid();
    if pool.contains_txid(&txid) {
        return Err(AcceptError::AlreadyInPool);
    }
    if is_coinbase(tx) {
        return Err(AcceptError::Coinbase);
    }
    if ctx.require_standard {
        is_standard_tx(tx, &ctx.standardness)?;
    }

    let view = MempoolUtxoView::new(pool, chain);

    let mut missing = Vec::new();
    let mut value_in = 0_u64;
    let mut prevouts = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        match view.lookup(&input.previous_output) {
            Some(prevout) => {
                value_in = value_in
                    .checked_add(prevout.value)
                    .ok_or(AcceptError::InputValueOverflow)?;
                prevouts.push((input.previous_output, prevout));
            }
            None => missing.push(input.previous_output),
        }
    }
    if !missing.is_empty() {
        return Err(AcceptError::MissingInputs(missing));
    }

    // Counted here, before script verification, for the same reason Core
    // counts it in `PreChecks` rather than in `PolicyScriptChecks`: the sigop
    // limit is a cheap rejection and there is no sense running scripts for a
    // transaction that cannot be relayed anyway.
    let sigop_cost = u32::try_from(total_sigop_cost(tx, &prevouts)).unwrap_or(u32::MAX);
    if sigop_cost > MAX_STANDARD_TX_SIGOPS_COST {
        return Err(AcceptError::TooManySigops {
            cost: sigop_cost,
            max: MAX_STANDARD_TX_SIGOPS_COST,
        });
    }

    // Full verification, scripts included, under relay flags. Core runs policy
    // flags in the mempool and consensus flags in a block, so a transaction
    // rejected here may still be valid in a block someone else mines.
    verify_transaction(
        tx,
        &view,
        ctx.height,
        ctx.locktime_cutoff,
        VerifyFlags::STANDARD,
    )?;

    let mut value_out = 0_u64;
    for output in &tx.outputs {
        value_out = value_out
            .checked_add(output.value)
            .ok_or(AcceptError::OutputValueOverflow)?;
    }
    // Verification already rejected `value_out > value_in`; saturating rather
    // than unwrapping keeps this from becoming a panic if that check moves.
    let fee = value_in.saturating_sub(value_out);

    let vsize = u32::try_from(tx.vsize()).map_err(|_| AcceptError::VsizeOverflow)?;
    let candidate = replacement_candidate(pool, tx, vsize, fee, sigop_cost);
    let replaced = pool
        .check_replacement(&candidate)?
        .evicted
        .iter()
        .filter_map(|id| pool.entry(*id).map(|entry| entry.txid))
        .collect::<Vec<_>>();

    Ok(AcceptChecks {
        txid,
        fee,
        vsize,
        sigop_cost,
        replaced,
    })
}

/// Validates `tx` and inserts it into `pool`.
///
/// Runs [`check_acceptance`] and, if it passes, applies any BIP125 eviction
/// and inserts the entry with the sigop cost the checks derived.
///
/// # Errors
///
/// As [`check_acceptance`], plus [`AcceptError::Mempool`] if insertion hits a
/// policy limit that only applies once the entry is placed.
pub fn accept_to_mempool<V>(
    pool: &mut Mempool,
    tx: Tx,
    chain: &V,
    ctx: &AcceptContext,
) -> Result<AcceptResult, AcceptError>
where
    V: UtxoView,
{
    let tx = Arc::new(tx);
    let checks = check_acceptance(pool, &tx, chain, ctx)?;
    // Before anything is removed or inserted. The fee is only known once the
    // prevouts are resolved, so the ceiling cannot be applied earlier -- but it
    // must be applied before the pool is touched, or a transaction the caller
    // capped has already replaced the originals by the time it is refused.
    if let Some(max_fee) = ctx.max_fee
        && checks.fee > max_fee
    {
        return Err(AcceptError::FeeExceedsMaximum {
            fee: checks.fee,
            max_fee,
        });
    }
    let candidate = replacement_candidate(pool, &tx, checks.vsize, checks.fee, checks.sigop_cost);
    // `replace_transaction` re-runs `check_replacement` internally. Paying for
    // one extra walk of the conflict set keeps BIP125 eviction implemented in
    // exactly one place; inlining it here would be a second copy to drift.
    let outcome = pool
        .replace_transaction(candidate, ctx.time, ctx.height, checks.sigop_cost)
        .map_err(|error| match error {
            // `replace_transaction` reports every failure as an `RbfError`,
            // including the plain insertion limits, which have nothing to do
            // with replacement. Reporting "below min relay fee" as
            // "replacement rejected" would send the caller looking for a
            // conflict that never existed.
            RbfError::Mempool(mempool) => AcceptError::Mempool(mempool),
            rbf => AcceptError::Rbf(rbf),
        })?;
    if outcome.is_shed() {
        // The entry committed and was shed by the size-limit trim in the
        // same step: the same refusal the pre-commit limit check produced.
        return Err(AcceptError::Mempool(MempoolError::Full));
    }
    let id = pool
        .entry_id_by_txid(&checks.txid)
        .ok_or(AcceptError::Mempool(MempoolError::TooManyEntries))?;
    Ok(AcceptResult { id, checks })
}

fn replacement_candidate(
    pool: &Mempool,
    tx: &Arc<Tx>,
    vsize: u32,
    fee: u64,
    sigop_cost: u32,
) -> ReplacementCandidate {
    ReplacementCandidate::new(Arc::clone(tx), vsize, fee, pool.min_relay_fee_sat_per_kvb())
        .with_sigop_cost(sigop_cost)
}

/// Returns true if `tx` is a coinbase: exactly one input with the null outpoint.
fn is_coinbase(tx: &Tx) -> bool {
    tx.inputs.len() == 1
        && tx.inputs[0].previous_output.txid == Txid::default()
        && tx.inputs[0].previous_output.vout == u32::MAX
}

/// Computes the total sigop cost for a transaction given resolved prevouts.
///
/// Mirrors the consensus `total_sigop_cost` using public script-crate counters:
/// legacy sigops × 4, plus P2SH redeem-script accurate sigops × 4, plus
/// segwit witness-program sigops.
fn total_sigop_cost(tx: &Tx, prevouts: &[(OutPoint, TxOut)]) -> u64 {
    let mut cost = u64::from(count_tx_legacy(tx)).saturating_mul(4);
    for input in &tx.inputs {
        let prevout = prevouts
            .iter()
            .find(|(op, _)| *op == input.previous_output)
            .map(|(_, txout)| txout);
        let Some(prevout) = prevout else {
            continue;
        };
        let redeem_script = last_push(&input.script_sig);
        if is_p2sh(&prevout.script_pubkey) {
            if let Some(redeem) = redeem_script {
                cost = cost.saturating_add(u64::from(count_accurate(redeem)).saturating_mul(4));
            }
        }
        let witness_program = if is_witness_program(&prevout.script_pubkey) {
            Some(prevout.script_pubkey.as_slice())
        } else {
            redeem_script.filter(|script| is_witness_program(script))
        };
        if let Some(program) = witness_program {
            cost = cost.saturating_add(u64::from(count_segwit(program, &input.witness)));
        }
    }
    cost
}

/// Returns the last data push from a script, or `None`.
fn last_push(script: &[u8]) -> Option<&[u8]> {
    let mut last = None;
    for instruction in instructions(script) {
        match instruction.ok()? {
            Instruction::PushBytes(bytes) => last = Some(bytes),
            Instruction::Op(_) => last = None,
        }
    }
    last
}

/// Counts sigops accurately (multisig uses the preceding pushnum value).
fn count_accurate(script: &[u8]) -> u32 {
    let mut count = 0_u32;
    let mut pushed_number = None;
    for instruction in instructions(script) {
        match instruction {
            Ok(Instruction::Op(op)) => match op {
                opcode::OP_CHECKSIG | opcode::OP_CHECKSIGVERIFY => {
                    count = count.saturating_add(1);
                    pushed_number = None;
                }
                opcode::OP_CHECKMULTISIG | opcode::OP_CHECKMULTISIGVERIFY => {
                    count = count.saturating_add(u32::from(pushed_number.unwrap_or(20)));
                    pushed_number = None;
                }
                other => pushed_number = opcode::decode_pushnum(other),
            },
            Ok(Instruction::PushBytes(_)) => pushed_number = None,
            Err(_) => break,
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MempoolLimits;
    use alloc::collections::BTreeMap;
    use alloc::vec;
    use bitcoin_rs_primitives::{Hash256, TxIn};
    use bitcoin_rs_script::script::{opcode, push_data, push_int};
    use bitcoin_rs_script::sigops::count_tx_legacy;

    /// A local `UtxoView` over a map. The trait is only implemented for
    /// `hashbrown::HashMap` upstream, and `OutPoint` has no `Ord`, so the
    /// fixtures key the map by the outpoint's wire bytes instead.
    struct ChainView(BTreeMap<[u8; 36], TxOut>);

    impl UtxoView for ChainView {
        fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
            self.0.get(&outpoint_key(outpoint)).cloned()
        }
    }

    fn outpoint_key(outpoint: &OutPoint) -> [u8; 36] {
        let mut key = [0_u8; 36];
        key[..32].copy_from_slice(outpoint.txid.as_bytes());
        key[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
        key
    }

    /// A prevout script anyone can spend with an empty scriptSig.
    ///
    /// Keeps these tests about acceptance. Producing real signatures would
    /// turn every fixture into a signing exercise, and a prevout's own script
    /// is not what standardness looks at.
    fn anyone_can_spend() -> Vec<u8> {
        vec![0x51]
    }

    fn p2pkh(tag: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(25);
        out.push(opcode::OP_DUP);
        out.push(opcode::OP_HASH160);
        out.push(0x14);
        out.extend_from_slice(&[tag; 20]);
        out.push(opcode::OP_EQUALVERIFY);
        out.push(opcode::OP_CHECKSIG);
        out
    }

    /// Builds a P2SH scriptPubKey from a 20-byte redeem-script hash.
    fn p2sh_script_pubkey(redeem_hash: &[u8; 20]) -> Vec<u8> {
        let mut out = Vec::with_capacity(23);
        out.push(opcode::OP_HASH160);
        out.push(0x14);
        out.extend_from_slice(redeem_hash);
        out.push(opcode::OP_EQUAL);
        out
    }

    fn outpoint(tag: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid(Hash256::from_le_bytes(&[tag; 32])), vout)
    }

    /// Spends `inputs` and pays `output_value` to a standard P2PKH script.
    fn spending_tx(inputs: &[OutPoint], output_value: u64, tag: u8) -> Tx {
        Tx {
            version: 2,
            lock_time: 0,
            inputs: inputs
                .iter()
                .map(|previous_output| TxIn {
                    previous_output: *previous_output,
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                })
                .collect(),
            outputs: vec![TxOut {
                value: output_value,
                script_pubkey: p2pkh(tag),
            }],
        }
    }

    fn chain_with(entries: &[(OutPoint, u64)]) -> ChainView {
        ChainView(
            entries
                .iter()
                .map(|(outpoint, value)| {
                    (
                        outpoint_key(outpoint),
                        TxOut {
                            value: *value,
                            script_pubkey: anyone_can_spend(),
                        },
                    )
                })
                .collect(),
        )
    }

    fn context() -> AcceptContext {
        AcceptContext {
            height: 800_001,
            locktime_cutoff: 1_700_000_000,
            time: 42,
            standardness: StandardnessPolicy {
                dust_relay_fee: 3_000,
                max_datacarrier_bytes: Some(83),
            },
            require_standard: true,
            max_fee: None,
        }
    }

    fn pool() -> Mempool {
        Mempool::new(MempoolLimits::default())
    }

    #[test]
    fn accepts_a_standard_transaction_and_derives_its_fee_from_the_prevouts() {
        let mut pool = pool();
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        let tx = spending_tx(&[outpoint(1, 0)], 90_000, 7);

        let Ok(result) = accept_to_mempool(&mut pool, tx, &chain, &context()) else {
            panic!("a standard transaction spending a confirmed output must be accepted");
        };

        assert_eq!(result.checks.fee, 10_000, "fee is value_in minus value_out");
        assert!(pool.contains_txid(&result.checks.txid));
        assert_eq!(pool.len(), 1);
    }

    /// The fee must come from the prevouts, not from anything the transaction
    /// carries. Changing only the prevout's value must move the reported fee.
    #[test]
    fn fee_tracks_the_prevout_value() {
        let tx = spending_tx(&[outpoint(1, 0)], 90_000, 7);
        let fee_for = |input_value: u64| {
            let mut pool = pool();
            let chain = chain_with(&[(outpoint(1, 0), input_value)]);
            accept_to_mempool(&mut pool, tx.clone(), &chain, &context())
                .map(|result| result.checks.fee)
        };

        assert_eq!(fee_for(100_000), Ok(10_000));
        assert_eq!(fee_for(95_000), Ok(5_000));
    }

    #[test]
    fn reports_the_outpoints_it_could_not_resolve() {
        let mut pool = pool();
        let chain = chain_with(&[]);
        let tx = spending_tx(&[outpoint(9, 0)], 90_000, 7);

        let outcome = accept_to_mempool(&mut pool, tx, &chain, &context());

        assert_eq!(
            outcome,
            Err(AcceptError::MissingInputs(vec![outpoint(9, 0)])),
            "the unresolved outpoint must be named so the caller can orphan it"
        );
        assert!(pool.is_empty(), "a rejected transaction must not be stored");
    }

    /// The layered view: a child spending an unconfirmed parent resolves
    /// against the pool. Without the mempool layer this is `MissingInputs`.
    #[test]
    fn accepts_a_child_spending_an_unconfirmed_parent() {
        let mut pool = pool();
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        // The parent pays to a script the child can spend with an empty
        // scriptSig, which is not a standard output — so standardness is off
        // for this pair. What is under test is prevout resolution against the
        // pool; a signing fixture would prove the same thing more slowly.
        let relaxed = AcceptContext {
            require_standard: false,
            ..context()
        };
        let mut parent = spending_tx(&[outpoint(1, 0)], 90_000, 7);
        parent.outputs[0].script_pubkey = anyone_can_spend();
        let parent_txid = parent.txid();
        let Ok(_parent) = accept_to_mempool(&mut pool, parent, &chain, &relaxed) else {
            panic!("parent must be accepted or the child case is untested");
        };

        let child = spending_tx(&[OutPoint::new(parent_txid, 0)], 80_000, 8);
        let Ok(result) = accept_to_mempool(&mut pool, child, &chain, &relaxed) else {
            panic!("a child spending an unconfirmed parent must resolve against the pool");
        };

        assert_eq!(
            result.checks.fee, 10_000,
            "the child's fee comes from its parent's unconfirmed output"
        );
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn rejects_a_transaction_already_in_the_pool() {
        let mut pool = pool();
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        let tx = spending_tx(&[outpoint(1, 0)], 90_000, 7);
        let Ok(_first) = accept_to_mempool(&mut pool, tx.clone(), &chain, &context()) else {
            panic!("the first acceptance must succeed");
        };

        assert_eq!(
            accept_to_mempool(&mut pool, tx, &chain, &context()),
            Err(AcceptError::AlreadyInPool)
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn rejects_a_coinbase() {
        let mut pool = pool();
        let chain = chain_with(&[]);
        let mut tx = spending_tx(&[OutPoint::new(Txid::default(), u32::MAX)], 90_000, 7);
        tx.inputs[0].script_sig = push_int(800_001);
        assert!(is_coinbase(&tx), "the fixture must be a coinbase");

        assert_eq!(
            accept_to_mempool(&mut pool, tx, &chain, &context()),
            Err(AcceptError::Coinbase)
        );
    }

    /// Standardness must be a gate the caller controls, and the fixture must
    /// be consensus-valid so that toggling the flag is the only difference.
    #[test]
    fn standardness_is_enforced_only_when_required() {
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        let mut tx = spending_tx(&[outpoint(1, 0)], 90_000, 7);
        // Version 4 is consensus-valid and non-standard.
        tx.version = 4;

        let mut strict = pool();
        assert_eq!(
            accept_to_mempool(&mut strict, tx.clone(), &chain, &context()),
            Err(AcceptError::Standardness(StandardnessError::Version))
        );

        let mut permissive = pool();
        let relaxed = AcceptContext {
            require_standard: false,
            ..context()
        };
        assert!(
            accept_to_mempool(&mut permissive, tx, &chain, &relaxed).is_ok(),
            "the same transaction must be accepted once standardness is off"
        );
    }

    #[test]
    fn rejects_a_transaction_below_the_min_relay_fee() {
        let mut pool = pool();
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        // One satoshi of fee on a ~110 vbyte transaction is far below 1 sat/vB.
        let tx = spending_tx(&[outpoint(1, 0)], 99_999, 7);

        let outcome = accept_to_mempool(&mut pool, tx, &chain, &context());

        assert!(
            matches!(outcome, Err(AcceptError::Mempool(_))),
            "expected a policy rejection, got {outcome:?}"
        );
        assert!(pool.is_empty());
    }

    /// `testmempoolaccept`'s contract: the verdict without the side effect.
    #[test]
    fn check_acceptance_leaves_the_pool_untouched() {
        let mut pool = pool();
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        let tx = Arc::new(spending_tx(&[outpoint(1, 0)], 90_000, 7));

        let Ok(checks) = check_acceptance(&pool, &tx, &chain, &context()) else {
            panic!("the transaction must pass its checks");
        };

        assert_eq!(checks.fee, 10_000);
        assert!(pool.is_empty(), "checking must not insert");
        // The same transaction still accepts afterwards, so the check did not
        // consume anything either.
        let tx = Arc::unwrap_or_clone(tx);
        assert!(accept_to_mempool(&mut pool, tx, &chain, &context()).is_ok());
    }

    #[test]
    fn a_replacement_reports_the_transaction_it_evicted() {
        let mut pool = pool();
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        let mut original = spending_tx(&[outpoint(1, 0)], 90_000, 7);
        original.inputs[0].sequence = 0xffff_fffd;
        let original_txid = original.txid();
        let Ok(_first) = accept_to_mempool(&mut pool, original, &chain, &context()) else {
            panic!("the original must be accepted");
        };

        // Same input, higher fee, different output so it is a distinct txid.
        let mut replacement = spending_tx(&[outpoint(1, 0)], 50_000, 8);
        replacement.inputs[0].sequence = 0xffff_fffd;
        let Ok(result) = accept_to_mempool(&mut pool, replacement, &chain, &context()) else {
            panic!("a higher-feerate replacement must be accepted");
        };

        assert_eq!(
            result.checks.replaced,
            vec![original_txid],
            "the evicted transaction must be named"
        );
        assert!(!pool.contains_txid(&original_txid));
        assert_eq!(pool.len(), 1);
    }

    /// The sigop cost must reach the stored entry, not just the return value.
    ///
    /// A single P2PKH output carries one legacy sigop, scaled by four. Pinning
    /// the number keeps a mutation that reports zero — or that drops the field
    /// on the way into the pool — from passing.
    #[test]
    fn the_sigop_cost_is_carried_onto_the_stored_entry() {
        let mut pool = pool();
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        let tx = spending_tx(&[outpoint(1, 0)], 90_000, 7);

        let Ok(result) = accept_to_mempool(&mut pool, tx, &chain, &context()) else {
            panic!("the transaction must be accepted");
        };

        assert_eq!(
            result.checks.sigop_cost, 4,
            "one P2PKH output is one legacy sigop, scaled by four"
        );
        assert_eq!(
            pool.entry(result.id).map(|entry| entry.sigop_cost),
            Some(4),
            "the count must be carried onto the entry, not only reported"
        );
    }

    /// The sigop cost must be counted against the resolved prevouts.
    ///
    /// This is the whole reason the count lives at acceptance. Each input here
    /// spends a **P2SH** output whose redeem script is a bare
    /// `OP_CHECKMULTISIG`, worth twenty sigops — and that contribution is
    /// invisible to anyone holding only the transaction, because it is
    /// attributed by way of the spent `scriptPubKey`.
    ///
    /// The assertion is the policy limit rather than the number: with the
    /// prevouts consulted the transaction is over `MAX_STANDARD_TX_SIGOPS_COST`
    /// and is rejected; counting blind gives four, which is nowhere near the
    /// limit. So a mutation that stops consulting the prevouts turns a
    /// rejection into an acceptance, and the test cannot pass by accident.
    ///
    /// Testing it this way also keeps the fixture off the script interpreter:
    /// the rejection lands before verification, so no input needs a signature
    /// and the test runs on both script backends.
    #[test]
    fn sigop_cost_is_counted_against_the_resolved_prevouts() {
        // Twenty sigops: `GetSigOpCount` charges the maximum for a
        // `CHECKMULTISIG` that is not preceded by a literal key count.
        let redeem = vec![opcode::OP_CHECKMULTISIG];
        let script_sig = push_data(&redeem);

        // P2SH scriptPubKey: OP_HASH160 <20 bytes> OP_EQUAL.
        // The hash need not be the actual HASH160 of the redeem script —
        // `is_p2sh` only checks the 23-byte shape, and the sigop counter
        // reads the redeem script from the scriptSig, not from this hash.
        let script_pubkey = p2sh_script_pubkey(&[0x42; 20]);

        // 200 inputs * 20 sigops * 4 = 16 000, one past the limit once the
        // output's own legacy sigop is scaled in.
        let inputs = (0..200_u32)
            .map(|vout| outpoint(3, vout))
            .collect::<Vec<_>>();
        let chain = ChainView(
            inputs
                .iter()
                .map(|outpoint| {
                    (
                        outpoint_key(outpoint),
                        TxOut {
                            value: 1_000,
                            script_pubkey: script_pubkey.clone(),
                        },
                    )
                })
                .collect(),
        );

        let mut tx = spending_tx(&inputs, 190_000, 7);
        for input in &mut tx.inputs {
            input.script_sig = script_sig.clone();
        }

        let blind = count_tx_legacy(&tx).saturating_mul(4);
        assert!(
            blind <= MAX_STANDARD_TX_SIGOPS_COST,
            "counting blind must stay under the limit ({blind}), or the \
             rejection would not prove the prevouts were read"
        );

        let mut pool = pool();
        let outcome = accept_to_mempool(&mut pool, tx, &chain, &context());

        assert!(
            matches!(outcome, Err(AcceptError::TooManySigops { .. })),
            "expected a sigop-limit rejection derived from the prevouts, got {outcome:?}"
        );
        assert!(pool.is_empty());
    }
}
