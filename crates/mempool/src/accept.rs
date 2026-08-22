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

use bitcoin::{OutPoint, Transaction, TxOut, Txid};
use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_consensus::{ConsensusError, verify_transaction_borrowed_with_mtp};
use bitcoin_rs_script::VerifyFlags;
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
            return entry.tx.output.get(vout).cloned();
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
    tx: &Arc<Transaction>,
    chain: &V,
    ctx: &AcceptContext,
) -> Result<AcceptChecks, AcceptError>
where
    V: UtxoView,
{
    let txid = tx.compute_txid();
    if pool.contains_txid(&txid) {
        return Err(AcceptError::AlreadyInPool);
    }
    if tx.is_coinbase() {
        return Err(AcceptError::Coinbase);
    }
    if ctx.require_standard {
        is_standard_tx(tx, &ctx.standardness)?;
    }

    let view = MempoolUtxoView::new(pool, chain);

    let mut missing = Vec::new();
    let mut value_in = 0_u64;
    for input in &tx.input {
        match view.lookup(&input.previous_output) {
            Some(prevout) => {
                value_in = value_in
                    .checked_add(prevout.value.to_sat())
                    .ok_or(AcceptError::InputValueOverflow)?;
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
    let sigop_cost =
        u32::try_from(tx.total_sigop_cost(|outpoint| view.lookup(outpoint))).unwrap_or(u32::MAX);
    if sigop_cost > MAX_STANDARD_TX_SIGOPS_COST {
        return Err(AcceptError::TooManySigops {
            cost: sigop_cost,
            max: MAX_STANDARD_TX_SIGOPS_COST,
        });
    }

    // Full verification, scripts included, under relay flags. Core runs policy
    // flags in the mempool and consensus flags in a block, so a transaction
    // rejected here may still be valid in a block someone else mines.
    verify_transaction_borrowed_with_mtp(
        tx,
        &view,
        ctx.height,
        ctx.locktime_cutoff,
        VerifyFlags::STANDARD,
    )?;

    let mut value_out = 0_u64;
    for output in &tx.output {
        value_out = value_out
            .checked_add(output.value.to_sat())
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
        .filter_map(|id| pool.entry(*id).map(|entry| entry.tx.compute_txid()))
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
    tx: Transaction,
    chain: &V,
    ctx: &AcceptContext,
) -> Result<AcceptResult, AcceptError>
where
    V: UtxoView,
{
    let tx = Arc::new(tx);
    let checks = check_acceptance(pool, &tx, chain, ctx)?;
    let candidate = replacement_candidate(pool, &tx, checks.vsize, checks.fee, checks.sigop_cost);
    // `replace_transaction` re-runs `check_replacement` internally. Paying for
    // one extra walk of the conflict set keeps BIP125 eviction implemented in
    // exactly one place; inlining it here would be a second copy to drift.
    let id = pool
        .replace_transaction(candidate, ctx.time, ctx.height)
        .map_err(|error| match error {
            // `replace_transaction` reports every failure as an `RbfError`,
            // including the plain insertion limits, which have nothing to do
            // with replacement. Reporting "below min relay fee" as
            // "replacement rejected" would send the caller looking for a
            // conflict that never existed.
            RbfError::Mempool(mempool) => AcceptError::Mempool(mempool),
            rbf => AcceptError::Rbf(rbf),
        })?;
    Ok(AcceptResult { id, checks })
}

fn replacement_candidate(
    pool: &Mempool,
    tx: &Arc<Transaction>,
    vsize: u32,
    fee: u64,
    sigop_cost: u32,
) -> ReplacementCandidate {
    ReplacementCandidate::new(Arc::clone(tx), vsize, fee, pool.min_relay_fee_sat_per_kvb())
        .with_sigop_cost(sigop_cost)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MempoolLimits;
    use alloc::collections::BTreeMap;
    use alloc::vec;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash as _;
    use bitcoin::script::Builder;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, FeeRate, PubkeyHash, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness};

    /// A prevout script anyone can spend with an empty scriptSig.
    ///
    /// Keeps these tests about acceptance. Producing real signatures would
    /// turn every fixture into a signing exercise, and a prevout's own script
    /// is not what standardness looks at.
    fn anyone_can_spend() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x51])
    }

    fn p2pkh(tag: u8) -> ScriptBuf {
        ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([tag; 20]))
    }

    fn outpoint(tag: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid::from_byte_array([tag; 32]), vout)
    }

    /// Spends `inputs` and pays `output_value` to a standard P2PKH script.
    fn spending_tx(inputs: &[OutPoint], output_value: u64, tag: u8) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|previous_output| TxIn {
                    previous_output: *previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: p2pkh(tag),
            }],
        }
    }

    fn chain_with(entries: &[(OutPoint, u64)]) -> BTreeMap<OutPoint, TxOut> {
        entries
            .iter()
            .map(|(outpoint, value)| {
                (
                    *outpoint,
                    TxOut {
                        value: Amount::from_sat(*value),
                        script_pubkey: anyone_can_spend(),
                    },
                )
            })
            .collect()
    }

    fn context() -> AcceptContext {
        AcceptContext {
            height: 800_001,
            locktime_cutoff: 1_700_000_000,
            time: 42,
            standardness: StandardnessPolicy {
                dust_relay_fee: FeeRate::DUST,
                max_datacarrier_bytes: Some(83),
            },
            require_standard: true,
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
        parent.output[0].script_pubkey = anyone_can_spend();
        let parent_txid = parent.compute_txid();
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
        let mut tx = spending_tx(&[OutPoint::null()], 90_000, 7);
        tx.input[0].script_sig = Builder::new().push_int(800_001).into_script();
        assert!(tx.is_coinbase(), "the fixture must be a coinbase");

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
        tx.version = Version(4);

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
        original.input[0].sequence = Sequence::from_consensus(0xffff_fffd);
        let original_txid = original.compute_txid();
        let Ok(_first) = accept_to_mempool(&mut pool, original, &chain, &context()) else {
            panic!("the original must be accepted");
        };

        // Same input, higher fee, different output so it is a distinct txid.
        let mut replacement = spending_tx(&[outpoint(1, 0)], 50_000, 8);
        replacement.input[0].sequence = Sequence::from_consensus(0xffff_fffd);
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
        use bitcoin::opcodes::all::OP_CHECKMULTISIG;

        // Twenty sigops: `GetSigOpCount` charges the maximum for a
        // `CHECKMULTISIG` that is not preceded by a literal key count.
        let redeem = Builder::new().push_opcode(OP_CHECKMULTISIG).into_script();
        let Ok(redeem_push) = <&bitcoin::script::PushBytes>::try_from(redeem.as_bytes()) else {
            panic!("a one-byte redeem script must be pushable");
        };
        let script_sig = Builder::new().push_slice(redeem_push).into_script();
        let script_pubkey = ScriptBuf::new_p2sh(&redeem.script_hash());

        // 200 inputs * 20 sigops * 4 = 16 000, one past the limit once the
        // output's own legacy sigop is scaled in.
        let inputs = (0..200_u32)
            .map(|vout| outpoint(3, vout))
            .collect::<Vec<_>>();
        let chain = inputs
            .iter()
            .map(|outpoint| {
                (
                    *outpoint,
                    TxOut {
                        value: Amount::from_sat(1_000),
                        script_pubkey: script_pubkey.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        let mut tx = spending_tx(&inputs, 190_000, 7);
        for input in &mut tx.input {
            input.script_sig = script_sig.clone();
        }

        let blind = u32::try_from(tx.total_sigop_cost(|_outpoint| None)).unwrap_or(u32::MAX);
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
