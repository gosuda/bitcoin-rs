//! Mempool acceptance, the verdict Bitcoin Core calls `AcceptToMemoryPool`.
//!
//! One function decides whether a transaction may enter the pool:
//! [`evaluate_package_acceptance`] (and its report-every-row twin
//! [`evaluate_package_acceptance_all`]). `sendrawtransaction`,
//! `testmempoolaccept`, and peer ingress all read the same verdict, so the
//! two RPC outlets cannot disagree and no ingress path can skip a rule the
//! others enforce. The verdict is computed against the live pool without
//! mutating it; the gateway commits it under its write lock.
//!
//! The order follows Core's `MemPoolAccept::PreChecks` and
//! `PolicyScriptChecks`: cheap non-contextual rejections first, then
//! standardness, then prevout resolution, then the non-script consensus
//! rules, then the policy checks that need to see the rest of the pool, and
//! script verification last so a transaction every cheaper rule refuses never
//! pays for signature checks.
//!
//! Everything the verdict needs about the spent outputs it derives here from
//! the resolved prevouts — fee, sigop cost, missing inputs — rather than
//! trusting a caller's arithmetic. P2SH and witness sigops are attributed
//! through the spent `scriptPubKey` and are invisible to anyone holding only
//! the transaction, so the place that resolved the prevouts is the only place
//! that can count them. Core stores `sigOpCost` on the entry at acceptance
//! for the same reason, and `MempoolEntry::sigop_cost` is the same decision.

use alloc::sync::Arc;
use alloc::vec::Vec;

use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_consensus::{ConsensusError, verify_transaction, verify_transaction_non_script};
use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, Txid, Wtxid};
use bitcoin_rs_script::VerifyFlags;
use bitcoin_rs_script::script::{Instruction, instructions, is_p2sh, is_witness_program, opcode};
use bitcoin_rs_script::sigops::{count_segwit, count_tx_legacy};
use hashbrown::{HashMap, HashSet};
use thiserror::Error;

use crate::rbf::ReplacementCandidate;
use crate::standardness::{StandardnessError, is_standard_tx};
use crate::{EntryId, Mempool, PolicyError, RbfError};

/// Bitcoin Core `MAX_PACKAGE_COUNT` for package acceptance / `testmempoolaccept`.
pub const MAX_PACKAGE_COUNT: usize = 25;

/// Relay limit on one transaction's sigop cost.
///
/// Bitcoin Core's `MAX_STANDARD_TX_SIGOPS_COST`, a fifth of the block limit:
/// a single transaction may not consume more than one fifth of a block's
/// sigop budget.
pub const MAX_STANDARD_TX_SIGOPS_COST: u32 = 16_000;

/// Caller-captured facts for one acceptance evaluation.
///
/// The chain position is read once by the caller so every transaction in a
/// package — and the commit that follows a preview — is judged against the
/// same tip.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AcceptanceContext {
    /// Applied tip height. Finality is evaluated at `height + 1`, Core's
    /// `CheckFinalTxAtTip`: a transaction entering the mempool is a
    /// candidate for the block being built, not for one already mined.
    pub height: u32,
    /// Timestamp `nLockTime` is compared against: the tip's median time past
    /// after BIP113. Zero disables the cutoff (pre-genesis).
    pub locktime_cutoff: u32,
    /// Submitter's fee-rate ceiling in sat/kvB; `None` means no ceiling.
    ///
    /// Bitcoin Core derives it from `sendrawtransaction`'s `maxfeerate` and
    /// checks it only on an admission-valid result, so a transaction every
    /// other rule refuses quotes that refusal, not the ceiling.
    pub max_feerate_sat_per_kvb: Option<u64>,
}

/// Per-transaction acceptance fact for RPC / admission consumers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxAcceptanceFact {
    /// Transaction id.
    pub txid: Txid,
    /// Witness transaction id.
    pub wtxid: Wtxid,
    /// Whether the transaction was accepted or rejected. `None` means package
    /// evaluation stopped before this row was validated.
    pub allowed: Option<bool>,
    /// Policy virtual size in vbytes.
    pub vsize: u32,
    /// Consensus weight.
    pub weight: u64,
    /// BIP141 sigop cost against the resolved prevouts; zero until they are.
    pub sigop_cost: u32,
    /// Fee derived from the resolved prevouts, once they resolved and the
    /// inputs cover the outputs.
    pub base_fee: Option<u64>,
    /// Rejection reason when `allowed` is false.
    pub reject_reason: Option<AcceptanceRejectReason>,
}

/// Package-level acceptance facts: optional package error plus per-tx rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageAcceptanceFacts {
    /// Package-wide failure (for example package count bounds).
    pub package_error: Option<AcceptanceRejectReason>,
    /// One row per submitted transaction, in input order.
    pub results: Vec<TxAcceptanceFact>,
}

/// Why a transaction was not accepted.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AcceptanceRejectReason {
    /// Package length is outside `1..=MAX_PACKAGE_COUNT`.
    #[error("package-too-large")]
    PackageTooLarge,
    /// Transaction is already present in the mempool.
    #[error("txn-already-in-mempool")]
    AlreadyInMempool,
    /// One or more inputs were resolved by neither the chain, the mempool,
    /// nor an earlier package transaction. Core reports
    /// `bad-txns-inputs-missingorspent` and cannot distinguish "never
    /// existed" from "already spent" either.
    #[error("missing-inputs")]
    MissingInputs,
    /// Fee rate is below the live min-relay / mempool-min floor.
    #[error("min relay fee not met")]
    MinRelayFeeNotMet,
    /// Fee rate exceeds the caller-supplied maximum.
    #[error("max-fee-exceeded")]
    MaxFeeExceeded,
    /// Transaction fails standardness policy.
    #[error(transparent)]
    NonStandard(#[from] StandardnessError),
    /// Sigop cost exceeds what relay policy allows for a single transaction.
    #[error("bad-txns-too-many-sigops")]
    TooManySigops,
    /// The transaction failed a consensus rule — finality, duplicate inputs,
    /// value balance — or its input scripts under Core's policy flags
    /// (`STANDARD_SCRIPT_VERIFY_FLAGS`, validation.cpp `PolicyScriptChecks`).
    /// A transaction rejected here may still be valid in a block someone
    /// else mines.
    #[error(transparent)]
    Consensus(#[from] ConsensusError),
    /// Conflicting replacement fails BIP125.
    #[error(transparent)]
    Replacement(#[from] RbfError),
    /// Transaction exceeds ancestor or descendant package limits.
    #[error(transparent)]
    PackageLimit(#[from] PolicyError),
    /// Next-block BIP68 relative sequence locks are unmet.
    #[error("non-BIP68-final")]
    NonBip68Final,
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

/// Outputs of the package transactions evaluated so far, layered over the
/// mempool view, so a child later in the package resolves its parent.
struct PackageUtxoView<'a, V> {
    earlier: HashMap<OutPoint, TxOut>,
    inner: MempoolUtxoView<'a, V>,
}

impl<V> PackageUtxoView<'_, V> {
    fn add_outputs(&mut self, tx: &Tx) {
        let txid = tx.txid();
        for (vout, output) in tx.outputs.iter().enumerate() {
            let Ok(vout) = u32::try_from(vout) else {
                break;
            };
            self.earlier
                .insert(OutPoint::new(txid, vout), output.clone());
        }
    }
}

impl<V> UtxoView for PackageUtxoView<'_, V>
where
    V: UtxoView,
{
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.earlier
            .get(outpoint)
            .cloned()
            .or_else(|| self.inner.lookup(outpoint))
    }
}

/// Evaluates a package against the live pool, stopping after the first
/// rejected row; later rows report `allowed: None`.
///
/// `chain` supplies confirmed outputs; the pool's unconfirmed outputs and the
/// outputs of earlier package transactions are layered over it. Nothing is
/// inserted.
#[must_use]
pub fn evaluate_package_acceptance<V>(
    pool: &Mempool,
    chain: &V,
    context: AcceptanceContext,
    txs: &[Tx],
) -> PackageAcceptanceFacts
where
    V: UtxoView,
{
    evaluate_package(pool, chain, context, txs, true)
}

/// Evaluates every row of a package independently, without stopping after
/// a rejection.
///
/// This is the `testmempoolaccept` form: it reports every row's acceptance
/// status, including rows after an earlier rejected row.
#[must_use]
pub fn evaluate_package_acceptance_all<V>(
    pool: &Mempool,
    chain: &V,
    context: AcceptanceContext,
    txs: &[Tx],
) -> PackageAcceptanceFacts
where
    V: UtxoView,
{
    evaluate_package(pool, chain, context, txs, false)
}

fn evaluate_package<V>(
    pool: &Mempool,
    chain: &V,
    context: AcceptanceContext,
    txs: &[Tx],
    stop_after_rejection: bool,
) -> PackageAcceptanceFacts
where
    V: UtxoView,
{
    if txs.is_empty() || txs.len() > MAX_PACKAGE_COUNT {
        return PackageAcceptanceFacts {
            package_error: Some(AcceptanceRejectReason::PackageTooLarge),
            results: Vec::new(),
        };
    }

    let mut view = PackageUtxoView {
        earlier: HashMap::new(),
        inner: MempoolUtxoView::new(pool, chain),
    };
    let mut results = Vec::with_capacity(txs.len());
    let mut package_failed = false;

    for tx in txs {
        if package_failed {
            let mut fact = unresolved_fact(tx);
            fact.allowed = None;
            results.push(fact);
            continue;
        }
        let fact = evaluate_one(pool, &view, context, tx);
        if stop_after_rejection && fact.allowed == Some(false) {
            package_failed = true;
        }
        view.add_outputs(tx);
        results.push(fact);
    }

    PackageAcceptanceFacts {
        package_error: None,
        results,
    }
}

/// The verdict for one transaction against `pool`, with `view` supplying
/// every spendable output: chain, unconfirmed pool outputs, and — inside a
/// package — earlier package transactions.
///
/// The gateway runs this under its write lock immediately before committing
/// the same transaction, so the facts it reports (fee, vsize, sigop cost) are
/// the facts the entry stores.
pub(crate) fn evaluate_one<V>(
    pool: &Mempool,
    view: &V,
    context: AcceptanceContext,
    tx: &Tx,
) -> TxAcceptanceFact
where
    V: UtxoView,
{
    let mut fact = unresolved_fact(tx);
    match check_one(pool, view, context, tx, &mut fact) {
        Ok(()) => fact.allowed = Some(true),
        Err(reason) => fact.reject_reason = Some(reason),
    }
    fact
}

/// The fact for a transaction whose prevouts have not been consulted: the
/// shape is known, the fee and sigop cost are not.
fn unresolved_fact(tx: &Tx) -> TxAcceptanceFact {
    TxAcceptanceFact {
        txid: tx.txid(),
        wtxid: tx.wtxid(),
        allowed: Some(false),
        vsize: u32::try_from(tx.vsize()).unwrap_or(u32::MAX),
        weight: tx.weight(),
        sigop_cost: 0,
        base_fee: None,
        reject_reason: None,
    }
}

fn check_one<V>(
    pool: &Mempool,
    view: &V,
    context: AcceptanceContext,
    tx: &Tx,
    fact: &mut TxAcceptanceFact,
) -> Result<(), AcceptanceRejectReason>
where
    V: UtxoView,
{
    if pool.contains_txid(&fact.txid) {
        return Err(AcceptanceRejectReason::AlreadyInMempool);
    }
    // A coinbase can only arrive inside a block; its null prevout resolves
    // nowhere, which is the same answer Core gives (`coinbase`).
    if is_coinbase(tx) {
        return Err(AcceptanceRejectReason::MissingInputs);
    }

    let mut prevouts = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        let Some(prevout) = view.lookup(&input.previous_output) else {
            return Err(AcceptanceRejectReason::MissingInputs);
        };
        prevouts.push((input.previous_output, prevout));
    }

    let policy = pool.policy_snapshot();
    is_standard_tx(tx, &policy.standardness)?;

    // Finality is evaluated at the height of the next block the transaction
    // could be mined in. A tip at `u32::MAX` is not a reachable chain state;
    // saturating keeps the arithmetic total without inventing a reject class.
    let finality_height = context.height.saturating_add(1);
    verify_transaction_non_script(tx, view, finality_height, context.locktime_cutoff)?;

    // The non-script pass rejected value overflow and `value_in <
    // value_out`, so the plain arithmetic below cannot wrap or underflow.
    let value_in = prevouts
        .iter()
        .fold(0_u64, |sum, (_, prevout)| sum.saturating_add(prevout.value));
    let value_out = tx
        .outputs
        .iter()
        .fold(0_u64, |sum, output| sum.saturating_add(output.value));
    let fee = value_in.saturating_sub(value_out);
    fact.base_fee = Some(fee);

    let fee_rate = if fact.vsize == 0 {
        0
    } else {
        fee.saturating_mul(1_000) / u64::from(fact.vsize)
    };
    let mempool_min_fee = crate::eviction::mempool_min_fee_sat_per_kvb(
        pool,
        policy.incremental_relay_fee_sat_per_kvb,
    );
    if fee_rate < mempool_min_fee {
        return Err(AcceptanceRejectReason::MinRelayFeeNotMet);
    }

    // Counted before script verification, for the same reason Core counts
    // it in `PreChecks` rather than in `PolicyScriptChecks`: the sigop limit
    // is a cheap rejection and there is no sense running scripts for a
    // transaction that cannot be relayed anyway.
    let sigop_cost = u32::try_from(total_sigop_cost(tx, &prevouts)).unwrap_or(u32::MAX);
    fact.sigop_cost = sigop_cost;
    if sigop_cost > MAX_STANDARD_TX_SIGOPS_COST {
        return Err(AcceptanceRejectReason::TooManySigops);
    }

    let candidate = ReplacementCandidate::new(
        Arc::new(tx.clone()),
        fact.vsize,
        fee,
        policy.incremental_relay_fee_sat_per_kvb,
    );
    let plan = pool.check_replacement(&candidate)?;
    let excluded: HashSet<EntryId> = plan.evicted.iter().copied().collect();
    pool.check_package_limits(tx, fact.vsize, &excluded)?;

    // Scripts last, under relay flags: Core runs policy flags in the
    // mempool and consensus flags in a block, so a transaction rejected here
    // may still be valid in a block someone else mines.
    verify_transaction(
        tx,
        view,
        finality_height,
        context.locktime_cutoff,
        VerifyFlags::STANDARD,
    )?;

    // Checked only on an admission-valid result, as Core's
    // `BroadcastTransaction` does: the ceiling is the submitter's guard
    // against a fee mistake, not a reason a broken transaction is broken.
    if context
        .max_feerate_sat_per_kvb
        .is_some_and(|max| fee_rate > max)
    {
        return Err(AcceptanceRejectReason::MaxFeeExceeded);
    }

    Ok(())
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
    for (input, (_, prevout)) in tx.inputs.iter().zip(prevouts) {
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
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{MempoolEntry, MempoolLimits};
    use alloc::vec;
    use bitcoin_rs_primitives::{Hash256, TxIn};
    use bitcoin_rs_script::script::{push_data, push_int};
    use sha2::{Digest as _, Sha256};

    /// Confirmed outputs keyed by outpoint.
    struct ChainView(HashMap<OutPoint, TxOut>);

    impl UtxoView for ChainView {
        fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
            self.0.get(outpoint).cloned()
        }
    }

    /// `OP_TRUE`: a prevout anyone can spend with an empty scriptSig.
    ///
    /// Keeps these tests about acceptance. Producing real signatures would
    /// turn every fixture into a signing exercise, and a prevout's own
    /// script is not what standardness looks at.
    fn anyone_can_spend() -> Vec<u8> {
        vec![0x51]
    }

    /// P2WSH wrapping `OP_TRUE`: a standard output template that a one-item
    /// witness spends, for fixtures whose outputs must themselves be spent.
    fn p2wsh_op_true() -> Vec<u8> {
        let mut out = vec![0x00, 0x20];
        out.extend_from_slice(&Sha256::digest([0x51_u8]));
        out
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

    fn p2wpkh(tag: u8) -> Vec<u8> {
        let mut out = vec![0x00, 0x14];
        out.extend_from_slice(&[tag; 20]);
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
        chain_paying(entries, &anyone_can_spend())
    }

    fn chain_paying(entries: &[(OutPoint, u64)], script_pubkey: &[u8]) -> ChainView {
        ChainView(
            entries
                .iter()
                .map(|(outpoint, value)| {
                    (
                        *outpoint,
                        TxOut {
                            value: *value,
                            script_pubkey: script_pubkey.to_vec(),
                        },
                    )
                })
                .collect(),
        )
    }

    fn context() -> AcceptanceContext {
        AcceptanceContext {
            height: 800_000,
            locktime_cutoff: 1_700_000_000,
            max_feerate_sat_per_kvb: None,
        }
    }

    fn pool() -> Mempool {
        Mempool::new(MempoolLimits::default())
    }

    fn verdict(pool: &Mempool, chain: &ChainView, tx: &Tx) -> TxAcceptanceFact {
        verdict_with(pool, chain, context(), tx)
    }

    fn verdict_with(
        pool: &Mempool,
        chain: &ChainView,
        context: AcceptanceContext,
        tx: &Tx,
    ) -> TxAcceptanceFact {
        evaluate_package_acceptance(pool, chain, context, core::slice::from_ref(tx))
            .results
            .pop()
            .expect("one row per submitted transaction")
    }

    #[test]
    fn accepts_a_standard_transaction_and_derives_its_fee_from_the_prevouts() {
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        let tx = spending_tx(&[outpoint(1, 0)], 90_000, 7);

        let fact = verdict(&pool(), &chain, &tx);

        assert_eq!(fact.reject_reason, None);
        assert_eq!(fact.allowed, Some(true));
        assert_eq!(
            fact.base_fee,
            Some(10_000),
            "fee is value_in minus value_out"
        );
        assert_eq!(fact.vsize, u32::try_from(tx.vsize()).expect("fits"));
        assert_eq!(fact.txid, tx.txid());
        assert_eq!(fact.wtxid, tx.wtxid());
    }

    /// The fee must come from the prevouts, not from anything the transaction
    /// carries. Changing only the prevout's value must move the reported fee.
    #[test]
    fn fee_tracks_the_prevout_value() {
        let tx = spending_tx(&[outpoint(1, 0)], 90_000, 7);
        let fee_for = |input_value: u64| {
            let chain = chain_with(&[(outpoint(1, 0), input_value)]);
            verdict(&pool(), &chain, &tx).base_fee
        };

        assert_eq!(fee_for(100_000), Some(10_000));
        assert_eq!(fee_for(95_000), Some(5_000));
    }

    #[test]
    fn reports_missing_inputs_without_a_fee() {
        let chain = chain_with(&[]);
        let tx = spending_tx(&[outpoint(9, 0)], 90_000, 7);

        let fact = verdict(&pool(), &chain, &tx);

        assert_eq!(
            fact.reject_reason,
            Some(AcceptanceRejectReason::MissingInputs)
        );
        assert_eq!(fact.base_fee, None, "no prevouts, no fee to report");
    }

    /// The layered view: a child spending an unconfirmed parent resolves
    /// against the pool. Without the mempool layer this is `MissingInputs`.
    #[test]
    fn accepts_a_child_spending_an_unconfirmed_parent() {
        let mut pool = pool();
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        let mut parent = spending_tx(&[outpoint(1, 0)], 90_000, 7);
        parent.outputs[0].script_pubkey = p2wsh_op_true();
        let parent_txid = parent.txid();
        let parent_fact = verdict(&pool, &chain, &parent);
        assert_eq!(
            parent_fact.reject_reason, None,
            "the parent must be acceptable"
        );
        pool.insert_entry(MempoolEntry::new(
            Arc::new(parent),
            parent_fact.vsize,
            parent_fact.base_fee.expect("accepted rows carry a fee"),
            1,
            1,
        ))
        .expect("insert parent");

        let mut child = spending_tx(&[OutPoint::new(parent_txid, 0)], 80_000, 8);
        child.inputs[0].witness = vec![vec![0x51]];
        let fact = verdict(&pool, &chain, &child);

        assert_eq!(fact.reject_reason, None);
        assert_eq!(
            fact.base_fee,
            Some(10_000),
            "the child's fee comes from its parent's unconfirmed output"
        );
    }

    /// Inside a package the same layering reaches earlier rows, and it
    /// carries the real script: a child of a package parent is script
    /// verified against the parent's output, not a value-only placeholder.
    #[test]
    fn a_package_child_resolves_and_verifies_against_an_earlier_row() {
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        let mut parent = spending_tx(&[outpoint(1, 0)], 90_000, 7);
        parent.outputs[0].script_pubkey = p2wsh_op_true();
        let mut child = spending_tx(&[OutPoint::new(parent.txid(), 0)], 80_000, 8);
        child.inputs[0].witness = vec![vec![0x51]];
        let mut unsigned_child = child.clone();
        unsigned_child.inputs[0].witness = Vec::new();

        let facts = evaluate_package_acceptance_all(
            &pool(),
            &chain,
            context(),
            &[parent, child, unsigned_child],
        );

        assert_eq!(facts.results[0].reject_reason, None);
        assert_eq!(facts.results[1].reject_reason, None);
        assert_eq!(facts.results[1].base_fee, Some(10_000));
        assert!(
            matches!(
                facts.results[2].reject_reason,
                Some(AcceptanceRejectReason::Consensus(
                    ConsensusError::Script { .. }
                ))
            ),
            "an unsigned spend of a package parent must fail script verification, got {:?}",
            facts.results[2].reject_reason
        );
    }

    #[test]
    fn rejects_a_transaction_already_in_the_pool() {
        let mut pool = pool();
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        let tx = spending_tx(&[outpoint(1, 0)], 90_000, 7);
        pool.insert_entry(MempoolEntry::new(Arc::new(tx.clone()), 100, 10_000, 1, 1))
            .expect("insert");

        assert_eq!(
            verdict(&pool, &chain, &tx).reject_reason,
            Some(AcceptanceRejectReason::AlreadyInMempool)
        );
    }

    #[test]
    fn rejects_a_coinbase_as_missing_inputs() {
        let chain = chain_with(&[]);
        let mut tx = spending_tx(&[OutPoint::new(Txid::default(), u32::MAX)], 90_000, 7);
        tx.inputs[0].script_sig = push_int(800_001);
        assert!(is_coinbase(&tx), "the fixture must be a coinbase");

        assert_eq!(
            verdict(&pool(), &chain, &tx).reject_reason,
            Some(AcceptanceRejectReason::MissingInputs)
        );
    }

    /// The fixture is consensus-valid, so the version is the only thing
    /// standardness can object to.
    #[test]
    fn rejects_a_non_standard_version() {
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        let mut tx = spending_tx(&[outpoint(1, 0)], 90_000, 7);
        tx.version = 4;

        assert_eq!(
            verdict(&pool(), &chain, &tx).reject_reason,
            Some(AcceptanceRejectReason::NonStandard(
                StandardnessError::Version
            ))
        );
    }

    #[test]
    fn rejects_a_transaction_below_the_min_relay_fee() {
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        // One satoshi of fee on a ~110 vbyte transaction is far below 1 sat/vB.
        let tx = spending_tx(&[outpoint(1, 0)], 99_999, 7);

        let fact = verdict(&pool(), &chain, &tx);

        assert_eq!(
            fact.reject_reason,
            Some(AcceptanceRejectReason::MinRelayFeeNotMet)
        );
        assert_eq!(
            fact.base_fee,
            Some(1),
            "the fee is known when the floor refuses it"
        );
    }

    /// The ceiling applies only to an otherwise-acceptable transaction, so a
    /// transaction that is both below the floor and above the ceiling quotes
    /// the floor, and one above the ceiling with a bad script quotes the
    /// script.
    #[test]
    fn max_feerate_is_checked_only_on_an_admission_valid_result() {
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        let tx = spending_tx(&[outpoint(1, 0)], 90_000, 7);
        let capped = AcceptanceContext {
            max_feerate_sat_per_kvb: Some(1_000),
            ..context()
        };

        assert_eq!(
            verdict_with(&pool(), &chain, capped, &tx).reject_reason,
            Some(AcceptanceRejectReason::MaxFeeExceeded)
        );

        let one_sat = spending_tx(&[outpoint(1, 0)], 99_999, 7);
        let capped_at_zero = AcceptanceContext {
            max_feerate_sat_per_kvb: Some(0),
            ..context()
        };
        assert_eq!(
            verdict_with(&pool(), &chain, capped_at_zero, &one_sat).reject_reason,
            Some(AcceptanceRejectReason::MinRelayFeeNotMet),
            "below the floor and above the ceiling quotes the floor"
        );
        let pool_at_zero_floor = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        assert_eq!(
            verdict_with(&pool_at_zero_floor, &chain, capped_at_zero, &one_sat).reject_reason,
            Some(AcceptanceRejectReason::MaxFeeExceeded),
            "with no floor the same transaction is admission-valid and only the ceiling refuses it"
        );

        let signed_prevout = chain_paying(&[(outpoint(1, 0), 100_000)], &p2wpkh(0x11));
        assert!(
            matches!(
                verdict_with(&pool(), &signed_prevout, capped, &tx).reject_reason,
                Some(AcceptanceRejectReason::Consensus(
                    ConsensusError::Script { .. }
                ))
            ),
            "a broken transaction quotes its defect, not the submitter's ceiling"
        );
    }

    /// The reported bug: an unsigned spend of a signature-guarded output
    /// must never be `allowed`, on any outlet that reads this verdict.
    #[test]
    fn rejects_a_spend_whose_input_script_does_not_verify() {
        let chain = chain_paying(&[(outpoint(1, 0), 100_000)], &p2wpkh(0x11));
        let tx = spending_tx(&[outpoint(1, 0)], 90_000, 7);

        let fact = verdict(&pool(), &chain, &tx);

        assert_eq!(fact.allowed, Some(false));
        assert!(
            matches!(
                fact.reject_reason,
                Some(AcceptanceRejectReason::Consensus(
                    ConsensusError::Script { .. }
                ))
            ),
            "expected a script rejection, got {:?}",
            fact.reject_reason
        );
    }

    #[test]
    fn rejects_a_non_final_locktime_and_accepts_one_final_at_the_next_height() {
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        let mut tx = spending_tx(&[outpoint(1, 0)], 90_000, 7);
        tx.inputs[0].sequence = 0xffff_fffe;
        // A height locktime is final once the block height exceeds it. The
        // transaction is a candidate for block `height + 1`, so a locktime of
        // `height + 1` is one past final while `height` is exactly final.
        tx.lock_time = context().height.saturating_add(1);

        let one_past = verdict(&pool(), &chain, &tx);
        assert!(
            matches!(
                one_past.reject_reason,
                Some(AcceptanceRejectReason::Consensus(
                    ConsensusError::Bip { .. }
                ))
            ),
            "locktime one past the next block is non-final, got {:?}",
            one_past.reject_reason
        );

        tx.lock_time = context().height;
        assert_eq!(verdict(&pool(), &chain, &tx).reject_reason, None);
    }

    #[test]
    fn rejects_duplicate_inputs_before_looking_at_the_fee() {
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        // Two spends of the same output would double-count the fee.
        let tx = spending_tx(&[outpoint(1, 0), outpoint(1, 0)], 150_000, 7);

        let fact = verdict(&pool(), &chain, &tx);

        assert!(
            matches!(
                fact.reject_reason,
                Some(AcceptanceRejectReason::Consensus(
                    ConsensusError::DuplicateInput { .. }
                ))
            ),
            "got {:?}",
            fact.reject_reason
        );
        assert_eq!(fact.base_fee, None);
    }

    /// The sigop cost must be counted against the resolved prevouts.
    ///
    /// Each input spends a **P2SH** output whose redeem script is a bare
    /// `OP_CHECKMULTISIG`, worth twenty sigops — a contribution invisible to
    /// anyone holding only the transaction, because it is attributed by way
    /// of the spent `scriptPubKey`. The assertion is the policy limit rather
    /// than the number: counting blind gives four, nowhere near the limit,
    /// so a mutation that stops consulting the prevouts turns this rejection
    /// into an acceptance. The rejection lands before script verification,
    /// so no input needs a signature and the test runs on both backends.
    #[test]
    fn sigop_cost_is_counted_against_the_resolved_prevouts() {
        // Twenty sigops: `GetSigOpCount` charges the maximum for a
        // `CHECKMULTISIG` that is not preceded by a literal key count.
        let redeem = vec![opcode::OP_CHECKMULTISIG];
        let script_sig = push_data(&redeem);
        // The hash need not be the actual HASH160 of the redeem script —
        // `is_p2sh` only checks the 23-byte shape, and the sigop counter
        // reads the redeem script from the scriptSig, not from this hash.
        let script_pubkey = p2sh_script_pubkey(&[0x42; 20]);

        // 200 inputs * 20 sigops * 4 = 16 000, one past the limit once the
        // output's own legacy sigop is scaled in.
        let inputs = (0..200_u32)
            .map(|vout| outpoint(3, vout))
            .collect::<Vec<_>>();
        let chain = chain_paying(
            &inputs.iter().map(|op| (*op, 1_000)).collect::<Vec<_>>(),
            &script_pubkey,
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

        let fact = verdict(&pool(), &chain, &tx);

        assert_eq!(
            fact.reject_reason,
            Some(AcceptanceRejectReason::TooManySigops)
        );
        assert!(fact.sigop_cost > MAX_STANDARD_TX_SIGOPS_COST);
    }

    #[test]
    fn a_single_p2pkh_output_costs_four_sigops() {
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        let tx = spending_tx(&[outpoint(1, 0)], 90_000, 7);

        assert_eq!(
            verdict(&pool(), &chain, &tx).sigop_cost,
            4,
            "one P2PKH output is one legacy sigop, scaled by four"
        );
    }

    #[test]
    fn package_acceptance_rejects_empty_and_oversized_packages() {
        let chain = chain_with(&[]);
        let empty = evaluate_package_acceptance(&pool(), &chain, context(), &[]);
        assert_eq!(
            empty.package_error,
            Some(AcceptanceRejectReason::PackageTooLarge)
        );

        let txs: Vec<Tx> = (0..=MAX_PACKAGE_COUNT)
            .map(|i| {
                let value = 90_000_u64.saturating_add(u64::try_from(i).expect("small index"));
                spending_tx(&[outpoint(1, 0)], value, 7)
            })
            .collect();
        let oversized = evaluate_package_acceptance(&pool(), &chain, context(), &txs);
        assert_eq!(
            oversized.package_error,
            Some(AcceptanceRejectReason::PackageTooLarge)
        );
        assert!(oversized.results.is_empty());
    }

    #[test]
    fn package_acceptance_stops_after_a_rejection_and_the_all_form_does_not() {
        let chain = chain_with(&[(outpoint(1, 0), 100_000)]);
        let missing = spending_tx(&[outpoint(9, 0)], 90_000, 7);
        let fine = spending_tx(&[outpoint(1, 0)], 90_000, 8);
        let package = [missing, fine.clone()];

        let stopped = evaluate_package_acceptance(&pool(), &chain, context(), &package);
        assert_eq!(
            stopped.results[0].reject_reason,
            Some(AcceptanceRejectReason::MissingInputs)
        );
        assert_eq!(stopped.results[1].allowed, None);
        assert_eq!(stopped.results[1].reject_reason, None);
        assert_eq!(stopped.results[1].base_fee, None);
        assert_eq!(stopped.results[1].txid, fine.txid());

        let all = evaluate_package_acceptance_all(&pool(), &chain, context(), &package);
        assert_eq!(
            all.results[1].allowed,
            Some(true),
            "evaluate-all must still evaluate the second row after the first rejects"
        );
    }
}
