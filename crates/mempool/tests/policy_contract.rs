//! Mempool policy compatibility contract: every policy row in
//! `docs/policies/mempool-policy.md` cites one fixture here (or in
//! `crates/rpc/tests/policy_contract.rs`). Each fixture asserts the
//! observable verdict on both admission surfaces — the mutating pool API and
//! the non-mutating acceptance-preview seam — and that the two agree.
//!
//! Contract clause: `docs/contracts/mempool-policy.md` `POL-01`.
#![deny(clippy::expect_used)]

extern crate alloc;

use alloc::sync::Arc;
use std::error::Error;

use bitcoin_rs_mempool::eviction::mempool_min_fee_sat_per_kvb;
use bitcoin_rs_mempool::standardness::{
    AcceptanceRejectReason, PackageTxContext, StandardnessError, StandardnessPolicy,
    evaluate_package_acceptance, is_standard_tx,
};
use bitcoin_rs_mempool::{
    Mempool, MempoolEntry, MempoolError, MempoolLimits, MutationOutcome, PolicyError, RbfError,
    RemovalReason, ReplacementCandidate,
};
use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut, Txid};
use bitcoin_rs_script::opcode;

/// Node default: Bitcoin Core incremental relay fee, 1000 sat/kvB.
const INCREMENTAL_RELAY_FEE_SAT_PER_KVB: u64 = 1_000;

/// Bitcoin Core default dust relay rate, sat/kvB.
const DUST_RELAY_FEE_SAT_PER_KVB: u64 = 3_000;

fn policy() -> StandardnessPolicy {
    StandardnessPolicy {
        dust_relay_fee: DUST_RELAY_FEE_SAT_PER_KVB,
        max_datacarrier_bytes: Some(83),
    }
}

/// `OP_0 <20 bytes>` — a P2WPKH witness program shape.
fn p2wpkh_script() -> Vec<u8> {
    let mut script = vec![opcode::OP_0, 0x14];
    script.extend([0x11_u8; 20]);
    script
}

/// `OP_TRUE` — no recognized standard output type.
fn op_true_script() -> Vec<u8> {
    vec![0x51]
}

fn outpoint(label: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid::from(Hash256::from_le_bytes(&[label; 32])), vout)
}

/// One-input, one-P2WPKH-output transaction. Distinct `output_value` values
/// keep txids distinct across fixtures.
fn tx(prevout: OutPoint, output_value: u64, sequence: u32) -> Tx {
    tx_multi(&[(prevout, sequence)], output_value, p2wpkh_script())
}

fn tx_multi(inputs: &[(OutPoint, u32)], output_value: u64, script_pubkey: Vec<u8>) -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: inputs
            .iter()
            .map(|(prevout, sequence)| TxIn {
                previous_output: *prevout,
                script_sig: Vec::new(),
                sequence: *sequence,
                witness: Vec::new(),
            })
            .collect(),
        outputs: vec![TxOut {
            value: output_value,
            script_pubkey,
        }],
    }
}

fn txid(tx: &Tx) -> Hash256 {
    Hash256::from_le_bytes(tx.txid().as_bytes())
}

fn entry(tx: Tx, vsize: u32, fee: u64) -> MempoolEntry {
    MempoolEntry::new(Arc::new(tx), vsize, fee, 0, 1)
}

fn context(fee: u64, vsize: u32) -> PackageTxContext {
    PackageTxContext {
        fee,
        vsize,
        sigop_cost: 0,
        missing_inputs: false,
    }
}

fn preview_reason(
    pool: &Mempool,
    tx: &Tx,
    ctx: PackageTxContext,
) -> Option<AcceptanceRejectReason> {
    evaluate_package_acceptance(
        pool,
        &policy(),
        std::slice::from_ref(tx),
        &[ctx],
        None,
        INCREMENTAL_RELAY_FEE_SAT_PER_KVB,
    )
    .results
    .into_iter()
    .next()
    .and_then(|fact| fact.reject_reason)
}

fn preview_allowed(pool: &Mempool, tx: &Tx, ctx: PackageTxContext) -> bool {
    evaluate_package_acceptance(
        pool,
        &policy(),
        std::slice::from_ref(tx),
        &[ctx],
        None,
        INCREMENTAL_RELAY_FEE_SAT_PER_KVB,
    )
    .results
    .first()
    .is_some_and(|fact| fact.allowed == Some(true))
}

// ---------------------------------------------------------------------------
// Min relay fee
// ---------------------------------------------------------------------------

#[test]
fn below_min_relay_fee_rejects_on_both_surfaces_at_the_same_floor() -> Result<(), Box<dyn Error>> {
    let mut pool = Mempool::new(MempoolLimits::default());
    // rate = fee * 1000 / vsize = 3999 * 1000 / 4000 = 999 sat/kvB.
    let low = tx(outpoint(1, 0), 1_000, 0xFF_FF_FF_FF);
    let err = pool
        .insert_entry(entry(low.clone(), 4_000, 3_999))
        .err()
        .ok_or("expected BelowMinRelayFee rejection")?;
    assert_eq!(
        err,
        MempoolError::Policy(PolicyError::BelowMinRelayFee {
            tx_rate: 999,
            min_rate: 1_000,
        })
    );
    assert_eq!(
        preview_reason(&pool, &low, context(3_999, 4_000)),
        Some(AcceptanceRejectReason::MinRelayFeeNotMet),
        "acceptance preview must quote the same floor"
    );

    // Boundary: exactly 1000 sat/kvB is admitted.
    let boundary = tx(outpoint(2, 0), 1_000, 0xFF_FF_FF_FF);
    pool.insert_entry(entry(boundary, 4_000, 4_000))?;
    assert_eq!(pool.len(), 1);
    Ok(())
}

#[test]
fn configured_min_relay_floor_overrides_the_default() -> Result<(), Box<dyn Error>> {
    let limits = MempoolLimits {
        min_relay_fee_sat_per_kvb: 5_000,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);
    let low = tx(outpoint(1, 0), 1_000, 0xFF_FF_FF_FF);
    let err = pool
        .insert_entry(entry(low.clone(), 4_000, 8_000))
        .err()
        .ok_or("expected BelowMinRelayFee rejection")?;
    assert_eq!(
        err,
        MempoolError::Policy(PolicyError::BelowMinRelayFee {
            tx_rate: 2_000,
            min_rate: 5_000,
        })
    );
    assert_eq!(
        preview_reason(&pool, &low, context(8_000, 4_000)),
        Some(AcceptanceRejectReason::MinRelayFeeNotMet)
    );

    let at_floor = tx(outpoint(2, 0), 1_000, 0xFF_FF_FF_FF);
    pool.insert_entry(entry(at_floor, 4_000, 20_000))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// BIP125 replacement policy
// ---------------------------------------------------------------------------

/// Original (signaling or not) plus a descendant, both at 2000 sat/kvB.
struct ConflictFixture {
    pool: Mempool,
    original: Tx,
    child: Tx,
}

fn conflict_pool(signaling: bool) -> Result<ConflictFixture, Box<dyn Error>> {
    // `ENABLE_RBF_NO_LOCKTIME` (BIP125 signal) is 0xFFFFFFFD.
    let sequence = if signaling {
        0xFF_FF_FF_FD
    } else {
        0xFF_FF_FF_FF
    };
    let mut pool = Mempool::new(MempoolLimits::default());
    let original = tx(outpoint(1, 0), 1_000, sequence);
    pool.insert_entry(entry(original.clone(), 4_000, 8_000))?;
    let child = tx(OutPoint::new(original.txid(), 0), 1_000, 0xFF_FF_FF_FF);
    pool.insert_entry(entry(child.clone(), 2_000, 4_000))?;
    Ok(ConflictFixture {
        pool,
        original,
        child,
    })
}

#[test]
fn rbf_opt_in_replacement_sweeps_conflicts_and_descendants() -> Result<(), Box<dyn Error>> {
    let fixture = conflict_pool(true)?;
    let mut pool = fixture.pool;
    // Pays the 12 000 sat evicted package (rule 3), at least its own vsize
    // more (rule 4: 16 000 - 12 000 >= 4 000), and outranks the originals'
    // 2000 sat/kvB (rule 6).
    let replacement = tx(outpoint(1, 0), 2_000, 0xFF_FF_FF_FF);

    let previewed = preview_reason(&pool, &replacement, context(16_000, 4_000));
    assert_eq!(previewed, None, "legal replacement must preview clean");

    let result = pool
        .replace_transaction(
            ReplacementCandidate::new(Arc::new(replacement.clone()), 4_000, 16_000, 1_000),
            0,
            1,
            0,
        )?
        .into_mutation();
    assert_eq!(
        result
            .changes
            .iter()
            .map(|change| (change.txid, change.outcome))
            .collect::<Vec<_>>(),
        vec![
            (
                txid(&fixture.original),
                MutationOutcome::Removed(RemovalReason::Replaced)
            ),
            (
                txid(&fixture.child),
                MutationOutcome::Removed(RemovalReason::Descendant)
            ),
            (txid(&replacement), MutationOutcome::Accepted),
        ],
        "commit order is direct conflicts, swept descendants, then the replacement"
    );
    assert_eq!(pool.len(), 1);
    assert!(pool.contains_txid(&replacement.txid()));
    Ok(())
}

#[test]
fn rbf_rule1_nonsignaling_originals_reject_on_both_surfaces() -> Result<(), Box<dyn Error>> {
    let fixture = conflict_pool(false)?;
    let mut pool = fixture.pool;
    let replacement = tx(outpoint(1, 0), 2_000, 0xFF_FF_FF_FF);

    let err = pool
        .replace_transaction(
            ReplacementCandidate::new(Arc::new(replacement.clone()), 4_000, 16_000, 1_000),
            0,
            1,
            0,
        )
        .err()
        .ok_or("expected rule 1 rejection")?;
    assert_eq!(err, RbfError::Rule1NoOptIn);
    assert_eq!(
        preview_reason(&pool, &replacement, context(16_000, 4_000)),
        Some(AcceptanceRejectReason::Replacement(RbfError::Rule1NoOptIn))
    );
    assert_eq!(pool.len(), 2, "rejection must leave the pool untouched");
    Ok(())
}

#[test]
fn rbf_rule3_replacement_must_pay_evicted_fees() -> Result<(), Box<dyn Error>> {
    let fixture = conflict_pool(true)?;
    let mut pool = fixture.pool;
    // 4 000 sat < the 8 000 sat direct conflict alone.
    let replacement = tx(outpoint(1, 0), 2_000, 0xFF_FF_FF_FF);
    let err = pool
        .replace_transaction(
            ReplacementCandidate::new(Arc::new(replacement.clone()), 4_000, 4_000, 1_000),
            0,
            1,
            0,
        )
        .err()
        .ok_or("expected rule 3 rejection")?;
    assert_eq!(err, RbfError::Rule3InsufficientAbsoluteFee);
    assert_eq!(
        preview_reason(&pool, &replacement, context(4_000, 4_000)),
        Some(AcceptanceRejectReason::Replacement(
            RbfError::Rule3InsufficientAbsoluteFee
        ))
    );
    Ok(())
}

#[test]
fn rbf_rule6_replacement_rate_must_exceed_direct_conflicts() -> Result<(), Box<dyn Error>> {
    let fixture = conflict_pool(true)?;
    let mut pool = fixture.pool;
    // Absolute fee 32 000 pays the 12 000 sat evicted package (rule 3) and
    // its own 16 000 vB of incremental fee (rule 4), but lands at exactly the
    // originals' 2000 sat/kvB — rule 6 wants strictly higher.
    let replacement = tx(outpoint(1, 0), 2_000, 0xFF_FF_FF_FF);
    let err = pool
        .replace_transaction(
            ReplacementCandidate::new(Arc::new(replacement.clone()), 16_000, 32_000, 1_000),
            0,
            1,
            0,
        )
        .err()
        .ok_or("expected rule 6 rejection")?;
    assert_eq!(err, RbfError::Rule6InsufficientFeeRate);
    assert_eq!(
        preview_reason(&pool, &replacement, context(32_000, 16_000)),
        Some(AcceptanceRejectReason::Replacement(
            RbfError::Rule6InsufficientFeeRate
        ))
    );
    Ok(())
}

#[test]
fn rbf_rule2_replacement_may_not_add_unconfirmed_inputs() -> Result<(), Box<dyn Error>> {
    let fixture = conflict_pool(true)?;
    let mut pool = fixture.pool;
    let unrelated = tx(outpoint(9, 9), 1_000, 0xFF_FF_FF_FF);
    pool.insert_entry(entry(unrelated.clone(), 4_000, 4_000))?;

    let replacement = tx_multi(
        &[
            (outpoint(1, 0), 0xFF_FF_FF_FF),
            (OutPoint::new(unrelated.txid(), 0), 0xFF_FF_FF_FF),
        ],
        2_000,
        p2wpkh_script(),
    );
    let err = pool
        .replace_transaction(
            ReplacementCandidate::new(Arc::new(replacement.clone()), 4_000, 16_000, 1_000),
            0,
            1,
            0,
        )
        .err()
        .ok_or("expected rule 2 rejection")?;
    assert_eq!(err, RbfError::Rule2NewUnconfirmedInput);
    assert_eq!(
        preview_reason(&pool, &replacement, context(16_000, 4_000)),
        Some(AcceptanceRejectReason::Replacement(
            RbfError::Rule2NewUnconfirmedInput
        ))
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Ancestor / descendant package limits
// ---------------------------------------------------------------------------

fn chain_pool(depth: u32) -> Result<(Mempool, Vec<Tx>), Box<dyn Error>> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let mut txs = Vec::new();
    let mut previous = outpoint(1, 0);
    for _ in 0..depth {
        let next = tx(previous, 1_000, 0xFF_FF_FF_FF);
        previous = OutPoint::new(next.txid(), 0);
        pool.insert_entry(entry(next.clone(), 4_000, 4_000))?;
        txs.push(next);
    }
    Ok((pool, txs))
}

#[test]
fn ancestor_count_limit_rejects_the_26th_unconfirmed_tx() -> Result<(), Box<dyn Error>> {
    let (mut pool, txs) = chain_pool(25)?;
    let tip = txs.last().ok_or("empty chain")?;
    let rejected = tx(OutPoint::new(tip.txid(), 0), 1_000, 0xFF_FF_FF_FF);
    let err = pool
        .insert_entry(entry(rejected, 4_000, 4_000))
        .err()
        .ok_or("expected TooManyAncestors rejection")?;
    assert_eq!(err, MempoolError::Policy(PolicyError::TooManyAncestors));
    Ok(())
}

#[test]
fn ancestor_size_limit_rejects_an_oversized_package() -> Result<(), Box<dyn Error>> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let mut previous = outpoint(1, 0);
    // 3 x 26 000 vB = 78 000 vB chained; the 4th would reach 104 000 > 101 000.
    for _ in 0..3 {
        let next = tx(previous, 1_000, 0xFF_FF_FF_FF);
        previous = OutPoint::new(next.txid(), 0);
        pool.insert_entry(entry(next, 26_000, 26_000))?;
    }
    let rejected = tx(previous, 1_000, 0xFF_FF_FF_FF);
    let err = pool
        .insert_entry(entry(rejected, 26_000, 26_000))
        .err()
        .ok_or("expected AncestorSizeLimit rejection")?;
    assert_eq!(err, MempoolError::Policy(PolicyError::AncestorSizeLimit));
    Ok(())
}

#[test]
fn descendant_count_limit_rejects_the_26th_child() -> Result<(), Box<dyn Error>> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let parent = tx(outpoint(1, 0), 1_000, 0xFF_FF_FF_FF);
    pool.insert_entry(entry(parent.clone(), 4_000, 4_000))?;
    let parent_out = OutPoint::new(parent.txid(), 0);
    for value in 1_000_u64..1_024 {
        let child = tx(parent_out, value, 0xFF_FF_FF_FF);
        pool.insert_entry(entry(child, 4_000, 4_000))?;
    }
    let rejected = tx(parent_out, 9_999, 0xFF_FF_FF_FF);
    let err = pool
        .insert_entry(entry(rejected, 4_000, 4_000))
        .err()
        .ok_or("expected TooManyDescendants rejection")?;
    assert_eq!(err, MempoolError::Policy(PolicyError::TooManyDescendants));
    Ok(())
}

#[test]
fn acceptance_preview_surfaces_ancestor_limits() -> Result<(), Box<dyn Error>> {
    // R4 closes the documented preview gap: the consolidated evaluator
    // carries package limits, so testmempoolaccept and the admission gate
    // now quote the same verdict.
    let (pool, txs) = chain_pool(25)?;
    let tip = txs.last().ok_or("empty chain")?;
    let candidate = tx(OutPoint::new(tip.txid(), 0), 1_000, 0xFF_FF_FF_FF);
    assert_eq!(
        preview_reason(&pool, &candidate, context(4_000, 4_000)),
        Some(AcceptanceRejectReason::PackageLimit(
            PolicyError::TooManyAncestors
        )),
        "preview must surface ancestor count limits"
    );
    let mut pool = pool;
    let err = pool
        .insert_entry(entry(candidate, 4_000, 4_000))
        .err()
        .ok_or("expected admission to enforce the limit")?;
    assert_eq!(err, MempoolError::Policy(PolicyError::TooManyAncestors));
    Ok(())
}

/// Builds a root with `output_count` outputs so siblings can share a cluster
/// without being in each other's ancestor or descendant packages.
fn fanout_root(label: u8, output_count: usize) -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: outpoint(label, 0),
            script_sig: Vec::new(),
            sequence: 0xFF_FF_FF_FF,
            witness: Vec::new(),
        }],
        outputs: (0..output_count)
            .map(|index| TxOut {
                value: 1_000_u64.saturating_add(u64::try_from(index).unwrap_or(u64::MAX)),
                script_pubkey: p2wpkh_script(),
            })
            .collect(),
    }
}

#[test]
fn cluster_count_limit_rejects_a_sibling_that_ancestors_would_admit() -> Result<(), Box<dyn Error>>
{
    // Root plus two siblings is three; a limit of two must refuse the second
    // sibling. Ancestor and descendant packages stay size two, so only the
    // cluster walk can refuse.
    let limits = MempoolLimits {
        cluster_count: 2,
        max_ancestors: 100,
        max_ancestor_size: 1_000_000,
        max_descendants: 100,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);
    let root = fanout_root(0xC1, 2);
    let root_txid = root.txid();
    pool.insert_entry(entry(root, 100, 10_000))?;
    let first = tx(OutPoint::new(root_txid, 0), 900, 0xFF_FF_FF_FF);
    pool.insert_entry(entry(first, 100, 10_000))?;
    let second = tx(OutPoint::new(root_txid, 1), 800, 0xFF_FF_FF_FF);
    assert_eq!(
        preview_reason(&pool, &second, context(10_000, 100)),
        Some(AcceptanceRejectReason::PackageLimit(
            PolicyError::ClusterCountLimit
        )),
        "preview must surface cluster count limits"
    );
    let err = pool
        .insert_entry(entry(second, 100, 10_000))
        .err()
        .ok_or("expected ClusterCountLimit rejection")?;
    assert_eq!(err, MempoolError::Policy(PolicyError::ClusterCountLimit));
    Ok(())
}

#[test]
fn cluster_size_limit_rejects_on_both_surfaces() -> Result<(), Box<dyn Error>> {
    let limits = MempoolLimits {
        cluster_count: 100,
        cluster_size_vbytes: 250,
        max_ancestors: 100,
        max_ancestor_size: 1_000_000,
        max_descendants: 100,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);
    let root = fanout_root(0xC2, 1);
    let root_txid = root.txid();
    pool.insert_entry(entry(root, 200, 10_000))?;
    let child = tx(OutPoint::new(root_txid, 0), 900, 0xFF_FF_FF_FF);
    assert_eq!(
        preview_reason(&pool, &child, context(10_000, 100)),
        Some(AcceptanceRejectReason::PackageLimit(
            PolicyError::ClusterSizeLimit
        )),
        "preview must surface cluster size limits"
    );
    let err = pool
        .insert_entry(entry(child, 100, 10_000))
        .err()
        .ok_or("expected ClusterSizeLimit rejection")?;
    assert_eq!(err, MempoolError::Policy(PolicyError::ClusterSizeLimit));
    Ok(())
}

#[test]
fn replacement_into_a_full_cluster_is_allowed_on_both_surfaces() -> Result<(), Box<dyn Error>> {
    let limits = MempoolLimits {
        cluster_count: 2,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);
    let root = fanout_root(0xC3, 1);
    let root_txid = root.txid();
    pool.insert_entry(entry(root, 100, 10_000))?;
    let original = tx(OutPoint::new(root_txid, 0), 900, 0xFF_FF_FF_FD);
    pool.insert_entry(entry(original.clone(), 100, 10_000))?;
    let replacement = tx(OutPoint::new(root_txid, 0), 800, 0xFF_FF_FF_FF);
    assert!(
        preview_allowed(&pool, &replacement, context(12_000, 100)),
        "preview must project the post-eviction cluster"
    );
    pool.replace_transaction(
        ReplacementCandidate::new(Arc::new(replacement), 100, 12_000, 1_000),
        0,
        1,
        0,
    )?;
    assert!(!pool.contains_txid(&original.txid()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Standardness
// ---------------------------------------------------------------------------

#[test]
fn oversized_weight_is_not_standard_on_both_surfaces() {
    let pool = Mempool::new(MempoolLimits::default());
    // 3400 P2WPKH outputs ≈ 435 000 weight units > 400 000.
    let mut oversized = tx(outpoint(1, 0), 1_000, 0xFF_FF_FF_FF);
    oversized.outputs = (0..3_400)
        .map(|_| TxOut {
            value: 1_000,
            script_pubkey: p2wpkh_script(),
        })
        .collect();

    assert_eq!(
        is_standard_tx(&oversized, &policy()).err(),
        Some(StandardnessError::Weight)
    );
    assert_eq!(
        preview_reason(&pool, &oversized, context(0, 100_000)),
        Some(AcceptanceRejectReason::NonStandard(
            StandardnessError::Weight
        ))
    );
}

#[test]
fn nonstandard_output_script_is_not_standard_on_both_surfaces() {
    let pool = Mempool::new(MempoolLimits::default());
    let weird = tx_multi(&[(outpoint(1, 0), 0xFF_FF_FF_FF)], 5_000, op_true_script());

    assert_eq!(
        preview_reason(&pool, &weird, context(1_000, 200)),
        Some(AcceptanceRejectReason::NonStandard(
            StandardnessError::NonStandardOutput
        ))
    );
}

#[test]
fn dust_output_is_not_standard_on_both_surfaces() {
    let pool = Mempool::new(MempoolLimits::default());
    let dust = tx_multi(&[(outpoint(1, 0), 0xFF_FF_FF_FF)], 100, p2wpkh_script());
    assert_eq!(
        preview_reason(&pool, &dust, context(1_000, 200)),
        Some(AcceptanceRejectReason::NonStandard(
            StandardnessError::DustOutput
        ))
    );
}

#[test]
fn missing_inputs_fact_is_reported_by_the_preview() -> Result<(), Box<dyn Error>> {
    let pool = Mempool::new(MempoolLimits::default());
    let orphan = tx(outpoint(200, 0), 1_000, 0xFF_FF_FF_FF);
    let missing = PackageTxContext {
        fee: 0,
        vsize: 200,
        sigop_cost: 0,
        missing_inputs: true,
    };
    let facts = evaluate_package_acceptance(
        &pool,
        &policy(),
        std::slice::from_ref(&orphan),
        &[missing],
        None,
        INCREMENTAL_RELAY_FEE_SAT_PER_KVB,
    );
    let fact = facts.results.first().ok_or("expected one fact row")?;
    assert_eq!(
        fact.reject_reason,
        Some(AcceptanceRejectReason::MissingInputs)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Size-limit eviction and the pressure mempool-min fee
// ---------------------------------------------------------------------------

#[test]
fn size_limit_eviction_removes_the_lowest_fee_package_first() -> Result<(), Box<dyn Error>> {
    let limits = MempoolLimits {
        max_total_bytes: 4_000,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);
    let high = tx(outpoint(1, 0), 1_000, 0xFF_FF_FF_FF);
    pool.insert_entry(entry(high, 1_000, 3_000))?;
    let low = tx(outpoint(2, 0), 1_000, 0xFF_FF_FF_FF);
    pool.insert_entry(entry(low.clone(), 1_000, 1_000))?;
    let mid = tx(outpoint(3, 0), 1_000, 0xFF_FF_FF_FF);
    pool.insert_entry(entry(mid, 1_000, 2_000))?;

    let overflow = tx(outpoint(4, 0), 1_000, 0xFF_FF_FF_FF);
    let result = pool
        .insert_entry(entry(overflow.clone(), 2_000, 6_000))?
        .into_mutation();
    assert_eq!(
        result
            .changes
            .iter()
            .map(|change| (change.txid, change.outcome))
            .collect::<Vec<_>>(),
        vec![
            (txid(&overflow), MutationOutcome::Accepted),
            (
                txid(&low),
                MutationOutcome::Removed(RemovalReason::PolicyEviction)
            ),
        ],
        "the 1000 sat/kvB package evicts first, accepted change commits first"
    );
    assert_eq!(pool.len(), 3);
    assert_eq!(pool.total_vsize(), 4_000);
    Ok(())
}

#[test]
fn mempool_min_fee_rises_under_size_pressure_and_the_preview_enforces_it()
-> Result<(), Box<dyn Error>> {
    let limits = MempoolLimits {
        max_total_bytes: 4_000,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);
    // Fill to exactly half of maxmempool: the pressure threshold.
    pool.insert_entry(entry(
        tx(outpoint(1, 0), 1_000, 0xFF_FF_FF_FF),
        1_000,
        1_000,
    ))?;
    pool.insert_entry(entry(
        tx(outpoint(2, 0), 1_000, 0xFF_FF_FF_FF),
        1_000,
        2_000,
    ))?;

    // Floor = cheapest evictable (1000) + incremental (1000).
    assert_eq!(
        mempool_min_fee_sat_per_kvb(&pool, INCREMENTAL_RELAY_FEE_SAT_PER_KVB),
        2_000
    );

    // rate 1200 sat/kvB: above the configured floor, below the pressure floor.
    let lukewarm = tx(outpoint(3, 0), 1_000, 0xFF_FF_FF_FF);
    assert_eq!(
        preview_reason(&pool, &lukewarm, context(1_200, 1_000)),
        Some(AcceptanceRejectReason::MinRelayFeeNotMet),
        "the preview must quote the pressure floor"
    );

    // What IS: the raw insert gate checks only the configured floor, so the
    // same tx admits through the pool API (deviation ledger, "pressure floor
    // surface").
    pool.insert_entry(entry(lukewarm, 1_000, 1_200))?;
    assert_eq!(pool.len(), 3);

    // Control: on an unloaded default pool the same tx previews clean.
    let empty = Mempool::new(MempoolLimits::default());
    let accepted = tx(outpoint(4, 0), 1_000, 0xFF_FF_FF_FF);
    assert!(preview_allowed(&empty, &accepted, context(1_200, 1_000)));
    Ok(())
}
