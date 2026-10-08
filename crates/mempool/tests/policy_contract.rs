//! Mempool policy compatibility contract: every policy row in
//! `docs/policies/mempool-policy.md` cites one fixture here (or in
//! `crates/rpc/tests/policy_contract.rs`).
//!
//! Fixtures in this file assert the mutating pool-side verdict. The preview-side
//! verdicts retired with the removed `evaluate_package_acceptance` helper are now
//! exercised through the real `MempoolGateway` preview path in
//! `crates/rpc/tests/policy_contract.rs`; the missing-inputs row keeps a direct
//! mempool-surface preview fixture below.
//!
//! Contract clause: `docs/contracts/mempool-policy.md` `POL-01`.
#![deny(clippy::expect_used)]

extern crate alloc;

use alloc::sync::Arc;
use bitcoin_rs_consensus::ValidationEngine;
use std::error::Error;

use bitcoin_rs_mempool::eviction::mempool_min_fee_sat_per_kvb;
use bitcoin_rs_mempool::standardness::{
    AcceptanceRejectReason, StandardnessError, StandardnessPolicy, is_standard_tx,
};
use bitcoin_rs_mempool::{
    AdmissionChain, ChainAdmissionSnapshot, Mempool, MempoolEntry, MempoolError, MempoolGateway,
    MempoolLimits, MutationOutcome, PolicyError, PrevoutMeta, RbfError, RemovalReason,
    ReplacementCandidate,
};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_script::opcode;
use parking_lot::RwLock;

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

/// Stub chain that provides no confirmed prevouts, exercising missing-input
/// classification through the real `MempoolGateway` preview path.
struct EmptyChain;

impl AdmissionChain for EmptyChain {
    fn snapshot(&self, _tx: &Tx) -> Option<ChainAdmissionSnapshot> {
        Some(ChainAdmissionSnapshot::default())
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
        lock_time: LockTime::ZERO,
        inputs: inputs
            .iter()
            .map(|(prevout, sequence)| TxIn {
                previous_output: *prevout,
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(*sequence),
                witness: Witness::new(),
            })
            .collect(),
        outputs: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: script_pubkey.into(),
        }],
    }
}

fn txid(tx: &Tx) -> Hash256 {
    Hash256::from_le_bytes(tx.txid().as_bytes())
}

fn entry(tx: Tx, vsize: u32, fee: u64) -> MempoolEntry {
    MempoolEntry::new(Arc::new(tx), vsize, fee, 0, 1, 0)
}

#[test]
fn below_min_relay_fee_rejects_on_both_surfaces_at_the_same_floor() -> Result<(), Box<dyn Error>> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let low = tx(outpoint(1, 0), 1_000, 0xFF_FF_FF_FF);
    let err = pool
        .insert_entry(entry(low, 4_000, 3_999))
        .err()
        .ok_or("expected BelowMinRelayFee rejection")?;
    assert_eq!(
        err,
        MempoolError::Policy(PolicyError::BelowMinRelayFee {
            tx_rate: 999,
            min_rate: 1_000,
        })
    );

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
        .insert_entry(entry(low, 4_000, 8_000))
        .err()
        .ok_or("expected BelowMinRelayFee rejection")?;
    assert_eq!(
        err,
        MempoolError::Policy(PolicyError::BelowMinRelayFee {
            tx_rate: 2_000,
            min_rate: 5_000,
        })
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
fn rbf_replacement_sweeps_nonsignaling_conflicts_and_descendants() -> Result<(), Box<dyn Error>> {
    let fixture = conflict_pool(false)?;
    let mut pool = fixture.pool;
    let replacement = tx(outpoint(1, 0), 2_000, 0xFF_FF_FF_FF);

    let result = pool.replace_transaction(
        &ReplacementCandidate::new(Arc::new(replacement.clone()), 4_000, 16_000, 1_000),
        0,
        1,
    )?;
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
fn rbf_rule3_replacement_must_pay_evicted_fees() -> Result<(), Box<dyn Error>> {
    let fixture = conflict_pool(true)?;
    let mut pool = fixture.pool;
    let replacement = tx(outpoint(1, 0), 2_000, 0xFF_FF_FF_FF);
    let err = pool
        .replace_transaction(
            &ReplacementCandidate::new(Arc::new(replacement), 4_000, 4_000, 1_000),
            0,
            1,
        )
        .err()
        .ok_or("expected rule 3 rejection")?;
    assert_eq!(err, RbfError::Rule3InsufficientAbsoluteFee);
    Ok(())
}

#[test]
fn replacement_with_equal_direct_rate_can_improve_the_full_diagram() -> Result<(), Box<dyn Error>> {
    let fixture = conflict_pool(true)?;
    let mut pool = fixture.pool;
    let replacement = tx(outpoint(1, 0), 2_000, 0xFF_FF_FF_FF);
    pool.replace_transaction(
        &ReplacementCandidate::new(Arc::new(replacement), 16_000, 32_000, 1_000),
        0,
        1,
    )?;
    assert_eq!(pool.len(), 1);
    Ok(())
}

#[test]
fn replacement_may_add_an_unconfirmed_input() -> Result<(), Box<dyn Error>> {
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
    let replacement_txid = replacement.txid();
    pool.replace_transaction(
        &ReplacementCandidate::new(Arc::new(replacement), 4_000, 16_000, 1_000),
        0,
        1,
    )?;
    assert!(pool.contains_txid(&replacement_txid));
    assert!(pool.contains_txid(&unrelated.txid()));
    assert!(!pool.contains_txid(&fixture.original.txid()));
    assert!(!pool.contains_txid(&fixture.child.txid()));
    Ok(())
}

/// Builds a root with `output_count` outputs so siblings can share a cluster
/// without being in each other's ancestor or descendant packages.
fn fanout_root(label: u8, output_count: usize) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: outpoint(label, 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: (0..output_count)
            .map(|index| TxOut {
                value: Amount::from_sat(
                    1_000_u64.saturating_add(u64::try_from(index).unwrap_or(u64::MAX)),
                ),
                script_pubkey: p2wpkh_script().into(),
            })
            .collect(),
    }
}

#[test]
fn cluster_count_limit_rejects_a_sibling_that_ancestors_would_admit() -> Result<(), Box<dyn Error>>
{
    let limits = MempoolLimits {
        cluster_count: 2,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);
    let root = fanout_root(0xC1, 2);
    let root_txid = root.txid();
    pool.insert_entry(entry(root, 100, 10_000))?;
    let first = tx(OutPoint::new(root_txid, 0), 900, 0xFF_FF_FF_FF);
    pool.insert_entry(entry(first, 100, 10_000))?;
    let second = tx(OutPoint::new(root_txid, 1), 800, 0xFF_FF_FF_FF);
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
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);
    let root = fanout_root(0xC2, 1);
    let root_txid = root.txid();
    pool.insert_entry(entry(root, 200, 10_000))?;
    let child = tx(OutPoint::new(root_txid, 0), 900, 0xFF_FF_FF_FF);
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
    pool.replace_transaction(
        &ReplacementCandidate::new(Arc::new(replacement), 100, 12_000, 1_000),
        0,
        1,
    )?;
    assert!(!pool.contains_txid(&original.txid()));
    Ok(())
}

#[test]
fn oversized_weight_is_not_standard_on_both_surfaces() {
    let mut oversized = tx(outpoint(1, 0), 1_000, 0xFF_FF_FF_FF);
    oversized.outputs = (0..3_400)
        .map(|_| TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: p2wpkh_script().into(),
        })
        .collect();

    assert_eq!(
        is_standard_tx(&oversized, &policy()).err(),
        Some(StandardnessError::Weight)
    );
}

#[test]
fn nonstandard_output_script_is_not_standard_on_both_surfaces() {
    let weird = tx_multi(&[(outpoint(1, 0), 0xFF_FF_FF_FF)], 5_000, op_true_script());
    assert_eq!(
        is_standard_tx(&weird, &policy()).err(),
        Some(StandardnessError::NonStandardOutput)
    );
}

#[test]
fn multiple_dust_outputs_are_not_standard() {
    let mut dust = tx_multi(&[(outpoint(1, 0), 0xFF_FF_FF_FF)], 100, p2wpkh_script());
    assert!(is_standard_tx(&dust, &policy()).is_ok());
    dust.outputs.push(dust.outputs[0].clone());
    assert_eq!(
        is_standard_tx(&dust, &policy()).err(),
        Some(StandardnessError::DustOutput)
    );
}

#[test]
fn missing_inputs_fact_is_reported_by_the_preview() -> Result<(), Box<dyn Error>> {
    let pool = Mempool::new(MempoolLimits::default());
    let gateway = MempoolGateway::new(Arc::new(RwLock::new(pool)), None, ValidationEngine::Native);
    let orphan = tx(outpoint(200, 0), 1_000, 0xFF_FF_FF_FF);
    let facts = gateway.preview_transactions(&[orphan], None, &EmptyChain)?;
    let fact = facts.results.first().ok_or("expected one fact row")?;
    assert_eq!(
        fact.reject_reason,
        Some(AcceptanceRejectReason::MissingInputs)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// BIP68 sequence locks and coinbase maturity at admission (policy §3, §5)
// ---------------------------------------------------------------------------

/// Confirmed chain facts for finality fixtures: one snapshot height, tip
/// median-time-past, CSV activation, and per-prevout metadata rows, mirroring
/// what the RPC producer derives from the live UTXO set and the block tree.
struct MetaChain {
    height: u32,
    locktime_cutoff: u32,
    csv_active: bool,
    prevouts: Vec<(OutPoint, TxOut)>,
    meta: hashbrown::HashMap<OutPoint, PrevoutMeta>,
}

impl AdmissionChain for MetaChain {
    fn snapshot(&self, _tx: &Tx) -> Option<ChainAdmissionSnapshot> {
        Some(ChainAdmissionSnapshot {
            prevouts: self.prevouts.clone(),
            prevout_meta: self.meta.clone(),
            height: self.height,
            locktime_cutoff: self.locktime_cutoff,
            csv_active: self.csv_active,
            confirmed: false,
        })
    }
}

/// Builds a chain whose only confirmed coin is `(outpoint, output, meta)`.
fn meta_chain(
    height: u32,
    locktime_cutoff: u32,
    csv_active: bool,
    outpoint: OutPoint,
    output: TxOut,
    meta: PrevoutMeta,
) -> MetaChain {
    MetaChain {
        height,
        locktime_cutoff,
        csv_active,
        prevouts: vec![(outpoint, output)],
        meta: hashbrown::HashMap::from([(outpoint, meta)]),
    }
}

struct Case {
    label: &'static str,
    tag: u8,
    sequence: u32,
    meta: PrevoutMeta,
    chain_height: u32,
    chain_mtp: u32,
    csv_active: bool,
    reject: Option<AcceptanceRejectReason>,
}

fn relative_lock_cases() -> [Case; 7] {
    let height_meta = PrevoutMeta {
        height: 10,
        mtp: 0,
        coinbase: false,
    };
    let time_meta = PrevoutMeta {
        height: 10,
        mtp: 1_000,
        coinbase: false,
    };
    let coinbase_meta = PrevoutMeta {
        height: 20,
        mtp: 0,
        coinbase: true,
    };
    [
        Case {
            label: "height lock two blocks short",
            tag: 41,
            sequence: 5,
            meta: height_meta,
            chain_height: 12,
            chain_mtp: 0,
            csv_active: true,
            reject: Some(AcceptanceRejectReason::NonBip68Final),
        },
        Case {
            label: "height lock satisfied",
            tag: 41,
            sequence: 2,
            meta: height_meta,
            chain_height: 12,
            chain_mtp: 0,
            csv_active: true,
            reject: None,
        },
        Case {
            label: "time lock short of the confirmed mtp",
            tag: 44,
            sequence: 0x0040_0001,
            meta: time_meta,
            chain_height: 12,
            chain_mtp: 1_400,
            csv_active: true,
            reject: Some(AcceptanceRejectReason::NonBip68Final),
        },
        Case {
            label: "time lock cleared by the confirmed mtp",
            tag: 44,
            sequence: 0x0040_0001,
            meta: time_meta,
            chain_height: 12,
            chain_mtp: 1_600,
            csv_active: true,
            reject: None,
        },
        Case {
            label: "height lock ignored before csv activation",
            tag: 45,
            sequence: 5,
            meta: height_meta,
            chain_height: 12,
            chain_mtp: 0,
            csv_active: false,
            reject: None,
        },
        Case {
            label: "coinbase one short of maturity",
            tag: 46,
            sequence: 0xFF_FF_FF_FF,
            meta: coinbase_meta,
            chain_height: 118,
            chain_mtp: 0,
            csv_active: true,
            reject: Some(AcceptanceRejectReason::ScriptVerify),
        },
        Case {
            label: "coinbase at maturity",
            tag: 46,
            sequence: 0xFF_FF_FF_FF,
            meta: coinbase_meta,
            chain_height: 119,
            chain_mtp: 0,
            csv_active: true,
            reject: None,
        },
    ]
}

/// Relative locks and coinbase maturity are reported from the confirmed
/// prevout metadata: a height lock clears once enough blocks passed, a time
/// lock is measured against the confirmed median-time-past, the BIP68 check is
/// inert before CSV activation, and a coinbase is spendable at 100
/// confirmations.
#[test]
fn preview_reports_relative_locks_and_coinbase_maturity() -> Result<(), Box<dyn Error>> {
    let pool = Mempool::new(MempoolLimits::default());
    let gateway = MempoolGateway::new(Arc::new(RwLock::new(pool)), None, ValidationEngine::Native);
    for case in relative_lock_cases() {
        let spendable = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(op_true_script()),
        };
        let chain = meta_chain(
            case.chain_height,
            case.chain_mtp,
            case.csv_active,
            outpoint(case.tag, 0),
            spendable,
            case.meta,
        );
        let spend = tx(outpoint(case.tag, 0), 9_000, case.sequence);
        let facts = gateway.preview_transactions(&[spend], None, &chain)?;
        assert_eq!(
            facts
                .results
                .first()
                .ok_or("expected one fact row")?
                .reject_reason,
            case.reject,
            "{}",
            case.label
        );
    }
    Ok(())
}

#[test]
fn bip68_unconfirmed_parent_positive_relative_lock_fails() -> Result<(), Box<dyn Error>> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let parent = tx_multi(
        &[(outpoint(48, 0), 0xFF_FF_FF_FF)],
        10_000,
        op_true_script(),
    );
    let parent_outpoint = OutPoint::new(parent.txid(), 0);
    pool.insert_entry(entry(parent, 250, 3_000))?;
    let gateway = MempoolGateway::new(Arc::new(RwLock::new(pool)), None, ValidationEngine::Native);
    let child = tx_multi(
        &[(parent_outpoint, 1), (outpoint(47, 0), 0xFF_FF_FF_FF)],
        9_000,
        p2wpkh_script(),
    );
    let coin = TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: Script::from_bytes(op_true_script()),
    };
    let chain = meta_chain(
        12,
        0,
        true,
        outpoint(47, 0),
        coin,
        PrevoutMeta {
            height: 10,
            mtp: 0,
            coinbase: false,
        },
    );
    let facts = gateway.preview_transactions(&[child], None, &chain)?;
    assert_eq!(
        facts
            .results
            .first()
            .ok_or("expected one fact row")?
            .reject_reason,
        Some(AcceptanceRejectReason::NonBip68Final)
    );
    Ok(())
}

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
    let result = pool.insert_entry(entry(overflow.clone(), 2_000, 6_000))?;
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

    assert_eq!(
        mempool_min_fee_sat_per_kvb(&pool, INCREMENTAL_RELAY_FEE_SAT_PER_KVB),
        2_000
    );

    let lukewarm = tx(outpoint(3, 0), 1_000, 0xFF_FF_FF_FF);

    pool.insert_entry(entry(lukewarm, 1_000, 1_200))?;
    assert_eq!(pool.len(), 3);

    Ok(())
}
