extern crate alloc;

use alloc::sync::Arc;

use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_mempool::standardness::{
    AcceptanceRejectReason, MAX_PACKAGE_COUNT, MAX_PACKAGE_WEIGHT, MAX_STANDARD_TX_WEIGHT,
    StandardnessError, StandardnessPolicy, is_standard_tx,
};
use bitcoin_rs_mempool::{
    AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, LocalOrigin, Mempool, MempoolEntry,
    MempoolError, MempoolGateway, MempoolLimits, PolicyError, RbfError, ReplacementCandidate,
    SubmitError, SubmitOutcome, required_fee,
};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};

use super::TestError;

struct EmptyChain;

impl AdmissionChain for EmptyChain {
    fn snapshot(&self, _tx: &Tx) -> Option<ChainAdmissionSnapshot> {
        Some(ChainAdmissionSnapshot::default())
    }
}

struct FundedChain {
    prevouts: Vec<(OutPoint, TxOut)>,
}

impl AdmissionChain for FundedChain {
    fn snapshot(&self, _tx: &Tx) -> Option<ChainAdmissionSnapshot> {
        Some(ChainAdmissionSnapshot {
            prevouts: self.prevouts.clone(),
            prevout_meta: hashbrown::HashMap::new(),
            height: 100,
            locktime_cutoff: 0,
            csv_active: false,
            next_block_script_flags: bitcoin_rs_script::VerifyFlags::STANDARD,
            confirmed: true,
        })
    }
}

fn p2sh_true_script() -> Vec<u8> {
    let hash = [
        0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a, 0x56, 0x99, 0x71, 0xc7, 0x7e,
        0xba, 0x30, 0xcd, 0x5a, 0x4b,
    ];
    let mut out = Vec::with_capacity(23);
    out.push(0xa9);
    out.push(0x14);
    out.extend_from_slice(&hash);
    out.push(0x87);
    out
}

fn true_redeem_script_sig() -> Vec<u8> {
    bitcoin_rs_script::push_data(&[0x51])
}

fn outpoint(label: u8, vout: u32) -> OutPoint {
    let mut bytes = [0_u8; 32];
    bytes[0] = label;
    OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), vout)
}

fn single_input_tx(label: u8, prevout: OutPoint, fee: u64) -> Tx {
    let input_value = 100_000_u64;
    let output_value = input_value.saturating_sub(fee);
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: prevout,
            script_sig: Script::from_bytes(true_redeem_script_sig()),
            sequence: Sequence::from_consensus(0xFFFF_FFFD),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: vec![
                0x00, 0x14, label, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            ]
            .into(),
        }],
    }
}

#[test]
fn admission_size_and_vsize_boundaries() {
    let policy = StandardnessPolicy::default();
    let prev = outpoint(1, 0);

    let tiny_tx = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![],
        outputs: vec![],
    };
    assert_eq!(
        is_standard_tx(&tiny_tx, &policy),
        Err(StandardnessError::TransactionTooSmall)
    );

    let standard = single_input_tx(2, prev, 1_000);
    assert!(standard.base_size() >= 65);
    assert!(is_standard_tx(&standard, &policy).is_ok());

    let mut heavy = standard;
    let padding = usize::try_from(MAX_STANDARD_TX_WEIGHT).unwrap_or(0);
    heavy.inputs[0].witness = Witness::from_stack(vec![vec![0x00; padding]]);
    assert!(heavy.weight() > MAX_STANDARD_TX_WEIGHT);
    assert_eq!(
        is_standard_tx(&heavy, &policy),
        Err(StandardnessError::Weight)
    );
}

#[test]
fn cluster_limits_count_and_size_boundaries() -> Result<(), TestError> {
    let limits = MempoolLimits {
        cluster_count: 3,
        cluster_size_vbytes: 1_000,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);

    let root = single_input_tx(10, outpoint(1, 0), 1_000);
    let root_txid = root.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(root), 100, 1_000, 1, 1, 0))?;

    let child1 = single_input_tx(11, OutPoint::new(root_txid, 0), 1_000);
    let child1_txid = child1.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(child1), 100, 1_000, 1, 1, 0))?;

    let child2 = single_input_tx(12, OutPoint::new(child1_txid, 0), 1_000);
    let child2_txid = child2.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(child2), 100, 1_000, 1, 1, 0))?;
    assert_eq!(pool.len(), 3);

    let child3 = single_input_tx(13, OutPoint::new(child2_txid, 0), 1_000);
    let overflow = pool.insert_entry(MempoolEntry::new(Arc::new(child3), 100, 1_000, 1, 1, 0));
    assert_eq!(
        overflow.err(),
        Some(MempoolError::Policy(PolicyError::ClusterCountLimit))
    );
    assert_eq!(pool.len(), 3);

    let small_limits = MempoolLimits {
        cluster_count: 10,
        cluster_size_vbytes: 150,
        ..MempoolLimits::default()
    };
    let mut size_pool = Mempool::new(small_limits);
    let base = single_input_tx(20, outpoint(2, 0), 1_000);
    let base_txid = base.txid();
    size_pool.insert_entry(MempoolEntry::new(Arc::new(base), 100, 1_000, 1, 1, 0))?;

    let heavy_child = single_input_tx(21, OutPoint::new(base_txid, 0), 1_000);
    let size_overflow = size_pool.insert_entry(MempoolEntry::new(
        Arc::new(heavy_child),
        100,
        1_000,
        1,
        1,
        0,
    ));
    assert_eq!(
        size_overflow.err(),
        Some(MempoolError::Policy(PolicyError::ClusterSizeLimit))
    );

    Ok(())
}

#[test]
fn rbf_replacement_fee_and_bip125_rules() -> Result<(), TestError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let shared_outpoint = outpoint(30, 0);

    let original = single_input_tx(31, shared_outpoint, 1_000);
    let orig_txid = original.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(original), 100, 1_000, 1, 1, 0))?;
    assert!(pool.contains_txid(&orig_txid));

    let underpaying = single_input_tx(32, shared_outpoint, 999);
    let candidate_underpay = ReplacementCandidate::new(Arc::new(underpaying), 100, 999, 1_000);
    let preview_underpay = pool.check_replacement(&candidate_underpay);
    assert_eq!(
        preview_underpay.err(),
        Some(RbfError::Rule3InsufficientAbsoluteFee)
    );

    let equal_fee = single_input_tx(33, shared_outpoint, 1_000);
    let candidate_equal = ReplacementCandidate::new(Arc::new(equal_fee), 100, 1_000, 1_000);
    let preview_equal = pool.check_replacement(&candidate_equal);
    assert_eq!(
        preview_equal.err(),
        Some(RbfError::Rule4InsufficientIncrementalFee)
    );

    let incremental = required_fee(1_000, 100)?;
    assert_eq!(incremental, 100);

    let just_below = single_input_tx(34, shared_outpoint, 1_099);
    let candidate_below = ReplacementCandidate::new(Arc::new(just_below), 100, 1_099, 1_000);
    let preview_below = pool.check_replacement(&candidate_below);
    assert_eq!(
        preview_below.err(),
        Some(RbfError::Rule4InsufficientIncrementalFee)
    );

    let valid_fee = 1_000 + u64::try_from(incremental).unwrap_or(0);
    let valid_replacement = single_input_tx(35, shared_outpoint, valid_fee);
    let candidate_valid =
        ReplacementCandidate::new(Arc::new(valid_replacement), 100, valid_fee, 1_000);
    assert!(pool.check_replacement(&candidate_valid).is_ok());

    let result = pool.replace_transaction(&candidate_valid, 2, 1)?;
    assert_eq!(result.removed_txids(), vec![orig_txid]);
    assert!(!pool.contains_txid(&orig_txid));

    Ok(())
}

#[test]
fn package_size_and_count_boundaries() {
    let gateway = MempoolGateway::new(
        Arc::new(parking_lot::RwLock::new(Mempool::new(
            MempoolLimits::default(),
        ))),
        None,
        ValidationEngine::Native,
        None,
    );
    let chain = EmptyChain;

    let empty_result = gateway.submit_local_package(Vec::new(), LocalOrigin::Rpc, None, 1, &chain);
    assert_eq!(
        empty_result.err(),
        Some(SubmitError::Policy(AcceptanceRejectReason::PackageCount))
    );

    let single = single_input_tx(40, outpoint(4, 0), 1_000);
    let duplicate_txs = vec![single.clone(), single];
    let dup_result = gateway.submit_local_package(duplicate_txs, LocalOrigin::Rpc, None, 1, &chain);
    assert_eq!(
        dup_result.err(),
        Some(SubmitError::Policy(
            AcceptanceRejectReason::PackageDuplicates
        ))
    );

    let conflict_a = single_input_tx(41, outpoint(5, 0), 1_000);
    let conflict_b = single_input_tx(42, outpoint(5, 0), 1_000);
    let conflict_result = gateway.submit_local_package(
        vec![conflict_a, conflict_b],
        LocalOrigin::Rpc,
        None,
        1,
        &chain,
    );
    assert!(matches!(
        conflict_result.err(),
        Some(SubmitError::Policy(
            AcceptanceRejectReason::PackageConflict | AcceptanceRejectReason::PackageTopology
        ))
    ));

    let txs_count_26: Vec<_> = (0..=25_u8)
        .map(|i| single_input_tx(i + 100, outpoint(i + 10, 0), 1_000))
        .collect();
    assert_eq!(txs_count_26.len(), MAX_PACKAGE_COUNT + 1);
    let count_overflow =
        gateway.submit_local_package(txs_count_26, LocalOrigin::Rpc, None, 1, &chain);
    assert_eq!(
        count_overflow.err(),
        Some(SubmitError::Policy(AcceptanceRejectReason::PackageCount))
    );

    let mut heavy_pkg_a = single_input_tx(43, outpoint(6, 0), 1_000);
    let padding = usize::try_from(MAX_PACKAGE_WEIGHT).unwrap_or(0);
    heavy_pkg_a.inputs[0].witness = Witness::from_stack(vec![vec![0x00; padding]]);
    let heavy_pkg_b = single_input_tx(44, outpoint(7, 0), 1_000);
    let weight_overflow = gateway.submit_local_package(
        vec![heavy_pkg_a, heavy_pkg_b],
        LocalOrigin::Rpc,
        None,
        1,
        &chain,
    );
    assert!(weight_overflow.is_err());
}

#[test]
fn dust_output_boundaries() {
    let policy = StandardnessPolicy::default();
    let p2pkh_script = vec![
        0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac,
    ];

    let tx_dust = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: outpoint(8, 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![vec![0x51; 32]]),
        }],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(545),
                script_pubkey: Script::from_bytes(p2pkh_script.clone()),
            },
            TxOut {
                value: Amount::from_sat(545),
                script_pubkey: Script::from_bytes(p2pkh_script),
            },
        ],
    };
    assert_eq!(
        is_standard_tx(&tx_dust, &policy),
        Err(StandardnessError::DustOutput)
    );
}

#[test]
fn eviction_under_byte_bound() -> Result<(), TestError> {
    let mut pool = Mempool::new(MempoolLimits {
        max_total_bytes: 100_000,
        min_relay_fee_sat_per_kvb: 1_000,
        ..MempoolLimits::default()
    });

    let tx1 = single_input_tx(50, outpoint(8, 0), 1_000);
    let tx1_id = tx1.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(tx1), 100, 1_000, 1, 1, 0))?;

    let tx2 = single_input_tx(51, outpoint(9, 0), 5_000);
    let _tx2_id = tx2.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(tx2), 100, 5_000, 1, 1, 0))?;
    assert_eq!(pool.len(), 2);

    let mem_before = pool.dynamic_memory_usage();
    pool.limits.max_total_bytes = mem_before.saturating_sub(100);

    let tx3 = single_input_tx(52, outpoint(10, 0), 10_000);
    let tx3_id = tx3.txid();
    let changes = pool.insert_entry(MempoolEntry::new(Arc::new(tx3), 100, 10_000, 1, 1, 0))?;
    assert!(
        changes.removed_txids().contains(&tx1_id),
        "lowest feerate tx1 must be evicted"
    );
    assert!(!pool.contains_txid(&tx1_id));
    assert!(pool.contains_txid(&tx3_id));
    Ok(())
}

#[test]
fn expiry_boundary_removes_old_entries() -> Result<(), TestError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let entry_time = 1_000_000_u64;

    let tx1 = single_input_tx(60, outpoint(11, 0), 1_000);
    let tx1_id = tx1.txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(tx1),
        100,
        1_000,
        entry_time,
        1,
        0,
    ))?;

    assert!(!pool.has_expired_entries(entry_time));
    assert!(!pool.has_expired_entries(entry_time + 336 * 3600));

    let expired_time = entry_time + 336 * 3600 + 1;
    assert!(pool.has_expired_entries(expired_time));

    let mutation = pool.expire(expired_time);
    assert_eq!(mutation.removed_txids(), vec![tx1_id]);
    assert!(!pool.contains_txid(&tx1_id));
    assert_eq!(pool.len(), 0);

    Ok(())
}

#[test]
fn double_spend_and_reorg_interleavings() -> Result<(), TestError> {
    let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
        MempoolLimits::default(),
    )));
    let gateway = Arc::new(MempoolGateway::new(
        pool,
        None,
        ValidationEngine::Native,
        None,
    ));

    let common_prev = outpoint(80, 0);
    let tx1 = single_input_tx(81, common_prev, 1_000);
    let tx1_id = tx1.txid();
    let chain = FundedChain {
        prevouts: vec![(
            common_prev,
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: Script::from_bytes(p2sh_true_script()),
            },
        )],
    };

    let outcome1 =
        gateway.submit_transaction(Arc::new(tx1.clone()), AdmissionOrigin::Rpc, None, 1, &chain)?;
    assert!(matches!(outcome1, SubmitOutcome::Committed(_)));
    assert!(gateway.read().contains_txid(&tx1_id));

    let tx2_low = single_input_tx(82, common_prev, 900);
    let outcome2 =
        gateway.submit_transaction(Arc::new(tx2_low), AdmissionOrigin::Rpc, None, 1, &chain);
    assert!(outcome2.is_err());
    assert!(gateway.read().contains_txid(&tx1_id));

    let tx2_high = single_input_tx(83, common_prev, 3_000);
    let tx2_high_id = tx2_high.txid();
    let outcome3 =
        gateway.submit_transaction(Arc::new(tx2_high), AdmissionOrigin::Rpc, None, 1, &chain)?;
    assert!(matches!(outcome3, SubmitOutcome::Committed(_)));
    assert!(!gateway.read().contains_txid(&tx1_id));
    assert!(gateway.read().contains_txid(&tx2_high_id));

    let change = gateway.begin_chain_change()?;
    let committed = gateway.reconsider_disconnected(&change, &chain, 2, [Arc::new(tx1)]);
    assert!(
        committed.is_empty(),
        "conflicting disconnected transaction must be refused"
    );
    assert!(gateway.read().contains_txid(&tx2_high_id));
    change.finish()?;

    Ok(())
}
