mod admission {
    extern crate alloc;

    use super::TestError;
    use super::{p2sh_true_script, true_redeem_script_sig};
    use alloc::sync::Arc;
    use bitcoin_rs_consensus::ValidationEngine;
    use std::sync::mpsc;
    use std::thread;

    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use bitcoin_rs_consensus::script::opcode;
    use bitcoin_rs_mempool::standardness::{AcceptanceRejectReason, PackageTxContext};
    use bitcoin_rs_mempool::{
        AdmissionOrigin, AdmissionRequest, AdmitError, AdmitOutcome, Mempool, MempoolEntry,
        MempoolGateway, MempoolLimits, arm_admission_park, reset_admission_park,
    };

    const P2PKH_SCRIPT: &[u8] = &[
        opcode::OP_DUP,
        opcode::OP_HASH160,
        0x14,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        opcode::OP_EQUALVERIFY,
        opcode::OP_CHECKSIG,
    ];

    fn p2sh_script_pubkey(hash: &[u8; 20]) -> Vec<u8> {
        let mut out = Vec::with_capacity(23);
        out.push(opcode::OP_HASH160);
        out.push(0x14);
        out.extend_from_slice(hash);
        out.push(opcode::OP_EQUAL);
        out
    }

    fn p2wsh_script_pubkey(hash: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(34);
        out.push(opcode::OP_0);
        out.push(0x20);
        out.extend_from_slice(hash);
        out
    }

    fn outpoint(label: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), vout)
    }

    fn tx_one_input(
        prevout: OutPoint,
        script_sig: Vec<u8>,
        witness: Vec<Vec<u8>>,
        output_value: u64,
        output_script: Vec<u8>,
    ) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: prevout,
                script_sig: Script::from_bytes(script_sig),
                sequence: Sequence::from_consensus(0xFFFF_FFFF),
                witness: Witness::from_stack(witness),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: Script::from_bytes(output_script),
            }],
        }
    }

    #[expect(clippy::expect_used, reason = "helper assumes even generation")]
    fn admission_request(
        gateway: &MempoolGateway,
        tx: &Tx,
        context: PackageTxContext,
        prevouts: Vec<(OutPoint, TxOut)>,
    ) -> AdmissionRequest {
        AdmissionRequest {
            tx: Arc::new(tx.clone()),
            context,
            prevouts,
            prevout_meta: hashbrown::HashMap::new(),
            csv_active: false,
            next_block_script_flags: bitcoin_rs_consensus::script::VerifyFlags::STANDARD,
            locktime_cutoff: 0,
            max_feerate_sat_per_kvb: None,
            time: 1,
            height: 1,
            origin: AdmissionOrigin::Rpc,
            expected_generation: gateway.stable_generation().expect("generation is even"),
            expected_sequence: gateway.read().sequence_number(),
        }
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test invariants are checked with expect"
    )]
    fn stale_policy_verdict_becomes_retryable() -> Result<(), TestError> {
        let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
            MempoolLimits::default(),
        )));
        let gateway = Arc::new(MempoolGateway::new(
            pool,
            None,
            ValidationEngine::Native,
            None,
        ));

        let prev = outpoint(1, 0);
        let tx = tx_one_input(
            prev,
            true_redeem_script_sig(),
            Vec::new(),
            99_000,
            P2PKH_SCRIPT.to_vec(),
        );
        let context = PackageTxContext {
            fee: 1_000,
            vsize: u32::try_from(tx.vsize()).unwrap_or(u32::MAX),
            sigop_cost: 0,
            missing_inputs: false,
        };
        let prevouts = vec![(
            prev,
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: Script::from_bytes(p2sh_true_script()),
            },
        )];
        let request = admission_request(&gateway, &tx, context, prevouts);

        let (parked_tx, parked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let target = Arc::as_ptr(&gateway).expose_provenance();
        arm_admission_park(target, parked_tx, release_rx);

        let gateway_for_thread = Arc::clone(&gateway);
        let admission = thread::spawn(move || gateway_for_thread.admit_transaction(request));

        parked_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("admission must park at the gateway seam");

        let unrelated = tx_one_input(
            outpoint(2, 0),
            Vec::new(),
            Vec::new(),
            99_000,
            P2PKH_SCRIPT.to_vec(),
        );
        gateway.insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::new(unrelated), 100, 100_000_000, 1, 1, 0),
        )?;

        release_tx.send(()).expect("release the parked admission");

        let result = admission.join().expect("admission thread did not panic");

        reset_admission_park();

        assert_eq!(
            result,
            Err(AdmitError::MempoolChanged),
            "a stale policy verdict must be downgraded to the retryable transient error"
        );
        Ok(())
    }

    // POL-04
    #[test]
    fn p2sh_sigop_cost_exceeds_standard_limit() {
        assert_eq!(
            bitcoin_rs_mempool::standardness::MAX_STANDARD_TX_SIGOPS_COST,
            16_000,
            "POL-04 and Core 31.1 policy.h"
        );
        let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
            MempoolLimits::default(),
        )));
        let gateway = Arc::new(MempoolGateway::new(
            pool,
            None,
            ValidationEngine::Native,
            None,
        ));

        let prev = outpoint(3, 0);
        let witness_script = vec![opcode::OP_CHECKMULTISIG; 900];
        let tx = tx_one_input(
            prev,
            bitcoin_rs_consensus::script::push_data(&p2wsh_script_pubkey(&[0x42; 32])),
            vec![witness_script],
            99_000,
            P2PKH_SCRIPT.to_vec(),
        );
        let context = PackageTxContext {
            fee: 1_000,
            vsize: u32::try_from(tx.vsize()).unwrap_or(u32::MAX),
            sigop_cost: 0,
            missing_inputs: false,
        };
        let prevouts = vec![(
            prev,
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: Script::from_bytes(p2sh_script_pubkey(&[0x42; 20])),
            },
        )];
        let request = admission_request(&gateway, &tx, context, prevouts);

        let result = gateway.admit_transaction(request);

        assert_eq!(
            result,
            Err(AdmitError::Policy(AcceptanceRejectReason::TooManySigops)),
            "Core counts 20 sigops for each CHECKMULTISIG in a P2SH-wrapped P2WSH witness script, so 900 exceed the 16,000 standard cost"
        );
        assert_eq!(
            gateway.read().len(),
            0,
            "rejected tx must not enter the pool"
        );
    }

    #[test]
    fn p2wsh_sigop_cost_exceeds_standard_limit() {
        let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
            MempoolLimits::default(),
        )));
        let gateway = Arc::new(MempoolGateway::new(
            pool,
            None,
            ValidationEngine::Native,
            None,
        ));

        let prev = outpoint(4, 0);
        let witness_script = vec![opcode::OP_CHECKMULTISIG; 800];
        let tx = tx_one_input(
            prev,
            Vec::new(),
            vec![vec![0_u8; 72], witness_script],
            99_000,
            P2PKH_SCRIPT.to_vec(),
        );
        let context = PackageTxContext {
            fee: 1_000,
            vsize: u32::try_from(tx.vsize()).unwrap_or(u32::MAX),
            sigop_cost: 0,
            missing_inputs: false,
        };
        let prevouts = vec![(
            prev,
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: Script::from_bytes(p2wsh_script_pubkey(&[0x42; 32])),
            },
        )];
        let request = admission_request(&gateway, &tx, context, prevouts);

        let result = gateway.admit_transaction(request);

        assert_eq!(
            result,
            Err(AdmitError::Policy(AcceptanceRejectReason::TooManySigops)),
            "P2WSH witness sigops counted from the prevout must trigger the standard limit"
        );
        assert_eq!(
            gateway.read().len(),
            0,
            "rejected tx must not enter the pool"
        );
    }

    #[test]
    fn overlay_resolved_parent_sigops_trigger_standard_limit() -> Result<(), TestError> {
        let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
            MempoolLimits::default(),
        )));
        let gateway = Arc::new(MempoolGateway::new(
            pool,
            None,
            ValidationEngine::Native,
            None,
        ));

        let parent = tx_one_input(
            outpoint(5, 0),
            Vec::new(),
            Vec::new(),
            100_000,
            p2sh_script_pubkey(&[0x42; 20]),
        );
        let parent_txid = parent.txid();
        gateway.insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::new(parent), 100, 100_000_000, 1, 1, 0),
        )?;

        let witness_script = vec![opcode::OP_CHECKMULTISIG; 900];
        let child = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(parent_txid, 0),
                    script_sig: Script::from_bytes(bitcoin_rs_consensus::script::push_data(
                        &p2wsh_script_pubkey(&[0x42; 32]),
                    )),
                    sequence: Sequence::MAX,
                    witness: Witness::from_stack(vec![witness_script]),
                },
                TxIn {
                    previous_output: outpoint(6, 0),
                    script_sig: Script::from_bytes(true_redeem_script_sig()),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            ],
            outputs: vec![TxOut {
                value: Amount::from_sat(198_000),
                script_pubkey: Script::from_bytes(P2PKH_SCRIPT.to_vec()),
            }],
        };
        let context = PackageTxContext {
            fee: 1_000,
            vsize: u32::try_from(child.vsize()).unwrap_or(u32::MAX),
            sigop_cost: 0,
            missing_inputs: false,
        };
        let prevouts = vec![(
            outpoint(6, 0),
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: Script::from_bytes(p2sh_true_script()),
            },
        )];
        let request = admission_request(&gateway, &child, context, prevouts);

        let result = gateway.admit_transaction(request);

        assert_eq!(
            result,
            Err(AdmitError::Policy(AcceptanceRejectReason::TooManySigops)),
            "overlay-resolved P2SH-wrapped P2WSH sigops must trigger the standard limit despite the omission"
        );
        assert_eq!(
            gateway.read().len(),
            1,
            "only the parent must remain in the pool"
        );
        Ok(())
    }

    // POL-04
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test invariants are checked with expect"
    )]
    fn caller_sigop_cost_is_ignored_in_stored_entry() -> Result<(), TestError> {
        let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
            MempoolLimits::default(),
        )));
        let gateway = Arc::new(MempoolGateway::new(
            pool,
            None,
            ValidationEngine::Native,
            None,
        ));

        let prev = outpoint(5, 0);
        let tx = tx_one_input(
            prev,
            true_redeem_script_sig(),
            Vec::new(),
            99_000,
            p2sh_script_pubkey(&[0x42; 20]),
        );
        let context = PackageTxContext {
            fee: 1_000,
            vsize: u32::try_from(tx.vsize()).unwrap_or(u32::MAX),
            sigop_cost: u32::MAX,
            missing_inputs: false,
        };
        let prevouts = vec![(
            prev,
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: Script::from_bytes(p2sh_true_script()),
            },
        )];
        let request = admission_request(&gateway, &tx, context, prevouts);

        let result = gateway.admit_transaction(request)?;
        let txid = tx.txid();
        let AdmitOutcome::Committed(_) = result else {
            panic!("tx must be committed, got {result:?}");
        };

        let pool = gateway.read();
        let entry_id = pool
            .entry_id_by_txid(&txid)
            .expect("tx must be in the pool");
        let entry = pool.entry(entry_id).expect("entry must exist");
        assert_eq!(
            entry.sigop_cost, 0,
            "stored sigop cost must be the computed value, not the caller-supplied u32::MAX"
        );
        Ok(())
    }

    #[test]
    fn v3_sibling_eviction_with_empty_direct_conflicts_admits_through_the_replacement_door()
    -> Result<(), TestError> {
        let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
            MempoolLimits::default(),
        )));
        let gateway = Arc::new(MempoolGateway::new(
            pool,
            None,
            bitcoin_rs_consensus::ValidationEngine::Native,
            None,
        ));

        let parent = Tx {
            version: 3,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: outpoint(20, 0),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0xFFFF_FFFF),
                witness: Witness::new(),
            }],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(60_000),
                    script_pubkey: Script::from_bytes(p2sh_true_script()),
                },
                TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: Script::from_bytes(p2sh_true_script()),
                },
            ],
        };
        let parent_txid = parent.txid();
        gateway.insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::new(parent), 100, 1_000, 1, 1, 0),
        )?;

        let mut sibling = tx_one_input(
            OutPoint::new(parent_txid, 0),
            Vec::new(),
            Vec::new(),
            59_000,
            P2PKH_SCRIPT.to_vec(),
        );
        sibling.version = 3;
        let sibling_txid = sibling.txid();
        gateway.insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::new(sibling), 100, 1_000, 1, 1, 0),
        )?;

        let mut candidate = tx_one_input(
            OutPoint::new(parent_txid, 1),
            true_redeem_script_sig(),
            Vec::new(),
            37_000,
            P2PKH_SCRIPT.to_vec(),
        );
        candidate.version = 3;
        let candidate_txid = candidate.txid();
        let context = PackageTxContext {
            fee: 3_000,
            vsize: u32::try_from(candidate.vsize()).unwrap_or(u32::MAX),
            sigop_cost: 0,
            missing_inputs: false,
        };
        let prevouts = vec![(
            OutPoint::new(parent_txid, 1),
            TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: Script::from_bytes(p2sh_true_script()),
            },
        )];
        let request = admission_request(&gateway, &candidate, context, prevouts);

        let result = gateway.admit_transaction(request)?;
        let AdmitOutcome::Committed(changes) = result else {
            panic!("the sibling-evicting candidate must commit, got {result:?}");
        };

        let pool = gateway.read();
        assert_eq!(
            changes.removed_txids(),
            vec![sibling_txid],
            "the sibling leaves through the replacement door"
        );
        assert!(
            pool.contains_txid(&candidate_txid),
            "the candidate must be resident"
        );
        assert!(pool.contains_txid(&parent_txid), "the parent stays");
        assert!(
            !pool.contains_txid(&sibling_txid),
            "the evicted sibling must be gone"
        );
        Ok(())
    }
}
mod adversarial_mempool {
    extern crate alloc;

    use alloc::sync::Arc;

    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use bitcoin_rs_mempool::standardness::{
        AcceptanceRejectReason, MAX_PACKAGE_COUNT, MAX_PACKAGE_WEIGHT, MAX_STANDARD_TX_WEIGHT,
        StandardnessError, StandardnessPolicy, is_standard_tx,
    };
    use bitcoin_rs_mempool::{
        AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, LocalOrigin, Mempool,
        MempoolEntry, MempoolError, MempoolGateway, MempoolLimits, PolicyError, RbfError,
        ReplacementCandidate, SubmitError, SubmitOutcome, required_fee,
    };

    use super::TestError;
    use super::{p2sh_true_script, true_redeem_script_sig};

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
                next_block_script_flags: bitcoin_rs_consensus::script::VerifyFlags::STANDARD,
                confirmed: true,
            })
        }
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

        let empty_result =
            gateway.submit_local_package(Vec::new(), LocalOrigin::Rpc, None, 1, &chain);
        assert_eq!(
            empty_result.err(),
            Some(SubmitError::Policy(AcceptanceRejectReason::PackageCount))
        );

        let single = single_input_tx(40, outpoint(4, 0), 1_000);
        let duplicate_txs = vec![single.clone(), single];
        let dup_result =
            gateway.submit_local_package(duplicate_txs, LocalOrigin::Rpc, None, 1, &chain);
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
            0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88,
            0xac,
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

        let outcome1 = gateway.submit_transaction(
            Arc::new(tx1.clone()),
            AdmissionOrigin::Rpc,
            None,
            1,
            &chain,
        )?;
        assert!(matches!(outcome1, SubmitOutcome::Committed(_)));
        assert!(gateway.read().contains_txid(&tx1_id));

        let tx2_low = single_input_tx(82, common_prev, 900);
        let outcome2 =
            gateway.submit_transaction(Arc::new(tx2_low), AdmissionOrigin::Rpc, None, 1, &chain);
        assert!(outcome2.is_err());
        assert!(gateway.read().contains_txid(&tx1_id));

        let tx2_high = single_input_tx(83, common_prev, 3_000);
        let tx2_high_id = tx2_high.txid();
        let outcome3 = gateway.submit_transaction(
            Arc::new(tx2_high),
            AdmissionOrigin::Rpc,
            None,
            1,
            &chain,
        )?;
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
}
mod graph_limits {
    #![allow(clippy::expect_used)]

    extern crate alloc;

    use super::TestError;
    use alloc::sync::Arc;

    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolError, MempoolLimits, PolicyError};

    #[test]
    fn cluster_weight_preserves_fractional_vbytes_at_the_exact_boundary() -> Result<(), TestError> {
        fn weighted(mut tx: Tx, target: u64) -> Tx {
            let padding = usize::try_from(target - tx.weight() - 4).expect("small padding");
            assert!(padding < 253);
            tx.inputs[0].witness = Witness::from_stack(vec![vec![0; padding]]);
            tx
        }
        for child_weight in [403, 404] {
            let mut pool = Mempool::new(MempoolLimits {
                cluster_size_vbytes: 201,
                ..MempoolLimits::default()
            });
            let parent = weighted(chained_tx(2, outpoint(1, 0)), 401);
            let child = weighted(chained_tx(3, OutPoint::new(parent.txid(), 0)), child_weight);
            for (tx, weight) in [(&parent, 401), (&child, child_weight)] {
                let oracle: bitcoin::Transaction = bitcoin::consensus::deserialize(
                    &bitcoin_rs_consensus::primitives::consensus_bytes(tx),
                )?;
                assert_eq!(oracle.weight().to_wu(), weight);
                assert_eq!(oracle.vsize(), 101);
            }
            pool.insert_entry(MempoolEntry::new(Arc::new(parent), 101, 1_000, 0, 1, 0))?;
            let before = pool.sequence_number();
            let result = pool.insert_entry(MempoolEntry::new(Arc::new(child), 101, 1_000, 0, 1, 0));
            if child_weight == 403 {
                result?;
                assert_eq!(
                    pool.total_vsize(),
                    202,
                    "rounded entry sizes exceed the exact 201-vB component weight"
                );
                assert_eq!(pool.len(), 2);
            } else {
                assert_eq!(
                    result.err(),
                    Some(MempoolError::Policy(PolicyError::ClusterSizeLimit))
                );
                assert_eq!(pool.sequence_number(), before);
                assert_eq!(pool.len(), 1);
            }
        }
        Ok(())
    }

    #[test]
    fn chain_accepts_sixty_four_and_rejects_the_next_cluster_member() -> Result<(), TestError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let mut previous = outpoint(1, 0);

        for height in 0_u32..64 {
            let label = u8::try_from(height + 2)?;
            let tx = chained_tx(label, previous);
            previous = OutPoint::new(tx.txid(), 0);
            pool.insert_entry(MempoolEntry::new(
                Arc::new(tx),
                1_000,
                4_000,
                u64::from(height),
                1,
                0,
            ))?;
        }

        let rejected = chained_tx(100, previous);
        let err = pool
            .insert_entry(MempoolEntry::new(
                Arc::new(rejected),
                1_000,
                4_000,
                65,
                1,
                0,
            ))
            .err();

        assert_eq!(
            err,
            Some(MempoolError::Policy(PolicyError::ClusterCountLimit))
        );
        assert_eq!(pool.len(), 64);

        Ok(())
    }

    #[test]
    fn rpc_graph_facts_are_transitive_and_aggregates_are_inclusive() -> Result<(), TestError> {
        let mut pool = Mempool::new(MempoolLimits::default());

        let root = chained_tx(50, outpoint(49, 0));
        let root_txid = root.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(root), 100, 1_000, 1, 1, 0))?;
        let root_id = pool.entry_id_by_txid(&root_txid).ok_or("missing root id")?;

        let child = chained_tx(51, OutPoint::new(root_txid, 0));
        let child_txid = child.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 200, 3_000, 2, 1, 0))?;
        let child_id = pool
            .entry_id_by_txid(&child_txid)
            .ok_or("missing child id")?;

        let grandchild = chained_tx(52, OutPoint::new(child_txid, 0));
        let grandchild_txid = grandchild.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(grandchild), 300, 6_000, 3, 1, 0))?;
        let grandchild_id = pool
            .entry_id_by_txid(&grandchild_txid)
            .ok_or("missing grandchild id")?;

        assert_eq!(
            pool.ancestor_ids_for_entry(grandchild_id),
            vec![root_id, child_id]
        );
        assert_eq!(
            pool.descendant_ids_for_entry(root_id),
            vec![child_id, grandchild_id]
        );
        assert_eq!(pool.ancestor_count_inclusive(grandchild_id), 3);
        assert_eq!(pool.descendant_count_inclusive(root_id), 3);
        assert_eq!(pool.spender_txids(root_id), vec![child_txid]);
        assert_eq!(pool.spender_txids(child_id), vec![grandchild_txid]);

        let root_entry = pool.entry(root_id).ok_or("missing root entry")?;
        assert_eq!(
            (root_entry.descendant_size, root_entry.descendant_fee),
            (600, 10_000)
        );
        let grandchild_entry = pool
            .entry(grandchild_id)
            .ok_or("missing grandchild entry")?;
        assert_eq!(
            (
                grandchild_entry.ancestor_size,
                grandchild_entry.ancestor_fee
            ),
            (600, 10_000)
        );

        Ok(())
    }

    #[test]
    fn cluster_limit_rejects_the_sixty_fifth_fanout_member() -> Result<(), TestError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let parent_tx = multi_output_tx(70, 64);
        let parent_txid = parent_tx.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(parent_tx), 100, 1_000, 1, 1, 0))?;

        for vout in 0_u32..63 {
            let child = chained_tx(u8::try_from(vout + 71)?, OutPoint::new(parent_txid, vout));
            pool.insert_entry(MempoolEntry::new(
                Arc::new(child),
                100,
                1_000,
                u64::from(vout) + 2,
                1,
                0,
            ))?;
        }
        assert_eq!(pool.len(), 64);

        let rejected = chained_tx(200, OutPoint::new(parent_txid, 63));
        let err = pool
            .insert_entry(MempoolEntry::new(Arc::new(rejected), 100, 1_000, 30, 1, 0))
            .err();
        assert_eq!(
            err,
            Some(MempoolError::Policy(PolicyError::ClusterCountLimit))
        );
        Ok(())
    }

    #[test]
    fn raw_pool_view_and_entry_metadata_facts() -> Result<(), TestError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let before = pool.sequence_number();
        let tx = chained_tx(80, outpoint(79, 0));
        let txid = tx.txid();
        let entry = MempoolEntry::new(Arc::new(tx), 150, 3_000, 9, 42, 17);
        pool.insert_entry(entry)?;

        assert!(pool.sequence_number() > before);
        assert_eq!(pool.iter_txids(), vec![txid]);
        let stats = pool.stats();
        assert_eq!((stats.txs, stats.bytes, stats.total_fee), (1, 150, 3_000));
        let loaded = pool.entry_by_txid(&txid).ok_or("missing entry")?;
        assert_eq!(loaded.sigop_cost, 17);
        assert_eq!(loaded.fee, 3_000);
        Ok(())
    }

    #[test]
    fn fee_estimate_access_reuses_pool_owned_estimator() -> Result<(), TestError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        assert_eq!(pool.estimate_fee_rate(2), None);

        let first = chained_tx(81, outpoint(80, 0));
        let second = chained_tx(82, outpoint(81, 0));
        pool.insert_entry(MempoolEntry::new(
            Arc::new(first.clone()),
            100,
            10_000,
            1,
            7,
            0,
        ))?;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(second.clone()),
            100,
            10_000,
            1,
            7,
            0,
        ))?;
        assert_eq!(pool.estimate_fee_rate(2), None);

        pool.remove_for_block(
            &bitcoin_rs_mempool::TransitionFacts::from_txs(&[&first, &second]),
            8,
            1,
        );
        assert!(pool.estimate_fee_rate(2).is_some());
        Ok(())
    }

    fn multi_output_tx(label: u8, outputs: u32) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: outpoint(label, 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: (0..outputs)
                .map(|vout| TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: vec![
                        0x51,
                        label,
                        u8::try_from(vout).expect("fixture vout fits u8"),
                    ]
                    .into(),
                })
                .collect(),
        }
    }

    fn chained_tx(label: u8, previous_output: OutPoint) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x51, label].into(),
            }],
        }
    }

    fn outpoint(label: u8, vout: u32) -> OutPoint {
        let mut bytes = [0_u8; 32];
        bytes[0] = label;
        OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), vout)
    }
}
mod policy_contract {
    #![deny(clippy::expect_used)]

    extern crate alloc;

    use super::TestError;
    use super::{p2sh_true_script, true_redeem_script_sig};
    use alloc::sync::Arc;
    use bitcoin_rs_consensus::ValidationEngine;

    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use bitcoin_rs_consensus::script::opcode;
    use bitcoin_rs_mempool::standardness::{
        AcceptanceRejectReason, StandardnessError, StandardnessPolicy, is_standard_tx,
    };
    use bitcoin_rs_mempool::{
        AdmissionChain, ChainAdmissionSnapshot, Mempool, MempoolEntry, MempoolError,
        MempoolGateway, MempoolLimits, MutationOutcome, PolicyError, PrevoutMeta, RbfError,
        RemovalReason, ReplacementCandidate,
    };
    use parking_lot::RwLock;

    const DUST_RELAY_FEE_SAT_PER_KVB: u64 = 3_000;

    fn policy() -> StandardnessPolicy {
        StandardnessPolicy {
            dust_relay_fee: DUST_RELAY_FEE_SAT_PER_KVB,
            max_datacarrier_bytes: Some(83),
        }
    }

    struct EmptyChain;

    impl AdmissionChain for EmptyChain {
        fn snapshot(&self, _tx: &Tx) -> Option<ChainAdmissionSnapshot> {
            Some(ChainAdmissionSnapshot::default())
        }
    }

    fn p2wpkh_script() -> Vec<u8> {
        let mut script = vec![opcode::OP_0, 0x14];
        script.extend([0x11_u8; 20]);
        script
    }

    fn op_true_script() -> Vec<u8> {
        vec![0x51]
    }

    fn outpoint(label: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid::from(Hash256::from_le_bytes(&[label; 32])), vout)
    }

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
                    script_sig: Script::from_bytes(true_redeem_script_sig()),
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
    fn below_min_relay_fee_rejects_at_the_same_floor() -> Result<(), TestError> {
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
    fn configured_min_relay_floor_overrides_the_default() -> Result<(), TestError> {
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

    struct ConflictFixture {
        pool: Mempool,
        original: Tx,
        child: Tx,
    }

    fn conflict_pool(signaling: bool) -> Result<ConflictFixture, TestError> {
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

    // POL-05
    #[test]
    fn rbf_replacement_sweeps_nonsignaling_conflicts_and_descendants() -> Result<(), TestError> {
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
    fn rbf_rule3_replacement_must_pay_evicted_fees() -> Result<(), TestError> {
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
    fn replacement_with_equal_direct_rate_can_improve_the_full_diagram() -> Result<(), TestError> {
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
    fn replacement_may_add_an_unconfirmed_input() -> Result<(), TestError> {
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
    fn cluster_count_limit_rejects_a_sibling_that_ancestors_would_admit() -> Result<(), TestError> {
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
    fn cluster_size_limit_rejects() -> Result<(), TestError> {
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
    fn replacement_into_a_full_cluster_is_allowed() -> Result<(), TestError> {
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
    fn oversized_weight_is_not_standard() {
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
    fn nonstandard_output_script_is_not_standard() {
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
    fn missing_inputs_fact_is_reported_by_the_preview() -> Result<(), TestError> {
        let pool = Mempool::new(MempoolLimits::default());
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(pool)),
            None,
            ValidationEngine::Native,
            None,
        );
        let orphan = tx(outpoint(200, 0), 1_000, 0xFF_FF_FF_FF);
        let facts = gateway.preview_transactions(&[orphan], None, &EmptyChain)?;
        let fact = facts.results.first().ok_or("expected one fact row")?;
        assert_eq!(
            fact.reject_reason,
            Some(AcceptanceRejectReason::MissingInputs)
        );
        Ok(())
    }

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
                next_block_script_flags: bitcoin_rs_consensus::script::VerifyFlags::STANDARD,
                confirmed: false,
            })
        }
    }

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

    // POL-06
    #[test]
    fn preview_reports_relative_locks_and_coinbase_maturity() -> Result<(), TestError> {
        let pool = Mempool::new(MempoolLimits::default());
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(pool)),
            None,
            ValidationEngine::Native,
            None,
        );
        for case in relative_lock_cases() {
            let spendable = TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes(p2sh_true_script()),
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
    fn bip68_unconfirmed_parent_positive_relative_lock_fails() -> Result<(), TestError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let parent = tx_multi(
            &[(outpoint(48, 0), 0xFF_FF_FF_FF)],
            10_000,
            p2sh_true_script(),
        );
        let parent_outpoint = OutPoint::new(parent.txid(), 0);
        pool.insert_entry(entry(parent, 250, 3_000))?;
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(pool)),
            None,
            ValidationEngine::Native,
            None,
        );
        let child = tx_multi(
            &[(parent_outpoint, 1), (outpoint(47, 0), 0xFF_FF_FF_FF)],
            9_000,
            p2wpkh_script(),
        );
        let coin = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(p2sh_true_script()),
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
    fn size_limit_eviction_removes_the_lowest_fee_package_first() -> Result<(), TestError> {
        let limits = MempoolLimits {
            max_total_bytes: 3 * unit(),
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

    fn unit() -> u64 {
        bitcoin_rs_mempool::entry_memory_usage(&tx(outpoint(1, 0), 1_000, 0xFF_FF_FF_FF))
    }

    const T0: u64 = 1_700_000_000;

    const HALF_LIFE_SECS: u64 = 12 * 60 * 60;

    const CAPACITY_EVICTION: MutationOutcome =
        MutationOutcome::Removed(RemovalReason::PolicyEviction);

    const SPEND_OUTPUT_SATS: u64 = 10_000;

    fn spend_vsize() -> u64 {
        tx(outpoint(1, 0), SPEND_OUTPUT_SATS, 0xFF_FF_FF_FF).vsize()
    }

    fn spend_fee_at(rate: u64) -> u64 {
        rate * spend_vsize() / 1_000
    }

    fn preview_spend(
        gateway: &MempoolGateway,
        tag: u8,
        fee: u64,
    ) -> Result<Option<AcceptanceRejectReason>, TestError> {
        let coin = TxOut {
            value: Amount::from_sat(SPEND_OUTPUT_SATS + fee),
            script_pubkey: Script::from_bytes(p2sh_true_script()),
        };
        let chain = meta_chain(
            12,
            0,
            true,
            outpoint(tag, 0),
            coin,
            PrevoutMeta {
                height: 10,
                mtp: 0,
                coinbase: false,
            },
        );
        let spend = tx(outpoint(tag, 0), SPEND_OUTPUT_SATS, 0xFF_FF_FF_FF);
        let facts = gateway.preview_transactions(&[spend], None, &chain)?;
        Ok(facts
            .results
            .first()
            .ok_or("expected one fact row")?
            .reject_reason)
    }

    fn gateway_over(pool: Mempool) -> MempoolGateway {
        MempoolGateway::new(
            Arc::new(RwLock::new(pool)),
            None,
            ValidationEngine::Native,
            None,
        )
    }

    fn pool_after_capacity_eviction(evicted_rate: u64) -> Result<Mempool, TestError> {
        let wide = |label: u8| {
            let mut wide = tx(outpoint(label, 0), 1_000, 0xFF_FF_FF_FF);
            wide.outputs[0].script_pubkey =
                Script::from_bytes(vec![0x51; usize::try_from(unit()).unwrap_or(0)]);
            wide
        };
        let limits = MempoolLimits {
            max_total_bytes: 2 * unit()
                + bitcoin_rs_mempool::entry_memory_usage(&wide(3))
                + unit() / 4,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);
        pool.insert_entry(entry(
            tx(outpoint(1, 0), 1_000, 0xFF_FF_FF_FF),
            1_000,
            3 * evicted_rate,
        ))?;
        pool.insert_entry(entry(
            tx(outpoint(2, 0), 1_000, 0xFF_FF_FF_FF),
            1_000,
            2 * evicted_rate,
        ))?;
        let evicted = wide(3);
        let evicted_txid = txid(&evicted);
        pool.insert_entry(entry(evicted, 2_000, 2 * evicted_rate))?;
        assert_eq!(pool.total_vsize(), 4_000, "the pool is exactly full");

        let overflow = tx(outpoint(4, 0), 1_000, 0xFF_FF_FF_FF);
        let result = pool.insert_entry(entry(overflow, 1_000, 6 * evicted_rate))?;
        let evicted_for_capacity: Vec<_> = result
            .changes
            .iter()
            .filter(|change| change.outcome == CAPACITY_EVICTION)
            .map(|change| change.txid)
            .collect();
        assert_eq!(
            evicted_for_capacity,
            vec![evicted_txid],
            "the cheapest package, and only it, leaves for capacity"
        );
        assert_eq!(pool.total_vsize(), 3_000);
        Ok(pool)
    }

    #[test]
    fn mempool_min_fee_stays_at_the_relay_floor_while_nothing_has_been_evicted()
    -> Result<(), TestError> {
        let limits = MempoolLimits {
            max_total_bytes: 4 * unit(),
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);
        for (label, fee) in [(1, 1_000), (2, 2_000), (3, 3_000)] {
            pool.insert_entry(entry(
                tx(outpoint(label, 0), 1_000, 0xFF_FF_FF_FF),
                1_000,
                fee,
            ))?;
        }
        assert_eq!(pool.total_vsize(), 3_000);
        let relay_floor = pool.min_relay_fee_sat_per_kvb();
        assert_eq!(pool.min_fee_sat_per_kvb(T0), relay_floor);

        let gateway = gateway_over(pool);
        assert_eq!(
            preview_spend(&gateway, 0x31, spend_fee_at(relay_floor))?,
            None,
            "a crowded pool that has evicted nothing admits at the relay floor"
        );
        Ok(())
    }

    #[test]
    fn mempool_min_fee_remembers_a_capacity_eviction_and_the_preview_enforces_it()
    -> Result<(), TestError> {
        const EVICTED_RATE: u64 = 1_000;
        let pool = pool_after_capacity_eviction(EVICTED_RATE)?;
        let relay_floor = pool.min_relay_fee_sat_per_kvb();

        let floor = pool.min_fee_sat_per_kvb(T0);
        assert_eq!(
            floor,
            EVICTED_RATE + pool.policy_snapshot().incremental_relay_fee_sat_per_kvb
        );
        assert!(floor > relay_floor, "the eviction raised the floor");

        let gateway = gateway_over(pool);
        let required = spend_fee_at(floor);
        assert!(
            required > spend_fee_at(relay_floor),
            "the failing fee clears the configured relay floor, so only the rolling floor can refuse it"
        );
        assert_eq!(
            preview_spend(&gateway, 0x32, required - 1)?,
            Some(AcceptanceRejectReason::MinRelayFeeNotMet),
            "one satoshi under the rolling floor"
        );
        assert_eq!(
            preview_spend(&gateway, 0x33, required)?,
            None,
            "exactly at the rolling floor"
        );
        Ok(())
    }

    #[test]
    fn mempool_min_fee_holds_until_a_block_connects_then_halves_each_half_life()
    -> Result<(), TestError> {
        const EVICTED_RATE: u64 = 7_000;
        let mut pool = pool_after_capacity_eviction(EVICTED_RATE)?;
        let floor = EVICTED_RATE + pool.policy_snapshot().incremental_relay_fee_sat_per_kvb;

        assert_eq!(pool.min_fee_sat_per_kvb(T0), floor);
        assert_eq!(pool.min_fee_sat_per_kvb(T0 + 30 * 24 * 60 * 60), floor);

        pool.remove_for_block(&bitcoin_rs_mempool::TransitionFacts::from_txs(&[]), 2, T0);
        assert_eq!(pool.min_fee_sat_per_kvb(T0), floor);
        assert_eq!(pool.min_fee_sat_per_kvb(T0 + HALF_LIFE_SECS), floor / 2);
        assert_eq!(pool.min_fee_sat_per_kvb(T0 + 2 * HALF_LIFE_SECS), floor / 4);
        Ok(())
    }
}
mod rbf_bip125 {
    #![allow(clippy::expect_used)]

    extern crate alloc;

    use super::TestError;
    use alloc::sync::Arc;

    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use bitcoin_rs_mempool::{
        Mempool, MempoolEntry, MempoolError, MempoolLimits, MempoolStats, PolicyError, RbfError,
        ReplacementCandidate,
    };

    #[derive(Clone, Copy)]
    struct OriginalSpec {
        sequence: u32,
        fee: u64,
        vsize: u32,
    }

    #[derive(Clone, Copy)]
    struct ReplacementSpec {
        fee: u64,
        vsize: u32,
        min_relay_fee_rate: u64,
        new_unconfirmed_input: bool,
        extra_descendants: u16,
    }

    struct Case {
        name: &'static str,
        original: OriginalSpec,
        replacement: ReplacementSpec,
        expected: Result<(), RbfError>,
    }

    const CASES: [Case; 9] = [
        Case {
            name: "accepts direct opt-in replacement",
            original: OriginalSpec {
                sequence: 0xFFFF_FFFD,
                fee: 1_000,
                vsize: 100,
            },
            replacement: ReplacementSpec {
                fee: 1_200,
                vsize: 100,
                min_relay_fee_rate: 1,
                new_unconfirmed_input: false,
                extra_descendants: 0,
            },
            expected: Ok(()),
        },
        Case {
            name: "accepts non-signaling originals",
            original: OriginalSpec {
                sequence: 0xFFFF_FFFF,
                fee: 1_000,
                vsize: 100,
            },
            replacement: ReplacementSpec {
                fee: 1_200,
                vsize: 100,
                min_relay_fee_rate: 1,
                new_unconfirmed_input: false,
                extra_descendants: 0,
            },
            expected: Ok(()),
        },
        Case {
            name: "accepts originals at the non-signaling sequence boundary",
            original: OriginalSpec {
                sequence: 0xFFFF_FFFE,
                fee: 1_000,
                vsize: 100,
            },
            replacement: ReplacementSpec {
                fee: 1_200,
                vsize: 100,
                min_relay_fee_rate: 1,
                new_unconfirmed_input: false,
                extra_descendants: 0,
            },
            expected: Ok(()),
        },
        Case {
            name: "cannot spend an evicted parent",
            original: OriginalSpec {
                sequence: 0xFFFF_FFFD,
                fee: 1_000,
                vsize: 100,
            },
            replacement: ReplacementSpec {
                fee: 1_200,
                vsize: 100,
                min_relay_fee_rate: 1,
                new_unconfirmed_input: true,
                extra_descendants: 0,
            },
            expected: Err(RbfError::Mempool(MempoolError::EvictedParent)),
        },
        Case {
            name: "rule 3 requires replacement to pay original absolute fees",
            original: OriginalSpec {
                sequence: 0xFFFF_FFFF,
                fee: 1_000,
                vsize: 100,
            },
            replacement: ReplacementSpec {
                fee: 999,
                vsize: 100,
                min_relay_fee_rate: 1,
                new_unconfirmed_input: false,
                extra_descendants: 0,
            },
            expected: Err(RbfError::Rule3InsufficientAbsoluteFee),
        },
        Case {
            name: "rule 4 requires incremental relay fee",
            original: OriginalSpec {
                sequence: 0xFFFF_FFFE,
                fee: 1_000,
                vsize: 100,
            },
            replacement: ReplacementSpec {
                fee: 1_050,
                vsize: 100,
                min_relay_fee_rate: 1_000,
                new_unconfirmed_input: false,
                extra_descendants: 0,
            },
            expected: Err(RbfError::Rule4InsufficientIncrementalFee),
        },
        Case {
            name: "many victims in one conflicting cluster are allowed",
            original: OriginalSpec {
                sequence: 0xFFFF_FFFD,
                fee: 1_000,
                vsize: 100,
            },
            replacement: ReplacementSpec {
                fee: 12_000,
                vsize: 100,
                min_relay_fee_rate: 1,
                new_unconfirmed_input: false,
                extra_descendants: 100,
            },
            expected: Ok(()),
        },
        Case {
            name: "fee diagram must strictly improve",
            original: OriginalSpec {
                sequence: 0xFFFF_FFFD,
                fee: 2_000,
                vsize: 100,
            },
            replacement: ReplacementSpec {
                fee: 2_001,
                vsize: 200,
                min_relay_fee_rate: 1,
                new_unconfirmed_input: false,
                extra_descendants: 0,
            },
            expected: Err(RbfError::InsufficientFeerateDiagram),
        },
        Case {
            name: "accepts an original with an unconfirmed parent",
            original: OriginalSpec {
                sequence: 0xFFFF_FFFF,
                fee: 1_000,
                vsize: 100,
            },
            replacement: ReplacementSpec {
                fee: 1_300,
                vsize: 100,
                min_relay_fee_rate: 1,
                new_unconfirmed_input: false,
                extra_descendants: 0,
            },
            expected: Ok(()),
        },
    ];

    #[test]
    fn retained_replacement_rules_are_enforced() -> Result<(), TestError> {
        for case in CASES {
            let has_parent = case.name == "accepts an original with an unconfirmed parent";
            let (pool, replacement_tx) =
                pool_with_conflict(case.original, case.replacement, has_parent)?;
            let candidate = ReplacementCandidate::new(
                Arc::new(replacement_tx),
                case.replacement.vsize,
                case.replacement.fee,
                case.replacement.min_relay_fee_rate,
            );
            let actual = pool.check_replacement(&candidate).map(|_| ());
            assert_eq!(actual, case.expected, "{}", case.name);
        }

        Ok(())
    }

    #[test]
    fn replacements_accept_mixed_signaling_conflicts() -> Result<(), TestError> {
        const RBF_SEQUENCE: u32 = 0xffff_fffd;
        const FINAL_SEQUENCE: u32 = 0xffff_ffff;
        for second_sequence in [RBF_SEQUENCE, 0xffff_fffe, FINAL_SEQUENCE] {
            let mut pool = Mempool::new(MempoolLimits::default());
            let first_input = outpoint(1, 0);
            let second_input = outpoint(2, 0);

            let opt_in = tx_from_inputs(20, &[(first_input, RBF_SEQUENCE)], 1);
            pool.insert_entry(MempoolEntry::new(Arc::new(opt_in), 100, 1_000, 1, 1, 0))?;
            let other = tx_from_inputs(21, &[(second_input, second_sequence)], 1);
            pool.insert_entry(MempoolEntry::new(Arc::new(other), 100, 1_000, 2, 1, 0))?;

            let replacement = tx_from_inputs(
                40,
                &[
                    (first_input, FINAL_SEQUENCE),
                    (second_input, FINAL_SEQUENCE),
                ],
                1,
            );
            let candidate = ReplacementCandidate::new(Arc::new(replacement), 200, 10_000, 1);

            assert_eq!(
                pool.check_replacement(&candidate).map(|_| ()),
                Ok(()),
                "second original sequence {second_sequence:#x}"
            );
        }
        Ok(())
    }

    fn pool_with_conflict(
        original: OriginalSpec,
        replacement: ReplacementSpec,
        has_parent: bool,
    ) -> Result<(Mempool, Tx), TestError> {
        let limits = if replacement.extra_descendants == 0 {
            MempoolLimits::default()
        } else {
            MempoolLimits {
                cluster_count: 400,
                cluster_size_vbytes: 1_000_000,
                ..MempoolLimits::default()
            }
        };
        let mut pool = Mempool::new(limits);
        let external_input = outpoint(1, 0);
        let mut original_input = external_input;

        if has_parent {
            let parent = tx_from_inputs(10, &[(outpoint(9, 0), 0xFFFF_FFFF)], 1);
            original_input = OutPoint::new(parent.txid(), 0);
            pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 500, 1, 1, 0))?;
        }

        let original_tx = tx_from_inputs(20, &[(original_input, original.sequence)], 1);
        let original_txid = original_tx.txid();
        pool.insert_entry(MempoolEntry::new(
            Arc::new(original_tx),
            original.vsize,
            original.fee,
            2,
            1,
            0,
        ))?;

        let mut last_parent = OutPoint::new(original_txid, 0);
        for i in 0..replacement.extra_descendants {
            let label = u8::try_from(i % 200)? + 30;
            let child = tx_from_inputs(label, &[(last_parent, 0xFFFF_FFFF)], 1);
            last_parent = OutPoint::new(child.txid(), 0);
            pool.insert_entry(MempoolEntry::new(
                Arc::new(child),
                50,
                100,
                u64::from(i) + 3,
                1,
                0,
            ))?;
        }

        let mut inputs = vec![(external_input, 0xFFFF_FFFD)];
        if has_parent {
            inputs[0] = (original_input, 0xFFFF_FFFD);
        }
        if replacement.new_unconfirmed_input {
            inputs.push((OutPoint::new(original_txid, 0), 0xFFFF_FFFD));
        }
        let replacement_tx = tx_from_inputs(40, &inputs, 1);

        Ok((pool, replacement_tx))
    }

    fn tx_from_inputs(label: u8, inputs: &[(OutPoint, u32)], outputs: usize) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: inputs
                .iter()
                .map(|(previous_output, sequence)| TxIn {
                    previous_output: *previous_output,
                    script_sig: Script::new(),
                    sequence: Sequence::from_consensus(*sequence),
                    witness: Witness::new(),
                })
                .collect(),
            outputs: (0..outputs)
                .map(|i| TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: vec![0x51, label, u8::try_from(i).unwrap_or(0)].into(),
                })
                .collect(),
        }
    }

    fn outpoint(label: u8, vout: u32) -> OutPoint {
        let mut bytes = [0_u8; 32];
        bytes[0] = label;
        OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), vout)
    }

    #[test]
    fn replace_transaction_leaves_only_the_replacement() -> Result<(), TestError> {
        let (mut pool, replacement_tx) = pool_with_conflict(
            OriginalSpec {
                sequence: 0xFFFF_FFFD,
                fee: 1_000,
                vsize: 100,
            },
            ReplacementSpec {
                fee: 1_200,
                vsize: 100,
                min_relay_fee_rate: 1,
                new_unconfirmed_input: false,
                extra_descendants: 0,
            },
            false,
        )?;
        let original_txid = pool
            .iter_txids()
            .into_iter()
            .next()
            .ok_or("original missing")?;
        let replacement_txid = replacement_tx.txid();
        let candidate = ReplacementCandidate::new(Arc::new(replacement_tx), 100, 1_200, 1);
        let _id = pool.replace_transaction(&candidate.with_sigop_cost(4), 10, 1)?;
        assert!(pool.contains_txid(&replacement_txid));
        assert!(!pool.contains_txid(&original_txid));
        assert_eq!(pool.len(), 1);
        Ok(())
    }

    type PoolFingerprint = (Vec<(Txid, u64, u32, i64)>, MempoolStats, u64);

    fn pool_fingerprint(pool: &Mempool) -> PoolFingerprint {
        let mut entries = pool
            .iter_txids()
            .into_iter()
            .map(|txid| {
                let entry = pool
                    .entry_by_txid(&txid)
                    .expect("txid indexed by iter_txids");
                (txid, entry.fee, entry.vsize, entry.fee_delta)
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|(txid, ..)| *txid);
        (entries, pool.stats(), pool.sequence_number())
    }

    #[test]
    fn replace_transaction_rejection_preserves_pool_state() -> Result<(), TestError> {
        {
            let mut pool = Mempool::new(MempoolLimits::default());
            let original = tx_from_inputs(20, &[(outpoint(1, 0), 0xFFFF_FFFD)], 1);
            pool.insert_entry(MempoolEntry::new(Arc::new(original), 300, 1_000, 2, 1, 0))?;
            pool.limits.min_relay_fee_sat_per_kvb = 5_000;
            let replacement = tx_from_inputs(40, &[(outpoint(1, 0), 0xFFFF_FFFD)], 1);
            let before = pool_fingerprint(&pool);
            let err = pool
                .replace_transaction(
                    &ReplacementCandidate::new(Arc::new(replacement), 300, 1_300, 1)
                        .with_sigop_cost(4),
                    10,
                    1,
                )
                .expect_err("below-floor replacement must fail");
            assert_eq!(
                err,
                RbfError::Mempool(MempoolError::Policy(PolicyError::BelowMinRelayFee {
                    tx_rate: 4_333,
                    min_rate: 5_000,
                }))
            );
            assert_eq!(pool_fingerprint(&pool), before);
        }

        {
            let mut pool = Mempool::new(MempoolLimits::default());
            let conflict1 = tx_from_inputs(10, &[(outpoint(1, 0), 0xFFFF_FFFD)], 1);
            let conflict1_txid = conflict1.txid();
            pool.insert_entry(MempoolEntry::new(Arc::new(conflict1), 100, 500, 1, 1, 0))?;
            let parent = tx_from_inputs(11, &[(OutPoint::new(conflict1_txid, 0), 0xFFFF_FFFF)], 1);
            let parent_txid = parent.txid();
            pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 500, 2, 1, 0))?;
            let conflict2 = tx_from_inputs(12, &[(OutPoint::new(parent_txid, 0), 0xFFFF_FFFD)], 1);
            pool.insert_entry(MempoolEntry::new(Arc::new(conflict2), 100, 500, 3, 1, 0))?;
            let replacement = tx_from_inputs(
                40,
                &[
                    (outpoint(1, 0), 0xFFFF_FFFD),
                    (OutPoint::new(parent_txid, 0), 0xFFFF_FFFD),
                ],
                1,
            );
            let before = pool_fingerprint(&pool);
            let err = pool
                .replace_transaction(
                    &ReplacementCandidate::new(Arc::new(replacement), 100, 2_000, 1)
                        .with_sigop_cost(4),
                    10,
                    1,
                )
                .expect_err("spending an evicted parent must fail");
            assert_eq!(err, RbfError::Mempool(MempoolError::EvictedParent));
            assert_eq!(pool_fingerprint(&pool), before);
        }

        for case in CASES.iter().filter(|case| case.expected.is_err()) {
            let (mut pool, replacement_tx) =
                pool_with_conflict(case.original, case.replacement, false)?;
            let before = pool_fingerprint(&pool);
            let err = pool
                .replace_transaction(
                    &ReplacementCandidate::new(
                        Arc::new(replacement_tx),
                        case.replacement.vsize,
                        case.replacement.fee,
                        case.replacement.min_relay_fee_rate,
                    )
                    .with_sigop_cost(4),
                    10,
                    1,
                )
                .expect_err(case.name);
            assert_eq!(Err(err), case.expected, "{}", case.name);
            assert_eq!(pool_fingerprint(&pool), before, "{}", case.name);
        }
        Ok(())
    }

    #[test]
    fn replace_transaction_cluster_limits_use_post_eviction_projection() -> Result<(), TestError> {
        let mut pool = Mempool::new(MempoolLimits {
            cluster_count: 25,
            ..MempoolLimits::default()
        });
        let parent = tx_from_inputs(10, &[(outpoint(1, 0), 0xFFFF_FFFD)], 24);
        let parent_txid = parent.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 1, 1, 0))?;
        for i in 0..23_u32 {
            let child = tx_from_inputs(
                u8::try_from(30 + i)?,
                &[(OutPoint::new(parent_txid, i), 0xFFFF_FFFF)],
                1,
            );
            pool.insert_entry(MempoolEntry::new(
                Arc::new(child),
                50,
                100,
                u64::from(i) + 2,
                1,
                0,
            ))?;
        }
        let conflict = tx_from_inputs(60, &[(OutPoint::new(parent_txid, 23), 0xFFFF_FFFD)], 1);
        pool.insert_entry(MempoolEntry::new(Arc::new(conflict), 50, 100, 30, 1, 0))?;
        let replacement = tx_from_inputs(40, &[(OutPoint::new(parent_txid, 23), 0xFFFF_FFFD)], 1);
        let replacement_txid = replacement.txid();
        let _id = pool.replace_transaction(
            &ReplacementCandidate::new(Arc::new(replacement), 50, 300, 1).with_sigop_cost(4),
            40,
            1,
        )?;
        assert!(pool.contains_txid(&replacement_txid));
        assert_eq!(pool.len(), 25);
        Ok(())
    }
}
mod replacement_profile {
    use super::TestError;
    use std::sync::Arc;

    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use bitcoin_rs_mempool::{
        Mempool, MempoolEntry, MempoolError, MempoolLimits, RbfError, ReplacementCandidate,
    };

    fn coin(tag: u32) -> OutPoint {
        let mut hash = [0_u8; 32];
        hash[..4].copy_from_slice(&tag.to_le_bytes());
        OutPoint::new(Txid(Hash256::from_le_bytes(&hash)), 0)
    }

    fn spend(tag: u32, inputs: &[OutPoint], outputs: usize) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: inputs
                .iter()
                .map(|&previous_output| TxIn {
                    previous_output,
                    script_sig: Script::from_bytes(tag.to_le_bytes().to_vec()),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            outputs: (0..outputs)
                .map(|_| TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: Script::from_bytes([vec![0, 20], vec![1; 20]].concat()),
                })
                .collect(),
        }
    }

    fn pool() -> Mempool {
        Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        })
    }

    fn entry(tx: Tx, fee: u64) -> MempoolEntry {
        let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
        MempoolEntry::new(Arc::new(tx), vsize, fee, 1, 1, 0)
    }

    fn candidate(tx: Tx, fee: u64) -> ReplacementCandidate {
        let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
        ReplacementCandidate::new(Arc::new(tx), vsize, fee, 1_000)
    }

    #[test]
    fn a_higher_direct_rate_and_total_fee_can_still_worsen_the_curve() -> Result<(), TestError> {
        let mut pool = pool();
        let parent = spend(1, &[coin(100)], 1);
        let parent_id = parent.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 0, 1, 1, 0))?;
        let child = spend(2, &[OutPoint::new(parent_id, 0)], 1);
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 1, 1, 0))?;
        let replacement = spend(3, &[coin(100)], 1);
        let before = pool.mining_snapshot();
        let error = pool
            .replace_transaction(
                &ReplacementCandidate::new(Arc::new(replacement), 300, 1_400, 1_000),
                2,
                1,
            )
            .err();
        assert_eq!(error, Some(RbfError::InsufficientFeerateDiagram));
        assert_eq!(pool.mining_snapshot().entries, before.entries);
        assert_eq!(pool.sequence_number(), before.sequence);
        Ok(())
    }

    #[test]
    fn lower_direct_rate_can_improve_the_parent_child_curve() -> Result<(), TestError> {
        let mut pool = pool();
        let parent = spend(1, &[coin(100)], 1);
        let parent_id = parent.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 2_250, 0, 1, 1, 0))?;
        let child = spend(2, &[OutPoint::new(parent_id, 0)], 1);
        let child_id = child.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 4_000, 1, 1, 0))?;
        let replacement = spend(3, &[OutPoint::new(parent_id, 0)], 1);
        let replacement_id = replacement.txid();
        pool.replace_transaction(
            &ReplacementCandidate::new(Arc::new(replacement), 200, 4_500, 1_000),
            2,
            1,
        )?;
        assert!(pool.contains_txid(&parent_id));
        assert!(!pool.contains_txid(&child_id));
        assert!(pool.contains_txid(&replacement_id));
        Ok(())
    }

    #[test]
    fn limit_counts_conflicting_clusters_not_evicted_transactions() -> Result<(), TestError> {
        let mut pool = pool();
        let mut roots = Vec::new();
        for cluster in 0..3_u32 {
            let mut input = coin(10_000 + cluster);
            roots.push(input);
            for depth in 0..50_u32 {
                let tx = spend(cluster * 100 + depth, &[input], 1);
                input = OutPoint::new(tx.txid(), 0);
                pool.insert_entry(entry(tx, 1_000))?;
            }
        }
        let replacement = candidate(spend(999, &roots, 1), 600_000);
        let plan = pool.check_replacement(&replacement)?;
        assert_eq!(plan.evicted.len(), 150);
        pool.replace_transaction(&replacement, 2, 1)?;
        assert_eq!(pool.len(), 1);
        Ok(())
    }

    #[test]
    fn one_hundred_conflicting_clusters_is_the_exact_boundary() -> Result<(), TestError> {
        for count in [100_u32, 101] {
            let mut pool = pool();
            let mut inputs = Vec::new();
            for index in 0..count {
                let input = coin(10_000 + index);
                inputs.push(input);
                pool.insert_entry(entry(spend(index, &[input], 1), 1_000))?;
            }
            let replacement = candidate(spend(999, &inputs, 1), 1_000_000);
            let before = pool.sequence_number();
            let result = pool.replace_transaction(&replacement, 2, 1);
            if count == 100 {
                assert!(result.is_ok(), "{result:?}");
                assert_eq!(pool.len(), 1);
            } else {
                assert_eq!(result.err(), Some(RbfError::TooManyConflictingClusters));
                assert_eq!(pool.len(), 101);
                assert_eq!(pool.sequence_number(), before);
            }
        }
        Ok(())
    }

    #[test]
    fn modified_fees_and_small_relay_charges_are_enforced() -> Result<(), TestError> {
        let mut pool = pool();
        let original = spend(1, &[coin(100)], 1);
        let original_id = original.txid();
        pool.insert_entry(entry(original, 1_000))?;
        let mut replacement = candidate(spend(2, &[coin(100)], 1), 1_000);
        replacement.min_relay_fee_rate = 1;
        assert_eq!(
            pool.check_replacement(&replacement).err(),
            Some(RbfError::Rule4InsufficientIncrementalFee)
        );
        pool.prioritise(original_id, 2_000)?;
        replacement.fee = 2_500;
        assert_eq!(
            pool.check_replacement(&replacement).err(),
            Some(RbfError::Rule3InsufficientAbsoluteFee)
        );
        pool.prioritise(replacement.tx.txid(), 1_000)?;
        pool.replace_transaction(&replacement, 2, 1)?;
        Ok(())
    }

    #[test]
    fn an_evicted_dependency_fails_without_narrowing_representable_fees() -> Result<(), TestError> {
        let mut pool = pool();
        let original = spend(1, &[coin(100)], 1);
        let original_id = original.txid();
        pool.insert_entry(entry(original, 1_000))?;
        let before = pool.sequence_number();
        let dependent = candidate(
            spend(2, &[coin(100), OutPoint::new(original_id, 0)], 1),
            10_000,
        );
        assert_eq!(
            pool.check_replacement(&dependent).err(),
            Some(RbfError::Mempool(MempoolError::EvictedParent))
        );
        let wide = candidate(spend(3, &[coin(100)], 1), u64::MAX);
        assert!(
            pool.check_replacement(&wide).is_ok(),
            "u64 fee metadata remains representable in the checked i128 diagram"
        );
        assert_eq!(pool.sequence_number(), before);
        assert!(pool.contains_txid(&original_id));
        Ok(())
    }

    #[test]
    fn truc_sizes_versions_and_sibling_eviction_match_bip431() -> Result<(), TestError> {
        use bitcoin_rs_mempool::TrucError;
        let mut pool = pool();
        let mut parent = spend(1, &[coin(100)], 2);
        parent.version = 3;
        let parent_id = parent.txid();
        for size in [10_000, 10_001] {
            let request = ReplacementCandidate::new(Arc::new(parent.clone()), size, 20_000, 1_000);
            let result = pool.check_replacement(&request);
            if size == 10_000 {
                assert!(result.is_ok());
            } else {
                assert_eq!(result.err(), Some(RbfError::Truc(TrucError::Size)));
            }
        }
        pool.insert_entry(entry(parent, 1_000))?;
        let mut child = spend(2, &[OutPoint::new(parent_id, 0)], 1);
        assert_eq!(
            pool.check_replacement(&candidate(child.clone(), 2_000))
                .err(),
            Some(RbfError::Truc(TrucError::Version))
        );
        child.version = 3;
        for size in [1_000, 1_001] {
            let request = ReplacementCandidate::new(Arc::new(child.clone()), size, 2_000, 1_000);
            let result = pool.check_replacement(&request);
            if size == 1_000 {
                assert!(result.is_ok());
            } else {
                assert_eq!(result.err(), Some(RbfError::Truc(TrucError::ChildSize)));
            }
        }
        let child_id = child.txid();
        pool.replace_transaction(&candidate(child, 2_000), 1, 1)?;
        let mut grandchild = spend(3, &[OutPoint::new(child_id, 0)], 1);
        grandchild.version = 3;
        assert_eq!(
            pool.check_replacement(&candidate(grandchild, 10_000)).err(),
            Some(RbfError::Truc(TrucError::Ancestors))
        );
        let mut sibling = spend(4, &[OutPoint::new(parent_id, 1)], 1);
        sibling.version = 3;
        let before = pool.mining_snapshot();
        assert_eq!(
            pool.check_replacement(&candidate(sibling.clone(), 2_000))
                .err(),
            Some(RbfError::SiblingIncrementalFee)
        );
        assert_eq!(pool.mining_snapshot().entries, before.entries);
        assert_eq!(pool.sequence_number(), before.sequence);
        let sibling_id = sibling.txid();
        let changes = pool.replace_transaction(&candidate(sibling, 4_000), 1, 1)?;
        assert_eq!(changes.removed_txids(), vec![child_id]);
        assert!(pool.contains_txid(&parent_id));
        assert!(pool.contains_txid(&sibling_id));
        assert_eq!(pool.len(), 2);
        Ok(())
    }
}
mod standardness_spend {
    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use bitcoin_rs_consensus::script::{opcode, push_data};
    use bitcoin_rs_mempool::standardness::{StandardnessError, is_standard_spend};

    const CORE_MAX_P2SH_SIGOPS: usize = 15;
    const CORE_MAX_TX_LEGACY_SIGOPS: u32 = 2_500;
    const CORE_MAX_P2WSH_STACK_ITEMS: usize = 100;
    const CORE_MAX_P2WSH_STACK_ITEM_SIZE: usize = 80;
    const CORE_MAX_TAPSCRIPT_STACK_ITEM_SIZE: usize = 80;
    const CORE_MAX_P2WSH_SCRIPT_SIZE: usize = 3_600;

    struct SpendInput {
        outpoint: OutPoint,
        script_sig: Vec<u8>,
        witness: Vec<Vec<u8>>,
        prevout_script: Vec<u8>,
    }

    fn outpoint(index: u8) -> OutPoint {
        OutPoint::new(Txid::from(Hash256::from_le_bytes(&[index; 32])), 0)
    }

    fn p2pkh_script() -> Vec<u8> {
        [
            vec![opcode::OP_DUP, opcode::OP_HASH160, 0x14],
            vec![7; 20],
            vec![opcode::OP_EQUALVERIFY, opcode::OP_CHECKSIG],
        ]
        .concat()
    }

    fn p2sh_script() -> Vec<u8> {
        [
            vec![opcode::OP_HASH160, 0x14],
            vec![9; 20],
            vec![opcode::OP_EQUAL],
        ]
        .concat()
    }

    fn p2wsh_script() -> Vec<u8> {
        [vec![opcode::OP_0, 0x20], vec![3; 32]].concat()
    }

    fn p2tr_script() -> Vec<u8> {
        [vec![opcode::OP_PUSHNUM_1, 0x20], vec![4; 32]].concat()
    }

    fn p2a_script() -> Vec<u8> {
        vec![opcode::OP_PUSHNUM_1, 0x02, 0x4e, 0x73]
    }

    fn hex_hash160_of_true() -> Vec<u8> {
        [
            0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a, 0x56, 0x99, 0x71, 0xc7,
            0x7e, 0xba, 0x30, 0xcd, 0x5a, 0x4b,
        ]
        .to_vec()
    }

    fn witness_program(version: u8, program: &[u8]) -> Vec<u8> {
        let Ok(length) = u8::try_from(program.len()) else {
            panic!("a test witness program is at most 40 bytes");
        };
        let mut script = vec![version, length];
        script.extend_from_slice(program);
        script
    }

    fn multisig_16_of_16() -> Vec<u8> {
        let mut script = vec![opcode::OP_PUSHNUM_1];
        for _ in 0..16 {
            script.extend(push_data(&[0x02; 33]));
        }
        script.extend([opcode::OP_PUSHNUM_16, opcode::OP_CHECKMULTISIG]);
        script
    }

    fn spend(inputs: &[SpendInput]) -> (Tx, Vec<(OutPoint, TxOut)>) {
        let tx_inputs = inputs
            .iter()
            .map(|input| TxIn {
                previous_output: input.outpoint,
                script_sig: Script::from_bytes(input.script_sig.clone()),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(input.witness.clone()),
            })
            .collect();
        let prevouts = inputs
            .iter()
            .map(|input| {
                (
                    input.outpoint,
                    TxOut {
                        value: Amount::from_sat(100_000),
                        script_pubkey: Script::from_bytes(input.prevout_script.clone()),
                    },
                )
            })
            .collect();
        let tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: tx_inputs,
            outputs: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: Script::from_bytes(p2pkh_script()),
            }],
        };
        (tx, prevouts)
    }

    fn single_input(
        prevout_script: Vec<u8>,
        extra: impl FnOnce(&mut SpendInput),
    ) -> (Tx, Vec<(OutPoint, TxOut)>) {
        let mut input = SpendInput {
            outpoint: outpoint(1),
            script_sig: Vec::new(),
            witness: Vec::new(),
            prevout_script,
        };
        extra(&mut input);
        spend(&[input])
    }

    #[test]
    fn core_reason_strings_name_the_input_and_witness_rules() {
        assert_eq!(
            StandardnessError::NonStandardInput.to_string(),
            "bad-txns-nonstandard-inputs"
        );
        assert_eq!(
            StandardnessError::NonStandardWitness.to_string(),
            "bad-witness-nonstandard"
        );
    }

    // POL-07
    #[test]
    fn undefined_witness_program_input_is_not_standard() {
        for program in [
            witness_program(opcode::OP_PUSHNUM_1, &[3; 20]),
            witness_program(opcode::OP_0, &[3; 25]),
            witness_program(opcode::OP_PUSHNUM_1 + 1, &[3; 32]),
        ] {
            let (tx, prevouts) = single_input(program, |_| {});
            assert_eq!(
                is_standard_spend(&tx, &prevouts),
                Err(StandardnessError::NonStandardInput),
                "Core Solver classifies an undefined witness program as WITNESS_UNKNOWN or NONSTANDARD, so ValidateInputsStandardness rejects it"
            );
        }
    }

    // POL-07
    #[test]
    fn p2sh_redeem_script_sigop_limit_is_core_max_p2sh_sigops() {
        let redeem = |sigops: usize| vec![opcode::OP_CHECKSIG; sigops];
        let accepted = single_input(p2sh_script(), |input| {
            input.script_sig = push_data(&redeem(CORE_MAX_P2SH_SIGOPS));
        });
        assert_eq!(
            is_standard_spend(&accepted.0, &accepted.1),
            Ok(()),
            "Core MAX_P2SH_SIGOPS is inclusive at 15 accurate sigops"
        );
        let rejected = single_input(p2sh_script(), |input| {
            input.script_sig = push_data(&redeem(CORE_MAX_P2SH_SIGOPS + 1));
        });
        assert_eq!(
            is_standard_spend(&rejected.0, &rejected.1),
            Err(StandardnessError::NonStandardInput),
            "a redeem script above 15 sigops is bad-txns-nonstandard-inputs in Core"
        );
    }

    #[test]
    fn bip54_legacy_sigop_limit_is_core_max_tx_legacy_sigops() {
        let spending = |count: usize| {
            let sigops_per_input = 16_u32;
            let inputs: Vec<SpendInput> = (0..count)
                .map(|index| {
                    let Ok(index) = u8::try_from(index) else {
                        panic!("the test spends at most 256 inputs");
                    };
                    SpendInput {
                        outpoint: outpoint(index),
                        script_sig: Vec::new(),
                        witness: Vec::new(),
                        prevout_script: multisig_16_of_16(),
                    }
                })
                .collect();
            let (tx, prevouts) = spend(&inputs);
            let total = sigops_per_input * u32::try_from(count).unwrap_or(u32::MAX);
            assert!(total <= CORE_MAX_TX_LEGACY_SIGOPS || count == 157);
            (tx, prevouts)
        };
        let accepted = spending(156);
        assert_eq!(
            is_standard_spend(&accepted.0, &accepted.1),
            Ok(()),
            "156 sixteen-key multisig spends reach 2,496 legacy sigops, below Core's 2,500 limit"
        );
        let rejected = spending(157);
        assert_eq!(
            is_standard_spend(&rejected.0, &rejected.1),
            Err(StandardnessError::NonStandardInput),
            "157 sixteen-key multisig spends reach 2,512 legacy sigops, above Core's BIP54 limit"
        );
    }

    // POL-07
    #[test]
    fn p2wsh_witness_script_limit_is_core_max_standard_p2wsh_script_size() {
        let with_script_size = |size: usize| {
            single_input(p2wsh_script(), |input| {
                input.witness = vec![vec![opcode::OP_CHECKSIG; size]];
            })
        };
        let accepted = with_script_size(CORE_MAX_P2WSH_SCRIPT_SIZE);
        assert_eq!(
            is_standard_spend(&accepted.0, &accepted.1),
            Ok(()),
            "Core MAX_STANDARD_P2WSH_SCRIPT_SIZE is inclusive at 3,600 bytes"
        );
        let rejected = with_script_size(CORE_MAX_P2WSH_SCRIPT_SIZE + 1);
        assert_eq!(
            is_standard_spend(&rejected.0, &rejected.1),
            Err(StandardnessError::NonStandardWitness),
            "a 3,601-byte witness script is bad-witness-nonstandard in Core"
        );
    }

    #[test]
    fn p2wsh_stack_item_count_limit_is_core_max_standard_p2wsh_stack_items() {
        let with_stack_items = |items: usize| {
            single_input(p2wsh_script(), |input| {
                input.witness = vec![vec![0x01]; items];
                input.witness.push(vec![opcode::OP_CHECKSIG]);
            })
        };
        let accepted = with_stack_items(CORE_MAX_P2WSH_STACK_ITEMS);
        assert_eq!(
            is_standard_spend(&accepted.0, &accepted.1),
            Ok(()),
            "Core MAX_STANDARD_P2WSH_STACK_ITEMS is inclusive at 100 items below the witness script"
        );
        let rejected = with_stack_items(CORE_MAX_P2WSH_STACK_ITEMS + 1);
        assert_eq!(
            is_standard_spend(&rejected.0, &rejected.1),
            Err(StandardnessError::NonStandardWitness),
            "101 witness stack items are bad-witness-nonstandard in Core"
        );
    }

    #[test]
    fn p2wsh_stack_item_size_limit_is_core_max_standard_p2wsh_stack_item_size() {
        let with_item_size = |size: usize| {
            single_input(p2wsh_script(), |input| {
                input.witness = vec![vec![0x01; size], vec![opcode::OP_CHECKSIG]];
            })
        };
        let accepted = with_item_size(CORE_MAX_P2WSH_STACK_ITEM_SIZE);
        assert_eq!(
            is_standard_spend(&accepted.0, &accepted.1),
            Ok(()),
            "Core MAX_STANDARD_P2WSH_STACK_ITEM_SIZE is inclusive at 80 bytes"
        );
        let rejected = with_item_size(CORE_MAX_P2WSH_STACK_ITEM_SIZE + 1);
        assert_eq!(
            is_standard_spend(&rejected.0, &rejected.1),
            Err(StandardnessError::NonStandardWitness),
            "an 81-byte P2WSH stack item is bad-witness-nonstandard in Core"
        );
    }

    #[test]
    fn p2sh_wrapped_p2wsh_applies_the_witness_script_limits() {
        let (tx, prevouts) = single_input(p2sh_script(), |input| {
            input.script_sig = push_data(&p2wsh_script());
            input.witness = vec![vec![0x01]; CORE_MAX_P2WSH_STACK_ITEMS + 1];
            input.witness.push(vec![opcode::OP_CHECKSIG]);
        });
        assert_eq!(
            is_standard_spend(&tx, &prevouts),
            Err(StandardnessError::NonStandardWitness),
            "Core IsWitnessStandard reads the P2SH redeem script and applies the P2WSH limits to it"
        );
    }

    #[test]
    fn tapscript_stack_item_size_limit_is_core_max_standard_tapscript_stack_item_size() {
        let control_block = |leaf: u8| {
            let mut block = vec![leaf];
            block.extend([0x05; 32]);
            block
        };
        let with_item_size = |size: usize| {
            single_input(p2tr_script(), |input| {
                input.witness = vec![
                    vec![0x01; size],
                    vec![opcode::OP_CHECKSIG],
                    control_block(0xc0),
                ];
            })
        };
        let accepted = with_item_size(CORE_MAX_TAPSCRIPT_STACK_ITEM_SIZE);
        assert_eq!(
            is_standard_spend(&accepted.0, &accepted.1),
            Ok(()),
            "Core MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE is inclusive at 80 bytes"
        );
        let rejected = with_item_size(CORE_MAX_TAPSCRIPT_STACK_ITEM_SIZE + 1);
        assert_eq!(
            is_standard_spend(&rejected.0, &rejected.1),
            Err(StandardnessError::NonStandardWitness),
            "an 81-byte tapscript stack item is bad-witness-nonstandard in Core"
        );
        let non_tapscript_leaf = single_input(p2tr_script(), |input| {
            input.witness = vec![
                vec![0x01; CORE_MAX_TAPSCRIPT_STACK_ITEM_SIZE + 1],
                vec![opcode::OP_CHECKSIG],
                control_block(0xc2),
            ];
        });
        assert_eq!(
            is_standard_spend(&non_tapscript_leaf.0, &non_tapscript_leaf.1),
            Ok(()),
            "Core applies the tapscript item-size limit only to leaf version 0xc0"
        );
    }

    #[test]
    fn tapscript_dense_empty_stack_stays_standard() {
        let (tx, prevouts) = single_input(p2tr_script(), |input| {
            input.witness = vec![Vec::new(); 1_000];
            input.witness.push(vec![opcode::OP_CHECKSIG]);
            input.witness.push(vec![0xc0; 33]);
        });
        assert_eq!(
            is_standard_spend(&tx, &prevouts),
            Ok(()),
            "Core caps the tapscript initial stack at 1,000 consensus items and sets no standard item count"
        );
    }

    #[test]
    fn taproot_annex_is_not_standard() {
        let (tx, prevouts) = single_input(p2tr_script(), |input| {
            input.witness = vec![vec![0x07; 64], vec![0x50, 0x00]];
        });
        assert_eq!(
            is_standard_spend(&tx, &prevouts),
            Err(StandardnessError::NonStandardWitness),
            "Core rejects any non-empty witness item beginning with the 0x50 annex tag"
        );
        let key_path = single_input(p2tr_script(), |input| {
            input.witness = vec![vec![0x07; 64]];
        });
        assert_eq!(
            is_standard_spend(&key_path.0, &key_path.1),
            Ok(()),
            "a one-item taproot key-path witness has no annex and no stack script"
        );
    }

    #[test]
    fn taproot_path_spend_with_empty_control_block_is_not_standard() {
        let (tx, prevouts) = single_input(p2tr_script(), |input| {
            input.witness = vec![vec![0x07; 64], vec![opcode::OP_CHECKSIG], Vec::new()];
        });
        assert_eq!(
            is_standard_spend(&tx, &prevouts),
            Err(StandardnessError::NonStandardWitness),
            "Core rejects a taproot path spend whose control block is empty"
        );
        let accepted = single_input(p2tr_script(), |input| {
            input.witness = vec![vec![0x07; 64], vec![opcode::OP_CHECKSIG], vec![0xc0]];
        });
        assert_eq!(
            is_standard_spend(&accepted.0, &accepted.1),
            Ok(()),
            "a non-empty tapscript control block passes when every stack item is within the size limit"
        );
    }

    #[test]
    fn p2a_witness_spend_is_witness_stuffing() {
        let (tx, prevouts) = single_input(p2a_script(), |input| {
            input.witness = vec![vec![0x01]];
        });
        assert_eq!(
            is_standard_spend(&tx, &prevouts),
            Err(StandardnessError::NonStandardWitness),
            "Core IsWitnessStandard rejects any witness on a pay-to-anchor output"
        );
        let bare = single_input(p2a_script(), |_| {});
        assert_eq!(
            is_standard_spend(&bare.0, &bare.1),
            Ok(()),
            "a P2A output is a known Solver type, so spending it without a witness is standard"
        );
    }

    #[test]
    fn witness_on_non_witness_prevout_is_not_standard() {
        let (tx, prevouts) = single_input(p2pkh_script(), |input| {
            input.witness = vec![vec![0x01]];
        });
        assert_eq!(
            is_standard_spend(&tx, &prevouts),
            Err(StandardnessError::NonStandardWitness),
            "Core requires a witness program, direct or P2SH wrapped, for any non-empty witness"
        );
    }

    #[test]
    fn missing_prevout_fails_closed() {
        let (tx, _) = single_input(p2pkh_script(), |_| {});
        assert_eq!(
            is_standard_spend(&tx, &[]),
            Err(StandardnessError::NonStandardInput),
            "Core Solver classifies an unresolved coin's empty scriptPubKey as NONSTANDARD"
        );
    }

    #[test]
    fn input_standardness_precedes_witness_standardness() {
        let (tx, prevouts) = spend(&[
            SpendInput {
                outpoint: outpoint(1),
                script_sig: Vec::new(),
                witness: vec![vec![0x01]],
                prevout_script: p2a_script(),
            },
            SpendInput {
                outpoint: outpoint(2),
                script_sig: Vec::new(),
                witness: Vec::new(),
                prevout_script: witness_program(opcode::OP_PUSHNUM_1 + 1, &[3; 32]),
            },
        ]);
        assert_eq!(
            is_standard_spend(&tx, &prevouts),
            Err(StandardnessError::NonStandardInput),
            "Core runs ValidateInputsStandardness before IsWitnessStandard, so the input reason wins"
        );
    }

    #[test]
    fn p2sh_true_redeem_script_spend_is_standard() {
        let prevout_script = [
            vec![opcode::OP_HASH160, 0x14],
            hex_hash160_of_true(),
            vec![opcode::OP_EQUAL],
        ]
        .concat();
        let (tx, prevouts) = single_input(prevout_script, |input| {
            input.script_sig = push_data(&[opcode::OP_PUSHNUM_1]);
        });
        assert_eq!(
            is_standard_spend(&tx, &prevouts),
            Ok(()),
            "a P2SH outpoint with a one-byte OP_TRUE redeem script carries no sigops and is a known Solver type"
        );
    }
}
mod support {
    use bitcoin_rs_consensus::script::{opcode, push_data};

    pub(crate) fn p2sh_true_script() -> Vec<u8> {
        [
            vec![opcode::OP_HASH160, 0x14],
            vec![
                0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a, 0x56, 0x99, 0x71, 0xc7,
                0x7e, 0xba, 0x30, 0xcd, 0x5a, 0x4b,
            ],
            vec![opcode::OP_EQUAL],
        ]
        .concat()
    }

    pub(crate) fn true_redeem_script_sig() -> Vec<u8> {
        push_data(&[opcode::OP_PUSHNUM_1])
    }
}
mod test_error {
    use bitcoin_rs_mempool::{
        AdmitError, ChainChangeError, MempoolError, PrioritiseError, RbfError, SubmitError,
    };
    #[derive(Debug, thiserror::Error)]
    pub enum TestError {
        #[error("mempool error: {0}")]
        Mempool(#[from] MempoolError),
        #[error("prioritise error: {0}")]
        Prioritise(#[from] PrioritiseError),
        #[error("rbf error: {0}")]
        Rbf(#[from] RbfError),
        #[error("admit error: {0}")]
        Admit(#[from] AdmitError),
        #[error("submit error: {0}")]
        Submit(#[from] SubmitError),
        #[error("chain change error: {0}")]
        ChainChange(#[from] ChainChangeError),
        #[error("try-from-int error: {0}")]
        TryFromInt(#[from] core::num::TryFromIntError),
        #[error("consensus decode error: {0}")]
        Consensus(#[from] bitcoin::consensus::encode::Error),
        #[error("missing expected value: {0}")]
        Missing(&'static str),
    }

    impl From<&'static str> for TestError {
        fn from(msg: &'static str) -> Self {
            Self::Missing(msg)
        }
    }
}

pub(crate) use support::{p2sh_true_script, true_redeem_script_sig};
pub use test_error::TestError;
