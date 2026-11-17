mod adversarial_consensus {
    use bitcoin::hashes::Hash as _;
    use bitcoin_rs_consensus::bip34::check_bip34;
    use bitcoin_rs_consensus::bip68::{check_sequence_lock, sequence_lock_satisfied};
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, Hash256, Header, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
        Txid, Witness,
    };
    use bitcoin_rs_consensus::verify_block::{
        MAX_BLOCK_WEIGHT, is_sixty_four_byte_mutation, verify_block_non_contextual,
        verify_block_rules, verify_merkle_root_with_txids,
    };
    use bitcoin_rs_consensus::verify_tx::{is_final_tx, verify_coinbase_script_sig_size};
    use bitcoin_rs_consensus::{
        ConsensusError, MAX_BLOCK_SIGOPS_COST, block_subsidy, verify_coinbase_amount,
    };

    fn coinbase_tx(script_sig_len: usize) -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x51; script_sig_len]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50 * 100_000_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn standard_spend_tx(seed: u8) -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[seed; 32])), 0),
                script_sig: Script::from_bytes(vec![0x51; 4]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes(vec![0x51; 4]),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn block_with(txs: Vec<Tx>) -> Block {
        let txids: Vec<Txid> = txs.iter().map(Tx::txid).collect();
        let root = match bitcoin::merkle_tree::calculate_root(txids.iter().map(|id| {
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                *id.as_bytes(),
            ))
        })) {
            Some(r) => Hash256::from_le_bytes(&r.to_byte_array()),
            None => Hash256::default(),
        };
        Block {
            header: Header {
                version: 1,
                prev_blockhash: bitcoin_rs_consensus::primitives::BlockHash::default(),
                merkle_root: root,
                time: 1_234_567_890,
                bits: bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txs,
        }
    }

    #[test]
    fn coinbase_script_sig_size_boundary_checks() {
        let tx_size_1 = coinbase_tx(1);
        assert_eq!(
            verify_coinbase_script_sig_size(&tx_size_1),
            Err(ConsensusError::CoinbaseScriptSigSize { len: 1 })
        );

        let tx_size_2 = coinbase_tx(2);
        assert_eq!(verify_coinbase_script_sig_size(&tx_size_2), Ok(()));

        let tx_size_100 = coinbase_tx(100);
        assert_eq!(verify_coinbase_script_sig_size(&tx_size_100), Ok(()));

        let tx_size_101 = coinbase_tx(101);
        assert_eq!(
            verify_coinbase_script_sig_size(&tx_size_101),
            Err(ConsensusError::CoinbaseScriptSigSize { len: 101 })
        );
    }

    #[test]
    fn block_stripped_size_boundaries() {
        assert_eq!(MAX_BLOCK_WEIGHT, 4_000_000);
        let mut cb = coinbase_tx(4);
        cb.outputs[0].script_pubkey = Script::from_bytes(vec![0x00; 1_000_001]);
        let heavy_block = block_with(vec![cb]);
        let res = verify_block_rules(&heavy_block);
        assert!(matches!(res, Err(ConsensusError::BlockBaseSize { .. })));
    }

    #[test]
    fn block_sigops_cost_limit_boundary() {
        assert_eq!(MAX_BLOCK_SIGOPS_COST, 80_000);
        let mut cb = coinbase_tx(4);
        cb.outputs[0].script_pubkey = Script::from_bytes(vec![
        bitcoin_rs_consensus::script::opcode::OP_CHECKSIG;
        20_001
    ]);
        let block = block_with(vec![cb]);
        let res = verify_block_non_contextual(&block);
        assert!(matches!(res, Err(ConsensusError::SigopsLimit { .. })));
    }

    #[test]
    fn merkle_duplicate_tx_mutation_cve_2012_2459() {
        let tx1 = standard_spend_tx(1);
        let tx1_dup = standard_spend_tx(1);
        let txids = vec![tx1.txid(), tx1_dup.txid()];
        let block = block_with(vec![tx1, tx1_dup]);
        let res = verify_merkle_root_with_txids(&block, &txids);
        assert_eq!(res, Err(ConsensusError::MerkleMutation));
    }

    #[test]
    fn sixty_four_byte_non_coinbase_mutation() {
        let mut tx = standard_spend_tx(1);
        tx.inputs[0].script_sig = Script::new();
        tx.outputs[0].script_pubkey = Script::from_bytes(vec![0x51; 4]);
        assert_eq!(tx.base_size(), 64);
        assert!(is_sixty_four_byte_mutation(&[tx]));
    }

    #[test]
    fn bip34_coinbase_height_encoding() {
        let encoded_height_100 = bitcoin_rs_consensus::script::push_int(100);
        assert_eq!(check_bip34(100, &encoded_height_100), Ok(()));

        let encoded_height_101 = bitcoin_rs_consensus::script::push_int(101);
        assert!(check_bip34(100, &encoded_height_101).is_err());
        assert!(check_bip34(100, &[]).is_err());
    }

    #[test]
    fn bip68_relative_locktime_block_based_boundaries() {
        let sequence = 10;
        assert!(!sequence_lock_satisfied(2, sequence, 100, 0, 109, 0));
        assert!(sequence_lock_satisfied(2, sequence, 100, 0, 110, 0));
        assert!(sequence_lock_satisfied(2, sequence, 100, 0, 111, 0));

        assert!(matches!(
            check_sequence_lock(2, sequence, 100, 0, 109, 0),
            Err(ConsensusError::Bip { bip: "BIP68", reason })
                if reason.starts_with("input sequence height-based lock unmet")
        ));
        assert_eq!(check_sequence_lock(2, sequence, 100, 0, 110, 0), Ok(()));
    }

    #[test]
    fn bip68_relative_locktime_time_based_boundaries() {
        let sequence = bitcoin_rs_consensus::primitives::SEQUENCE_LOCKTIME_TYPE_FLAG | 2;
        let prev_mtp = 10_000;
        let earliest = prev_mtp + 2 * 512;

        assert!(!sequence_lock_satisfied(
            2,
            sequence,
            0,
            prev_mtp,
            0,
            earliest - 1
        ));
        assert!(sequence_lock_satisfied(
            2, sequence, 0, prev_mtp, 0, earliest
        ));
        assert!(sequence_lock_satisfied(
            2,
            sequence,
            0,
            prev_mtp,
            0,
            earliest + 1
        ));

        assert!(check_sequence_lock(2, sequence, 0, prev_mtp, 0, earliest - 1).is_err());
        assert_eq!(
            check_sequence_lock(2, sequence, 0, prev_mtp, 0, earliest),
            Ok(())
        );
    }

    #[test]
    fn bip68_disable_flag_and_version_one_bypass_lock() {
        let disabled = bitcoin_rs_consensus::primitives::SEQUENCE_LOCKTIME_DISABLE_FLAG | 0x64;
        assert!(sequence_lock_satisfied(2, disabled, 100, 0, 0, 0));

        assert!(sequence_lock_satisfied(1, 100, 100, 0, 0, 0));
        assert_eq!(check_sequence_lock(1, 100, 100, 0, 0, 0), Ok(()));
    }

    #[test]
    fn is_final_tx_boundaries() {
        let mut tx = standard_spend_tx(1);
        tx.lock_time = LockTime::ZERO;
        assert!(is_final_tx(&tx, 100, 1_000_000));

        tx.lock_time = LockTime::from_consensus(200);
        tx.inputs[0].sequence = Sequence::from_consensus(0xffff_fffe);
        assert!(is_final_tx(&tx, 201, 1_000_000));
        assert!(!is_final_tx(&tx, 200, 1_000_000));
        assert!(!is_final_tx(&tx, 199, 1_000_000));

        tx.inputs[0].sequence =
            Sequence::from_consensus(bitcoin_rs_consensus::primitives::SEQUENCE_FINAL);
        assert!(is_final_tx(&tx, 199, 1_000_000));

        tx.inputs[0].sequence = Sequence::from_consensus(0xffff_fffe);
        tx.lock_time =
            LockTime::from_consensus(bitcoin_rs_consensus::primitives::LOCKTIME_THRESHOLD + 100);
        let cutoff = bitcoin_rs_consensus::primitives::LOCKTIME_THRESHOLD + 100;
        assert!(!is_final_tx(&tx, 100, cutoff));
        assert!(is_final_tx(&tx, 100, cutoff + 1));
    }

    #[test]
    fn block_subsidy_and_coinbase_verification() {
        assert_eq!(block_subsidy(0, 210_000), 50 * 100_000_000);
        assert_eq!(block_subsidy(209_999, 210_000), 50 * 100_000_000);
        assert_eq!(block_subsidy(210_000, 210_000), 25 * 100_000_000);
        assert_eq!(block_subsidy(420_000, 210_000), 12_5000_0000);
        assert_eq!(block_subsidy(64 * 210_000, 210_000), 0);

        assert_eq!(
            verify_coinbase_amount(50 * 100_000_000, 0, 0, 210_000),
            Ok(())
        );
        assert_eq!(
            verify_coinbase_amount(50 * 100_000_000 + 10_000, 10_000, 0, 210_000),
            Ok(())
        );
        assert_eq!(
            verify_coinbase_amount(50 * 100_000_000 + 1, 0, 0, 210_000),
            Err(ConsensusError::CoinbaseAmount {
                paid: 50 * 100_000_000 + 1,
                allowed: 50 * 100_000_000
            })
        );
    }
}
mod block_facts_borrowed {
    #![expect(clippy::expect_used, reason = "test assertions")]

    mod fixtures {
        use bitcoin_rs_consensus::BlockFacts;
        use bitcoin_rs_consensus::primitives::{
            Amount, Block, Hash256, Header, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
            Txid, Witness,
        };

        pub(crate) fn fixture(
            tx_count: usize,
            input_count: usize,
            output_count: usize,
            script_len: usize,
            witness_modulus: usize,
        ) -> Block {
            let txs = (0..tx_count)
                .map(|index| {
                    let identity = u32::try_from(index)
                        .unwrap_or_else(|error| panic!("fixture transaction count: {error}"));
                    let mut previous = [0_u8; 32];
                    previous[..4].copy_from_slice(&identity.to_le_bytes());
                    previous[4] = 1;
                    let witnessed =
                        witness_modulus != 0 && (index + 1).is_multiple_of(witness_modulus);
                    let inputs = (0..input_count)
                        .map(|input_index| TxIn {
                            previous_output: OutPoint::new(
                                Txid(Hash256::from_le_bytes(&previous)),
                                u32::try_from(input_index)
                                    .unwrap_or_else(|error| panic!("fixture input count: {error}")),
                            ),
                            script_sig: Script::from_bytes(vec![0x51; script_len]),
                            sequence: Sequence::from_consensus(0xffff_fffe),
                            witness: if witnessed && input_index == 0 {
                                Witness::from_stack(vec![vec![0x30; 72], vec![0x02; 33]])
                            } else {
                                Witness::new()
                            },
                        })
                        .collect();
                    Tx {
                        version: 2,
                        inputs,
                        outputs: vec![
                            TxOut {
                                value: Amount::from_sat(1),
                                script_pubkey: Script::from_bytes(vec![0x51; script_len]),
                            };
                            output_count
                        ],
                        lock_time: LockTime::from_consensus(identity),
                    }
                })
                .collect();
            Block {
                header: Header {
                    version: 1,
                    ..Header::default()
                },
                txs,
            }
        }

        pub(crate) fn assert_oracle(bytes: &[u8], facts: &BlockFacts) {
            let oracle: bitcoin::Block = bitcoin::consensus::deserialize(bytes)
                .unwrap_or_else(|error| panic!("oracle block decode: {error}"));
            assert_eq!(facts.tx_count(), oracle.txdata.len());
            assert_eq!(facts.weight(), oracle.weight().to_wu());
            for (actual, expected) in facts.txids().iter().zip(&oracle.txdata) {
                assert_eq!(actual.to_string(), expected.compute_txid().to_string());
            }
            let has_witness = oracle
                .txdata
                .iter()
                .any(|tx| tx.input.iter().any(|input| !input.witness.is_empty()));
            assert_eq!(facts.has_witness(), has_witness);
            match facts.wtxids() {
                Some(ids) => {
                    assert_eq!(ids.len(), oracle.txdata.len());
                    for (actual, expected) in ids.iter().zip(&oracle.txdata) {
                        assert_eq!(actual.to_string(), expected.compute_wtxid().to_string());
                    }
                }
                None => assert!(!has_witness, "witness-bearing facts must carry witness IDs"),
            }
            let root = bitcoin::merkle_tree::calculate_root(
                oracle.txdata.iter().map(bitcoin::Transaction::compute_txid),
            );
            assert_eq!(
                facts.merkle_root().map(|root| root.to_string()),
                root.map(|root| root.to_string()),
            );
        }
    }

    use bitcoin_rs_consensus::primitives::layout::ParsedBlock;
    use bitcoin_rs_consensus::primitives::{Block, LockTime, Tx, Witness, consensus_bytes};
    use bitcoin_rs_consensus::{BlockFacts, BlockView};

    fn facts(block: &Block) -> BlockFacts {
        let bytes = consensus_bytes(block);
        let parsed = ParsedBlock::parse_exact(&bytes).expect("fixture layout");
        let facts = BlockFacts::from_parsed(&parsed);
        fixtures::assert_oracle(&bytes, &facts);
        facts
    }

    #[test]
    fn sha256_and_compact_size_script_boundaries_match_oracle() {
        for len in [0, 1, 55, 56, 63, 64, 65, 252, 253, 254, 65_535, 65_536] {
            for witness_modulus in [0, 1, 2] {
                let block = fixtures::fixture(3, 1, 1, len, witness_modulus);
                assert!(!facts(&block).merkle_mutated());
            }
        }
    }

    #[test]
    fn count_prefixes_and_nonzero_transaction_origins_match_oracle() {
        for count in [1, 252, 253, 254] {
            for witness_modulus in [0, 1, 2] {
                facts(&fixtures::fixture(3, count, 1, 0, witness_modulus));
                facts(&fixtures::fixture(3, 1, count, 0, witness_modulus));
                facts(&fixtures::fixture(count, 1, 1, 0, witness_modulus));
            }
        }
    }

    #[test]
    fn zero_outputs_and_empty_last_script_preserve_base_body_end() {
        for witness_modulus in [0, 1, 2] {
            for outputs in [0, 1, 2] {
                let mut block = fixtures::fixture(3, 2, outputs, 17, witness_modulus);
                for tx in &mut block.txs {
                    if let Some(output) = tx.outputs.last_mut() {
                        output.script_pubkey.clear();
                    }
                }
                facts(&block);
            }
        }
    }

    #[test]
    fn witness_only_mutations_leave_txids_and_merkle_root_unchanged() {
        let mut block = fixtures::fixture(3, 2, 2, 7, 2);
        let original = facts(&block);
        block.txs[1].inputs[0].witness = Witness::from_stack(vec![Vec::new(), vec![0xab; 253]]);
        let mutated = facts(&block);
        assert_eq!(original.txids(), mutated.txids());
        assert_eq!(original.merkle_root(), mutated.merkle_root());
        assert_ne!(original.wtxids(), mutated.wtxids());
        assert_ne!(original.weight(), mutated.weight());
    }

    #[test]
    fn a_single_empty_witness_item_is_not_a_legacy_transaction() {
        let mut block = fixtures::fixture(3, 2, 0, 0, 0);
        block.txs[1].inputs[1].witness = Witness::from_stack(vec![Vec::new()]);
        let result = facts(&block);
        assert!(result.has_witness());
        let ids = result
            .wtxids()
            .expect("one empty item still has witness data");
        assert_ne!(ids[1].0, result.txids()[1].0);
        assert_eq!(ids[0].0, result.txids()[0].0);
        assert_eq!(ids[2].0, result.txids()[2].0);
    }

    #[test]
    fn parsing_a_prefix_never_hashes_the_following_message() {
        let block = fixtures::fixture(3, 2, 2, 253, 2);
        let original = consensus_bytes(&block);
        let mut bytes = original.clone();
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let mut reader = bytes.as_slice();
        let parsed = ParsedBlock::parse(&mut reader).expect("prefix parse");
        assert_eq!(reader, &[0xde, 0xad, 0xbe, 0xef]);
        let actual = BlockFacts::from_parsed(&parsed);
        fixtures::assert_oracle(&original, &actual);
        assert_eq!(actual, facts(&block));
        assert!(ParsedBlock::parse_exact(&bytes).is_err());
    }

    #[test]
    fn legacy_and_mixed_lazy_witness_ids_match_oracle_and_reuse_cache() {
        for witness_modulus in [0, 1, 2, 3] {
            let block = fixtures::fixture(9, 3, 2, 253, witness_modulus);
            let bytes = consensus_bytes(&block);
            let oracle: bitcoin::Block = bitcoin::consensus::deserialize(&bytes).expect("oracle");
            let txids = block.txs.iter().map(Tx::txid).collect();
            let mut view =
                BlockView::from_facts(&block.txs, BlockFacts::from_txids(&block.txs, txids));
            assert!(view.facts().wtxids().is_none());
            let ids = view.witness_ids().to_vec();
            assert_eq!(ids.len(), oracle.txdata.len());
            for (actual, expected) in ids.iter().zip(&oracle.txdata) {
                assert_eq!(actual.to_string(), expected.compute_wtxid().to_string());
            }
            let first = view.witness_ids();
            let cached = first.as_ptr();
            assert_eq!(cached, view.witness_ids().as_ptr());
            assert_eq!(view.witness_ids(), ids.as_slice());
        }
    }

    #[test]
    fn empty_blocks_preserve_lazy_and_parsed_fact_shapes() {
        let block = fixtures::fixture(0, 1, 1, 0, 0);
        let actual = facts(&block);
        assert_eq!(actual.tx_count(), 0);
        assert_eq!(actual.weight(), 324);
        assert!(!actual.has_witness());
        assert!(actual.merkle_root().is_none());
        assert!(!actual.merkle_mutated());
        let mut view =
            BlockView::from_facts(&block.txs, BlockFacts::from_txids(&block.txs, Vec::new()));
        assert_eq!(view.witness_ids(), []);
    }

    #[test]
    fn mutation_flag_distinguishes_real_duplicate_tail_from_odd_padding() {
        for witness_modulus in [0, 1, 2] {
            let mut block = fixtures::fixture(6, 1, 1, 0, witness_modulus);
            let original = facts(&block);
            let tail = block.txs[4..].to_vec();
            block.txs.extend(tail);
            let duplicated = facts(&block);
            assert_eq!(original.merkle_root(), duplicated.merkle_root());
            assert!(!original.merkle_mutated());
            assert!(duplicated.merkle_mutated());
        }
    }

    #[test]
    fn noncanonical_script_lengths_still_fail_at_the_layout_boundary() {
        for witness_modulus in [0, 1] {
            let block = fixtures::fixture(1, 1, 1, 1, witness_modulus);
            let mut bytes = consensus_bytes(&block);
            let parsed = ParsedBlock::parse_exact(&bytes).expect("canonical layout");
            let script = parsed.transactions()[0].inputs()[0].script_sig();
            let prefix = usize::try_from(script.start()).expect("fixture offset") - 1;
            drop(parsed);
            drop(bytes.splice(prefix..=prefix, [0xfd, 1, 0]));
            assert!(ParsedBlock::parse_exact(&bytes).is_err());
            assert!(bitcoin::consensus::deserialize::<bitcoin::Block>(&bytes).is_err());
        }
    }

    #[test]
    fn version_and_lock_time_bytes_remain_in_the_transaction_id() {
        let mut block = fixtures::fixture(3, 1, 1, 0, 2);
        let original = facts(&block);
        block.txs[1].version = u32::MAX;
        block.txs[1].lock_time = LockTime::from_consensus(u32::MAX);
        let changed = facts(&block);
        assert_ne!(original.txids()[1], changed.txids()[1]);
        assert_eq!(original.txids()[0], changed.txids()[0]);
        assert_eq!(original.txids()[2], changed.txids()[2]);
        assert_eq!(original.weight(), changed.weight());
    }
}
mod coinbase_amount {
    use bitcoin_rs_consensus::primitives::Network;
    use bitcoin_rs_consensus::{ConsensusError, block_subsidy, verify_coinbase_amount};

    const MAINNET: u32 = 210_000;
    const REGTEST: u32 = 150;
    const FIFTY_BTC: u64 = 50 * 100_000_000;

    #[test]
    fn the_subsidy_halves_on_the_network_s_schedule_and_saturates_to_zero() {
        assert_eq!(Network::Mainnet.subsidy_halving_interval(), MAINNET);
        assert_eq!(Network::Signet.subsidy_halving_interval(), MAINNET);
        assert_eq!(Network::Regtest.subsidy_halving_interval(), REGTEST);

        let cases: [(u32, u32, u64); 11] = [
            (0, MAINNET, FIFTY_BTC),
            (209_999, MAINNET, FIFTY_BTC),
            (210_000, MAINNET, FIFTY_BTC / 2),
            (419_999, MAINNET, FIFTY_BTC / 2),
            (420_000, MAINNET, FIFTY_BTC / 4),
            (630_000, MAINNET, 625_000_000),
            (64 * MAINNET, MAINNET, 0),
            (u32::MAX, MAINNET, 0),
            (150, REGTEST, FIFTY_BTC / 2),
            (150, MAINNET, FIFTY_BTC),
            (u32::MAX, REGTEST, 0),
        ];
        for (height, interval, subsidy) in cases {
            assert_eq!(
                block_subsidy(height, interval),
                subsidy,
                "height {height} interval {interval}"
            );
        }
    }

    #[test]
    fn a_coinbase_may_claim_the_halved_subsidy_plus_the_fees_and_no_more() {
        let cases: [(u64, u64, u32, Result<(), ConsensusError>); 6] = [
            (FIFTY_BTC + 999, 999, 1, Ok(())),
            (0, 999, 1, Ok(())),
            (
                FIFTY_BTC + 1_000,
                999,
                1,
                Err(ConsensusError::CoinbaseAmount {
                    paid: FIFTY_BTC + 1_000,
                    allowed: FIFTY_BTC + 999,
                }),
            ),
            (FIFTY_BTC, 0, 209_999, Ok(())),
            (
                FIFTY_BTC,
                0,
                210_000,
                Err(ConsensusError::CoinbaseAmount {
                    paid: FIFTY_BTC,
                    allowed: FIFTY_BTC / 2,
                }),
            ),
            (0, u64::MAX, 1, Err(ConsensusError::BlockValueOverflow)),
        ];
        for (paid, fees, height, expected) in cases {
            assert_eq!(
                verify_coinbase_amount(paid, fees, height, MAINNET),
                expected,
                "paid {paid} fees {fees} height {height}"
            );
        }
    }
}
mod kernel_block_parity {
    #![cfg(feature = "kernel")]

    use std::path::{Path, PathBuf};

    use bitcoin::hex::FromHex;
    use bitcoin_rs_consensus::ConsensusError;
    use bitcoin_rs_consensus::primitives::{
        Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness, consensus_bytes,
        deserialize,
    };
    use bitcoin_rs_consensus::script::{Interpreter, VerifyFlags};
    use serde::Deserialize;

    use crate::support::error::{OracleFault, TestError};

    type TestResult = Result<(), TestError>;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Verdict {
        Accept,
        Reject,
    }

    impl Verdict {
        fn of_interpreter<T, E>(result: &Result<T, E>) -> Self {
            match result {
                Ok(_) => Self::Accept,
                Err(_) => Self::Reject,
            }
        }

        fn of_kernel(result: &Result<(), ConsensusError>) -> Result<Self, &ConsensusError> {
            match result {
                Ok(()) => Ok(Self::Accept),
                Err(ConsensusError::Script { .. }) => Ok(Self::Reject),
                Err(other) => Err(other),
            }
        }
    }

    fn kernel_result(
        tx: &Tx,
        prevouts: &[TxOut],
        flags: VerifyFlags,
    ) -> Result<(), ConsensusError> {
        let spent: Vec<(OutPoint, TxOut)> = tx
            .inputs
            .iter()
            .zip(prevouts)
            .map(|(input, prevout)| (input.previous_output, prevout.clone()))
            .collect();
        bitcoin_rs_consensus::kernel::verify_tx_scripts(
            tx,
            &spent,
            flags,
            bitcoin_rs_consensus::ValidationEngine::Kernel,
            None,
        )
    }

    fn interpreter_result(
        tx: &Tx,
        prevouts: &[TxOut],
        flags: VerifyFlags,
    ) -> Result<(), TestError> {
        for (input_index, (input, prevout)) in tx.inputs.iter().zip(prevouts).enumerate() {
            let witness = input.witness.clone();
            let passed = Interpreter
                .execute_with_prevouts(
                    &prevout.script_pubkey,
                    &input.script_sig,
                    &witness,
                    flags,
                    prevouts,
                    tx,
                    input_index,
                )
                .map_err(|source| TestError::Interpreter {
                    input: input_index,
                    source,
                })?;
            if !passed {
                return Err(TestError::InterpreterRejected { input: input_index });
            }
        }
        Ok(())
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Mutation {
        Pristine,
        FlipSignatureBit,
        TruncateScriptSig,
        WrongSighashTypeByte,
        TamperWitness,
        TruncateWitness,
    }

    impl Mutation {
        const ALL: [Self; 6] = [
            Self::Pristine,
            Self::FlipSignatureBit,
            Self::TruncateScriptSig,
            Self::WrongSighashTypeByte,
            Self::TamperWitness,
            Self::TruncateWitness,
        ];

        const fn expected(self) -> Verdict {
            match self {
                Self::Pristine => Verdict::Accept,
                _ => Verdict::Reject,
            }
        }

        fn apply(self, tx: &Tx) -> Option<Tx> {
            let mut tx = tx.clone();
            let applied = match self {
                Self::Pristine => true,
                Self::FlipSignatureBit => flip_signature_bit(&mut tx),
                Self::TruncateScriptSig => truncate_script_sig(&mut tx),
                Self::WrongSighashTypeByte => wrong_sighash_type_byte(&mut tx),
                Self::TamperWitness => tamper_witness(&mut tx),
                Self::TruncateWitness => truncate_witness(&mut tx),
            };
            applied.then_some(tx)
        }
    }

    fn der_sig_range(script: &[u8]) -> Option<(usize, usize)> {
        let mut cursor = 0usize;
        while let Some(&opcode) = script.get(cursor) {
            let (payload_start, payload_len) = match opcode {
                1..=75 => (cursor.checked_add(1)?, usize::from(opcode)),
                0x4c => {
                    let len = *script.get(cursor.checked_add(1)?)?;
                    (cursor.checked_add(2)?, usize::from(len))
                }
                0x4d => {
                    let low = *script.get(cursor.checked_add(1)?)?;
                    let high = *script.get(cursor.checked_add(2)?)?;
                    (
                        cursor.checked_add(3)?,
                        usize::from(u16::from_le_bytes([low, high])),
                    )
                }
                _ => {
                    cursor = cursor.checked_add(1)?;
                    continue;
                }
            };
            let payload_end = payload_start.checked_add(payload_len)?;
            let payload = script.get(payload_start..payload_end)?;
            if looks_like_der_sig(payload) {
                return Some((payload_start, payload_len));
            }
            cursor = payload_end;
        }
        None
    }

    fn looks_like_der_sig(payload: &[u8]) -> bool {
        (9..=73).contains(&payload.len())
            && payload.first() == Some(&0x30)
            && payload
                .last()
                .is_some_and(|byte| matches!(byte & 0x7f, 1..=3))
    }

    fn is_signature_element(element: &[u8]) -> bool {
        looks_like_der_sig(element) || matches!(element.len(), 64 | 65)
    }

    fn flip_signature_bit(tx: &mut Tx) -> bool {
        for input in &mut tx.inputs {
            let mut bytes = input.script_sig.clone();
            if let Some((start, len)) = der_sig_range(&bytes)
                && let Some(mid) = start.checked_add(len / 2)
                && let Some(byte) = bytes.get_mut(mid)
            {
                *byte ^= 0x01;
                input.script_sig = bytes;
                return true;
            }
        }
        for input in &mut tx.inputs {
            let mut elements: Vec<Vec<u8>> = input.witness.iter().map(<[u8]>::to_vec).collect();
            if let Some(element) = elements
                .iter_mut()
                .find(|element| is_signature_element(element))
            {
                let mid = element.len() / 2;
                if let Some(byte) = element.get_mut(mid) {
                    *byte ^= 0x01;
                    input.witness = Witness::from_stack(elements);
                    return true;
                }
            }
        }
        false
    }

    fn truncate_script_sig(tx: &mut Tx) -> bool {
        for input in &mut tx.inputs {
            let mut bytes = input.script_sig.clone();
            if bytes.pop().is_some() {
                input.script_sig = bytes;
                return true;
            }
        }
        false
    }

    fn wrong_sighash_type_byte(tx: &mut Tx) -> bool {
        for input in &mut tx.inputs {
            let mut bytes = input.script_sig.clone();
            if let Some((start, len)) = der_sig_range(&bytes)
                && let Some(last) = start.checked_add(len.saturating_sub(1))
                && let Some(byte) = bytes.get_mut(last)
            {
                *byte ^= 0x02;
                input.script_sig = bytes;
                return true;
            }
        }
        for input in &mut tx.inputs {
            let mut elements: Vec<Vec<u8>> = input.witness.iter().map(<[u8]>::to_vec).collect();
            let mut mutated = false;
            for element in &mut elements {
                if looks_like_der_sig(element) || element.len() == 65 {
                    if let Some(byte) = element.last_mut() {
                        *byte ^= 0x02;
                        mutated = true;
                        break;
                    }
                }
                if element.len() == 64 {
                    element.push(0x03);
                    mutated = true;
                    break;
                }
            }
            if mutated {
                input.witness = Witness::from_stack(elements);
                return true;
            }
        }
        false
    }

    fn tamper_witness(tx: &mut Tx) -> bool {
        for input in &mut tx.inputs {
            let mut elements: Vec<Vec<u8>> = input.witness.iter().map(<[u8]>::to_vec).collect();
            if let Some(last) = elements.last_mut()
                && !last.is_empty()
            {
                let mid = last.len() / 2;
                if let Some(byte) = last.get_mut(mid) {
                    *byte ^= 0x01;
                    input.witness = Witness::from_stack(elements);
                    return true;
                }
            }
        }
        false
    }

    fn truncate_witness(tx: &mut Tx) -> bool {
        for input in &mut tx.inputs {
            let mut elements: Vec<Vec<u8>> = input.witness.iter().map(<[u8]>::to_vec).collect();
            if elements.pop().is_some() {
                input.witness = Witness::from_stack(elements);
                return true;
            }
        }
        false
    }

    #[derive(Deserialize)]
    struct FixtureFile {
        name: String,
        class: String,
        txid: String,
        wtxid: String,
        height: u32,
        #[allow(dead_code, reason = "provenance lives in the JSON; read by humans")]
        source: String,
        flags: String,
        interpreter_parity: bool,
        tx_hex: String,
        prevouts: Vec<PrevoutFile>,
    }

    #[derive(Deserialize)]
    struct PrevoutFile {
        script_hex: String,
        amount_sat: u64,
    }

    struct Fixture {
        name: String,
        class: String,
        height: u32,
        interpreter_parity: bool,
        tx: Tx,
        prevouts: Vec<TxOut>,
        flags: VerifyFlags,
    }

    fn vectors_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/consensus/vectors/scripts")
    }

    fn load_fixtures() -> Result<Vec<Fixture>, TestError> {
        let dir = vectors_dir();
        let entries = std::fs::read_dir(&dir)?;
        let mut paths: Vec<PathBuf> = entries
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<_, _>>()?;
        paths.retain(|path| path.extension().is_some_and(|ext| ext == "json"));
        paths.sort();

        let mut fixtures = Vec::with_capacity(paths.len());
        for path in &paths {
            let text = std::fs::read_to_string(path)?;
            let file: FixtureFile = sonic_rs::from_str(&text)?;
            fixtures.push(validate_fixture(file, path)?);
        }
        Ok(fixtures)
    }

    fn validate_fixture(file: FixtureFile, path: &Path) -> Result<Fixture, TestError> {
        let tx: Tx = deserialize(&decode_hex(&file.tx_hex)?)?;
        let computed_txid = tx.txid().to_string();
        if computed_txid != file.txid {
            return Err(TestError::TxidMismatch {
                path: path.display().to_string(),
                expected: file.txid,
                actual: computed_txid,
            });
        }
        let computed_wtxid = tx.wtxid().to_string();
        if computed_wtxid != file.wtxid {
            return Err(TestError::WtxidMismatch {
                path: path.display().to_string(),
                expected: file.wtxid,
                actual: computed_wtxid,
            });
        }
        if file.prevouts.len() != tx.inputs.len() {
            return Err(TestError::PrevoutMismatch {
                path: path.display().to_string(),
                prevouts: file.prevouts.len(),
                inputs: tx.inputs.len(),
            });
        }
        let flags = VerifyFlags::from_core_names(&file.flags)?;
        let prevouts = file
            .prevouts
            .iter()
            .map(|prevout| {
                Ok(TxOut {
                    value: Amount::from_sat(prevout.amount_sat),
                    script_pubkey: decode_hex(&prevout.script_hex)?.into(),
                })
            })
            .collect::<Result<Vec<_>, TestError>>()?;
        Ok(Fixture {
            name: file.name,
            class: file.class,
            height: file.height,
            interpreter_parity: file.interpreter_parity,
            tx,
            prevouts,
            flags,
        })
    }

    fn decode_hex(hex: &str) -> Result<Vec<u8>, TestError> {
        Ok(Vec::from_hex(hex)?)
    }

    fn require_non_empty(fixtures: &[Fixture]) -> Result<(), TestError> {
        if fixtures.is_empty() {
            return Err(TestError::VacuousVectors("kernel parity fixture corpus"));
        }
        Ok(())
    }

    #[test]
    fn script_verdict_parity() -> TestResult {
        let fixtures = load_fixtures()?;
        require_non_empty(&fixtures)?;

        let mut interpreter_scoped = 0usize;
        for fixture in &fixtures {
            let pristine_bytes = consensus_bytes(&fixture.tx);
            let mut reject_mutations = 0usize;

            for mutation in Mutation::ALL {
                let Some(tx) = mutation.apply(&fixture.tx) else {
                    continue;
                };
                if mutation != Mutation::Pristine {
                    assert_ne!(
                        consensus_bytes(&tx),
                        pristine_bytes,
                        "mutation {mutation:?} must change tx bytes: fixture={}",
                        fixture.name,
                    );
                    reject_mutations = reject_mutations.saturating_add(1);
                }

                let kernel = kernel_result(&tx, &fixture.prevouts, fixture.flags);
                let kernel_verdict = Verdict::of_kernel(&kernel)
                    .unwrap_or_else(|err| panic!("kernel oracle infrastructure error: {err}"));
                assert_eq!(
                    kernel_verdict,
                    mutation.expected(),
                    "kernel verdict: fixture={} class={} height={} mutation={mutation:?} \
                 result={kernel:?}",
                    fixture.name,
                    fixture.class,
                    fixture.height,
                );
                if mutation.expected() == Verdict::Reject {
                    assert!(
                        matches!(kernel, Err(ConsensusError::Script { .. })),
                        "kernel rejection is not a script verdict (infrastructure \
                     failure, not a consensus reject): fixture={} class={} \
                     mutation={mutation:?} result={kernel:?}",
                        fixture.name,
                        fixture.class,
                    );
                }

                if fixture.interpreter_parity {
                    let interpreter = interpreter_result(&tx, &fixture.prevouts, fixture.flags);
                    assert_eq!(
                        Verdict::of_interpreter(&interpreter),
                        kernel_verdict,
                        "engine divergence: fixture={} class={} mutation={mutation:?} \
                     kernel={kernel:?} interpreter={interpreter:?}",
                        fixture.name,
                        fixture.class,
                    );
                }
            }

            assert!(
                reject_mutations >= 2,
                "fixture {} exercised only {reject_mutations} reject mutations; \
             the catalog no longer bites on class {}",
                fixture.name,
                fixture.class,
            );
            if fixture.interpreter_parity {
                interpreter_scoped = interpreter_scoped.saturating_add(1);
            }
        }

        assert_eq!(
            interpreter_scoped,
            fixtures.len(),
            "all fixtures must be interpreter-scoped: every committed spend class must \
         exercise native-kernel differential parity"
        );
        Ok(())
    }

    #[test]
    fn differential_is_non_vacuous() -> TestResult {
        let fixtures = load_fixtures()?;
        let script_path = fixtures
            .iter()
            .find(|fixture| fixture.class == "taproot_scriptpath")
            .ok_or("taproot_scriptpath fixture missing from the committed corpus")?;

        let kernel = kernel_result(&script_path.tx, &script_path.prevouts, script_path.flags);
        let interpreter =
            interpreter_result(&script_path.tx, &script_path.prevouts, script_path.flags);
        let pristine_kernel_verdict =
            Verdict::of_kernel(&kernel).map_err(|_| TestError::Oracle {
                fault: OracleFault::PristineKernel,
            })?;
        assert_eq!(
            pristine_kernel_verdict,
            Verdict::Accept,
            "kernel must accept the pristine taproot script-path fixture: {kernel:?}"
        );
        assert_eq!(
            Verdict::of_interpreter(&interpreter),
            Verdict::Accept,
            "interpreter must accept the pristine taproot script-path fixture: {interpreter:?}"
        );

        let tampered = Mutation::TamperWitness
            .apply(&script_path.tx)
            .ok_or("TamperWitness must apply to a taproot script-path spend")?;
        let kernel = kernel_result(&tampered, &script_path.prevouts, script_path.flags);
        let interpreter = interpreter_result(&tampered, &script_path.prevouts, script_path.flags);
        let tampered_kernel_verdict =
            Verdict::of_kernel(&kernel).map_err(|_| TestError::Oracle {
                fault: OracleFault::TamperedKernel,
            })?;
        assert_eq!(
            tampered_kernel_verdict,
            Verdict::Reject,
            "kernel must reject a tampered control block; a constant Accept means \
         the kernel arm is not reading the transaction: {kernel:?}"
        );
        assert_eq!(
            Verdict::of_interpreter(&interpreter),
            Verdict::Reject,
            "interpreter must reject a tampered control block; a constant Accept \
         means the Rust arm is not reading the transaction: {interpreter:?}"
        );
        Ok(())
    }

    #[test]
    fn pristine_mutation_is_identity() -> TestResult {
        let tx = Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: vec![0x51].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: Script::new(),
            }],
        };
        let pristine = Mutation::Pristine.apply(&tx).ok_or("Pristine must apply")?;
        assert_eq!(consensus_bytes(&tx), consensus_bytes(&pristine));
        Ok(())
    }
}
mod kernel_boundary_parity {
    #![cfg(feature = "kernel")]
    #![expect(clippy::expect_used, reason = "test assertions")]

    use std::str::FromStr;

    use bitcoin_rs_consensus::ConsensusError;
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_consensus::primitives::{
        Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use bitcoin_rs_consensus::script::VerifyFlags;

    use crate::support::error::TestError;

    type TestResult = Result<(), TestError>;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Verdict {
        Accept,
        Reject,
    }

    struct BoundaryCase {
        name: &'static str,
        script_sig: Vec<u8>,
        witness: Vec<Vec<u8>>,
        script_pubkey: Vec<u8>,
        expected: Verdict,
    }

    fn push_data2(payload_len: usize, fill: u8) -> Vec<u8> {
        let len = u16::try_from(payload_len).expect("boundary pushes fit PUSHDATA2");
        let mut script = Vec::with_capacity(3 + payload_len);
        script.push(0x4d);
        script.extend_from_slice(&len.to_le_bytes());
        script.resize(3 + payload_len, fill);
        script
    }

    fn repeats(opcode_byte: u8, count: usize) -> Vec<u8> {
        vec![opcode_byte; count]
    }

    fn multisig_script(keys: usize) -> Vec<u8> {
        let mut script = vec![0x00];
        for _ in 0..keys {
            script.push(0x21);
            script.push(0x02);
            script.extend_from_slice(&[0x11u8; 32]);
        }
        script.push(0xae);
        script
    }

    fn p2tr_program() -> Vec<u8> {
        let mut program = vec![0x51, 0x20];
        program.extend_from_slice(&[0x02u8; 32]);
        program
    }

    fn control_block(size: usize) -> Vec<u8> {
        let mut control = vec![0xc0];
        control.resize(size, 0x02);
        control
    }

    fn script_size_boundary_bytes(extra_tail: usize) -> Vec<u8> {
        let mut script = Vec::new();
        for _ in 0..19 {
            script.push(0x4d);
            script.extend_from_slice(&520u16.to_le_bytes());
            script.resize(script.len() + 520, 0x01);
        }
        script.push(0x3e);
        script.resize(script.len() + 62, 0x01);
        script.resize(script.len() + extra_tail, 0x00);
        script
    }

    fn nop_count_then_op1(nop_count: usize) -> Vec<u8> {
        let mut script = repeats(0x61, nop_count);
        script.push(0x51);
        script
    }

    fn legacy_boundary_cases() -> Vec<BoundaryCase> {
        vec![
            BoundaryCase {
                name: "script_size_at_limit",
                script_sig: Vec::new(),
                witness: Vec::new(),
                script_pubkey: script_size_boundary_bytes(0),
                expected: Verdict::Accept,
            },
            BoundaryCase {
                name: "script_size_over_limit",
                script_sig: Vec::new(),
                witness: Vec::new(),
                script_pubkey: script_size_boundary_bytes(1),
                expected: Verdict::Reject,
            },
            BoundaryCase {
                name: "op_count_at_limit",
                script_sig: Vec::new(),
                witness: Vec::new(),
                script_pubkey: nop_count_then_op1(201),
                expected: Verdict::Accept,
            },
            BoundaryCase {
                name: "op_count_over_limit",
                script_sig: Vec::new(),
                witness: Vec::new(),
                script_pubkey: nop_count_then_op1(202),
                expected: Verdict::Reject,
            },
            BoundaryCase {
                name: "push_element_at_limit",
                script_sig: Vec::new(),
                witness: Vec::new(),
                script_pubkey: push_data2(520, 0x01),
                expected: Verdict::Accept,
            },
            BoundaryCase {
                name: "push_element_over_limit",
                script_sig: Vec::new(),
                witness: Vec::new(),
                script_pubkey: push_data2(521, 0x01),
                expected: Verdict::Reject,
            },
            BoundaryCase {
                name: "stack_depth_at_limit",
                script_sig: Vec::new(),
                witness: Vec::new(),
                script_pubkey: repeats(0x51, 1000),
                expected: Verdict::Accept,
            },
            BoundaryCase {
                name: "stack_depth_over_limit",
                script_sig: Vec::new(),
                witness: Vec::new(),
                script_pubkey: repeats(0x51, 1001),
                expected: Verdict::Reject,
            },
            BoundaryCase {
                name: "multisig_key_count_over_limit",
                script_sig: vec![0x00],
                witness: Vec::new(),
                script_pubkey: multisig_script(21),
                expected: Verdict::Reject,
            },
            BoundaryCase {
                name: "multisig_at_key_limit_without_signatures",
                script_sig: vec![0x00],
                witness: Vec::new(),
                script_pubkey: multisig_script(20),
                expected: Verdict::Reject,
            },
            BoundaryCase {
                name: "nonstandard_nop_is_consensus_valid",
                script_sig: Vec::new(),
                witness: Vec::new(),
                script_pubkey: vec![0xb0, 0x51],
                expected: Verdict::Accept,
            },
            BoundaryCase {
                name: "codeseparator_then_value_accepts",
                script_sig: Vec::new(),
                witness: Vec::new(),
                script_pubkey: vec![0xab, 0x51],
                expected: Verdict::Accept,
            },
        ]
    }

    fn taproot_boundary_cases() -> Vec<BoundaryCase> {
        vec![
            BoundaryCase {
                name: "taproot_control_size_shape_invalid",
                script_sig: Vec::new(),
                witness: vec![vec![0x51], control_block(64)],
                script_pubkey: p2tr_program(),
                expected: Verdict::Reject,
            },
            BoundaryCase {
                name: "taproot_control_tampered_at_valid_shape",
                script_sig: Vec::new(),
                witness: vec![vec![0x51], control_block(65)],
                script_pubkey: p2tr_program(),
                expected: Verdict::Reject,
            },
            BoundaryCase {
                name: "annex_only_witness_invalid",
                script_sig: Vec::new(),
                witness: vec![vec![0x50]],
                script_pubkey: p2tr_program(),
                expected: Verdict::Reject,
            },
            BoundaryCase {
                name: "script_path_annex_without_signature_invalid",
                script_sig: Vec::new(),
                witness: vec![vec![0x51], control_block(65), vec![0x50]],
                script_pubkey: p2tr_program(),
                expected: Verdict::Reject,
            },
        ]
    }

    fn boundary_cases() -> Vec<BoundaryCase> {
        let mut cases = legacy_boundary_cases();
        cases.extend(taproot_boundary_cases());
        cases
    }

    fn boundary_tx(case: &BoundaryCase) -> (Tx, Vec<(OutPoint, TxOut)>) {
        let txid =
            Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .expect("boundary prevout txid");
        let outpoint = OutPoint::new(txid, 0);
        let tx = Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: case.script_sig.clone().into(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(case.witness.clone()),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: Script::new(),
            }],
        };
        let prevouts = vec![(
            outpoint,
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: Script::from_bytes(case.script_pubkey.clone()),
            },
        )];
        (tx, prevouts)
    }

    fn engine_verdict(
        tx: &Tx,
        prevouts: &[(OutPoint, TxOut)],
        flags: VerifyFlags,
        engine: ValidationEngine,
    ) -> Result<Verdict, ConsensusError> {
        match bitcoin_rs_consensus::kernel::verify_tx_scripts(tx, prevouts, flags, engine, None) {
            Ok(()) => Ok(Verdict::Accept),
            Err(ConsensusError::Script { .. }) => Ok(Verdict::Reject),
            Err(error) => Err(error),
        }
    }

    #[test]
    fn consensus_limit_boundaries_parity() -> TestResult {
        let cases = boundary_cases();
        assert!(!cases.is_empty(), "boundary parity case table is empty");

        for case in &cases {
            let (tx, prevouts) = boundary_tx(case);
            let native = engine_verdict(
                &tx,
                &prevouts,
                VerifyFlags::MANDATORY,
                ValidationEngine::Native,
            )
            .map_err(TestError::Consensus)?;
            let kernel = engine_verdict(
                &tx,
                &prevouts,
                VerifyFlags::MANDATORY,
                ValidationEngine::Kernel,
            )
            .map_err(TestError::Consensus)?;
            assert_eq!(
                native, kernel,
                "engine divergence on boundary {}: native={native:?} kernel={kernel:?}",
                case.name,
            );
            assert_eq!(
                kernel, case.expected,
                "kernel oracle disagrees with the Core boundary semantics of {}",
                case.name,
            );
            if case.expected == Verdict::Reject {
                let verdict = engine_verdict(
                    &tx,
                    &prevouts,
                    VerifyFlags::MANDATORY,
                    ValidationEngine::Kernel,
                )
                .map_err(TestError::Consensus)?;
                assert_eq!(
                    verdict,
                    Verdict::Reject,
                    "reject boundary {} must stay a verdict, not infrastructure",
                    case.name,
                );
            }
        }
        Ok(())
    }
}
mod kernel_vector_parity {
    #![cfg(feature = "kernel")]

    use std::path::Path;
    use std::str::FromStr;

    use bitcoin::hex::FromHex;
    use bitcoin_rs_consensus::ConsensusError;
    use bitcoin_rs_consensus::primitives::{
        OutPoint, Tx, TxOut, Txid, consensus_bytes, deserialize,
    };
    use bitcoin_rs_consensus::script::{VerifyFlags, push_int};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

    use crate::support::error::{RowFault, RowFlagNames, TestError, TokenText};

    type TestResult = Result<(), TestError>;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Verdict {
        Accept,
        Reject,
    }

    fn kernel_verdict(
        tx: &Tx,
        prevouts: &[(OutPoint, TxOut)],
        flags: VerifyFlags,
    ) -> Result<Verdict, ConsensusError> {
        match bitcoin_rs_consensus::kernel::verify_tx_scripts(
            tx,
            prevouts,
            flags,
            bitcoin_rs_consensus::ValidationEngine::Kernel,
            None,
        ) {
            Ok(()) => Ok(Verdict::Accept),
            Err(ConsensusError::Script { .. }) => Ok(Verdict::Reject),
            Err(err) => Err(err),
        }
    }

    fn parse_core_asm(asm: &str) -> Result<Vec<u8>, TestError> {
        let mut script = Vec::new();
        for token in asm.split_whitespace() {
            if let Some(hex) = token.strip_prefix("0x") {
                script.extend_from_slice(&hex_to_bytes(hex)?);
            } else if let Ok(n) = token.parse::<i64>() {
                script.extend_from_slice(&push_int(n));
            } else {
                let byte = resolve_opcode(token).ok_or_else(|| TestError::UnknownOpcode {
                    token: TokenText(token.to_owned()),
                })?;
                script.push(byte);
            }
        }
        Ok(script)
    }

    fn resolve_opcode(name: &str) -> Option<u8> {
        use bitcoin_rs_consensus::script::opcode::*;
        let bare = name.strip_prefix("OP_").unwrap_or(name);
        Some(match bare {
            "0" | "EMPTY" => OP_0,
            "PUSHDATA1" => 0x4c,
            "PUSHDATA2" => 0x4d,
            "PUSHDATA4" => 0x4e,
            "1NEGATE" => OP_1NEGATE,
            "1" | "PUSHNUM_1" => OP_PUSHNUM_1,
            "2" | "PUSHNUM_2" => 0x52,
            "3" | "PUSHNUM_3" => 0x53,
            "4" | "PUSHNUM_4" => 0x54,
            "5" | "PUSHNUM_5" => 0x55,
            "6" | "PUSHNUM_6" => 0x56,
            "7" | "PUSHNUM_7" => 0x57,
            "8" | "PUSHNUM_8" => 0x58,
            "9" | "PUSHNUM_9" => 0x59,
            "10" | "PUSHNUM_10" => 0x5a,
            "11" | "PUSHNUM_11" => 0x5b,
            "12" | "PUSHNUM_12" => 0x5c,
            "13" | "PUSHNUM_13" => 0x5d,
            "14" | "PUSHNUM_14" => 0x5e,
            "15" | "PUSHNUM_15" => 0x5f,
            "16" | "PUSHNUM_16" => OP_PUSHNUM_16,
            "NOP" => 0x61,
            "VER" => 0x62,
            "IF" => 0x63,
            "NOTIF" => 0x64,
            "VERIF" => 0x65,
            "VERNOTIF" => 0x66,
            "ELSE" => 0x67,
            "ENDIF" => 0x68,
            "VERIFY" => 0x69,
            "RETURN" => OP_RETURN,
            "TOALTSTACK" => 0x6b,
            "FROMALTSTACK" => 0x6c,
            "2DROP" => 0x6d,
            "2DUP" => 0x6e,
            "3DUP" => 0x6f,
            "2OVER" => 0x70,
            "2ROT" => 0x71,
            "2SWAP" => 0x72,
            "IFDUP" => 0x73,
            "DEPTH" => 0x74,
            "DROP" => 0x75,
            "DUP" => OP_DUP,
            "NIP" => 0x77,
            "OVER" => 0x78,
            "PICK" => 0x79,
            "ROLL" => 0x7a,
            "ROT" => 0x7b,
            "SWAP" => 0x7c,
            "TUCK" => 0x7d,
            "CAT" => 0x7e,
            "SUBSTR" => 0x7f,
            "LEFT" => 0x80,
            "RIGHT" => 0x81,
            "SIZE" => 0x82,
            "INVERT" => 0x83,
            "AND" => 0x84,
            "OR" => 0x85,
            "XOR" => 0x86,
            "EQUAL" => OP_EQUAL,
            "EQUALVERIFY" => OP_EQUALVERIFY,
            "1ADD" => 0x8b,
            "1SUB" => 0x8c,
            "2MUL" => 0x8d,
            "2DIV" => 0x8e,
            "NEGATE" => 0x8f,
            "ABS" => 0x90,
            "NOT" => 0x91,
            "0NOTEQUAL" => 0x92,
            "ADD" => 0x93,
            "SUB" => 0x94,
            "MUL" => 0x95,
            "DIV" => 0x96,
            "MOD" => 0x97,
            "LSHIFT" => 0x98,
            "RSHIFT" => 0x99,
            "BOOLAND" => 0x9a,
            "BOOLOR" => 0x9b,
            "NUMEQUAL" => 0x9c,
            "NUMEQUALVERIFY" => 0x9d,
            "NUMNOTEQUAL" => 0x9e,
            "LESSTHAN" => 0x9f,
            "GREATERTHAN" => 0xa0,
            "LESSTHANOREQUAL" => 0xa1,
            "GREATERTHANOREQUAL" => 0xa2,
            "MIN" => 0xa3,
            "MAX" => 0xa4,
            "WITHIN" => 0xa5,
            "RIPEMD160" => 0xa6,
            "SHA1" => 0xa7,
            "SHA256" => 0xa8,
            "HASH160" => OP_HASH160,
            "HASH256" => 0xaa,
            "CODESEPARATOR" => 0xab,
            "CHECKSIG" => OP_CHECKSIG,
            "CHECKSIGVERIFY" => 0xad,
            "CHECKMULTISIG" => OP_CHECKMULTISIG,
            "CHECKMULTISIGVERIFY" => 0xaf,
            "CHECKLOCKTIMEVERIFY" => 0xb1,
            "CHECKSEQUENCEVERIFY" => 0xb2,
            "CHECKSIGADD" => 0xba,
            _ => return None,
        })
    }

    fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, TestError> {
        Ok(Vec::from_hex(hex)?)
    }

    struct VectorRow {
        tx: Tx,
        prevouts: Vec<(OutPoint, TxOut)>,
        flags: VerifyFlags,
        expected: Verdict,
        row_index: usize,
    }

    fn is_policy_only_tx(row: &VectorRow) -> bool {
        if row.expected == Verdict::Accept {
            return false;
        }
        if row.flags.bits() & !VerifyFlags::MANDATORY.bits() == 0 {
            return false;
        }
        let mand_flags = VerifyFlags::from_bits_retain(
            row.flags.filled().bits() & VerifyFlags::MANDATORY.bits(),
        );
        let Ok(prepared) =
            bitcoin_rs_consensus::script::PreparedTransaction::new(&row.tx, &row.prevouts)
        else {
            return false;
        };
        for input_idx in 0..row.tx.inputs.len() {
            let result = prepared.verify_input(input_idx, mand_flags, None);
            if !matches!(result, Ok(true)) {
                return false;
            }
        }
        true
    }

    const FULL_FLAGS: VerifyFlags = VerifyFlags::STANDARD
        .union(VerifyFlags::SIGPUSHONLY)
        .union(VerifyFlags::CONST_SCRIPTCODE)
        .union(VerifyFlags::MINIMALIF);

    fn tx_valid_flags(names: &str) -> Result<VerifyFlags, TestError> {
        let parsed = VerifyFlags::from_core_names(names)?;
        let effective = VerifyFlags::from_bits_retain(FULL_FLAGS.bits() & !parsed.bits());
        if effective != effective.filled() {
            return Err(TestError::UnfilledFlags {
                names: RowFlagNames("full flag set"),
            });
        }
        Ok(effective)
    }

    fn tx_invalid_flags(names: &str) -> Result<VerifyFlags, TestError> {
        let parsed = VerifyFlags::from_core_names(names)?;
        if parsed != parsed.filled() {
            return Err(TestError::UnfilledFlags {
                names: RowFlagNames("test flags"),
            });
        }
        Ok(parsed)
    }

    fn load_vectors(name: &str, expected: Verdict) -> Result<Vec<VectorRow>, TestError> {
        let path = Path::new("../../testdata/consensus/vectors").join(name);
        let text = std::fs::read_to_string(&path)?;
        let root: Vec<Value> = sonic_rs::from_str(&text)?;

        let mut rows = Vec::new();
        for (index, row) in root.iter().enumerate() {
            let Some(arr) = row.as_array() else {
                continue;
            };
            if arr.len() < 3 || !arr[0].is_array() || arr[1].as_str().is_none() {
                continue;
            }

            let flags_str = arr[2].as_str().unwrap_or("NONE");
            if flags_str.contains("BADTX") {
                continue;
            }

            let tx_hex = arr[1].as_str().ok_or(TestError::Row {
                row: index,
                fault: RowFault::NotText("tx hex"),
            })?;
            let tx_bytes = hex_to_bytes(tx_hex)?;
            let tx: Tx = deserialize(&tx_bytes)
                .map_err(|source| TestError::RowDecode { row: index, source })?;

            let flags = match expected {
                Verdict::Accept => tx_valid_flags(flags_str),
                Verdict::Reject => tx_invalid_flags(flags_str),
            }
            .map_err(|_| TestError::Row {
                row: index,
                fault: RowFault::NotText("flags"),
            })?;

            let prevout_specs = arr[0].as_array().ok_or(TestError::Row {
                row: index,
                fault: RowFault::NotArray("prevout specs"),
            })?;
            let mut available_prevouts = Vec::with_capacity(prevout_specs.len());
            for spec in prevout_specs {
                let spec = spec.as_array().ok_or(TestError::Row {
                    row: index,
                    fault: RowFault::NotArray("prevout spec"),
                })?;
                let hash_hex = spec[0].as_str().ok_or(TestError::Row {
                    row: index,
                    fault: RowFault::NotText("prevout hash"),
                })?;
                let vout_signed = spec[1].as_i64().ok_or(TestError::Row {
                    row: index,
                    fault: RowFault::NotInteger("prevout vout"),
                })?;
                let vout = if vout_signed == -1 {
                    u32::MAX
                } else {
                    u32::try_from(vout_signed).map_err(|_| TestError::Row {
                        row: index,
                        fault: RowFault::OutOfRange("prevout vout"),
                    })?
                };
                let script_asm = spec[2].as_str().ok_or(TestError::Row {
                    row: index,
                    fault: RowFault::NotText("prevout script"),
                })?;
                let amount = spec
                    .get(3)
                    .and_then(sonic_rs::JsonValueTrait::as_u64)
                    .unwrap_or(0);

                let script_pubkey = parse_core_asm(script_asm)?;

                let txid = Txid::from_str(hash_hex).map_err(|_| TestError::Row {
                    row: index,
                    fault: RowFault::NotText("prevout txid"),
                })?;
                let outpoint = OutPoint::new(txid, vout);

                available_prevouts.push((
                    outpoint,
                    TxOut {
                        value: bitcoin_rs_consensus::primitives::Amount::from_sat(amount),
                        script_pubkey: script_pubkey.into(),
                    },
                ));
            }

            let mut prevouts = Vec::with_capacity(tx.inputs.len());
            for input in &tx.inputs {
                let Some((_, spent)) = available_prevouts
                    .iter()
                    .find(|(op, _)| *op == input.previous_output)
                else {
                    return Err(TestError::RowMissingPrevout {
                        row: index,
                        outpoint: input.previous_output,
                    });
                };
                prevouts.push((input.previous_output, spent.clone()));
            }

            rows.push(VectorRow {
                tx,
                prevouts,
                flags,
                expected,
                row_index: index + 1,
            });
        }
        Ok(rows)
    }

    #[test]
    fn kernel_verdict_matches_mandatory_core_catalogs() -> TestResult {
        for (name, expected) in [
            ("tx_valid.json", Verdict::Accept),
            ("tx_invalid.json", Verdict::Reject),
        ] {
            let rows = load_vectors(name, expected)?;
            require_non_empty(&rows, name)?;
            let runnable: Vec<&VectorRow> =
                rows.iter().filter(|row| !is_policy_only_tx(row)).collect();
            assert!(!runnable.is_empty(), "{name}: zero runnable rows");
            let mismatches: Vec<String> = runnable
            .iter()
            .filter_map(|row| match kernel_verdict(&row.tx, &row.prevouts, row.flags) {
                Ok(actual) => (actual != row.expected).then(|| {
                    format!(
                        "{name} row {}: expected {:?}, got {actual:?}",
                        row.row_index, row.expected
                    )
                }),
                Err(err) => Some(format!(
                    "{name} row {}: kernel oracle infrastructure error (must fail closed): {err}",
                    row.row_index
                )),
            })
            .collect();
            println!(
                "{name}: {} executed rows, {} policy rows skipped",
                runnable.len(),
                rows.len() - runnable.len()
            );
            assert!(
                mismatches.is_empty(),
                "{} mismatches:\n{}",
                mismatches.len(),
                mismatches.join("\n")
            );
        }
        Ok(())
    }

    fn require_non_empty(rows: &[VectorRow], name: &'static str) -> Result<(), TestError> {
        if rows.is_empty() {
            return Err(TestError::VacuousVectors(name));
        }
        Ok(())
    }

    #[test]
    fn non_vacuous_wrong_verdict_goes_red() -> TestResult {
        let valid_rows = load_vectors("tx_valid.json", Verdict::Accept)?;
        require_non_empty(&valid_rows, "tx_valid.json")?;
        let valid_row = &valid_rows[0];
        let actual_valid = kernel_verdict(&valid_row.tx, &valid_row.prevouts, valid_row.flags)?;
        assert_eq!(
            actual_valid,
            Verdict::Accept,
            "tx_valid row must be accepted"
        );

        let mut tampered_tx = valid_row.tx.clone();
        tampered_tx.inputs[0].script_sig =
            bitcoin_rs_consensus::primitives::Script::from_bytes(vec![0x00]);
        let tampered_verdict = kernel_verdict(&tampered_tx, &valid_row.prevouts, valid_row.flags)?;
        assert_eq!(
            tampered_verdict,
            Verdict::Reject,
            "tampered transaction must be rejected by kernel oracle"
        );

        let invalid_rows = load_vectors("tx_invalid.json", Verdict::Reject)?;
        require_non_empty(&invalid_rows, "tx_invalid.json")?;
        let invalid_row = invalid_rows
            .iter()
            .find(|row| !is_policy_only_tx(row))
            .ok_or("no runnable invalid rows found")?;
        let actual_invalid =
            kernel_verdict(&invalid_row.tx, &invalid_row.prevouts, invalid_row.flags)?;
        assert_eq!(
            actual_invalid,
            Verdict::Reject,
            "tx_invalid row must be rejected"
        );

        Ok(())
    }

    #[test]
    fn kernel_infrastructure_error_fails_closed() -> TestResult {
        let rows = load_vectors("tx_invalid.json", Verdict::Reject)?;
        require_non_empty(&rows, "tx_invalid.json")?;
        let row = rows
            .iter()
            .find(|row| !is_policy_only_tx(row))
            .ok_or("no runnable invalid rows found")?;

        let empty_prevouts: Vec<(OutPoint, TxOut)> = Vec::new();
        let verdict_result = kernel_verdict(&row.tx, &empty_prevouts, row.flags);
        assert!(
            matches!(verdict_result, Err(ConsensusError::PrevoutCount { .. })),
            "empty prevouts must produce an infrastructure error, got {verdict_result:?}"
        );
        assert_ne!(
            verdict_result.as_ref().ok(),
            Some(&Verdict::Reject),
            "infrastructure error must never masquerade as expected consensus Reject"
        );

        let tx_bytes = consensus_bytes(&row.tx);
        let kernel_tx = bitcoinkernel::Transaction::new(&tx_bytes)?;
        let kernel_prevouts = row
            .prevouts
            .iter()
            .map(|(_, prevout)| {
                let script = bitcoinkernel::ScriptPubkey::new(&prevout.script_pubkey)?;
                let amount = i64::try_from(prevout.value.to_sat())?;
                Ok(bitcoinkernel::TxOut::new(&script, amount))
            })
            .collect::<Result<Vec<_>, TestError>>()?;
        let precomputed =
            bitcoinkernel::PrecomputedTransactionData::new(&kernel_tx, &kernel_prevouts)?;
        let script = bitcoinkernel::ScriptPubkey::new(&row.prevouts[0].1.script_pubkey)?;
        let amount = i64::try_from(row.prevouts[0].1.value.to_sat())?;
        let kernel_verify_err = bitcoinkernel::verify(
            &script,
            Some(amount),
            &kernel_tx,
            999,
            Some(bitcoinkernel::VERIFY_ALL),
            &precomputed,
        );
        assert!(
            matches!(
                kernel_verify_err,
                Err(bitcoinkernel::KernelError::ScriptVerify(
                    bitcoinkernel::ScriptVerifyError::TxInputIndex
                ))
            ),
            "out of bounds index must produce ScriptVerifyError::TxInputIndex from kernel, got: {kernel_verify_err:?}"
        );

        Ok(())
    }
}
mod overhaul_parse_parity {
    #![expect(clippy::expect_used, reason = "test assertions")]
    use std::str::FromStr;

    use bitcoin::merkle_tree::calculate_root;
    use bitcoin_rs_consensus::BlockFacts;
    use bitcoin_rs_consensus::kernel::BlockParse;
    use bitcoin_rs_consensus::primitives::layout::ParsedBlock;
    use bitcoin_rs_consensus::primitives::{Block, Tx, Txid, Wtxid, consensus_bytes};
    use bitcoin_rs_consensus::verify_block::{
        BlockRuleContext, block_witness_commitment_matches, verify_block_rules,
        verify_block_rules_precomputed,
    };
    use bitcoin_rs_consensus::{ConsensusError, ValidationEngine};

    const LEGACY_HEIGHT: u32 = 170;
    const SEGWIT_HEIGHT: u32 = 481_824;
    const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

    fn fixture_bytes(height: u32) -> Vec<u8> {
        let path = format!(
            "{}/../../testdata/consensus/blocks/{}.bin",
            env!("CARGO_MANIFEST_DIR"),
            height
        );
        std::fs::read(&path).unwrap_or_else(|error| {
            panic!("missing fixture {path} (run scripts/fetch-golden.sh): {error}")
        })
    }

    fn fixture_txids(height: u32) -> Vec<Txid> {
        let path = format!(
            "{}/../../testdata/consensus/blocks/{}.txids.txt",
            env!("CARGO_MANIFEST_DIR"),
            height
        );
        let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("missing fixture {path} (run scripts/fetch-golden.sh): {error}")
        });
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                Txid::from_str(line.trim())
                    .unwrap_or_else(|error| panic!("bad fixture txid: {error}"))
            })
            .collect()
    }

    const fn compact_size_len(value: u64) -> u32 {
        match value {
            0..=0xfc => 1,
            0xfd..=0xffff => 3,
            0x1_0000..=0xffff_ffff => 5,
            _ => 9,
        }
    }

    #[test]
    fn golden_facts_match_oracle_on_ids_weight_positions_and_merkle() {
        for height in [LEGACY_HEIGHT, SEGWIT_HEIGHT] {
            let bytes = fixture_bytes(height);
            let oracle: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)
                .unwrap_or_else(|error| panic!("height {height}: oracle decode failed: {error}"));
            let expected_txids = fixture_txids(height);
            let mut reader = bytes.as_slice();
            let parsed = ParsedBlock::parse(&mut reader)
                .unwrap_or_else(|error| panic!("height {height}: layout parse failed: {error:?}"));
            assert!(
                reader.is_empty(),
                "height {height}: layout left trailing bytes"
            );
            let facts = BlockFacts::from_parsed(&parsed);

            assert_eq!(
                facts.tx_count(),
                oracle.txdata.len(),
                "height {height}: tx count"
            );
            assert_eq!(
                facts.tx_count(),
                expected_txids.len(),
                "height {height}: fixture tx count"
            );
            for (index, expected) in expected_txids.iter().enumerate() {
                let ours = facts.txids()[index].to_string();
                let oracle_id = oracle.txdata[index].compute_txid().to_string();
                let fixture_id = expected.to_string();
                assert_eq!(ours, oracle_id, "height {height}: txid mismatch at {index}");
                assert_eq!(
                    ours, fixture_id,
                    "height {height}: fixture txid mismatch at {index}"
                );
            }

            let oracle_has_witness = oracle
                .txdata
                .iter()
                .any(|tx| tx.input.iter().any(|input| !input.witness.is_empty()));
            assert_eq!(
                facts.has_witness(),
                oracle_has_witness,
                "height {height}: witness presence"
            );
            match facts.wtxids() {
                Some(wtxids) => {
                    assert!(
                        oracle_has_witness,
                        "height {height}: wtxids without witness data"
                    );
                    for (index, wtxid) in wtxids.iter().enumerate() {
                        assert_eq!(
                            wtxid.to_string(),
                            oracle.txdata[index].compute_wtxid().to_string(),
                            "height {height}: wtxid mismatch at {index}"
                        );
                    }
                }
                None => assert!(
                    !oracle_has_witness,
                    "height {height}: witness data but no wtxids"
                ),
            }

            assert_eq!(
                facts.weight(),
                oracle.weight().to_wu(),
                "height {height}: block weight"
            );

            let spans = parsed.transaction_spans();
            assert_eq!(spans.len(), facts.tx_count(), "height {height}: span count");
            assert_eq!(
                parsed.tx_count_span().start(),
                80,
                "height {height}: count prefix not after header"
            );
            assert_eq!(
                u64::from(compact_size_len(
                    u64::try_from(facts.tx_count()).unwrap_or(u64::MAX)
                )),
                u64::from(parsed.tx_count_span().len()),
                "height {height}: count prefix length"
            );
            let mut expected_start = parsed.tx_count_span().end();
            for (index, span) in spans.iter().enumerate() {
                assert_eq!(
                    u64::from(span.start()),
                    expected_start,
                    "height {height}: tx {index} span start"
                );
                let span_bytes = parsed.transactions()[index]
                    .span_bytes(*span)
                    .unwrap_or_else(|| panic!("height {height}: tx {index} span outside image"));
                let oracle_bytes = bitcoin::consensus::serialize(&oracle.txdata[index]);
                assert_eq!(
                    span_bytes, oracle_bytes,
                    "height {height}: tx {index} span bytes"
                );
                expected_start = span.end();
            }
            assert_eq!(
                expected_start,
                u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                "height {height}: spans must tile the image"
            );
            assert_eq!(
                parsed.consumed_len(),
                bytes.len(),
                "height {height}: consumed length"
            );

            let oracle_root = calculate_root(oracle.txdata.iter().map(|tx| {
                bitcoin::Txid::from_str(&tx.compute_txid().to_string()).expect("oracle txid")
            }))
            .expect("oracle merkle root")
            .to_string();
            let derived_root = facts
                .merkle_root()
                .unwrap_or_else(|| panic!("height {height}: empty tree over a fixture"))
                .to_string();
            assert_eq!(derived_root, oracle_root, "height {height}: merkle root");
            assert!(
                !facts.merkle_mutated(),
                "height {height}: valid tree flagged as mutated"
            );

            let materialized: Block = parsed.materialize();
            for (index, tx) in materialized.txs.iter().enumerate() {
                assert_eq!(
                    &tx.txid(),
                    &facts.txids()[index],
                    "height {height}: materialized txid"
                );
            }
            assert_eq!(
                consensus_bytes(&materialized),
                bytes,
                "height {height}: re-encode"
            );
        }
    }

    fn assert_parse_matches_oracle(
        parsed: BlockParse,
        oracle: &bitcoin::Block,
        materialized: &Block,
    ) -> BlockFacts {
        assert_eq!(parsed.transaction_count(), oracle.txdata.len());
        let (_, facts) = parsed
            .into_parts(&materialized.txs)
            .unwrap_or_else(|error| panic!("parse facts failed: {error:?}"));
        let parsed_txids = facts.txids();
        assert_eq!(parsed_txids.len(), oracle.txdata.len());
        for (ours, oracle_tx) in parsed_txids.iter().zip(&oracle.txdata) {
            assert_eq!(ours.to_string(), oracle_tx.compute_txid().to_string());
        }

        assert_eq!(facts.tx_count(), oracle.txdata.len());
        assert_eq!(facts.weight(), oracle.weight().to_wu());
        assert_eq!(
        facts.merkle_root().expect("non-empty tree").to_string(),
        calculate_root(
            oracle
                .txdata
                .iter()
                .map(|tx| bitcoin::Txid::from_str(&tx.compute_txid().to_string()).expect("txid"))
                .collect::<Vec<_>>()
                .into_iter(),
        )
        .expect("oracle merkle root")
        .to_string(),
    );
        facts
    }

    fn fixture_parts(height: u32) -> (Vec<u8>, bitcoin::Block, Block) {
        let bytes = fixture_bytes(height);
        let oracle: bitcoin::Block =
            bitcoin::consensus::deserialize(&bytes).expect("oracle decode");
        let mut reader = bytes.as_slice();
        let layout = ParsedBlock::parse(&mut reader).expect("layout parse");
        let materialized: Block = layout.materialize();
        (bytes, oracle, materialized)
    }

    #[test]
    fn native_block_parse_matches_oracle_identities() {
        let (bytes, oracle, materialized) = fixture_parts(SEGWIT_HEIGHT);
        let parsed = BlockParse::parse(&bytes, ValidationEngine::Native)
            .expect("one-pass native block parse");
        let facts = assert_parse_matches_oracle(parsed, &oracle, &materialized);
        assert!(facts.wtxids().is_some());
        let mut padded = bytes;
        padded.push(0x00);
        assert!(
            BlockParse::parse(&padded, ValidationEngine::Native).is_err(),
            "trailing bytes must be rejected"
        );
    }

    #[test]
    #[cfg(feature = "kernel")]
    fn kernel_block_parse_matches_oracle_identities() {
        let (bytes, oracle, materialized) = fixture_parts(SEGWIT_HEIGHT);
        let parsed = BlockParse::parse(&bytes, ValidationEngine::Kernel)
            .expect("one-pass kernel block parse");
        assert_parse_matches_oracle(parsed, &oracle, &materialized);
    }

    #[test]
    fn coinbase_witness_leaf_is_zero_for_commitment_only() {
        use bitcoin::hashes::{Hash, sha256};
        let bytes = fixture_bytes(SEGWIT_HEIGHT);
        let oracle: bitcoin::Block =
            bitcoin::consensus::deserialize(&bytes).expect("oracle decode");
        let mut reader = bytes.as_slice();
        let parsed = ParsedBlock::parse(&mut reader).expect("layout parse");
        let facts = BlockFacts::from_parsed(&parsed);
        let materialized: Block = parsed.materialize();
        let wtxids: &[Wtxid] = facts.wtxids().expect("segwit fixture carries witness IDs");

        assert!(
            block_witness_commitment_matches(&materialized, wtxids),
            "production commitment check must accept the fixture"
        );

        let oracle_leaves = std::iter::once(
            bitcoin::Txid::from_str(&"0".repeat(64)).expect("zero leaf"),
        )
        .chain(oracle.txdata.iter().skip(1).map(|tx| {
            bitcoin::Txid::from_str(&tx.compute_wtxid().to_string()).expect("oracle wtxid leaf")
        }));
        let witness_root = calculate_root(oracle_leaves).expect("oracle witness root");
        let coinbase = &oracle.txdata[0];
        let reserved = coinbase.input[0]
            .witness
            .iter()
            .find(|item| item.len() == 32)
            .expect("coinbase witness reserved value");
        let mut preimage = Vec::with_capacity(64);
        preimage.extend_from_slice(&witness_root.to_byte_array());
        preimage.extend_from_slice(reserved);
        let commitment = sha256::Hash::hash(sha256::Hash::hash(&preimage).as_byte_array());

        let stored = coinbase
            .output
            .iter()
            .find_map(|output| {
                let script = output.script_pubkey.as_bytes();
                if script.len() == 38 && script[..6] == WITNESS_COMMITMENT_PREFIX {
                    Some(&script[6..38])
                } else {
                    None
                }
            })
            .expect("fixture carries a witness commitment output");
        assert_eq!(
            stored,
            commitment.as_byte_array().as_slice(),
            "oracle witness commitment"
        );

        assert_eq!(
            wtxids[0].to_string(),
            coinbase.compute_wtxid().to_string(),
            "coinbase actual wtxid must not be zeroed"
        );
    }

    #[test]
    fn mutated_tree_flags_merkle_mutation_while_unmutated_passes() {
        let bytes = fixture_bytes(LEGACY_HEIGHT);
        let mut reader = bytes.as_slice();
        let parsed = ParsedBlock::parse(&mut reader).expect("layout parse");
        let base: Block = parsed.materialize();
        let coinbase = base.txs[0].clone();
        let spender = base.txs[1].clone();
        let coinbase_id = coinbase.txid();
        let spender_id = spender.txid();
        let oracle_root = calculate_root(
            [
                bitcoin::Txid::from_str(&coinbase_id.to_string()).expect("txid"),
                bitcoin::Txid::from_str(&spender_id.to_string()).expect("txid"),
                bitcoin::Txid::from_str(&spender_id.to_string()).expect("txid"),
                bitcoin::Txid::from_str(&spender_id.to_string()).expect("txid"),
            ]
            .into_iter(),
        )
        .expect("oracle merkle root over mutated tree");
        let mut mutated = base.clone();
        mutated.header.merkle_root = Txid::from_str(&oracle_root.to_string())
            .expect("oracle root")
            .0;
        let leaf = spender.clone();
        let leaf2 = spender;
        let leaf3 = leaf.clone();
        mutated.txs = vec![coinbase, leaf, leaf2, leaf3];
        let mutated_ids = vec![coinbase_id, spender_id, spender_id, spender_id];
        let facts = BlockFacts::from_txids(&mutated.txs, mutated_ids);
        assert!(
            facts.merkle_mutated(),
            "equal real siblings must flag mutation"
        );
        let error = verify_block_rules_precomputed(
            &mutated,
            BlockRuleContext {
                segwit_active: true,
            },
            &facts,
        )
        .expect_err("mutated tree must be rejected");
        assert!(
            matches!(error, ConsensusError::MerkleMutation),
            "expected MerkleMutation, got {error:?}"
        );

        let control_facts =
            BlockFacts::from_txids(&base.txs, base.txs.iter().map(Tx::txid).collect());
        verify_block_rules_precomputed(
            &base,
            BlockRuleContext {
                segwit_active: true,
            },
            &control_facts,
        )
        .unwrap_or_else(|error| panic!("valid fixture must pass rules: {error:?}"));
    }

    #[test]
    fn rules_entry_accepts_golden_fixtures_from_derived_facts() {
        for height in [LEGACY_HEIGHT, SEGWIT_HEIGHT] {
            let bytes = fixture_bytes(height);
            let mut reader = bytes.as_slice();
            let parsed = ParsedBlock::parse(&mut reader).expect("layout parse");
            let block: Block = parsed.materialize();
            verify_block_rules(&block).unwrap_or_else(|error| {
                panic!("height {height}: rules must accept the fixture: {error:?}")
            });
        }
    }
}
mod overhaul_prepared_inputs {
    #![expect(clippy::expect_used, reason = "test assertions")]

    use bitcoin::hashes::Hash as _;
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
        Txid, consensus_bytes,
    };
    use bitcoin_rs_consensus::script::VerifyFlags;
    use bitcoin_rs_consensus::{ConsensusError, UtxoView, ValidationEngine, verify_transaction};

    struct Coins(hashbrown::HashMap<OutPoint, TxOut>);

    impl UtxoView for Coins {
        fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
            self.0.get(outpoint).cloned()
        }
    }

    fn outpoint(byte: u8) -> OutPoint {
        OutPoint::new(Txid(Hash256::from_le_bytes(&[byte; 32])), 0)
    }

    fn two_input_tx() -> (Tx, Coins) {
        let tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: [1, 2]
                .map(|byte| TxIn {
                    previous_output: outpoint(byte),
                    sequence: Sequence::MAX,
                    ..TxIn::default()
                })
                .to_vec(),
            outputs: vec![TxOut {
                value: Amount::from_sat(100),
                script_pubkey: Script::new(),
            }],
        };
        let coins = Coins(
            [1, 2]
                .map(|byte| {
                    (
                        outpoint(byte),
                        TxOut {
                            value: Amount::from_sat(50),
                            script_pubkey: Script::new(),
                        },
                    )
                })
                .into(),
        );
        (tx, coins)
    }

    #[test]
    fn missing_or_duplicate_prevouts_fail_before_scripts() {
        for (second, expected) in [
            (
                outpoint(0xee),
                ConsensusError::MissingPrevout { input_index: 1 },
            ),
            (
                outpoint(1),
                ConsensusError::DuplicateInput { input_index: 1 },
            ),
        ] {
            let (mut tx, coins) = two_input_tx();
            tx.inputs[1].previous_output = second;
            assert_eq!(
                verify_transaction(
                    &tx,
                    &coins,
                    0,
                    0,
                    VerifyFlags::MANDATORY,
                    ValidationEngine::Native,
                    None
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn transaction_identities_match_reference_oracle() {
        let fixture = format!(
            "{}/../../testdata/consensus/blocks/481824.bin",
            env!("CARGO_MANIFEST_DIR")
        );
        let segwit =
            std::fs::read(&fixture).unwrap_or_else(|error| panic!("read {fixture}: {error}"));
        for bytes in [consensus_bytes(&Network::Mainnet.genesis_block()), segwit] {
            let parsed = bitcoin_rs_consensus::primitives::layout::ParsedBlock::parse_exact(&bytes)
                .expect("parse");
            let oracle: bitcoin::Block =
                bitcoin::consensus::deserialize(&bytes).expect("oracle decode");
            let materialized: Block = parsed.materialize();
            assert_eq!(materialized.txs.len(), oracle.txdata.len());
            for (index, (tx, reference)) in materialized.txs.iter().zip(&oracle.txdata).enumerate()
            {
                assert_eq!(
                    tx.txid().0,
                    Hash256::from_le_bytes(reference.compute_txid().as_byte_array()),
                    "txid {index} in {} byte block",
                    bytes.len()
                );
                assert_eq!(
                    tx.wtxid().0,
                    Hash256::from_le_bytes(reference.compute_wtxid().as_byte_array()),
                    "wtxid {index} in {} byte block",
                    bytes.len()
                );
            }
        }
    }
}
mod primitives_adversarial_decode {
    use bitcoin_rs_consensus::primitives::layout::ParsedTransaction;
    use bitcoin_rs_consensus::primitives::varint::{self, VarintError};
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, ConsensusDecode, DecodeError, Header, LockTime, OutPoint, Sequence, Tx,
        TxIn, TxOut, Txid, Witness, consensus_bytes, deserialize,
    };

    fn dummy_tx() -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), 0),
                script_sig: vec![0x51].into(),
                sequence: Sequence::from_consensus(0xffff_fffe),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: vec![0x51].into(),
            }],
            lock_time: LockTime::from_consensus(100),
        }
    }

    #[test]
    fn rejects_noncanonical_varint_prefix_fd_boundaries() {
        assert_eq!(
            varint::decode(&[0xfd, 0x00, 0x00]),
            Err(VarintError::NonCanonical { value: 0 })
        );
        assert_eq!(
            varint::decode(&[0xfd, 0x01, 0x00]),
            Err(VarintError::NonCanonical { value: 1 })
        );
        assert_eq!(
            varint::decode(&[0xfd, 0xfc, 0x00]),
            Err(VarintError::NonCanonical { value: 0xfc })
        );
        assert_eq!(varint::decode(&[0xfd, 0xfd, 0x00]), Ok((0xfd, 3)));
    }

    #[test]
    fn rejects_noncanonical_varint_prefix_fe_boundaries() {
        assert_eq!(
            varint::decode(&[0xfe, 0x00, 0x00, 0x00, 0x00]),
            Err(VarintError::NonCanonical { value: 0 })
        );
        assert_eq!(
            varint::decode(&[0xfe, 0xff, 0xff, 0x00, 0x00]),
            Err(VarintError::NonCanonical { value: 0xffff })
        );
        assert_eq!(
            varint::decode(&[0xfe, 0x00, 0x00, 0x01, 0x00]),
            Ok((0x1_0000, 5))
        );
    }

    #[test]
    fn rejects_noncanonical_varint_prefix_ff_boundaries() {
        assert_eq!(
            varint::decode(&[0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Err(VarintError::NonCanonical { value: 0 })
        );
        assert_eq!(
            varint::decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]),
            Err(VarintError::NonCanonical { value: 0xffff_ffff })
        );
        assert_eq!(
            varint::decode(&[0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
            Ok((0x1_0000_0000, 9))
        );
    }

    #[test]
    fn rejects_truncated_varints_at_all_lengths() {
        assert_eq!(
            varint::decode(&[]),
            Err(VarintError::Truncated {
                prefix: 0,
                needed: 1,
                available: 0,
            })
        );
        assert_eq!(
            varint::decode(&[0xfd]),
            Err(VarintError::Truncated {
                prefix: 0xfd,
                needed: 3,
                available: 1,
            })
        );
        assert_eq!(
            varint::decode(&[0xfe, 0x01, 0x02]),
            Err(VarintError::Truncated {
                prefix: 0xfe,
                needed: 5,
                available: 3,
            })
        );
        assert_eq!(
            varint::decode(&[0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
            Err(VarintError::Truncated {
                prefix: 0xff,
                needed: 9,
                available: 7,
            })
        );
    }

    #[test]
    fn rejects_noncanonical_varint_in_tx_input_count() {
        let mut raw = 1_i32.to_le_bytes().to_vec();
        raw.extend_from_slice(&[0xfd, 0x01, 0x00]);
        assert!(matches!(
            deserialize::<Tx>(&raw),
            Err(DecodeError::Varint(VarintError::NonCanonical { value: 1 }))
        ));
    }

    #[test]
    fn rejects_noncanonical_varint_in_tx_output_count() {
        let tx = dummy_tx();
        let valid_bytes = consensus_bytes(&tx);
        let mut corrupted = valid_bytes[..47].to_vec();
        corrupted.extend_from_slice(&[0xfd, 0x01, 0x00]);
        assert!(matches!(
            deserialize::<Tx>(&corrupted),
            Err(DecodeError::Varint(VarintError::NonCanonical { value: 1 }))
        ));
    }

    #[test]
    fn rejects_noncanonical_varint_in_script_len() {
        let mut out_bytes = 100_u64.to_le_bytes().to_vec();
        out_bytes.extend_from_slice(&[0xfd, 0x02, 0x00, 0x51, 0x51]);
        let mut reader = out_bytes.as_slice();
        assert!(matches!(
            TxOut::consensus_decode(&mut reader),
            Err(DecodeError::Varint(VarintError::NonCanonical { value: 2 }))
        ));
    }

    #[test]
    fn rejects_oversized_counts_without_allocation() {
        let mut raw = 1_i32.to_le_bytes().to_vec();
        raw.extend_from_slice(&[0xfe, 0x00, 0x00, 0x10, 0x00]);
        raw.extend_from_slice(&[0u8; 10]);
        assert!(matches!(
            deserialize::<Tx>(&raw),
            Err(DecodeError::EndOfData { .. })
        ));

        let mut block_raw = vec![0u8; 80];
        block_raw.extend_from_slice(&[0xfe, 0x00, 0x00, 0x10, 0x00]);
        block_raw.extend_from_slice(&[0u8; 10]);
        assert!(matches!(
            deserialize::<Block>(&block_raw),
            Err(DecodeError::EndOfData { .. })
        ));
    }

    #[test]
    fn rejects_max_u64_count_without_panic() {
        let mut raw = 1_i32.to_le_bytes().to_vec();
        raw.extend_from_slice(&[0xff; 9]);
        raw.extend_from_slice(&[0u8; 10]);
        assert!(matches!(
            deserialize::<Tx>(&raw),
            Err(DecodeError::EndOfData { .. })
        ));
    }

    #[test]
    fn rejects_trailing_bytes_on_all_primitives() {
        let header_bytes = [0x55_u8; 80];
        let mut with_trailing = header_bytes.to_vec();
        with_trailing.push(0xab);
        assert_eq!(
            deserialize::<Header>(&with_trailing),
            Err(DecodeError::TrailingBytes { remaining: 1 })
        );

        let mut outpoint_bytes = [0x11_u8; 32].to_vec();
        outpoint_bytes.extend_from_slice(&0_u32.to_le_bytes());
        outpoint_bytes.push(0xab);
        assert_eq!(
            deserialize::<OutPoint>(&outpoint_bytes),
            Err(DecodeError::TrailingBytes { remaining: 1 })
        );

        let tx = dummy_tx();
        let mut tx_bytes = consensus_bytes(&tx);
        tx_bytes.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(
            deserialize::<Tx>(&tx_bytes),
            Err(DecodeError::TrailingBytes { remaining: 2 })
        );

        let block = Block {
            header: Header::default(),
            txs: vec![tx],
        };
        let mut block_bytes = consensus_bytes(&block);
        block_bytes.push(0xff);
        assert_eq!(
            deserialize::<Block>(&block_bytes),
            Err(DecodeError::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn rejects_invalid_segwit_flags() {
        let base = 2_i32.to_le_bytes().to_vec();
        for bad_flag in [0x02_u8, 0x03, 0x7f, 0x80, 0xff] {
            let mut raw = base.clone();
            raw.extend_from_slice(&[0x00, bad_flag]);
            assert_eq!(
                deserialize::<Tx>(&raw),
                Err(DecodeError::InvalidSegwitFlag { got: bad_flag })
            );
        }
    }

    #[test]
    fn rejects_superfluous_witness_with_empty_witnesses() {
        let mut raw = 2_i32.to_le_bytes().to_vec();
        raw.extend_from_slice(&[0x00, 0x01]);
        raw.push(0x01);
        raw.extend_from_slice(&[0xaa; 32]);
        raw.extend_from_slice(&0_u32.to_le_bytes());
        raw.push(0x00);
        raw.extend_from_slice(&0xffff_ffff_u32.to_le_bytes());
        raw.push(0x00);
        raw.push(0x00);
        raw.extend_from_slice(&0_u32.to_le_bytes());

        assert_eq!(
            deserialize::<Tx>(&raw),
            Err(DecodeError::SuperfluousWitness)
        );
    }

    #[test]
    fn accepts_segwit_tx_with_single_empty_witness_item() {
        let mut raw = 2_i32.to_le_bytes().to_vec();
        raw.extend_from_slice(&[0x00, 0x01]);
        raw.push(0x01);
        raw.extend_from_slice(&[0xaa; 32]);
        raw.extend_from_slice(&0_u32.to_le_bytes());
        raw.push(0x00);
        raw.extend_from_slice(&0xffff_ffff_u32.to_le_bytes());
        raw.push(0x00);
        raw.push(0x01);
        raw.push(0x00);
        raw.extend_from_slice(&0_u32.to_le_bytes());

        let parsed = ParsedTransaction::parse_exact(&raw);
        assert!(parsed.is_ok());
        let Ok(tx) = deserialize::<Tx>(&raw) else {
            panic!("must decode");
        };
        assert!(tx.has_witness());
        assert_eq!(tx.inputs[0].witness.len(), 1);
        assert_eq!(tx.inputs[0].witness[0].len(), 0);
    }

    #[test]
    fn amount_constants_and_arithmetic_boundaries() {
        assert_eq!(Amount::ZERO.to_sat(), 0);
        assert_eq!(Amount::SAT.to_sat(), 1);
        assert_eq!(Amount::COIN.to_sat(), 100_000_000);
        assert_eq!(Amount::MAX_MONEY.to_sat(), 2_100_000_000_000_000);

        let limit = Amount::MAX_MONEY;
        let below = Amount::from_sat(limit.to_sat() - 1);
        let above = Amount::from_sat(limit.to_sat() + 1);

        assert!(below < limit);
        assert!(above > limit);
        assert_eq!(limit.saturating_add(Amount::SAT), above);
        assert_eq!(
            Amount::from_sat(u64::MAX).saturating_add(Amount::SAT),
            Amount::from_sat(u64::MAX)
        );
    }

    #[test]
    fn locktime_and_sequence_constants_and_boundaries() {
        assert_eq!(
            bitcoin_rs_consensus::primitives::LOCKTIME_THRESHOLD,
            500_000_000
        );
        assert_eq!(
            bitcoin_rs_consensus::primitives::SEQUENCE_FINAL,
            0xffff_ffff
        );

        let height_bound = LockTime::from_consensus(499_999_999);
        let time_bound = LockTime::from_consensus(500_000_000);
        assert!(height_bound.to_consensus() < bitcoin_rs_consensus::primitives::LOCKTIME_THRESHOLD);
        assert!(time_bound.to_consensus() >= bitcoin_rs_consensus::primitives::LOCKTIME_THRESHOLD);

        let final_seq = Sequence::from_consensus(bitcoin_rs_consensus::primitives::SEQUENCE_FINAL);
        assert_eq!(final_seq, bitcoin_rs_consensus::primitives::SEQUENCE_FINAL);

        let disabled_seq = Sequence::from_consensus(
            bitcoin_rs_consensus::primitives::SEQUENCE_LOCKTIME_DISABLE_FLAG | 0x0a,
        );
        assert_ne!(
            disabled_seq & bitcoin_rs_consensus::primitives::SEQUENCE_LOCKTIME_DISABLE_FLAG,
            0
        );
    }
}
mod primitives_bip_vectors {
    #![expect(clippy::expect_used, reason = "test assertions")]

    use std::path::PathBuf;

    use bitcoin_rs_consensus::primitives::{
        Amount, Script, Sighash, SighashCache, Tx as NativeTx, TxOut, encode::deserialize,
    };
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

    use crate::support::primitives::TestError;

    type Result<T, E = TestError> = std::result::Result<T, E>;

    fn vectors_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/consensus/vectors")
    }

    fn load_json(name: &str) -> Result<Value> {
        let path = vectors_dir().join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
        Ok(sonic_rs::from_str(&text)?)
    }

    fn taproot_hash_type(byte: u8) -> Sighash {
        match byte {
            0 => Sighash::Default,
            1 => Sighash::All,
            2 => Sighash::None,
            3 => Sighash::Single,
            0x81 => Sighash::AllAnyoneCanPay,
            0x82 => Sighash::NoneAnyoneCanPay,
            0x83 => Sighash::SingleAnyoneCanPay,
            other => panic!("unexpected BIP341 hash type {other:#x}"),
        }
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&hex[index..index + 2], 16)
                    .unwrap_or_else(|error| panic!("bad hex at {index}: {error}"))
            })
            .collect()
    }

    fn digest_hex(digest: &bitcoin_rs_consensus::primitives::Hash256) -> String {
        digest
            .as_byte_array()
            .iter()
            .fold(String::new(), |mut acc, b| {
                use std::fmt::Write as _;
                let _ = write!(acc, "{b:02x}");
                acc
            })
    }

    #[test]
    fn bip143_examples_match_spec_digests() -> Result<()> {
        let vectors = load_json("bip143.json")?;
        for example in ["p2wpkh_example", "p2wsh_multisig_example"] {
            let example = vectors
                .get(example)
                .unwrap_or_else(|| panic!("bip143.json missing {example}"));
            let tx_bytes = hex_decode(example["unsigned_tx"].as_str().expect("tx hex"));
            let tx = deserialize::<NativeTx>(&tx_bytes)
                .unwrap_or_else(|error| panic!("{example}: native decode failed: {error}"));
            let script_code = hex_decode(example["script_code"].as_str().expect("script code"));
            let value_sats = example["value_sats"].as_u64().expect("value sats");
            let input_index =
                usize::try_from(example["input_index"].as_u64().expect("input index"))
                    .expect("input index fits usize");
            let cache = SighashCache::new(&tx);

            for vector in example["vectors"].as_array().expect("vectors array") {
                let hash_type = u32::try_from(vector["hash_type"].as_u64().expect("hash type"))
                    .expect("hash type fits u32");
                let expected = vector["sighash"].as_str().expect("sighash hex");
                let ty =
                    Sighash::from_consensus_u8(u8::try_from(hash_type).expect("hash type fits u8"))
                        .unwrap_or_else(|error| {
                            panic!("bip143: hash type {hash_type:#x}: {error}")
                        });

                let cached = cache
                    .segwit_v0_signature_hash(
                        input_index,
                        &script_code,
                        Amount::from_sat(value_sats),
                        ty,
                    )
                    .unwrap_or_else(|error| panic!("bip143 {example}: cache failed: {error}"));
                assert_eq!(
                    digest_hex(&cached),
                    expected,
                    "bip143 {example} hash type {hash_type:#x}"
                );

                let raw = cache
                    .segwit_v0_signature_hash_raw(
                        input_index,
                        &script_code,
                        Amount::from_sat(value_sats),
                        hash_type,
                    )
                    .unwrap_or_else(|error| panic!("bip143 {example}: raw failed: {error}"));
                assert_eq!(
                    digest_hex(&raw),
                    expected,
                    "bip143 {example} raw hash type {hash_type:#x}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn bip341_keypath_vectors_match_spec_digests() -> Result<()> {
        let vectors = load_json("bip341-wallet-test-vectors.json")?;
        let spending = vectors["keyPathSpending"]
            .as_array()
            .expect("keyPathSpending array");

        let mut checked = 0_usize;
        for case in spending {
            let tx_bytes = hex_decode(case["given"]["rawUnsignedTx"].as_str().expect("raw tx"));
            let tx = deserialize::<NativeTx>(&tx_bytes)
                .unwrap_or_else(|error| panic!("bip341: native decode failed: {error}"));
            let prevouts: Vec<TxOut> = case["given"]["utxosSpent"]
                .as_array()
                .expect("utxosSpent array")
                .iter()
                .map(|utxo| TxOut {
                    value: Amount::from_sat(utxo["amountSats"].as_u64().expect("amount sats")),
                    script_pubkey: Script::from_bytes(hex_decode(
                        utxo["scriptPubKey"].as_str().expect("script pubkey"),
                    )),
                })
                .collect();

            let cache = SighashCache::new(&tx);
            for input in case["inputSpending"]
                .as_array()
                .expect("inputSpending array")
            {
                let index =
                    usize::try_from(input["given"]["txinIndex"].as_u64().expect("txin index"))
                        .expect("txin index fits usize");
                let hash_type = input["given"]["hashType"].as_u64().expect("hash type");
                let expected = input["intermediary"]["sigHash"]
                    .as_str()
                    .expect("sigHash hex");
                let ty = taproot_hash_type(u8::try_from(hash_type).expect("hash type fits u8"));

                let digest = cache
                    .taproot_signature_hash(index, &prevouts, None, None, ty)
                    .unwrap_or_else(|error| {
                        panic!("bip341 keypath input {index} type {hash_type:#x}: {error}")
                    });
                assert_eq!(
                    digest_hex(&digest),
                    expected,
                    "bip341 keypath input {index} hash type {hash_type:#x}"
                );
                checked += 1;
            }
        }
        assert!(checked > 0, "bip341 keypath vectors must not be vacuous");
        Ok(())
    }
}
mod primitives_differential {
    #![expect(
        clippy::expect_used,
        reason = "test fixtures: a malformed vector or missing fixture file is an authoring bug, not a runtime path"
    )]
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::str::FromStr as _;

    use bitcoin_rs_consensus::primitives::{
        Amount, Block as NativeBlock, ConsensusDecode, ConsensusEncode, DecodeError, LockTime,
        Script, Sequence, SighashCache, Tx as NativeTx, Witness, Wtxid, consensus_bytes,
        deserialize,
    };

    use crate::support::primitives::TestError;

    type Result<T, E = TestError> = std::result::Result<T, E>;
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root is reachable from the primitives crate")
    }

    fn fixture_blocks() -> Vec<(String, Vec<u8>)> {
        let mut blocks = Vec::new();
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/consensus/blocks");
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "bin") {
                let name = path
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
                blocks.push((name, bytes));
            }
        }
        blocks.sort_by(|left, right| left.0.cmp(&right.0));
        assert!(
            !blocks.is_empty(),
            "testdata contains no .bin block fixtures"
        );
        blocks
    }

    fn corpus_root() -> Option<PathBuf> {
        if let Some(var) = std::env::var_os("BITCOIN_RS_FUZZ_CORPUS") {
            let path = PathBuf::from(var);
            assert!(
                path.is_dir(),
                "BITCOIN_RS_FUZZ_CORPUS={} must name an existing directory",
                path.display()
            );
            return Some(path);
        }
        let local = repo_root().join("fuzz/corpus");
        if local.is_dir() {
            return Some(local);
        }
        None
    }

    fn corpus_seeds(target: &str) -> Option<Vec<(String, Vec<u8>)>> {
        let root = corpus_root()?;
        let dir = root.join(target);
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => panic!("{}: {error}", dir.display()),
        };
        let mut seeds = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(bytes) = std::fs::read(&path) {
                    seeds.push((entry.file_name().to_string_lossy().into_owned(), bytes));
                }
            }
        }
        seeds.sort_by(|left, right| left.0.cmp(&right.0));
        Some(seeds)
    }

    fn deterministic_seeds(target: &str) -> Vec<(&'static str, Vec<u8>, &'static str)> {
        match target {
            "tx_validate" => {
                let legacy_tx = NativeTx {
                    version: 1,
                    inputs: vec![bitcoin_rs_consensus::primitives::TxIn {
                        previous_output: bitcoin_rs_consensus::primitives::OutPoint::default(),
                        script_sig: Script::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    }],
                    outputs: vec![bitcoin_rs_consensus::primitives::TxOut {
                        value: Amount::from_sat(50_000),
                        script_pubkey: Script::new(),
                    }],
                    lock_time: LockTime::ZERO,
                };
                let segwit_tx = NativeTx {
                    version: 2,
                    inputs: vec![bitcoin_rs_consensus::primitives::TxIn {
                        previous_output: bitcoin_rs_consensus::primitives::OutPoint::default(),
                        script_sig: Script::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::from_stack(vec![vec![0x01]]),
                    }],
                    outputs: vec![bitcoin_rs_consensus::primitives::TxOut {
                        value: Amount::from_sat(50_000),
                        script_pubkey: Script::new(),
                    }],
                    lock_time: LockTime::ZERO,
                };
                let mut bad_flag = 2_i32.to_le_bytes().to_vec();
                bad_flag.extend_from_slice(&[0x00, 0x02]);

                let mut non_canonical = 1_i32.to_le_bytes().to_vec();
                non_canonical.extend_from_slice(&[0xfd, 0x01, 0x00]);

                let mut superfluous = 2_i32.to_le_bytes().to_vec();
                superfluous.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

                let mut trailing = consensus_bytes(&legacy_tx);
                trailing.push(0xff);

                vec![
                    ("valid_legacy", consensus_bytes(&legacy_tx), "accepted"),
                    ("valid_segwit", consensus_bytes(&segwit_tx), "accepted"),
                    ("empty", Vec::new(), "rejected:end_of_data"),
                    ("non_canonical_varint", non_canonical, "rejected:varint"),
                    (
                        "invalid_segwit_flag",
                        bad_flag,
                        "rejected:invalid_segwit_flag",
                    ),
                    (
                        "superfluous_witness",
                        superfluous,
                        "rejected:superfluous_witness",
                    ),
                    ("trailing_bytes", trailing, "rejected:trailing_bytes"),
                ]
            }
            "block_validate" => {
                let blocks = fixture_blocks();
                let block0 = blocks.iter().find(|(name, _)| name == "0").map_or_else(
                    || panic!("fixture block 0.bin must exist"),
                    |(_, b)| b.clone(),
                );

                let mut bad_varint = if block0.len() >= 80 {
                    block0[..80].to_vec()
                } else {
                    vec![0u8; 80]
                };
                bad_varint.extend_from_slice(&[0xfd, 0x01, 0x00]);

                let mut trailing = block0.clone();
                trailing.push(0xee);

                vec![
                    ("genesis_block", block0, "accepted"),
                    ("empty", Vec::new(), "rejected:end_of_data"),
                    ("non_canonical_tx_count", bad_varint, "rejected:varint"),
                    ("trailing_bytes", trailing, "rejected:trailing_bytes"),
                ]
            }
            _ => Vec::new(),
        }
    }

    fn enforce_deterministic_seeds(target: &str) {
        let seeds = deterministic_seeds(target);
        assert!(
            !seeds.is_empty(),
            "deterministic seed set for {target} must not be empty"
        );
        for (name, bytes, expected_verdict) in seeds {
            let observed = match target {
                "tx_validate" => decode_verdict::<NativeTx>(&bytes),
                "block_validate" => decode_verdict::<NativeBlock>(&bytes),
                other => panic!("unknown corpus target {other}"),
            };
            assert_eq!(
                observed, expected_verdict,
                "{target} deterministic seed {name} failed verdict check"
            );
        }
    }

    fn assert_tx_roundtrip(serialized: &[u8], expected_wtxid: &str, context: &str) {
        let native = deserialize::<NativeTx>(serialized)
            .unwrap_or_else(|error| panic!("{context}: native decode failed: {error}"));
        assert_eq!(consensus_bytes(&native), serialized, "{context}: re-encode");
        assert_eq!(
            native.txid().0.as_byte_array().len(),
            32,
            "{context}: txid width"
        );
        let expected = Wtxid::from_str(expected_wtxid)
            .unwrap_or_else(|error| panic!("{context}: golden wtxid hex: {error}"));
        assert_eq!(native.wtxid(), expected, "{context}: golden wtxid");
    }

    #[test]
    fn fixture_blocks_roundtrip_byte_identically() {
        for (name, bytes) in fixture_blocks() {
            let native = deserialize::<NativeBlock>(&bytes)
                .unwrap_or_else(|error| panic!("fixture {name}: native decode failed: {error}"));

            assert_eq!(consensus_bytes(&native), bytes, "fixture {name}: re-encode");
            let wtxid_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../testdata/consensus/blocks")
                .join(format!("{name}.wtxids.txt"));
            let expected_wtxids: Vec<String> = std::fs::read_to_string(&wtxid_path)
                .unwrap_or_else(|error| {
                    panic!("fixture {name}: reading {}: {error}", wtxid_path.display())
                })
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(str::to_owned)
                .collect();
            assert_eq!(
                expected_wtxids.len(),
                native.txs.len(),
                "fixture {name}: golden wtxid count"
            );
            for (index, tx) in native.txs.iter().enumerate() {
                assert_tx_roundtrip(
                    &consensus_bytes(tx),
                    &expected_wtxids[index],
                    &format!("fixture {name} tx {index}"),
                );
            }
        }
    }

    fn enforce_corpus_verdicts(target: &str) {
        let Some(seeds) = corpus_seeds(target) else {
            eprintln!(
                "SKIP {target}: no corpus directory \
             (set BITCOIN_RS_FUZZ_CORPUS to a bitcoin-rs-fuzz-corpus checkout)"
            );
            return;
        };
        assert!(
            !seeds.is_empty(),
            "corpus for {target} exists but contains no seeds; gate would be vacuous"
        );

        let mut observed: BTreeMap<String, String> = BTreeMap::new();
        for (name, bytes) in &seeds {
            let name = name.as_str();
            let verdict = match target {
                "tx_validate" => decode_verdict::<NativeTx>(bytes),
                "block_validate" => decode_verdict::<NativeBlock>(bytes),
                other => panic!("unknown corpus target {other}"),
            };
            assert!(
                verdict == "accepted" || verdict.starts_with("rejected:"),
                "{target}: seed {name} has unknown verdict {verdict}"
            );
            observed.insert(name.to_owned(), verdict);
        }

        let manifest_path = corpus_root()
            .expect("corpus root is present when seeds are present")
            .join("verdicts.json");
        if std::env::var_os("CORPUS_VERDICTS_WRITE").is_some() {
            let mut root = std::fs::read_to_string(&manifest_path)
                .ok()
                .and_then(|text| sonic_rs::from_str::<Value>(&text).ok())
                .and_then(|value| value.as_object().cloned())
                .unwrap_or_default();
            root.insert(
                "_contract",
                Value::from(
                    "QAC-05 (docs/contracts/qa-corpus.md): expected decoder verdict per seed; \
                 regenerate with BITCOIN_RS_FUZZ_CORPUS=<corpus> \
                 CORPUS_VERDICTS_WRITE=1 cargo test -p bitcoin-rs-consensus",
                ),
            );
            let mut section = sonic_rs::Object::with_capacity(observed.len());
            for (name, verdict) in observed {
                section.insert(name.as_str(), Value::from(verdict.as_str()));
            }
            root.insert(target, Value::from(section));
            let rendered =
                sonic_rs::to_string_pretty(&Value::from(root)).expect("verdicts.json renders");
            std::fs::write(&manifest_path, rendered + "\n")
                .unwrap_or_else(|error| panic!("writing {}: {error}", manifest_path.display()));
            eprintln!(
                "wrote {}; re-run without CORPUS_VERDICTS_WRITE to enforce",
                manifest_path.display()
            );
            return;
        }

        let Ok(manifest_text) = std::fs::read_to_string(&manifest_path) else {
            eprintln!(
                "WARN {target}: {} absent; checking verdict shape only \
             (regenerate with CORPUS_VERDICTS_WRITE=1 to pin per-seed verdicts)",
                manifest_path.display()
            );
            return;
        };
        let manifest = sonic_rs::from_str::<Value>(&manifest_text)
            .unwrap_or_else(|error| panic!("{}: {error}", manifest_path.display()));
        let expected = manifest
            .get(target)
            .unwrap_or_else(|| panic!("{} has no \"{target}\" section", manifest_path.display()));
        let expected = expected
            .as_object()
            .expect("verdicts.json section is an object");

        for (name, observed_verdict) in &observed {
            match expected.get(name) {
                None => panic!(
                    "{target}: seed {name} is not listed in {}; \
                 pin its verdict with CORPUS_VERDICTS_WRITE=1",
                    manifest_path.display()
                ),
                Some(expected_verdict) => {
                    let expected_verdict = expected_verdict.as_str().expect("verdict is a string");
                    assert_eq!(
                        observed_verdict, expected_verdict,
                        "{target}: seed {name} verdict drifted; if intentional, \
                     re-pin with CORPUS_VERDICTS_WRITE=1"
                    );
                }
            }
        }
        for (name, _) in expected {
            assert!(
                observed.contains_key(name),
                "{target}: verdicts.json lists {name} but the corpus no longer has it; \
             drop the entry with CORPUS_VERDICTS_WRITE=1"
            );
        }
    }

    fn decode_verdict<T: ConsensusDecode + ConsensusEncode>(bytes: &[u8]) -> String {
        match deserialize::<T>(bytes) {
            Ok(value) => {
                assert_eq!(
                    consensus_bytes(&value),
                    bytes,
                    "accepted seed must re-encode byte-identically"
                );
                "accepted".to_owned()
            }
            Err(error) => format!("rejected:{}", error_kind(&error)),
        }
    }

    fn error_kind(error: &DecodeError) -> String {
        match error {
            DecodeError::EndOfData { .. } => "end_of_data".to_owned(),
            DecodeError::Varint(_) => "varint".to_owned(),
            DecodeError::InvalidSegwitFlag { .. } => "invalid_segwit_flag".to_owned(),
            DecodeError::SuperfluousWitness => "superfluous_witness".to_owned(),
            DecodeError::TrailingBytes { .. } => "trailing_bytes".to_owned(),
        }
    }

    // QAC-05
    #[test]
    fn corpus_seeds_decode_with_typed_verdicts() {
        enforce_deterministic_seeds("tx_validate");
        enforce_deterministic_seeds("block_validate");
        for target in ["tx_validate", "block_validate"] {
            enforce_corpus_verdicts(target);
        }
    }

    // QAC-05
    #[test]
    fn malformed_input_returns_typed_errors_without_panicking() {
        let mut bad_flag = 2_i32.to_le_bytes().to_vec();
        bad_flag.extend_from_slice(&[0x00, 0x02]);
        assert_eq!(
            deserialize::<NativeTx>(&bad_flag),
            Err(DecodeError::InvalidSegwitFlag { got: 0x02 })
        );

        let mut non_canonical = 1_i32.to_le_bytes().to_vec();
        non_canonical.extend_from_slice(&[0xfd, 0x01, 0x00]);
        assert!(matches!(
            deserialize::<NativeTx>(&non_canonical),
            Err(DecodeError::Varint(
                bitcoin_rs_consensus::primitives::varint::VarintError::NonCanonical { .. }
            ))
        ));

        let tx = NativeTx {
            version: 1,
            inputs: vec![bitcoin_rs_consensus::primitives::TxIn {
                previous_output: bitcoin_rs_consensus::primitives::OutPoint::default(),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: Vec::new(),
            lock_time: LockTime::ZERO,
        };
        let mut trailing = consensus_bytes(&tx);
        trailing.push(0xff);
        assert_eq!(
            deserialize::<NativeTx>(&trailing),
            Err(DecodeError::TrailingBytes { remaining: 1 })
        );

        assert!(matches!(
            deserialize::<NativeTx>(&[]),
            Err(DecodeError::EndOfData { .. })
        ));

        let small: Vec<_> = fixture_blocks()
            .into_iter()
            .filter(|(name, _)| matches!(name.as_str(), "0" | "170"))
            .collect();
        for (name, bytes) in small {
            for len in 0..bytes.len() {
                let result = deserialize::<NativeBlock>(&bytes[..len]);
                assert!(result.is_err(), "fixture {name}: prefix len {len} decoded");
            }
            for (offset, byte) in bytes.iter().enumerate() {
                let mut corrupted = bytes.clone();
                corrupted[offset] = byte.wrapping_add(1);
                let _ = deserialize::<NativeBlock>(&corrupted);
            }
        }
    }

    #[test]
    fn legacy_sighash_matches_core_vectors() -> Result<()> {
        let path = repo_root().join("testdata/consensus/vectors/sighash.json");
        let data = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
        let vectors = sonic_rs::from_str::<Value>(&data)?
            .as_array()
            .expect("sighash.json is an array")
            .clone();

        let mut matched = 0_usize;
        let mut skipped_codeseparator = 0_usize;
        for vector in vectors.iter().skip(1) {
            let tx_hex = vector.get(0).and_then(|v| v.as_str()).expect("tx hex");
            let script_hex = vector.get(1).and_then(|v| v.as_str()).unwrap_or("");
            let input_index = vector
                .get(2)
                .and_then(JsonValueTrait::as_u64)
                .expect("input index");
            let hash_type = vector
                .get(3)
                .and_then(JsonValueTrait::as_i64)
                .expect("hash type");
            let expected = vector
                .get(4)
                .and_then(|v| v.as_str())
                .expect("expected sighash");

            let tx_bytes = hex_decode(tx_hex);
            let native_tx = deserialize::<NativeTx>(&tx_bytes)
                .unwrap_or_else(|error| panic!("vector {expected}: native decode failed: {error}"));
            let script = hex_decode(script_hex);
            let flag = u32::from_le_bytes(
                hash_type.to_le_bytes()[..4]
                    .try_into()
                    .expect("slice of length 4"),
            );
            let input_index = usize::try_from(input_index)
                .unwrap_or_else(|error| panic!("vector {expected}: input index overflow: {error}"));

            let native_hash = SighashCache::new(&native_tx)
                .legacy_signature_hash(input_index, &script, flag)
                .unwrap_or_else(|error| {
                    panic!("vector {expected}: native sighash failed: {error}")
                });

            if script.contains(&0xab) {
                skipped_codeseparator = skipped_codeseparator.saturating_add(1);
                continue;
            }
            assert_eq!(
                native_hash.to_string_be(),
                expected,
                "vector {expected}: native sighash"
            );
            matched = matched.saturating_add(1);
        }
        assert_eq!(
            matched, 290,
            "Core sighash.json non-OP_CODESEPARATOR rows must keep matching; skipped {skipped_codeseparator}"
        );
        assert_eq!(
            skipped_codeseparator, 210,
            "OP_CODESEPARATOR skip count drifted; matched {matched}"
        );
        Ok(())
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&hex[index..index + 2], 16)
                    .unwrap_or_else(|error| panic!("bad hex at {index}: {error}"))
            })
            .collect()
    }
}
mod primitives_genesis {
    use bitcoin_rs_consensus::primitives::{Network, consensus_bytes};

    #[test]
    fn native_genesis_matches_published_hash_and_compiled_bytes() {
        let times = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
        let cases = [
            (
                Network::Mainnet,
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                true,
            ),
            (
                Network::Testnet3,
                "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
                true,
            ),
            (
                Network::Testnet4,
                "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
                false,
            ),
            (
                Network::Signet,
                "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
                true,
            ),
            (
                Network::Regtest,
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
                true,
            ),
        ];
        for (network, published, has_times) in cases {
            let native = network.genesis_block();
            assert_eq!(
                format!("{}", native.block_hash()),
                published,
                "{network:?} genesis hash diverges from the published identifier"
            );
            assert_eq!(
                format!("{}", network.genesis_block_hash()),
                published,
                "{network:?} compiled genesis hash diverges"
            );
            let bytes = consensus_bytes(&native);
            assert_eq!(
                bitcoin_rs_consensus::primitives::deserialize::<
                    bitcoin_rs_consensus::primitives::Block,
                >(&bytes)
                .unwrap_or_else(|error| panic!("{network:?} genesis must re-decode: {error}")),
                native,
                "{network:?} genesis must round-trip"
            );
            assert_eq!(native.txs.len(), 1, "{network:?} genesis is a single tx");
            assert!(
                native.txs[0].inputs[0].previous_output.is_null(),
                "{network:?} genesis coinbase prevout is null"
            );
            assert_eq!(
                native.txs[0].outputs[0].value,
                bitcoin_rs_consensus::primitives::Amount::from_sat(5_000_000_000),
                "{network:?} genesis subsidy is 50 BTC"
            );
            if has_times {
                assert!(
                    native.txs[0].inputs[0]
                        .script_sig
                        .windows(times.len())
                        .any(|window| window == times),
                    "{network:?} genesis coinbase must carry the Times message"
                );
            }
        }
    }
}
mod primitives_golden {
    use std::str::FromStr;

    use crate::support::primitives::TestError;
    use bitcoin_rs_consensus::primitives::{
        Block as PrimitiveBlock, BlockHash, BlockImage, Txid, Wtxid, deserialize,
    };
    const HEIGHTS: &[(u32, &str)] = &[
        (
            0,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        ),
        (
            1,
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
        ),
        (
            170,
            "00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee",
        ),
        (
            91722,
            "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e",
        ),
        (
            91812,
            "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f",
        ),
        (
            91842,
            "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec",
        ),
        (
            91880,
            "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721",
        ),
        (
            173_818,
            "00000000000008a5097526239afca1d59e6e112aca135ab7dd5189b5fe9f0696",
        ),
        (
            363_731,
            "00000000000000000c28e23330c29046f19e817fe8fe039f4044b2b2882aef53",
        ),
        (
            481_823,
            "000000000000000000cbeff0b533f8e1189cf09dfbebf57a8ebe349362811b80",
        ),
        (
            481_824,
            "0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893",
        ),
        (
            624_455,
            "0000000000000000000159c36c1e487714ef94d4e93419a2455eaa8cd0e05ddb",
        ),
        (
            709_632,
            "0000000000000000000687bca986194dc2c1f949318629b44bb54ec0a94d8244",
        ),
        (
            800_000,
            "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054",
        ),
        (
            880_000,
            "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880",
        ),
    ];

    #[test]
    fn golden_blocks_decode_and_hash_to_blockstream_txids() -> Result<(), TestError> {
        for (height, expected_hash) in HEIGHTS {
            let block_bytes = read_fixture(*height, "bin")?;
            let txid_text = String::from_utf8(read_fixture(*height, "txids.txt")?)?;
            let expected_txids = parse_txids(&txid_text)?;
            let wtxid_text = String::from_utf8(read_fixture(*height, "wtxids.txt")?)?;
            let expected_wtxids = parse_wtxids(&wtxid_text)?;
            let block = deserialize::<PrimitiveBlock>(&block_bytes)?;
            let expected_block_hash = expected_hash.parse::<BlockHash>()?;

            assert_eq!(
                block.block_hash(),
                expected_block_hash,
                "height {height} block hash"
            );
            assert_eq!(
                block.txs.len(),
                expected_txids.len(),
                "height {height} tx count"
            );

            assert_eq!(
                expected_wtxids.len(),
                expected_txids.len(),
                "height {height} wtxid golden count"
            );
            for (index, (tx, expected_txid)) in
                block.txs.iter().zip(expected_txids.iter()).enumerate()
            {
                assert_eq!(
                    tx.txid(),
                    *expected_txid,
                    "height {height} tx index {index}"
                );
                let expected_wtxid = expected_wtxids[index];
                if !tx.has_witness() {
                    assert_eq!(
                        tx.wtxid().0,
                        tx.txid().0,
                        "height {height} tx index {index}: pre-segwit wtxid must equal txid"
                    );
                }
                assert_eq!(
                    tx.wtxid(),
                    expected_wtxid,
                    "height {height} tx index {index}: golden wtxid"
                );
            }
            assert_eq!(
                bitcoin_rs_consensus::primitives::consensus_bytes(&block),
                block_bytes,
                "height {height} re-encode"
            );
        }
        Ok(())
    }
    // BLK-02, BLK-03, BLK-05, BLK-06
    #[test]
    fn golden_blocks_image_identities_and_views_match_core_vectors() -> Result<(), TestError> {
        for (height, expected_hash) in HEIGHTS {
            let block_bytes = read_fixture(*height, "bin")?;
            let txid_text = String::from_utf8(read_fixture(*height, "txids.txt")?)?;
            let expected_txids = parse_txids(&txid_text)?;
            let wtxid_text = String::from_utf8(read_fixture(*height, "wtxids.txt")?)?;
            let expected_wtxids = parse_wtxids(&wtxid_text)?;
            let expected_block_hash = expected_hash.parse::<BlockHash>()?;

            let raw = bytes::Bytes::from(block_bytes.clone());
            let image = BlockImage::from_raw(raw)?;

            assert_eq!(
                image.block_hash(),
                expected_block_hash,
                "height {height} block hash"
            );
            assert_eq!(
                image.tx_count(),
                expected_txids.len(),
                "height {height} tx count"
            );
            assert_eq!(
                image.identities().len(),
                expected_txids.len(),
                "height {height} identities count"
            );

            let decoded = deserialize::<PrimitiveBlock>(&block_bytes)?;
            for index in 0..image.tx_count() {
                let identity = image.identity(index);
                let tx_view = image.tx(index);
                let expected_txid = expected_txids[index];
                let expected_wtxid = expected_wtxids[index];
                let decoded_tx = &decoded.txs[index];

                assert_eq!(
                    identity.txid(),
                    expected_txid,
                    "height {height} tx index {index}: identity txid"
                );
                assert_eq!(
                    tx_view.txid(),
                    expected_txid,
                    "height {height} tx index {index}: tx_view txid"
                );

                if !tx_view.has_witness() {
                    assert_eq!(
                        identity.wtxid(),
                        None,
                        "height {height} tx index {index}: legacy identity wtxid must be None"
                    );
                    assert_eq!(
                        tx_view.wtxid().0,
                        tx_view.txid().0,
                        "height {height} tx index {index}: legacy tx_view wtxid must equal txid"
                    );
                } else {
                    assert_eq!(
                        identity.wtxid(),
                        Some(expected_wtxid),
                        "height {height} tx index {index}: segwit identity wtxid"
                    );
                }
                assert_eq!(
                    tx_view.wtxid(),
                    expected_wtxid,
                    "height {height} tx index {index}: tx_view wtxid"
                );

                assert_eq!(
                    usize::try_from(identity.total_size())?,
                    decoded_tx.total_size(),
                    "height {height} tx index {index}: total size"
                );
                assert_eq!(
                    usize::try_from(identity.base_size())?,
                    decoded_tx.base_size(),
                    "height {height} tx index {index}: base size"
                );
                assert_eq!(
                    tx_view.total_size(),
                    decoded_tx.total_size(),
                    "height {height} tx index {index}: view total size"
                );
                assert_eq!(
                    tx_view.base_size(),
                    decoded_tx.base_size(),
                    "height {height} tx index {index}: view base size"
                );

                assert_eq!(
                    tx_view.version(),
                    decoded_tx.version,
                    "height {height} tx index {index}: version"
                );
                assert_eq!(
                    tx_view.lock_time(),
                    decoded_tx.lock_time,
                    "height {height} tx index {index}: lock_time"
                );
                assert_eq!(
                    tx_view.is_coinbase(),
                    decoded_tx.is_coinbase(),
                    "height {height} tx index {index}: is_coinbase"
                );
                assert_eq!(
                    tx_view.input_count(),
                    decoded_tx.inputs.len(),
                    "height {height} tx index {index}: input_count"
                );
                assert_eq!(
                    tx_view.output_count(),
                    decoded_tx.outputs.len(),
                    "height {height} tx index {index}: output_count"
                );

                for (in_idx, expected_in) in decoded_tx.inputs.iter().enumerate() {
                    assert_eq!(
                        tx_view.input_outpoint(in_idx),
                        expected_in.previous_output,
                        "height {height} tx {index} input {in_idx}: outpoint"
                    );
                    assert_eq!(
                        tx_view.input_script_sig(in_idx),
                        expected_in.script_sig.as_bytes(),
                        "height {height} tx {index} input {in_idx}: script_sig"
                    );
                    assert_eq!(
                        tx_view.input_sequence(in_idx),
                        expected_in.sequence,
                        "height {height} tx {index} input {in_idx}: sequence"
                    );
                    assert_eq!(
                        tx_view.witness_item_count(in_idx),
                        expected_in.witness.len(),
                        "height {height} tx {index} input {in_idx}: witness count"
                    );
                    for (item_idx, expected_item) in expected_in.witness.iter().enumerate() {
                        assert_eq!(
                            tx_view.witness_item(in_idx, item_idx),
                            expected_item,
                            "height {height} tx {index} input {in_idx} item {item_idx}"
                        );
                    }
                }

                for (out_idx, expected_out) in decoded_tx.outputs.iter().enumerate() {
                    assert_eq!(
                        tx_view.output_value(out_idx),
                        expected_out.value,
                        "height {height} tx {index} output {out_idx}: value"
                    );
                    assert_eq!(
                        tx_view.output_script(out_idx),
                        expected_out.script_pubkey.as_bytes(),
                        "height {height} tx {index} output {out_idx}: script"
                    );
                }

                let materialized_tx = tx_view.materialize();
                assert_eq!(
                    &materialized_tx, decoded_tx,
                    "height {height} tx {index}: materialized tx"
                );
            }

            let materialized_block = image.materialize();
            assert_eq!(
                materialized_block, decoded,
                "height {height} materialized block"
            );
        }
        Ok(())
    }

    fn read_fixture(height: u32, extension: &'static str) -> Result<Vec<u8>, TestError> {
        let path = format!("../../testdata/consensus/blocks/{height}.{extension}");
        match std::fs::read(&path) {
            Ok(bytes) => Ok(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(TestError::MissingFixture { height, extension })
            }
            Err(error) => Err(error.into()),
        }
    }

    fn parse_wtxids(wtxid_text: &str) -> Result<Vec<Wtxid>, TestError> {
        wtxid_text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| Wtxid::from_str(line).map_err(Into::into))
            .collect()
    }

    fn parse_txids(
        txid_text: &str,
    ) -> Result<Vec<Txid>, bitcoin_rs_consensus::primitives::HashError> {
        txid_text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(Txid::from_str)
            .collect()
    }
}
mod primitives_overhaul_layout {
    #![expect(clippy::expect_used, reason = "test assertions")]

    use bitcoin_rs_consensus::primitives::layout::{ByteSpan, ParsedBlock, ParsedTransaction};
    use bitcoin_rs_consensus::primitives::{
        Block, DecodeError, Network, Tx, consensus_bytes, deserialize,
    };

    const HEIGHTS: &[u32] = &[170, 481_824];

    fn read_fixture(height: u32) -> Vec<u8> {
        let path = format!("../../testdata/consensus/blocks/{height}.bin");
        match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                panic!("missing {path}; run scripts/fetch-golden.sh to populate testdata")
            }
            Err(error) => panic!("read {path}: {error}"),
        }
    }

    #[test]
    fn golden_blocks_validate_all_spans_and_consumed_counts() {
        for height in HEIGHTS {
            let bytes = read_fixture(*height);
            let parsed =
                ParsedBlock::parse_exact(&bytes).unwrap_or_else(|e| panic!("{height}: {e}"));

            assert_eq!(
                parsed.consumed_len(),
                bytes.len(),
                "height {height} exact consumption"
            );
            assert_eq!(
                parsed.transaction_spans().len(),
                parsed.tx_count(),
                "height {height} one span per transaction"
            );

            let mut per_tx_total = 0_usize;
            for (index, span) in parsed.transaction_spans().iter().enumerate() {
                let transaction = parsed
                    .transactions()
                    .get(index)
                    .unwrap_or_else(|| panic!("height {height} tx {index} missing"));
                let slice = parsed
                    .span_bytes(*span)
                    .unwrap_or_else(|| panic!("height {height} tx {index} span out of bounds"));
                assert_eq!(
                    slice.len(),
                    transaction.consumed_len(),
                    "height {height} tx {index} span equals consumed region"
                );
                per_tx_total += transaction.consumed_len();
            }
            let prefix = if u64::try_from(parsed.tx_count()).is_ok_and(|count| count <= 0xfc) {
                1
            } else {
                3
            };
            assert_eq!(
                per_tx_total + 80 + prefix,
                bytes.len(),
                "height {height} consumed regions account for the whole block"
            );

            let materialized = parsed.materialize();
            assert_eq!(
                consensus_bytes(&materialized),
                bytes,
                "height {height} materialize re-encode"
            );
        }
    }

    #[test]
    fn truncation_sweep_produces_defined_errors_only() {
        let bytes = read_fixture(170);
        for cut in 0..bytes.len() {
            match ParsedBlock::parse_exact(&bytes[..cut]) {
                Ok(_) => panic!("prefix of length {cut} must not parse as a complete block"),
                Err(
                    DecodeError::EndOfData { .. }
                    | DecodeError::Varint(_)
                    | DecodeError::InvalidSegwitFlag { .. }
                    | DecodeError::SuperfluousWitness
                    | DecodeError::TrailingBytes { .. },
                ) => {}
            }
        }
    }

    #[test]
    fn trailing_byte_is_rejected() {
        let mut bytes = read_fixture(170);
        bytes.push(0xAB);
        assert!(matches!(
            ParsedBlock::parse_exact(&bytes),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn impossible_counts_are_rejected_before_allocation() {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&1_i32.to_le_bytes());
        tx_bytes.extend_from_slice(&[0x00, 0x01]);
        tx_bytes.extend_from_slice(&[0xFF; 9]);
        assert!(matches!(
            ParsedTransaction::parse_exact(&tx_bytes),
            Err(DecodeError::EndOfData { .. })
        ));
    }

    #[test]
    fn noncanonical_varints_are_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1_i32.to_le_bytes());
        bytes.extend_from_slice(&[0xFD, 0x05, 0x00]);
        bytes.extend_from_slice(&[0u8; 8]);
        let err = ParsedTransaction::parse_exact(&bytes).expect_err("must fail");
        assert!(
            matches!(err, DecodeError::Varint(_)),
            "expected Varint, got {err:?}"
        );
    }
    #[test]
    fn segwit_flag_rules_hold() {
        let golden = read_fixture(481_824);
        let parsed = ParsedBlock::parse_exact(&golden).expect("segwit golden block parses");
        assert!(
            parsed.transactions().iter().any(|tx| tx
                .inputs()
                .iter()
                .any(|input| input.witness_item_count() > 0)),
            "height 481824 carries witness data"
        );

        let mut corrupted = golden.clone();
        let mut replaced = false;
        let mut cursor = 81;
        while cursor + 1 < corrupted.len() {
            if corrupted[cursor] == 0x00 && corrupted[cursor + 1] == 0x01 {
                corrupted[cursor + 1] = 0x02;
                replaced = true;
                break;
            }
            cursor += 1;
        }
        assert!(replaced, "fixture contains a marker/flag pair");
        assert!(matches!(
            ParsedBlock::parse_exact(&corrupted),
            Err(DecodeError::InvalidSegwitFlag { got: 0x02 }
                | DecodeError::EndOfData { .. }
                | DecodeError::Varint(_))
        ));
    }

    #[test]
    fn witness_item_spans_resolve_and_match_the_materialized_witness() {
        let bytes = read_fixture(481_824);
        let parsed = ParsedBlock::parse_exact(&bytes).expect("segwit golden parses");
        let materialized = parsed.materialize();
        let mut checked_items = 0;
        for (transaction, tx) in parsed.transactions().iter().zip(&materialized.txs) {
            for (input_index, input) in tx.inputs.iter().enumerate() {
                let spans: Vec<ByteSpan> = transaction.witness_item_spans(input_index).collect();
                assert_eq!(
                    spans.len(),
                    input.witness.len(),
                    "layout item count equals the materialized witness length"
                );
                for (span, item) in spans.iter().zip(&input.witness) {
                    assert_eq!(
                        parsed.span_bytes(*span),
                        Some(item),
                        "witness item span resolves to the materialized item bytes"
                    );
                    checked_items += 1;
                }
            }
        }
        assert!(checked_items > 0, "height 481824 carries witness data");
    }

    #[test]
    fn genesis_txid_through_layout_matches_direct_decode() {
        let genesis = Network::Mainnet.genesis_block();
        let bytes = consensus_bytes(&genesis);
        let parsed = ParsedBlock::parse_exact(&bytes).expect("genesis parses");
        let materialized: Block = parsed.materialize();
        let direct: Block = deserialize(&bytes).expect("direct decode");

        assert_eq!(materialized.txs.len(), 1);
        let through_layout: &Tx = materialized
            .txs
            .first()
            .expect("genesis coinbase through layout");
        assert_eq!(
            through_layout.txid(),
            direct.txs.first().expect("direct coinbase").txid()
        );

        let span = parsed
            .transaction_spans()
            .first()
            .copied()
            .expect("genesis span");
        let slice = parsed.span_bytes(span).expect("genesis span in bounds");
        assert_eq!(slice, consensus_bytes(through_layout).as_slice());
    }

    #[test]
    fn parsed_transaction_txid_and_base_size_match_materialized_form() {
        let mut compared = 0_usize;
        let mut segwit = 0_usize;
        for height in HEIGHTS {
            let bytes = read_fixture(*height);
            let parsed = ParsedBlock::parse_exact(&bytes).expect("golden block parses");
            for (index, tx) in parsed.transactions().iter().enumerate() {
                let materialized = tx.materialize();
                assert_eq!(
                    tx.txid().as_bytes(),
                    materialized.txid().as_bytes(),
                    "height {height} tx {index} txid"
                );
                assert_eq!(
                    tx.base_size(),
                    materialized.base_size(),
                    "height {height} tx {index} base size"
                );
                compared += 1;
                segwit += usize::from(tx.is_segwit());
            }
        }
        assert!(
            segwit > 0 && segwit < compared,
            "the fixtures must exercise both encodings, got {segwit} SegWit of {compared}"
        );
    }

    #[test]
    fn stripped_parts_never_panics_on_truncated_or_boundary_segwit_tx() {
        let raw = [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        if let Ok(parsed) = ParsedTransaction::parse_exact(&raw) {
            let _ = parsed.stripped_parts();
            let _ = parsed.txid();
            let _ = parsed.base_size();
        }
    }
}
mod script_adversarial_limits {
    use bitcoin::hashes::Hash as _;
    use bitcoin::key::TweakedPublicKey;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use bitcoin::taproot::{LeafVersion, TaprootBuilder};
    use bitcoin::{ScriptBuf, absolute, transaction};
    use bitcoin_rs_consensus::primitives::{
        Amount, OutPoint, Script, Tx, TxIn, TxOut, Txid, Witness,
    };
    use bitcoin_rs_consensus::script::{
        PreparedTransaction, ScriptErrCode, ScriptError, VerifyFlags, opcode, push_data,
    };

    const OP_1: u8 = opcode::OP_PUSHNUM_1;
    const OP_NOP: u8 = 0x61;
    const OP_ELSE: u8 = 0x67;
    const OP_PUSHDATA1: u8 = 0x4c;

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Secp256k1(#[from] bitcoin::secp256k1::Error),
        #[error(transparent)]
        TaprootBuilder(#[from] bitcoin::taproot::TaprootBuilderError),
        #[error(transparent)]
        Decode(#[from] bitcoin_rs_consensus::primitives::DecodeError),
        #[error(transparent)]
        Prevout(#[from] bitcoin_rs_consensus::script::PrevoutError),
        #[error("{0}")]
        Message(&'static str),
    }

    impl From<&'static str> for TestError {
        fn from(s: &'static str) -> Self {
            Self::Message(s)
        }
    }

    type TestResult = Result<(), TestError>;

    fn make_legacy_tx(script_sig: Vec<u8>, script_pubkey: Vec<u8>) -> (Tx, TxOut) {
        let prevout_point = OutPoint::new(Txid::default(), 0);
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: prevout_point,
                script_sig: Script::from_bytes(script_sig),
                sequence: bitcoin_rs_consensus::primitives::Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: Script::new(),
            }],
            lock_time: bitcoin_rs_consensus::primitives::LockTime::ZERO,
        };
        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(script_pubkey),
        };
        (tx, prevout)
    }

    fn check_legacy(
        script_sig: Vec<u8>,
        script_pubkey: Vec<u8>,
        flags: VerifyFlags,
    ) -> Result<bool, ScriptError> {
        let (tx, prevout) = make_legacy_tx(script_sig, script_pubkey);
        let rows = [(tx.inputs[0].previous_output, prevout)];
        let prepared = match PreparedTransaction::new(&tx, &rows) {
            Ok(p) => p,
            Err(_) => {
                return Err(ScriptError::Invalid {
                    code: ScriptErrCode::BadOpcode,
                });
            }
        };
        prepared.verify_input(0, flags, None)
    }

    fn make_tapscript_tx(
        script: Vec<u8>,
        witness_stack: Vec<Vec<u8>>,
        annex: Option<Vec<u8>>,
    ) -> Result<(Tx, TxOut), TestError> {
        let script_buf = ScriptBuf::from_bytes(script);
        let secp = Secp256k1::new();
        let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[17; 32])?);
        let info = TaprootBuilder::new()
            .add_leaf(0, script_buf.clone())?
            .finalize(&secp, key.x_only_public_key().0)
            .map_err(|_| "complete taproot tree")?;
        let control_block = info
            .control_block(&(script_buf.clone(), LeafVersion::TapScript))
            .ok_or("taproot control block")?
            .serialize();

        let mut full_witness = witness_stack;
        full_witness.push(script_buf.to_bytes());
        full_witness.push(control_block);
        if let Some(annex_bytes) = annex {
            full_witness.push(annex_bytes);
        }

        let oracle = bitcoin::Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([42; 32]),
                    0,
                ),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::from_slice(&full_witness),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(9_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let tx =
            bitcoin_rs_consensus::primitives::deserialize(&bitcoin::consensus::serialize(&oracle))?;
        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(
                ScriptBuf::new_p2tr_tweaked(info.output_key()).to_bytes(),
            ),
        };
        Ok((tx, prevout))
    }

    fn verify_taproot_witness(
        output_key: TweakedPublicKey,
        full_witness: Vec<Vec<u8>>,
    ) -> Result<Result<bool, ScriptError>, TestError> {
        let oracle = bitcoin::Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([42; 32]),
                    0,
                ),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::from_slice(&full_witness),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(9_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let tx: Tx =
            bitcoin_rs_consensus::primitives::deserialize(&bitcoin::consensus::serialize(&oracle))?;
        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(ScriptBuf::new_p2tr_tweaked(output_key).to_bytes()),
        };
        let rows = [(tx.inputs[0].previous_output, prevout)];
        let prepared = PreparedTransaction::new(&tx, &rows)?;
        Ok(prepared.verify_input(0, VerifyFlags::MANDATORY, None))
    }

    fn build_clean_sized_script(target_len: usize) -> Vec<u8> {
        let mut script = Vec::with_capacity(target_len);
        while script.len() + 524 <= target_len.saturating_sub(1) {
            script.extend(push_data(&[0x01; 520]));
            script.push(opcode::OP_DROP);
        }
        let remaining = target_len - script.len();
        if remaining > 1 {
            let push_needed = remaining - 1;
            if push_needed == 2 {
                script.push(opcode::OP_0);
                script.push(opcode::OP_DROP);
            } else if push_needed >= 3 {
                let data_len = push_needed - 2;
                script.extend(push_data(&vec![0x01; data_len]));
                script.push(opcode::OP_DROP);
            }
        }
        while script.len() < target_len - 1 {
            script.push(opcode::OP_0);
            script.push(opcode::OP_DROP);
        }
        script.push(OP_1);
        assert_eq!(script.len(), target_len);
        script
    }

    #[test]
    fn script_size_limits_enforced_at_boundary() -> TestResult {
        let exact_10000 = build_clean_sized_script(10_000);
        assert_eq!(
            check_legacy(vec![], exact_10000, VerifyFlags::MANDATORY),
            Ok(true)
        );

        let script_10001 = build_clean_sized_script(10_001);
        assert_eq!(
            check_legacy(vec![], script_10001.clone(), VerifyFlags::MANDATORY),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::ScriptSize
            })
        );

        let (tx, prevout) = make_tapscript_tx(script_10001, vec![], None)?;
        let rows = [(tx.inputs[0].previous_output, prevout)];
        let prep = PreparedTransaction::new(&tx, &rows)?;
        assert_eq!(prep.verify_input(0, VerifyFlags::MANDATORY, None), Ok(true));
        Ok(())
    }

    #[test]
    fn opcode_count_limit_201_enforced_at_boundary() -> TestResult {
        let op_201 = [vec![OP_NOP; 201], vec![OP_1]].concat();
        assert_eq!(
            check_legacy(vec![], op_201, VerifyFlags::MANDATORY),
            Ok(true)
        );

        let op_202 = [vec![OP_NOP; 202], vec![OP_1]].concat();
        assert_eq!(
            check_legacy(vec![], op_202, VerifyFlags::MANDATORY),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::OpCount
            })
        );

        let mut unexecuted_ops = vec![opcode::OP_0, opcode::OP_IF];
        unexecuted_ops.extend(vec![OP_NOP; 202]);
        unexecuted_ops.push(opcode::OP_ENDIF);
        unexecuted_ops.push(OP_1);
        assert_eq!(
            check_legacy(vec![], unexecuted_ops, VerifyFlags::MANDATORY),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::OpCount
            })
        );

        let tap_op_202 = [vec![OP_NOP; 202], vec![OP_1]].concat();
        let (tx, prevout) = make_tapscript_tx(tap_op_202, vec![], None)?;
        let rows = [(tx.inputs[0].previous_output, prevout)];
        let prep = PreparedTransaction::new(&tx, &rows)?;
        assert_eq!(prep.verify_input(0, VerifyFlags::MANDATORY, None), Ok(true));
        Ok(())
    }

    #[test]
    fn push_size_limit_520_enforced_at_boundary() {
        let mut script_520 = push_data(&vec![0x42; 520]);
        script_520.push(opcode::OP_DROP);
        script_520.push(OP_1);
        assert_eq!(
            check_legacy(vec![], script_520, VerifyFlags::MANDATORY),
            Ok(true)
        );

        let mut script_521 = push_data(&vec![0x42; 521]);
        script_521.push(opcode::OP_DROP);
        script_521.push(OP_1);
        assert_eq!(
            check_legacy(vec![], script_521, VerifyFlags::MANDATORY),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::PushSize
            })
        );

        let mut unexecuted_521 = vec![opcode::OP_0, opcode::OP_IF];
        unexecuted_521.extend(push_data(&vec![0x42; 521]));
        unexecuted_521.push(opcode::OP_ENDIF);
        unexecuted_521.push(OP_1);
        assert_eq!(
            check_legacy(vec![], unexecuted_521, VerifyFlags::MANDATORY),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::PushSize
            })
        );
    }

    #[test]
    fn disabled_opcodes_rejected_everywhere() {
        let disabled = [
            0x7e_u8, 0x7f, 0x80, 0x81, 0x83, 0x84, 0x85, 0x86, 0x8d, 0x8e, 0x95, 0x96, 0x97, 0x98,
            0x99,
        ];
        for op in disabled {
            assert_eq!(
                check_legacy(vec![], vec![op], VerifyFlags::MANDATORY),
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::DisabledOpcode
                })
            );
            let unexecuted = vec![opcode::OP_0, opcode::OP_IF, op, opcode::OP_ENDIF, OP_1];
            assert_eq!(
                check_legacy(vec![], unexecuted, VerifyFlags::MANDATORY),
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::DisabledOpcode
                })
            );
        }
    }

    #[test]
    fn minimal_push_data_rules_enforced() {
        let non_minimal_one = vec![0x01, 0x01];
        let flags = VerifyFlags::MANDATORY.union(VerifyFlags::MINIMALDATA);
        assert_eq!(
            check_legacy(vec![], non_minimal_one, flags),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::MinimalData
            })
        );

        let non_minimal_neg_one = vec![0x01, 0x81];
        assert_eq!(
            check_legacy(vec![], non_minimal_neg_one, flags),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::MinimalData
            })
        );

        let mut pd1_75 = vec![OP_PUSHDATA1, 75];
        pd1_75.extend(vec![0x00; 75]);
        pd1_75.push(opcode::OP_DROP);
        pd1_75.push(OP_1);
        assert_eq!(
            check_legacy(vec![], pd1_75, flags),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::MinimalData
            })
        );

        assert_eq!(check_legacy(vec![], vec![OP_1], flags), Ok(true));
        assert_eq!(
            check_legacy(
                vec![],
                vec![opcode::OP_1NEGATE, opcode::OP_DROP, OP_1],
                flags
            ),
            Ok(true)
        );
    }

    #[test]
    fn conditional_nesting_and_unbalanced_branches() {
        assert_eq!(
            check_legacy(vec![], vec![OP_1, opcode::OP_IF], VerifyFlags::MANDATORY),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::UnbalancedConditional
            })
        );

        assert_eq!(
            check_legacy(vec![], vec![OP_ELSE], VerifyFlags::MANDATORY),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::UnbalancedConditional
            })
        );

        assert_eq!(
            check_legacy(vec![], vec![opcode::OP_ENDIF], VerifyFlags::MANDATORY),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::UnbalancedConditional
            })
        );

        let nested = vec![
            opcode::OP_0,
            opcode::OP_IF,
            opcode::OP_0,
            opcode::OP_IF,
            OP_1,
            OP_ELSE,
            OP_1,
            opcode::OP_ENDIF,
            OP_ELSE,
            OP_1,
            opcode::OP_ENDIF,
        ];
        assert_eq!(
            check_legacy(vec![], nested, VerifyFlags::MANDATORY),
            Ok(true)
        );
    }

    #[test]
    fn taproot_control_block_size_boundaries() -> TestResult {
        let secp = Secp256k1::new();
        let internal = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[17; 32])?)
            .x_only_public_key()
            .0;
        let script = ScriptBuf::from_bytes(vec![OP_1]);

        let depth_zero = TaprootBuilder::new()
            .add_leaf(0, script.clone())?
            .finalize(&secp, internal)
            .map_err(|_| "complete taproot tree")?;
        let depth_zero_control = depth_zero
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or("depth-zero control block")?
            .serialize();
        assert_eq!(depth_zero_control.len(), 33);
        assert_eq!(
            verify_taproot_witness(
                depth_zero.output_key(),
                vec![script.to_bytes(), depth_zero_control.clone()]
            )?,
            Ok(true)
        );

        let depth_one = TaprootBuilder::new()
            .add_leaf(1, ScriptBuf::from_bytes(vec![OP_NOP, OP_1]))?
            .add_leaf(1, script.clone())?
            .finalize(&secp, internal)
            .map_err(|_| "complete taproot tree")?;
        let depth_one_control = depth_one
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or("depth-one control block")?
            .serialize();
        assert_eq!(depth_one_control.len(), 65);
        assert_eq!(
            verify_taproot_witness(
                depth_one.output_key(),
                vec![script.to_bytes(), depth_one_control]
            )?,
            Ok(true)
        );

        let extended = |extra: usize| {
            let mut control = depth_zero_control.clone();
            control.extend(std::iter::repeat_n(0x01, extra));
            control
        };
        let below_base = vec![0xc0; 32];
        let misaligned = extended(1);
        let at_max = extended(32 * 128);
        let over_max = extended(32 * 128 + 1);
        let node_over_max = extended(32 * 129);
        assert_eq!(
            [
                below_base.len(),
                misaligned.len(),
                at_max.len(),
                over_max.len(),
                node_over_max.len()
            ],
            [32, 34, 4_129, 4_130, 4_161]
        );

        let wrong_size = || {
            Err(ScriptError::Invalid {
                code: ScriptErrCode::TaprootWrongControlSize,
            })
        };
        for control in [below_base, misaligned, over_max, node_over_max] {
            assert_eq!(
                verify_taproot_witness(depth_zero.output_key(), vec![script.to_bytes(), control])?,
                wrong_size()
            );
        }
        assert_eq!(
            verify_taproot_witness(depth_zero.output_key(), vec![script.to_bytes(), at_max])?,
            Err(ScriptError::Invalid {
                code: ScriptErrCode::WitnessProgramMismatch,
            })
        );
        Ok(())
    }

    #[test]
    fn annex_stripping_respects_witness_stack_size() -> TestResult {
        let (tx_two, prevout_two) =
            make_tapscript_tx(vec![OP_1], vec![], Some(vec![0x50, 0x01, 0x02]))?;
        let rows_two = [(tx_two.inputs[0].previous_output, prevout_two)];
        let prep_two = PreparedTransaction::new(&tx_two, &rows_two)?;
        assert_eq!(
            prep_two.verify_input(0, VerifyFlags::MANDATORY, None),
            Ok(true)
        );
        Ok(())
    }
}
mod script_core_vectors {
    #![cfg(test)]

    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait};
    use std::str::FromStr;

    use bitcoin::ScriptBuf;
    use bitcoin::hex::FromHex;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
    use bitcoin::taproot::{LeafVersion, TaprootBuilder};
    use bitcoin_rs_consensus::primitives::tapleaf_hash;
    use bitcoin_rs_consensus::primitives::{
        Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness, deserialize,
    };
    use bitcoin_rs_consensus::script::{
        Instruction, Interpreter, PreparedTransaction, ScriptErrCode, ScriptError, SignatureCache,
        VerifyFlags, instructions, opcode, push_data, push_int,
    };

    static CORE_ERROR_NAMES: &[&str] = &[
        "OK",
        "EVAL_FALSE",
        "OP_RETURN",
        "SCRIPTNUM",
        "SCRIPT_SIZE",
        "PUSH_SIZE",
        "OP_COUNT",
        "STACK_SIZE",
        "SIG_COUNT",
        "PUBKEY_COUNT",
        "VERIFY",
        "EQUALVERIFY",
        "CHECKMULTISIGVERIFY",
        "CHECKSIGVERIFY",
        "NUMEQUALVERIFY",
        "BAD_OPCODE",
        "DISABLED_OPCODE",
        "INVALID_STACK_OPERATION",
        "INVALID_ALTSTACK_OPERATION",
        "UNBALANCED_CONDITIONAL",
        "NEGATIVE_LOCKTIME",
        "UNSATISFIED_LOCKTIME",
        "SIG_HASHTYPE",
        "SIG_DER",
        "MINIMALDATA",
        "SIG_PUSHONLY",
        "SIG_HIGH_S",
        "SIG_NULLDUMMY",
        "PUBKEYTYPE",
        "CLEANSTACK",
        "MINIMALIF",
        "NULLFAIL",
        "DISCOURAGE_UPGRADABLE_NOPS",
        "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
        "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION",
        "DISCOURAGE_OP_SUCCESS",
        "DISCOURAGE_UPGRADABLE_PUBKEYTYPE",
        "WITNESS_PROGRAM_WRONG_LENGTH",
        "WITNESS_PROGRAM_WITNESS_EMPTY",
        "WITNESS_PROGRAM_MISMATCH",
        "WITNESS_MALLEATED",
        "WITNESS_MALLEATED_P2SH",
        "WITNESS_UNEXPECTED",
        "WITNESS_PUBKEYTYPE",
        "SCHNORR_SIG_SIZE",
        "SCHNORR_SIG_HASHTYPE",
        "SCHNORR_SIG",
        "TAPROOT_WRONG_CONTROL_SIZE",
        "TAPSCRIPT_VALIDATION_WEIGHT",
        "TAPSCRIPT_CHECKMULTISIG",
        "TAPSCRIPT_MINIMALIF",
        "TAPSCRIPT_EMPTY_PUBKEY",
        "OP_CODESEPARATOR",
        "SIG_FINDANDDELETE",
    ];

    fn parse_core_asm(asm: &str) -> Result<Vec<u8>, String> {
        let mut script = Vec::new();
        for token in asm.split([' ', '\t', '\n']) {
            if token.is_empty() {
                continue;
            }
            if let Some(hex) = token.strip_prefix("0x") {
                if hex.is_empty() {
                    return Err(format!("empty 0x token: {token}"));
                }
                let bytes =
                    hex_to_bytes(hex).map_err(|e| format!("invalid hex in token {token}: {e}"))?;
                script.extend_from_slice(&bytes);
            } else if is_decimal_int(token) {
                let n = token
                    .parse::<i64>()
                    .map_err(|e| format!("decimal parse failed for {token}: {e}"))?;
                script.extend_from_slice(&push_int(n));
            } else if token.len() >= 2 && token.starts_with('\'') && token.ends_with('\'') {
                let inner = &token[1..token.len() - 1];
                script.extend_from_slice(&push_data(inner.as_bytes()));
            } else {
                let byte = resolve_opcode(token)
                    .ok_or_else(|| format!("unknown opcode token: {token}"))?;
                script.push(byte);
            }
        }
        Ok(script)
    }

    fn is_decimal_int(s: &str) -> bool {
        let bytes = s.as_bytes();
        if bytes.is_empty() {
            return false;
        }
        let start = usize::from(bytes[0] == b'-');
        if start >= bytes.len() {
            return false;
        }
        bytes[start..].iter().all(u8::is_ascii_digit)
    }

    fn resolve_opcode(name: &str) -> Option<u8> {
        let bare = name.strip_prefix("OP_").unwrap_or(name);
        lookup_opcode(bare)
    }

    static OPCODE_BYTES: &[(u8, &[&str])] = &[
        (0x00, &["0", "EMPTY"]),
        (0x4c, &["PUSHDATA1"]),
        (0x4d, &["PUSHDATA2"]),
        (0x4e, &["PUSHDATA4"]),
        (0x4f, &["1NEGATE"]),
        (0x50, &["RESERVED"]),
        (0x51, &["1", "PUSHNUM_1"]),
        (0x52, &["2", "PUSHNUM_2"]),
        (0x53, &["3", "PUSHNUM_3"]),
        (0x54, &["4", "PUSHNUM_4"]),
        (0x55, &["5", "PUSHNUM_5"]),
        (0x56, &["6", "PUSHNUM_6"]),
        (0x57, &["7", "PUSHNUM_7"]),
        (0x58, &["8", "PUSHNUM_8"]),
        (0x59, &["9", "PUSHNUM_9"]),
        (0x5a, &["10", "PUSHNUM_10"]),
        (0x5b, &["11", "PUSHNUM_11"]),
        (0x5c, &["12", "PUSHNUM_12"]),
        (0x5d, &["13", "PUSHNUM_13"]),
        (0x5e, &["14", "PUSHNUM_14"]),
        (0x5f, &["15", "PUSHNUM_15"]),
        (0x60, &["16", "PUSHNUM_16"]),
        (0x61, &["NOP"]),
        (0x62, &["VER"]),
        (0x63, &["IF"]),
        (0x64, &["NOTIF"]),
        (0x65, &["VERIF"]),
        (0x66, &["VERNOTIF"]),
        (0x67, &["ELSE"]),
        (0x68, &["ENDIF"]),
        (0x69, &["VERIFY"]),
        (0x6a, &["RETURN"]),
        (0x6b, &["TOALTSTACK"]),
        (0x6c, &["FROMALTSTACK"]),
        (0x6d, &["2DROP"]),
        (0x6e, &["2DUP"]),
        (0x6f, &["3DUP"]),
        (0x70, &["2OVER"]),
        (0x71, &["2ROT"]),
        (0x72, &["2SWAP"]),
        (0x73, &["IFDUP"]),
        (0x74, &["DEPTH"]),
        (0x75, &["DROP"]),
        (0x76, &["DUP"]),
        (0x77, &["NIP"]),
        (0x78, &["OVER"]),
        (0x79, &["PICK"]),
        (0x7a, &["ROLL"]),
        (0x7b, &["ROT"]),
        (0x7c, &["SWAP"]),
        (0x7d, &["TUCK"]),
        (0x7e, &["CAT"]),
        (0x7f, &["SUBSTR"]),
        (0x80, &["LEFT"]),
        (0x81, &["RIGHT"]),
        (0x82, &["SIZE"]),
        (0x83, &["INVERT"]),
        (0x84, &["AND"]),
        (0x85, &["OR"]),
        (0x86, &["XOR"]),
        (0x87, &["EQUAL"]),
        (0x88, &["EQUALVERIFY"]),
        (0x89, &["RESERVED1"]),
        (0x8a, &["RESERVED2"]),
        (0x8b, &["1ADD"]),
        (0x8c, &["1SUB"]),
        (0x8d, &["2MUL"]),
        (0x8e, &["2DIV"]),
        (0x8f, &["NEGATE"]),
        (0x90, &["ABS"]),
        (0x91, &["NOT"]),
        (0x92, &["0NOTEQUAL"]),
        (0x93, &["ADD"]),
        (0x94, &["SUB"]),
        (0x95, &["MUL"]),
        (0x96, &["DIV"]),
        (0x97, &["MOD"]),
        (0x98, &["LSHIFT"]),
        (0x99, &["RSHIFT"]),
        (0x9a, &["BOOLAND"]),
        (0x9b, &["BOOLOR"]),
        (0x9c, &["NUMEQUAL"]),
        (0x9d, &["NUMEQUALVERIFY"]),
        (0x9e, &["NUMNOTEQUAL"]),
        (0x9f, &["LESSTHAN"]),
        (0xa0, &["GREATERTHAN"]),
        (0xa1, &["LESSTHANOREQUAL"]),
        (0xa2, &["GREATERTHANOREQUAL"]),
        (0xa3, &["MIN"]),
        (0xa4, &["MAX"]),
        (0xa5, &["WITHIN"]),
        (0xa6, &["RIPEMD160"]),
        (0xa7, &["SHA1"]),
        (0xa8, &["SHA256"]),
        (0xa9, &["HASH160"]),
        (0xaa, &["HASH256"]),
        (0xab, &["CODESEPARATOR"]),
        (0xac, &["CHECKSIG"]),
        (0xad, &["CHECKSIGVERIFY"]),
        (0xae, &["CHECKMULTISIG"]),
        (0xaf, &["CHECKMULTISIGVERIFY"]),
        (0xb0, &["NOP1"]),
        (0xb1, &["CHECKLOCKTIMEVERIFY"]),
        (0xb2, &["CHECKSEQUENCEVERIFY"]),
        (0xb3, &["NOP4"]),
        (0xb4, &["NOP5"]),
        (0xb5, &["NOP6"]),
        (0xb6, &["NOP7"]),
        (0xb7, &["NOP8"]),
        (0xb8, &["NOP9"]),
        (0xb9, &["NOP10"]),
        (0xba, &["CHECKSIGADD"]),
        (0xfd, &["PUBKEYHASH"]),
        (0xfe, &["PUBKEY"]),
        (0xff, &["INVALIDOPCODE"]),
    ];

    static OP_SUCCESS_NAMES: &[(u8, &str)] = &[
        (0x50, "SUCCESS_0"),
        (0x7e, "SUCCESS_80"),
        (0x7f, "SUCCESS_81"),
        (0x80, "SUCCESS_82"),
        (0x81, "SUCCESS_83"),
        (0x82, "SUCCESS_84"),
        (0x83, "SUCCESS_85"),
        (0x84, "SUCCESS_86"),
        (0x85, "SUCCESS_87"),
        (0x86, "SUCCESS_88"),
        (0x87, "SUCCESS_89"),
        (0x88, "SUCCESS_90"),
        (0x89, "SUCCESS_91"),
        (0x8a, "SUCCESS_92"),
        (0x8b, "SUCCESS_93"),
        (0x8c, "SUCCESS_94"),
        (0x8d, "SUCCESS_95"),
        (0x8e, "SUCCESS_96"),
        (0x8f, "SUCCESS_97"),
        (0x90, "SUCCESS_98"),
        (0x91, "SUCCESS_99"),
        (0x92, "SUCCESS_100"),
        (0x93, "SUCCESS_101"),
        (0x94, "SUCCESS_102"),
        (0x95, "SUCCESS_103"),
        (0x96, "SUCCESS_104"),
        (0x97, "SUCCESS_105"),
        (0x98, "SUCCESS_106"),
        (0x99, "SUCCESS_107"),
        (0x9a, "SUCCESS_108"),
        (0x9b, "SUCCESS_109"),
        (0x9c, "SUCCESS_110"),
        (0x9d, "SUCCESS_111"),
        (0x9e, "SUCCESS_112"),
        (0x9f, "SUCCESS_113"),
        (0xa0, "SUCCESS_114"),
        (0xa1, "SUCCESS_115"),
        (0xa2, "SUCCESS_116"),
        (0xa3, "SUCCESS_117"),
        (0xa4, "SUCCESS_118"),
        (0xa5, "SUCCESS_119"),
        (0xa6, "SUCCESS_120"),
        (0xa7, "SUCCESS_121"),
        (0xa8, "SUCCESS_122"),
        (0xa9, "SUCCESS_123"),
        (0xaa, "SUCCESS_124"),
        (0xab, "SUCCESS_125"),
        (0xac, "SUCCESS_126"),
        (0xad, "SUCCESS_127"),
        (0xae, "SUCCESS_128"),
        (0xaf, "SUCCESS_129"),
        (0xb0, "SUCCESS_130"),
        (0xb1, "SUCCESS_131"),
        (0xb2, "SUCCESS_132"),
        (0xb3, "SUCCESS_133"),
        (0xb4, "SUCCESS_134"),
        (0xb5, "SUCCESS_135"),
        (0xb6, "SUCCESS_136"),
        (0xb7, "SUCCESS_137"),
        (0xb8, "SUCCESS_138"),
        (0xb9, "SUCCESS_139"),
        (0xba, "SUCCESS_140"),
        (0xbb, "SUCCESS_141"),
        (0xbc, "SUCCESS_142"),
        (0xbd, "SUCCESS_143"),
        (0xbe, "SUCCESS_144"),
        (0xbf, "SUCCESS_145"),
        (0xc0, "SUCCESS_146"),
        (0xc1, "SUCCESS_147"),
        (0xc2, "SUCCESS_148"),
        (0xc3, "SUCCESS_149"),
        (0xc4, "SUCCESS_150"),
        (0xc5, "SUCCESS_151"),
        (0xc6, "SUCCESS_152"),
        (0xc7, "SUCCESS_153"),
        (0xc8, "SUCCESS_154"),
        (0xc9, "SUCCESS_155"),
        (0xca, "SUCCESS_156"),
        (0xcb, "SUCCESS_157"),
        (0xcc, "SUCCESS_158"),
        (0xcd, "SUCCESS_159"),
        (0xce, "SUCCESS_160"),
        (0xcf, "SUCCESS_161"),
        (0xd0, "SUCCESS_162"),
        (0xd1, "SUCCESS_163"),
        (0xd2, "SUCCESS_164"),
        (0xd3, "SUCCESS_165"),
        (0xd4, "SUCCESS_166"),
        (0xd5, "SUCCESS_167"),
        (0xd6, "SUCCESS_168"),
        (0xd7, "SUCCESS_169"),
        (0xd8, "SUCCESS_170"),
        (0xd9, "SUCCESS_171"),
        (0xda, "SUCCESS_172"),
        (0xdb, "SUCCESS_173"),
        (0xdc, "SUCCESS_174"),
        (0xdd, "SUCCESS_175"),
        (0xde, "SUCCESS_176"),
        (0xdf, "SUCCESS_177"),
        (0xe0, "SUCCESS_178"),
        (0xe1, "SUCCESS_179"),
        (0xe2, "SUCCESS_180"),
        (0xe3, "SUCCESS_181"),
        (0xe4, "SUCCESS_182"),
        (0xe5, "SUCCESS_183"),
        (0xe6, "SUCCESS_184"),
        (0xe7, "SUCCESS_185"),
        (0xe8, "SUCCESS_186"),
        (0xe9, "SUCCESS_187"),
        (0xea, "SUCCESS_188"),
        (0xeb, "SUCCESS_189"),
        (0xec, "SUCCESS_190"),
        (0xed, "SUCCESS_191"),
    ];

    fn lookup_opcode(bare: &str) -> Option<u8> {
        for &(byte, names) in OPCODE_BYTES {
            if names.contains(&bare) {
                return Some(byte);
            }
        }
        for &(byte, name) in OP_SUCCESS_NAMES {
            if name == bare {
                return Some(byte);
            }
        }
        None
    }

    fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
        Vec::from_hex(hex).map_err(|error| error.to_string())
    }

    fn build_crediting_tx(script_pubkey: &[u8], amount: u64) -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![opcode::OP_0, opcode::OP_0].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: script_pubkey.to_vec().into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn build_spending_tx(script_sig: &[u8], witness: &[Vec<u8>], credit_tx: &Tx) -> Tx {
        let credit_txid = credit_tx.txid();
        Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(credit_txid, 0),
                script_sig: script_sig.to_vec().into(),
                sequence: Sequence::MAX,
                witness: witness.to_vec().into(),
            }],
            outputs: vec![TxOut {
                value: credit_tx.outputs[0].value,
                script_pubkey: Script::new(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Verdict {
        Accept,
        Reject(Option<String>),
    }

    impl Verdict {
        fn from_interpreter(result: &Result<bool, ScriptError>) -> Self {
            match result {
                Ok(true) => Self::Accept,
                Err(ScriptError::Invalid { code }) => Self::Reject(Some(code.to_string())),
                Ok(false) | Err(_) => Self::Reject(None),
            }
        }

        #[cfg(feature = "kernel")]
        fn from_kernel(result: &Result<(), bitcoin_rs_consensus::ConsensusError>) -> Self {
            match result {
                Ok(()) => Self::Accept,
                Err(bitcoin_rs_consensus::ConsensusError::Script { .. }) => Self::Reject(None),
                Err(other) => panic!("kernel oracle infrastructure error: {other}"),
            }
        }

        const fn accepted(&self) -> bool {
            matches!(self, Self::Accept)
        }
    }

    #[derive(Default, Debug)]
    struct Counts {
        parsed: usize,
        executed: usize,
        skipped: usize,
        failed: usize,
        skip_reasons: Vec<String>,
    }

    impl Counts {
        fn record_skip(&mut self, reason: &str) {
            self.skipped += 1;
            if !self.skip_reasons.iter().any(|r| r == reason) {
                self.skip_reasons.push(reason.to_owned());
            }
        }
    }

    impl std::fmt::Display for Counts {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "parsed={}, executed={}, skipped={}, failed={}",
                self.parsed, self.executed, self.skipped, self.failed,
            )?;
            if !self.skip_reasons.is_empty() {
                write!(f, " [skip reasons: {}]", self.skip_reasons.join("; "))?;
            }
            Ok(())
        }
    }

    fn assert_pinned_column(
        counts: &Counts,
        mismatch_count: usize,
        pinned_failures: usize,
        pinned_skips: usize,
        pinned_executed: usize,
        allowed_skip_reasons: &[&str],
        corpus: &str,
        column: &str,
    ) {
        assert_eq!(
            mismatch_count, pinned_failures,
            "{corpus} {column} mismatches changed; triage each row, then move the pinned count"
        );
        assert_eq!(
            counts.skipped, pinned_skips,
            "{corpus} {column} skips changed; a new skip category shrinks coverage"
        );
        assert_eq!(
            counts.executed, pinned_executed,
            "{corpus} {column} executed count changed; update the pin with the skip triage"
        );
        for reason in &counts.skip_reasons {
            assert!(
                allowed_skip_reasons
                    .iter()
                    .copied()
                    .any(|allowed| allowed == reason),
                "{corpus} {column}: unexpected skip reason `{reason}`; allowed {allowed_skip_reasons:?}"
            );
        }
        assert_eq!(
            counts.skip_reasons.len(),
            allowed_skip_reasons.len(),
            "{corpus} {column}: skip-reason set changed: {:?}",
            counts.skip_reasons
        );
    }

    fn assert_pinned_native_column(
        counts: &Counts,
        mismatch_count: usize,
        pinned_failures: usize,
        pinned_skips: usize,
        pinned_executed: usize,
        allowed_skip_reasons: &[&str],
        corpus: &str,
    ) {
        assert_pinned_column(
            counts,
            mismatch_count,
            pinned_failures,
            pinned_skips,
            pinned_executed,
            allowed_skip_reasons,
            corpus,
            "native",
        );
    }

    const CORE_TAPROOT_INTERNAL_SECRET: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];

    const SCRIPT_PLACEHOLDER: &str = "#SCRIPT#";

    const CONTROL_BLOCK_PLACEHOLDER: &str = "#CONTROLBLOCK#";

    const TAPROOT_OUTPUT_ASM: &str = "0x51 0x20 #TAPROOTOUTPUT#";

    struct TaprootPlaceholder {
        control_block: Vec<u8>,
        output_key: [u8; 32],
    }

    fn build_taproot_placeholder(leaf_script: &[u8]) -> Result<TaprootPlaceholder, String> {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&CORE_TAPROOT_INTERNAL_SECRET)
            .map_err(|e| format!("Core's fixed key0 must be a valid secret: {e}"))?;
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (internal, _) = XOnlyPublicKey::from_keypair(&keypair);
        let script = ScriptBuf::from_bytes(leaf_script.to_vec());

        let builder = TaprootBuilder::new()
            .add_leaf_with_ver(0, script.clone(), LeafVersion::TapScript)
            .map_err(|e| format!("single-leaf taproot tree must build: {e}"))?;
        let spend_info = builder
            .finalize(&secp, internal)
            .map_err(|_| "a one-leaf tree must finalize".to_owned())?;
        let control_bytes = spend_info
            .control_block(&(script, LeafVersion::TapScript))
            .ok_or("the leaf Core adds must have a control block")?
            .serialize();
        let output_key = spend_info.output_key().serialize();

        let tapleaf = tapleaf_hash(LeafVersion::TapScript.to_consensus(), leaf_script);
        let core_root = spend_info
            .merkle_root()
            .ok_or("a one-leaf tree has a merkle root")?;
        let core_root_bytes: &[u8] = core_root.as_ref();
        if core_root_bytes != tapleaf.as_byte_array() {
            return Err(format!(
                "tapleaf hash disagreement: rust-bitcoin {core_root:?}, this crate {tapleaf:?}"
            ));
        }

        Ok(TaprootPlaceholder {
            control_block: control_bytes,
            output_key,
        })
    }

    struct ScriptTestRow {
        script_sig: Vec<u8>,
        script_pubkey: Vec<u8>,
        witness: Vec<Vec<u8>>,
        amount: u64,
        flags: VerifyFlags,
        expected: String,
        row_index: usize,
        comment: String,
    }

    fn load_script_tests(counts: &mut Counts) -> Result<Vec<ScriptTestRow>, String> {
        let path = reference_path("script_tests.json");
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("script_tests.json unreadable: {e}"))?;
        let root: sonic_rs::Value =
            sonic_rs::from_str(&text).map_err(|e| format!("script_tests.json parse: {e}"))?;
        let arr = root
            .as_array()
            .ok_or("script_tests.json root is not an array")?;

        let mut rows = Vec::new();
        'row: for (index, row) in arr.iter().enumerate() {
            let Some(arr) = row.as_array() else {
                continue;
            };
            counts.parsed += 1;

            let (
                witness_raw,
                script_sig_idx,
                script_pubkey_idx,
                flags_idx,
                expected_idx,
                comment_idx,
            ) = if arr.first().is_some_and(sonic_rs::Value::is_array) {
                (Some(&arr[0]), 1, 2, 3, 4, 5)
            } else if arr.len() >= 4 {
                (None, 0, 1, 2, 3, 4)
            } else if arr.len() == 1 && arr[0].is_str() {
                counts.record_skip(SCRIPT_TESTS_PROSE_SKIP);
                continue;
            } else {
                counts.record_skip(&format!(
                    "short row ({} elements): needs scriptSig, scriptPubKey, flags, expected error",
                    arr.len()
                ));
                continue;
            };

            let mut placeholder_tree = None;
            let (witness, amount) = if let Some(wit_arr) = witness_raw {
                let wit = wit_arr
                    .as_array()
                    .ok_or_else(|| format!("row {index}: witness is not an array"))?;
                if wit.is_empty() {
                    counts.record_skip("witness array empty");
                    continue;
                }
                let Some(amount_btc) = wit.last().and_then(sonic_rs::Value::as_f64) else {
                    counts.record_skip("witness amount not a number");
                    continue;
                };
                let amount = btc_to_sats(amount_btc);
                let mut items = Vec::new();
                for elem in &wit[..wit.len() - 1] {
                    let Some(s) = elem.as_str() else {
                        counts.record_skip("witness element is not a string");
                        continue 'row;
                    };
                    if let Some(asm) = s.strip_prefix(SCRIPT_PLACEHOLDER) {
                        let leaf = match parse_core_asm(asm) {
                            Ok(script) => script,
                            Err(e) => {
                                counts.record_skip(&format!("#SCRIPT# asm parse error: {e}"));
                                continue 'row;
                            }
                        };
                        match build_taproot_placeholder(&leaf) {
                            Ok(tree) => {
                                placeholder_tree = Some(tree);
                                items.push(leaf);
                            }
                            Err(e) => {
                                counts.record_skip(&format!("#CONTROLBLOCK# tree: {e}"));
                                continue 'row;
                            }
                        }
                        continue;
                    }
                    if s == CONTROL_BLOCK_PLACEHOLDER {
                        if let Some(tree) = &placeholder_tree {
                            items.push(tree.control_block.clone());
                        } else {
                            counts.record_skip("#CONTROLBLOCK# with no preceding #SCRIPT# leaf");
                            continue 'row;
                        }
                        continue;
                    }
                    items.push(
                        hex_to_bytes(s)
                            .map_err(|e| format!("row {index}: bad witness hex: {e}"))?,
                    );
                }
                (items, amount)
            } else {
                (Vec::new(), 0)
            };

            let script_sig_str = arr
                .get(script_sig_idx)
                .and_then(sonic_rs::Value::as_str)
                .ok_or_else(|| format!("row {index}: scriptSig is not a string"))?;
            let script_pubkey_str = arr
                .get(script_pubkey_idx)
                .and_then(sonic_rs::Value::as_str)
                .ok_or_else(|| format!("row {index}: scriptPubKey is not a string"))?;
            let flags_str = arr
                .get(flags_idx)
                .and_then(sonic_rs::Value::as_str)
                .unwrap_or("");
            let expected_str = arr
                .get(expected_idx)
                .and_then(sonic_rs::Value::as_str)
                .ok_or_else(|| format!("row {index}: expected result is not a string"))?;

            let script_sig = match parse_core_asm(script_sig_str) {
                Ok(s) => s,
                Err(e) => {
                    counts.record_skip(&format!("scriptSig asm parse error: {e}"));
                    continue;
                }
            };
            let script_pubkey = if script_pubkey_str == TAPROOT_OUTPUT_ASM {
                if let Some(tree) = &placeholder_tree {
                    let mut spk = vec![opcode::OP_PUSHNUM_1, 0x20];
                    spk.extend_from_slice(&tree.output_key);
                    spk
                } else {
                    counts.record_skip("#TAPROOTOUTPUT# with no #CONTROLBLOCK# witness element");
                    continue;
                }
            } else {
                match parse_core_asm(script_pubkey_str) {
                    Ok(s) => s,
                    Err(e) => {
                        counts.record_skip(&format!("scriptPubKey asm parse error: {e}"));
                        continue;
                    }
                }
            };

            let flags = match VerifyFlags::from_core_names(flags_str) {
                Ok(f) => f,
                Err(e) => {
                    counts.record_skip(&format!("unknown flag: {e}"));
                    continue;
                }
            };

            if !CORE_ERROR_NAMES.contains(&expected_str) {
                counts.record_skip(&format!("unknown expected error name: {expected_str}"));
                continue;
            }
            let expected = expected_str.to_owned();

            let comment = arr
                .get(comment_idx)
                .and_then(sonic_rs::Value::as_str)
                .unwrap_or("")
                .to_owned();

            rows.push(ScriptTestRow {
                script_sig,
                script_pubkey,
                witness,
                amount,
                flags,
                expected,
                row_index: index + 1,
                comment,
            });
        }
        Ok(rows)
    }

    #[expect(clippy::expect_used, reason = "Core satoshi amounts are valid u64")]
    fn btc_to_sats(btc: f64) -> u64 {
        format!("{:.0}", (btc * 100_000_000.0).round())
            .parse::<u64>()
            .expect("btc amount is non-negative and fits u64")
    }

    fn run_script_tests(
        rows: &[ScriptTestRow],
        counts: &mut Counts,
        verify: impl Fn(&ScriptTestRow, &Tx, &Tx) -> Verdict,
    ) -> Vec<String> {
        let mut mismatches = Vec::new();

        for row in rows {
            counts.executed += 1;
            let credit = build_crediting_tx(&row.script_pubkey, row.amount);
            let spend = build_spending_tx(&row.script_sig, &row.witness, &credit);
            let verdict = verify(row, &credit, &spend);

            if verdict.accepted() != (row.expected == "OK") {
                counts.failed += 1;
                mismatches.push(format!(
                    "row {}: expected {}, got {:?} (flags {:#x}, sig {}, pubkey {}, comment: {})",
                    row.row_index,
                    row.expected,
                    verdict,
                    row.flags.bits(),
                    hex_of(&row.script_sig),
                    hex_of(&row.script_pubkey),
                    row.comment
                ));
            }
        }
        mismatches
    }

    struct TxVectorRow {
        tx: Tx,
        prevouts: Vec<(OutPoint, TxOut)>,
        flags: VerifyFlags,
        expected: Verdict,
        row_index: usize,
    }

    fn load_tx_vectors(
        name: &str,
        expected_accept: bool,
        counts: &mut Counts,
    ) -> Result<Vec<TxVectorRow>, String> {
        let path = reference_path(name);
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{name} unreadable: {e}"))?;
        let root: sonic_rs::Value =
            sonic_rs::from_str(&text).map_err(|e| format!("{name} parse: {e}"))?;
        let arr = root
            .as_array()
            .ok_or_else(|| format!("{name} root is not an array"))?;

        let mut rows = Vec::new();
        for (index, row) in arr.iter().enumerate() {
            let Some(arr) = row.as_array() else {
                continue;
            };
            if arr.len() < 3 || !arr[0].is_array() || arr[1].as_str().is_none() {
                continue;
            }
            counts.parsed += 1;

            let flags_str = arr[2].as_str().unwrap_or("NONE");
            if flags_str.contains("BADTX") {
                counts.record_skip(TX_INVALID_BADTX_SKIP);
                continue;
            }

            let tx_hex = arr[1].as_str().unwrap_or("");
            let tx_bytes = match hex_to_bytes(tx_hex) {
                Ok(b) => b,
                Err(e) => {
                    counts.record_skip(&format!("bad tx hex: {e}"));
                    continue;
                }
            };
            let Ok(tx) = deserialize::<Tx>(&tx_bytes) else {
                if expected_accept {
                    counts.record_skip("tx_valid row failed to deserialize");
                } else {
                    counts.record_skip(
                        "tx_invalid row failed to deserialize (expected rejection at parse stage)",
                    );
                }
                continue;
            };

            let flags = match if expected_accept {
                tx_valid_flags(flags_str)
            } else {
                tx_invalid_flags(flags_str)
            } {
                Ok(f) => f,
                Err(e) => {
                    counts.record_skip(&e);
                    continue;
                }
            };

            let Some(prevout_specs) = arr[0].as_array() else {
                counts.record_skip("prevout spec is not an array");
                continue;
            };
            let mut prevouts = Vec::with_capacity(prevout_specs.len());
            let mut prevout_error = false;
            for spec in prevout_specs {
                let Some(spec_arr) = spec.as_array() else {
                    counts.record_skip("prevout spec element is not an array");
                    prevout_error = true;
                    break;
                };
                let Some(hash_hex) = spec_arr.first().and_then(sonic_rs::Value::as_str) else {
                    counts.record_skip("prevout hash not a string");
                    prevout_error = true;
                    break;
                };
                let Some(vout_i64) = spec_arr.get(1).and_then(sonic_rs::Value::as_i64) else {
                    counts.record_skip("prevout vout not an integer");
                    prevout_error = true;
                    break;
                };
                let mut vout_bytes = [0_u8; 4];
                vout_bytes.copy_from_slice(&vout_i64.to_le_bytes()[..4]);
                let vout = u32::from_le_bytes(vout_bytes);
                let Some(script_asm) = spec_arr.get(2).and_then(sonic_rs::Value::as_str) else {
                    counts.record_skip("prevout script not a string");
                    prevout_error = true;
                    break;
                };
                let amount = spec_arr
                    .get(3)
                    .and_then(sonic_rs::Value::as_u64)
                    .unwrap_or(0);

                let script_pubkey = match parse_core_asm(script_asm) {
                    Ok(s) => s,
                    Err(e) => {
                        counts.record_skip(&format!("prevout script asm error: {e}"));
                        prevout_error = true;
                        break;
                    }
                };

                let Ok(txid) = Txid::from_str(hash_hex) else {
                    counts.record_skip(&format!("prevout txid parse: {hash_hex}"));
                    prevout_error = true;
                    break;
                };
                prevouts.push((
                    OutPoint::new(txid, vout),
                    TxOut {
                        value: Amount::from_sat(amount),
                        script_pubkey: script_pubkey.into(),
                    },
                ));
            }
            if prevout_error {
                continue;
            }

            let mut ordered_prevouts = Vec::with_capacity(tx.inputs.len());
            let mut missing_prevout = false;
            for input in &tx.inputs {
                if let Some((_, spent)) =
                    prevouts.iter().find(|(op, _)| *op == input.previous_output)
                {
                    ordered_prevouts.push((input.previous_output, spent.clone()));
                } else {
                    counts.record_skip(&format!(
                        "input spending {:?} missing from prevout set",
                        input.previous_output
                    ));
                    missing_prevout = true;
                    break;
                }
            }
            if missing_prevout {
                continue;
            }

            let expected = if expected_accept {
                Verdict::Accept
            } else {
                Verdict::Reject(None)
            };

            rows.push(TxVectorRow {
                tx,
                prevouts: ordered_prevouts,
                flags,
                expected,
                row_index: index + 1,
            });
        }
        Ok(rows)
    }

    fn verify_native_tx(row: &TxVectorRow) -> Verdict {
        let prepared = match PreparedTransaction::new(&row.tx, &row.prevouts) {
            Ok(prepared) => prepared,
            Err(error) => panic!("native harness prevout error: {error}"),
        };
        let mut first_failure = None;
        for input_idx in 0..row.tx.inputs.len() {
            let result = prepared.verify_input(input_idx, row.flags, None);
            if !matches!(result, Ok(true)) {
                first_failure = Some((input_idx, Verdict::from_interpreter(&result)));
                break;
            }
        }

        match &first_failure {
            None => Verdict::Accept,
            Some((input_idx, Verdict::Reject(code))) => Verdict::Reject(Some(format!(
                "input {input_idx}: {}",
                code.clone().unwrap_or_else(|| "no code".to_owned())
            ))),
            Some((input_idx, Verdict::Accept)) => {
                Verdict::Reject(Some(format!("input {input_idx}: accepted-but-not-true")))
            }
        }
    }

    fn run_tx_vectors(
        rows: &[TxVectorRow],
        counts: &mut Counts,
        verify: impl Fn(&TxVectorRow) -> Verdict,
    ) -> Vec<String> {
        let mut mismatches = Vec::new();

        for row in rows {
            counts.executed += 1;
            let verdict = verify(row);

            let matches = verdict.accepted() == row.expected.accepted();
            if !matches {
                counts.failed += 1;
                mismatches.push(format!(
                    "row {}: expected {:?}, got {:?} (flags {:#x}, locktime {}, seq0 {:#x})",
                    row.row_index,
                    row.expected,
                    verdict,
                    row.flags.bits(),
                    row.tx.lock_time,
                    row.tx
                        .inputs
                        .first()
                        .map_or(0, |input| input.sequence.to_consensus())
                ));
            }
        }
        mismatches
    }

    fn hex_of(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    const FULL_FLAGS: VerifyFlags = VerifyFlags::STANDARD
        .union(VerifyFlags::SIGPUSHONLY)
        .union(VerifyFlags::CONST_SCRIPTCODE)
        .union(VerifyFlags::MINIMALIF);

    const SINGLE_BIT_FLAGS: [VerifyFlags; 21] = [
        VerifyFlags::P2SH,
        VerifyFlags::STRICTENC,
        VerifyFlags::DERSIG,
        VerifyFlags::LOW_S,
        VerifyFlags::NULLDUMMY,
        VerifyFlags::SIGPUSHONLY,
        VerifyFlags::MINIMALDATA,
        VerifyFlags::DISCOURAGE_UPGRADABLE_NOPS,
        VerifyFlags::CLEANSTACK,
        VerifyFlags::CHECKLOCKTIMEVERIFY,
        VerifyFlags::CHECKSEQUENCEVERIFY,
        VerifyFlags::WITNESS,
        VerifyFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
        VerifyFlags::MINIMALIF,
        VerifyFlags::NULLFAIL,
        VerifyFlags::WITNESS_PUBKEYTYPE,
        VerifyFlags::CONST_SCRIPTCODE,
        VerifyFlags::TAPROOT,
        VerifyFlags::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
        VerifyFlags::DISCOURAGE_OP_SUCCESS,
        VerifyFlags::DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
    ];

    fn flags_from_bits(bits: u32) -> VerifyFlags {
        let mut flags = VerifyFlags::NONE;
        for flag in SINGLE_BIT_FLAGS {
            if bits & flag.bits() != 0 {
                flags = flags.union(flag);
            }
        }
        assert_eq!(flags.bits(), bits, "flag bits outside SINGLE_BIT_FLAGS");
        flags
    }

    fn tx_valid_flags(names: &str) -> Result<VerifyFlags, String> {
        let parsed = VerifyFlags::from_core_names(names).map_err(|e| e.to_string())?;
        let effective = flags_from_bits(FULL_FLAGS.bits() & !parsed.bits());
        if effective != effective.filled() {
            return Err(format!(
                "bad test flags (not a filled combination): {names}"
            ));
        }
        Ok(effective)
    }

    fn tx_invalid_flags(names: &str) -> Result<VerifyFlags, String> {
        let parsed = VerifyFlags::from_core_names(names).map_err(|e| e.to_string())?;
        if parsed != parsed.filled() {
            return Err(format!(
                "bad test flags (not a filled combination): {names}"
            ));
        }
        Ok(parsed)
    }

    fn mismatch_print_limit() -> usize {
        std::env::var("SCRIPT_VECTOR_MISMATCHES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(5)
    }

    fn reference_path(name: &str) -> std::path::PathBuf {
        let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = crate_dir
            .ancestors()
            .find(|dir| dir.join(".references").is_dir())
            .unwrap_or(crate_dir);
        let candidates = [
            crate_dir
                .join("../../testdata/consensus/vectors")
                .join(name),
            workspace_root
                .join(".references/bitcoin/src/test/data")
                .join(name),
        ];
        for candidate in &candidates {
            if candidate.exists() {
                return candidate.clone();
            }
        }
        candidates[0].clone()
    }

    #[test]
    #[expect(
        clippy::unwrap_used,
        reason = "test assertions on known-good asm inputs"
    )]
    fn asm_assembler_matches_known_bytes() {
        assert_eq!(parse_core_asm("DEPTH 0 EQUAL").unwrap(), [0x74, 0x00, 0x87]);
        assert_eq!(
            parse_core_asm("0x02 0x01 0x00").unwrap(),
            [0x02, 0x01, 0x00]
        );
        assert_eq!(
            parse_core_asm("'Az' EQUAL").unwrap(),
            [0x02, b'A', b'z', 0x87]
        );
        assert_eq!(parse_core_asm("1 2").unwrap(), [0x51, 0x52]);
        assert_eq!(parse_core_asm("-1").unwrap(), [0x4f]);
        assert_eq!(parse_core_asm("DUP IF ENDIF").unwrap(), [0x76, 0x63, 0x68]);
        assert_eq!(parse_core_asm("NOP").unwrap(), [0x61]);
        assert_eq!(parse_core_asm("OP_NOP").unwrap(), [0x61]);
        assert_eq!(parse_core_asm("").unwrap(), Vec::<u8>::new());
        assert_eq!(
            parse_core_asm("1000 ADD").unwrap(),
            [0x02, 0xe8, 0x03, 0x93]
        );
    }

    const NATIVE_SCRIPT_TESTS_FAILURES: usize = 0;
    const NATIVE_SCRIPT_TESTS_SKIPS: usize = 55;
    const NATIVE_SCRIPT_TESTS_EXECUTED: usize = 1233;
    const SCRIPT_TESTS_PROSE_SKIP: &str =
        "prose row (1 string element: format note or section header, no test fields)";

    // VAL-02
    #[test]
    fn script_tests_native_column() {
        let mut counts = Counts::default();
        let rows = match load_script_tests(&mut counts) {
            Ok(r) => r,
            Err(e) => panic!("script_tests.json should load: {e}"),
        };
        assert!(!rows.is_empty(), "script_tests produced zero runnable rows");

        let mismatches = run_script_tests(&rows, &mut counts, |row, credit, spend| {
            let prevouts = [credit.outputs[0].clone()];

            let result = Interpreter.execute_with_prevouts(
                &row.script_pubkey,
                &row.script_sig,
                &Witness::from_stack(row.witness.clone()),
                row.flags,
                &prevouts,
                spend,
                0,
            );
            Verdict::from_interpreter(&result)
        });
        println!("script_tests [native]: {counts}");
        assert!(
            counts.executed > 0,
            "harness executed zero script_tests rows — wiring is broken"
        );
        for m in mismatches.iter().take(mismatch_print_limit()) {
            println!("  {m}");
        }
        assert_pinned_native_column(
            &counts,
            mismatches.len(),
            NATIVE_SCRIPT_TESTS_FAILURES,
            NATIVE_SCRIPT_TESTS_SKIPS,
            NATIVE_SCRIPT_TESTS_EXECUTED,
            &[SCRIPT_TESTS_PROSE_SKIP],
            "script_tests",
        );
    }

    #[cfg(feature = "kernel")]
    const SCRIPT_TESTS_POLICY_SKIP: &str =
        "policy-only rejection: libbitcoinkernel enforces mandatory consensus flags only";

    #[cfg(feature = "kernel")]
    const KERNEL_SCRIPT_TESTS_FAILURES: usize = 0;
    #[cfg(feature = "kernel")]
    const KERNEL_SCRIPT_TESTS_SKIPS: usize = 172;
    #[cfg(feature = "kernel")]
    const KERNEL_SCRIPT_TESTS_EXECUTED: usize = 1116;

    #[cfg(feature = "kernel")]
    fn is_policy_only_script_test(row: &ScriptTestRow) -> bool {
        if row.expected == "OK" {
            return false;
        }
        if row.flags.bits() & !VerifyFlags::MANDATORY.bits() == 0 {
            return false;
        }
        let prevouts = [bitcoin_rs_consensus::primitives::TxOut {
            value: bitcoin_rs_consensus::primitives::Amount::from_sat(row.amount),
            script_pubkey: row.script_pubkey.clone().into(),
        }];
        let credit = build_crediting_tx(&row.script_pubkey, row.amount);
        let spend = build_spending_tx(&row.script_sig, &row.witness, &credit);
        let mand_flags = VerifyFlags::from_bits_retain(
            row.flags.filled().bits() & VerifyFlags::MANDATORY.bits(),
        );
        matches!(
            Interpreter.execute_with_prevouts(
                &row.script_pubkey,
                &row.script_sig,
                &Witness::from_stack(row.witness.clone()),
                mand_flags,
                &prevouts,
                &spend,
                0,
            ),
            Ok(true)
        )
    }

    #[cfg(feature = "kernel")]
    #[test]
    fn script_tests_kernel_column() {
        let mut counts = Counts::default();
        let rows = match load_script_tests(&mut counts) {
            Ok(r) => r,
            Err(e) => panic!("script_tests.json should load: {e}"),
        };
        assert!(!rows.is_empty(), "script_tests produced zero runnable rows");

        let runnable: Vec<ScriptTestRow> = rows
            .into_iter()
            .filter(|row| {
                if is_policy_only_script_test(row) {
                    counts.record_skip(SCRIPT_TESTS_POLICY_SKIP);
                    false
                } else {
                    true
                }
            })
            .collect();

        let mismatches = run_script_tests(&runnable, &mut counts, |row, credit, spend| {
            let prevouts = [(OutPoint::new(credit.txid(), 0), credit.outputs[0].clone())];

            let result = bitcoin_rs_consensus::kernel::verify_tx_scripts(
                spend,
                &prevouts,
                row.flags,
                bitcoin_rs_consensus::ValidationEngine::Kernel,
                None,
            );
            Verdict::from_kernel(&result)
        });
        println!("script_tests [kernel]: {counts}");
        assert!(
            counts.executed > 0,
            "harness executed zero script_tests rows — wiring is broken"
        );
        for m in mismatches.iter().take(mismatch_print_limit()) {
            println!("  {m}");
        }
        assert_pinned_column(
            &counts,
            mismatches.len(),
            KERNEL_SCRIPT_TESTS_FAILURES,
            KERNEL_SCRIPT_TESTS_SKIPS,
            KERNEL_SCRIPT_TESTS_EXECUTED,
            &[SCRIPT_TESTS_PROSE_SKIP, SCRIPT_TESTS_POLICY_SKIP],
            "script_tests",
            "kernel",
        );
    }

    const NATIVE_TX_VALID_FAILURES: usize = 0;
    const NATIVE_TX_VALID_SKIPS: usize = 0;
    const NATIVE_TX_VALID_EXECUTED: usize = 121;

    // VAL-02
    #[test]
    fn tx_valid_native_column() {
        let mut counts = Counts::default();
        let rows = match load_tx_vectors("tx_valid.json", true, &mut counts) {
            Ok(r) => r,
            Err(e) => panic!("tx_valid should load: {e}"),
        };
        assert!(!rows.is_empty(), "tx_valid produced zero runnable rows");

        let mismatches = run_tx_vectors(&rows, &mut counts, verify_native_tx);
        println!("tx_valid [native]: {counts}");
        assert!(counts.executed > 0, "harness executed zero tx_valid rows");
        for m in mismatches.iter().take(mismatch_print_limit()) {
            println!("  {m}");
        }
        assert_pinned_native_column(
            &counts,
            mismatches.len(),
            NATIVE_TX_VALID_FAILURES,
            NATIVE_TX_VALID_SKIPS,
            NATIVE_TX_VALID_EXECUTED,
            &[],
            "tx_valid",
        );
    }

    #[cfg(feature = "kernel")]
    const KERNEL_TX_VALID_FAILURES: usize = 0;
    #[cfg(feature = "kernel")]
    const KERNEL_TX_VALID_SKIPS: usize = 0;
    #[cfg(feature = "kernel")]
    const KERNEL_TX_VALID_EXECUTED: usize = 121;

    #[cfg(feature = "kernel")]
    #[test]
    fn tx_valid_kernel_column() {
        let mut counts = Counts::default();
        let rows = match load_tx_vectors("tx_valid.json", true, &mut counts) {
            Ok(r) => r,
            Err(e) => panic!("tx_valid should load: {e}"),
        };
        assert!(!rows.is_empty(), "tx_valid produced zero runnable rows");

        let mismatches = run_tx_vectors(&rows, &mut counts, |row| {
            let result = bitcoin_rs_consensus::kernel::verify_tx_scripts(
                &row.tx,
                &row.prevouts,
                row.flags,
                bitcoin_rs_consensus::ValidationEngine::Kernel,
                None,
            );
            Verdict::from_kernel(&result)
        });
        println!("tx_valid [kernel]: {counts}");
        assert!(counts.executed > 0, "harness executed zero tx_valid rows");
        for m in mismatches.iter().take(mismatch_print_limit()) {
            println!("  {m}");
        }
        assert_pinned_column(
            &counts,
            mismatches.len(),
            KERNEL_TX_VALID_FAILURES,
            KERNEL_TX_VALID_SKIPS,
            KERNEL_TX_VALID_EXECUTED,
            &[],
            "tx_valid",
            "kernel",
        );
    }

    const NATIVE_TX_INVALID_FAILURES: usize = 0;
    const NATIVE_TX_INVALID_SKIPS: usize = 9;
    const NATIVE_TX_INVALID_EXECUTED: usize = 84;
    const TX_INVALID_BADTX_SKIP: &str = "BADTX: fails CheckTransaction, not script verification";

    // VAL-02
    #[test]
    fn tx_invalid_native_column() {
        let mut counts = Counts::default();
        let rows = match load_tx_vectors("tx_invalid.json", false, &mut counts) {
            Ok(r) => r,
            Err(e) => panic!("tx_invalid should load: {e}"),
        };
        assert!(!rows.is_empty(), "tx_invalid produced zero runnable rows");

        let mismatches = run_tx_vectors(&rows, &mut counts, verify_native_tx);
        println!("tx_invalid [native]: {counts}");
        assert!(counts.executed > 0, "harness executed zero tx_invalid rows");
        for m in mismatches.iter().take(mismatch_print_limit()) {
            println!("  {m}");
        }
        assert_pinned_native_column(
            &counts,
            mismatches.len(),
            NATIVE_TX_INVALID_FAILURES,
            NATIVE_TX_INVALID_SKIPS,
            NATIVE_TX_INVALID_EXECUTED,
            &[TX_INVALID_BADTX_SKIP],
            "tx_invalid",
        );
    }

    #[cfg(feature = "kernel")]
    fn is_policy_only_tx_invalid(row: &TxVectorRow) -> bool {
        if row.flags.bits() & !VerifyFlags::MANDATORY.bits() == 0 {
            return false;
        }
        let mand_flags = VerifyFlags::from_bits_retain(
            row.flags.filled().bits() & VerifyFlags::MANDATORY.bits(),
        );
        let Ok(prepared) = PreparedTransaction::new(&row.tx, &row.prevouts) else {
            return false;
        };
        for input_idx in 0..row.tx.inputs.len() {
            let result = prepared.verify_input(input_idx, mand_flags, None);
            if !matches!(result, Ok(true)) {
                return false;
            }
        }
        true
    }

    #[cfg(feature = "kernel")]
    const TX_INVALID_POLICY_SKIP: &str =
        "policy-only flags: libbitcoinkernel enforces mandatory consensus flags only";
    #[cfg(feature = "kernel")]
    const KERNEL_TX_INVALID_FAILURES: usize = 0;
    #[cfg(feature = "kernel")]
    const KERNEL_TX_INVALID_SKIPS: usize = 23;
    #[cfg(feature = "kernel")]
    const KERNEL_TX_INVALID_EXECUTED: usize = 70;

    #[cfg(feature = "kernel")]
    #[test]
    fn tx_invalid_kernel_column() {
        let mut counts = Counts::default();
        let rows = match load_tx_vectors("tx_invalid.json", false, &mut counts) {
            Ok(r) => r,
            Err(e) => panic!("tx_invalid should load: {e}"),
        };
        assert!(!rows.is_empty(), "tx_invalid produced zero runnable rows");

        let runnable: Vec<TxVectorRow> = rows
            .into_iter()
            .filter(|row| {
                if is_policy_only_tx_invalid(row) {
                    counts.record_skip(TX_INVALID_POLICY_SKIP);
                    false
                } else {
                    true
                }
            })
            .collect();

        let mismatches = run_tx_vectors(&runnable, &mut counts, |row| {
            let result = bitcoin_rs_consensus::kernel::verify_tx_scripts(
                &row.tx,
                &row.prevouts,
                row.flags,
                bitcoin_rs_consensus::ValidationEngine::Kernel,
                None,
            );
            Verdict::from_kernel(&result)
        });
        println!("tx_invalid [kernel]: {counts}");
        assert!(counts.executed > 0, "harness executed zero tx_invalid rows");
        for m in mismatches.iter().take(mismatch_print_limit()) {
            println!("  {m}");
        }
        assert_pinned_column(
            &counts,
            mismatches.len(),
            KERNEL_TX_INVALID_FAILURES,
            KERNEL_TX_INVALID_SKIPS,
            KERNEL_TX_INVALID_EXECUTED,
            &[TX_INVALID_BADTX_SKIP, TX_INVALID_POLICY_SKIP],
            "tx_invalid",
            "kernel",
        );
    }

    #[cfg(feature = "kernel")]
    #[test]
    #[should_panic(expected = "kernel oracle infrastructure error:")]
    fn kernel_oracle_infrastructure_error_panics() {
        let err =
            bitcoin_rs_consensus::ConsensusError::Kernel("simulated harness failure".to_string());
        Verdict::from_kernel(&Err(err));
    }

    fn sigcache_verify_every_input(
        tx: &Tx,
        prevouts: &[(OutPoint, TxOut)],
        flags: VerifyFlags,
        cache: Option<&SignatureCache>,
    ) -> Result<bool, ScriptError> {
        let prepared = match PreparedTransaction::new(tx, prevouts) {
            Ok(prepared) => prepared,
            Err(error) => panic!("adversarial prevouts resolve: {error}"),
        };
        for input_idx in 0..tx.inputs.len() {
            let result = prepared.verify_input(input_idx, flags, cache);
            if !matches!(result, Ok(true)) {
                return result;
            }
        }
        Ok(true)
    }

    fn push_shape(script: &[u8]) -> Vec<Option<usize>> {
        instructions(script)
            .map(|instruction| match instruction {
                Ok(Instruction::PushBytes(data)) => Some(data.len()),
                _ => None,
            })
            .collect()
    }

    fn sigcache_flip_first_signature_byte(tx: &mut Tx) {
        for input in &mut tx.inputs {
            if let Some(index) = input.witness.iter().position(|item| !item.is_empty()) {
                input.witness = flip_first_byte(&input.witness, index);
                return;
            }
            if input.script_sig.as_bytes().is_empty() {
                continue;
            }
            let before = push_shape(input.script_sig.as_bytes());
            let start = {
                let bytes = input.script_sig.as_bytes();
                let mut start = None;
                for instruction in instructions(bytes) {
                    if let Ok(Instruction::PushBytes(data)) = instruction
                        && !data.is_empty()
                    {
                        start = Some(data.as_ptr().addr() - bytes.as_ptr().addr());
                        break;
                    }
                }
                start
            };
            let Some(start) = start else {
                panic!(
                    "a non-empty scriptSig without a data push carries no signature payload to flip"
                );
            };
            input.script_sig[start] ^= 0x01;
            assert_eq!(
                push_shape(input.script_sig.as_bytes()),
                before,
                "the signature flip must not reshape the scriptSig"
            );
            return;
        }
        panic!("adversarial row carries no signature bytes to flip");
    }

    fn sigcache_digest_bound_row() -> TxVectorRow {
        let mut counts = Counts::default();
        let rows = match load_tx_vectors("tx_valid.json", true, &mut counts) {
            Ok(rows) => rows,
            Err(error) => panic!("tx_valid should load: {error}"),
        };
        let found = rows.into_iter().find(|row| {
            let bound = row.tx.inputs.iter().any(|input| {
                input.witness.iter().any(|item| !item.is_empty())
                    || push_shape(input.script_sig.as_bytes())
                        .iter()
                        .any(|push| push.is_some_and(|len| len > 0))
            });
            if !bound {
                return false;
            }
            if sigcache_verify_every_input(&row.tx, &row.prevouts, row.flags, None) != Ok(true) {
                return false;
            }
            if sigcache_verify_every_input(&row.tx, &row.prevouts, VerifyFlags::MANDATORY, None)
                != Ok(true)
            {
                return false;
            }
            let mut flipped = row.tx.clone();
            sigcache_flip_first_signature_byte(&mut flipped);
            if sigcache_verify_every_input(&flipped, &row.prevouts, row.flags, None) == Ok(true) {
                return false;
            }
            let mut retargeted = row.tx.clone();
            let bumped = row.tx.lock_time.to_consensus().wrapping_add(1);
            retargeted.lock_time =
                bitcoin_rs_consensus::primitives::LockTime::from_consensus(bumped);
            sigcache_verify_every_input(&retargeted, &row.prevouts, row.flags, None) != Ok(true)
        });
        match found {
            Some(row) => row,
            None => panic!("tx_valid carries no signature-bound row broken by both mutations"),
        }
    }

    #[test]
    fn signature_cache_hit_matches_uncached_across_flags() {
        let row = sigcache_digest_bound_row();
        let cache = SignatureCache::new();
        assert_eq!(
            sigcache_verify_every_input(
                &row.tx,
                &row.prevouts,
                VerifyFlags::MANDATORY,
                Some(&cache)
            ),
            Ok(true),
            "warmup under MANDATORY"
        );
        assert_eq!(
            sigcache_verify_every_input(&row.tx, &row.prevouts, row.flags, Some(&cache)),
            Ok(true),
            "hit under row flags matches the uncached accept"
        );
        assert_eq!(
            sigcache_verify_every_input(
                &row.tx,
                &row.prevouts,
                VerifyFlags::MANDATORY,
                Some(&cache)
            ),
            Ok(true),
            "repeat hit stays accepting"
        );
    }

    #[test]
    fn signature_cache_warmed_still_rejects_bad_signature() {
        let row = sigcache_digest_bound_row();
        let cache = SignatureCache::new();
        assert_eq!(
            sigcache_verify_every_input(&row.tx, &row.prevouts, row.flags, Some(&cache)),
            Ok(true),
            "warmup"
        );
        let mut bad = row.tx.clone();
        sigcache_flip_first_signature_byte(&mut bad);
        let uncached = sigcache_verify_every_input(&bad, &row.prevouts, row.flags, None);
        assert_ne!(
            uncached,
            Ok(true),
            "selection guarantees the flip breaks verification"
        );
        assert_eq!(
            sigcache_verify_every_input(&bad, &row.prevouts, row.flags, Some(&cache)),
            uncached,
            "cached verdict matches uncached after warming"
        );
    }

    #[test]
    fn signature_cache_warmed_still_rejects_mutated_sighash_input() {
        let row = sigcache_digest_bound_row();
        let cache = SignatureCache::new();
        assert_eq!(
            sigcache_verify_every_input(&row.tx, &row.prevouts, row.flags, Some(&cache)),
            Ok(true),
            "warmup"
        );
        let mut retargeted = row.tx.clone();
        let bumped = row.tx.lock_time.to_consensus().wrapping_add(1);
        retargeted.lock_time = bitcoin_rs_consensus::primitives::LockTime::from_consensus(bumped);
        let uncached = sigcache_verify_every_input(&retargeted, &row.prevouts, row.flags, None);
        assert_ne!(
            uncached,
            Ok(true),
            "selection guarantees the retarget breaks verification"
        );
        assert_eq!(
            sigcache_verify_every_input(&retargeted, &row.prevouts, row.flags, Some(&cache)),
            uncached,
            "cached verdict matches uncached after warming"
        );
    }

    fn sigcache_p2wpkh_s_twins() -> (Tx, Tx, Vec<(OutPoint, TxOut)>) {
        use bitcoin_hashes::hash160;
        use bitcoin_rs_consensus::primitives::{Hash256, Sighash, SighashCache};
        use secp256k1::{Message, PublicKey, SecretKey, ecdsa};

        let secret = match SecretKey::from_secret_bytes([11; 32]) {
            Ok(secret) => secret,
            Err(error) => panic!("fixed ecdsa secret: {error}"),
        };
        let pubkey = PublicKey::from_secret_key(&secret).serialize().to_vec();
        let program_digest = hash160::Hash::hash(&pubkey);
        let mut program = Vec::with_capacity(22);
        program.push(0x00);
        program.push(0x14);
        program.extend_from_slice(program_digest.as_byte_array());
        let mut code = Vec::with_capacity(25);
        code.push(0x76);
        code.push(0xa9);
        code.push(0x14);
        code.extend_from_slice(program_digest.as_byte_array());
        code.push(0x88);
        code.push(0xac);

        let mut txid_bytes = [0u8; 32];
        txid_bytes[0] = 0x51;
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&txid_bytes)), 0);
        let tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
        };
        let prevout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(program),
        };
        let digest = match SighashCache::new(&tx).segwit_v0_signature_hash(
            0,
            &code,
            prevout.value,
            Sighash::All,
        ) {
            Ok(digest) => digest,
            Err(error) => panic!("bip143 digest: {error}"),
        };
        let mut low = ecdsa::sign(Message::from_digest(*digest.as_byte_array()), &secret);
        low.normalize_s();
        let mut low_bytes = low.serialize_der().to_vec();
        low_bytes.push(0x01);

        let compact = low.serialize_compact();
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&compact[32..]);
        let high_s = match SecretKey::from_secret_bytes(scalar) {
            Ok(s) => s,
            Err(error) => panic!("low-S s scalar: {error}"),
        }
        .negate()
        .to_secret_bytes();
        let mut twin = [0u8; 64];
        twin[..32].copy_from_slice(&compact[..32]);
        twin[32..].copy_from_slice(&high_s);
        let high = match ecdsa::Signature::from_compact(&twin) {
            Ok(high) => high,
            Err(error) => panic!("high-S compact: {error}"),
        };
        let mut high_bytes = high.serialize_der().to_vec();
        high_bytes.push(0x01);
        assert_ne!(high_bytes, low_bytes, "twins must differ in s");

        let rows = vec![(outpoint, prevout)];
        let mut low_tx = tx.clone();
        low_tx.inputs[0].witness = vec![low_bytes, pubkey.clone()].into();
        let mut high_tx = tx;
        high_tx.inputs[0].witness = vec![high_bytes, pubkey].into();
        (low_tx, high_tx, rows)
    }

    #[test]
    fn signature_cache_policy_encoding_still_rejected_after_permissive_success() {
        let (low_tx, high_tx, rows) = sigcache_p2wpkh_s_twins();
        let strict = VerifyFlags::MANDATORY.union(VerifyFlags::LOW_S);
        let low_prepared = match PreparedTransaction::new(&low_tx, &rows) {
            Ok(prepared) => prepared,
            Err(error) => panic!("low-S prevouts resolve: {error}"),
        };
        assert_eq!(
            low_prepared.verify_input(0, VerifyFlags::MANDATORY, None),
            Ok(true),
            "low-S consensus-valid"
        );
        assert_eq!(
            low_prepared.verify_input(0, strict, None),
            Ok(true),
            "low-S policy-clean"
        );

        let cache = SignatureCache::new();
        let high_prepared = match PreparedTransaction::new(&high_tx, &rows) {
            Ok(prepared) => prepared,
            Err(error) => panic!("high-S prevouts resolve: {error}"),
        };
        assert_eq!(
            high_prepared.verify_input(0, VerifyFlags::MANDATORY, Some(&cache)),
            Ok(true),
            "permissive warmup succeeds and caches the group operation"
        );
        assert_eq!(
            high_prepared.verify_input(0, strict, Some(&cache)),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::SigHighS
            }),
            "high-S rejection survives a permissive cached success"
        );
    }

    fn flip_first_byte(witness: &Witness, item: usize) -> Witness {
        let mut stack: Vec<Vec<u8>> = witness.iter().map(<[u8]>::to_vec).collect();
        stack[item][0] ^= 0x01;
        Witness::from_stack(stack)
    }
}
mod script_ecdsa_encoding_order {
    #![expect(clippy::expect_used, reason = "fixed regression fixtures")]

    use bitcoin_rs_consensus::primitives::{Amount, Script, Tx, TxOut, Witness, deserialize};
    use bitcoin_rs_consensus::script::{Interpreter, ScriptErrCode, ScriptError, VerifyFlags};
    use secp256k1::{PublicKey, SecretKey};
    use sha2::{Digest, Sha256};

    const TX_HEX: &str = concat!(
        "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f",
        "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57",
        "b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85",
        "c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2",
        "f0167faa815988ac11000000",
    );
    const TEST_KEY: &str = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9";
    const VALUE: u64 = 600_000_000;
    const INPUT: usize = 1;

    fn hex(text: &str) -> Vec<u8> {
        bitcoin::hex::FromHex::from_hex(text).expect("valid fixture hex")
    }

    fn fixture() -> Tx {
        deserialize(&hex(TX_HEX)).expect("native fixture decode")
    }

    fn test_key() -> SecretKey {
        SecretKey::from_secret_bytes(hex(TEST_KEY).try_into().expect("32-byte test key"))
            .expect("public BIP143 test key")
    }

    fn verify_witness(
        tx: &Tx,
        prevout: &TxOut,
        witness: &[Vec<u8>],
        flags: VerifyFlags,
    ) -> Result<bool, ScriptError> {
        let prevouts = vec![prevout.clone(); tx.inputs.len()];
        Interpreter.execute_with_prevouts(
            &prevout.script_pubkey,
            &[],
            &Witness::from_stack(witness.to_vec()),
            flags,
            &prevouts,
            tx,
            INPUT,
        )
    }

    #[derive(Clone, Copy, Debug)]
    enum Lane {
        Base,
        WitnessV0,
    }

    fn check_via_script(
        tx: &Tx,
        key: &[u8],
        sig: &[u8],
        lane: Lane,
        flags: VerifyFlags,
    ) -> Result<bool, ScriptError> {
        assert!(key.len() <= 75);
        let mut script = Vec::with_capacity(key.len() + 3);
        script.push(u8::try_from(key.len()).expect("short test pubkey"));
        script.extend_from_slice(key);
        script.push(0xac);
        script.push(0x91);
        let (script_pubkey, script_sig, witness, effective_flags) = match lane {
            Lane::Base => {
                let mut script_sig = Vec::with_capacity(sig.len() + 1);
                script_sig.push(u8::try_from(sig.len()).expect("short test signature"));
                script_sig.extend_from_slice(sig);
                (script, script_sig, Vec::new(), flags)
            }
            Lane::WitnessV0 => {
                let mut program = vec![0x00, 0x20];
                program.extend_from_slice(&Sha256::digest(&script));
                (
                    program,
                    Vec::new(),
                    vec![sig.to_vec(), script],
                    flags.union(VerifyFlags::WITNESS),
                )
            }
        };
        let prevout = TxOut {
            value: Amount::from_sat(VALUE),
            script_pubkey: Script::from_bytes(script_pubkey),
        };
        let prevouts = vec![prevout.clone(); tx.inputs.len()];
        Interpreter.execute_with_prevouts(
            &prevout.script_pubkey,
            &script_sig,
            &Witness::from_stack(witness),
            effective_flags,
            &prevouts,
            tx,
            INPUT,
        )
    }

    fn negative_checksig_script(pubkey: &[u8]) -> Vec<u8> {
        assert!(pubkey.len() <= 75);
        let mut script = Vec::new();
        script.push(u8::try_from(pubkey.len()).expect("short test pubkey"));
        script.extend_from_slice(pubkey);
        script.push(0xac);
        script.push(0x91);
        script
    }

    fn negative_multisig_script(pubkey: &[u8]) -> Vec<u8> {
        assert!(pubkey.len() <= 75);
        let mut script = Vec::new();
        script.push(0x51);
        script.push(u8::try_from(pubkey.len()).expect("short test pubkey"));
        script.extend_from_slice(pubkey);
        script.push(0x51);
        script.push(0xae);
        script.push(0x91);
        script
    }

    #[test]
    fn empty_signature_cannot_bypass_key_encoding_policy() {
        let tx = fixture();
        let uncompressed = PublicKey::from_secret_key(&test_key()).serialize_uncompressed();
        let cases = [
            (
                Vec::new(),
                VerifyFlags::STRICTENC,
                ScriptErrCode::PubkeyType,
                false,
            ),
            (
                uncompressed.to_vec(),
                VerifyFlags::WITNESS_PUBKEYTYPE,
                ScriptErrCode::WitnessPubkeyType,
                true,
            ),
        ];
        for (key, policy, code, witness) in cases {
            for (multisig, script) in [
                (false, negative_checksig_script(&key)),
                (true, negative_multisig_script(&key)),
            ] {
                let mut witness_stack = vec![Vec::new()];
                if multisig {
                    witness_stack.push(Vec::new());
                }
                witness_stack.push(script.clone());
                let script_sig = if multisig {
                    vec![0x00, 0x00]
                } else {
                    vec![0x00]
                };
                let baseline = if witness {
                    VerifyFlags::MANDATORY
                } else {
                    VerifyFlags::NONE
                };
                let run = |flags: VerifyFlags| {
                    if witness {
                        let mut program = vec![0x00, 0x20];
                        program.extend_from_slice(&Sha256::digest(&script));
                        let prevout = TxOut {
                            value: Amount::from_sat(VALUE),
                            script_pubkey: Script::from_bytes(program),
                        };
                        verify_witness(&tx, &prevout, &witness_stack, flags)
                    } else {
                        let prevout = TxOut {
                            value: Amount::from_sat(VALUE),
                            script_pubkey: Script::from_bytes(script.clone()),
                        };
                        let prevouts = vec![prevout; tx.inputs.len()];
                        Interpreter.execute_with_prevouts(
                            &script,
                            &script_sig,
                            &Witness::new(),
                            flags,
                            &prevouts,
                            &tx,
                            INPUT,
                        )
                    }
                };
                assert_eq!(run(baseline), Ok(true), "multisig={multisig}, {code:?}");
                assert_eq!(
                    run(baseline.union(policy)),
                    Err(ScriptError::Invalid { code }),
                    "multisig={multisig}, {code:?}",
                );
            }
        }
    }

    #[test]
    fn encoding_error_precedence_matches_core() {
        let tx = fixture();
        for lane in [Lane::Base, Lane::WitnessV0] {
            assert_eq!(
                check_via_script(&tx, &[], &[], lane, VerifyFlags::DERSIG),
                Ok(true),
            );
            assert_eq!(
                check_via_script(&tx, &[], &[], lane, VerifyFlags::STRICTENC),
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::PubkeyType,
                }),
            );
            assert_eq!(
                check_via_script(&tx, &[], &[0], lane, VerifyFlags::STRICTENC),
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::SigDer,
                }),
            );
        }
        let flags = VerifyFlags::STRICTENC.union(VerifyFlags::WITNESS_PUBKEYTYPE);
        assert_eq!(
            check_via_script(&tx, &[], &[], Lane::WitnessV0, flags),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::PubkeyType,
            }),
        );
    }

    #[test]
    fn empty_signature_policy_matrix_preserves_error_order_and_clean_false() {
        let tx = fixture();
        let public = PublicKey::from_secret_key(&test_key());
        let mut off_curve = vec![0xff; 33];
        off_curve[0] = 0x02;
        let keys = [
            (Vec::new(), false, false),
            (vec![0x05; 33], false, false),
            (vec![0x02; 32], false, false),
            (vec![0x02; 65], false, false),
            (public.serialize().to_vec(), true, true),
            (public.serialize_uncompressed().to_vec(), true, false),
            (off_curve, true, true),
        ];
        let policies = [
            VerifyFlags::DERSIG,
            VerifyFlags::LOW_S,
            VerifyFlags::STRICTENC,
            VerifyFlags::WITNESS_PUBKEYTYPE,
            VerifyFlags::NULLFAIL,
            VerifyFlags::NULLDUMMY,
        ];
        for mask in 0..(1_u32 << policies.len()) {
            let mut flags = VerifyFlags::NONE;
            for (index, policy) in policies.iter().enumerate() {
                if mask & (1 << index) != 0 {
                    flags = flags.union(*policy);
                }
            }
            for lane in [Lane::Base, Lane::WitnessV0] {
                for (key, strict_valid, compressed) in &keys {
                    let expected = if flags.contains(VerifyFlags::STRICTENC) && !strict_valid {
                        Err(ScriptError::Invalid {
                            code: ScriptErrCode::PubkeyType,
                        })
                    } else if matches!(lane, Lane::WitnessV0)
                        && flags.contains(VerifyFlags::WITNESS_PUBKEYTYPE)
                        && !compressed
                    {
                        Err(ScriptError::Invalid {
                            code: ScriptErrCode::WitnessPubkeyType,
                        })
                    } else {
                        Ok(true)
                    };
                    assert_eq!(
                        check_via_script(&tx, key, &[], lane, flags),
                        expected,
                        "mask={mask:#x}, lane={lane:?}, key={key:?}",
                    );
                    if flags.contains(VerifyFlags::DERSIG)
                        || flags.contains(VerifyFlags::LOW_S)
                        || flags.contains(VerifyFlags::STRICTENC)
                    {
                        assert_eq!(
                            check_via_script(&tx, key, &[0], lane, flags),
                            Err(ScriptError::Invalid {
                                code: ScriptErrCode::SigDer,
                            }),
                            "mask={mask:#x}, lane={lane:?}, key={key:?}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn zero_signature_multisig_does_not_validate_unexamined_keys() {
        let tx = fixture();
        let script = vec![0x00, 0x00, 0x51, 0xae];
        let flags = VerifyFlags::MANDATORY
            .union(VerifyFlags::STRICTENC)
            .union(VerifyFlags::WITNESS_PUBKEYTYPE)
            .union(VerifyFlags::NULLFAIL);
        let legacy_prevout = TxOut {
            value: Amount::from_sat(VALUE),
            script_pubkey: Script::from_bytes(script.clone()),
        };
        let legacy_prevouts = vec![legacy_prevout; tx.inputs.len()];
        assert_eq!(
            Interpreter.execute_with_prevouts(
                &script,
                &[0x00],
                &Witness::new(),
                flags,
                &legacy_prevouts,
                &tx,
                INPUT,
            ),
            Ok(true),
        );
        let mut program = vec![0x00, 0x20];
        program.extend_from_slice(&Sha256::digest(&script));
        let witness_prevout = TxOut {
            value: Amount::from_sat(VALUE),
            script_pubkey: Script::from_bytes(program),
        };
        let witness_prevouts = vec![witness_prevout.clone(); tx.inputs.len()];
        assert_eq!(
            Interpreter.execute_with_prevouts(
                &witness_prevout.script_pubkey,
                &[],
                &Witness::from_stack(vec![Vec::new(), script]),
                flags,
                &witness_prevouts,
                &tx,
                INPUT,
            ),
            Ok(true),
        );
    }
}
mod script_proptest {
    use bitcoin::hashes::Hash as _;
    use bitcoin::script::Builder;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::{
        Amount as OracleAmount, OutPoint, ScriptBuf, Sequence as OracleSequence, Transaction, TxIn,
        TxOut as OracleTxOut, Txid, Witness as OracleWitness, absolute, transaction,
    };
    use bitcoin_rs_consensus::primitives::{Tx, TxOut};
    use bitcoin_rs_consensus::script::{Interpreter, ScriptErrCode, ScriptError, VerifyFlags};
    use proptest::prelude::*;

    fn to_native(tx: &Transaction) -> Tx {
        let bytes = bitcoin::consensus::serialize(tx);
        bitcoin_rs_consensus::primitives::deserialize(&bytes)
            .unwrap_or_else(|error| panic!("oracle transaction must decode natively: {error}"))
    }

    fn to_native_prevout(prevout: &OracleTxOut) -> TxOut {
        TxOut {
            value: bitcoin_rs_consensus::primitives::Amount::from_sat(prevout.value.to_sat()),
            script_pubkey: prevout.script_pubkey.as_bytes().to_vec().into(),
        }
    }

    fn proptest_config(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|val| val.parse().ok())
            .unwrap_or(default_cases);
        ProptestConfig {
            cases,
            ..ProptestConfig::default()
        }
    }

    fn sighash_type_strategy() -> impl Strategy<Value = TapSighashType> {
        prop_oneof![
            Just(TapSighashType::Default),
            Just(TapSighashType::All),
            Just(TapSighashType::None),
            Just(TapSighashType::Single),
            Just(TapSighashType::AllPlusAnyoneCanPay),
            Just(TapSighashType::NonePlusAnyoneCanPay),
            Just(TapSighashType::SinglePlusAnyoneCanPay),
        ]
    }

    fn valid_secret_key_strategy() -> impl Strategy<Value = SecretKey> {
        (1u8..=250u8).prop_filter_map("valid key", secret_key)
    }

    fn taproot_sighash_byte(sighash_type: TapSighashType) -> u8 {
        match sighash_type {
            TapSighashType::Default => 0x00,
            TapSighashType::All => 0x01,
            TapSighashType::None => 0x02,
            TapSighashType::Single => 0x03,
            TapSighashType::AllPlusAnyoneCanPay => 0x81,
            TapSighashType::NonePlusAnyoneCanPay => 0x82,
            TapSighashType::SinglePlusAnyoneCanPay => 0x83,
        }
    }

    fn serialize_taproot_signature(
        sig: bitcoin::secp256k1::schnorr::Signature,
        sighash_type: TapSighashType,
    ) -> Vec<u8> {
        let mut bytes = sig.serialize().to_vec();
        if sighash_type != TapSighashType::Default {
            bytes.push(taproot_sighash_byte(sighash_type));
        }
        bytes
    }

    struct MultiInputFixture {
        tx: Tx,
        prevouts: Vec<TxOut>,
    }

    fn signed_multi_input_p2tr_with_types(
        keys: &[SecretKey],
        sighash_types: &[TapSighashType],
    ) -> MultiInputFixture {
        let secp = Secp256k1::new();
        let mut keypairs = Vec::with_capacity(keys.len());
        let mut oracle_prevouts = Vec::with_capacity(keys.len());
        for secret in keys {
            let keypair = Keypair::from_secret_key(&secp, secret);
            let tweaked = bitcoin::key::TapTweak::tap_tweak(keypair, &secp, None);
            let (output_key, _) = tweaked.public_parts();
            oracle_prevouts.push(OracleTxOut {
                value: OracleAmount::from_sat(50_000),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(output_key),
            });
            keypairs.push(tweaked);
        }

        let mut tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: keys
                .iter()
                .enumerate()
                .map(|(index, secret)| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array(secret.secret_bytes()),
                        vout: u32::try_from(index).unwrap_or(0),
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: OracleSequence::MAX,
                    witness: OracleWitness::new(),
                })
                .collect(),
            output: vec![
                OracleTxOut {
                    value: OracleAmount::from_sat(40_000),
                    script_pubkey: Builder::new().push_int(1).into_script(),
                },
                OracleTxOut {
                    value: OracleAmount::from_sat(40_000),
                    script_pubkey: Builder::new().push_int(2).into_script(),
                },
                OracleTxOut {
                    value: OracleAmount::from_sat(10_000),
                    script_pubkey: Builder::new().push_int(3).into_script(),
                },
            ],
        };

        for (input_idx, keypair) in keypairs.iter().enumerate() {
            let sighash_type = sighash_types
                .get(input_idx)
                .copied()
                .unwrap_or(TapSighashType::Default);
            let mut cache = SighashCache::new(&tx);
            let sighash = match cache.taproot_key_spend_signature_hash(
                input_idx,
                &Prevouts::All(&oracle_prevouts),
                sighash_type,
            ) {
                Ok(hash) => hash,
                Err(err) => panic!("oracle taproot sighash failed: {err}"),
            };
            let message = Message::from_digest(*sighash.as_byte_array());
            let signature = secp.sign_schnorr(&message, keypair.as_keypair());
            let sig_bytes = serialize_taproot_signature(signature, sighash_type);
            tx.input[input_idx].witness = OracleWitness::from_slice(&[sig_bytes]);
        }

        let native_prevouts = oracle_prevouts.iter().map(to_native_prevout).collect();
        MultiInputFixture {
            tx: to_native(&tx),
            prevouts: native_prevouts,
        }
    }

    proptest! {
    #![proptest_config(proptest::test_runner::Config {
        failure_persistence: Some(std::boxed::Box::new(
            proptest::test_runner::FileFailurePersistence::Direct(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/consensus/regressions/script_proptest.txt"
            )),
        )),
        ..(proptest_config(256))
    })]

        #[test]
        fn offensive_p2tr_keypath_spends_execute_with_diverse_sighash_and_inputs(
            keys in prop::collection::vec(valid_secret_key_strategy(), 1..=3),
            sighash_types in prop::collection::vec(sighash_type_strategy(), 1..=3),
            use_standard_flags in any::<bool>(),
        ) {
            let fixture = signed_multi_input_p2tr_with_types(&keys, &sighash_types);
            let interpreter = Interpreter;
            let flags = if use_standard_flags {
                VerifyFlags::STANDARD
            } else {
                VerifyFlags::MANDATORY
            };

            for (input_idx, input) in fixture.tx.inputs.iter().enumerate() {
                let prevout = &fixture.prevouts[input_idx];
                let ok = interpreter.execute_with_prevouts(
                    &prevout.script_pubkey,
                    &input.script_sig,
                    &input.witness,
                    flags,
                    &fixture.prevouts,
                    &fixture.tx,
                    input_idx,
                );
                prop_assert_eq!(ok, Ok(true));
            }
        }

        #[test]
        fn offensive_p2tr_keypath_spends_refuse_corrupted_witnesses(
            key in valid_secret_key_strategy(),
            sighash_type in sighash_type_strategy(),
            corruption_mode in 0u8..=7u8,
            extra_bytes in prop::collection::vec(any::<u8>(), 0..=80),
        ) {
            let fixture = signed_multi_input_p2tr_with_types(&[key], &[sighash_type]);
            let interpreter = Interpreter;
            let input = &fixture.tx.inputs[0];
            let prevout = &fixture.prevouts[0];

            let mut mutated_witness = input.witness.clone();
            let mut mutated_script_sig = input.script_sig.clone();
            let expected_code = match corruption_mode {
                0 => {
                    mutated_witness.clear();
                    ScriptErrCode::WitnessProgramWitnessEmpty
                }
                1 => {
                    mutated_witness.clear();
                    mutated_witness.push(&[]);
                    ScriptErrCode::SchnorrSigSize
                }
                2 => {
                    let sig = &input.witness[0];
                    let truncated = &sig[..sig.len().saturating_sub(2).min(63)];
                    mutated_witness.clear();
                    mutated_witness.push(truncated);
                    ScriptErrCode::SchnorrSigSize
                }
                3 => {
                    let mut overlong = input.witness[0].to_vec();
                    overlong.extend_from_slice(&[0x01, 0x02]);
                    mutated_witness.clear();
                    mutated_witness.push(&overlong);
                    ScriptErrCode::SchnorrSigSize
                }
                4 => {
                    let mut bad_hashtype = input.witness[0][..64].to_vec();
                    bad_hashtype.push(0x00);
                    mutated_witness.clear();
                    mutated_witness.push(&bad_hashtype);
                    ScriptErrCode::SchnorrSigHashtype
                }
                5 => {
                    let mut bad_hashtype = input.witness[0][..64].to_vec();
                    bad_hashtype.push(0x04);
                    mutated_witness.clear();
                    mutated_witness.push(&bad_hashtype);
                    ScriptErrCode::SchnorrSigHashtype
                }
                6 => {
                    let mut corrupted_sig = input.witness[0].to_vec();
                    corrupted_sig[0] ^= 0xff;
                    mutated_witness.clear();
                    mutated_witness.push(&corrupted_sig);
                    ScriptErrCode::SchnorrSig
                }
                _ => {
                    mutated_script_sig = bitcoin_rs_consensus::primitives::Script::from_bytes(vec![0x51]);
                    ScriptErrCode::WitnessMalleated
                }
            };

            let result = interpreter.execute_with_prevouts(
                &prevout.script_pubkey,
                &mutated_script_sig,
                &mutated_witness,
                VerifyFlags::MANDATORY,
                &fixture.prevouts,
                &fixture.tx,
                0,
            );
            prop_assert_eq!(
                result,
                Err(ScriptError::Invalid { code: expected_code }),
                "corruption_mode={}",
                corruption_mode
            );

            let mut extra_witness = input.witness.clone();
            extra_witness.push(&extra_bytes);
            let extra_result = interpreter.execute_with_prevouts(
                &prevout.script_pubkey,
                &input.script_sig,
                &extra_witness,
                VerifyFlags::MANDATORY,
                &fixture.prevouts,
                &fixture.tx,
                0,
            );
            prop_assert!(
                matches!(
                    extra_result,
                    Err(ScriptError::Invalid {
                        code: ScriptErrCode::TaprootWrongControlSize
                            | ScriptErrCode::WitnessProgramMismatch
                            | ScriptErrCode::WitnessProgramWitnessEmpty
                            | ScriptErrCode::SchnorrSig,
                    })
                ),
                "expected extra witness rejection, got {extra_result:?}"
            );
        }
    }

    fn secret_key(byte: u8) -> Option<SecretKey> {
        SecretKey::from_slice(&[byte; 32]).ok()
    }
}
mod script_segwit_v0_sighash_edges {
    #![expect(clippy::expect_used, reason = "fixed regression fixtures")]

    use bitcoin::consensus::{deserialize as oracle_decode, encode::VarInt, serialize};
    use bitcoin_rs_consensus::primitives::{
        Amount, Script, Sighash, SighashCache, SighashError, Tx, TxOut, Witness, deserialize,
    };
    use bitcoin_rs_consensus::script::{Interpreter, ScriptErrCode, ScriptError, VerifyFlags};
    use secp256k1::{Message, PublicKey, SecretKey};
    use sha2::{Digest, Sha256};

    const TX_HEX: &str = concat!(
        "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f",
        "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57",
        "b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85",
        "c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2",
        "f0167faa815988ac11000000",
    );
    const TEST_KEY: &str = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9";
    const SCRIPT_CODE: &str = "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac";
    const PROGRAM: &str = "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1";
    const VALUE: u64 = 600_000_000;
    const INPUT: usize = 1;

    fn hex(text: &str) -> Vec<u8> {
        bitcoin::hex::FromHex::from_hex(text).expect("valid fixture hex")
    }

    fn fixture(outputs: usize) -> (Tx, bitcoin::Transaction) {
        let bytes = hex(TX_HEX);
        let mut native: Tx = deserialize(&bytes).expect("native fixture decode");
        let mut oracle: bitcoin::Transaction =
            oracle_decode(&bytes).expect("oracle fixture decode");
        native.outputs.truncate(outputs);
        oracle.output.truncate(outputs);
        (native, oracle)
    }

    fn double_sha256(bytes: &[u8]) -> [u8; 32] {
        bitcoin_rs_consensus::primitives::encode::double_sha256(bytes).to_le_bytes()
    }

    fn reference_bip143(
        tx: &bitcoin::Transaction,
        input: usize,
        script: &[u8],
        value: u64,
        raw: u32,
    ) -> [u8; 32] {
        let anyone = raw & 0x80 != 0;
        let base = raw & 0x1f;
        let mut prevouts = [0_u8; 32];
        let mut sequences = [0_u8; 32];
        let mut outputs = [0_u8; 32];
        if !anyone {
            let bytes: Vec<u8> = tx
                .input
                .iter()
                .flat_map(|input| serialize(&input.previous_output))
                .collect();
            prevouts = double_sha256(&bytes);
        }
        if !anyone && base != 2 && base != 3 {
            let bytes: Vec<u8> = tx
                .input
                .iter()
                .flat_map(|input| serialize(&input.sequence))
                .collect();
            sequences = double_sha256(&bytes);
        }
        if base != 2 && base != 3 {
            let bytes: Vec<u8> = tx.output.iter().flat_map(serialize).collect();
            outputs = double_sha256(&bytes);
        } else if base == 3 {
            if let Some(output) = tx.output.get(input) {
                outputs = double_sha256(&serialize(output));
            }
        }
        let selected = &tx.input[input];
        let mut preimage = serialize(&tx.version);
        preimage.extend_from_slice(&prevouts);
        preimage.extend_from_slice(&sequences);
        preimage.extend(serialize(&selected.previous_output));
        let script_len = u64::try_from(script.len()).expect("script length");
        preimage.extend(serialize(&VarInt(script_len)));
        preimage.extend_from_slice(script);
        preimage.extend_from_slice(&value.to_le_bytes());
        preimage.extend(serialize(&selected.sequence));
        preimage.extend_from_slice(&outputs);
        preimage.extend(serialize(&tx.lock_time));
        preimage.extend_from_slice(&raw.to_le_bytes());
        double_sha256(&preimage)
    }

    fn test_key() -> SecretKey {
        SecretKey::from_secret_bytes(hex(TEST_KEY).try_into().expect("32-byte test key"))
            .expect("public BIP143 test key")
    }

    fn p2wpkh_prevout() -> TxOut {
        TxOut {
            value: Amount::from_sat(VALUE),
            script_pubkey: Script::from_bytes(hex(PROGRAM)),
        }
    }

    fn verify_witness(
        tx: &Tx,
        prevout: &TxOut,
        witness: &[Vec<u8>],
        flags: VerifyFlags,
    ) -> Result<bool, ScriptError> {
        let prevouts = vec![prevout.clone(); tx.inputs.len()];
        Interpreter.execute_with_prevouts(
            &prevout.script_pubkey,
            &[],
            &Witness::from_stack(witness.to_vec()),
            flags,
            &prevouts,
            tx,
            INPUT,
        )
    }

    #[cfg(feature = "kernel")]
    fn kernel_witness_parity(tx: &Tx, prevout: &TxOut, witness: &[Vec<u8>]) {
        use bitcoin_rs_consensus::{ConsensusError, kernel::verify_tx_scripts};

        let mut signed = tx.clone();
        signed.inputs[INPUT].witness = witness.to_vec().into();
        let mut spent: Vec<_> = signed
            .inputs
            .iter()
            .enumerate()
            .map(|(index, input)| {
                let output = if index == INPUT {
                    prevout.clone()
                } else {
                    TxOut {
                        value: Amount::from_sat(VALUE),
                        script_pubkey: vec![0x51].into(),
                    }
                };
                (input.previous_output, output)
            })
            .collect();
        verify_tx_scripts(
            &signed,
            &spent,
            VerifyFlags::MANDATORY,
            bitcoin_rs_consensus::ValidationEngine::Kernel,
            None,
        )
        .expect("kernel accepts independently signed BIP143 input");
        spent[INPUT].1.value = spent[INPUT].1.value.saturating_add(Amount::from_sat(1));
        assert!(matches!(
            verify_tx_scripts(
                &signed,
                &spent,
                VerifyFlags::MANDATORY,
                bitcoin_rs_consensus::ValidationEngine::Kernel,
                None,
            ),
            Err(ConsensusError::Script {
                input_index: INPUT,
                ..
            })
        ));
    }

    #[test]
    fn published_bip143_digest_and_signature_anchor_reference() {
        let (tx, oracle) = fixture(2);
        let script = hex(SCRIPT_CODE);
        let expected = hex("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
        assert_eq!(
            reference_bip143(&oracle, INPUT, &script, VALUE, 1).as_slice(),
            expected,
        );
        let cache = SighashCache::new(&tx);
        assert_eq!(
            cache
                .segwit_v0_signature_hash_raw(INPUT, &script, Amount::from_sat(VALUE), 1)
                .expect("BIP143 digest")
                .as_byte_array()
                .as_slice(),
            expected,
        );
        let witness = vec![
            hex(concat!(
                "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a",
                "0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01",
            )),
            hex("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"),
        ];
        assert_eq!(
            verify_witness(&tx, &p2wpkh_prevout(), &witness, VerifyFlags::MANDATORY),
            Ok(true),
        );
    }

    #[test]
    fn every_segwit_hashtype_byte_matches_reference_and_verifies() {
        let key = test_key();
        let pubkey = PublicKey::from_secret_key(&key).serialize().to_vec();
        let script = hex(SCRIPT_CODE);
        let prevout = p2wpkh_prevout();
        for output_count in [1, 2] {
            let (tx, oracle) = fixture(output_count);
            let cache = SighashCache::new(&tx);
            for byte in 0_u8..=u8::MAX {
                let raw = u32::from(byte);
                let expected = reference_bip143(&oracle, INPUT, &script, VALUE, raw);
                assert_eq!(
                    cache
                        .segwit_v0_signature_hash_raw(INPUT, &script, Amount::from_sat(VALUE), raw)
                        .expect("raw BIP143 digest")
                        .as_byte_array(),
                    &expected,
                    "outputs={output_count}, raw={raw:#x}",
                );
                let message = Message::from_digest(expected);
                let mut signature = secp256k1::ecdsa::sign(message, &key)
                    .serialize_der()
                    .to_vec();
                signature.push(byte);
                let witness = vec![signature, pubkey.clone()];
                assert_eq!(
                    verify_witness(&tx, &prevout, &witness, VerifyFlags::MANDATORY),
                    Ok(true),
                    "consensus: outputs={output_count}, raw={raw:#x}",
                );
                let mut wrong_amount = prevout.clone();
                wrong_amount.value = Amount::from_sat(wrong_amount.value.to_sat() + 1);
                assert_eq!(
                    verify_witness(&tx, &wrong_amount, &witness, VerifyFlags::MANDATORY),
                    Err(ScriptError::Invalid {
                        code: ScriptErrCode::EvalFalse,
                    }),
                    "amount commitment: outputs={output_count}, raw={raw:#x}",
                );
                #[cfg(feature = "kernel")]
                kernel_witness_parity(&tx, &prevout, &witness);
                let strict = VerifyFlags::MANDATORY.union(VerifyFlags::STRICTENC);
                let result = verify_witness(&tx, &prevout, &witness, strict);
                if matches!(byte, 1 | 2 | 3 | 0x81 | 0x82 | 0x83) {
                    assert_eq!(result, Ok(true));
                } else {
                    assert_eq!(
                        result,
                        Err(ScriptError::Invalid {
                            code: ScriptErrCode::SigHashtype,
                        }),
                    );
                }
            }
        }
    }

    #[test]
    fn raw_segwit_hash_commits_all_32_bits_and_checks_input_bounds() {
        let script = hex(SCRIPT_CODE);
        for output_count in [1, 2] {
            let (tx, oracle) = fixture(output_count);
            let cache = SighashCache::new(&tx);
            for raw in [0x100, 0x101, 0x1234_5682, 0x8000_0083, u32::MAX] {
                let expected = reference_bip143(&oracle, INPUT, &script, VALUE, raw);
                let actual = cache
                    .segwit_v0_signature_hash_raw(INPUT, &script, Amount::from_sat(VALUE), raw)
                    .expect("raw u32 digest");
                assert_eq!(actual.as_byte_array(), &expected);
                assert_ne!(
                    actual.as_byte_array(),
                    &reference_bip143(&oracle, INPUT, &script, VALUE, raw & 0xff),
                );
            }
            assert_eq!(
                cache.segwit_v0_signature_hash_raw(
                    tx.inputs.len(),
                    &script,
                    Amount::from_sat(VALUE),
                    0
                ),
                Err(SighashError::InputOutOfRange {
                    index: tx.inputs.len(),
                    total: tx.inputs.len(),
                }),
            );
        }
    }

    #[test]
    fn typed_segwit_api_preserves_named_modes_and_default_rejection() {
        let script = hex(SCRIPT_CODE);
        let modes = [
            (Sighash::All, 1),
            (Sighash::None, 2),
            (Sighash::Single, 3),
            (Sighash::AllAnyoneCanPay, 0x81),
            (Sighash::NoneAnyoneCanPay, 0x82),
            (Sighash::SingleAnyoneCanPay, 0x83),
        ];
        for output_count in [1, 2] {
            let (tx, oracle) = fixture(output_count);
            let cache = SighashCache::new(&tx);
            for (mode, raw) in modes {
                assert_eq!(
                    cache
                        .segwit_v0_signature_hash(INPUT, &script, Amount::from_sat(VALUE), mode)
                        .expect("named mode")
                        .as_byte_array(),
                    &reference_bip143(&oracle, INPUT, &script, VALUE, raw),
                );
            }
            for input in [INPUT, tx.inputs.len()] {
                assert_eq!(
                    cache.segwit_v0_signature_hash(
                        input,
                        &script,
                        Amount::from_sat(VALUE),
                        Sighash::Default
                    ),
                    Err(SighashError::DefaultOnlyTaproot),
                );
            }
        }
    }

    fn separator_witness_script(pubkey: &[u8], multisig: bool, verify: bool) -> Vec<u8> {
        let mut script = vec![0xab, 0x02, 0xab, 0xab, 0x75];
        if multisig {
            script.push(0x51);
        }
        script.push(u8::try_from(pubkey.len()).expect("short public key"));
        script.extend_from_slice(pubkey);
        if multisig {
            script.push(0x51);
        }
        script.push(match (multisig, verify) {
            (false, false) => 0xac,
            (false, true) => 0xad,
            (true, false) => 0xae,
            (true, true) => 0xaf,
        });
        if verify {
            script.push(0x51);
        }
        script.extend_from_slice(&[0x00, 0x63, 0xab, 0x68]);
        script
    }

    #[test]
    fn every_hashtype_verifies_all_witness_ecdsa_opcodes_with_separators() {
        let key = test_key();
        let pubkey = PublicKey::from_secret_key(&key).serialize();
        for (multisig, verify) in [(false, false), (false, true), (true, false), (true, true)] {
            let script = separator_witness_script(&pubkey, multisig, verify);
            let mut program = vec![0x00, 0x20];
            program.extend_from_slice(&Sha256::digest(&script));
            let prevout = TxOut {
                value: Amount::from_sat(VALUE),
                script_pubkey: Script::from_bytes(program),
            };
            let failure = match (multisig, verify) {
                (false, true) => ScriptErrCode::CheckSigVerify,
                (true, true) => ScriptErrCode::CheckMultisigVerify,
                (_, false) => ScriptErrCode::EvalFalse,
            };
            for output_count in [1, 2] {
                let (tx, oracle) = fixture(output_count);
                for byte in 0_u8..=u8::MAX {
                    let digest =
                        reference_bip143(&oracle, INPUT, &script[1..], VALUE, u32::from(byte));
                    let mut signature = secp256k1::ecdsa::sign(Message::from_digest(digest), &key)
                        .serialize_der()
                        .to_vec();
                    signature.push(byte);
                    let mut witness = Vec::new();
                    if multisig {
                        witness.push(Vec::new());
                    }
                    witness.extend([signature, script.clone()]);
                    assert_eq!(
                        verify_witness(&tx, &prevout, &witness, VerifyFlags::MANDATORY),
                        Ok(true),
                        "multisig={multisig}, verify={verify}, outputs={output_count}, raw={byte:#x}",
                    );
                    let mut wrong_amount = prevout.clone();
                    wrong_amount.value = Amount::from_sat(wrong_amount.value.to_sat() + 1);
                    assert_eq!(
                        verify_witness(&tx, &wrong_amount, &witness, VerifyFlags::MANDATORY),
                        Err(ScriptError::Invalid { code: failure }),
                        "wrong amount: multisig={multisig}, verify={verify}, raw={byte:#x}",
                    );
                    let strict = VerifyFlags::MANDATORY.union(VerifyFlags::STRICTENC);
                    let expected = if matches!(byte, 1 | 2 | 3 | 0x81 | 0x82 | 0x83) {
                        Ok(true)
                    } else {
                        Err(ScriptError::Invalid {
                            code: ScriptErrCode::SigHashtype,
                        })
                    };
                    assert_eq!(verify_witness(&tx, &prevout, &witness, strict), expected);
                    #[cfg(feature = "kernel")]
                    kernel_witness_parity(&tx, &prevout, &witness);
                }
            }
        }
    }

    #[test]
    fn raw_segwit_script_code_is_verbatim_across_compactsize_boundaries() {
        for output_count in [1, 2] {
            let (tx, oracle) = fixture(output_count);
            let cache = SighashCache::new(&tx);
            for size in [0, 1, 252, 253, 520, 10_000] {
                let script = vec![0xab; size];
                for value in [VALUE, VALUE + 1] {
                    for raw in [0, 1, 3, 0x83, 0xc2, u32::MAX] {
                        let expected = reference_bip143(&oracle, INPUT, &script, value, raw);
                        assert_eq!(
                            cache
                                .segwit_v0_signature_hash_raw(
                                    INPUT,
                                    &script,
                                    Amount::from_sat(value),
                                    raw
                                )
                                .expect("raw script-code digest")
                                .as_byte_array(),
                            &expected,
                            "outputs={output_count}, script_len={size}, value={value}, raw={raw:#x}",
                        );
                    }
                }
            }
        }
    }
}
mod script_stack_limits {
    use bitcoin::hashes::Hash as _;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use bitcoin::taproot::{LeafVersion, TaprootBuilder};
    use bitcoin::{ScriptBuf, absolute, transaction};
    use bitcoin_rs_consensus::primitives::{Amount, Script, Tx, TxOut};
    use bitcoin_rs_consensus::script::{
        Interpreter, PreparedTransaction, ScriptErrCode, ScriptError, VerifyFlags, opcode,
        push_data,
    };

    #[derive(Clone, Copy, Debug)]
    enum Spend {
        Legacy,
        P2sh,
        WitnessV0,
        Tapscript,
    }

    const SPENDS: [Spend; 4] = [
        Spend::Legacy,
        Spend::P2sh,
        Spend::WitnessV0,
        Spend::Tapscript,
    ];
    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Secp256k1(#[from] bitcoin::secp256k1::Error),
        #[error(transparent)]
        TaprootBuilder(#[from] bitcoin::taproot::TaprootBuilderError),
        #[error(transparent)]
        Decode(#[from] bitcoin_rs_consensus::primitives::DecodeError),
        #[error(transparent)]
        Prevout(#[from] bitcoin_rs_consensus::script::PrevoutError),
        #[cfg(feature = "kernel")]
        #[error(transparent)]
        Consensus(#[from] bitcoin_rs_consensus::ConsensusError),
        #[error("{0}")]
        Message(&'static str),
    }

    impl From<&'static str> for TestError {
        fn from(s: &'static str) -> Self {
            Self::Message(s)
        }
    }

    type TestResult = Result<(), TestError>;

    fn fixture(spend: Spend, initial: usize, script: Vec<u8>) -> Result<(Tx, TxOut), TestError> {
        let script = ScriptBuf::from_bytes(script);
        let mut script_sig = vec![opcode::OP_0; initial];
        let mut witness = vec![Vec::new(); initial];
        let script_pubkey = match spend {
            Spend::Legacy => {
                witness.clear();
                script
            }
            Spend::P2sh => {
                witness.clear();
                script_sig.extend(push_data(script.as_bytes()));
                script.to_p2sh()
            }
            Spend::WitnessV0 => {
                script_sig.clear();
                witness.push(script.to_bytes());
                script.to_p2wsh()
            }
            Spend::Tapscript => {
                script_sig.clear();
                let secp = Secp256k1::new();
                let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[17; 32])?);
                let info = TaprootBuilder::new()
                    .add_leaf(0, script.clone())?
                    .finalize(&secp, key.x_only_public_key().0)
                    .map_err(|_| "complete taproot tree")?;
                witness.push(script.to_bytes());
                witness.push(
                    info.control_block(&(script, LeafVersion::TapScript))
                        .ok_or("taproot control block")?
                        .serialize(),
                );
                ScriptBuf::new_p2tr_tweaked(info.output_key())
            }
        };
        let oracle = bitcoin::Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([42; 32]),
                    0,
                ),
                script_sig: ScriptBuf::from_bytes(script_sig),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::from_slice(&witness),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(9_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        Ok((
            bitcoin_rs_consensus::primitives::deserialize(&bitcoin::consensus::serialize(&oracle))?,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes(script_pubkey.to_bytes()),
            },
        ))
    }

    fn check(
        spend: Spend,
        initial: usize,
        script: Vec<u8>,
        expected: &Result<bool, ScriptError>,
    ) -> TestResult {
        let (tx, prevout) = fixture(spend, initial, script)?;
        let rows = [(tx.inputs[0].previous_output, prevout.clone())];
        assert_eq!(
            PreparedTransaction::new(&tx, &rows)?.verify_input(0, VerifyFlags::MANDATORY, None),
            *expected,
            "{spend:?}, initial={initial}, prepared"
        );
        assert_eq!(
            Interpreter.execute_with_prevouts(
                &prevout.script_pubkey,
                &tx.inputs[0].script_sig,
                &tx.inputs[0].witness,
                VerifyFlags::MANDATORY,
                std::slice::from_ref(&prevout),
                &tx,
                0,
            ),
            *expected,
            "{spend:?}, initial={initial}, interpreter"
        );
        #[cfg(feature = "kernel")]
        {
            use bitcoin_rs_consensus::{
                ConsensusError, ValidationEngine, kernel::verify_tx_scripts,
            };
            let result = verify_tx_scripts(
                &tx,
                &rows,
                VerifyFlags::MANDATORY,
                ValidationEngine::Kernel,
                None,
            );
            match result {
                Ok(()) => assert!(expected.is_ok(), "{spend:?}: kernel accepted"),
                Err(ConsensusError::Script { .. }) => {
                    assert!(expected.is_err(), "{spend:?}: kernel rejected");
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    #[test]
    fn combined_stack_limit_after_pushes() -> TestResult {
        // #1745: both stacks stay individually <= 1000. Only their sum overflows.
        // Exercise direct pushes and each PUSHDATA encoding without MINIMALDATA.
        for spend in SPENDS {
            for push in [
                vec![1, 0x42],
                vec![0x4c, 1, 0x42],
                vec![0x4d, 1, 0, 0x42],
                vec![0x4e, 1, 0, 0, 0, 0x42],
            ] {
                for initial in [995, 996, 997] {
                    let mut script = vec![
                        bitcoin::opcodes::all::OP_TOALTSTACK.to_u8(),
                        opcode::OP_0,
                        opcode::OP_0,
                        opcode::OP_0,
                    ];
                    script.extend(&push);
                    let expected = if initial == 997 {
                        Err(ScriptError::Invalid {
                            code: ScriptErrCode::StackSize,
                        })
                    } else if matches!(spend, Spend::WitnessV0 | Spend::Tapscript) {
                        // At sums 999/1000 evaluation reaches the separate final
                        // clean-stack rule; those large final stacks are not valid witnesses.
                        Err(ScriptError::Invalid {
                            code: ScriptErrCode::CleanStack,
                        })
                    } else {
                        Ok(true)
                    };
                    check(spend, initial, script, &expected)?;
                }
            }
        }
        Ok(())
    }

    #[test]
    fn combined_stack_overflow_cannot_be_hidden_by_a_later_drop() -> TestResult {
        for spend in SPENDS {
            check(
                spend,
                997,
                vec![
                    bitcoin::opcodes::all::OP_TOALTSTACK.to_u8(),
                    opcode::OP_0,
                    opcode::OP_0,
                    opcode::OP_0,
                    1,
                    0x42,
                    opcode::OP_DROP,
                ],
                &Err(ScriptError::Invalid {
                    code: ScriptErrCode::StackSize,
                }),
            )?;
        }
        Ok(())
    }

    #[test]
    fn empty_push_also_enforces_combined_stack_limit() -> TestResult {
        for spend in SPENDS {
            check(
                spend,
                997,
                vec![
                    bitcoin::opcodes::all::OP_TOALTSTACK.to_u8(),
                    opcode::OP_0,
                    opcode::OP_0,
                    opcode::OP_0,
                    opcode::OP_0,
                ],
                &Err(ScriptError::Invalid {
                    code: ScriptErrCode::StackSize,
                }),
            )?;
        }
        Ok(())
    }

    #[test]
    fn tapscript_combined_limit_is_checked_before_cleaning_the_stack() -> TestResult {
        for initial in [996, 997] {
            let mut script = vec![
                bitcoin::opcodes::all::OP_TOALTSTACK.to_u8(),
                opcode::OP_0,
                opcode::OP_0,
                opcode::OP_0,
                1,
                0x42,
            ];
            // Tapscript has no legacy opcode-count limit, so remove all items
            // below the true top. A transient sum of 1000 is a valid full spend;
            // a transient sum of 1001 must fail before the first NIP can hide it.
            script.extend(std::iter::repeat_n(
                bitcoin::opcodes::all::OP_NIP.to_u8(),
                initial + 2,
            ));
            let expected = if initial == 996 {
                Ok(true)
            } else {
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::StackSize,
                })
            };
            check(Spend::Tapscript, initial, script, &expected)?;
        }
        Ok(())
    }

    #[test]
    fn unexecuted_pushes_do_not_increase_combined_stack_size() -> TestResult {
        for spend in SPENDS {
            check(
                spend,
                1,
                vec![
                    opcode::OP_IF,
                    opcode::OP_0,
                    opcode::OP_ENDIF,
                    opcode::OP_PUSHNUM_1,
                ],
                &Ok(true),
            )?;
        }
        Ok(())
    }
}
mod script_taproot_spend_rules {
    #![expect(clippy::expect_used)]

    use bitcoin_rs_e2e::helpers::taproot as fixture;

    use bitcoin::hashes::Hash as _;
    use bitcoin_rs_consensus::primitives::{Script, Tx, TxOut, Witness};
    use bitcoin_rs_consensus::script::{
        Interpreter, PreparedTransaction, ScriptErrCode, ScriptError, SignatureCache, VerifyFlags,
    };

    fn prepared(
        tx: &bitcoin::Transaction,
        output: &bitcoin::TxOut,
        flags: VerifyFlags,
    ) -> Result<bool, ScriptError> {
        let tx: Tx =
            bitcoin_rs_consensus::primitives::deserialize(&bitcoin::consensus::serialize(tx))
                .expect("native decode");
        let output = TxOut {
            value: bitcoin_rs_consensus::primitives::Amount::from_sat(output.value.to_sat()),
            script_pubkey: Script::from_bytes(output.script_pubkey.to_bytes()),
        };
        let rows = vec![(tx.inputs[0].previous_output, output.clone())];
        let result = PreparedTransaction::new(&tx, &rows)
            .expect("ordered complete prevouts")
            .verify_input(0, flags, None);
        let input = &tx.inputs[0];
        assert_eq!(
            result,
            Interpreter.execute_with_prevouts(
                &output.script_pubkey,
                &input.script_sig,
                &input.witness,
                flags,
                std::slice::from_ref(&output),
                &tx,
                0
            )
        );
        result
    }

    fn output() -> bitcoin::TxOut {
        bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(100_000),
            script_pubkey: fixture::funding_script(),
        }
    }
    fn outpoint() -> bitcoin::OutPoint {
        bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([17; 32]), 0)
    }

    #[test]
    fn native_complete_spends_match_independent_bip341_cases() {
        let prevout = output();
        let mut mismatches = Vec::new();
        for case in fixture::cases(outpoint(), &prevout) {
            for flags in [VerifyFlags::MANDATORY, VerifyFlags::STANDARD] {
                let result = prepared(&case.tx, &prevout, flags);
                if result.is_ok() != case.accepted {
                    mismatches.push(format!("{} flags={:?}: {:?}", case.name, flags, result));
                }
            }
        }
        assert!(
            mismatches.is_empty(),
            "BIP341 mismatches:\n{}",
            mismatches.join("\n")
        );
    }

    #[test]
    fn tapscript_codeseparator_uses_decoded_opcode_positions() {
        let prevout = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(100_000),
            script_pubkey: fixture::codeseparator_funding_script(),
        };
        for case in fixture::codeseparator_cases(outpoint(), &prevout) {
            for flags in [VerifyFlags::MANDATORY, VerifyFlags::STANDARD] {
                let result = prepared(&case.tx, &prevout, flags);
                if case.accepted {
                    assert_eq!(result, Ok(true), "{} {flags:?}", case.name);
                } else {
                    assert_eq!(
                        result,
                        Err(ScriptError::Invalid {
                            code: ScriptErrCode::SchnorrSig
                        }),
                        "{} {flags:?}",
                        case.name
                    );
                }
            }
        }
    }

    #[test]
    #[cfg(feature = "kernel")]
    fn tapscript_codeseparator_positions_match_kernel() {
        let prevout = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(100_000),
            script_pubkey: fixture::codeseparator_funding_script(),
        };
        for case in fixture::codeseparator_cases(outpoint(), &prevout) {
            let tx: Tx = bitcoin_rs_consensus::primitives::deserialize(
                &bitcoin::consensus::serialize(&case.tx),
            )
            .expect("native decode");
            let output = TxOut {
                value: bitcoin_rs_consensus::primitives::Amount::from_sat(prevout.value.to_sat()),
                script_pubkey: Script::from_bytes(prevout.script_pubkey.to_bytes()),
            };
            let rows = [(tx.inputs[0].previous_output, output)];
            let result = bitcoin_rs_consensus::kernel::verify_tx_scripts(
                &tx,
                &rows,
                VerifyFlags::MANDATORY,
                bitcoin_rs_consensus::ValidationEngine::Kernel,
                None,
            );
            assert_eq!(result.is_ok(), case.accepted, "{}: {result:?}", case.name);
            if !case.accepted {
                assert!(
                    matches!(
                        result,
                        Err(bitcoin_rs_consensus::ConsensusError::Script { .. })
                    ),
                    "kernel infrastructure error is not a rejection: {result:?}"
                );
            }
            assert_eq!(
                prepared(&case.tx, &prevout, VerifyFlags::MANDATORY).is_ok(),
                result.is_ok(),
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn appended_default_and_malformed_sighash_bytes_are_explicit_errors() {
        let prevout = output();
        for case in fixture::cases(outpoint(), &prevout) {
            if case.name.starts_with("key-suffix-") {
                assert_eq!(
                    prepared(&case.tx, &prevout, VerifyFlags::MANDATORY),
                    Err(ScriptError::Invalid {
                        code: ScriptErrCode::SchnorrSigHashtype
                    }),
                    "{}",
                    case.name
                );
            }
        }
    }

    #[test]
    fn script_sig_errors_keep_existing_verification_order() {
        let prevout = output();
        let mut tx = fixture::cases(outpoint(), &prevout).remove(0).tx;
        tx.input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0x6a]);
        assert_eq!(
            prepared(&tx, &prevout, VerifyFlags::STANDARD),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::OpReturn
            })
        );
        assert_eq!(
            prepared(
                &tx,
                &prevout,
                VerifyFlags::STANDARD.union(VerifyFlags::SIGPUSHONLY)
            ),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::SigPushonly
            })
        );
        tx.input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0x00]);
        assert_eq!(
            prepared(&tx, &prevout, VerifyFlags::STANDARD),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::WitnessMalleated
            })
        );
    }

    #[test]
    fn inactive_taproot_and_wrapped_v1_keep_their_witness_rules() {
        let prevout = output();
        let mut tx = fixture::cases(outpoint(), &prevout).remove(0).tx;
        tx.input[0].witness = bitcoin::Witness::from_slice(&[vec![0_u8]]);
        assert_eq!(prepared(&tx, &prevout, VerifyFlags::WITNESS), Ok(true));
        assert_eq!(
            prepared(
                &tx,
                &prevout,
                VerifyFlags::WITNESS.union(VerifyFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
            ),
            Ok(true),
            "recognized native Taproot is inactive, not an unknown witness program"
        );
        tx.input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0x00]);
        assert_eq!(prepared(&tx, &prevout, VerifyFlags::NONE), Ok(true));
        assert_eq!(
            prepared(&tx, &prevout, VerifyFlags::TAPROOT),
            Ok(true),
            "Taproot dispatch still requires witness verification"
        );
        let wrapped = bitcoin::TxOut {
            value: prevout.value,
            script_pubkey: prevout.script_pubkey.to_p2sh(),
        };
        tx.input[0].script_sig = bitcoin::script::Builder::new()
            .push_slice(
                bitcoin::script::PushBytesBuf::try_from(prevout.script_pubkey.to_bytes())
                    .expect("witness program push"),
            )
            .into_script();
        assert_eq!(
            prepared(&tx, &wrapped, VerifyFlags::MANDATORY),
            Ok(true),
            "wrapped v1 is not native Taproot"
        );
        assert_eq!(
            prepared(
                &tx,
                &wrapped,
                VerifyFlags::MANDATORY.union(VerifyFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
            ),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::DiscourageUpgradableWitnessProgram
            }),
            "wrapped v1 still follows upgradeable-witness policy"
        );
        let mut unknown = prevout;
        unknown.script_pubkey =
            bitcoin::ScriptBuf::from_bytes([vec![0x51, 20], vec![1; 20]].concat());
        tx.input[0].script_sig = bitcoin::ScriptBuf::new();
        assert_eq!(
            prepared(
                &tx,
                &unknown,
                VerifyFlags::WITNESS.union(VerifyFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
            ),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::DiscourageUpgradableWitnessProgram
            }),
            "v1 with another program size remains upgradeable"
        );
    }

    #[test]
    fn op_success_overrides_stack_limits_and_final_truth_checks() {
        let prevout = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(100_000),
            script_pubkey: fixture::success_funding_script(),
        };
        let mut mismatches = Vec::new();
        for case in fixture::success_cases(outpoint(), &prevout) {
            let result = prepared(&case.tx, &prevout, VerifyFlags::MANDATORY);
            if result.is_ok() != case.accepted {
                mismatches.push(format!("{}: {:?}", case.name, result));
            }
        }
        assert!(
            mismatches.is_empty(),
            "OP_SUCCESS mismatches: {}",
            mismatches.join("\n")
        );
    }

    fn first_accepted_key_spend() -> (Tx, TxOut) {
        let prevout = output();
        let case = fixture::cases(outpoint(), &prevout)
            .into_iter()
            .find(|case| case.accepted && case.name.starts_with("key-Default"))
            .expect("fixture carries an accepted key-path Default spend");
        let tx: Tx =
            bitcoin_rs_consensus::primitives::deserialize(&bitcoin::consensus::serialize(&case.tx))
                .expect("native decode");
        let output = TxOut {
            value: bitcoin_rs_consensus::primitives::Amount::from_sat(prevout.value.to_sat()),
            script_pubkey: Script::from_bytes(prevout.script_pubkey.to_bytes()),
        };
        (tx, output)
    }

    fn verify_cached(
        tx: &Tx,
        output: &TxOut,
        flags: VerifyFlags,
        cache: Option<&SignatureCache>,
    ) -> Result<bool, ScriptError> {
        let rows = vec![(tx.inputs[0].previous_output, output.clone())];
        PreparedTransaction::new(tx, &rows)
            .expect("ordered complete prevouts")
            .verify_input(0, flags, cache)
    }

    #[test]
    fn signature_cache_hit_matches_uncached_across_flags() {
        let (tx, output) = first_accepted_key_spend();
        let cache = SignatureCache::new();
        assert_eq!(
            verify_cached(&tx, &output, VerifyFlags::MANDATORY, Some(&cache)),
            Ok(true),
            "warmup under MANDATORY"
        );
        assert_eq!(
            verify_cached(&tx, &output, VerifyFlags::STANDARD, Some(&cache)),
            Ok(true),
            "hit under STANDARD matches the uncached accept"
        );
        assert_eq!(
            verify_cached(&tx, &output, VerifyFlags::MANDATORY, Some(&cache)),
            Ok(true),
            "repeat hit stays accepting"
        );
    }

    #[test]
    fn signature_cache_warmed_still_rejects_flipped_signature_byte() {
        let (tx, output) = first_accepted_key_spend();
        let cache = SignatureCache::new();
        assert_eq!(
            verify_cached(&tx, &output, VerifyFlags::MANDATORY, Some(&cache)),
            Ok(true),
            "warmup"
        );
        let mut bad = tx;
        bad.inputs[0].witness = flip_first_byte(&bad.inputs[0].witness, 0);
        let uncached = verify_cached(&bad, &output, VerifyFlags::MANDATORY, None);
        assert!(
            uncached != Ok(true),
            "flipped Schnorr byte must break uncached verification (else the test is vacuous)"
        );
        assert_eq!(
            verify_cached(&bad, &output, VerifyFlags::MANDATORY, Some(&cache)),
            uncached,
            "cached verdict matches uncached after warming"
        );
    }

    #[test]
    fn signature_cache_warmed_still_rejects_mutated_sighash_input() {
        let (tx, output) = first_accepted_key_spend();
        let cache = SignatureCache::new();
        assert_eq!(
            verify_cached(&tx, &output, VerifyFlags::MANDATORY, Some(&cache)),
            Ok(true),
            "warmup"
        );
        let mut retargeted = tx;
        let paid = retargeted.outputs[0].value.to_sat();
        retargeted.outputs[0].value = bitcoin_rs_consensus::primitives::Amount::from_sat(paid + 1);
        let uncached = verify_cached(&retargeted, &output, VerifyFlags::MANDATORY, None);
        assert!(
            uncached != Ok(true),
            "retargeted sighash must break uncached verification (else the test is vacuous)"
        );
        assert_eq!(
            verify_cached(&retargeted, &output, VerifyFlags::MANDATORY, Some(&cache)),
            uncached,
            "cached verdict matches uncached after warming"
        );
    }

    fn accepted_spend_under_different_key() -> (bitcoin::Transaction, bitcoin::TxOut) {
        use bitcoin::secp256k1::{Keypair, Message as OracleMessage, Secp256k1, SecretKey};
        use bitcoin::sighash::{Prevouts, SighashCache as OracleCache, TapSighashType};

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[77; 32]).expect("second fixture key");
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let tweaked = bitcoin::key::TapTweak::tap_tweak(keypair, &secp, None);
        let (output_key, _) = tweaked.public_parts();
        let prevout = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(100_000),
            script_pubkey: bitcoin::ScriptBuf::new_p2tr_tweaked(output_key),
        };
        let mut tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([78; 32]),
                    0,
                ),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(90_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let hash = OracleCache::new(&tx)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(&prevout)),
                TapSighashType::Default,
            )
            .expect("second-key BIP341 digest");
        let signature = secp.sign_schnorr_no_aux_rand(
            &OracleMessage::from_digest(*bitcoin::hashes::Hash::as_byte_array(&hash)),
            tweaked.as_keypair(),
        );
        tx.input[0].witness = bitcoin::Witness::from_slice(&[signature.serialize()]);
        (tx, prevout)
    }

    #[test]
    fn signature_cache_warmed_still_rejects_wrong_key_signature() {
        let (tx, output) = first_accepted_key_spend();
        let cache = SignatureCache::new();
        assert_eq!(
            verify_cached(&tx, &output, VerifyFlags::MANDATORY, Some(&cache)),
            Ok(true),
            "warmup"
        );
        let (other_oracle, other_oracle_prevout) = accepted_spend_under_different_key();
        assert_ne!(
            other_oracle_prevout.script_pubkey.to_bytes(),
            output.script_pubkey.as_bytes(),
            "funding programs (hence tweaked keys) must differ"
        );
        assert_eq!(
            prepared(&other_oracle, &other_oracle_prevout, VerifyFlags::MANDATORY),
            Ok(true),
            "second source valid under its own key"
        );
        let other_tx: Tx = bitcoin_rs_consensus::primitives::deserialize(
            &bitcoin::consensus::serialize(&other_oracle),
        )
        .expect("native decode");
        let mut wrong_key = tx;
        wrong_key.inputs[0].witness = other_tx.inputs[0].witness.clone();
        let uncached = verify_cached(&wrong_key, &output, VerifyFlags::MANDATORY, None);
        assert!(
            uncached != Ok(true),
            "wrong-key signature must break uncached verification (else the test is vacuous)"
        );
        assert_eq!(
            verify_cached(&wrong_key, &output, VerifyFlags::MANDATORY, Some(&cache)),
            uncached,
            "cached verdict matches uncached after warming"
        );
    }

    #[test]
    fn op_success_policy_rejection_precedes_stack_limits() {
        let prevout = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(100_000),
            script_pubkey: fixture::success_funding_script(),
        };
        for case in fixture::success_cases(outpoint(), &prevout)
            .into_iter()
            .filter(|case| case.accepted)
        {
            assert_eq!(
                prepared(
                    &case.tx,
                    &prevout,
                    VerifyFlags::MANDATORY.union(VerifyFlags::DISCOURAGE_OP_SUCCESS)
                ),
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::DiscourageOpSuccess
                }),
                "{}",
                case.name
            );
        }
    }

    fn flip_first_byte(witness: &Witness, item: usize) -> Witness {
        let mut stack: Vec<Vec<u8>> = witness.iter().map(<[u8]>::to_vec).collect();
        stack[item][0] ^= 0x01;
        Witness::from_stack(stack)
    }
}
mod script_verifier_boundaries {
    use bitcoin::hashes::Hash as _;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut as OracleTxOut, Txid,
        Witness, absolute, transaction,
    };
    use bitcoin_rs_consensus::primitives::{Script, Tx, TxOut};
    use bitcoin_rs_consensus::script::{Interpreter, ScriptError, VerifyFlags};

    fn signed_spend() -> (Tx, Vec<TxOut>) {
        let secp = Secp256k1::new();
        let seeds = [11_u8, 12];
        let mut keys = Vec::new();
        let mut prevouts = Vec::new();
        for seed in seeds {
            let secret = SecretKey::from_slice(&[seed; 32])
                .unwrap_or_else(|error| panic!("fixed secret key: {error}"));
            let keypair = Keypair::from_secret_key(&secp, &secret);
            let tweaked = bitcoin::key::TapTweak::tap_tweak(keypair, &secp, None);
            let (output_key, _) = tweaked.public_parts();
            prevouts.push(OracleTxOut {
                value: Amount::from_sat(u64::from(seed) * 10_000),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(output_key),
            });
            keys.push(tweaked);
        }
        let mut oracle = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: seeds
                .iter()
                .map(|seed| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([*seed; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![OracleTxOut {
                value: Amount::from_sat(229_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        for (index, key) in keys.iter().enumerate() {
            let hash = SighashCache::new(&oracle)
                .taproot_key_spend_signature_hash(
                    index,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .unwrap_or_else(|error| panic!("oracle BIP341 digest: {error}"));
            let signature = secp.sign_schnorr_no_aux_rand(
                &Message::from_digest(*hash.as_byte_array()),
                key.as_keypair(),
            );
            oracle.input[index].witness = Witness::from_slice(&[signature.serialize()]);
        }
        let tx =
            bitcoin_rs_consensus::primitives::deserialize(&bitcoin::consensus::serialize(&oracle))
                .unwrap_or_else(|error| panic!("native decode of oracle transaction: {error}"));
        let prevouts = prevouts
            .iter()
            .map(|prevout| TxOut {
                value: bitcoin_rs_consensus::primitives::Amount::from_sat(prevout.value.to_sat()),
                script_pubkey: Script::from_bytes(prevout.script_pubkey.as_bytes().to_vec()),
            })
            .collect();
        (tx, prevouts)
    }

    fn verify(tx: &Tx, prevouts: &[TxOut], index: usize) -> Result<bool, ScriptError> {
        let input = &tx.inputs[index];
        Interpreter.execute_with_prevouts(
            &prevouts[index].script_pubkey,
            &input.script_sig,
            &input.witness,
            VerifyFlags::MANDATORY,
            prevouts,
            tx,
            index,
        )
    }

    #[test]
    fn bip341_binds_all_prevouts_and_the_transaction() {
        let (tx, prevouts) = signed_spend();
        for index in 0..tx.inputs.len() {
            assert_eq!(verify(&tx, &prevouts, index), Ok(true), "input {index}");
        }

        let mut altered_prevouts = prevouts.clone();
        altered_prevouts[1].value = bitcoin_rs_consensus::primitives::Amount::from_sat(
            altered_prevouts[1].value.to_sat() + 1,
        );
        assert!(verify(&tx, &altered_prevouts, 0).is_err());

        let mut reordered_prevouts = prevouts.clone();
        reordered_prevouts.swap(0, 1);
        let input = &tx.inputs[0];
        assert!(
            Interpreter
                .execute_with_prevouts(
                    &prevouts[0].script_pubkey,
                    &input.script_sig,
                    &input.witness,
                    VerifyFlags::MANDATORY,
                    &reordered_prevouts,
                    &tx,
                    0,
                )
                .is_err()
        );
        assert_eq!(
            Interpreter.execute_with_prevouts(
                &[0x51],
                &[],
                &bitcoin_rs_consensus::primitives::Witness::new(),
                VerifyFlags::NONE,
                &prevouts[..1],
                &tx,
                0,
            ),
            Err(ScriptError::TaprootPrevoutsUnavailable),
        );

        let mut altered_tx = tx;
        altered_tx.outputs[0].value = bitcoin_rs_consensus::primitives::Amount::from_sat(
            altered_tx.outputs[0].value.to_sat() - 1,
        );
        assert!(verify(&altered_tx, &prevouts, 0).is_err());
    }

    #[test]
    fn supplied_witness_is_verified_without_mutating_the_transaction() {
        let (tx, prevouts) = signed_spend();
        assert_eq!(verify(&tx, &prevouts, 0), Ok(true));
        let witness = tx.inputs[0].witness.clone();
        let mut corrupted_tx = tx;
        corrupted_tx.inputs[0].witness = flip_first_byte(&corrupted_tx.inputs[0].witness, 0);
        assert!(verify(&corrupted_tx, &prevouts, 0).is_err());
        let unchanged_tx = corrupted_tx.clone();
        assert_eq!(
            Interpreter.execute_with_prevouts(
                &prevouts[0].script_pubkey,
                &corrupted_tx.inputs[0].script_sig,
                &witness,
                VerifyFlags::MANDATORY,
                &prevouts,
                &corrupted_tx,
                0,
            ),
            Ok(true)
        );
        assert_eq!(corrupted_tx, unchanged_tx);
    }

    #[test]
    fn invalid_input_index_is_a_typed_error() {
        let (tx, prevouts) = signed_spend();
        assert_eq!(verify(&tx, &prevouts, 0), Ok(true));
        for index in [tx.inputs.len(), usize::MAX] {
            assert_eq!(
                Interpreter.execute_with_prevouts(
                    &prevouts[0].script_pubkey,
                    &[],
                    &bitcoin_rs_consensus::primitives::Witness::new(),
                    VerifyFlags::MANDATORY,
                    &prevouts,
                    &tx,
                    index,
                ),
                Err(ScriptError::InputIndexOutOfRange {
                    index,
                    inputs: tx.inputs.len(),
                })
            );
        }
    }

    fn flip_first_byte(
        witness: &bitcoin_rs_consensus::primitives::Witness,
        item: usize,
    ) -> bitcoin_rs_consensus::primitives::Witness {
        let mut stack: Vec<Vec<u8>> = witness.iter().map(<[u8]>::to_vec).collect();
        stack[item][0] ^= 0x01;
        bitcoin_rs_consensus::primitives::Witness::from_stack(stack)
    }
}
mod shared_sighash {
    #![expect(clippy::expect_used, reason = "fixed independent-reference fixtures")]

    use bitcoin::hashes::Hash as _;
    use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
    use bitcoin::sighash::{
        Annex, EcdsaSighashType, Prevouts, SighashCache as OracleCache, TapSighashType,
    };
    use bitcoin_rs_consensus::kernel::{BlockParse, verify_tx_scripts};
    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, Network, OutPoint, Script, Sequence, Sighash, SighashCache,
        SighashError, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
    };
    use bitcoin_rs_consensus::script::{
        PreparedTransaction, PrevoutError, ScriptErrCode, ScriptError, VerifyFlags, opcode,
        push_data,
    };
    use bitcoin_rs_consensus::{
        BlockView, ConsensusError, ScriptStageTimings, ValidationEngine, verify_block_input_scripts,
    };

    const MODES: [Sighash; 7] = [
        Sighash::Default,
        Sighash::All,
        Sighash::None,
        Sighash::Single,
        Sighash::AllAnyoneCanPay,
        Sighash::NoneAnyoneCanPay,
        Sighash::SingleAnyoneCanPay,
    ];

    fn resolved_prevouts(tx: &Tx, prevouts: &[TxOut]) -> Vec<(OutPoint, TxOut)> {
        tx.inputs
            .iter()
            .zip(prevouts)
            .map(|(input, output)| (input.previous_output, output.clone()))
            .collect()
    }

    fn fixture(inputs: u8, outputs: usize) -> (Tx, Vec<TxOut>) {
        let prevouts: Vec<TxOut> = (0..inputs)
            .map(|index| TxOut {
                value: Amount::from_sat(10_000 + u64::from(index)),
                script_pubkey: Script::from_bytes(vec![opcode::OP_PUSHNUM_1, index]),
            })
            .collect();
        let tx = Tx {
            version: 2,
            lock_time: LockTime::from_consensus(7),
            inputs: (0..inputs)
                .map(|index| TxIn {
                    previous_output: OutPoint::new(
                        Txid(Hash256::from_le_bytes(&[index + 1; 32])),
                        0,
                    ),
                    sequence: Sequence::from_consensus(0xffff_ff00 + u32::from(index)),
                    ..TxIn::default()
                })
                .collect(),
            outputs: prevouts.iter().take(outputs).cloned().collect(),
        };
        (tx, prevouts)
    }

    fn oracle_tx(tx: &Tx) -> bitcoin::Transaction {
        bitcoin::consensus::deserialize(&consensus_bytes(tx)).expect("oracle transaction")
    }

    fn oracle_prevouts(prevouts: &[TxOut]) -> Vec<bitcoin::TxOut> {
        prevouts
            .iter()
            .map(|output| {
                bitcoin::consensus::deserialize(&consensus_bytes(output)).expect("oracle output")
            })
            .collect()
    }

    #[test]
    fn parallel_shared_digests_match_reference_for_each_input_context() {
        let (tx, prevouts) = fixture(3, 2);
        let reference = oracle_tx(&tx);
        let reference_prevouts = oracle_prevouts(&prevouts);
        let cache = SighashCache::new(&tx);
        std::thread::scope(|scope| {
            for input in 0..tx.inputs.len() {
                let (cache, tx, prevouts, reference, reference_prevouts) =
                    (&cache, &tx, &prevouts, &reference, &reference_prevouts);
                scope.spawn(move || {
                    let context = SharedContext {
                        tx,
                        prevouts,
                        reference_prevouts,
                    };
                    compare_input_contexts(cache, reference, &context, input);
                });
            }
        });
    }

    struct SharedContext<'a> {
        tx: &'a Tx,
        prevouts: &'a [TxOut],
        reference_prevouts: &'a [bitcoin::TxOut],
    }

    fn compare_input_contexts(
        cache: &SighashCache<'_>,
        reference: &bitcoin::Transaction,
        context: &SharedContext<'_>,
        input: usize,
    ) {
        let mut oracle = OracleCache::new(reference);
        for mode in MODES {
            let raw = u32::from(mode.to_u8());
            assert_legacy_digest_matches(cache, &oracle, input, raw);
            if mode != Sighash::Default {
                assert_bip143_digest_matches(cache, &mut oracle, context, input, mode);
            }
            assert_taproot_digests_match(cache, &mut oracle, context, input, mode);
        }
    }

    fn assert_legacy_digest_matches(
        cache: &SighashCache<'_>,
        oracle: &OracleCache<&bitcoin::Transaction>,
        input: usize,
        raw: u32,
    ) {
        let legacy_script = bitcoin::Script::from_bytes(&[0x51, 0x52]);
        assert_eq!(
            cache
                .legacy_signature_hash(input, legacy_script.as_bytes(), raw)
                .expect("legacy"),
            Hash256::from_le_bytes(
                oracle
                    .legacy_signature_hash(input, legacy_script, raw)
                    .expect("oracle legacy")
                    .as_byte_array()
            ),
        );
    }

    fn assert_bip143_digest_matches(
        cache: &SighashCache<'_>,
        oracle: &mut OracleCache<&bitcoin::Transaction>,
        context: &SharedContext<'_>,
        input: usize,
        mode: Sighash,
    ) {
        let raw = u32::from(mode.to_u8());
        let script = bitcoin::Script::from_bytes(&[0x51, 0xab, 0x52]);
        let value = context.prevouts[input].value;
        assert_eq!(
            cache
                .segwit_v0_signature_hash(input, script.as_bytes(), value, mode)
                .expect("BIP143"),
            Hash256::from_le_bytes(
                oracle
                    .p2wsh_signature_hash(
                        input,
                        script,
                        bitcoin::Amount::from_sat(value.to_sat()),
                        EcdsaSighashType::from_consensus(raw)
                    )
                    .expect("oracle BIP143")
                    .as_byte_array()
            ),
        );
    }

    fn assert_taproot_digests_match(
        cache: &SighashCache<'_>,
        oracle: &mut OracleCache<&bitcoin::Transaction>,
        context: &SharedContext<'_>,
        input: usize,
        mode: Sighash,
    ) {
        let leaf = bitcoin::TapLeafHash::from_script(
            bitcoin::Script::from_bytes(&[0x51, 0xab, 0xac]),
            bitcoin::taproot::LeafVersion::TapScript,
        );
        for annex in [None, Some(&[0x50, 0x01][..]), Some(&[0x50, 0x02, 0x03][..])] {
            for separator in [None, Some(u32::MAX), Some(0), Some(2)] {
                let native_leaf = separator
                    .map(|position| (Hash256::from_le_bytes(leaf.as_byte_array()), position));
                let result =
                    cache.taproot_signature_hash(input, context.prevouts, annex, native_leaf, mode);
                let expected = oracle.taproot_signature_hash(
                    input,
                    &Prevouts::All(context.reference_prevouts),
                    annex.map(|bytes| Annex::new(bytes).expect("annex")),
                    separator.map(|position| (leaf, position)),
                    TapSighashType::from_consensus_u8(mode.to_u8()).expect("mode"),
                );
                if input >= context.tx.outputs.len()
                    && matches!(mode, Sighash::Single | Sighash::SingleAnyoneCanPay)
                {
                    assert!(expected.is_err());
                    assert_eq!(
                        result,
                        Err(SighashError::SingleMissingOutput {
                            input_index: input,
                            outputs_length: context.tx.outputs.len()
                        })
                    );
                } else {
                    assert_eq!(
                        result.expect("BIP341"),
                        Hash256::from_le_bytes(expected.expect("oracle BIP341").as_byte_array())
                    );
                }
            }
        }
    }
    fn signed_fixture() -> (Tx, Vec<TxOut>) {
        let (mut tx, mut prevouts) = fixture(42, 42);
        tx.lock_time = LockTime::ZERO;
        let signing = signing_fixture();
        assign_output_scripts(&mut prevouts, &signing);
        let reference = oracle_tx(&tx);
        let reference_prevouts = oracle_prevouts(&prevouts);
        sign_inputs(&mut tx, &reference, &reference_prevouts, &signing);
        (tx, prevouts)
    }

    struct SigningFixture {
        key: SecretKey,
        keypair: Keypair,
        script: Vec<u8>,
        witness_script: Vec<u8>,
        tapscript: bitcoin::ScriptBuf,
        leaf: bitcoin::TapLeafHash,
        control: Vec<u8>,
        output_key: [u8; 32],
    }

    fn signing_fixture() -> SigningFixture {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[7; 32]).expect("test key");
        let pubkey = PublicKey::from_secret_key(&secp, &key);
        let keypair = Keypair::from_secret_key(&secp, &key);
        let mut script = push_data(&pubkey.serialize());
        script.push(opcode::OP_CHECKSIG);
        let mut witness_script = vec![0xab];
        witness_script.extend_from_slice(&script);
        let mut tapscript = Vec::new();
        tapscript.extend(push_data(&keypair.x_only_public_key().0.serialize()));
        tapscript.push(opcode::OP_CHECKSIG);
        let tapscript = bitcoin::ScriptBuf::from_bytes(tapscript);
        let leaf =
            bitcoin::TapLeafHash::from_script(&tapscript, bitcoin::taproot::LeafVersion::TapScript);
        let tree = bitcoin::taproot::TaprootBuilder::new()
            .add_leaf(0, tapscript.clone())
            .expect("single leaf")
            .finalize(&secp, keypair.x_only_public_key().0)
            .expect("taproot tree");
        let control = tree
            .control_block(&(tapscript.clone(), bitcoin::taproot::LeafVersion::TapScript))
            .expect("control block")
            .serialize();
        SigningFixture {
            key,
            keypair,
            script,
            witness_script,
            tapscript,
            leaf,
            control,
            output_key: tree.output_key().serialize(),
        }
    }

    fn assign_output_scripts(prevouts: &mut [TxOut], fixture: &SigningFixture) {
        for (index, output) in prevouts.iter_mut().enumerate() {
            output.script_pubkey = match index % 4 {
                0 => Script::from_bytes(fixture.script.clone()),
                1 => {
                    let mut program = vec![0, 32];
                    program.extend_from_slice(
                        bitcoin::WScriptHash::hash(&fixture.witness_script).as_byte_array(),
                    );
                    Script::from_bytes(program)
                }
                _ => {
                    let mut program = vec![opcode::OP_PUSHNUM_1, 32];
                    let output_key = if index % 4 == 2 {
                        fixture.keypair.x_only_public_key().0.serialize()
                    } else {
                        fixture.output_key
                    };
                    program.extend_from_slice(&output_key);
                    Script::from_bytes(program)
                }
            };
        }
    }

    fn sign_inputs(
        tx: &mut Tx,
        reference: &bitcoin::Transaction,
        reference_prevouts: &[bitcoin::TxOut],
        fixture: &SigningFixture,
    ) {
        for (index, input) in tx.inputs.iter_mut().enumerate() {
            let mode = MODES[index % MODES.len()];
            if index % 4 >= 2 {
                sign_taproot_input(input, index, mode, reference, reference_prevouts, fixture);
            } else {
                sign_ecdsa_input(input, index, mode, reference, reference_prevouts, fixture);
            }
        }
    }

    fn sign_taproot_input(
        input: &mut TxIn,
        index: usize,
        mode: Sighash,
        reference: &bitcoin::Transaction,
        reference_prevouts: &[bitcoin::TxOut],
        fixture: &SigningFixture,
    ) {
        let scriptpath = index % 4 == 3;
        let mode = if scriptpath { mode } else { Sighash::Default };
        let annex = [0x50, u8::try_from(index).expect("small index")];
        let mut oracle = OracleCache::new(reference);
        let digest = oracle
            .taproot_signature_hash(
                index,
                &Prevouts::All(reference_prevouts),
                Some(Annex::new(&annex).expect("annex")),
                scriptpath.then_some((fixture.leaf, u32::MAX)),
                TapSighashType::from_consensus_u8(mode.to_u8()).expect("mode"),
            )
            .expect("taproot digest");
        let secp = Secp256k1::new();
        let mut signature = secp
            .sign_schnorr_no_aux_rand(
                &Message::from_digest(digest.to_byte_array()),
                &fixture.keypair,
            )
            .serialize()
            .to_vec();
        if mode != Sighash::Default {
            signature.push(mode.to_u8());
        }
        input.witness = if scriptpath {
            Witness::from_stack(vec![
                signature,
                fixture.tapscript.to_bytes(),
                fixture.control.clone(),
                annex.to_vec(),
            ])
        } else {
            Witness::from_stack(vec![signature, annex.to_vec()])
        };
    }

    fn sign_ecdsa_input(
        input: &mut TxIn,
        index: usize,
        mode: Sighash,
        reference: &bitcoin::Transaction,
        reference_prevouts: &[bitcoin::TxOut],
        fixture: &SigningFixture,
    ) {
        let mode = if mode == Sighash::Default {
            Sighash::All
        } else {
            mode
        };
        let script = bitcoin::Script::from_bytes(&fixture.script);
        let mut oracle = OracleCache::new(reference);
        let digest = if index.is_multiple_of(4) {
            oracle
                .legacy_signature_hash(index, script, u32::from(mode.to_u8()))
                .expect("legacy digest")
                .to_byte_array()
        } else {
            oracle
                .p2wsh_signature_hash(
                    index,
                    script,
                    reference_prevouts[index].value,
                    EcdsaSighashType::from_consensus(u32::from(mode.to_u8())),
                )
                .expect("BIP143 digest")
                .to_byte_array()
        };
        let secp = Secp256k1::new();
        let mut signature = secp
            .sign_ecdsa(&Message::from_digest(digest), &fixture.key)
            .serialize_der()
            .to_vec();
        signature.push(mode.to_u8());
        if index.is_multiple_of(4) {
            input.script_sig = Script::from_bytes(push_data(&signature));
        } else {
            input.witness = Witness::from_stack(vec![signature, fixture.witness_script.clone()]);
        }
    }

    fn verify_block(
        tx: &Tx,
        prevouts: &[TxOut],
        engine: ValidationEngine,
    ) -> Result<(), ConsensusError> {
        let mut block = Network::Regtest.genesis_block();
        block.txs = vec![tx.clone()];
        let parsed = BlockParse::parse(&consensus_bytes(&block), engine)?;
        let (parsed, facts) = parsed.into_parts(&block.txs)?;
        let mut view = BlockView::from_facts(&block.txs, facts);
        view.set_resolved(vec![prevouts.iter().cloned().map(Some).collect()]);
        verify_block_input_scripts(
            &mut view,
            0,
            0,
            VerifyFlags::MANDATORY,
            &mut ScriptStageTimings::default(),
            &parsed,
            None,
        )
    }

    #[test]
    fn prepared_block_and_transaction_accept_reference_signatures_and_order_failures() {
        let (tx, prevouts) = signed_fixture();
        let mut changed_tx = tx.clone();
        for (failed_input, signature_input) in [(1, 41), (41, 1)] {
            let mut isolated = tx.clone();
            isolated.inputs[failed_input].witness =
                with_item(&isolated.inputs[failed_input].witness, 0, |item| {
                    item.clear();
                    item.extend_from_slice(&tx.inputs[signature_input].witness[0]);
                });
            let prepared =
                PreparedTransaction::new(&isolated, &resolved_prevouts(&isolated, &prevouts))
                    .expect("ordered prevouts");
            for input_index in 0..tx.inputs.len() {
                let expected = if input_index == failed_input {
                    Err(ScriptError::Invalid {
                        code: ScriptErrCode::EvalFalse,
                    })
                } else {
                    Ok(true)
                };
                assert_eq!(
                    prepared.verify_input(input_index, VerifyFlags::MANDATORY, None),
                    expected,
                    "isolated signature substitution at {failed_input}, checking {input_index}"
                );
            }
            changed_tx.inputs[failed_input].witness =
                with_item(&changed_tx.inputs[failed_input].witness, 0, |item| {
                    item.clear();
                    item.extend_from_slice(&tx.inputs[signature_input].witness[0]);
                });
        }
        for engine in std::iter::once(ValidationEngine::Native).chain(if cfg!(feature = "kernel") {
            Some(ValidationEngine::Kernel)
        } else {
            None
        }) {
            let spent: Vec<_> = tx
                .inputs
                .iter()
                .zip(&prevouts)
                .map(|(input, output)| (input.previous_output, output.clone()))
                .collect();
            assert_eq!(
                verify_tx_scripts(&tx, &spent, VerifyFlags::MANDATORY, engine, None),
                Ok(())
            );
            assert_eq!(verify_block(&tx, &prevouts, engine), Ok(()));
            let sequential =
                verify_tx_scripts(&changed_tx, &spent, VerifyFlags::MANDATORY, engine, None);
            let parallel = verify_block(&changed_tx, &prevouts, engine);
            assert_eq!(parallel, sequential);
            assert!(matches!(
                parallel,
                Err(ConsensusError::Script { input_index: 1, .. })
            ));
        }
    }

    #[test]
    fn prepared_input_preserves_typed_bounds_and_count_precedence() {
        let (tx, prevouts) = fixture(3, 2);
        for wrong_count in [
            PreparedTransaction::new(&tx, &[]),
            PreparedTransaction::from_owned(&tx, vec![]),
        ] {
            assert_eq!(
                wrong_count.err(),
                Some(PrevoutError::Count {
                    input_count: 3,
                    prevout_count: 0
                })
            );
        }
        let rows = resolved_prevouts(&tx, &prevouts);
        for prepared in [
            PreparedTransaction::new(&tx, &rows),
            PreparedTransaction::from_owned(&tx, rows),
        ] {
            assert_eq!(
                prepared
                    .expect("ordered prevouts")
                    .verify_input(999, VerifyFlags::MANDATORY, None),
                Err(ScriptError::InputIndexOutOfRange {
                    index: 999,
                    inputs: 3
                })
            );
        }
    }

    #[test]
    fn preparation_rejects_swapped_and_foreign_prevout_identities_before_scripts() {
        let (tx, mut outputs) = fixture(3, 2);
        for output in &mut outputs {
            *output = TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Script::from_bytes(vec![opcode::OP_PUSHNUM_1]),
            };
        }
        let rows = resolved_prevouts(&tx, &outputs);
        for prepared in [
            PreparedTransaction::new(&tx, &rows),
            PreparedTransaction::from_owned(&tx, rows.clone()),
        ] {
            let prepared = prepared.expect("ordered identities");
            for index in 0..tx.inputs.len() {
                assert_eq!(
                    prepared.verify_input(index, VerifyFlags::NONE, None),
                    Ok(true)
                );
            }
        }
        let mut swapped = rows.clone();
        swapped.swap(0, 1);
        let mut foreign = rows.clone();
        foreign[1].0.vout += 1;
        for (bad_rows, input_index) in [(swapped, 0), (foreign, 1)] {
            assert_eq!(
                PreparedTransaction::new(&tx, &bad_rows).err(),
                Some(PrevoutError::Mismatch { input_index })
            );
            assert_eq!(
                PreparedTransaction::from_owned(&tx, bad_rows.clone()).err(),
                Some(PrevoutError::Mismatch { input_index })
            );
            for engine in [ValidationEngine::Native, ValidationEngine::Kernel] {
                assert_eq!(
                    verify_tx_scripts(&tx, &bad_rows, VerifyFlags::NONE, engine, None),
                    Err(ConsensusError::PrevoutMismatch { input_index })
                );
            }
        }
        let mut short = rows;
        short.swap(0, 1);
        short.pop();
        assert_eq!(
            PreparedTransaction::new(&tx, &short).err(),
            Some(PrevoutError::Count {
                input_count: 3,
                prevout_count: 2
            })
        );
        assert_eq!(
            PreparedTransaction::from_owned(&tx, short).err(),
            Some(PrevoutError::Count {
                input_count: 3,
                prevout_count: 2
            })
        );
    }

    #[test]
    fn native_signature_cache_preserves_verdicts() {
        let (tx, prevouts) = signed_fixture();
        let spent: Vec<_> = tx
            .inputs
            .iter()
            .zip(&prevouts)
            .map(|(input, output)| (input.previous_output, output.clone()))
            .collect();
        let cache = bitcoin_rs_consensus::script::SignatureCache::new();
        assert_eq!(
            verify_tx_scripts(
                &tx,
                &spent,
                VerifyFlags::MANDATORY,
                ValidationEngine::Native,
                Some(&cache),
            ),
            Ok(())
        );
        assert_eq!(
            verify_tx_scripts(
                &tx,
                &spent,
                VerifyFlags::MANDATORY,
                ValidationEngine::Native,
                Some(&cache),
            ),
            Ok(())
        );
        assert_eq!(
            verify_tx_scripts(
                &tx,
                &spent,
                VerifyFlags::MANDATORY,
                ValidationEngine::Native,
                None,
            ),
            Ok(())
        );
        let mut changed = tx.clone();
        changed.inputs[1].witness = with_item(&changed.inputs[1].witness, 0, |item| {
            item.clear();
            item.extend_from_slice(&tx.inputs[41].witness[0]);
        });
        let uncached = verify_tx_scripts(
            &changed,
            &spent,
            VerifyFlags::MANDATORY,
            ValidationEngine::Native,
            None,
        );
        assert!(
            matches!(uncached, Err(ConsensusError::Script { input_index: 1, .. })),
            "swapped signature must reject at input 1, got {uncached:?}"
        );
        assert_eq!(
            verify_tx_scripts(
                &changed,
                &spent,
                VerifyFlags::MANDATORY,
                ValidationEngine::Native,
                Some(&cache),
            ),
            uncached
        );
    }

    fn with_item(witness: &Witness, index: usize, edit: impl FnOnce(&mut Vec<u8>)) -> Witness {
        let mut stack: Vec<Vec<u8>> = witness.iter().map(<[u8]>::to_vec).collect();
        edit(&mut stack[index]);
        Witness::from_stack(stack)
    }
}
mod support {
    pub(crate) mod error {
        #[cfg(feature = "kernel")]
        use bitcoin_rs_consensus::primitives::OutPoint;

        #[expect(dead_code, reason = "used when feature kernel is enabled")]
        #[derive(Debug, thiserror::Error)]
        pub(crate) enum TestError {
            #[error("io error: {0}")]
            Io(#[from] std::io::Error),
            #[error("json error: {0}")]
            Json(#[from] sonic_rs::Error),
            #[error("hex decode error: {0}")]
            Hex(#[from] bitcoin::hex::HexToArrayError),
            #[error("hex slice decode error: {0}")]
            HexSlice(#[from] bitcoin::hex::HexToBytesError),
            #[error("consensus decode error: {0}")]
            Decode(#[from] bitcoin_rs_consensus::primitives::DecodeError),
            #[error("consensus error: {0}")]
            Consensus(#[from] bitcoin_rs_consensus::ConsensusError),
            #[error("script flags error: {0}")]
            ScriptFlags(#[from] bitcoin_rs_consensus::script::ScriptError),
            #[cfg(feature = "kernel")]
            #[error("kernel error: {0}")]
            Kernel(#[from] bitcoinkernel::KernelError),
            #[error("try-from-int error: {0}")]
            TryFromInt(#[from] core::num::TryFromIntError),
            #[error("try-from-slice error: {0}")]
            TryFromSlice(#[from] core::array::TryFromSliceError),
            #[error("tx hex does not decode for {path}: {source}")]
            TxHex {
                path: String,
                source: bitcoin_rs_consensus::primitives::DecodeError,
            },
            #[error("txid mismatch for {path}: manifest says {expected} but hashes to {actual}")]
            TxidMismatch {
                path: String,
                expected: String,
                actual: String,
            },
            #[error("wtxid mismatch for {path}: manifest says {expected} but hashes to {actual}")]
            WtxidMismatch {
                path: String,
                expected: String,
                actual: String,
            },
            #[error("prevout mismatch for {path}: {prevouts} prevouts for {inputs} inputs")]
            PrevoutMismatch {
                path: String,
                prevouts: usize,
                inputs: usize,
            },
            #[cfg(feature = "kernel")]
            #[error("vector row {row}: {fault}")]
            Row { row: usize, fault: RowFault },
            #[cfg(feature = "kernel")]
            #[error("vector row {row}: tx does not decode: {source}")]
            RowDecode {
                row: usize,
                source: bitcoin_rs_consensus::primitives::DecodeError,
            },
            #[cfg(feature = "kernel")]
            #[error("vector row {row}: missing prevout for input {outpoint:?}")]
            RowMissingPrevout { row: usize, outpoint: OutPoint },
            #[cfg(feature = "kernel")]
            #[error("flags {names} are not a filled combination")]
            UnfilledFlags { names: RowFlagNames },
            #[cfg(feature = "kernel")]
            #[error("unknown opcode token: {token}")]
            UnknownOpcode { token: TokenText },
            #[cfg(feature = "kernel")]
            #[error("interpreter failed on input {input}: {source}")]
            Interpreter {
                input: usize,
                #[source]
                source: bitcoin_rs_consensus::script::ScriptError,
            },
            #[cfg(feature = "kernel")]
            #[error("interpreter rejected input {input}")]
            InterpreterRejected { input: usize },
            #[cfg(feature = "kernel")]
            #[error("kernel oracle failed on the {fault} fixture")]
            Oracle { fault: OracleFault },
            #[error("zero vectors loaded for {0}: gate is vacuous")]
            VacuousVectors(&'static str),
            #[error("missing expected value: {0}")]
            Missing(&'static str),
        }

        impl From<&'static str> for TestError {
            fn from(msg: &'static str) -> Self {
                Self::Missing(msg)
            }
        }

        #[cfg(feature = "kernel")]
        #[derive(Debug)]
        pub(crate) enum RowFault {
            NotText(&'static str),
            NotArray(&'static str),
            NotInteger(&'static str),
            OutOfRange(&'static str),
        }

        #[cfg(feature = "kernel")]
        impl std::fmt::Display for RowFault {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::NotText(what) => write!(formatter, "{what} should be text"),
                    Self::NotArray(what) => write!(formatter, "{what} should be an array"),
                    Self::NotInteger(what) => write!(formatter, "{what} should be an integer"),
                    Self::OutOfRange(what) => write!(formatter, "{what} does not fit"),
                }
            }
        }

        #[cfg(feature = "kernel")]
        #[derive(Debug)]
        pub(crate) struct RowFlagNames(pub(crate) &'static str);

        #[cfg(feature = "kernel")]
        impl std::fmt::Display for RowFlagNames {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.0)
            }
        }

        #[cfg(feature = "kernel")]
        #[derive(Debug)]
        pub(crate) struct TokenText(pub(crate) String);

        #[cfg(feature = "kernel")]
        impl std::fmt::Display for TokenText {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        #[cfg(feature = "kernel")]
        #[derive(Debug)]
        pub(crate) enum OracleFault {
            PristineKernel,
            TamperedKernel,
        }

        #[cfg(feature = "kernel")]
        impl std::fmt::Display for OracleFault {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(match self {
                    Self::PristineKernel => "pristine taproot script-path",
                    Self::TamperedKernel => "tampered taproot script-path",
                })
            }
        }
    }
    pub(crate) mod primitives {
        pub(crate) mod error {
            #[derive(Debug, thiserror::Error)]
            pub(crate) enum TestError {
                #[error("decode error: {0}")]
                Decode(#[from] bitcoin_rs_consensus::primitives::DecodeError),
                #[error("hash error: {0}")]
                Hash(#[from] bitcoin_rs_consensus::primitives::HashError),
                #[error("io error: {0}")]
                Io(#[from] std::io::Error),
                #[error("utf8 error: {0}")]
                Utf8(#[from] std::string::FromUtf8Error),
                #[error("json error: {0}")]
                Json(#[from] sonic_rs::Error),
                #[error(
                    "missing fixture {height}.{extension}; run scripts/fetch-golden.sh to populate testdata"
                )]
                MissingFixture {
                    height: u32,
                    extension: &'static str,
                },
                #[error("missing expected value: {0}")]
                Missing(&'static str),
                #[error("integer conversion: {0}")]
                TryFromInt(#[from] std::num::TryFromIntError),
            }

            impl From<&'static str> for TestError {
                fn from(msg: &'static str) -> Self {
                    Self::Missing(msg)
                }
            }
        }
        pub(crate) use error::TestError;
    }
}
mod validation_engine {
    use bitcoin_rs_consensus::kernel::BlockParse;
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence, Tx,
        TxIn, TxOut, Txid, Witness, consensus_bytes,
    };
    use bitcoin_rs_consensus::script::opcode::OP_EQUAL;
    use bitcoin_rs_consensus::script::{VerifyFlags, push_int};
    #[cfg(feature = "kernel")]
    use bitcoin_rs_consensus::{BlockView, ScriptStageTimings, verify_block_input_scripts};
    use bitcoin_rs_consensus::{ConsensusError, UtxoView, ValidationEngine, verify_transaction};

    struct Coins(hashbrown::HashMap<OutPoint, TxOut>);

    impl UtxoView for Coins {
        fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
            self.0.get(outpoint).cloned()
        }
    }

    fn mismatched_equal_spend() -> (Tx, Coins) {
        let outpoint = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[8; 32])),
            vout: 0,
        };
        let tx = Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: [push_int(7), push_int(8)].concat().into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::new(),
            }],
        };
        let prevout = TxOut {
            value: Amount::from_sat(100),
            script_pubkey: vec![OP_EQUAL].into(),
        };
        let coins = Coins(hashbrown::HashMap::from([(outpoint, prevout)]));
        (tx, coins)
    }

    fn single_tx_block(tx: &Tx) -> Block {
        Block {
            header: Header {
                version: 1,
                bits: CompactTarget::from_consensus(0x2000_ffff),
                ..Header::default()
            },
            txs: vec![tx.clone()],
        }
    }

    #[cfg(feature = "kernel")]
    fn script_reason(result: Result<(), ConsensusError>) -> String {
        match result {
            Err(ConsensusError::Script { reason, .. }) => reason,
            other => panic!("expected a script verdict, got {other:?}"),
        }
    }

    #[test]
    #[cfg(feature = "kernel")]
    fn native_engine_remains_available_when_kernel_is_compiled() {
        let (tx, coins) = mismatched_equal_spend();

        let native = verify_transaction(
            &tx,
            &coins,
            0,
            0,
            VerifyFlags::MANDATORY,
            ValidationEngine::Native,
            None,
        );
        let native_reason = script_reason(native);
        assert!(
            native_reason.starts_with("script failed:"),
            "native engine must run the interpreter, got {native_reason}"
        );

        let kernel = verify_transaction(
            &tx,
            &coins,
            0,
            0,
            VerifyFlags::MANDATORY,
            ValidationEngine::Kernel,
            None,
        );
        let kernel_reason = script_reason(kernel);
        assert!(
            kernel_reason.starts_with("kernel script verification failed:"),
            "kernel engine must run the kernel, got {kernel_reason}"
        );

        let block = single_tx_block(&tx);
        let parsed = BlockParse::parse(&consensus_bytes(&block), ValidationEngine::Native)
            .unwrap_or_else(|error| panic!("native parse: {error}"));
        let (parsed, facts) = parsed
            .into_parts(&block.txs)
            .unwrap_or_else(|error| panic!("native facts: {error}"));
        let mut view = BlockView::from_facts(&block.txs, facts);
        view.set_resolved(vec![vec![coins.lookup(&tx.inputs[0].previous_output)]]);
        let native_block = verify_block_input_scripts(
            &mut view,
            0,
            0,
            VerifyFlags::MANDATORY,
            &mut ScriptStageTimings::default(),
            &parsed,
            None,
        );
        assert!(
            script_reason(native_block).starts_with("script failed:"),
            "native engine must run the interpreter on the block seam"
        );
    }

    #[test]
    #[cfg(not(feature = "kernel"))]
    fn kernel_engine_fails_closed_without_the_kernel_feature() {
        let (tx, coins) = mismatched_equal_spend();

        let tx_verdict = verify_transaction(
            &tx,
            &coins,
            0,
            0,
            VerifyFlags::MANDATORY,
            ValidationEngine::Kernel,
            None,
        );
        match tx_verdict {
            Err(ConsensusError::UnsupportedEngine { engine }) => {
                assert_eq!(engine, ValidationEngine::Kernel);
            }
            other => panic!("kernel engine must fail closed without the feature, got {other:?}"),
        }

        let coinbase = Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![1, 1].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::new(),
            }],
        };
        match verify_transaction(
            &coinbase,
            &coins,
            0,
            0,
            VerifyFlags::MANDATORY,
            ValidationEngine::Kernel,
            None,
        ) {
            Err(ConsensusError::UnsupportedEngine { engine }) => {
                assert_eq!(engine, ValidationEngine::Kernel);
            }
            other => {
                panic!("coinbase under kernel must fail closed without the feature, got {other:?}")
            }
        }

        let block = single_tx_block(&tx);
        match BlockParse::parse(&consensus_bytes(&block), ValidationEngine::Kernel) {
            Err(ConsensusError::UnsupportedEngine { engine }) => {
                assert_eq!(engine, ValidationEngine::Kernel);
            }
            other => panic!("kernel parse must fail closed without the feature, got {other:?}"),
        }
    }

    #[test]
    fn prevout_count_mismatch_is_rejected_under_every_engine() {
        let (tx, coins) = mismatched_equal_spend();
        let one_prevout = coins.0.into_iter().collect::<Vec<_>>();

        let engines = ValidationEngine::ALL
            .iter()
            .copied()
            .filter(|engine| engine.is_supported())
            .collect::<Vec<_>>();

        for engine in engines {
            let two_input = Tx {
                version: 1,
                lock_time: LockTime::ZERO,
                inputs: vec![
                    tx.inputs[0].clone(),
                    TxIn {
                        previous_output: OutPoint {
                            txid: Txid(Hash256::from_le_bytes(&[9; 32])),
                            vout: 0,
                        },
                        sequence: Sequence::MAX,
                        ..TxIn::default()
                    },
                ],
                outputs: tx.outputs.clone(),
            };

            let short = bitcoin_rs_consensus::kernel::verify_tx_scripts(
                &two_input,
                &one_prevout,
                VerifyFlags::MANDATORY,
                engine,
                None,
            );
            assert!(
                matches!(
                    short,
                    Err(ConsensusError::PrevoutCount {
                        input_count: 2,
                        prevout_count: 1
                    })
                ),
                "{engine:?} must reject a short prevout slice, got {short:?}"
            );

            let mut long = one_prevout.clone();
            long.push((
                OutPoint {
                    txid: Txid(Hash256::from_le_bytes(&[10; 32])),
                    vout: 0,
                },
                TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: Script::new(),
                },
            ));
            let long = bitcoin_rs_consensus::kernel::verify_tx_scripts(
                &tx,
                &long,
                VerifyFlags::MANDATORY,
                engine,
                None,
            );
            assert!(
                matches!(
                    long,
                    Err(ConsensusError::PrevoutCount {
                        input_count: 1,
                        prevout_count: 2
                    })
                ),
                "{engine:?} must reject a long prevout slice, got {long:?}"
            );
        }
    }
}
mod vectors {
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait};
    use std::path::Path;

    use bitcoin::hex::FromHex;
    use bitcoin_rs_consensus::primitives::{
        ConsensusDecode, Hash256, SighashCache, Tx, deserialize,
    };
    use sonic_rs::Value;

    #[test]
    fn script_tests_vectors_load_and_flags_parse() {
        let root = read_json("script_tests.json");
        let rows = root
            .as_array()
            .unwrap_or_else(|| panic!("script_tests root must be array"));
        let mut total = 0usize;
        let mut parsed_flags = 0usize;
        for row in rows {
            let Some(row) = row.as_array() else {
                continue;
            };
            if row.len() < 4 {
                continue;
            }
            total = total.saturating_add(1);
            let flags_index = if row.first().is_some_and(Value::is_array) {
                3
            } else {
                2
            };
            let Some(flags) = row.get(flags_index).and_then(Value::as_str) else {
                continue;
            };
            if bitcoin_rs_consensus::script::VerifyFlags::from_core_names(flags).is_ok() {
                parsed_flags = parsed_flags.saturating_add(1);
            }
        }
        println!(
            "script_tests.json: parsed flags for {parsed_flags}/{total} runnable script vectors"
        );
        assert!(total > 0);
        assert_eq!(parsed_flags, total);
    }

    #[test]
    fn sighash_vectors_match_bitcoin_cache() {
        let root = read_json("sighash.json");
        let rows = root
            .as_array()
            .unwrap_or_else(|| panic!("sighash root must be array"));
        let mut total = 0usize;
        let mut matched = 0usize;
        let mut skipped_codeseparator = 0usize;
        for row in rows {
            let Some(row) = row.as_array() else {
                continue;
            };
            if row.len() != 5 || !row.first().is_some_and(JsonValueTrait::is_str) {
                continue;
            }
            total = total.saturating_add(1);
            let tx_hex = string_at(row, 0);
            let script_hex = string_at(row, 1);
            let input_index = usize_at(row, 2);
            let hash_type = raw_u32_at(row, 3);
            let expected = hash_at(row, 4);
            let tx: Tx = deserialize_hex(tx_hex);
            let script = decode_hex(script_hex);
            if script.contains(&0xab) {
                skipped_codeseparator = skipped_codeseparator.saturating_add(1);
                continue;
            }
            let cache = SighashCache::new(&tx);
            let actual = match cache.legacy_signature_hash(input_index, &script, hash_type) {
                Ok(hash) => hash,
                Err(error) => panic!("sighash vector should compute: {error}"),
            };
            assert_eq!(actual, expected);
            matched = matched.saturating_add(1);
        }
        println!(
            "sighash.json: matched {matched}/{total} legacy sighash vectors; skipped {skipped_codeseparator} OP_CODESEPARATOR vectors unsupported by native SighashCache"
        );
        assert!(total > 0);
        assert!(matched > 0);
    }

    fn read_json(name: &str) -> Value {
        let path = Path::new("../../testdata/consensus/vectors").join(name);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => panic!("{} should be readable: {error}", path.display()),
        };
        match sonic_rs::from_str(&text) {
            Ok(value) => value,
            Err(error) => panic!("{} should parse as JSON: {error}", path.display()),
        }
    }

    fn deserialize_hex<T: ConsensusDecode>(hex: &str) -> T {
        let bytes = decode_hex(hex);
        match deserialize(&bytes) {
            Ok(value) => value,
            Err(error) => panic!("hex consensus payload should deserialize: {error}"),
        }
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        Vec::from_hex(hex).unwrap_or_else(|error| panic!("bad hex: {error}"))
    }

    fn string_at(row: &[Value], index: usize) -> &str {
        row.get(index)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("vector column {index} should be a string"))
    }

    fn usize_at(row: &[Value], index: usize) -> usize {
        let value = row
            .get(index)
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("vector column {index} should be an unsigned integer"));
        usize::try_from(value)
            .unwrap_or_else(|error| panic!("usize vector column should fit: {error}"))
    }

    fn raw_u32_at(row: &[Value], index: usize) -> u32 {
        let value = row
            .get(index)
            .and_then(Value::as_i64)
            .unwrap_or_else(|| panic!("vector column {index} should be an integer"));
        let signed = i32::try_from(value)
            .unwrap_or_else(|error| panic!("hash type should fit i32: {error}"));
        u32::from_ne_bytes(signed.to_ne_bytes())
    }

    fn hash_at(row: &[Value], index: usize) -> Hash256 {
        Hash256::from_str_be(string_at(row, index))
            .unwrap_or_else(|error| panic!("sighash vector result should parse: {error}"))
    }
}
mod witness_commitment_rules {
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, Hash256, Header, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
        Txid, Witness,
    };
    use bitcoin_rs_consensus::verify_block::{
        BlockRuleContext, verify_block_rules, verify_block_rules_precomputed,
    };
    use bitcoin_rs_consensus::{
        BlockFacts, BlockView, ConsensusError, check_block_body_binding, compute_merkle_root,
    };

    const PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    const ZERO_RESERVED_COMMITMENT: [u8; 32] = [
        0xe2, 0xf6, 0x1c, 0x3f, 0x71, 0xd1, 0xde, 0xfd, 0x3f, 0xa9, 0x99, 0xdf, 0xa3, 0x69, 0x53,
        0x75, 0x5c, 0x69, 0x06, 0x89, 0x79, 0x99, 0x62, 0xb4, 0x8b, 0xeb, 0xd8, 0x36, 0x97, 0x4e,
        0x8c, 0xf9,
    ];

    fn coinbase(witness_size: Option<usize>, commitment: Option<[u8; 32]>) -> Tx {
        let mut tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![1, 1]),
                sequence: Sequence::MAX,
                witness: witness_size.map_or_else(Witness::new, |size| {
                    Witness::from_stack(vec![vec![0; size]])
                }),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::new(),
            }],
            lock_time: LockTime::ZERO,
        };
        if let Some(commitment) = commitment {
            tx.outputs.push(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: Script::from_bytes([PREFIX.as_slice(), &commitment].concat()),
            });
        }
        tx
    }

    fn block(txs: Vec<Tx>, merkle_root: Hash256) -> Block {
        Block {
            header: Header {
                version: 1,
                merkle_root,
                ..Header::default()
            },
            txs,
        }
    }

    fn single(tx: Tx) -> Block {
        let root = tx.txid().into();
        block(vec![tx], root)
    }

    fn rules(block: &Block, context: BlockRuleContext) -> Result<(), ConsensusError> {
        if context.segwit_active {
            return verify_block_rules(block);
        }
        let txids = block.txs.iter().map(Tx::txid).collect();
        let mut view = BlockView::from_facts(&block.txs, BlockFacts::from_txids(&block.txs, txids));
        if view.facts().has_witness() {
            let _ = view.witness_ids();
        }
        verify_block_rules_precomputed(block, context, view.facts())
    }

    #[test]
    fn staging_gate_and_block_rules_agree_on_witness_commitment_shapes() {
        use ConsensusError::{UnexpectedWitness, WitnessCommitment, WitnessNonceSize};
        let zero = Some(ZERO_RESERVED_COMMITMENT);
        let cases = [
            (None, zero, true, Err(WitnessNonceSize)),
            (Some(31), zero, true, Err(WitnessNonceSize)),
            (Some(33), zero, true, Err(WitnessNonceSize)),
            (Some(32), Some([0xff; 32]), true, Err(WitnessCommitment)),
            (Some(32), zero, true, Ok(())),
            (None, None, true, Ok(())),
            (Some(32), None, true, Err(UnexpectedWitness)),
            (None, zero, false, Ok(())),
            (None, None, false, Ok(())),
            (Some(32), zero, false, Err(UnexpectedWitness)),
            (Some(32), None, false, Err(UnexpectedWitness)),
        ];
        for (witness, commitment, active, expected) in cases {
            let block = single(coinbase(witness, commitment));
            let shape = format!("witness={witness:?} commitment={commitment:?} active={active}");
            let context = BlockRuleContext {
                segwit_active: active,
            };
            assert_eq!(
                check_block_body_binding(&block, context),
                expected,
                "gate {shape}"
            );
            assert_eq!(rules(&block, context), expected, "rules {shape}");
        }
    }

    #[test]
    fn witness_without_commitment_is_unexpected_even_outside_coinbase() {
        let txs = vec![
            coinbase(None, None),
            Tx {
                version: 1,
                lock_time: LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid(Hash256::from_le_bytes(&[1; 32])),
                        vout: 0,
                    },
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::from_stack(vec![vec![1]]),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: Script::new(),
                }],
            },
        ];
        let mut leaves = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
        let Some(root) = compute_merkle_root(&mut leaves) else {
            panic!("two transactions must have a Merkle root");
        };
        let block = block(txs, Hash256::from_le_bytes(&root));
        for active in [false, true] {
            let context = BlockRuleContext {
                segwit_active: active,
            };
            assert_eq!(
                check_block_body_binding(&block, context),
                Err(ConsensusError::UnexpectedWitness)
            );
            assert_eq!(
                rules(&block, context),
                Err(ConsensusError::UnexpectedWitness)
            );
        }
    }

    #[test]
    fn altered_non_witness_transaction_is_rejected() {
        let mut malformed = single(coinbase(None, None));
        let expected_hash = malformed.block_hash();
        malformed.txs[0].outputs[0].value = Amount::from_sat(49);
        assert_eq!(malformed.block_hash(), expected_hash);
        assert_eq!(
            check_block_body_binding(
                &malformed,
                BlockRuleContext {
                    segwit_active: true
                }
            ),
            Err(ConsensusError::MerkleRoot)
        );
    }

    #[test]
    fn merkle_mutation_is_rejected() {
        let tx = coinbase(None, None);
        let mut leaves = vec![*tx.txid().as_bytes(); 2];
        let Some(root) = compute_merkle_root(&mut leaves) else {
            panic!("two leaves must have a Merkle root");
        };
        let mutated = block(vec![tx.clone(), tx], Hash256::from_le_bytes(&root));
        assert_eq!(
            check_block_body_binding(
                &mutated,
                BlockRuleContext {
                    segwit_active: true
                }
            ),
            Err(ConsensusError::MerkleMutation)
        );
    }
}
mod witness_sigop_activation {
    use bitcoin::hashes::{Hash as _, sha256};
    use bitcoin_rs_consensus::kernel::{BlockParse, BlockScriptSource};
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence, Tx,
        TxIn, TxOut, Txid, Witness, consensus_bytes,
    };
    use bitcoin_rs_consensus::script::{VerifyFlags, opcode};
    use bitcoin_rs_consensus::verify_tx::{
        BlockScriptChecks, prepare_block_script_checks, verify_prepared_units,
    };
    use bitcoin_rs_consensus::{
        BlockFacts, BlockView, ConsensusError, MAX_BLOCK_SIGOPS_COST, UtxoView, ValidationEngine,
        transaction_sigop_cost, verify_transaction, verify_transaction_non_script,
    };

    const BIP141_SIGOP_LIMIT: u32 = 80_000;
    const SIGOPS_PER_INPUT: u32 = 199;

    struct WitnessFixture {
        tx: Tx,
        prevouts: Vec<(OutPoint, TxOut)>,
    }

    impl WitnessFixture {
        fn new(sigops: u32) -> Self {
            let mut inputs = Vec::new();
            let mut prevouts = Vec::new();
            for vout in 0..sigops.div_ceil(SIGOPS_PER_INPUT) {
                let mut script = vec![0x00, opcode::OP_IF];
                let input_sigops = (sigops - vout * SIGOPS_PER_INPUT).min(SIGOPS_PER_INPUT);
                script.extend((0..input_sigops).map(|_| opcode::OP_CHECKSIG));
                script.extend_from_slice(&[opcode::OP_ENDIF, opcode::OP_PUSHNUM_1]);
                let mut script_pubkey = vec![0x00, 0x20];
                script_pubkey.extend_from_slice(sha256::Hash::hash(&script).as_byte_array());
                let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[7; 32])), vout);
                inputs.push(TxIn {
                    previous_output: outpoint,
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::from_stack(vec![script]),
                });
                prevouts.push((
                    outpoint,
                    TxOut {
                        value: Amount::from_sat(1),
                        script_pubkey: Script::from_bytes(script_pubkey),
                    },
                ));
            }
            Self {
                tx: Tx {
                    version: 2,
                    inputs,
                    outputs: vec![TxOut {
                        value: Amount::from_sat(1),
                        script_pubkey: Script::from_bytes(vec![opcode::OP_PUSHNUM_1]),
                    }],
                    lock_time: LockTime::ZERO,
                },
                prevouts,
            }
        }

        fn block(&self, engine: ValidationEngine) -> Result<BlockScriptSource, ConsensusError> {
            let block = Block {
                header: Header {
                    version: 1,
                    bits: CompactTarget::from_consensus(0x2000_ffff),
                    ..Header::default()
                },
                txs: vec![self.tx.clone()],
            };
            BlockParse::parse(&consensus_bytes(&block), engine)?
                .into_parts(&block.txs)
                .map(|(source, _)| source)
        }

        fn prepare<'b>(
            &'b self,
            flags: VerifyFlags,
            block: &'b BlockScriptSource,
        ) -> Result<BlockScriptChecks<'b>, ConsensusError> {
            let txs = core::slice::from_ref(&self.tx);
            let mut view =
                BlockView::from_facts(txs, BlockFacts::from_txids(txs, vec![self.tx.txid()]));
            let resolved = self
                .prevouts
                .iter()
                .map(|(_, coin)| Some(coin.clone()))
                .collect();
            view.set_resolved(vec![resolved]);
            prepare_block_script_checks(&mut view, 0, 0, flags, block, None)
        }
    }

    impl UtxoView for WitnessFixture {
        fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
            self.prevouts
                .iter()
                .find(|(candidate, _)| candidate == outpoint)
                .map(|(_, coin)| coin.clone())
        }
    }

    fn engines() -> Vec<ValidationEngine> {
        ValidationEngine::ALL
            .iter()
            .copied()
            .filter(|engine| engine.is_supported())
            .collect()
    }

    #[test]
    fn implied_witness_flags_reach_standalone_and_prepared_scripts() -> Result<(), ConsensusError> {
        for engine in engines() {
            let mut fixture = WitnessFixture::new(1);
            fixture.tx.inputs[0].witness = with_item(&fixture.tx.inputs[0].witness, 0, |item| {
                item.push(opcode::OP_PUSHNUM_1);
            });
            let block = fixture.block(engine)?;
            for (flags, witness_active) in [
                (VerifyFlags::NONE, false),
                (VerifyFlags::P2SH, false),
                (VerifyFlags::WITNESS, true),
                (VerifyFlags::CLEANSTACK, true),
                (VerifyFlags::MANDATORY, true),
                (VerifyFlags::STANDARD, true),
            ] {
                assert_eq!(
                    transaction_sigop_cost(&fixture.tx, &fixture.prevouts, flags),
                    u32::from(witness_active),
                );
                let unit = fixture.prepare(flags, &block)?;
                let single = verify_transaction(&fixture.tx, &fixture, 0, 0, flags, engine, None);
                let batched = verify_prepared_units(core::slice::from_ref(&unit))
                    .map_err(|failure| failure.error);
                for verdict in [single, batched] {
                    if witness_active {
                        assert!(matches!(
                            verdict,
                            Err(ConsensusError::Script { input_index: 0, .. })
                        ));
                    } else {
                        assert_eq!(verdict, Ok(()));
                    }
                }
                assert_eq!(
                    verify_transaction_non_script(&fixture.tx, &fixture, 0, 0, flags),
                    Ok(()),
                );
            }
        }
        Ok(())
    }

    #[test]
    fn valid_witness_scripts_enforce_the_inclusive_sigop_limit() -> Result<(), ConsensusError> {
        assert_eq!(MAX_BLOCK_SIGOPS_COST, BIP141_SIGOP_LIMIT);
        for engine in engines() {
            for cost in [BIP141_SIGOP_LIMIT, BIP141_SIGOP_LIMIT + 1] {
                let fixture = WitnessFixture::new(cost);
                let block = fixture.block(engine)?;
                for (flags, witness_active) in [
                    (VerifyFlags::P2SH, false),
                    (VerifyFlags::WITNESS, true),
                    (VerifyFlags::CLEANSTACK, true),
                    (VerifyFlags::MANDATORY, true),
                    (VerifyFlags::STANDARD, true),
                ] {
                    let expected = if witness_active && cost > BIP141_SIGOP_LIMIT {
                        Err(ConsensusError::SigopsLimit {
                            cost,
                            max: BIP141_SIGOP_LIMIT,
                        })
                    } else {
                        Ok(())
                    };
                    assert_eq!(
                        transaction_sigop_cost(&fixture.tx, &fixture.prevouts, flags),
                        if witness_active { cost } else { 0 },
                    );
                    assert_eq!(
                        verify_transaction_non_script(&fixture.tx, &fixture, 0, 0, flags),
                        expected,
                    );
                    assert_eq!(
                        verify_transaction(&fixture.tx, &fixture, 0, 0, flags, engine, None),
                        expected,
                    );
                    let unit = fixture.prepare(flags, &block)?;
                    assert_eq!(
                        verify_prepared_units(core::slice::from_ref(&unit))
                            .map_err(|failure| failure.error),
                        expected,
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn mixed_activation_units_keep_their_own_sigop_context() -> Result<(), ConsensusError> {
        let cost = BIP141_SIGOP_LIMIT + 1;
        for engine in engines() {
            let fixture = WitnessFixture::new(cost);
            let block = fixture.block(engine)?;
            for active_index in [0, 1] {
                let inactive = fixture.prepare(VerifyFlags::P2SH, &block)?;
                let active = fixture.prepare(VerifyFlags::CLEANSTACK, &block)?;
                let mut units = [inactive, active];
                if active_index == 0 {
                    units.swap(0, 1);
                }
                match verify_prepared_units(&units) {
                    Err(failure) => {
                        assert_eq!(failure.unit, active_index);
                        assert_eq!(
                            failure.error,
                            ConsensusError::SigopsLimit {
                                cost,
                                max: BIP141_SIGOP_LIMIT,
                            },
                        );
                    }
                    Ok(()) => panic!("the witness-active unit must reject cost {cost}"),
                }
            }
        }
        Ok(())
    }

    fn with_item(witness: &Witness, index: usize, edit: impl FnOnce(&mut Vec<u8>)) -> Witness {
        let mut stack: Vec<Vec<u8>> = witness.iter().map(<[u8]>::to_vec).collect();
        edit(&mut stack[index]);
        Witness::from_stack(stack)
    }
}
