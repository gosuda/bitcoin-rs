use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, Hash256, Header, LockTime, Network, OutPoint, Script, Sequence, Tx,
    TxIn, TxOut, Txid, Witness, encode::double_sha256,
};

use super::{
    BlockRuleContext, WITNESS_COMMITMENT_PREFIX, block_merkle_root_matches_txids,
    check_block_body_binding, compute_merkle_root, is_sixty_four_byte_mutation,
    merkle_root_and_mutation, merkle_root_and_mutation_borrowed, merkle_root_spine,
    verify_block_non_contextual, verify_block_rules, verify_block_rules_precomputed, verify_flags,
    verify_merkle_root_with_txids,
};
use crate::ConsensusError;
use crate::bip9::SoftforkState;
use crate::block_view::BlockFacts;
use bitcoin_rs_script::VerifyFlags;

type BindingCase = (Vec<[u8; 32]>, Vec<Vec<u8>>, Result<(), ConsensusError>);

fn coinbase_tx() -> Tx {
    Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(vec![1, 1]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn spend_tx(seed: u8, witness: Vec<Vec<u8>>) -> Tx {
    let mut tx = coinbase_tx();
    tx.inputs[0].previous_output = OutPoint::new(Txid(Hash256::from_le_bytes(&[seed; 32])), 0);
    tx.inputs[0].script_sig = Script::new();
    tx.inputs[0].witness = Witness::from_stack(witness);
    tx.outputs[0].value = Amount::from_sat(1);
    tx
}

fn witness_spend_tx() -> Tx {
    spend_tx(2, vec![vec![1; 32]])
}

fn sized_spend_tx(seed: u8, script_len: usize, witness: Vec<Vec<u8>>) -> Tx {
    let mut tx = spend_tx(seed, witness);
    tx.outputs[0].script_pubkey = Script::from_bytes(vec![0x51; script_len]);
    tx
}

fn sixty_four_byte_tx(seed: u8, witness: Vec<Vec<u8>>) -> Tx {
    let tx = sized_spend_tx(seed, 4, witness);
    assert_eq!(tx.base_size(), 64, "fixture must be a Merkle node's size");
    tx
}

fn sixty_four_byte_coinbase() -> Tx {
    let mut tx = coinbase_tx();
    tx.inputs[0].script_sig = Script::from_bytes(vec![1; 4]);
    assert_eq!(tx.base_size(), 64, "fixture must be a Merkle node's size");
    tx
}

fn block_with_transactions(txs: Vec<Tx>) -> Block {
    let mut hashes: Vec<Txid> = txs.iter().map(Tx::txid).collect();
    let Some((root, _)) = merkle_root_and_mutation(&mut hashes) else {
        panic!("block should have merkle root");
    };
    Block {
        header: header_with(root.into()),
        txs,
    }
}

fn header_with(merkle_root: Hash256) -> Header {
    Header {
        version: 1,
        merkle_root,
        ..Header::default()
    }
}

fn check_block_rules(block: &Block, context: BlockRuleContext) -> Result<(), ConsensusError> {
    let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
    let mut facts = BlockFacts::from_txids(&block.txs, txids);
    if facts.has_witness() {
        facts.or_insert_wtxids_from(&block.txs);
    }
    verify_block_rules_precomputed(block, context, &facts)
}

#[test]
fn non_contextual_checks_reject_invalid_transactions_with_valid_merkle_roots() {
    type Case = (fn(&mut Vec<Tx>), ConsensusError);
    let cases: &[Case] = &[
        (
            |txs| txs[0].inputs[0].previous_output = txs[1].inputs[0].previous_output,
            ConsensusError::MissingCoinbase,
        ),
        (
            |txs| txs.push(coinbase_tx()),
            ConsensusError::ExtraCoinbase { tx_index: 2 },
        ),
        (
            |txs| txs[0].inputs[0].script_sig = Script::from_bytes(vec![0]),
            ConsensusError::CoinbaseScriptSigSize { len: 1 },
        ),
        (
            |txs| txs[0].inputs[0].script_sig = Script::from_bytes(vec![0; 101]),
            ConsensusError::CoinbaseScriptSigSize { len: 101 },
        ),
        (|txs| txs[1].inputs.clear(), ConsensusError::EmptyInputs),
        (|txs| txs[1].outputs.clear(), ConsensusError::EmptyOutputs),
        (
            |txs| txs[1].outputs[0].value = Amount::from_sat(u64::MAX),
            ConsensusError::OutputValueOverflow,
        ),
        (
            |txs| {
                let output = txs[1].outputs[0].clone();
                txs[1].outputs[0].value = Amount::MAX_MONEY;
                txs[1].outputs.push(output);
            },
            ConsensusError::OutputValueOverflow,
        ),
        (
            |txs| {
                let input = txs[1].inputs[0].clone();
                txs[1].inputs.push(input);
            },
            ConsensusError::DuplicateInput { input_index: 1 },
        ),
        (
            |txs| {
                let input = txs[1].inputs[0].clone();
                txs[1].inputs.push(input);
                txs[1].inputs[0].previous_output = OutPoint::null();
            },
            ConsensusError::NullPrevout { input_index: 0 },
        ),
    ];
    assert_eq!(
        verify_block_non_contextual(&Block::default()),
        Err(ConsensusError::EmptyBlock)
    );
    for (mutate, error) in cases {
        let mut txs = vec![coinbase_tx(), spend_tx(1, vec![])];
        mutate(&mut txs);
        let block = block_with_transactions(txs);
        assert!(verify_merkle_root_with_txids(&block, &block.txids()).is_ok());
        assert_eq!(verify_block_non_contextual(&block), Err(error.clone()));
    }
}

#[test]
fn non_contextual_size_and_aggregate_legacy_sigops_have_core_boundaries() {
    let mut txs = vec![coinbase_tx(), spend_tx(1, vec![])];
    for tx in &mut txs {
        tx.outputs[0].script_pubkey =
            Script::from_bytes(vec![bitcoin_rs_script::opcode::OP_CHECKSIG; 10_000]);
    }
    assert!(verify_block_non_contextual(&block_with_transactions(txs.clone())).is_ok());
    txs[1].outputs[0].script_pubkey =
        Script::from_bytes(vec![bitcoin_rs_script::opcode::OP_CHECKSIG; 10_001]);
    assert_eq!(
        verify_block_non_contextual(&block_with_transactions(txs)),
        Err(ConsensusError::SigopsLimit {
            cost: 80_004,
            max: 80_000
        })
    );

    let mut tx = coinbase_tx();
    tx.outputs[0].script_pubkey = Script::from_bytes(vec![0; 1_000_000]);
    let excess = block_with_transactions(vec![tx.clone()]).stripped_size() - 1_000_000;
    tx.outputs[0].script_pubkey = Script::from_bytes(vec![0; 1_000_000 - excess]);
    let at_limit = block_with_transactions(vec![tx.clone()]);
    assert_eq!(at_limit.stripped_size(), 1_000_000);
    assert!(verify_block_non_contextual(&at_limit).is_ok());
    tx.outputs[0].script_pubkey = Script::from_bytes(vec![0; 1_000_001 - excess]);
    assert_eq!(
        verify_block_non_contextual(&block_with_transactions(vec![tx])),
        Err(ConsensusError::BlockBaseSize {
            size: 1_000_001,
            max: 1_000_000
        })
    );
}

#[test]
fn non_contextual_checks_do_not_apply_witness_or_chain_context() {
    let mut coinbase = coinbase_tx();
    coinbase.outputs[0].script_pubkey = Script::from_bytes(vec![0; 300_000]);
    coinbase.inputs[0].witness = Witness::from_stack(vec![vec![0; 3_000_000]]);
    let mut spend = spend_tx(1, vec![]);
    spend.lock_time = LockTime::from_consensus(499_999_999);
    spend.inputs[0].sequence = Sequence::from_consensus(0);
    let block = block_with_transactions(vec![coinbase, spend]);
    assert!(block.weight() > super::MAX_BLOCK_WEIGHT);
    assert!(verify_block_non_contextual(&block).is_ok());
    assert!(verify_block_rules(&block).is_err());
}

fn commitment_output(commitment: [u8; 32]) -> TxOut {
    let mut script = WITNESS_COMMITMENT_PREFIX.to_vec();
    script.extend_from_slice(&commitment);
    TxOut {
        value: Amount::from_sat(0),
        script_pubkey: Script::from_bytes(script),
    }
}

fn compute_witness_commitment(txs: &[Tx], reserved: &[u8]) -> [u8; 32] {
    let mut leaves: Vec<[u8; 32]> = txs
        .iter()
        .enumerate()
        .map(|(index, tx)| {
            if index == 0 {
                [0u8; 32]
            } else {
                *tx.wtxid().as_bytes()
            }
        })
        .collect();
    let root = compute_merkle_root(&mut leaves).unwrap_or([0u8; 32]);
    let mut buffer = [0u8; 64];
    buffer[..32].copy_from_slice(&root);
    buffer[32..].copy_from_slice(reserved);
    double_sha256(&buffer).to_le_bytes()
}

fn txid(seed: u8) -> Txid {
    Txid(Hash256::from_le_bytes(&[seed; 32]))
}

fn txids(count: usize) -> Vec<Txid> {
    (0..count)
        .map(|seed| match u8::try_from(seed) {
            Ok(seed) => txid(seed),
            Err(error) => panic!("test leaf count must fit u8: {error}"),
        })
        .collect()
}

fn distinct_txids(count: usize) -> Vec<Txid> {
    (0..count)
        .map(|index| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&index.to_le_bytes());
            Txid(Hash256::from_le_bytes(&bytes))
        })
        .collect()
}

fn oracle_root(leaves: &[Txid]) -> Option<[u8; 32]> {
    use bitcoin::hashes::Hash as _;
    bitcoin::merkle_tree::calculate_root(
        leaves
            .iter()
            .map(|leaf| bitcoin::Txid::from_byte_array(*leaf.as_bytes())),
    )
    .map(bitcoin::hashes::Hash::to_byte_array)
}

#[test]
fn verify_flags_follow_activation_and_the_bip16_exception() {
    let flags = verify_flags(
        Network::Mainnet,
        481_824,
        Hash256::from_le_bytes(&[0x11; 32]),
        SoftforkState {
            csv_active: true,
            segwit_active: true,
        },
    );
    for expected in [
        VerifyFlags::P2SH,
        VerifyFlags::DERSIG,
        VerifyFlags::CHECKLOCKTIMEVERIFY,
        VerifyFlags::CHECKSEQUENCEVERIFY,
        VerifyFlags::WITNESS,
        VerifyFlags::NULLDUMMY,
    ] {
        assert!(flags.contains(expected), "missing {expected:?}");
    }

    let exception = match "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
        .parse::<BlockHash>()
    {
        Ok(hash) => Hash256::from(hash),
        Err(error) => panic!("invalid BIP16 exception hash: {error}"),
    };
    let exempt = verify_flags(
        Network::Mainnet,
        170_060,
        exception,
        SoftforkState {
            csv_active: false,
            segwit_active: false,
        },
    );
    assert!(!exempt.contains(VerifyFlags::P2SH));
}

#[test]
fn structural_block_rules_hold_under_both_activation_states() {
    let duplicated = spend_tx(3, Vec::new());
    let cases: [(Vec<Tx>, Result<(), ConsensusError>); 6] = [
        (vec![coinbase_tx()], Ok(())),
        (
            vec![coinbase_tx(), coinbase_tx()],
            Err(ConsensusError::ExtraCoinbase { tx_index: 1 }),
        ),
        (
            vec![spend_tx(1, Vec::new())],
            Err(ConsensusError::MissingCoinbase),
        ),
        (
            vec![duplicated.clone(), duplicated.clone()],
            Err(ConsensusError::MissingCoinbase),
        ),
        (
            vec![
                coinbase_tx(),
                spend_tx(2, Vec::new()),
                duplicated.clone(),
                duplicated.clone(),
            ],
            Err(ConsensusError::MerkleMutation),
        ),
        (
            vec![
                coinbase_tx(),
                duplicated.clone(),
                spend_tx(5, Vec::new()),
                duplicated,
            ],
            Ok(()),
        ),
    ];

    for (txs, expected) in cases {
        let block = block_with_transactions(txs);
        for segwit_active in [false, true] {
            assert_eq!(
                check_block_rules(&block, BlockRuleContext { segwit_active }),
                expected,
                "segwit_active {segwit_active}"
            );
        }
        assert_eq!(
            verify_block_rules(&block),
            expected,
            "the public entry derives the same facts"
        );
    }
    let mut wrong = block_with_transactions(vec![coinbase_tx()]);
    wrong.header.merkle_root = Hash256::default();
    assert_eq!(
        check_block_rules(
            &wrong,
            BlockRuleContext {
                segwit_active: true
            }
        ),
        Err(ConsensusError::MerkleRoot)
    );
}

#[test]
fn witness_without_commitment_and_oversized_blocks_are_rejected() {
    let witness_block = block_with_transactions(vec![coinbase_tx(), witness_spend_tx()]);
    let mut heavy = coinbase_tx();
    heavy.inputs[0].script_sig = Script::from_bytes(vec![1; 1_000_001]);
    let heavy_block = block_with_transactions(vec![heavy]);

    for segwit_active in [false, true] {
        let context = BlockRuleContext { segwit_active };
        assert_eq!(
            check_block_rules(&witness_block, context),
            Err(ConsensusError::UnexpectedWitness),
            "segwit_active {segwit_active}"
        );
        assert!(
            matches!(
                check_block_rules(&heavy_block, context),
                Err(ConsensusError::BlockWeight { .. })
            ),
            "segwit_active {segwit_active}"
        );
    }
}

#[test]
fn mutation_fixture_sizes_count_only_stripped_bytes() {
    assert_eq!(spend_tx(1, Vec::new()).base_size(), 60);
    assert_eq!(sized_spend_tx(1, 3, Vec::new()).base_size(), 63);
    assert_eq!(sized_spend_tx(1, 4, Vec::new()).base_size(), 64);
    assert_eq!(sized_spend_tx(1, 5, Vec::new()).base_size(), 65);
    let witnessed = sized_spend_tx(1, 4, vec![vec![1; 32]]);
    assert_eq!(witnessed.base_size(), 64);
    assert!(
        witnessed.total_size() > 64,
        "witness bytes must not count toward the 64-byte test"
    );
}

#[test]
fn mutation_predicate_needs_a_missing_coinbase_and_an_exact_64_byte_tx() {
    let node = || sixty_four_byte_tx(1, Vec::new());
    let sixty = || spend_tx(2, Vec::new());
    let cases: [(Vec<Tx>, bool); 11] = [
        (Vec::new(), false),
        (vec![node()], true),
        (vec![sixty_four_byte_tx(1, vec![vec![1; 32]])], true),
        (vec![sixty(), node()], true),
        (vec![node(), sixty()], true),
        (vec![sixty()], false),
        (vec![sized_spend_tx(3, 3, Vec::new())], false),
        (vec![sized_spend_tx(3, 5, Vec::new())], false),
        (vec![coinbase_tx(), node()], false),
        (vec![sixty_four_byte_coinbase()], false),
        (vec![sixty_four_byte_coinbase(), node()], false),
    ];
    for (txs, expected) in cases {
        assert_eq!(
            is_sixty_four_byte_mutation(&txs),
            expected,
            "{} transactions, sizes {:?}",
            txs.len(),
            txs.iter().map(Tx::base_size).collect::<Vec<_>>()
        );
    }
}

fn assert_sixty_four_byte_mutation(txs: Vec<Tx>, label: &str) {
    let block = block_with_transactions(txs);
    for segwit_active in [false, true] {
        assert_eq!(
            check_block_rules(&block, BlockRuleContext { segwit_active }),
            Err(ConsensusError::SixtyFourByteMutation),
            "rules, {label}, segwit_active {segwit_active}"
        );
        assert_eq!(
            check_block_body_binding(&block, segwit_active),
            Err(ConsensusError::SixtyFourByteMutation),
            "binding, {label}, segwit_active {segwit_active}"
        );
    }
    assert_eq!(
        verify_block_rules(&block),
        Err(ConsensusError::SixtyFourByteMutation),
        "the public entry derives the same facts, {label}"
    );
}

#[test]
fn sixty_four_byte_body_without_coinbase_is_a_mutation_at_both_entry_points() {
    let witnessed = || vec![vec![1; 32]];
    assert_sixty_four_byte_mutation(vec![sixty_four_byte_tx(1, Vec::new())], "alone");
    assert_sixty_four_byte_mutation(
        vec![sixty_four_byte_tx(1, witnessed())],
        "alone with witness",
    );
    assert_sixty_four_byte_mutation(
        vec![spend_tx(2, Vec::new()), sixty_four_byte_tx(3, Vec::new())],
        "after a 60-byte transaction",
    );
    assert_sixty_four_byte_mutation(
        vec![spend_tx(2, Vec::new()), sixty_four_byte_tx(3, witnessed())],
        "after a 60-byte transaction with witness",
    );
}

#[test]
fn binding_reports_a_wrong_root_before_the_sixty_four_byte_mutation() {
    let mut block = block_with_transactions(vec![sixty_four_byte_tx(1, Vec::new())]);
    block.header.merkle_root = Hash256::from_le_bytes(&[0xff; 32]);
    for segwit_active in [false, true] {
        assert_eq!(
            check_block_body_binding(&block, segwit_active),
            Err(ConsensusError::MerkleRoot),
            "segwit_active {segwit_active}"
        );
    }
}

#[test]
fn sixty_byte_body_without_coinbase_stays_missing_coinbase_and_binds() {
    let tx = spend_tx(1, Vec::new());
    assert_eq!(tx.base_size(), 60);
    let block = block_with_transactions(vec![tx]);
    for segwit_active in [false, true] {
        assert_eq!(
            check_block_rules(&block, BlockRuleContext { segwit_active }),
            Err(ConsensusError::MissingCoinbase),
            "segwit_active {segwit_active}"
        );
        assert_eq!(
            check_block_body_binding(&block, segwit_active),
            Ok(()),
            "a coinbase-less body of another size is bound to its header"
        );
    }
    assert_eq!(
        verify_block_rules(&block),
        Err(ConsensusError::MissingCoinbase)
    );
}

#[test]
fn a_body_with_a_coinbase_is_never_a_sixty_four_byte_mutation() {
    for txs in [
        vec![coinbase_tx(), sixty_four_byte_tx(1, Vec::new())],
        vec![sixty_four_byte_coinbase()],
    ] {
        let block = block_with_transactions(txs);
        for segwit_active in [false, true] {
            assert_eq!(
                check_block_rules(&block, BlockRuleContext { segwit_active }),
                Ok(()),
                "segwit_active {segwit_active}"
            );
            assert_eq!(
                check_block_body_binding(&block, segwit_active),
                Ok(()),
                "segwit_active {segwit_active}"
            );
        }
    }
}

#[test]
fn bip141_commitment_selection_and_reserved_nonce_shape() {
    let reserved = vec![0u8; 32];
    let spend = witness_spend_tx();
    let valid = compute_witness_commitment(&[coinbase_tx(), spend.clone()], &reserved);
    let bogus = [0xff; 32];
    let nonce = vec![reserved];

    let cases: [BindingCase; 7] = [
        (vec![valid], nonce.clone(), Ok(())),
        (vec![bogus, valid], nonce.clone(), Ok(())),
        (
            vec![valid, bogus],
            nonce,
            Err(ConsensusError::WitnessCommitment),
        ),
        (
            vec![valid],
            Vec::new(),
            Err(ConsensusError::WitnessNonceSize),
        ),
        (
            vec![valid],
            vec![vec![0u8; 31]],
            Err(ConsensusError::WitnessNonceSize),
        ),
        (
            vec![valid],
            vec![vec![0u8; 33]],
            Err(ConsensusError::WitnessNonceSize),
        ),
        (
            vec![valid],
            vec![vec![0u8; 32], vec![0u8; 32]],
            Err(ConsensusError::WitnessNonceSize),
        ),
    ];

    for (commitments, witness, expected) in cases {
        let mut coinbase = coinbase_tx();
        coinbase.inputs[0].witness = Witness::from_stack(witness);
        coinbase
            .outputs
            .extend(commitments.iter().copied().map(commitment_output));
        let block = block_with_transactions(vec![coinbase, spend.clone()]);
        assert_eq!(
            check_block_rules(
                &block,
                BlockRuleContext {
                    segwit_active: true
                }
            ),
            expected
        );
    }
}

#[test]
fn every_merkle_reducer_agrees_with_the_oracle_and_on_mutation() {
    let sizes = (0..=130usize).chain([255, 256, 257, 264, 1000]);
    for leaf_count in sizes {
        for tail in 0..=2usize {
            let mut leaves = distinct_txids(leaf_count);
            if leaf_count >= 2 {
                for _ in 0..tail {
                    leaves.push(leaves[1]);
                }
            }
            let label = format!("leaf count {leaf_count} tail {tail}");
            let mut in_place = leaves.clone();
            let spine = merkle_root_spine(&leaves);
            assert_eq!(merkle_root_and_mutation(&mut in_place), spine, "{label}");
            assert_eq!(
                merkle_root_and_mutation_borrowed(&leaves),
                spine,
                "{label} production dispatch"
            );
            assert_eq!(
                spine.map(|(root, _)| *root.as_bytes()),
                oracle_root(&leaves),
                "{label} against rust-bitcoin"
            );
            let mut bytes: Vec<[u8; 32]> = leaves.iter().map(|leaf| *leaf.as_bytes()).collect();
            assert_eq!(
                compute_merkle_root(&mut bytes),
                oracle_root(&leaves),
                "{label} byte fold"
            );
        }
    }
}

#[test]
fn mutation_flags_distinguish_padding_from_real_duplicate_pairs() {
    let (a, b) = (txid(1), txid(2));
    let one_to_six: Vec<Txid> = (1u8..=6).map(txid).collect();
    let cases: [(Vec<Txid>, bool); 8] = [
        (vec![a, b, a], false),
        (vec![a, b, b, a], false),
        (vec![a, b, b], false),
        (vec![a, b, b, b], true),
        (one_to_six.clone(), false),
        ((1u8..=6).chain([5, 6]).map(txid).collect(), true),
        (vec![txid(0x2b); 3], true),
        (vec![txid(0x2b); 7], true),
    ];

    for (leaves, expected_mutated) in cases {
        let mut in_place = leaves.clone();
        let Some((root, mutated)) = merkle_root_and_mutation(&mut in_place) else {
            panic!("test Merkle tree must be nonempty");
        };
        assert_eq!(mutated, expected_mutated, "{leaves:?}");
        assert_eq!(merkle_root_spine(&leaves), Some((root, mutated)));
        assert_eq!(
            merkle_root_and_mutation_borrowed(&leaves),
            Some((root, mutated))
        );
        assert_eq!(Some(*root.as_bytes()), oracle_root(&leaves));
    }
    assert_eq!(
        oracle_root(&one_to_six),
        oracle_root(&(1u8..=6).chain([5, 6]).map(txid).collect::<Vec<_>>())
    );
}

#[test]
fn header_merkle_verification_orders_root_before_mutation() {
    let empty = Block {
        header: header_with(Hash256::default()),
        txs: Vec::new(),
    };
    assert_eq!(
        verify_merkle_root_with_txids(&empty, &[]),
        Err(ConsensusError::MerkleRoot)
    );

    let wrong = Block {
        header: header_with(Hash256::from_le_bytes(&[0xff; 32])),
        txs: Vec::new(),
    };
    for leaf_count in 1..=9usize {
        let leaves = txids(leaf_count);
        let Some((root, mutated)) = merkle_root_and_mutation_borrowed(&leaves) else {
            panic!("merkle root over a non-empty leaf set");
        };
        let matching = Block {
            header: header_with(root.into()),
            txs: Vec::new(),
        };
        assert_eq!(
            verify_merkle_root_with_txids(&matching, &leaves),
            if mutated {
                Err(ConsensusError::MerkleMutation)
            } else {
                Ok(())
            },
            "leaf count {leaf_count}"
        );
        assert_eq!(
            verify_merkle_root_with_txids(&wrong, &leaves),
            Err(ConsensusError::MerkleRoot),
            "leaf count {leaf_count}"
        );
    }

    let duplicated = vec![txid(1), txid(1)];
    let Some((root, mutated)) = merkle_root_and_mutation_borrowed(&duplicated) else {
        panic!("merkle root over duplicated leaves");
    };
    assert!(mutated);
    let mutated_block = Block {
        header: header_with(root.into()),
        txs: Vec::new(),
    };
    assert_eq!(
        verify_merkle_root_with_txids(&mutated_block, &duplicated),
        Err(ConsensusError::MerkleMutation)
    );
    assert_eq!(
        verify_merkle_root_with_txids(&wrong, &duplicated),
        Err(ConsensusError::MerkleRoot),
        "wrong root must be reported before the duplicate mutation"
    );
    assert!(block_merkle_root_matches_txids(&mutated_block, &duplicated));
    assert!(!block_merkle_root_matches_txids(&wrong, &duplicated));
    assert!(!block_merkle_root_matches_txids(&empty, &[]));
}

#[test]
fn is_coinbase_detects_null_prevout() {
    assert!(coinbase_tx().is_coinbase());
    assert!(!witness_spend_tx().is_coinbase());
    assert!(!spend_tx(1, Vec::new()).is_coinbase());
}
