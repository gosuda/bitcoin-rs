use bitcoin::hashes::Hash as _;
use bitcoin_rs_consensus::bip34::check_bip34;
use bitcoin_rs_consensus::bip68::{check_sequence_lock, sequence_lock_satisfied};
use bitcoin_rs_consensus::verify_block::{
    MAX_BLOCK_WEIGHT, is_sixty_four_byte_mutation, verify_block_non_contextual, verify_block_rules,
    verify_merkle_root_with_txids,
};
use bitcoin_rs_consensus::verify_tx::{is_final_tx, verify_coinbase_script_sig_size};
use bitcoin_rs_consensus::{
    ConsensusError, LocktimeRule, MAX_BLOCK_SIGOPS_COST, block_subsidy, locktime_cutoff,
    verify_coinbase_amount,
};
use bitcoin_rs_primitives::{
    Amount, Block, Hash256, Header, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid,
    Witness,
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
            prev_blockhash: bitcoin_rs_primitives::BlockHash::default(),
            merkle_root: root,
            time: 1_234_567_890,
            bits: bitcoin_rs_primitives::CompactTarget::from_consensus(0x207f_ffff),
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
    cb.outputs[0].script_pubkey =
        Script::from_bytes(vec![bitcoin_rs_script::opcode::OP_CHECKSIG; 20_001]);
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
    let encoded_height_100 = bitcoin_rs_script::push_int(100);
    assert_eq!(check_bip34(100, &encoded_height_100), Ok(()));

    let encoded_height_101 = bitcoin_rs_script::push_int(101);
    assert!(check_bip34(100, &encoded_height_101).is_err());
    assert!(check_bip34(100, &[]).is_err());
}

#[test]
fn bip68_relative_locktime_block_based_boundaries() {
    let sequence = 10;
    assert!(!sequence_lock_satisfied(2, sequence, 100, 0, 109, 0));
    assert!(sequence_lock_satisfied(2, sequence, 100, 0, 110, 0));
    assert!(sequence_lock_satisfied(2, sequence, 100, 0, 111, 0));

    assert_eq!(
        check_sequence_lock(2, sequence, 100, 0, 109, 0),
        Err(ConsensusError::Bip {
            bip: "BIP68",
            reason: "input sequence height-based lock unmet: prevout at height 100 + 10 blocks > current 109".to_owned()
        })
    );
    assert_eq!(check_sequence_lock(2, sequence, 100, 0, 110, 0), Ok(()));
}

#[test]
fn bip68_relative_locktime_time_based_boundaries() {
    let sequence = bitcoin_rs_primitives::SEQUENCE_LOCKTIME_TYPE_FLAG | 2;
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
    let disabled = bitcoin_rs_primitives::SEQUENCE_LOCKTIME_DISABLE_FLAG | 0x64;
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

    tx.inputs[0].sequence = Sequence::from_consensus(bitcoin_rs_primitives::SEQUENCE_FINAL);
    assert!(is_final_tx(&tx, 199, 1_000_000));

    tx.inputs[0].sequence = Sequence::from_consensus(0xffff_fffe);
    tx.lock_time = LockTime::from_consensus(bitcoin_rs_primitives::LOCKTIME_THRESHOLD + 100);
    let cutoff = bitcoin_rs_primitives::LOCKTIME_THRESHOLD + 100;
    assert!(!is_final_tx(&tx, 100, cutoff));
    assert!(is_final_tx(&tx, 100, cutoff + 1));
}

#[test]
fn locktime_cutoff_rules() {
    let prev_mtp = 1_000_000;
    let candidate = 1_000_500;
    assert_eq!(
        locktime_cutoff(LocktimeRule::MedianTimePast, prev_mtp, candidate),
        prev_mtp
    );
    assert_eq!(
        locktime_cutoff(LocktimeRule::CandidateTime, prev_mtp, candidate),
        candidate
    );
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
