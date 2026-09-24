use bitcoin_rs_chain::{BlockTree, ChainTxCount, NodeStatus, TipSnapshot};
use bitcoin_rs_primitives::{
    Amount, BlockHash, CompactTarget, Hash256, Header, OutPoint, TxOut, Txid, consensus_bytes,
};
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};

use super::{JournalRecord, JournalReplayError, Mutation, replay_records, validate_replayed_head};
use bitcoin_rs_storage::chainstate_journal::Coin;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type BaseState = (BlockTree, UtxoSet, CoinStats, TipSnapshot, Coin);

fn header(prev_blockhash: BlockHash, marker: u8, time: u32) -> Header {
    let mut merkle = [0_u8; 32];
    merkle[0] = marker;
    Header {
        version: 1,
        prev_blockhash,
        merkle_root: Hash256::from_le_bytes(&merkle),
        time,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: u32::from(marker),
    }
}

fn raw_header(header: &Header) -> [u8; 80] {
    let encoded = consensus_bytes(header);
    assert_eq!(encoded.len(), 80, "consensus header length changed");
    let mut raw = [0_u8; 80];
    raw.copy_from_slice(&encoded);
    raw
}

fn coin(marker: u8, height: u32, value: u64) -> Coin {
    Coin {
        outpoint: OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0),
        txout: TxOut {
            value: Amount::from_sat(value),
            script_pubkey: vec![0x51].into(),
        },
        height,
        coinbase: true,
    }
}

fn base_state() -> TestResult<BaseState> {
    let mut tree = BlockTree::new();
    let base_header = header(BlockHash::default(), 1, 1);
    let base_id = tree.insert_node(None, base_header, NodeStatus::HeaderValid)?;
    tree.restore_chain_tx_count(base_id, ChainTxCount::established(1))?;
    let base_node = tree.node(base_id)?;
    let base_tip = TipSnapshot {
        tip_id: base_id,
        height: base_node.height,
        chainwork: base_node.chainwork,
        hash: base_node.hash,
        chain_tx_count: base_node.chain_tx_count,
    };

    let base_coin = coin(1, 0, 50);
    let listener = CoinStatsListener::new(CoinStats::default());
    let mut utxo = UtxoSet::new();
    utxo.track_coin_stats(listener.clone());
    let mut changes = BlockChanges::with_capacity(1, 0);
    changes.add(UtxoAdd::new(
        base_coin.outpoint,
        &base_coin.txout,
        base_coin.coinbase,
        base_coin.height,
    ));
    bitcoin_rs_utxo::contract::commit_block_changes(&utxo, &changes, &base_tip.hash)?;
    listener.finish_block(0, 1);
    Ok((tree, utxo, listener.snapshot(), base_tip, base_coin))
}

#[test]
fn replayed_frontier_must_match_the_durable_head_identity() -> TestResult {
    let (tree, utxo, coin_stats, base_tip, _) = base_state()?;
    let next_header = header(BlockHash(base_tip.hash), 2, 2);
    let next_hash = next_header.compute_hash();
    let record = JournalRecord {
        height: 1,
        block_hash: next_hash.0.to_le_bytes(),
        prev_hash: base_tip.hash.to_le_bytes(),
        block_tx_count: 2,
        coin_stats_height_delta: 1,
        raw_header: raw_header(&next_header),
        mutations: Vec::new(),
    };
    let replayed = replay_records(vec![record], tree, utxo, coin_stats, base_tip, 1)?;

    validate_replayed_head(
        &replayed,
        replayed.applied_tip.height,
        replayed.applied_tip.hash.to_le_bytes(),
    )?;
    assert!(
        validate_replayed_head(
            &replayed,
            replayed.applied_tip.height + 1,
            replayed.applied_tip.hash.to_le_bytes(),
        )
        .is_err()
    );
    let mut wrong_hash = replayed.applied_tip.hash.to_le_bytes();
    wrong_hash[0] ^= 0xff;
    assert!(validate_replayed_head(&replayed, replayed.applied_tip.height, wrong_hash).is_err());
    Ok(())
}

#[test]
fn replay_extends_checkpoint_state_and_returns_valid_tip() -> TestResult {
    let (tree, utxo, coin_stats, base_tip, base_coin) = base_state()?;
    let next_header = header(BlockHash(base_tip.hash), 2, 2);
    let next_hash = next_header.compute_hash();
    let new_coin = coin(2, 1, 25);
    let record = JournalRecord {
        height: 1,
        block_hash: next_hash.0.to_le_bytes(),
        prev_hash: base_tip.hash.to_le_bytes(),
        block_tx_count: 2,
        coin_stats_height_delta: 1,
        raw_header: raw_header(&next_header),
        mutations: vec![Mutation::Create {
            coin: new_coin.clone(),
        }],
    };

    let replayed = replay_records(vec![record], tree, utxo, coin_stats, base_tip, 1)?;

    assert!(replayed.utxo.get_entry(&base_coin.outpoint).is_some());
    assert!(replayed.utxo.get_entry(&new_coin.outpoint).is_some());
    assert_eq!(replayed.chain_tx_count, 3);
    assert_eq!(replayed.coin_stats.height, 1);
    assert_eq!(replayed.coin_stats.tx_count, 3);
    assert_eq!(replayed.applied_tip.height, 1);
    assert_eq!(replayed.applied_tip.hash, next_hash.0);
    let node = replayed.tree.node(replayed.applied_tip.tip_id)?;
    assert_eq!(node.hash, replayed.applied_tip.hash);
    assert_eq!(node.chainwork, replayed.applied_tip.chainwork);
    Ok(())
}

#[test]
fn replay_requires_each_record_to_extend_the_replayed_tip() -> TestResult {
    for stale_parent in [false, true] {
        let (tree, utxo, coin_stats, base_tip, _) = base_state()?;
        let first = header(BlockHash(base_tip.hash), 2, 2);
        let parent = if stale_parent {
            BlockHash(base_tip.hash)
        } else {
            first.compute_hash()
        };
        let second = header(parent, 3, 3);
        let expected_hash = second.compute_hash().0;
        let records = [first, second]
            .into_iter()
            .zip(1_u32..=2)
            .map(|(header, height)| JournalRecord {
                height,
                block_hash: header.compute_hash().0.to_le_bytes(),
                prev_hash: header.prev_blockhash.0.to_le_bytes(),
                block_tx_count: 2,
                coin_stats_height_delta: 1,
                raw_header: raw_header(&header),
                mutations: Vec::new(),
            })
            .collect();

        let result = replay_records(records, tree, utxo, coin_stats, base_tip, 1);
        if stale_parent {
            assert!(matches!(
                result,
                Err(JournalReplayError::CommittedRangeInvalid(reason))
                    if reason == "record 2 header identity does not match its chain fields"
            ));
        } else {
            let replayed = result?;
            assert_eq!(replayed.applied_tip.hash, expected_hash);
            assert_eq!(replayed.applied_tip.height, 2);
            assert_eq!(replayed.chain_tx_count, 5);
            assert_eq!(replayed.coin_stats.height, 2);
            assert_eq!(replayed.coin_stats.tx_count, 5);
        }
    }
    Ok(())
}
