//! Snapshot trailer integration tests for coinstats.
use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_coinstats::{CoinStats, CoinStatsListener};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{
    BlockChanges, UtxoAdd, UtxoChangeListener, UtxoKey, UtxoSet, write_snapshot,
};

#[test]
fn snapshot_trailer_uses_listener_muhash() -> Result<(), Box<dyn std::error::Error>> {
    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(listener.clone()));

    let mut changes = BlockChanges::default();
    for index in 0_u32..3 {
        let outpoint = OutPoint::new(txid(index), index);
        changes.add(UtxoAdd::new(outpoint, txout(index), index == 0, 7));
    }

    set.commit_block(&changes, &txid(999))?;

    let mut snapshot = Vec::new();
    let trailer = write_snapshot(&set, &txid(999), 7, &mut snapshot)?;
    let expected = listener.snapshot().muhash.finalize();

    assert_eq!(trailer, expected);
    assert_ne!(trailer, [0_u8; 384]);
    assert_eq!(&snapshot[snapshot.len() - 384..], expected);
    Ok(())
}

#[test]
fn snapshot_trailer_tracks_listener_after_removal() -> Result<(), Box<dyn std::error::Error>> {
    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(listener.clone()));

    let removed_outpoint = OutPoint::new(txid(1), 0);
    let kept_outpoint = OutPoint::new(txid(2), 1);
    let removed_txout = txout(1);
    let kept_txout = txout(2);

    let mut adds = BlockChanges::default();
    adds.add(UtxoAdd::new(
        removed_outpoint,
        removed_txout.clone(),
        false,
        7,
    ));
    adds.add(UtxoAdd::new(kept_outpoint, kept_txout.clone(), true, 7));
    set.commit_block(&adds, &txid(100))?;
    let before_removal = listener.snapshot();

    let mut removes = BlockChanges::default();
    removes.remove(removed_outpoint);
    set.commit_block(&removes, &txid(101))?;

    let mut expected = CoinStats::new();
    expected.insert_utxo(&removed_outpoint, &removed_txout, 7, false);
    expected.insert_utxo(&kept_outpoint, &kept_txout, 7, true);
    expected.remove_utxo(&removed_outpoint, &removed_txout, 7, false);

    let after_removal = listener.snapshot();
    assert_eq!(after_removal, expected);
    assert_ne!(
        after_removal.muhash.finalize(),
        before_removal.muhash.finalize()
    );
    assert_eq!(after_removal.utxo_count, 1);
    assert_eq!(after_removal.total_amount, kept_txout.value.to_sat());

    let mut snapshot = Vec::new();
    let trailer = write_snapshot(&set, &txid(101), 8, &mut snapshot)?;
    let expected_trailer = after_removal.muhash.finalize();

    assert_eq!(trailer, expected_trailer);
    assert_eq!(&snapshot[snapshot.len() - 384..], expected_trailer);
    Ok(())
}

#[test]
fn listener_tracks_duplicate_txid_overwrite() -> Result<(), Box<dyn std::error::Error>> {
    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(listener.clone()));

    let outpoint = OutPoint::new(txid(30), 0);
    let original = txout(30);
    let replacement = txout(31);

    let mut first = BlockChanges::default();
    first.add(UtxoAdd::new(outpoint, original.clone(), true, 91_722));
    set.commit_block(&first, &txid(100))?;

    let mut overwrite = BlockChanges::default();
    overwrite.add(UtxoAdd::new(outpoint, replacement.clone(), true, 91_842));
    set.commit_block(&overwrite, &txid(101))?;

    let mut expected = CoinStats::new();
    expected.insert_utxo(&outpoint, &original, 91_722, true);
    expected.remove_utxo(&outpoint, &original, 91_722, true);
    expected.insert_utxo(&outpoint, &replacement, 91_842, true);

    let after_overwrite = listener.snapshot();
    assert_eq!(set.get(&outpoint), Some(replacement.clone()));
    assert_eq!(after_overwrite, expected);
    assert_eq!(after_overwrite.utxo_count, 1);
    assert_eq!(after_overwrite.total_amount, replacement.value.to_sat());
    Ok(())
}

#[test]
fn snapshot_can_observe_mid_block_listener_state_before_finish_block()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    let gate = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(2));
    set.set_listener(Box::new(FirstInsertGate {
        inner: listener.clone(),
        gate: Arc::clone(&gate),
        barrier: Arc::clone(&barrier),
    }));

    let first_txid = txid(1);
    let second_txid = txid(257);
    assert_eq!(
        UtxoKey::from_txid(&first_txid).shard(),
        UtxoKey::from_txid(&second_txid).shard()
    );

    let first_outpoint = OutPoint::new(first_txid, 0);
    let second_outpoint = OutPoint::new(second_txid, 0);
    let first_txout = txout(1);
    let second_txout = txout(257);
    let height = 7;
    let tx_delta = 2;

    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        first_outpoint,
        first_txout.clone(),
        false,
        height,
    ));
    changes.add(UtxoAdd::new(
        second_outpoint,
        second_txout.clone(),
        true,
        height,
    ));

    let block_hash = txid(1_000);
    thread::scope(|scope| {
        let commit = scope.spawn(|| set.commit_block(&changes, &block_hash));

        barrier.wait();
        let mid_block = listener.snapshot();
        let mut expected_mid_block = CoinStats::new();
        expected_mid_block.insert_utxo(&first_outpoint, &first_txout, height, false);
        assert_eq!(mid_block, expected_mid_block);
        assert_eq!(mid_block.height, 0);
        assert_eq!(mid_block.tx_count, 0);

        barrier.wait();
        match commit.join() {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })?;

    let post_commit = listener.snapshot();
    let mut expected_post_commit = CoinStats::new();
    expected_post_commit.insert_utxo(&first_outpoint, &first_txout, height, false);
    expected_post_commit.insert_utxo(&second_outpoint, &second_txout, height, true);
    assert_eq!(post_commit, expected_post_commit);
    assert_eq!(post_commit.height, 0);
    assert_eq!(post_commit.tx_count, 0);

    listener.finish_block(height, tx_delta);
    let final_snapshot = listener.snapshot();
    let mut expected_final = expected_post_commit;
    expected_final.finish_block(height, tx_delta);
    assert_eq!(final_snapshot, expected_final);
    assert_eq!(final_snapshot.total_amount, post_commit.total_amount);
    assert_eq!(final_snapshot.bogo_size, post_commit.bogo_size);
    assert_eq!(final_snapshot.utxo_count, post_commit.utxo_count);
    Ok(())
}

struct FirstInsertGate {
    inner: CoinStatsListener,
    gate: Arc<AtomicBool>,
    barrier: Arc<Barrier>,
}

impl UtxoChangeListener for FirstInsertGate {
    fn on_insert(&self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        self.inner.on_insert(op, txout, height, coinbase);
        if self
            .gate
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.barrier.wait();
            self.barrier.wait();
        }
    }

    fn on_remove(&self, op: &OutPoint, txout: &TxOut, height: u32) {
        self.inner.on_remove(op, txout, height);
    }

    fn on_remove_coin(&self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        self.inner.on_remove_coin(op, txout, height, coinbase);
    }

    fn muhash3072(&self) -> Option<[u8; 384]> {
        self.inner.muhash3072()
    }
}

fn txout(index: u32) -> TxOut {
    TxOut {
        value: Amount::from_sat(50_000 + u64::from(index)),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51, index.to_le_bytes()[0]]),
    }
}

fn txid(index: u32) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}
