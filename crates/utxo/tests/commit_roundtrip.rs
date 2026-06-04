//! Commit/get round-trip coverage for a synthetic UTXO set.
use std::sync::Arc;

use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, varint};
use bitcoin_rs_utxo::{
    BlockChanges, UtxoAdd, UtxoChangeListener, UtxoError, UtxoInserted, UtxoKey, UtxoSet,
    hash_serialized_3,
    set::{UtxoChangeEvents, UtxoCommittedEvent},
};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
enum ListenerEvent {
    InsertBatch(Vec<u32>),
    Insert(u32),
    Remove(u32),
}

#[derive(Clone, Debug)]
struct RecordingListener {
    events: Arc<Mutex<Vec<ListenerEvent>>>,
}

#[derive(Clone, Debug)]
struct CoalescingRecordingListener {
    events: Arc<Mutex<Vec<ListenerEvent>>>,
    batch_calls: Arc<Mutex<usize>>,
}

impl UtxoChangeListener for RecordingListener {
    fn on_insert(&self, op: &OutPoint, _txout: &TxOut, _height: u32, _coinbase: bool) {
        self.events.lock().push(ListenerEvent::Insert(op.vout));
    }

    fn on_insert_coins(&self, insertions: &[UtxoInserted<'_>]) {
        self.events.lock().push(ListenerEvent::InsertBatch(
            insertions
                .iter()
                .map(|insertion| insertion.op.vout)
                .collect(),
        ));
    }

    fn on_remove(&self, op: &OutPoint, _txout: &TxOut, _height: u32) {
        self.events.lock().push(ListenerEvent::Remove(op.vout));
    }
}

impl UtxoChangeListener for CoalescingRecordingListener {
    fn on_insert(&self, op: &OutPoint, _txout: &TxOut, _height: u32, _coinbase: bool) {
        self.events.lock().push(ListenerEvent::Insert(op.vout));
    }

    fn on_insert_coins(&self, insertions: &[UtxoInserted<'_>]) {
        self.events.lock().push(ListenerEvent::InsertBatch(
            insertions
                .iter()
                .map(|insertion| insertion.op.vout)
                .collect(),
        ));
    }

    fn on_remove(&self, op: &OutPoint, _txout: &TxOut, _height: u32) {
        self.events.lock().push(ListenerEvent::Remove(op.vout));
    }

    fn on_committed_event_batches(&self, batches: &[UtxoChangeEvents<'_>]) -> bool {
        let mut batch_calls = self.batch_calls.lock();
        *batch_calls = batch_calls.saturating_add(1);
        drop(batch_calls);

        let mut events = self.events.lock();
        for batch in batches {
            batch.for_each(|event| match event {
                UtxoCommittedEvent::InsertBatch(insertions) => {
                    events.push(ListenerEvent::InsertBatch(
                        insertions
                            .iter()
                            .map(|insertion| insertion.op.vout)
                            .collect(),
                    ));
                }
                UtxoCommittedEvent::RemoveBatch(removals) => {
                    for removal in removals {
                        events.push(ListenerEvent::Remove(removal.op.vout));
                    }
                }
                UtxoCommittedEvent::RemoveCoin(removal) => {
                    events.push(ListenerEvent::Remove(removal.op.vout));
                }
            });
        }
        true
    }

    fn coalesces_committed_events(&self) -> bool {
        true
    }
}

fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(17).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0xa5a5_a5a5_a5a5_a5a5).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txout(seed: u64) -> TxOut {
    let mut script = Vec::with_capacity(10);
    script.extend_from_slice(&[0x51, 0x20]);
    script.extend_from_slice(&seed.to_le_bytes());
    TxOut {
        value: Amount::from_sat(1_000 + seed),
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

fn txid_with_prefix(prefix: u64, suffix: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&prefix.to_le_bytes());
    bytes[8..16].copy_from_slice(&suffix.to_le_bytes());
    bytes[16..24].copy_from_slice(&suffix.rotate_left(11).to_le_bytes());
    bytes[24..32].copy_from_slice(&suffix.wrapping_mul(17).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txid_in_shard(shard: u8, suffix: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[0] = shard;
    bytes[1..9].copy_from_slice(&suffix.to_le_bytes());
    bytes[9..17].copy_from_slice(&suffix.rotate_left(13).to_le_bytes());
    bytes[17..25].copy_from_slice(&suffix.wrapping_mul(29).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn expected_hash_serialized_3(
    entries: &[(OutPoint, TxOut, bool, u32)],
) -> Result<Hash256, Box<dyn std::error::Error>> {
    let mut sorted: Vec<&(OutPoint, TxOut, bool, u32)> = entries.iter().collect();
    sorted.sort_unstable_by(|left, right| {
        left.0
            .txid
            .to_le_bytes()
            .cmp(&right.0.txid.to_le_bytes())
            .then_with(|| {
                let left_vout = left.0.vout;
                let right_vout = right.0.vout;
                left_vout.cmp(&right_vout)
            })
    });

    let mut engine = Sha256::new();
    for (outpoint, txout, coinbase, height) in sorted {
        engine.update(outpoint.txid.to_le_bytes());
        engine.update(outpoint.vout.to_le_bytes());
        let code = (*height << 1) | u32::from(*coinbase);
        engine.update(code.to_le_bytes());
        engine.update(txout.value.to_sat().to_le_bytes());
        let script = txout.script_pubkey.as_bytes();
        let script_len = u64::try_from(script.len())?;
        let encoded_len = varint::encode(script_len);
        engine.update(encoded_len.as_slice());
        engine.update(script);
    }

    let first = engine.finalize();
    let second = Sha256::digest(first);
    let bytes: [u8; 32] = second.into();
    Ok(Hash256::from_le_bytes(&bytes))
}

#[test]
fn commit_roundtrips_ten_thousand_outputs() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();
    let mut expected = Vec::with_capacity(10_000);

    for i in 0_u64..10_000 {
        let outpoint = OutPoint::new(txid(i), u32::try_from(i % 4)?);
        let txout = txout(i);
        expected.push((outpoint, txout.clone()));
        changes.add(UtxoAdd::new(outpoint, txout, false, 100));
    }

    set.commit_block(&changes, &txid(10_001))?;

    for (outpoint, txout) in expected {
        assert_eq!(set.get(&outpoint), Some(txout));
    }

    Ok(())
}

#[test]
fn invalid_add_does_not_apply_removes_in_same_commit() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let retained = OutPoint::new(txid(10), 0);
    let retained_txout = txout(10);
    let mut initial = BlockChanges::default();
    initial.add(UtxoAdd::new(retained, retained_txout.clone(), false, 1));
    set.commit_block(&initial, &txid(11))?;

    let mut invalid = BlockChanges::default();
    invalid.remove(retained);
    invalid.add(UtxoAdd::new(
        OutPoint::new(txid(12), 0),
        TxOut {
            value: Amount::from_sat(12),
            script_pubkey: ScriptBuf::from_bytes(vec![0; usize::from(u16::MAX) + 1]),
        },
        false,
        2,
    ));

    let error = match set.commit_block(&invalid, &txid(13)) {
        Ok(()) => return Err("oversized script unexpectedly committed".into()),
        Err(error) => error,
    };
    assert!(
        matches!(
            error,
            UtxoError::ScriptTooLarge { len } if len == usize::from(u16::MAX) + 1
        ),
        "unexpected error: {error}"
    );
    assert_eq!(set.get(&retained), Some(retained_txout));
    assert_eq!(set.get(&OutPoint::new(txid(12), 0)), None);
    Ok(())
}

#[test]
fn get_entry_surfaces_coinbase_and_height() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();
    let outpoint = OutPoint::new(txid(42), 0);
    let txout = txout(42);

    changes.add(UtxoAdd::new(outpoint, txout.clone(), true, 123));
    set.commit_block(&changes, &txid(43))?;

    let entry = set
        .get_entry(&outpoint)
        .ok_or("expected committed outpoint to be live")?;
    assert_eq!(entry.txout, txout);
    assert!(entry.coinbase);
    assert_eq!(entry.height, 123);

    Ok(())
}

#[test]
fn scan_script_pubkeys_returns_matching_live_outputs() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();
    let first = OutPoint::new(txid(52), 0);
    let second = OutPoint::new(txid(53), 0);
    let first_txout = txout(52);
    let second_txout = txout(53);

    changes.add(UtxoAdd::new(first, first_txout.clone(), false, 222));
    changes.add(UtxoAdd::new(second, second_txout, true, 223));
    set.commit_block(&changes, &txid(54))?;

    let scan = set.scan_script_pubkeys(std::slice::from_ref(&first_txout.script_pubkey))?;

    assert_eq!(scan.txouts, 2);
    assert_eq!(scan.unspents.len(), 1);
    assert_eq!(scan.unspents[0].outpoint, first);
    assert_eq!(scan.unspents[0].txout, first_txout);
    assert!(!scan.unspents[0].coinbase);
    assert_eq!(scan.unspents[0].height, 222);
    Ok(())
}

#[test]
fn has_live_outputs_for_txid_tracks_any_remaining_vout() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(77);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(live_txid, 1),
        txout(77),
        false,
        200,
    ));
    changes.add(UtxoAdd::new(
        OutPoint::new(live_txid, 2),
        txout(78),
        false,
        200,
    ));
    set.commit_block(&changes, &txid(78))?;

    assert!(set.has_live_outputs_for_txid(&live_txid));
    assert!(!set.has_live_outputs_for_txid(&txid(79)));

    let mut first_spend = BlockChanges::default();
    first_spend.remove(OutPoint::new(live_txid, 1));
    set.commit_block(&first_spend, &txid(80))?;

    assert!(set.has_live_outputs_for_txid(&live_txid));

    let mut final_spend = BlockChanges::default();
    final_spend.remove(OutPoint::new(live_txid, 2));
    set.commit_block(&final_spend, &txid(81))?;

    assert!(!set.has_live_outputs_for_txid(&live_txid));
    Ok(())
}

#[test]
fn listener_batches_inserts_without_crossing_overwrite_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(RecordingListener {
        events: Arc::clone(&events),
    }));
    let live_txid = txid(600);

    let mut initial = BlockChanges::default();
    initial.add(UtxoAdd::new(
        OutPoint::new(live_txid, 0),
        txout(600),
        false,
        300,
    ));
    initial.add(UtxoAdd::new(
        OutPoint::new(live_txid, 1),
        txout(601),
        true,
        300,
    ));
    set.commit_block(&initial, &txid(602))?;
    events.lock().clear();

    let mut overwrite = BlockChanges::default();
    overwrite.add(UtxoAdd::new(
        OutPoint::new(live_txid, 2),
        txout(603),
        false,
        301,
    ));
    overwrite.add(UtxoAdd::new(
        OutPoint::new(live_txid, 1),
        txout(604),
        false,
        301,
    ));
    overwrite.add(UtxoAdd::new(
        OutPoint::new(live_txid, 3),
        txout(605),
        true,
        301,
    ));
    set.commit_block(&overwrite, &txid(606))?;

    assert_eq!(
        events.lock().clone(),
        vec![
            ListenerEvent::InsertBatch(vec![2]),
            ListenerEvent::Remove(1),
            ListenerEvent::InsertBatch(vec![1, 3]),
        ]
    );
    assert_eq!(set.get(&OutPoint::new(live_txid, 1)), Some(txout(604)));
    assert_eq!(set.get(&OutPoint::new(live_txid, 2)), Some(txout(603)));
    assert_eq!(set.get(&OutPoint::new(live_txid, 3)), Some(txout(605)));
    Ok(())
}

#[test]
fn listener_emits_explicit_removes_before_add_batches_in_single_shard_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(RecordingListener {
        events: Arc::clone(&events),
    }));
    let live_txid = txid(620);
    let first = OutPoint::new(live_txid, 0);
    let second = OutPoint::new(live_txid, 1);
    let third = OutPoint::new(live_txid, 2);

    let mut initial = BlockChanges::default();
    initial.add(UtxoAdd::new(first, txout(620), false, 302));
    initial.add(UtxoAdd::new(second, txout(621), false, 302));
    set.commit_block(&initial, &txid(622))?;
    events.lock().clear();

    let mut mixed = BlockChanges::default();
    mixed.remove(first);
    mixed.add(UtxoAdd::new(third, txout(623), true, 303));
    set.commit_block(&mixed, &txid(624))?;

    assert_eq!(
        events.lock().clone(),
        vec![
            ListenerEvent::Remove(0),
            ListenerEvent::InsertBatch(vec![2])
        ]
    );
    assert_eq!(set.get(&first), None);
    assert_eq!(set.get(&second), Some(txout(621)));
    assert_eq!(set.get(&third), Some(txout(623)));
    Ok(())
}

#[test]
fn listener_replays_parallel_multi_shard_events_in_shard_order()
-> Result<(), Box<dyn std::error::Error>> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(RecordingListener {
        events: Arc::clone(&events),
    }));

    let mut initial = BlockChanges::default();
    let mut removes = Vec::new();
    let mut inserts = Vec::new();
    for shard in 0_u8..20 {
        let txid = txid_in_shard(shard, u64::from(shard) + 630);
        assert_eq!(UtxoKey::from_txid(&txid).shard(), shard);
        let remove = OutPoint::new(txid, u32::from(shard));
        let insert = OutPoint::new(txid, u32::from(shard) + 100);
        removes.push(remove);
        inserts.push(insert);
        initial.add(UtxoAdd::new(
            remove,
            txout(u64::from(shard) + 630),
            false,
            304,
        ));
    }
    set.commit_block(&initial, &txid(632))?;
    events.lock().clear();

    let mut mixed = BlockChanges::default();
    for index in (0..removes.len()).rev() {
        mixed.add(UtxoAdd::new(
            inserts[index],
            txout(u64::try_from(index)? + 700),
            false,
            305,
        ));
        mixed.remove(removes[index]);
    }
    set.commit_block(&mixed, &txid(635))?;

    let mut expected = Vec::new();
    for shard in 0_u32..20 {
        expected.push(ListenerEvent::Remove(shard));
        expected.push(ListenerEvent::InsertBatch(vec![shard + 100]));
    }
    assert_eq!(events.lock().clone(), expected);
    for (index, (remove, insert)) in removes.iter().zip(&inserts).enumerate() {
        assert_eq!(set.get(remove), None);
        assert_eq!(set.get(insert), Some(txout(u64::try_from(index)? + 700)));
    }
    Ok(())
}

#[test]
fn coalescing_listener_batches_small_multi_shard_commits() -> Result<(), Box<dyn std::error::Error>>
{
    let events = Arc::new(Mutex::new(Vec::new()));
    let batch_calls = Arc::new(Mutex::new(0_usize));
    let mut set = UtxoSet::new();

    let mut initial = BlockChanges::default();
    let first_remove = OutPoint::new(txid_in_shard(0, 650), 0);
    let second_remove = OutPoint::new(txid_in_shard(1, 651), 1);
    let first_insert = OutPoint::new(txid_in_shard(0, 652), 100);
    let second_insert = OutPoint::new(txid_in_shard(1, 653), 101);
    initial.add(UtxoAdd::new(first_remove, txout(650), false, 306));
    initial.add(UtxoAdd::new(second_remove, txout(651), false, 306));
    set.commit_block(&initial, &txid(654))?;

    set.set_listener(Box::new(CoalescingRecordingListener {
        events: Arc::clone(&events),
        batch_calls: Arc::clone(&batch_calls),
    }));
    let mut mixed = BlockChanges::default();
    mixed.add(UtxoAdd::new(second_insert, txout(653), false, 307));
    mixed.remove(second_remove);
    mixed.add(UtxoAdd::new(first_insert, txout(652), false, 307));
    mixed.remove(first_remove);
    set.commit_block(&mixed, &txid(655))?;

    assert_eq!(*batch_calls.lock(), 1);
    assert_eq!(
        events.lock().clone(),
        vec![
            ListenerEvent::Remove(0),
            ListenerEvent::InsertBatch(vec![100]),
            ListenerEvent::Remove(1),
            ListenerEvent::InsertBatch(vec![101]),
        ]
    );
    assert_eq!(set.get(&first_remove), None);
    assert_eq!(set.get(&second_remove), None);
    assert_eq!(set.get(&first_insert), Some(txout(652)));
    assert_eq!(set.get(&second_insert), Some(txout(653)));
    Ok(())
}

#[test]
fn same_txid_churn_preserves_live_outputs_and_record_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(700);
    let first = OutPoint::new(live_txid, 0);
    let second = OutPoint::new(live_txid, 1);
    let third = OutPoint::new(live_txid, 2);
    let fourth = OutPoint::new(live_txid, 3);
    let first_txout = txout(701);
    let second_txout = txout(702);
    let third_txout = txout(703);
    let fourth_txout = txout(704);

    let mut initial = BlockChanges::default();
    initial.add(UtxoAdd::new(first, first_txout, false, 400));
    initial.add(UtxoAdd::new(second, second_txout.clone(), false, 400));
    initial.add(UtxoAdd::new(third, third_txout, false, 400));
    set.commit_block(&initial, &txid(705))?;

    assert_eq!(set.record_count(), 1);
    assert_eq!(set.len(), 3);

    let mut churn = BlockChanges::default();
    churn.remove(first);
    churn.remove(third);
    churn.add(UtxoAdd::new(fourth, fourth_txout.clone(), true, 401));
    set.commit_block(&churn, &txid(706))?;

    assert_eq!(set.get(&first), None);
    assert_eq!(set.get(&second), Some(second_txout));
    assert_eq!(set.get(&third), None);
    assert_eq!(set.get(&fourth), Some(fourth_txout));
    assert!(set.has_live_outputs_for_txid(&live_txid));
    assert_eq!(set.record_count(), 1);
    assert_eq!(set.len(), 2);
    Ok(())
}

#[test]
fn vout_64_roundtrips_through_public_utxo_api() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(88);
    let low = OutPoint::new(live_txid, 63);
    let high = OutPoint::new(live_txid, 64);
    let low_txout = txout(88);
    let high_txout = txout(89);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(low, low_txout.clone(), false, 300));
    changes.add(UtxoAdd::new(high, high_txout.clone(), true, 301));
    set.commit_block(&changes, &txid(90))?;

    assert_eq!(set.get(&low), Some(low_txout.clone()));
    assert_eq!(set.get(&high), Some(high_txout.clone()));
    let high_entry = set
        .get_entry(&high)
        .ok_or("expected vout 64 to remain live")?;
    assert_eq!(high_entry.txout, high_txout);
    assert!(high_entry.coinbase);
    assert_eq!(high_entry.height, 301);
    assert!(set.has_live_outputs_for_txid(&live_txid));

    let scan = set.scan_script_pubkeys(std::slice::from_ref(&high_txout.script_pubkey))?;
    assert_eq!(scan.txouts, 2);
    assert_eq!(scan.unspents.len(), 1);
    assert_eq!(scan.unspents[0].outpoint, high);

    let mut high_spend = BlockChanges::default();
    high_spend.remove(high);
    set.commit_block(&high_spend, &txid(91))?;

    assert_eq!(set.get(&high), None);
    assert_eq!(set.get(&low), Some(low_txout));
    assert!(set.has_live_outputs_for_txid(&live_txid));

    let mut low_spend = BlockChanges::default();
    low_spend.remove(low);
    set.commit_block(&low_spend, &txid(92))?;

    assert!(!set.has_live_outputs_for_txid(&live_txid));
    assert!(set.is_empty());
    Ok(())
}

#[test]
fn hash_serialized_3_matches_independent_core_serialization_for_unsorted_utxos()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();
    let entries = vec![
        (OutPoint::new(txid(30), 2), txout(30), false, 210),
        (OutPoint::new(txid(10), 1), txout(10), true, 208),
        (OutPoint::new(txid(30), 0), txout(31), false, 210),
        (OutPoint::new(txid(20), 3), txout(20), true, 209),
    ];

    for (outpoint, txout, coinbase, height) in &entries {
        changes.add(UtxoAdd::new(*outpoint, txout.clone(), *coinbase, *height));
    }
    set.commit_block(&changes, &txid(99))?;

    assert_eq!(
        hash_serialized_3(&set)?,
        expected_hash_serialized_3(&entries)?
    );
    Ok(())
}

#[test]
fn same_prefix_txids_do_not_collide_in_get_or_remove_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let prefix = 0xfeed_face_cafe_beef_u64;
    let first = OutPoint::new(txid_with_prefix(prefix, 1), 0);
    let second = OutPoint::new(txid_with_prefix(prefix, 2), 0);
    let first_txout = txout(101);
    let second_txout = txout(202);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(first, first_txout.clone(), false, 1));
    changes.add(UtxoAdd::new(second, second_txout.clone(), false, 1));
    set.commit_block(&changes, &txid(300))?;

    assert_eq!(set.get(&first), Some(first_txout));
    assert_eq!(set.get(&second), Some(second_txout.clone()));

    let mut spend = BlockChanges::default();
    spend.remove(first);
    set.commit_block(&spend, &txid(301))?;

    assert_eq!(set.get(&first), None);
    assert_eq!(set.get(&second), Some(second_txout));
    Ok(())
}

#[test]
fn full_record_delete_uses_full_txid_and_preserves_collision_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let prefix = 0xfeed_face_cafe_beef_u64;
    let first = OutPoint::new(txid_with_prefix(prefix, 10), 0);
    let second = OutPoint::new(txid_with_prefix(prefix, 11), 0);
    let second_txout = txout(202);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(first, txout(101), false, 1));
    changes.add(UtxoAdd::new(second, second_txout.clone(), false, 1));
    set.commit_block(&changes, &txid(300))?;

    let mut spend = BlockChanges::default();
    spend.remove(first);
    set.commit_block(&spend, &txid(301))?;

    assert_eq!(set.get(&first), None);
    assert_eq!(set.get(&second), Some(second_txout));
    assert!(set.has_live_outputs_for_txid(&second.txid));
    assert_eq!(set.record_count(), 1);
    assert_eq!(set.len(), 1);
    Ok(())
}

#[test]
fn duplicate_remove_does_not_fast_delete_unspent_vout() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(700);
    let removed = OutPoint::new(live_txid, 0);
    let retained = OutPoint::new(live_txid, 1);
    let retained_txout = txout(701);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(removed, txout(700), false, 1));
    changes.add(UtxoAdd::new(retained, retained_txout.clone(), false, 1));
    set.commit_block(&changes, &txid(702))?;

    let mut duplicate_spend = BlockChanges::default();
    duplicate_spend.remove(removed);
    duplicate_spend.remove(removed);
    set.commit_block(&duplicate_spend, &txid(703))?;

    assert_eq!(set.get(&removed), None);
    assert_eq!(set.get(&retained), Some(retained_txout));
    assert!(set.has_live_outputs_for_txid(&live_txid));
    assert_eq!(set.record_count(), 1);
    assert_eq!(set.len(), 1);
    Ok(())
}
