use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_storage::{
    DisconnectMarker, DisconnectPhase, InMemoryUndoStore, StorageError, UndoStore,
};

use super::*;
use crate::stats::CoinStats;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const HEIGHT: u32 = 91;
const HASH: Hash256 = Hash256::from_le_bytes(&[0x5a; 32]);
const FUNDED: OutPoint = OutPoint {
    txid: Txid(Hash256::from_le_bytes(&[0x31; 32])),
    vout: 0,
};
const CREATED: OutPoint = OutPoint {
    txid: Txid(Hash256::from_le_bytes(&[0x42; 32])),
    vout: 0,
};

fn coin(value: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: Script::from_bytes(vec![0x51]),
    }
}

#[test]
fn spent_output_projection_orders_inputs_and_ignores_bip30_restorations() -> TestResult {
    let mut cb = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![0x01, 0x01].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![coin(50)],
    };
    let spend = |previous_output, value| Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![coin(value)],
    };
    let parent = spend(FUNDED, 800);
    let same_block = OutPoint::new(parent.txid(), 0);
    let child = spend(same_block, 700);
    let mut undo = UndoBatch::empty();
    undo.restore(UtxoAdd::new(OutPoint::new(cb.txid(), 0), coin(60), true, 1));
    undo.restore(UtxoAdd::new(FUNDED, coin(900), true, 2));
    let block = Block {
        header: bitcoin_rs_primitives::Network::Regtest
            .genesis_block()
            .header,
        txs: vec![cb.clone(), parent, child],
    };
    let spent = block_spent_outputs(&block, HEIGHT, &undo)?;
    assert_eq!(spent[0], Vec::<UtxoCoin>::new());
    assert_eq!(
        spent[1],
        vec![UtxoCoin {
            outpoint: FUNDED,
            txout: coin(900),
            coinbase: true,
            height: 2
        }]
    );
    assert_eq!(
        spent[2],
        vec![UtxoCoin {
            outpoint: same_block,
            txout: coin(800),
            coinbase: false,
            height: HEIGHT
        }]
    );
    let missing = UndoBatch::empty();
    assert!(matches!(
        block_spent_outputs(&block, HEIGHT, &missing),
        Err(BlockSpendsError::Corrupt(_))
    ));
    cb.outputs.clear();
    let no_outputs = Block {
        header: block.header,
        txs: vec![cb],
    };
    let bytes = crate::undo_codec::encode(&undo, no_outputs.block_hash().into());
    assert!(decode_undo_record(&bytes, no_outputs.block_hash().into()).is_ok());
    assert!(matches!(
        decode_undo_record_for_block(&bytes, &no_outputs),
        Err(UndoCodecError::BlockCountLimit { .. })
    ));
    Ok(())
}

struct NoSpend;
impl SpentOutputLookup for NoSpend {
    fn entry(&self, _outpoint: &OutPoint) -> Option<&UtxoCoin> {
        None
    }
}

fn connected() -> Result<(UtxoSet, CoinStatsListener, State, UndoBatch), UtxoError> {
    let mut utxo = UtxoSet::new();
    let coin_stats = CoinStatsListener::new(CoinStats::new());
    utxo.track_coin_stats(coin_stats.clone());
    let mut seed = BlockChanges::default();
    seed.add(UtxoAdd::new(FUNDED, coin(900), false, 1));
    commit_block_changes(&utxo, &seed, &Hash256::from_le_bytes(&[0x01; 32]))?;
    coin_stats.finish_block(1, 1);
    let before = observe(&utxo, &coin_stats)?;

    let mut changes = BlockChanges::default();
    changes.remove(FUNDED);
    changes.add(UtxoAdd::new(CREATED, coin(850), false, HEIGHT));
    commit_block_changes(&utxo, &changes, &HASH)?;
    coin_stats.finish_block(HEIGHT, 2);
    let mut undo = UndoBatch::empty();
    undo.restore(UtxoAdd::new(FUNDED, coin(900), false, 1));
    undo.remove(CREATED);
    Ok((utxo, coin_stats, before, undo))
}

type State = (Hash256, Hash256, [u64; 5]);

fn observe(utxo: &UtxoSet, coin_stats: &CoinStatsListener) -> Result<State, UtxoError> {
    let s = coin_stats.snapshot();
    Ok((
        utxo.lock_stable_view().hash_serialized_3()?,
        s.muhash.finalize_hash(),
        [
            s.height.into(),
            s.total_amount,
            s.bogo_size,
            s.tx_count,
            s.utxo_count,
        ],
    ))
}

#[cfg(feature = "fjall")]
#[test]
fn persisted_record_survives_reopening_the_store() -> TestResult {
    use std::sync::Arc;

    use bitcoin_rs_storage::{FjallStore, KvUndoStore};

    let dir = tempfile::tempdir()?;
    let (.., undo) = connected()?;
    persist_block_undo(
        &KvUndoStore::new(Arc::new(FjallStore::open(dir.path())?)),
        HEIGHT,
        HASH,
        &undo,
    )?;
    let reopened = KvUndoStore::new(Arc::new(FjallStore::open(dir.path())?));
    assert_eq!(load_block_undo(&reopened, HEIGHT, HASH)?, undo);
    Ok(())
}

#[test]
fn missing_and_foreign_records_are_refused() -> TestResult {
    let store = InMemoryUndoStore::default();
    let outcome = load_block_undo(&store, HEIGHT, HASH);
    assert!(
        matches!(outcome, Err(UndoLoadError::Missing { hash, height }) if hash == HASH && height == HEIGHT),
        "{outcome:?}"
    );

    let other = Hash256::from_le_bytes(&[0xab; 32]);
    let record = persist_block_undo(&store, HEIGHT, other, &UndoBatch::empty())?;
    store.persist_undo(HEIGHT, HASH, record.as_bytes())?;
    let outcome = load_block_undo(&store, HEIGHT, HASH);
    assert!(
        matches!(outcome, Err(UndoLoadError::Unreadable { hash, .. }) if hash == HASH),
        "{outcome:?}"
    );
    Ok(())
}

#[test]
fn persisted_record_bytes_decode_back_to_the_batch() -> TestResult {
    let (.., undo) = connected()?;
    let store = InMemoryUndoStore::default();
    let record = persist_block_undo(&store, HEIGHT, HASH, &undo)?;
    assert_eq!(decode_undo_record(record.as_bytes(), HASH)?, undo);
    assert_eq!(load_block_undo(&store, HEIGHT, HASH)?, undo);
    Ok(())
}

#[test]
fn rollback_restores_the_exact_prior_state() -> TestResult {
    let (utxo, coin_stats, before, undo) = connected()?;
    let store = InMemoryUndoStore::default();

    let receipt = rollback_block(&store, &utxo, &coin_stats, HASH, HEIGHT, 1, 2, &undo)?;

    assert!(utxo.get_entry(&CREATED).is_none());
    assert_eq!(
        utxo.get_entry(&FUNDED).map(|e| (e.txout, e.height)),
        Some((coin(900), 1))
    );
    assert_eq!(observe(&utxo, &coin_stats)?, before);
    assert_eq!(receipt.restored_parents, vec![FUNDED.txid]);
    let marker = store.load_disconnect_marker()?.ok_or("marker missing")?;
    assert_eq!(
        (marker.phase, marker.height, marker.hash),
        (DisconnectPhase::RolledBack, HEIGHT, HASH)
    );
    Ok(())
}

#[test]
fn in_flight_marker_refuses_before_arming() -> TestResult {
    let (utxo, coin_stats, _, undo) = connected()?;
    let connected_state = observe(&utxo, &coin_stats)?;
    let store = InMemoryUndoStore::default();
    let torn = Hash256::from_le_bytes(&[0x77; 32]);
    store.arm_disconnect(HEIGHT - 1, torn)?;

    let outcome = rollback_block(&store, &utxo, &coin_stats, HASH, HEIGHT, 1, 2, &undo);

    assert!(
        matches!(outcome, Err(RollbackError::Refused(_))),
        "{outcome:?}"
    );
    assert_eq!(observe(&utxo, &coin_stats)?, connected_state);
    let marker = store.load_disconnect_marker()?.ok_or("marker missing")?;
    assert_eq!(
        (marker.phase, marker.height, marker.hash),
        (DisconnectPhase::InFlight, HEIGHT - 1, torn)
    );
    Ok(())
}

#[test]
fn recovery_rewind_preserves_the_surviving_marker() -> TestResult {
    let (utxo, coin_stats, before, undo) = connected()?;
    let store = InMemoryUndoStore::default();
    let torn = Hash256::from_le_bytes(&[0x77; 32]);
    store.arm_disconnect(HEIGHT - 1, torn)?;

    rollback_block_recovery(&utxo, &coin_stats, HEIGHT, 1, 2, &undo)?;

    assert_eq!(observe(&utxo, &coin_stats)?, before);
    let marker = store.load_disconnect_marker()?.ok_or("marker missing")?;
    assert_eq!(
        (marker.phase, marker.height, marker.hash),
        (DisconnectPhase::InFlight, HEIGHT - 1, torn)
    );
    Ok(())
}

#[test]
fn rolled_back_marker_carries_into_the_next_disconnect() -> TestResult {
    let (utxo, coin_stats, before, undo) = connected()?;
    let store = InMemoryUndoStore::default();
    let prior = Hash256::from_le_bytes(&[0x66; 32]);
    store.arm_disconnect(HEIGHT - 1, prior)?;
    store.complete_disconnect(HEIGHT - 1, prior)?;

    let receipt = rollback_block(&store, &utxo, &coin_stats, HASH, HEIGHT, 1, 2, &undo)?;

    assert_eq!(observe(&utxo, &coin_stats)?, before);
    assert_eq!(receipt.restored_parents, vec![FUNDED.txid]);
    let marker = store.load_disconnect_marker()?.ok_or("marker missing")?;
    assert_eq!(
        (marker.phase, marker.height, marker.hash),
        (DisconnectPhase::RolledBack, HEIGHT, HASH)
    );
    Ok(())
}

#[derive(Default)]
struct MarkerFails {
    inner: InMemoryUndoStore,
    at: Option<DisconnectPhase>,
}

impl UndoStore for MarkerFails {
    fn persist_undo(&self, h: u32, hash: Hash256, r: &[u8]) -> Result<(), StorageError> {
        self.inner.persist_undo(h, hash, r)
    }
    fn load_undo(&self, h: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_undo(h, hash)
    }
    fn arm_disconnect(&self, h: u32, hash: Hash256) -> Result<(), StorageError> {
        if self.at == Some(DisconnectPhase::InFlight) {
            return Err(StorageError::Backend("injected".into()));
        }
        self.inner.arm_disconnect(h, hash)
    }
    fn complete_disconnect(&self, h: u32, hash: Hash256) -> Result<(), StorageError> {
        if self.at == Some(DisconnectPhase::RolledBack) {
            return Err(StorageError::Backend("injected".into()));
        }
        self.inner.complete_disconnect(h, hash)
    }
    fn disarm_disconnect(&self) -> Result<(), StorageError> {
        self.inner.disarm_disconnect()
    }
    fn retire_disconnect_marker(&self) -> Result<(), StorageError> {
        self.inner.retire_disconnect_marker()
    }
    fn load_disconnect_marker(&self) -> Result<Option<DisconnectMarker>, StorageError> {
        self.inner.load_disconnect_marker()
    }
}

#[test]
fn arm_failure_refuses_before_any_mutation() -> TestResult {
    let (utxo, coin_stats, _, undo) = connected()?;
    let connected_state = observe(&utxo, &coin_stats)?;
    let store = MarkerFails {
        at: Some(DisconnectPhase::InFlight),
        ..MarkerFails::default()
    };
    let outcome = rollback_block(&store, &utxo, &coin_stats, HASH, HEIGHT, 1, 2, &undo);
    assert!(
        matches!(outcome, Err(RollbackError::Refused(_))),
        "{outcome:?}"
    );
    assert_eq!(observe(&utxo, &coin_stats)?, connected_state);
    assert_eq!(store.load_disconnect_marker()?, None);
    Ok(())
}

#[test]
fn completion_failure_is_fatal_and_leaves_the_marker_in_flight() -> TestResult {
    let (utxo, coin_stats, _, undo) = connected()?;
    let store = MarkerFails {
        at: Some(DisconnectPhase::RolledBack),
        ..MarkerFails::default()
    };
    let outcome = rollback_block(&store, &utxo, &coin_stats, HASH, HEIGHT, 1, 2, &undo);
    assert!(
        matches!(outcome, Err(RollbackError::Marker(_))),
        "{outcome:?}"
    );
    let marker = store.load_disconnect_marker()?.ok_or("marker missing")?;
    assert_eq!(marker.phase, DisconnectPhase::InFlight);
    Ok(())
}

#[test]
fn coinstats_refusal_precedes_the_undo() -> TestResult {
    let (utxo, coin_stats, _, undo) = connected()?;
    let connected_state = observe(&utxo, &coin_stats)?;
    let store = InMemoryUndoStore::default();
    let outcome = rollback_block(&store, &utxo, &coin_stats, HASH, HEIGHT + 1, 1, 2, &undo);
    assert!(
        matches!(outcome, Err(RollbackError::CoinStats(_))),
        "{outcome:?}"
    );
    assert_eq!(observe(&utxo, &coin_stats)?, connected_state);
    Ok(())
}

fn undo_txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(9).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0xd6e8_feb8_6659_fd93).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0xfeed_face_cafe_beef).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn undo_txout(seed: u64) -> TxOut {
    let mut script = Vec::with_capacity(10);
    script.extend_from_slice(&[0x00, 0x08]);
    script.extend_from_slice(&seed.to_le_bytes());
    TxOut {
        value: Amount::from_sat(50_000 + seed),
        script_pubkey: script.into(),
    }
}

fn build_undo_blocks() -> Result<Vec<(BlockChanges, UndoBatch)>, Box<dyn std::error::Error>> {
    let mut live: Vec<UtxoAdd> = Vec::new();
    let mut blocks = Vec::with_capacity(10);

    for height in 1_u32..=10 {
        let mut changes = BlockChanges::default();
        let mut undo = UndoBatch::empty();

        let remove_count = live.len().min(50);
        for _ in 0..remove_count {
            let add = live.remove(0);
            changes.remove(add.outpoint);
            undo.restore(add);
        }

        for n in 0_u64..100 {
            let seed = u64::from(height) * 1_000 + n;
            let outpoint = OutPoint::new(undo_txid(seed).into(), u32::try_from(n % 3)?);
            let txout = undo_txout(seed);
            let add = UtxoAdd::new(outpoint, txout, height == 1, height);
            live.push(add.clone());
            changes.add(add);
            undo.remove(outpoint);
        }

        blocks.push((changes, undo));
    }

    Ok(blocks)
}

#[test]
fn undoing_last_five_blocks_matches_first_five_only_state() -> TestResult {
    let blocks = build_undo_blocks()?;
    let full = UtxoSet::new();

    for (height, (changes, _undo)) in (1_u64..=10).zip(&blocks) {
        commit_block_changes(&full, changes, &undo_txid(height))?;
    }
    for (_changes, undo) in blocks.iter().rev().take(5) {
        full.undo_block(undo)?;
    }

    let first_five = UtxoSet::new();
    for (height, (changes, _undo)) in (1_u64..=5).zip(&blocks) {
        commit_block_changes(&first_five, changes, &undo_txid(height))?;
    }

    assert_eq!(
        full.lock_stable_view().hash_serialized_3()?,
        first_five.lock_stable_view().hash_serialized_3()?
    );
    assert_eq!(full.len(), first_five.len());

    Ok(())
}

fn listener_set() -> (UtxoSet, CoinStatsListener) {
    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    set.track_coin_stats(listener.clone());
    (set, listener)
}

fn first_undo_test_block(
    coinbase_outpoint: OutPoint,
    coinbase_txout: TxOut,
    kept_outpoint: OutPoint,
    kept_txout: TxOut,
) -> BlockChanges {
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(coinbase_outpoint, coinbase_txout, true, 1));
    changes.add(UtxoAdd::new(kept_outpoint, kept_txout, false, 1));
    changes
}

#[test]
fn listener_undo_restores_muhash_and_accounting() -> TestResult {
    let (full, full_listener) = listener_set();
    let coinbase_outpoint = OutPoint::new(undo_txid(40).into(), 0);
    let coinbase_txout = undo_txout(40);
    let kept_outpoint = OutPoint::new(undo_txid(41).into(), 0);
    let kept_txout = undo_txout(41);
    let replacement_outpoint = OutPoint::new(undo_txid(42).into(), 0);
    let replacement_txout = undo_txout(42);

    let first = first_undo_test_block(
        coinbase_outpoint,
        coinbase_txout.clone(),
        kept_outpoint,
        kept_txout.clone(),
    );
    commit_block_changes(&full, &first, &undo_txid(140))?;

    let mut second = BlockChanges::default();
    second.remove(coinbase_outpoint);
    second.add(UtxoAdd::new(
        replacement_outpoint,
        replacement_txout,
        false,
        2,
    ));
    let mut undo = UndoBatch::empty();
    undo.restore(UtxoAdd::new(
        coinbase_outpoint,
        coinbase_txout.clone(),
        true,
        1,
    ));
    undo.remove(replacement_outpoint);

    commit_block_changes(&full, &second, &undo_txid(141))?;
    full.undo_block(&undo)?;

    let (first_only, first_only_listener) = listener_set();
    commit_block_changes(&first_only, &first, &undo_txid(140))?;

    assert_eq!(full.get(&coinbase_outpoint), Some(coinbase_txout));
    assert_eq!(full.get(&kept_outpoint), Some(kept_txout));
    assert_eq!(full.get(&replacement_outpoint), None);
    assert_eq!(full.len(), first_only.len());
    assert_eq!(
        observe(&full, &full_listener)?,
        observe(&first_only, &first_only_listener)?
    );
    assert_eq!(
        full_listener.snapshot().muhash.finalize(),
        first_only_listener.snapshot().muhash.finalize()
    );
    Ok(())
}

fn block_with_short_txids() -> (Block, Vec<Txid>) {
    let make_tx = |seed: u8| Tx {
        version: 1,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[seed; 32])), u32::MAX),
            script_sig: vec![0x00].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![coin(500)],
    };
    let block = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash(Hash256::default()),
            merkle_root: Hash256::default(),
            time: 0,
            bits: CompactTarget::from_consensus(0x2100_ffff),
            nonce: 0,
        },
        txs: vec![make_tx(1), make_tx(2)],
    };
    let txids = vec![Txid(Hash256::from_le_bytes(&[0x77; 32]))];
    (block, txids)
}

#[test]
fn a_short_txid_list_is_refused_at_every_height() {
    let (block, txids) = block_with_short_txids();
    for height in [0, HEIGHT] {
        let outcome = build_block_changes(&block, height, &txids, None, 4, 4, &NoSpend, None, 64);
        assert!(
            matches!(
                outcome,
                Err(BlockChangeError::TxidCountMismatch {
                    transactions: 2,
                    txids: 1
                })
            ),
            "a short txid list was accepted at height {height}"
        );
    }
}
