use std::sync::Arc;

use bitcoin_rs_storage::ColumnFamily;
use bitcoin_rs_storage::KvStore as _;
use bitcoin_rs_storage::utxo::SnapshotCoinObserver as _;

use crate::IndexCapabilities;
use crate::IndexError;
use crate::IndexWatermark;
use crate::snapshot_seed::{ScriptLiveSeedPhase, ScriptLiveSeedState};
use crate::{IndexWriter, ScriptHash};
use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid};
use bitcoin_rs_storage::RocksDbStore;
use bitcoin_rs_storage::utxo::SnapshotCoin;

type Harness = (
    tempfile::TempDir,
    Arc<RocksDbStore>,
    Arc<parking_lot::RwLock<IndexWriter<RocksDbStore>>>,
    Arc<ScriptLiveSeedState>,
);

fn harness() -> Harness {
    let dir = tempfile::tempdir().expect("index dir");
    let store = Arc::new(RocksDbStore::open(dir.path()).expect("rocksdb open"));
    let writer = Arc::new(parking_lot::RwLock::new(
        IndexWriter::open(Arc::clone(&store), 1).expect("index writer open"),
    ));
    let seed = Arc::new(ScriptLiveSeedState::new());
    (dir, store, writer, seed)
}

fn coin(index: u64, height: u32) -> SnapshotCoin<'static> {
    let mut txid = [0_u8; 32];
    txid[..8].copy_from_slice(&index.to_le_bytes());
    SnapshotCoin {
        txid: Hash256::from_le_bytes(&txid),
        vout: 0,
        value: 1_000 + index,
        script_pubkey: &[0x51],
        height,
        coinbase: false,
    }
}

fn watermark(height: u32) -> IndexWatermark {
    let byte = u8::try_from(height).unwrap_or(0);
    IndexWatermark {
        height,
        hash: Hash256::from_le_bytes(&[byte; 32]).to_le_bytes(),
    }
}

#[test]
fn a_second_session_is_refused_while_one_is_active() {
    let (_dir, _store, _writer, seed) = harness();
    let session = seed.begin_session().expect("first session");
    assert_eq!(seed.phase(), ScriptLiveSeedPhase::Seeding);
    assert!(matches!(
        seed.begin_session(),
        Err(IndexError::SeedAlreadyActive)
    ));
    drop(session);
    assert_eq!(seed.phase(), ScriptLiveSeedPhase::AbortPending);
    seed.complete_abort();
    assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
    seed.begin_session().expect("session after abort");
}

#[test]
fn staged_rows_stay_unpublished_until_the_worker_publishes() {
    let (_dir, _store, writer, seed) = harness();
    let session = seed.begin_session().expect("session");
    {
        let mut observer = session.observer();
        for i in 0..4 {
            observer.observe_coin(coin(i, 10));
        }
    }
    assert!(session.take_error().is_none());
    assert_eq!(session.staged_rows(), 4);
    assert_eq!(
        writer.read().watermarks().expect("watermarks").script_live,
        None,
        "SNP-07: rows exist without a watermark while decoding"
    );

    session.publish(watermark(10));
    assert_eq!(
        seed.phase(),
        ScriptLiveSeedPhase::PublishPending { tip: watermark(10) }
    );
    writer
        .write()
        .publish_script_live_seed(watermark(10))
        .expect("publish staged rows");
    seed.complete_publish();
    assert_eq!(
        writer.read().watermarks().expect("watermarks").script_live,
        Some(watermark(10))
    );
    assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
}

#[test]
fn an_aborted_session_discards_the_staged_base() {
    let (_dir, store, writer, seed) = harness();
    let session = seed.begin_session().expect("session");
    {
        let mut observer = session.observer();
        for i in 0..4 {
            observer.observe_coin(coin(i, 10));
        }
    }
    session.abort();
    writer
        .write()
        .reset_capabilities(IndexCapabilities::SCRIPT_LIVE)
        .expect("reset staged rows");
    seed.complete_abort();
    let probe = writer
        .write()
        .fenced_watermarks()
        .expect("watermarks")
        .1
        .script_live;
    assert_eq!(probe, None);
    assert_eq!(
        count_live_rows(&store),
        0,
        "SNP-07: discarded staging must leave no rows"
    );
}

#[test]
fn a_closed_channel_is_a_sticky_stage_error() {
    let (_dir, _store, _writer, seed) = harness();
    let session = seed.begin_session().expect("session");
    let receiver = seed.take_receiver().expect("receiver parked");
    drop(receiver);
    {
        let mut observer = session.observer();
        observer.observe_coin(coin(1, 1));
    }
    assert!(matches!(
        session.take_error(),
        Some(IndexError::SeedChannelClosed)
    ));
}

#[test]
fn rows_without_a_watermark_are_recovered_as_an_interrupted_seed() {
    let (_dir, store, writer, _seed) = harness();
    let rows = (0..3_u64)
        .map(|i| -> Result<Vec<u8>, IndexError> {
            let scripthash = ScriptHash::from_script_bytes(&[0x51]);
            let outpoint = OutPoint::new(
                Txid(Hash256::from_le_bytes(&{
                    let mut bytes = [0_u8; 32];
                    bytes[..8].copy_from_slice(&i.to_le_bytes());
                    bytes
                })),
                0,
            );
            let row = crate::types::ScriptLiveRow::new(scripthash, &outpoint);
            let coin = crate::types::ScriptLiveCoin::new(scripthash, 1_000 + i, 1, false);
            let mut bytes = row.as_bytes().to_vec();
            bytes.extend_from_slice(&coin.encode_value()?);
            Ok(bytes)
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("encode rows");
    let staged = writer
        .read()
        .stage_script_live_rows(&mut rows.into_iter())
        .expect("stage rows");
    assert_eq!(staged, 3);
    let cleared = writer
        .read()
        .reset_interrupted_script_live_seed()
        .expect("interrupted probe");
    assert!(cleared, "unwatermarked rows must be cleared before replay");
    assert_eq!(count_live_rows(&store), 0);
}

fn count_live_rows(store: &RocksDbStore) -> usize {
    let mut count = 0;
    let iter = store
        .iter_prefix(ColumnFamily::ScriptLive, &[])
        .expect("live scan");
    for entry in iter {
        let _ = entry.expect("live row");
        count += 1;
    }
    count
}
