//! Backend metric contracts: one logical write is counted exactly once per
//! durability path, and explicit budgeted cache sizes are configured verbatim
//! (no backend floor may raise a share above its allocation).

use hashbrown::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use bitcoin_rs_storage::cache_budget::{MIN_DBCACHE_BYTES, split_cache_budget};
use bitcoin_rs_storage::{ColumnFamily, KvStore, WriteBatch};
use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};

/// The txindex share of the minimum 16 MiB budget, so configuring it verbatim
/// keeps the backend from silently raising an allocated namespace budget.
fn txindex_share() -> u64 {
    let share = split_cache_budget(MIN_DBCACHE_BYTES, true)[1].bytes;
    assert_eq!(share, 3_355_443, "txindex keeps a floored 20% of 16 MiB");
    share
}

/// Records labeled metric values keyed `name{label="value",...}`.
#[derive(Clone, Debug, Default)]
struct LabeledRecorder {
    counters: Arc<Mutex<HashMap<String, u64>>>,
    gauges: Arc<Mutex<HashMap<String, f64>>>,
}

impl LabeledRecorder {
    fn metric_key(key: &Key) -> String {
        let labels = key
            .labels()
            .map(|label| format!("{}=\"{}\"", label.key(), label.value()))
            .collect::<Vec<_>>()
            .join(",");
        if labels.is_empty() {
            key.name().to_owned()
        } else {
            format!("{}{{{}}}", key.name(), labels)
        }
    }

    fn counter(&self, key: &str) -> u64 {
        *self.counters.lock().get(key).unwrap_or(&0)
    }

    fn writes_total(&self, backend: &str) -> u64 {
        let prefix = format!("storage.writes_total{{backend=\"{backend}\"");
        self.counters
            .lock()
            .iter()
            .filter(|(key, _)| key.starts_with(&prefix))
            .map(|(_, value)| value)
            .sum()
    }

    fn gauge(&self, key: &str) -> f64 {
        *self.gauges.lock().get(key).unwrap_or(&0.0)
    }
}

impl Recorder for LabeledRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        let name = Self::metric_key(key);
        self.counters.lock().entry(name.clone()).or_insert(0);
        Counter::from_arc(Arc::new(CounterCell {
            counters: Arc::clone(&self.counters),
            name,
        }))
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        let name = Self::metric_key(key);
        self.gauges.lock().entry(name.clone()).or_insert(0.0);
        Gauge::from_arc(Arc::new(GaugeCell {
            gauges: Arc::clone(&self.gauges),
            name,
        }))
    }

    fn register_histogram(&self, _key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(Arc::new(NoopHistogram))
    }
}

struct CounterCell {
    counters: Arc<Mutex<HashMap<String, u64>>>,
    name: String,
}

impl CounterFn for CounterCell {
    fn increment(&self, value: u64) {
        *self.counters.lock().entry(self.name.clone()).or_insert(0) += value;
    }

    fn absolute(&self, value: u64) {
        self.counters.lock().insert(self.name.clone(), value);
    }
}

struct GaugeCell {
    gauges: Arc<Mutex<HashMap<String, f64>>>,
    name: String,
}

impl GaugeFn for GaugeCell {
    fn increment(&self, value: f64) {
        *self.gauges.lock().entry(self.name.clone()).or_insert(0.0) += value;
    }

    fn decrement(&self, value: f64) {
        if let Some(entry) = self.gauges.lock().get_mut(&self.name) {
            *entry -= value;
        }
    }

    fn set(&self, value: f64) {
        self.gauges.lock().insert(self.name.clone(), value);
    }
}

struct NoopHistogram;

impl HistogramFn for NoopHistogram {
    fn record(&self, _value: f64) {}
}

fn writes_total(backend: &str, durability: &str) -> String {
    format!("storage.writes_total{{backend=\"{backend}\",durability=\"{durability}\"}}")
}

fn cache_capacity(backend: &str) -> String {
    format!("storage.cache_capacity_bytes{{backend=\"{backend}\"}}")
}

fn put_one_row(store: &impl KvStore) -> Result<(), bitcoin_rs_storage::StorageError> {
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::BlockBodies, b"metrics-key", b"value");
    store.write(batch)?;
    Ok(())
}

/// Asserts a gauge equals the expected byte count. The values are small
/// integers (< 2^24) that f64 represents exactly, so a direct equality
/// check is safe — but `clippy::float_cmp` requires an explicit tolerance.
#[expect(
    clippy::cast_precision_loss,
    reason = "byte counts < 2^24, lossless in f64"
)]
#[expect(clippy::as_conversions, reason = "byte counts < 2^24, lossless in f64")]
fn assert_gauge_eq(recorder: &LabeledRecorder, key: &str, expected: u64) {
    let actual = recorder.gauge(key);
    assert!(
        (actual - expected as f64).abs() < 1.0,
        "{key}: expected {expected}, got {actual}"
    );
}

#[test]
fn fjall_counts_each_durability_path_once() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let store = bitcoin_rs_storage::FjallStore::open_with_cache(dir.path(), txindex_share())?;
    metrics::with_local_recorder(&recorder, || {
        let Ok(()) = put_one_row(&store) else {
            panic!("fjall default write failed")
        };
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::BlockBodies, b"metrics-key", b"value");
        let Ok(()) = store.write_durable(batch) else {
            panic!("fjall durable write failed")
        };
    });
    assert_eq!(recorder.counter(&writes_total("fjall", "default")), 1);
    assert_eq!(recorder.counter(&writes_total("fjall", "durable")), 1);
    assert_eq!(
        recorder.writes_total("fjall"),
        2,
        "two logical writes must produce exactly two events"
    );
    Ok(())
}

#[test]
#[cfg(feature = "fjall")]
fn fjall_configures_the_budgeted_share_verbatim() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let share = txindex_share();
    metrics::with_local_recorder(&recorder, || {
        let Ok(_store) = bitcoin_rs_storage::FjallStore::open_with_cache(dir.path(), share) else {
            panic!("fjall open with budgeted share failed")
        };
    });
    assert_gauge_eq(&recorder, &cache_capacity("fjall"), share);
    Ok(())
}

#[test]
#[cfg(feature = "redb")]
fn redb_counts_each_durability_path_once() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let store = bitcoin_rs_storage::RedbStore::open_with_cache(dir.path(), txindex_share())?;
    metrics::with_local_recorder(&recorder, || {
        let mut deferred = store.new_batch();
        deferred.put(ColumnFamily::BlockBodies, b"deferred-key", b"value");
        let Ok(()) = store.write_deferred(deferred) else {
            panic!("redb deferred write failed")
        };
        let mut durable = store.new_batch();
        durable.put(ColumnFamily::BlockBodies, b"durable-key", b"value");
        let Ok(()) = store.write_durable(durable) else {
            panic!("redb durable write failed")
        };
    });
    assert_eq!(recorder.counter(&writes_total("redb", "deferred")), 1);
    assert_eq!(recorder.counter(&writes_total("redb", "durable")), 1);
    assert_eq!(
        recorder.writes_total("redb"),
        2,
        "two logical writes must produce exactly two events"
    );
    Ok(())
}

#[test]
#[cfg(feature = "redb")]
fn redb_configures_the_budgeted_share_verbatim() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let share = txindex_share();
    metrics::with_local_recorder(&recorder, || {
        let Ok(_store) = bitcoin_rs_storage::RedbStore::open_with_cache(dir.path(), share) else {
            panic!("redb open with budgeted share failed")
        };
    });
    assert_gauge_eq(&recorder, &cache_capacity("redb"), share);
    Ok(())
}

#[test]
#[cfg(feature = "redb")]
fn redb_txindex_wrapper_configures_the_budgeted_share_verbatim()
-> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let share = txindex_share();
    metrics::with_local_recorder(&recorder, || {
        let Ok(_store) = bitcoin_rs_storage::open_redb_tx_index_store_with_cache(dir.path(), share)
        else {
            panic!("redb txindex open with budgeted share failed")
        };
    });
    assert_gauge_eq(&recorder, &cache_capacity("redb-txindex"), share);
    Ok(())
}

#[test]
#[cfg(feature = "rocksdb")]
fn rocksdb_deferred_and_durable_writes_count_once() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let store = bitcoin_rs_storage::RocksDbStore::open_with_cache(dir.path(), txindex_share())?;
    metrics::with_local_recorder(&recorder, || {
        let Ok(()) = put_one_row(&store) else {
            panic!("rocksdb default write failed")
        };
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::BlockBodies, b"metrics-key", b"value");
        let Ok(()) = store.write_deferred(batch) else {
            panic!("rocksdb deferred write failed")
        };
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::BlockBodies, b"metrics-key", b"value");
        let Ok(()) = store.write_durable(batch) else {
            panic!("rocksdb durable write failed")
        };
    });
    // Each durability path counts exactly once: write_deferred must not leak a
    // second increment through the default write path it delegates to.
    assert_eq!(recorder.counter(&writes_total("rocksdb", "default")), 1);
    assert_eq!(recorder.counter(&writes_total("rocksdb", "deferred")), 1);
    assert_eq!(recorder.counter(&writes_total("rocksdb", "durable")), 1);
    assert_eq!(
        recorder.writes_total("rocksdb"),
        3,
        "three logical writes must produce exactly three events"
    );
    Ok(())
}

#[test]
#[cfg(feature = "rocksdb")]
fn rocksdb_configures_the_budgeted_share_verbatim() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let share = txindex_share();
    metrics::with_local_recorder(&recorder, || {
        let Ok(_store) = bitcoin_rs_storage::RocksDbStore::open_with_cache(dir.path(), share)
        else {
            panic!("rocksdb open with budgeted share failed")
        };
    });
    assert_gauge_eq(&recorder, &cache_capacity("rocksdb"), share);
    Ok(())
}

#[test]
#[cfg(feature = "mdbx")]
fn mdbx_durable_write_counts_once() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let store = bitcoin_rs_storage::MdbxStore::open_with_cache(dir.path(), txindex_share())?;
    metrics::with_local_recorder(&recorder, || {
        let Ok(()) = put_one_row(&store) else {
            panic!("mdbx default write failed")
        };
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::BlockBodies, b"metrics-key", b"value");
        let Ok(()) = store.write_durable(batch) else {
            panic!("mdbx durable write failed")
        };
    });
    // write_durable must not leak a second increment through the default write
    // path it delegates to.
    assert_eq!(recorder.counter(&writes_total("mdbx", "durable")), 1);
    assert_eq!(recorder.counter(&writes_total("mdbx", "default")), 1);
    assert_eq!(
        recorder.writes_total("mdbx"),
        2,
        "two logical writes must produce exactly two events"
    );
    Ok(())
}

#[test]
#[cfg(feature = "mdbx")]
fn mdbx_configures_the_budgeted_share_verbatim() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let share = txindex_share();
    metrics::with_local_recorder(&recorder, || {
        let Ok(_store) = bitcoin_rs_storage::MdbxStore::open_with_cache(dir.path(), share) else {
            panic!("mdbx open with budgeted share failed")
        };
    });
    assert_gauge_eq(&recorder, &cache_capacity("mdbx"), share);
    Ok(())
}
