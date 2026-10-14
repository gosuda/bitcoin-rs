use std::sync::Arc;

use hashbrown::HashMap;
use parking_lot::Mutex;

use anyhow::Result;
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};
use metrics::{
    Counter, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};

#[test]
fn opens_storage_backend() -> Result<()> {
    #[cfg(feature = "rocksdb")]
    assert_backend_opens("rocksdb")?;
    #[cfg(feature = "fjall")]
    assert_backend_opens("fjall")?;
    #[cfg(feature = "redb")]
    assert_backend_opens("redb")?;
    Ok(())
}

fn assert_backend_opens(backend: &str) -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join(backend);
    config.storage.backend = backend.parse().map_err(anyhow::Error::msg)?;
    config.p2p.listen.clear();

    let state = NodeState::open(config, None)?;

    assert_eq!(state.storage_kind(), backend);
    assert!(state.data_dir().join("chainstate").is_dir());
    Ok(())
}

/// The chainstate cache share must reach the backend that was opened: a
/// `dbcache` the operator set is only honored if the byte count survives every
/// hop from [`NodeState::open`] down to `open_with_cache`. A hop that drops it
/// falls back to the engine default, which no other assertion notices, so this
/// reads the capacity each compiled-in backend published on open.
#[test]
fn open_gives_every_chainstate_backend_its_budgeted_cache_share() -> Result<()> {
    #[cfg(feature = "rocksdb")]
    assert_chainstate_cache_share("rocksdb")?;
    #[cfg(feature = "fjall")]
    assert_chainstate_cache_share("fjall")?;
    #[cfg(feature = "redb")]
    assert_chainstate_cache_share("redb")?;
    Ok(())
}

#[cfg(any(feature = "rocksdb", feature = "fjall", feature = "redb"))]
fn assert_chainstate_cache_share(backend: &str) -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join(backend);
    config.storage.backend = backend.parse().map_err(anyhow::Error::msg)?;
    config.storage.dbcache_mb = 64;
    config.p2p.listen.clear();

    let expected =
        bitcoin_rs_storage::split_cache_budget(clamp_budget(&config), txindex_enabled(&config))[0]
            .bytes;
    assert_ne!(
        expected,
        engine_default_cache_bytes(backend),
        "{backend}: the budget must differ from the engine default or this proves nothing"
    );

    let gauges = GaugeSpy::default();
    let state = metrics::with_local_recorder(&gauges, || NodeState::open(config, None))?;

    assert_capacity_eq(
        &gauges,
        &format!("storage.cache_capacity_bytes{{backend=\"{backend}\"}}"),
        expected,
    );
    drop(state);
    Ok(())
}

/// The capacity each engine configures when no budget reaches it, so a dropped
/// budget is distinguishable from a delivered one. Read from the storage crate
/// so a changed default cannot make the guard below vacuous.
#[cfg(any(feature = "rocksdb", feature = "fjall", feature = "redb"))]
fn engine_default_cache_bytes(backend: &str) -> u64 {
    match backend {
        #[cfg(feature = "rocksdb")]
        "rocksdb" => bitcoin_rs_storage::ROCKSDB_DEFAULT_CACHE_BYTES,
        #[cfg(feature = "fjall")]
        "fjall" => bitcoin_rs_storage::FJALL_DEFAULT_CACHE_BYTES,
        #[cfg(feature = "redb")]
        "redb" => bitcoin_rs_storage::REDB_DEFAULT_CACHE_BYTES,
        #[cfg(feature = "redb")]
        "redb-txindex" => bitcoin_rs_storage::REDB_TXINDEX_DEFAULT_CACHE_BYTES,
        other => panic!("no engine default recorded for {other}"),
    }
}

#[cfg(any(feature = "rocksdb", feature = "fjall", feature = "redb"))]
fn clamp_budget(config: &NodeConfig) -> u64 {
    bitcoin_rs_storage::clamp_dbcache_bytes(config.storage.dbcache_mb)
}

/// `NodeState::open` splits the budget on the capabilities the index config
/// enables, so read the same predicate instead of a literal.
#[cfg(any(feature = "rocksdb", feature = "fjall", feature = "redb"))]
fn txindex_enabled(config: &NodeConfig) -> bool {
    !config
        .indexes
        .script_index
        .enabled_capabilities(config.indexes.txindex)
        .is_empty()
}

/// Asserts a published capacity equals the expected byte count. Both are small
/// integers (< 2^31) that `f64` represents exactly.
#[cfg(any(feature = "rocksdb", feature = "fjall", feature = "redb"))]
#[expect(
    clippy::cast_precision_loss,
    reason = "byte counts < 2^31, lossless in f64"
)]
#[expect(clippy::as_conversions, reason = "byte counts < 2^31, lossless in f64")]
fn assert_capacity_eq(gauges: &GaugeSpy, key: &str, expected: u64) {
    let actual = gauges.get(key);
    assert!(
        actual.is_some_and(|value| (value - expected as f64).abs() < 1.0),
        "{key}: expected {expected}, published {actual:?}"
    );
}

/// Captures gauge values keyed `name{label="value",...}`; counters and
/// histograms are discarded.
#[derive(Clone, Default)]
struct GaugeSpy {
    gauges: Arc<Mutex<HashMap<String, f64>>>,
}

impl GaugeSpy {
    fn key(key: &Key) -> String {
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

    fn get(&self, key: &str) -> Option<f64> {
        self.gauges.lock().get(key).copied()
    }
}

impl Recorder for GaugeSpy {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, _key: &Key, _metadata: &Metadata<'_>) -> Counter {
        Counter::noop()
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        Gauge::from_arc(Arc::new(GaugeCell {
            gauges: Arc::clone(&self.gauges),
            name: Self::key(key),
        }))
    }

    fn register_histogram(&self, _key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(Arc::new(DiscardHistogram))
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
        self.increment(-value);
    }

    fn set(&self, value: f64) {
        self.gauges.lock().insert(self.name.clone(), value);
    }
}

struct DiscardHistogram;

impl HistogramFn for DiscardHistogram {
    fn record(&self, _value: f64) {}
}
