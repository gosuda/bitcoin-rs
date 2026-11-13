use std::sync::Arc;

use hashbrown::HashMap;
use parking_lot::Mutex;

use bitcoin_rs_node::test_support::TestError;

type Result<T, E = TestError> = core::result::Result<T, E>;
use bitcoin_rs_node::{Network, NodeConfig, ScriptIndexMode, state::NodeState};
use bitcoin_rs_storage::{Bytes, COIN_KEY_LEN, CoinKey, budget::BudgetOwner};
use metrics::{
    Counter, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};

#[test]
fn opens_storage_backend() -> Result<()> {
    assert_backend_opens("rocksdb")?;
    Ok(())
}

fn assert_backend_opens(backend: &str) -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join(backend);
    config.storage.backend = backend.parse().map_err(TestError::message)?;
    config.p2p.listen.clear();

    let state = NodeState::open(config, None)?;

    assert_eq!(state.storage_kind(), backend);
    assert!(state.data_dir().join("chainstate").is_dir());
    Ok(())
}

const ROW_BYTES: usize = 64 * 1024;
const ROW_COUNT: usize = 192;

struct ExpectedCacheAllocation {
    coin_allowance_bytes: u64,
    engine_capacity_bytes: u64,
}

// BUD-06
#[test]
fn opened_coin_cache_enforces_no_txindex_coin_share() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join("rocksdb");
    config.storage.backend = "rocksdb".parse().map_err(TestError::message)?;
    config.storage.dbcache_mb = 16;
    config.indexes.txindex = false;
    config.indexes.blockfilterindex = false;
    config.indexes.script_index = ScriptIndexMode::Disabled;
    config.p2p.listen.clear();
    assert_opened_cache_pressure(
        config,
        ExpectedCacheAllocation {
            coin_allowance_bytes: 8_388_608,
            engine_capacity_bytes: 8_388_608,
        },
    )
}

// BUD-06
#[test]
fn opened_coin_cache_enforces_txindex_coin_share() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join("rocksdb");
    config.storage.backend = "rocksdb".parse().map_err(TestError::message)?;
    config.storage.dbcache_mb = 16;
    config.indexes.txindex = true;
    config.indexes.blockfilterindex = false;
    config.indexes.script_index = ScriptIndexMode::Disabled;
    config.p2p.listen.clear();
    assert_opened_cache_pressure(
        config,
        ExpectedCacheAllocation {
            coin_allowance_bytes: 6_710_887,
            engine_capacity_bytes: 6_710_886,
        },
    )
}

fn assert_opened_cache_pressure(
    config: NodeConfig,
    expected: ExpectedCacheAllocation,
) -> Result<()> {
    let gauges = GaugeSpy::default();
    let state = metrics::with_local_recorder(&gauges, || NodeState::open(config, None))?;
    let chainstate = state.chainstate();
    let coins = chainstate.coins();

    let row_count =
        u64::try_from(ROW_COUNT).map_err(|_| TestError::Missing("row count exceeds u64"))?;
    let keys: Vec<CoinKey> = (0..row_count).map(coin_key).collect();
    let values: Vec<Bytes> = (0..row_count).map(coin_value).collect();
    coins.ingest_sorted(keys.iter().copied().zip(values.iter().cloned()))?;
    assert_eq!(
        coins.cache().resident_bytes(),
        0,
        "ingest_sorted must leave the coin cache cold"
    );

    for (key, value) in keys.iter().zip(&values) {
        let read = coins
            .get(key)?
            .ok_or(TestError::Missing("ingested coin row must be readable"))?;
        assert_eq!(&read, value, "coin row must round-trip unchanged");
    }

    let resident = coins.cache().resident_bytes();
    let row_len =
        u64::try_from(ROW_BYTES).map_err(|_| TestError::Missing("row size exceeds u64"))?;
    let total = u64::try_from(ROW_COUNT * ROW_BYTES)
        .map_err(|_| TestError::Missing("row total exceeds u64"))?;
    assert!(
        resident <= expected.coin_allowance_bytes,
        "coin cache resident {resident} exceeds policy allowance {}",
        expected.coin_allowance_bytes
    );
    assert!(
        resident >= expected.coin_allowance_bytes.saturating_sub(2 * row_len),
        "coin cache resident {resident} stayed far below allowance {}",
        expected.coin_allowance_bytes
    );
    assert!(
        resident < total,
        "coin cache resident {resident} retained every row without eviction"
    );
    assert!(
        keys.iter().any(|key| coins.cache().lookup(key).is_none()),
        "at least one supplied row must have been evicted under the coin allowance"
    );
    let retained = coins
        .cache()
        .lookup(
            keys.last()
                .ok_or(TestError::Missing("rows are non-empty"))?,
        )
        .ok_or(TestError::Missing("latest row must stay cached"))?;
    let last_value = values
        .last()
        .ok_or(TestError::Missing("rows are non-empty"))?;
    assert_eq!(
        &retained, last_value,
        "latest row must stay readable and intact"
    );

    let caps = state.budget().caps();
    assert_eq!(
        caps.owner_cap(BudgetOwner::EngineCache),
        expected.engine_capacity_bytes,
        "the opened node ledger must cap EngineCache at its post-index share"
    );
    assert_eq!(
        caps.owner_cap(BudgetOwner::CoinCache),
        expected.coin_allowance_bytes,
        "the opened node ledger must cap CoinCache at its post-index share"
    );
    assert_capacity_eq(
        &gauges,
        "storage.cache_capacity_bytes{backend=\"rocksdb\"}",
        expected.engine_capacity_bytes,
    );
    drop(state);
    Ok(())
}

fn coin_key(index: u64) -> CoinKey {
    let mut key = [0_u8; COIN_KEY_LEN];
    key[0] = 1;
    key[1..9].copy_from_slice(&index.to_be_bytes());
    CoinKey(key)
}

fn coin_value(index: u64) -> Bytes {
    let mut value = vec![0_u8; ROW_BYTES];
    value[0..8].copy_from_slice(&index.to_be_bytes());
    Bytes::from(value)
}

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
