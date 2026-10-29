use std::sync::Arc;

use bitcoin_rs_primitives::{BlockPayload, Network};
use bitcoin_rs_utxo::UtxoSet;
use hashbrown::HashSet;
use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};
use parking_lot::Mutex;

use bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at as mined_child;

use crate::test_fixtures::{handles, seed_genesis};

const RETIRED_APPLY_METRICS: &[&str] = &[
    "node.apply_block.contextual_header_seconds",
    "node.apply_block.pow_self_consistency_seconds",
    "node.apply_block.coinbase_maturity_seconds",
    "node.apply_block.bip68_seconds",
    "node.apply_block.utxo_changes_seconds",
    "node.apply_block.durable_sync_seconds",
    "node.apply_block.durable_commit_seconds",
    "node.apply_block.script_verify_coinbase_only_seconds",
    "node.utxo.listener.event_batches_seconds",
];

const RETIRED_WINDOW_METRICS: &[&str] = &[
    "node.durable_head.group_sync_seconds",
    "node.durable_head.group_commit_seconds",
    "node.durable_head.group_blocks",
    "node.window.checks_seconds",
];

#[derive(Default)]
struct NameRecorder {
    names: Arc<Mutex<HashSet<String>>>,
}

impl NameRecorder {
    fn saw(&self, name: &str) -> bool {
        self.names.lock().contains(name)
    }
}

#[derive(Default)]
struct NameCell {
    names: Arc<Mutex<HashSet<String>>>,
    name: String,
}

impl CounterFn for NameCell {
    fn increment(&self, _value: u64) {
        self.names.lock().insert(self.name.clone());
    }

    fn absolute(&self, _value: u64) {
        self.names.lock().insert(self.name.clone());
    }
}

impl GaugeFn for NameCell {
    fn increment(&self, _value: f64) {
        self.names.lock().insert(self.name.clone());
    }

    fn decrement(&self, _value: f64) {
        self.names.lock().insert(self.name.clone());
    }

    fn set(&self, _value: f64) {
        self.names.lock().insert(self.name.clone());
    }
}

impl HistogramFn for NameCell {
    fn record(&self, _value: f64) {
        self.names.lock().insert(self.name.clone());
    }
}

impl Recorder for NameRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        Counter::from_arc(Arc::new(NameCell {
            names: Arc::clone(&self.names),
            name: key.name().to_string(),
        }))
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        Gauge::from_arc(Arc::new(NameCell {
            names: Arc::clone(&self.names),
            name: key.name().to_string(),
        }))
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(Arc::new(NameCell {
            names: Arc::clone(&self.names),
            name: key.name().to_string(),
        }))
    }
}

fn assert_names_absent(recorder: &NameRecorder, names: &[&str]) {
    let recorded = recorder.names.lock();
    for name in names {
        assert!(
            !recorded.contains(*name),
            "{name} is a diagnostic (OBS-02/OBS-06) and must not reach the metrics API"
        );
    }
}

#[test]
fn retired_apply_stage_timings_stay_off_caller_thread_metrics()
-> Result<(), Box<dyn std::error::Error>> {
    let recorder = NameRecorder::default();
    let genesis = Network::Regtest.genesis_block();
    metrics::with_local_recorder(&recorder, || -> Result<(), Box<dyn std::error::Error>> {
        let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        seed_genesis(&handles)?;
        let first = mined_child(genesis.block_hash(), 1)?;
        handles.apply_block(&BlockPayload::from_local(first))?;
        Ok(())
    })?;
    assert_names_absent(&recorder, RETIRED_APPLY_METRICS);
    assert!(
        recorder.saw("node.apply_block.total_seconds"),
        "the apply.commit hot-path hook is a kept signal (OBS-04)"
    );
    assert!(
        recorder.saw("node.apply_block.txs_applied"),
        "the apply throughput counter is a kept operator signal (OBS-01)"
    );
    Ok(())
}

#[test]
fn retired_group_and_check_timings_stay_off_caller_thread_metrics()
-> Result<(), Box<dyn std::error::Error>> {
    let recorder = NameRecorder::default();
    let genesis = Network::Regtest.genesis_block();
    metrics::with_local_recorder(&recorder, || -> Result<(), Box<dyn std::error::Error>> {
        let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        let first = mined_child(genesis.block_hash(), 1)?;
        let second = mined_child(first.block_hash(), 2)?;
        seed_genesis(&handles)?;
        {
            let mut tree = handles.block_tree.write();
            bitcoin_rs_chain::accept_headers(
                &mut tree,
                &[first.header, second.header],
                Network::Regtest,
                bitcoin_rs_chain::current_unix_seconds(),
                bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
            )?;
        }
        let first_payload = BlockPayload::from_local(first);
        let second_payload = BlockPayload::from_local(second);
        let payloads = [&first_payload, &second_payload];
        let transition = handles.begin_transition()?;
        transition.connect_window(&payloads)?;
        Ok(())
    })?;
    assert_names_absent(&recorder, RETIRED_WINDOW_METRICS);
    assert!(
        recorder.saw("node.window.verify_seconds"),
        "the apply.prove_window hot-path hook is a kept signal (OBS-04)"
    );
    Ok(())
}

#[test]
fn window_commit_emits_transition_and_flush_diagnostics() -> Result<(), Box<dyn std::error::Error>>
{
    let genesis = Network::Regtest.genesis_block();
    let fields = ProfileFields::default();
    capture_profile(&fields, || -> Result<(), Box<dyn std::error::Error>> {
        let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        let first = mined_child(genesis.block_hash(), 1)?;
        let second = mined_child(first.block_hash(), 2)?;
        seed_genesis(&handles)?;
        {
            let mut tree = handles.block_tree.write();
            bitcoin_rs_chain::accept_headers(
                &mut tree,
                &[first.header, second.header],
                Network::Regtest,
                bitcoin_rs_chain::current_unix_seconds(),
                bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
            )?;
        }
        let first_payload = BlockPayload::from_local(first);
        let second_payload = BlockPayload::from_local(second);
        let payloads = [&first_payload, &second_payload];
        let transition = handles.begin_transition()?;
        transition.connect_window(&payloads)?;
        Ok(())
    })?;
    for field in ["transition_held_us", "flush_wait_us"] {
        assert!(
            fields.0.lock().contains(field),
            "missing window diagnostic: {field}"
        );
    }
    Ok(())
}

#[derive(Clone, Default)]
struct ProfileFields(Arc<Mutex<HashSet<String>>>);

impl tracing::field::Visit for ProfileFields {
    fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {}

    fn record_u128(&mut self, field: &tracing::field::Field, _value: u128) {
        if field.name().ends_with("_us") {
            self.0.lock().insert(field.name().to_owned());
        }
    }
}

impl tracing::Subscriber for ProfileFields {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target().starts_with("bitcoin_rs_chainstate")
    }

    fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        event.record(&mut self.clone());
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

fn capture_profile<T>(fields: &ProfileFields, action: impl FnOnce() -> T) -> T {
    let _registration_guard = tracing::Dispatch::new(ProfileFields::default());
    let dispatch = tracing::Dispatch::new(fields.clone());
    tracing::dispatcher::with_default(&dispatch, action)
}

#[test]
fn proposal_emits_completed_validation_timings() -> Result<(), Box<dyn std::error::Error>> {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&handles)?;
    let block = mined_child(Network::Regtest.genesis_block().block_hash(), 1)?;
    let fields = ProfileFields::default();
    let payload = bitcoin_rs_primitives::BlockPayload::from_local(block);
    capture_profile(&fields, || handles.validate_block(&payload))?;
    for field in [
        "contextual_header_us",
        "pow_self_us",
        "script_verify_us",
        "coinbase_maturity_us",
        "bip68_us",
        "utxo_changes_us",
    ] {
        assert!(
            fields.0.lock().contains(field),
            "missing proposal timing: {field}"
        );
    }
    assert!(!fields.0.lock().contains("utxo_commit_us"));
    Ok(())
}

#[test]
fn rejected_header_emits_only_completed_validation_timings()
-> Result<(), Box<dyn std::error::Error>> {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&handles)?;
    let genesis = Network::Regtest.genesis_block();
    let mut block = mined_child(genesis.block_hash(), 1)?;
    block.header.time = genesis.header.time;
    let fields = ProfileFields::default();
    let payload = bitcoin_rs_primitives::BlockPayload::from_local(block);
    let result = capture_profile(&fields, || handles.validate_block(&payload));
    assert!(matches!(
        result,
        Err(super::ApplyError::Chain(
            bitcoin_rs_chain::ChainError::TimestampTooEarly { .. }
        ))
    ));
    assert!(fields.0.lock().contains("contextual_header_us"));
    assert!(!fields.0.lock().contains("pow_self_us"));
    assert!(!fields.0.lock().contains("utxo_commit_us"));
    Ok(())
}

#[test]
fn rejected_spend_keeps_resolution_and_dispatch_timings() -> Result<(), Box<dyn std::error::Error>>
{
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&handles)?;
    let genesis = Network::Regtest.genesis_block();
    let mut block = mined_child(genesis.block_hash(), 1)?;
    let mut spend = block.txs[0].clone();
    spend.inputs[0].previous_output =
        bitcoin_rs_primitives::OutPoint::new(genesis.txs[0].txid(), 0);
    block.txs.push(spend);
    let mut leaves: Vec<_> = block.txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    let root = bitcoin_rs_consensus::verify_block::compute_merkle_root(&mut leaves)
        .ok_or("test merkle root missing")?;
    block.header.merkle_root = bitcoin_rs_primitives::Hash256::from_le_bytes(&root);
    let fields = ProfileFields::default();
    let payload = bitcoin_rs_primitives::BlockPayload::from_local(block);
    let result = capture_profile(&fields, || handles.validate_block(&payload));
    assert!(matches!(
        result,
        Err(super::ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::MissingPrevout { input_index: 0 }
        ))
    ));
    assert!(fields.0.lock().contains("script_resolution_us"));
    assert!(fields.0.lock().contains("script_verify_us"));
    assert!(!fields.0.lock().contains("coinbase_maturity_us"));
    assert!(!fields.0.lock().contains("utxo_commit_us"));
    Ok(())
}
