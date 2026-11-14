#![expect(
    clippy::expect_used,
    reason = "test: fixture setup failures abort the test with context"
)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitcoin::consensus::deserialize;
use bitcoin::hashes::{Hash as _, sha256, sha256d};
use bitcoin::hex::FromHex as _;
use bitcoin_rs_consensus::primitives::Network;
use bitcoin_rs_projection::portable::{
    CompactFilterArtifact, IndexBundleError, ManifestArtifactTarget, SpillBudget,
    attach_compact_filter_artifact, write_compact_filter_artifact,
};
use bitcoin_rs_projection::{
    IndexCapabilities, IndexCapability, IndexError, IndexReader, IndexWatermark, IndexWriter,
    PreparedBatch, PreparedBatchLimits, SpentCoin, SpentCoins, index_format_version,
};
use bitcoin_rs_storage::{ColumnFamily, KvStore};
use parking_lot::RwLock;

use crate::support::common::MemoryStore;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../storage/tests/fixtures/core-v2/blocks200.json"
);
const HEADER_LEN: usize = 73;
const RECORD_FIXED_LEN: usize = 104;
const FILTER_HASH_AT: usize = 36;
const LENGTH_AT: usize = 100;
const UTXO_FILTER_PREFIX: [u8; 2] = [1, b'F'];

struct Fixture {
    raw: Vec<Vec<u8>>,
    blocks: Vec<bitcoin::Block>,
    hashes: Vec<[u8; 32]>,
}

type OutputMap = HashMap<([u8; 32], u32), (Vec<u8>, u64, u32, bool)>;

struct FixtureOutputs(OutputMap);

impl SpentCoins for FixtureOutputs {
    fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<SpentCoin<'_>> {
        self.0
            .get(&(*txid, vout))
            .map(|(script, value, height, coinbase)| SpentCoin {
                script,
                value: *value,
                height: *height,
                coinbase: *coinbase,
            })
    }
}

fn load_fixture() -> Fixture {
    let text = fs::read_to_string(FIXTURE).expect("core-v2 block fixture");
    let hexes: Vec<String> =
        sonic_rs::from_str(&text).expect("block fixture is a JSON array of hex strings");
    let raw: Vec<Vec<u8>> = hexes
        .iter()
        .map(|hex| Vec::<u8>::from_hex(hex).expect("fixture block is hex"))
        .collect();
    let blocks: Vec<bitcoin::Block> = raw
        .iter()
        .map(|bytes| deserialize(bytes).expect("fixture block decodes"))
        .collect();
    for pair in blocks.windows(2) {
        assert_eq!(
            pair[1].header.prev_blockhash,
            pair[0].block_hash(),
            "fixture blocks form one chain in list order"
        );
    }
    let hashes = blocks
        .iter()
        .map(|block| block.block_hash().to_byte_array())
        .collect();
    Fixture {
        raw,
        blocks,
        hashes,
    }
}

fn fixture_outputs(fixture: &Fixture) -> FixtureOutputs {
    let mut outputs = HashMap::new();
    for (index, block) in fixture.blocks.iter().enumerate() {
        let height = u32::try_from(index).expect("fixture height fits in u32");
        for tx in &block.txdata {
            let txid = tx.compute_txid().to_byte_array();
            for (vout, output) in tx.output.iter().enumerate() {
                let vout = u32::try_from(vout).expect("fixture vout fits in u32");
                outputs.insert(
                    (txid, vout),
                    (
                        output.script_pubkey.as_bytes().to_vec(),
                        output.value.to_sat(),
                        height,
                        tx.is_coinbase(),
                    ),
                );
            }
        }
    }
    FixtureOutputs(outputs)
}

fn build_source(fixture: &Fixture) -> IndexWriter<MemoryStore> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(store, 1).expect("source writer");
    let spent = fixture_outputs(fixture);
    for (index, body) in fixture.raw.iter().enumerate() {
        let height = u32::try_from(index).expect("fixture height fits in u32");
        let prepared = writer
            .prepare_block_with_spent_scripts(
                IndexCapabilities::COMPACT_FILTERS,
                height,
                fixture.hashes[index],
                body,
                &spent,
            )
            .expect("fixture block prepares");
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        assert!(batch.try_push(prepared).is_ok(), "one block per batch");
        writer.commit_forward(batch).expect("fixture block commits");
    }
    writer
}

fn produce(
    source: &IndexWriter<MemoryStore>,
    fixture: &Fixture,
    network: Network,
    dir: &Path,
    name: &str,
) -> (PathBuf, CompactFilterArtifact) {
    let path = dir.join(name);
    let artifact = write_compact_filter_artifact(source, network, &fixture.hashes, &path)
        .expect("producer writes the artifact");
    (path, artifact)
}

fn base_at_tip(fixture: &Fixture) -> IndexWatermark {
    let last = fixture.blocks.len() - 1;
    IndexWatermark {
        height: u32::try_from(last).expect("fixture height fits in u32"),
        hash: fixture.hashes[last],
    }
}

fn target(
    artifact: &Path,
    base: IndexWatermark,
    sha256: [u8; 32],
    size_bytes: u64,
) -> ManifestArtifactTarget {
    ManifestArtifactTarget {
        artifact_path: artifact.to_path_buf(),
        base_height: base.height,
        base_hash: base.hash,
        floor: 0,
        network: Network::Regtest,
        index_format: index_format_version(),
        sha256,
        size_bytes,
        chain_tx_count: 0,
    }
}

fn empty_receiver() -> (Arc<MemoryStore>, RwLock<IndexWriter<MemoryStore>>) {
    let store = Arc::new(MemoryStore::default());
    let writer = IndexWriter::open(Arc::clone(&store), 1).expect("receiver writer");
    (store, RwLock::new(writer))
}

fn rows_with_prefix(store: &MemoryStore, cf: ColumnFamily, prefix: &[u8]) -> usize {
    store
        .iter_prefix(cf, prefix)
        .expect("family scan")
        .collect::<Result<Vec<_>, _>>()
        .expect("family rows")
        .len()
}

fn assert_untouched(store: &MemoryStore, receiver: &RwLock<IndexWriter<MemoryStore>>) {
    assert_eq!(
        receiver
            .read()
            .watermarks()
            .expect("watermarks")
            .compact_filters,
        None,
        "a refused artifact publishes no watermark"
    );
    assert_eq!(
        rows_with_prefix(store, ColumnFamily::UtxoMeta, &UTXO_FILTER_PREFIX),
        0,
        "a refused artifact writes no filter rows"
    );
    assert_eq!(
        rows_with_prefix(store, ColumnFamily::Filters, &[]),
        0,
        "a refused artifact writes no height-keyed filter rows"
    );
}

fn record_offset(bytes: &[u8], wanted: usize) -> usize {
    let mut at = HEADER_LEN;
    for _ in 0..wanted {
        let mut length = [0_u8; 4];
        length.copy_from_slice(&bytes[at + LENGTH_AT..at + LENGTH_AT + 4]);
        at += RECORD_FIXED_LEN + usize::try_from(u32::from_le_bytes(length)).expect("fits");
    }
    at
}

#[test]
fn compact_filter_artifact_attaches_and_serves_the_live_rows_at_its_base() {
    let fixture = load_fixture();
    let source = build_source(&fixture);
    let root = tempfile::tempdir().expect("tempdir");
    let (path, artifact) = produce(&source, &fixture, Network::Regtest, root.path(), "good.dat");
    let base = base_at_tip(&fixture);
    assert_eq!(artifact.base, base, "the artifact is cut at the live base");
    let records = u64::try_from(fixture.hashes.len()).expect("fits");
    assert_eq!(artifact.records, records);

    let (receiver_store, receiver) = empty_receiver();
    let attached = attach_compact_filter_artifact(
        &receiver,
        &target(&path, base, artifact.sha256, artifact.bytes),
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect("a verified artifact attaches");
    assert_eq!(attached, records);

    let receiver_guard = receiver.read();
    let served = receiver_guard.snapshot().expect("receiver snapshot");
    let live = source.snapshot().expect("source snapshot");
    assert_eq!(
        served
            .capability_watermark(IndexCapability::CompactFilters)
            .expect("watermark read"),
        Some(base),
        "coverage is published at the base"
    );
    assert_eq!(
        rows_with_prefix(&receiver_store, ColumnFamily::Filters, &[]),
        fixture.hashes.len(),
        "one height-keyed row per block"
    );

    let mut previous = [0_u8; 32];
    for (height, hash) in fixture.hashes.iter().enumerate() {
        let height = u32::try_from(height).expect("fixture height fits u32");
        let attached_filter = served
            .compact_filter(height, hash)
            .expect("filter read")
            .expect("attached row");
        let live_filter = live
            .compact_filter(height, hash)
            .expect("live filter read")
            .expect("live row");
        assert_eq!(
            attached_filter, live_filter,
            "height {height} matches the live writer"
        );
        let filter_hash = sha256d::Hash::hash(&attached_filter.filter).to_byte_array();
        assert_eq!(
            attached_filter.hash, filter_hash,
            "height {height} filter hash is dSHA256 of the filter bytes"
        );
        let mut chained = [0_u8; 64];
        chained[..32].copy_from_slice(&filter_hash);
        chained[32..].copy_from_slice(&previous);
        let header = sha256d::Hash::hash(&chained).to_byte_array();
        assert_eq!(
            attached_filter.header, header,
            "height {height} header chains from the previous header"
        );
        previous = header;
    }
}
// SNP-05
#[test]
fn small_budget_compact_filter_restore_matches_live_rows() {
    let fixture = load_fixture();
    let source = build_source(&fixture);
    let root = tempfile::tempdir().expect("tempdir");
    let (path, artifact) = produce(
        &source,
        &fixture,
        Network::Regtest,
        root.path(),
        "bounded.dat",
    );
    let size = fs::metadata(&path).expect("artifact metadata").len();
    let base = base_at_tip(&fixture);
    let decoded = size.saturating_sub(u64::try_from(HEADER_LEN).expect("header fits u64"));
    let budget = SpillBudget::new(4096);
    assert!(
        decoded > budget.peak_bytes().max(4096),
        "the artifact must exceed the budget to prove streaming: {decoded} <= 4096"
    );

    let (receiver_store, receiver) = empty_receiver();
    let attached = attach_compact_filter_artifact(
        &receiver,
        &target(&path, base, artifact.sha256, artifact.bytes),
        root.path(),
        &budget,
    )
    .expect("a bounded re-encode attaches");
    assert_eq!(attached, artifact.records);
    assert!(
        budget.peak_bytes() > 0,
        "the bounded re-encode charges its rows to the budget"
    );
    assert!(
        budget.peak_bytes() <= 4096,
        "the re-encode buffered {} bytes above the 4096-byte budget",
        budget.peak_bytes()
    );

    let receiver_guard = receiver.read();
    let served = receiver_guard.snapshot().expect("receiver snapshot");
    let live = source.snapshot().expect("source snapshot");
    for (height, hash) in fixture.hashes.iter().enumerate() {
        let height = u32::try_from(height).expect("fixture height fits u32");
        let attached_filter = served
            .compact_filter(height, hash)
            .expect("filter read")
            .expect("attached row");
        let live_filter = live
            .compact_filter(height, hash)
            .expect("live filter read")
            .expect("live row");
        assert_eq!(
            attached_filter, live_filter,
            "height {height} matches the live writer"
        );
    }
    assert_eq!(
        rows_with_prefix(&receiver_store, ColumnFamily::Filters, &[]),
        fixture.hashes.len(),
        "one height-keyed row per block"
    );
}

#[test]
fn compact_filter_artifact_forged_digest_is_refused_without_rows() {
    let fixture = load_fixture();
    let source = build_source(&fixture);
    let root = tempfile::tempdir().expect("tempdir");
    let (path, artifact) = produce(
        &source,
        &fixture,
        Network::Regtest,
        root.path(),
        "forged.dat",
    );
    let mut forged = artifact.sha256;
    forged[0] ^= 0x01;

    let (receiver_store, receiver) = empty_receiver();
    let error = attach_compact_filter_artifact(
        &receiver,
        &target(&path, base_at_tip(&fixture), forged, artifact.bytes),
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect_err("a forged digest is refused");
    assert!(
        matches!(error, IndexBundleError::ArtifactHash { .. }),
        "got {error:?}"
    );
    assert_untouched(&receiver_store, &receiver);
}

#[test]
fn compact_filter_artifact_broken_header_chain_is_refused_without_rows() {
    let fixture = load_fixture();
    let source = build_source(&fixture);
    let root = tempfile::tempdir().expect("tempdir");
    let (path, _artifact) = produce(
        &source,
        &fixture,
        Network::Regtest,
        root.path(),
        "chain.dat",
    );
    let mut bytes = fs::read(&path).expect("artifact bytes");
    let broken: usize = 37;
    let at = record_offset(&bytes, broken);
    let mut length = [0_u8; 4];
    length.copy_from_slice(&bytes[at + LENGTH_AT..at + LENGTH_AT + 4]);
    let length = usize::try_from(u32::from_le_bytes(length)).expect("fits");
    assert!(length > 1, "the record carries a filter");
    let filter_start = at + RECORD_FIXED_LEN;
    bytes[filter_start + 1] ^= 0x01;
    let new_filter_hash =
        sha256d::Hash::hash(&bytes[filter_start..filter_start + length]).to_byte_array();
    bytes[at + FILTER_HASH_AT..at + FILTER_HASH_AT + 32].copy_from_slice(&new_filter_hash);
    let tampered = root.path().join("chain-tampered.dat");
    fs::write(&tampered, &bytes).expect("tampered artifact");
    let digest = sha256::Hash::hash(&bytes).to_byte_array();

    let (receiver_store, receiver) = empty_receiver();
    let error = attach_compact_filter_artifact(
        &receiver,
        &target(
            &tampered,
            base_at_tip(&fixture),
            digest,
            u64::try_from(bytes.len()).expect("fits"),
        ),
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect_err("a broken filter header chain is refused");
    assert!(
        matches!(
            error,
            IndexBundleError::ArtifactFraming { record, .. }
                if record == u64::try_from(broken).expect("fits")
        ),
        "got {error:?}"
    );
    assert_untouched(&receiver_store, &receiver);
}

#[test]
fn compact_filter_artifact_foreign_base_hash_is_refused_without_rows() {
    let fixture = load_fixture();
    let source = build_source(&fixture);
    let root = tempfile::tempdir().expect("tempdir");
    let (path, artifact) = produce(&source, &fixture, Network::Regtest, root.path(), "base.dat");
    let mut foreign = base_at_tip(&fixture);
    foreign.hash[0] ^= 0x01;

    let (receiver_store, receiver) = empty_receiver();
    let error = attach_compact_filter_artifact(
        &receiver,
        &target(&path, foreign, artifact.sha256, artifact.bytes),
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect_err("a foreign base hash is refused");
    assert!(
        matches!(error, IndexBundleError::ArtifactHeader { .. }),
        "got {error:?}"
    );
    assert_untouched(&receiver_store, &receiver);
}

#[test]
fn compact_filter_artifact_truncated_payload_is_refused_without_rows() {
    let fixture = load_fixture();
    let source = build_source(&fixture);
    let root = tempfile::tempdir().expect("tempdir");
    let (path, _artifact) = produce(&source, &fixture, Network::Regtest, root.path(), "full.dat");
    let bytes = fs::read(&path).expect("artifact bytes");
    let short = &bytes[..bytes.len() - 5];
    let truncated = root.path().join("short.dat");
    fs::write(&truncated, short).expect("truncated artifact");
    let digest = sha256::Hash::hash(short).to_byte_array();

    let (receiver_store, receiver) = empty_receiver();
    let error = attach_compact_filter_artifact(
        &receiver,
        &target(
            &truncated,
            base_at_tip(&fixture),
            digest,
            u64::try_from(short.len()).expect("fits"),
        ),
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect_err("a truncated payload is refused");
    assert!(
        matches!(error, IndexBundleError::ArtifactHeader { .. }),
        "got {error:?}"
    );
    assert_untouched(&receiver_store, &receiver);
}

#[test]
fn compact_filter_artifact_second_attach_over_populated_family_is_refused() {
    let fixture = load_fixture();
    let source = build_source(&fixture);
    let root = tempfile::tempdir().expect("tempdir");
    let (path, artifact) = produce(
        &source,
        &fixture,
        Network::Regtest,
        root.path(),
        "twice.dat",
    );
    let base = base_at_tip(&fixture);
    let manifest = target(&path, base, artifact.sha256, artifact.bytes);

    let (receiver_store, receiver) = empty_receiver();
    attach_compact_filter_artifact(
        &receiver,
        &manifest,
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect("the first attach succeeds");
    let before = rows_with_prefix(&receiver_store, ColumnFamily::Filters, &[]);
    assert_eq!(
        before,
        fixture.hashes.len(),
        "the first attach stores one height-keyed row per block"
    );

    let error = attach_compact_filter_artifact(
        &receiver,
        &manifest,
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect_err("a populated CompactFilters family refuses a second attach");
    assert!(
        matches!(
            error,
            IndexBundleError::Index(IndexError::WatermarkMismatch { .. })
        ),
        "got {error:?}"
    );
    assert_eq!(
        rows_with_prefix(&receiver_store, ColumnFamily::Filters, &[]),
        before,
        "the refused attach leaves the rows as they were"
    );
}

// SNP-02
#[test]
fn compact_filter_artifact_nonzero_floor_is_refused_without_rows() {
    let fixture = load_fixture();
    let source = build_source(&fixture);
    let root = tempfile::tempdir().expect("tempdir");
    let (path, artifact) = produce(
        &source,
        &fixture,
        Network::Regtest,
        root.path(),
        "floor.dat",
    );
    let mut raised = target(
        &path,
        base_at_tip(&fixture),
        artifact.sha256,
        artifact.bytes,
    );
    raised.floor = 1;

    let (receiver_store, receiver) = empty_receiver();
    let error = attach_compact_filter_artifact(
        &receiver,
        &raised,
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect_err("a compact filter floor above zero is refused");
    assert!(
        matches!(error, IndexBundleError::ArtifactHeader { .. }),
        "got {error:?}"
    );
    assert_untouched(&receiver_store, &receiver);
}
