#![expect(
    clippy::expect_used,
    reason = "test: fixture setup failures abort the test with context"
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitcoin::consensus::deserialize;
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::hex::FromHex as _;
use bitcoin_rs_consensus::primitives::Network;
use bitcoin_rs_projection::portable::{
    IndexBundleError, ManifestArtifactTarget, ScriptHistoryArtifact, SpillBudget,
    attach_script_history_artifact, write_script_history_artifact,
};
use bitcoin_rs_projection::types::ScriptHistoryOccurrence;
use bitcoin_rs_projection::{
    IndexCapabilities, IndexCapability, IndexError, IndexReader, IndexWatermark, IndexWriter,
    Indexer, PreparedBatch, PreparedBatchLimits, ScriptHash, SpentCoin, SpentCoins,
    TxIndexSnapshot, index_format_version,
};
use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScanLimit};
use parking_lot::RwLock;

use crate::support::{TestError, common::MemoryStore};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../storage/tests/fixtures/core-v2/blocks200.json"
);
const SCAN_ALL: PrefixScanLimit = PrefixScanLimit {
    max_rows: 1_000_000,
    max_bytes: 256 << 20,
};
const FUNDING: u8 = ScriptHistoryOccurrence::FUNDING;

type Occurrence = (u32, [u8; 32], u8);

struct NoSpent;

impl SpentCoins for NoSpent {
    fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
        None
    }
}

struct Fixture {
    raw: Vec<Vec<u8>>,
    blocks: Vec<bitcoin::Block>,
    hashes: Vec<[u8; 32]>,
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

fn height_of(index: usize) -> u32 {
    u32::try_from(index).expect("fixture height fits in u32")
}

fn funded_scripthashes(fixture: &Fixture) -> Vec<[u8; 32]> {
    let mut hashes = BTreeSet::new();
    for block in &fixture.blocks {
        for tx in &block.txdata {
            for output in &tx.output {
                if !output.script_pubkey.is_op_return() {
                    let hash = sha256::Hash::hash(output.script_pubkey.as_bytes());
                    hashes.insert(hash.to_byte_array());
                }
            }
        }
    }
    hashes.into_iter().collect()
}

fn pays_scripthash(tx: &bitcoin::Transaction, scripthash: [u8; 32]) -> bool {
    tx.output.iter().any(|output| {
        !output.script_pubkey.is_op_return()
            && sha256::Hash::hash(output.script_pubkey.as_bytes()).to_byte_array() == scripthash
    })
}

fn expected_funding(fixture: &Fixture, scripthash: [u8; 32]) -> Vec<Occurrence> {
    let mut found = Vec::new();
    for (index, block) in fixture.blocks.iter().enumerate() {
        for tx in &block.txdata {
            if pays_scripthash(tx, scripthash) {
                let txid = tx.compute_txid().to_byte_array();
                found.push((height_of(index), txid, FUNDING));
            }
        }
    }
    found.sort_unstable();
    found
}

fn served_funding(snapshot: &dyn TxIndexSnapshot, scripthash: [u8; 32]) -> Vec<Occurrence> {
    let scan = snapshot
        .funding_rows(ScriptHash::from_byte_array(scripthash), SCAN_ALL)
        .expect("funding rows at the base");
    assert!(scan.complete, "one bounded scan covers the script");
    let mut found = Vec::new();
    for row in scan.rows {
        let height = row.row.height();
        let occurrences = ScriptHistoryOccurrence::decode_all(&row.value).expect("valid row");
        for occurrence in occurrences {
            if occurrence.scripthash.to_byte_array() == scripthash {
                found.push((height, occurrence.txid, occurrence.flags));
            }
        }
    }
    found.sort_unstable();
    found
}

fn build_source(fixture: &Fixture) -> (Arc<MemoryStore>, IndexWriter<MemoryStore>) {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1).expect("source writer");
    for (index, body) in fixture.raw.iter().enumerate() {
        let prepared = writer
            .prepare_block_with_spent_scripts(
                IndexCapabilities::HISTORICAL,
                height_of(index),
                fixture.hashes[index],
                body,
                &NoSpent,
            )
            .expect("fixture block prepares");
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        assert!(batch.try_push(prepared).is_ok(), "one block per batch");
        writer.commit_forward(batch).expect("fixture block commits");
    }
    (store, writer)
}

fn produce(
    source: &IndexWriter<MemoryStore>,
    network: Network,
    dir: &Path,
    name: &str,
) -> (PathBuf, ScriptHistoryArtifact) {
    let path = dir.join(name);
    let artifact = write_script_history_artifact(source, network, &path)
        .expect("producer writes the artifact");
    (path, artifact)
}

fn chain_tx_count(fixture: &Fixture) -> Result<u64, TestError> {
    let mut total = 0u64;
    for block in &fixture.blocks {
        total += u64::try_from(block.txdata.len())?;
    }
    Ok(total)
}

fn target(
    artifact: &Path,
    base: IndexWatermark,
    sha256: [u8; 32],
    size_bytes: u64,
    chain_tx_count: u64,
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
        chain_tx_count,
    }
}

fn empty_receiver() -> (Arc<MemoryStore>, RwLock<IndexWriter<MemoryStore>>) {
    let store = Arc::new(MemoryStore::default());
    let writer = IndexWriter::open(Arc::clone(&store), 1).expect("receiver writer");
    (store, RwLock::new(writer))
}

fn rows_of(store: &MemoryStore, cf: ColumnFamily) -> Vec<(Vec<u8>, Vec<u8>)> {
    store
        .iter_prefix(cf, &[])
        .expect("family scan")
        .collect::<Result<Vec<_>, _>>()
        .expect("family rows")
}

fn assert_untouched(store: &Arc<MemoryStore>) {
    let indexer = Indexer::new(Arc::clone(store));
    let snapshot = indexer.snapshot().expect("receiver snapshot");
    assert_eq!(
        snapshot
            .capability_watermark(IndexCapability::ScriptHistory)
            .expect("watermark read"),
        None,
        "a refused artifact publishes no watermark"
    );
    assert!(
        rows_of(store, ColumnFamily::Funding).is_empty(),
        "a refused artifact writes no Funding rows"
    );
    assert!(
        rows_of(store, ColumnFamily::Spending).is_empty(),
        "a refused artifact writes no Spending rows"
    );
}

fn base_at_tip(fixture: &Fixture) -> IndexWatermark {
    let last = fixture.blocks.len() - 1;
    IndexWatermark {
        height: height_of(last),
        hash: fixture.hashes[last],
    }
}

// SNP-05
#[test]
fn good_artifact_attaches_and_serves_the_live_rows_at_its_base() -> Result<(), TestError> {
    let fixture = load_fixture();
    let (source_store, source) = build_source(&fixture);
    let root = tempfile::tempdir().expect("tempdir");
    let (path, artifact) = produce(&source, Network::Regtest, root.path(), "good.dat");
    let base = base_at_tip(&fixture);
    assert_eq!(artifact.base, base, "the artifact is cut at the live base");

    let (receiver_store, receiver) = empty_receiver();
    let attached = attach_script_history_artifact(
        &receiver,
        &target(
            &path,
            base,
            artifact.sha256,
            artifact.bytes,
            chain_tx_count(&fixture)?,
        ),
        &fixture.hashes,
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect("a verified artifact attaches");
    assert_eq!(
        attached, artifact.records,
        "every artifact record is ingested"
    );
    assert!(attached > 0, "the fixture produces history rows");

    let indexer = Indexer::new(Arc::clone(&receiver_store));
    let snapshot = indexer.snapshot().expect("receiver snapshot");
    assert_eq!(
        snapshot
            .capability_watermark(IndexCapability::ScriptHistory)
            .expect("watermark read"),
        Some(base),
        "the attach publishes the manifest base as coverage"
    );
    assert_eq!(
        snapshot
            .capability_floor(IndexCapability::ScriptHistory)
            .expect("floor read"),
        0,
        "the attach publishes the manifest floor"
    );
    for scripthash in funded_scripthashes(&fixture) {
        let expected = expected_funding(&fixture, scripthash);
        assert!(!expected.is_empty(), "every listed script is funded");
        assert_eq!(
            served_funding(snapshot.as_ref(), scripthash),
            expected,
            "the served history equals the fixture's funding rows"
        );
    }
    assert_eq!(
        rows_of(&receiver_store, ColumnFamily::Funding),
        rows_of(&source_store, ColumnFamily::Funding),
        "attached Funding rows equal the live rows"
    );
    assert_eq!(
        rows_of(&receiver_store, ColumnFamily::Spending),
        rows_of(&source_store, ColumnFamily::Spending),
        "attached Spending rows equal the live rows"
    );
    Ok(())
}

// SNP-03
#[test]
fn forged_digest_is_refused_without_rows_or_watermark() -> Result<(), TestError> {
    let fixture = load_fixture();
    let (_source_store, source) = build_source(&fixture);
    let root = tempfile::tempdir().expect("tempdir");
    let (path, artifact) = produce(&source, Network::Regtest, root.path(), "forged.dat");
    let mut forged = artifact.sha256;
    forged[0] ^= 0x01;

    let (receiver_store, receiver) = empty_receiver();
    let error = attach_script_history_artifact(
        &receiver,
        &target(
            &path,
            base_at_tip(&fixture),
            forged,
            artifact.bytes,
            chain_tx_count(&fixture)?,
        ),
        &fixture.hashes,
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect_err("an artifact with a forged digest must be refused");
    assert!(
        matches!(error, IndexBundleError::ArtifactHash { .. }),
        "got {error:?}"
    );
    assert_untouched(&receiver_store);
    Ok(())
}

// SNP-03
#[test]
fn foreign_base_hash_is_refused_without_rows_or_watermark() -> Result<(), TestError> {
    let fixture = load_fixture();
    let (_source_store, source) = build_source(&fixture);
    let root = tempfile::tempdir().expect("tempdir");
    let (path, artifact) = produce(&source, Network::Regtest, root.path(), "base.dat");
    let mut foreign = base_at_tip(&fixture);
    foreign.hash[0] ^= 0x01;

    let (receiver_store, receiver) = empty_receiver();
    let error = attach_script_history_artifact(
        &receiver,
        &target(
            &path,
            foreign,
            artifact.sha256,
            artifact.bytes,
            chain_tx_count(&fixture)?,
        ),
        &fixture.hashes,
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect_err("an artifact cut at another base must be refused");
    assert!(
        matches!(error, IndexBundleError::ArtifactHeader { .. }),
        "got {error:?}"
    );
    assert_untouched(&receiver_store);
    Ok(())
}

// SNP-03
#[test]
fn foreign_network_magic_is_refused_without_rows_or_watermark() -> Result<(), TestError> {
    let fixture = load_fixture();
    let (_source_store, source) = build_source(&fixture);
    let root = tempfile::tempdir().expect("tempdir");
    let (path, artifact) = produce(&source, Network::Signet, root.path(), "signet.dat");

    let (receiver_store, receiver) = empty_receiver();
    let error = attach_script_history_artifact(
        &receiver,
        &target(
            &path,
            base_at_tip(&fixture),
            artifact.sha256,
            artifact.bytes,
            chain_tx_count(&fixture)?,
        ),
        &fixture.hashes,
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect_err("an artifact cut on another network must be refused");
    assert!(
        matches!(error, IndexBundleError::ArtifactHeader { .. }),
        "got {error:?}"
    );
    assert_untouched(&receiver_store);
    Ok(())
}

// SNP-03
#[test]
fn truncated_payload_is_refused_without_rows_or_watermark() -> Result<(), TestError> {
    let fixture = load_fixture();
    let (_source_store, source) = build_source(&fixture);
    let root = tempfile::tempdir().expect("tempdir");
    let (path, artifact) = produce(&source, Network::Regtest, root.path(), "full.dat");
    let bytes = fs::read(&path).expect("artifact bytes");
    let short = root.path().join("short.dat");
    fs::write(&short, &bytes[..bytes.len() - 5]).expect("truncated artifact");
    let short_bytes = fs::read(&short).expect("truncated bytes");
    let short_digest = sha256::Hash::hash(&short_bytes).to_byte_array();
    let base = base_at_tip(&fixture);

    let (receiver_store, receiver) = empty_receiver();
    let error = attach_script_history_artifact(
        &receiver,
        &target(
            &short,
            base,
            short_digest,
            u64::try_from(short_bytes.len()).expect("length fits"),
            chain_tx_count(&fixture)?,
        ),
        &fixture.hashes,
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect_err("a manifest matching a truncated payload must be refused");
    assert!(
        matches!(error, IndexBundleError::ArtifactHeader { .. }),
        "the header payload length must match the bytes: {error:?}"
    );

    let error = attach_script_history_artifact(
        &receiver,
        &target(
            &short,
            base,
            artifact.sha256,
            artifact.bytes,
            chain_tx_count(&fixture)?,
        ),
        &fixture.hashes,
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect_err("a manifest declaring the full length must refuse the short file");
    assert!(
        matches!(error, IndexBundleError::ArtifactLength { .. }),
        "got {error:?}"
    );
    assert_untouched(&receiver_store);
    Ok(())
}

#[test]
fn second_attach_over_a_populated_family_is_refused() -> Result<(), TestError> {
    let fixture = load_fixture();
    let (_source_store, source) = build_source(&fixture);
    let root = tempfile::tempdir().expect("tempdir");
    let (path, artifact) = produce(&source, Network::Regtest, root.path(), "twice.dat");
    let base = base_at_tip(&fixture);
    let manifest = target(
        &path,
        base,
        artifact.sha256,
        artifact.bytes,
        chain_tx_count(&fixture)?,
    );

    let (receiver_store, receiver) = empty_receiver();
    attach_script_history_artifact(
        &receiver,
        &manifest,
        &fixture.hashes,
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .map_err(|e| e.to_string())?;
    let before = rows_of(&receiver_store, ColumnFamily::Funding);

    let error = attach_script_history_artifact(
        &receiver,
        &manifest,
        &fixture.hashes,
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect_err("a populated ScriptHistory family must refuse a second attach");
    assert!(
        matches!(
            error,
            IndexBundleError::Index(IndexError::WatermarkMismatch { .. })
        ),
        "got {error:?}"
    );
    assert_eq!(
        rows_of(&receiver_store, ColumnFamily::Funding),
        before,
        "the refused attach leaves the attached rows unchanged"
    );
    Ok(())
}

#[test]
fn populated_rows_without_a_watermark_are_refused_and_kept() -> Result<(), TestError> {
    let fixture = load_fixture();
    let (_source_store, source) = build_source(&fixture);
    let root = tempfile::tempdir().expect("tempdir");
    let (path, artifact) = produce(&source, Network::Regtest, root.path(), "stray.dat");

    let (receiver_store, receiver) = empty_receiver();
    let stray_key = [0xEE_u8; 12];
    let stray_value = vec![0xEE_u8; ScriptHistoryOccurrence::SIZE];
    receiver_store
        .put(ColumnFamily::Funding, &stray_key, &stray_value)
        .expect("stray row is staged");
    let error = attach_script_history_artifact(
        &receiver,
        &target(
            &path,
            base_at_tip(&fixture),
            artifact.sha256,
            artifact.bytes,
            chain_tx_count(&fixture)?,
        ),
        &fixture.hashes,
        root.path(),
        &SpillBudget::new(u64::MAX),
    )
    .expect_err("a family that already holds rows must refuse the attach");
    assert!(
        matches!(
            error,
            IndexBundleError::Index(IndexError::ScriptHistoryPopulated)
        ),
        "got {error:?}"
    );
    assert_eq!(
        rows_of(&receiver_store, ColumnFamily::Funding),
        vec![(stray_key.to_vec(), stray_value)],
        "the refused attach keeps the rows it found"
    );
    Ok(())
}
