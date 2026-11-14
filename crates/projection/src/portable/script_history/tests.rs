use super::{Cut, write_records};
use crate::portable::artifact::{ARTIFACT_VERSION, ArtifactHeader};
use crate::portable::manifest::BundleFamily;
use crate::portable::{IndexBundleError, ManifestArtifactTarget, SpillBudget};
use crate::segment::bulk_builder::BulkSegmentBuilder;
use crate::segment::format::{
    TX_KIND_TXID, decode_spend_dir_key, decode_spend_dir_value, decode_tx_dir_key,
    decode_tx_dir_value, tx_dir_kind_prefix,
};
use crate::segment::import::{ImportedSegment, put_segment};
use crate::segment::import::{ScriptHistoryImportError, script_history_segment};
use crate::segment::{
    Coverage, NoSealedTxOrdinals, RecordPage, SegmentSnapshot, TailWriterState, append_tail_block,
    seal_tail_generation,
};
use crate::writer::ScriptHistoryAttachment;
use crate::{IndexCapabilities, IndexError, IndexWatermark, IndexWriter, index_format_version};
use bitcoin_rs_consensus::primitives::Network;
use bitcoin_rs_storage::budget::UnboundedBudget;
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, SpentPrevout, TxFacts};
use bitcoin_rs_storage::{Bytes, ColumnFamily, KvStore, PrefixScanLimit, RocksDbStore};
use parking_lot::RwLock;
use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use tempfile::{TempDir, tempdir};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type Rows = Vec<(Vec<u8>, Vec<u8>)>;

const BLOCKS: u32 = 50;
const TX_COUNT: u64 = 250;

fn cross_block_script(height: u32) -> Bytes {
    let mut script = b"\x76\xa9\x14cross_block_spent_\x88\xac".to_vec();
    script[15] = u8::try_from(height & 0xff).unwrap_or(0);
    Bytes::from(script)
}

fn self_transfer_script(height: u32) -> Bytes {
    let mut script = b"\x76\xa9\x14self_transfer_script\x88\xac".to_vec();
    script[16] = u8::try_from(height & 0xff).unwrap_or(0);
    Bytes::from(script)
}

fn cross_block_input(height: u32) -> SpentPrevout {
    let (txid, spent_height, script) = if height > 1 {
        let mut txid = [0u8; 32];
        txid[..4].copy_from_slice(&(height - 1).to_be_bytes());
        txid[4..8].copy_from_slice(&4u32.to_be_bytes());
        (txid, height - 1, cross_block_script(height - 1))
    } else {
        ([0xFFu8; 32], 0, cross_block_script(0))
    };
    SpentPrevout {
        txid,
        vout: 0,
        value: 33_000,
        script,
        height: spent_height,
        coinbase: false,
    }
}

fn cross_block_second_input(height: u32) -> SpentPrevout {
    let mut second = cross_block_input(height);
    second.vout = 1;
    second.value = 7_000;
    second
}

fn synthetic_blocks(count: u32) -> Vec<CommittedBlock> {
    let mut blocks = Vec::new();
    for h in 1..=count {
        let mut hash = [0u8; 32];
        hash[..4].copy_from_slice(&h.to_be_bytes());
        hash[31] = 0xAA;

        let mut txs = Vec::new();
        for t in 0..5u32 {
            let mut txid = [0u8; 32];
            txid[..4].copy_from_slice(&h.to_be_bytes());
            txid[4..8].copy_from_slice(&t.to_be_bytes());

            let mut inputs = Vec::new();
            if t > 0 && t != 2 {
                let mut prev_txid = [0u8; 32];
                prev_txid[..4].copy_from_slice(&h.to_be_bytes());
                prev_txid[4..8].copy_from_slice(&(t.saturating_sub(1)).to_be_bytes());
                inputs.push(SpentPrevout {
                    txid: prev_txid,
                    vout: 0,
                    value: 50_000,
                    script: Bytes::copy_from_slice(b"\x76\xa9\x14synthetic_prev_script\x88\xac"),
                    height: 0,
                    coinbase: false,
                });
            }
            if t == 2 {
                inputs.push(cross_block_input(h));
                inputs.push(cross_block_second_input(h));
            }
            if t == 4 {
                let mut older_txid = [0u8; 32];
                older_txid[0] = 0xCC;
                inputs.push(SpentPrevout {
                    txid: older_txid,
                    vout: 0,
                    value: 21_000,
                    script: self_transfer_script(h),
                    height: 0,
                    coinbase: false,
                });
            }

            let outputs = vec![
                CreatedOutput {
                    vout: 0,
                    value: if t == 4 { 20_000 } else { 50_000 },
                    script: if t == 4 {
                        self_transfer_script(h)
                    } else {
                        Bytes::copy_from_slice(b"\x76\xa9\x14synthetic_output_script\x88\xac")
                    },
                },
                CreatedOutput {
                    vout: 1,
                    value: 25_000,
                    script: Bytes::copy_from_slice(b"\x00\x14synthetic_witness_script"),
                },
            ];

            txs.push(TxFacts {
                txid,
                offset: t.saturating_mul(100),
                len: 90,
                inputs,
                outputs,
            });
        }

        blocks.push(CommittedBlock {
            height: h,
            hash,
            parent_hash: [0u8; 32],
            header: [0u8; 80],
            txs,
        });
    }
    blocks
}

fn base_of(blocks: &[CommittedBlock]) -> IndexWatermark {
    let last = blocks.last().map(|block| (block.height, block.hash));
    let (height, hash) = last.unwrap_or((0, [0; 32]));
    IndexWatermark { height, hash }
}

fn live_store(blocks: &[CommittedBlock]) -> TestResult<(TempDir, RocksDbStore)> {
    let dir = tempdir()?;
    let scratch = tempdir()?;
    let store = RocksDbStore::open(dir.path())?;
    let mut state = TailWriterState::new();
    for block in blocks {
        let mut batch = store.new_batch();
        append_tail_block(&mut batch, block, &mut state, &NoSealedTxOrdinals)?;
        store.write_durable(batch)?;
    }
    let base = base_of(blocks);
    seal_tail_generation(
        &store,
        1,
        base.height,
        IndexCapabilities::ALL,
        scratch.path(),
    )?;
    Ok((dir, store))
}

fn bulk_store(blocks: &[CommittedBlock]) -> TestResult<(TempDir, RocksDbStore)> {
    let dir = tempdir()?;
    let scratch = tempdir()?;
    let store = RocksDbStore::open(dir.path())?;
    let builder = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    );
    let coverage = builder.build_and_ingest(&store, 1, blocks)?;
    let published = ImportedSegment {
        coverage,
        next_ordinal: u32::try_from(TX_COUNT)?,
        records: 0,
        families: Vec::new(),
    };
    let mut batch = store.new_batch();
    put_segment(&mut batch, 1, &published, IndexCapabilities::ALL);
    store.write_durable(batch)?;
    Ok((dir, store))
}

fn export<S: KvStore>(store: &S, base: IndexWatermark) -> TestResult<Vec<u8>> {
    let snapshot = SegmentSnapshot::open(store.snapshot()?)?;
    let mut out = Vec::new();
    write_records(
        &snapshot,
        Cut {
            base,
            floor: 0,
            path: Path::new("export"),
        },
        &mut out,
    )?;
    Ok(out)
}

fn all_pages(
    mut page: impl FnMut(Option<&[u8]>) -> Result<RecordPage, IndexError>,
) -> Result<Rows, IndexError> {
    let mut rows = Vec::new();
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let current = page(cursor.as_deref())?;
        cursor = current.rows.last().map(|(key, _)| key.clone());
        rows.extend(current.rows);
        if current.complete {
            return Ok(rows);
        }
    }
}

fn whole_page_limit() -> PrefixScanLimit {
    PrefixScanLimit {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
    }
}

fn records_of<S: KvStore>(store: &S) -> TestResult<(Rows, Rows)> {
    let snapshot = SegmentSnapshot::open(store.snapshot()?)?;
    let funding = all_pages(|after| snapshot.funding_record_page(after, whole_page_limit()))?;
    let spending = all_pages(|after| snapshot.spending_record_page(after, whole_page_limit()))?;
    Ok((funding, spending))
}

#[test]
fn live_built_export_is_byte_identical_to_bulk_built_export() -> TestResult {
    let blocks = synthetic_blocks(BLOCKS);
    let base = base_of(&blocks);
    let (_live_dir, live) = live_store(&blocks)?;
    let (_bulk_dir, bulk) = bulk_store(&blocks)?;
    let from_live = export(&live, base)?;
    let from_bulk = export(&bulk, base)?;
    assert!(!from_bulk.is_empty(), "the bulk export carries records");
    assert_eq!(from_live, from_bulk);
    Ok(())
}

#[test]
fn paged_export_resumes_from_the_cursor_to_the_full_record_sequence() -> TestResult {
    let blocks = synthetic_blocks(BLOCKS);
    let (_dir, store) = live_store(&blocks)?;
    let snapshot = SegmentSnapshot::open(store.snapshot()?)?;
    let small = PrefixScanLimit {
        max_rows: 3,
        max_bytes: usize::MAX,
    };
    let whole_funding = all_pages(|after| snapshot.funding_record_page(after, whole_page_limit()))?;
    let paged_funding = all_pages(|after| snapshot.funding_record_page(after, small))?;
    assert_eq!(paged_funding, whole_funding);
    let whole_spending =
        all_pages(|after| snapshot.spending_record_page(after, whole_page_limit()))?;
    let paged_spending = all_pages(|after| snapshot.spending_record_page(after, small))?;
    assert!(
        !whole_spending.is_empty(),
        "the chain spends indexed outputs"
    );
    assert_eq!(paged_spending, whole_spending);
    Ok(())
}

#[test]
fn imported_segment_exports_the_same_pages_as_a_bulk_build() -> TestResult {
    let blocks = synthetic_blocks(BLOCKS);
    let base = base_of(&blocks);
    let (_live_dir, live) = live_store(&blocks)?;
    let (_bulk_dir, bulk) = bulk_store(&blocks)?;
    let (funding, spending) = records_of(&live)?;
    let coverage = Coverage::new(0, base.height, base.hash);
    let segment = script_history_segment(
        &funding,
        &spending,
        coverage,
        TX_COUNT,
        &block_hashes(&blocks),
    )?;

    let receiver_dir = tempdir()?;
    let scratch = tempdir()?;
    let receiver = Arc::new(RocksDbStore::open(receiver_dir.path())?);
    let writer = IndexWriter::open(Arc::clone(&receiver), 1)?;
    writer.attach_script_history_segment(
        &segment,
        &ScriptHistoryAttachment {
            base,
            floor: 0,
            scratch: scratch.path(),
        },
    )?;
    let imported = export(&*receiver, base)?;
    assert_eq!(imported, export(&bulk, base)?);
    Ok(())
}

#[test]
fn artifact_of_the_previous_version_is_refused_with_a_typed_error() -> TestResult {
    let blocks = synthetic_blocks(BLOCKS);
    let base = base_of(&blocks);
    let (_live_dir, live) = live_store(&blocks)?;
    let snapshot = SegmentSnapshot::open(live.snapshot()?)?;
    let mut body = Vec::new();
    let totals = write_records(
        &snapshot,
        Cut {
            base,
            floor: 0,
            path: Path::new("export"),
        },
        &mut body,
    )?;
    let header = ArtifactHeader {
        family: BundleFamily::ScriptHistory,
        artifact_version: 1,
        index_format: index_format_version(),
        network_magic: Network::Regtest.magic(),
        base_height: base.height,
        base_hash: base.hash,
        records: totals.records,
        payload_bytes: totals.payload_bytes,
    };
    let mut bytes = header.encode().to_vec();
    bytes.extend_from_slice(&body);

    let dir = tempdir()?;
    let path = dir.path().join("scripthistory.artifact");
    std::fs::write(&path, &bytes)?;
    let target = ManifestArtifactTarget {
        artifact_path: path,
        base_height: base.height,
        base_hash: base.hash,
        floor: 0,
        network: Network::Regtest,
        index_format: index_format_version(),
        sha256: Sha256::digest(&bytes).into(),
        size_bytes: u64::try_from(bytes.len())?,
        chain_tx_count: TX_COUNT,
    };
    let receiver_dir = tempdir()?;
    let scratch = tempdir()?;
    let receiver = RwLock::new(IndexWriter::open(
        Arc::new(RocksDbStore::open(receiver_dir.path())?),
        1,
    )?);
    let refused = crate::portable::restore::attach_script_history_artifact(
        &receiver,
        &target,
        &[],
        scratch.path(),
        &SpillBudget::new(u64::MAX),
    );
    assert!(
        matches!(
            &refused,
            Err(IndexBundleError::ArtifactHeader {
                reason: "artifact version is not supported",
                ..
            })
        ),
        "an old artifact version is refused: {refused:?}"
    );
    assert_ne!(ARTIFACT_VERSION, 1);
    Ok(())
}

fn block_hashes(blocks: &[CommittedBlock]) -> Vec<[u8; 32]> {
    std::iter::once([0_u8; 32])
        .chain(blocks.iter().map(|block| block.hash))
        .collect()
}

fn tx_directory<S: KvStore>(store: &S) -> TestResult<Rows> {
    let snapshot = store.snapshot()?;
    let rows = snapshot
        .iter_prefix(ColumnFamily::TxDir, &tx_dir_kind_prefix(1, TX_KIND_TXID))?
        .collect::<Result<Rows, _>>()?;
    Ok(rows)
}

fn imported_receiver(
    segment: &ImportedSegment,
    base: IndexWatermark,
) -> TestResult<(TempDir, Arc<RocksDbStore>)> {
    let receiver_dir = tempdir()?;
    let scratch = tempdir()?;
    let receiver = Arc::new(RocksDbStore::open(receiver_dir.path())?);
    let writer = IndexWriter::open(Arc::clone(&receiver), 1)?;
    writer.attach_script_history_segment(
        segment,
        &ScriptHistoryAttachment {
            base,
            floor: 0,
            scratch: scratch.path(),
        },
    )?;
    Ok((receiver_dir, receiver))
}

#[test]
fn imported_tx_directory_rows_carry_the_chain_block_hash() -> TestResult {
    let blocks = synthetic_blocks(BLOCKS);
    let base = base_of(&blocks);
    let (_live_dir, live) = live_store(&blocks)?;
    let (_bulk_dir, bulk) = bulk_store(&blocks)?;
    let (funding, spending) = records_of(&live)?;
    let coverage = Coverage::new(0, base.height, base.hash);
    let segment = script_history_segment(
        &funding,
        &spending,
        coverage,
        TX_COUNT,
        &block_hashes(&blocks),
    )?;
    let (_receiver_dir, receiver) = imported_receiver(&segment, base)?;
    let expected = tx_directory(&bulk)?;
    assert!(!expected.is_empty(), "the bulk build writes directory rows");
    assert_eq!(tx_directory(&*receiver)?, expected);
    Ok(())
}

#[test]
fn repeated_coinbase_txid_imports_to_the_same_pages_as_a_bulk_build() -> TestResult {
    let mut blocks = synthetic_blocks(BLOCKS);
    let earlier = blocks[9].txs[0].txid;
    blocks[29].txs[0].txid = earlier;
    let base = base_of(&blocks);
    let (_live_dir, live) = live_store(&blocks)?;
    let (_bulk_dir, bulk) = bulk_store(&blocks)?;
    let (funding, spending) = records_of(&live)?;
    let coverage = Coverage::new(0, base.height, base.hash);
    let segment = script_history_segment(
        &funding,
        &spending,
        coverage,
        TX_COUNT,
        &block_hashes(&blocks),
    )?;
    let (_receiver_dir, receiver) = imported_receiver(&segment, base)?;
    assert_eq!(tx_directory(&*receiver)?, tx_directory(&bulk)?);
    assert_eq!(export(&*receiver, base)?, export(&bulk, base)?);
    Ok(())
}

#[test]
fn a_height_without_a_verified_header_refuses_the_import() -> TestResult {
    let blocks = synthetic_blocks(BLOCKS);
    let base = base_of(&blocks);
    let (_live_dir, live) = live_store(&blocks)?;
    let (funding, spending) = records_of(&live)?;
    let coverage = Coverage::new(0, base.height, base.hash);
    let mut hashes = block_hashes(&blocks);
    hashes.pop();
    let refused = script_history_segment(&funding, &spending, coverage, TX_COUNT, &hashes);
    assert!(
        matches!(
            refused,
            Err(ScriptHistoryImportError::MissingHeader { height }) if height == BLOCKS
        ),
        "a height without a verified header refuses the import"
    );
    Ok(())
}
// SNP-05
#[test]
fn small_budget_restore_matches_the_live_export() -> TestResult {
    let blocks = synthetic_blocks(BLOCKS);
    let base = base_of(&blocks);
    let (_live_dir, live) = live_store(&blocks)?;
    let snapshot = SegmentSnapshot::open(live.snapshot()?)?;
    let mut body = Vec::new();
    let totals = write_records(
        &snapshot,
        Cut {
            base,
            floor: 0,
            path: Path::new("export"),
        },
        &mut body,
    )?;
    let header = ArtifactHeader {
        family: BundleFamily::ScriptHistory,
        artifact_version: ARTIFACT_VERSION,
        index_format: index_format_version(),
        network_magic: Network::Regtest.magic(),
        base_height: base.height,
        base_hash: base.hash,
        records: totals.records,
        payload_bytes: totals.payload_bytes,
    };
    let mut bytes = header.encode().to_vec();
    bytes.extend_from_slice(&body);
    let sha256: [u8; 32] = Sha256::digest(&bytes).into();
    let dir = tempdir()?;
    let artifact_path = dir.path().join("bounded.dat");
    std::fs::write(&artifact_path, &bytes)?;
    let budget = SpillBudget::new(8192);
    assert!(
        u64::try_from(bytes.len())? > budget.peak_bytes().max(8192),
        "the artifact must exceed the budget to prove streaming"
    );
    let target = ManifestArtifactTarget {
        artifact_path,
        base_height: base.height,
        base_hash: base.hash,
        floor: 0,
        network: Network::Regtest,
        index_format: index_format_version(),
        sha256,
        size_bytes: u64::try_from(bytes.len())?,
        chain_tx_count: TX_COUNT,
    };
    let receiver_dir = tempdir()?;
    let scratch = tempdir()?;
    let receiver_store = Arc::new(RocksDbStore::open(receiver_dir.path())?);
    let receiver = RwLock::new(IndexWriter::open(Arc::clone(&receiver_store), 1)?);
    let attached = crate::portable::restore::attach_script_history_artifact(
        &receiver,
        &target,
        &block_hashes(&blocks),
        scratch.path(),
        &budget,
    )?;
    assert_eq!(attached, totals.records);
    assert!(
        budget.peak_bytes() <= 8192,
        "the re-encode buffered {} bytes above the 8192-byte budget",
        budget.peak_bytes()
    );
    let receiver_export = export(&*receiver_store, base)?;
    assert_eq!(
        receiver_export,
        export(&live, base)?,
        "the bounded restore exports the live pages"
    );
    let family_rows = |store: &RocksDbStore, cf: ColumnFamily| {
        let rows = store
            .iter_prefix(cf, &[])?
            .collect::<Result<Vec<(Vec<u8>, Vec<u8>)>, _>>()?;
        let mut stripped: Vec<(Vec<u8>, Vec<u8>)> = rows
            .into_iter()
            .map(|(key, value)| (key[8..].to_vec(), value))
            .collect();
        stripped.sort_unstable();
        Ok::<_, Box<dyn Error>>(stripped)
    };
    assert_eq!(
        family_rows(&receiver_store, ColumnFamily::TxDir)?,
        family_rows(&live, ColumnFamily::TxDir)?,
        "the bounded restore serves the live directory rows"
    );
    Ok(())
}
// PRJ-06, PRJ-07
#[test]
fn one_spender_of_two_outpoints_names_one_transaction() -> TestResult {
    let script_a = Bytes::copy_from_slice(b"\x76\xa9\x14double_spend_script_a\x88\xac");
    let script_b = Bytes::copy_from_slice(b"\x76\xa9\x14double_spend_script_b\x88\xac");
    let script_c = Bytes::copy_from_slice(b"\x76\xa9\x14double_spend_script_c\x88\xac");
    let funding = CommittedBlock {
        height: 1,
        hash: [0x11_u8; 32],
        parent_hash: [0_u8; 32],
        header: [0_u8; 80],
        txs: vec![TxFacts {
            txid: [0xA1_u8; 32],
            offset: 0,
            len: 100,
            inputs: Vec::new(),
            outputs: vec![
                CreatedOutput {
                    vout: 0,
                    value: 50_000,
                    script: script_a.clone(),
                },
                CreatedOutput {
                    vout: 1,
                    value: 25_000,
                    script: script_b.clone(),
                },
            ],
        }],
    };
    let spending = CommittedBlock {
        height: 2,
        hash: [0x22_u8; 32],
        parent_hash: [0x11_u8; 32],
        header: [0_u8; 80],
        txs: vec![TxFacts {
            txid: [0xB1_u8; 32],
            offset: 0,
            len: 120,
            inputs: vec![
                SpentPrevout {
                    txid: [0xA1_u8; 32],
                    vout: 0,
                    value: 50_000,
                    script: script_a,
                    height: 1,
                    coinbase: false,
                },
                SpentPrevout {
                    txid: [0xA1_u8; 32],
                    vout: 1,
                    value: 25_000,
                    script: script_b,
                    height: 1,
                    coinbase: false,
                },
            ],
            outputs: vec![CreatedOutput {
                vout: 0,
                value: 74_000,
                script: script_c,
            }],
        }],
    };
    let blocks = vec![funding, spending];
    let base = base_of(&blocks);
    let (_live_dir, live) = live_store(&blocks)?;
    let snapshot = SegmentSnapshot::open(live.snapshot()?)?;
    let mut body = Vec::new();
    let totals = write_records(
        &snapshot,
        Cut {
            base,
            floor: 0,
            path: Path::new("export"),
        },
        &mut body,
    )?;
    let header = ArtifactHeader {
        family: BundleFamily::ScriptHistory,
        artifact_version: ARTIFACT_VERSION,
        index_format: index_format_version(),
        network_magic: Network::Regtest.magic(),
        base_height: base.height,
        base_hash: base.hash,
        records: totals.records,
        payload_bytes: totals.payload_bytes,
    };
    let mut bytes = header.encode().to_vec();
    bytes.extend_from_slice(&body);
    let dir = tempdir()?;
    let artifact_path = dir.path().join("double-spend.dat");
    std::fs::write(&artifact_path, &bytes)?;
    let target = ManifestArtifactTarget {
        artifact_path,
        base_height: base.height,
        base_hash: base.hash,
        floor: 0,
        network: Network::Regtest,
        index_format: index_format_version(),
        sha256: Sha256::digest(&bytes).into(),
        size_bytes: u64::try_from(bytes.len())?,
        chain_tx_count: 2,
    };
    let receiver_dir = tempdir()?;
    let scratch = tempdir()?;
    let receiver_store = Arc::new(RocksDbStore::open(receiver_dir.path())?);
    let receiver = RwLock::new(IndexWriter::open(Arc::clone(&receiver_store), 1)?);
    let budget = SpillBudget::new(u64::MAX);
    let attached = crate::portable::restore::attach_script_history_artifact(
        &receiver,
        &target,
        &block_hashes(&blocks),
        scratch.path(),
        &budget,
    )?;
    assert_eq!(attached, totals.records);
    let family_rows = |store: &RocksDbStore, cf: ColumnFamily| {
        let rows = store
            .iter_prefix(cf, &[])?
            .collect::<Result<Vec<(Vec<u8>, Vec<u8>)>, _>>()?;
        let mut stripped: Vec<(Vec<u8>, Vec<u8>)> = rows
            .into_iter()
            .map(|(key, value)| (key[8..].to_vec(), value))
            .collect();
        stripped.sort_unstable();
        Ok::<_, Box<dyn Error>>(stripped)
    };
    assert_eq!(
        family_rows(&receiver_store, ColumnFamily::TxDir)?,
        family_rows(&live, ColumnFamily::TxDir)?,
        "one spender of two outpoints restores the live ordinals"
    );
    let spender = [0xB1_u8; 32];
    let funding = [0xA1_u8; 32];
    let mut spender_ordinal = None;
    let mut funding_ordinal = None;
    for entry in receiver_store.iter_prefix(ColumnFamily::TxDir, &[])? {
        let (key, value) = entry?;
        let Some((_, txid, height)) = decode_tx_dir_key(&key) else {
            continue;
        };
        if txid == spender {
            let (block_hash, ordinal, offset, len) = decode_tx_dir_value(&value)
                .ok_or_else(|| std::io::Error::other("spender directory value"))?;
            assert_eq!(height, 2, "the spender row carries its confirming height");
            assert_eq!(
                block_hash, [0x22_u8; 32],
                "the spender row carries its block hash"
            );
            assert_eq!(offset, 0, "the spender row carries its block offset");
            assert_eq!(len, 120, "the spender row carries its block length");
            spender_ordinal = Some(ordinal);
        } else if txid == funding {
            let (_, ordinal, _, _) = decode_tx_dir_value(&value)
                .ok_or_else(|| std::io::Error::other("funding directory value"))?;
            assert_eq!(height, 1, "the funding row carries its confirming height");
            funding_ordinal = Some(ordinal);
        }
    }
    let spender_ordinal =
        spender_ordinal.ok_or_else(|| std::io::Error::other("the restore names the spender"))?;
    let funding_ordinal =
        funding_ordinal.ok_or_else(|| std::io::Error::other("the restore names the funding"))?;
    let mut resolved = 0;
    for entry in receiver_store.iter_prefix(ColumnFamily::SpendDir, &[])? {
        let (key, value) = entry?;
        let Some((_, creation_ordinal, vout)) = decode_spend_dir_key(&key) else {
            continue;
        };
        if creation_ordinal == funding_ordinal && (vout == 0 || vout == 1) {
            assert_eq!(
                decode_spend_dir_value(&value)
                    .ok_or_else(|| std::io::Error::other("spend directory value"))?,
                spender_ordinal,
                "both spent outpoints name the one spending transaction"
            );
            resolved += 1;
        }
    }
    assert_eq!(resolved, 2, "both spent outpoints resolve to the spender");
    Ok(())
}

// PRJ-05, PRJ-06, PRJ-07, IDX-07
#[test]
fn restored_history_identity_resolves_subsequent_spender() -> TestResult {
    use crate::types::{TxPosition, TxPositionValue};
    use crate::{IndexReader, PreparedBatch, PreparedBatchLimits};
    use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid};

    let script = Bytes::from_static(&[0x51]);
    let header = [0_u8; 80];
    let hash = bitcoin_rs_consensus::primitives::encode::double_sha256(&header).to_le_bytes();
    let funding_id = [0x22; 32];
    let funding = CommittedBlock {
        height: 0,
        hash,
        parent_hash: [0; 32],
        header,
        txs: vec![
            TxFacts {
                txid: funding_id,
                offset: 81,
                len: 100,
                inputs: Vec::new(),
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 5_000,
                    script: script.clone(),
                }],
            },
            TxFacts {
                txid: [0x33; 32],
                offset: 181,
                len: 100,
                inputs: Vec::new(),
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 0,
                    script: Bytes::from_static(&[0x6a, 0x00]),
                }],
            },
        ],
    };
    let base = IndexWatermark { height: 0, hash };
    let (_source_dir, source) = live_store(std::slice::from_ref(&funding))?;
    let source_snapshot = SegmentSnapshot::open(source.snapshot()?)?;
    let scratch = tempdir()?;
    let receiver_dir = tempdir()?;
    let receiver_store = Arc::new(RocksDbStore::open(receiver_dir.path())?);
    let receiver = RwLock::new(
        IndexWriter::open(Arc::clone(&receiver_store), 1)?
            .with_seal_scratch(scratch.path().to_path_buf()),
    );
    let budget = SpillBudget::new(u64::MAX);
    for family in [BundleFamily::TxLookup, BundleFamily::ScriptHistory] {
        let mut body = Vec::new();
        let records = match family {
            BundleFamily::TxLookup => {
                for tx in &funding.txs {
                    crate::portable::artifact::write_record(
                        &mut body,
                        &tx.txid,
                        0,
                        &[TxPosition::new(tx.offset, tx.len)],
                    )?;
                }
                2
            }
            BundleFamily::ScriptHistory => {
                write_records(
                    &source_snapshot,
                    Cut {
                        base,
                        floor: 0,
                        path: scratch.path(),
                    },
                    &mut body,
                )?
                .records
            }
            BundleFamily::CompactFilters => unreachable!(),
        };
        let mut bytes = ArtifactHeader {
            family,
            artifact_version: ARTIFACT_VERSION,
            index_format: index_format_version(),
            network_magic: Network::Regtest.magic(),
            base_height: 0,
            base_hash: hash,
            records,
            payload_bytes: u64::try_from(body.len())?,
        }
        .encode()
        .to_vec();
        bytes.extend_from_slice(&body);
        let artifact_path = scratch.path().join(family.file_name());
        std::fs::write(&artifact_path, &bytes)?;
        let target = ManifestArtifactTarget {
            artifact_path,
            base_height: 0,
            base_hash: hash,
            floor: 0,
            network: Network::Regtest,
            index_format: index_format_version(),
            sha256: Sha256::digest(&bytes).into(),
            size_bytes: u64::try_from(bytes.len())?,
            chain_tx_count: 2,
        };
        match family {
            BundleFamily::TxLookup => {
                crate::portable::restore::attach_tx_lookup_artifact(
                    &receiver,
                    &target,
                    &[&header],
                    scratch.path(),
                    &budget,
                )?;
                let rows = receiver.read().snapshot()?.transaction_rows(
                    &Txid(Hash256::from_le_bytes(&funding_id)),
                    whole_page_limit(),
                )?;
                assert!(rows.complete);
                assert_eq!(rows.rows.len(), 1);
                let positions = TxPositionValue::decode(&rows.rows[0].value)
                    .ok_or("lookup-only funding positions")?;
                assert_eq!(positions.len(), 1);
                assert_eq!(positions[0].offset(), 81);
                assert_eq!(positions[0].byte_len(), 100);
            }
            BundleFamily::ScriptHistory => {
                crate::portable::restore::attach_script_history_artifact(
                    &receiver,
                    &target,
                    &[hash],
                    scratch.path(),
                    &budget,
                )?;
            }
            BundleFamily::CompactFilters => unreachable!(),
        }
    }
    let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&funding_id)), 0);
    let spending = CommittedBlock {
        height: 1,
        hash: [0x33; 32],
        parent_hash: hash,
        header: [0; 80],
        txs: vec![TxFacts {
            txid: [0x44; 32],
            offset: 81,
            len: 120,
            inputs: vec![SpentPrevout {
                txid: funding_id,
                vout: 0,
                value: 5_000,
                script,
                height: 0,
                coinbase: false,
            }],
            outputs: vec![CreatedOutput {
                vout: 0,
                value: 4_000,
                script: Bytes::from_static(&[0x52]),
            }],
        }],
    };
    let mut writer = receiver.write();
    let prepared = writer.prepare_block_from_facts(IndexCapabilities::HISTORICAL, spending)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
    });
    assert!(batch.try_push(prepared).is_ok());
    writer.commit_forward(batch)?;
    let snapshot = writer.snapshot()?;
    let rows = snapshot.spending_rows(&outpoint, whole_page_limit())?;
    assert!(rows.complete);
    assert_eq!(rows.rows.len(), 1, "the committed spend must be visible");
    assert_eq!(rows.rows[0].row.height(), 1);
    let positions = TxPositionValue::decode(&rows.rows[0].value).ok_or("spender positions")?;
    assert_eq!(positions.len(), 1);
    assert_eq!(positions[0].offset(), 81);
    assert_eq!(positions[0].byte_len(), 120);
    Ok(())
}
