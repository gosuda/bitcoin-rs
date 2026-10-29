use super::*;
use crate::types::ScriptHash;
use crate::{ScriptLiveScan, TxIndexPage, TxIndexScan, TxIndexScanRow};
use bitcoin_rs_primitives::{OutPoint, Txid};
use std::cell::Cell;
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult = Result<(), Box<dyn Error>>;

thread_local! {
    static SYNC_CALLS: Cell<u32> = const { Cell::new(0) };
}

fn calls() -> u32 {
    SYNC_CALLS.with(Cell::get)
}

fn injected(dir: &Path) -> IndexBundleError {
    io_error(dir, io::Error::other("injected directory fsync failure"))
}

fn fail_first_sync(dir: &Path) -> Result<(), IndexBundleError> {
    let call = calls();
    SYNC_CALLS.with(|count| count.set(call + 1));
    if call == 0 {
        Err(injected(dir))
    } else {
        sync_dir(dir)
    }
}

fn fail_every_sync(dir: &Path) -> Result<(), IndexBundleError> {
    SYNC_CALLS.with(|count| count.set(count.get() + 1));
    Err(injected(dir))
}

fn stage(publication: &mut Publication, dir: &Path) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let artifact = dir.join(BundleFamily::TxLookup.file_name());
    let mut file = publication.create_new(&artifact)?;
    file.write_all(b"artifact")?;
    file.sync_all()?;
    drop(file);
    let manifest = dir.join(MANIFEST_FILE);
    write_manifest(publication, &manifest, b"{}")?;
    Ok((artifact, manifest))
}

#[test]
fn failed_final_directory_sync_removes_the_manifest_and_its_artifact() -> TestResult {
    let dir = tempfile::tempdir()?;
    let operator = dir.path().join("operator.dat");
    fs::write(&operator, b"keep")?;
    SYNC_CALLS.with(|count| count.set(0));
    let mut publication = Publication::with_sync(dir.path(), fail_first_sync);
    let (artifact, manifest) = stage(&mut publication, dir.path())?;
    assert!(matches!(
        publication.commit(),
        Err(IndexBundleError::Io { .. })
    ));
    assert!(
        !manifest.exists(),
        "a manifest must not survive a failed commit"
    );
    assert!(
        !artifact.exists(),
        "the artifact is removed after the manifest"
    );
    assert_eq!(calls(), 3, "commit, then one fsync per durable removal");
    assert_eq!(fs::read(&operator)?, b"keep");
    Ok(())
}

#[test]
fn undurable_manifest_removal_keeps_the_artifact_it_names() -> TestResult {
    let dir = tempfile::tempdir()?;
    SYNC_CALLS.with(|count| count.set(0));
    let mut publication = Publication::with_sync(dir.path(), fail_every_sync);
    let (artifact, manifest) = stage(&mut publication, dir.path())?;
    assert!(publication.commit().is_err());
    assert!(!manifest.exists());
    assert!(
        artifact.exists(),
        "an artifact is never removed before its manifest's removal is durable"
    );
    assert_eq!(calls(), 2, "the failed fsync is not retried");
    Ok(())
}

/// stored-key order with no overlap, gap, or repeat.
#[test]
fn paged_stream_preserves_row_order_across_small_pages() {
    let fake = PagedFake::new(25);
    let expected: Vec<[u8; 12]> = fake.rows.iter().map(|(row, _)| row.to_db_row()).collect();
    assert!(
        expected.windows(2).all(|pair| pair[0] < pair[1]),
        "fixture keys strictly increase"
    );
    let limit = PrefixScanLimit {
        max_rows: 7,
        max_bytes: usize::MAX,
    };
    let mut seen = Vec::new();
    let (records, bytes) = stream_family_pages(&fake, limit, &|| false, &mut |row, value| {
        seen.push(row.to_db_row());
        let bytes = u64::try_from(value.len()).expect("test row value fits u64");
        Ok((1, bytes))
    })
    .expect("paged stream completes");
    assert_eq!(seen, expected, "pages concatenate in stored-key order");
    assert_eq!(records, 25);
    assert_eq!(bytes, 25);
    assert!(
        fake.pages.load(Ordering::SeqCst) > 1,
        "the small page size forced multiple pages"
    );
}

#[test]
fn paged_stream_stops_at_cancellation() {
    let fake = PagedFake::new(5_000);
    let emitted = Cell::new(0_usize);
    let stop = Cell::new(false);
    let result = stream_family_pages(
        &fake,
        PrefixScanLimit {
            max_rows: 7,
            max_bytes: usize::MAX,
        },
        &|| stop.get(),
        &mut |_, _| {
            emitted.set(emitted.get() + 1);
            if emitted.get() == 100 {
                stop.set(true);
            }
            Ok((1, 0))
        },
    );
    assert!(
        matches!(result, Err(IndexBundleError::Cancelled)),
        "cancellation aborts the page loop"
    );
    assert!(
        fake.pages.load(Ordering::SeqCst) > 1,
        "cancellation fired after several small pages"
    );
}

#[test]
fn external_sort_aborts_when_cancelled() -> TestResult {
    let mut file = tempfile::tempfile()?;
    let records = 10_000_u64;
    for i in 0..records {
        let key = (records - i).to_be_bytes();
        write_framed(&mut file, &key, b"payload")?;
    }
    file.seek(SeekFrom::Start(0))?;
    let path = Path::new("cancel-sort");
    let polls = AtomicUsize::new(0);
    let cancelled = || polls.fetch_add(1, Ordering::SeqCst) >= 3;
    let result = external_sort(&mut file, 8, path, &cancelled);
    assert!(
        matches!(result, Err(IndexBundleError::Cancelled)),
        "a cancelled sort must abort instead of running to completion"
    );
    Ok(())
}

#[test]
fn enumeration_charges_positions_before_staging() -> TestResult {
    let valid = TxPositionValue::encode(&[TxPosition::new(0, 1), TxPosition::new(1, 1)]);
    let ceiling = u64::try_from(MAX_RESTORE_POSITIONS).unwrap_or(u64::MAX);
    let almost_full = ceiling.saturating_sub(1);
    assert!(
        matches!(
            RowExporter::charge_row(&valid, 7, almost_full),
            Err(IndexBundleError::ExportTooLarge { .. })
        ),
        "over-limit positions must fail before staging"
    );
    let charged = RowExporter::charge_row(&valid, 7, 0)?;
    assert_eq!(charged, 2, "valid positions charge their exact count");
    assert!(
        matches!(
            RowExporter::charge_row(&[], 7, 0),
            Err(IndexBundleError::SourceRow { .. })
        ),
        "empty values must fail validation before staging"
    );
    let zero_len = TxPositionValue::encode(&[TxPosition::new(0, 0)]);
    assert!(
        matches!(
            RowExporter::charge_row(&zero_len, 7, 0),
            Err(IndexBundleError::SourceRow { .. })
        ),
        "zero-length positions must fail validation before staging"
    );
    Ok(())
}

#[test]
fn paged_stream_accepts_an_empty_family() {
    let fake = PagedFake::new(0);
    let (records, bytes) = stream_family_pages(
        &fake,
        PrefixScanLimit {
            max_rows: 7,
            max_bytes: usize::MAX,
        },
        &|| false,
        &mut |_, _| Ok((1, 0)),
    )
    .expect("an empty family completes");
    assert_eq!((records, bytes), (0, 0));
    assert_eq!(fake.pages.load(Ordering::SeqCst), 1);
}

#[test]
fn paged_stream_refuses_a_page_that_makes_no_progress() {
    let fake = PagedFake {
        rows: Vec::new(),
        pages: AtomicUsize::new(0),
        stuck: true,
    };
    let result = stream_family_pages(
        &fake,
        PrefixScanLimit {
            max_rows: 7,
            max_bytes: usize::MAX,
        },
        &|| false,
        &mut |_, _| Ok((1, 0)),
    );
    assert!(
        matches!(result, Err(IndexBundleError::Index(_))),
        "an empty incomplete page is a seam error, not a spin"
    );
}

struct PagedFake {
    rows: Vec<(HashPrefixRow, Vec<u8>)>,
    pages: AtomicUsize,
    stuck: bool,
}

impl PagedFake {
    fn new(count: usize) -> Self {
        let mut rows = Vec::with_capacity(count);
        for index in 0..count {
            let prefix = u64::try_from(index)
                .expect("test row count fits u64")
                .to_be_bytes();
            let height = u32::try_from(index % 3).expect("test height residue fits u32");
            rows.push((HashPrefixRow::new(prefix, height), vec![0xA5]));
        }
        Self {
            rows,
            pages: AtomicUsize::new(0),
            stuck: false,
        }
    }

    fn lookup_error() -> IndexError {
        IndexError::from(StorageError::InvalidOperation(
            "the paged export test never calls row lookups",
        ))
    }
}

impl TxIndexSnapshot for PagedFake {
    fn capability_watermark(
        &self,
        _capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        Ok(None)
    }

    fn scan_family_page(
        &self,
        _family: TxIndexFamily,
        start_after: Option<&[u8]>,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexPage, IndexError> {
        self.pages.fetch_add(1, Ordering::SeqCst);
        if self.stuck {
            return Ok(TxIndexPage {
                rows: Vec::new(),
                complete: false,
            });
        }
        let mut rows = Vec::new();
        let mut bytes = 0_usize;
        for (row, value) in &self.rows {
            let key = row.to_db_row();
            if start_after.is_some_and(|cursor| key.as_slice() <= cursor) {
                continue;
            }
            let row_bytes = key.len() + value.len();
            if rows.len() >= limit.max_rows
                || (!rows.is_empty() && bytes.saturating_add(row_bytes) > limit.max_bytes)
            {
                return Ok(TxIndexPage {
                    rows,
                    complete: false,
                });
            }
            bytes = bytes.saturating_add(row_bytes);
            rows.push(TxIndexScanRow {
                row: *row,
                value: value.clone(),
            });
        }
        Ok(TxIndexPage {
            rows,
            complete: true,
        })
    }

    fn transaction_rows(
        &self,
        _txid: &Txid,
        _limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        Err(Self::lookup_error())
    }

    fn funding_rows(
        &self,
        _scripthash: ScriptHash,
        _limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        Err(Self::lookup_error())
    }

    fn spending_rows(
        &self,
        _outpoint: &OutPoint,
        _limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        Err(Self::lookup_error())
    }

    fn live_rows(
        &self,
        _scripthash: ScriptHash,
        _limit: PrefixScanLimit,
    ) -> Result<ScriptLiveScan, IndexError> {
        Err(Self::lookup_error())
    }
}

#[test]
fn committed_publication_keeps_both_files_and_never_replaces_an_entry() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut publication = Publication::new(dir.path());
    let (artifact, manifest) = stage(&mut publication, dir.path())?;
    publication.commit()?;
    assert_eq!(fs::read(&artifact)?, b"artifact");
    assert_eq!(fs::read(&manifest)?, b"{}");

    let mut again = Publication::new(dir.path());
    let refused = again.create_new(&manifest);
    assert!(
        matches!(&refused, Err(IndexBundleError::ExistingBundle(path)) if *path == manifest),
        "create-new must refuse an existing manifest"
    );
    drop(refused);
    drop(again);
    assert_eq!(
        fs::read(&manifest)?,
        b"{}",
        "a refused create leaves the existing entry untouched"
    );
    assert_eq!(fs::read(&artifact)?, b"artifact");
    Ok(())
}
