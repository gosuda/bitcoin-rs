use std::{
    fs::OpenOptions,
    io::{self, Write as _},
};

use tempfile::tempdir;

use super::{
    BLOCK_FILE_MAGIC, BlockFilePosition, FlatFileBlockStore, RECORD_HEADER_LEN_U64, write_record,
};

fn hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

struct VectoredTestWriter {
    bytes: Vec<u8>,
    max_write: usize,
    interrupt_once: bool,
}

impl io::Write for VectoredTestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = bytes.len().min(self.max_write);
        self.bytes.extend_from_slice(&bytes[..written]);
        Ok(written)
    }

    fn write_vectored(&mut self, slices: &[io::IoSlice<'_>]) -> io::Result<usize> {
        if self.interrupt_once {
            self.interrupt_once = false;
            return Err(io::Error::new(io::ErrorKind::Interrupted, "try again"));
        }
        let requested = slices.iter().map(|slice| slice.len()).sum::<usize>();
        let written = requested.min(self.max_write);
        let mut remaining = written;
        for slice in slices {
            let count = remaining.min(slice.len());
            self.bytes.extend_from_slice(&slice[..count]);
            remaining -= count;
            if remaining == 0 {
                break;
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn write_record_handles_short_interrupted_and_zero_writes() -> io::Result<()> {
    let mut writer = VectoredTestWriter {
        bytes: Vec::new(),
        max_write: 1,
        interrupt_once: true,
    };
    write_record(&mut writer, b"header", b"body")?;
    assert_eq!(writer.bytes, b"headerbody");

    let mut writer = VectoredTestWriter {
        bytes: Vec::new(),
        max_write: 0,
        interrupt_once: false,
    };
    let Err(error) = write_record(&mut writer, b"header", b"body") else {
        return Err(io::Error::other("a zero write must fail"));
    };
    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    Ok(())
}

#[test]
fn disk_usage_follows_the_files_through_appends_and_deletion() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let store = FlatFileBlockStore::open_with_max_file_bytes(data_dir.path(), 120, None)?;
    let blocks_dir = data_dir.path().join(super::BLOCK_FILE_DIRECTORY);
    assert_eq!(store.disk_usage(), 0, "a fresh store occupies nothing");

    let _first = store.persist(None, 1, hash(1), b"first")?;
    let after_first = store.disk_usage();
    assert_eq!(after_first, super::measure_blocks_dir(&blocks_dir)?);
    assert!(after_first > 0, "an appended body occupies bytes");

    let third = store.persist(None, 2, hash(2), b"a longer second body")?;
    let third = store.persist(None, 3, hash(3), b"third").map(|_| third)?;
    assert_eq!(third.file_no, 0, "the fixture must roll over");
    let after_rollover = store.disk_usage();
    assert_eq!(after_rollover, super::measure_blocks_dir(&blocks_dir)?);
    assert!(after_rollover > after_first, "appends add bytes");

    assert!(
        store.delete_file_if_not_current(0)?,
        "the fixture must have a prunable file"
    );
    let after_prune = store.disk_usage();
    assert_eq!(
        after_prune,
        super::measure_blocks_dir(&blocks_dir)?,
        "usage must follow the files after a deletion"
    );
    assert!(
        after_prune < after_rollover,
        "pruning a file must reduce the reported size, which is the whole \
             reason this is not a sum of block lengths"
    );
    Ok(())
}

#[test]
fn retry_recovers_an_append_whose_rollback_failed() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let store = FlatFileBlockStore::open(data_dir.path())?;
    let read_only = std::fs::File::open(store.file_path(0))?;
    let writable = {
        let mut writer = store.writer.lock();
        std::mem::replace(&mut writer.file, read_only)
    };

    let error = match store.append(1, hash(1), b"fails") {
        Ok(position) => panic!(
            "the read-only file accepted an append at {}:{}",
            position.file_no, position.offset
        ),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("failed to roll back block file"),
        "the rollback failure must be reported: {error}"
    );
    assert_eq!(
        store.disk_usage(),
        0,
        "a dirty counter must be reconciled against the file"
    );

    {
        let mut writer = store.writer.lock();
        assert_eq!(
            writer.rollback_offset,
            Some(0),
            "the retry must know where the valid prefix ends"
        );
        writer.file = writable;
    }

    let position = store.append(2, hash(2), b"retry")?;
    assert_eq!(position.offset, 0, "the retry must replace the torn frame");
    assert_eq!(
        store.load(position, 2, hash(2))?.as_deref(),
        Some(b"retry".as_slice())
    );
    assert_eq!(
        store.disk_usage(),
        super::measure_blocks_dir(&store.blocks_dir)?
    );
    Ok(())
}

#[test]
fn disk_usage_counts_only_block_files() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let blocks_dir = data_dir.path().join(super::BLOCK_FILE_DIRECTORY);
    let expected = {
        let store = FlatFileBlockStore::open_with_max_file_bytes(data_dir.path(), 120, None)?;
        let _ = store.persist(None, 1, hash(1), b"first")?;
        store.disk_usage()
    };

    std::fs::write(blocks_dir.join("blk00000.dat.bak"), vec![9_u8; 8_192])?;
    std::fs::write(blocks_dir.join("notes.txt"), vec![9_u8; 8_192])?;

    assert_eq!(
        super::measure_blocks_dir(&blocks_dir)?,
        expected,
        "the walk must ignore files that are not block files"
    );
    let reopened = FlatFileBlockStore::open_with_max_file_bytes(data_dir.path(), 120, None)?;
    assert_eq!(
        reopened.disk_usage(),
        expected,
        "a stray file must not be seeded into the usage figure"
    );
    Ok(())
}

/// A reopened store starts from the files it finds, not from zero.
#[test]
fn disk_usage_is_seeded_from_an_existing_directory() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let expected = {
        let store = FlatFileBlockStore::open_with_max_file_bytes(data_dir.path(), 120, None)?;
        let _ = store.persist(None, 1, hash(1), b"first")?;
        let _ = store.persist(None, 2, hash(2), b"second")?;
        store.disk_usage()
    };
    assert!(expected > 0, "the fixture must write something");

    let reopened = FlatFileBlockStore::open_with_max_file_bytes(data_dir.path(), 120, None)?;
    assert_eq!(
        reopened.disk_usage(),
        expected,
        "a reopened store must account for the files already there"
    );
    Ok(())
}

#[test]
fn round_trips_and_rolls_over_without_large_allocations() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let store = FlatFileBlockStore::open_with_max_file_bytes(data_dir.path(), 120, None)?;
    let first = store.persist(None, 1, hash(1), b"first")?;
    let second = store.persist(None, 2, hash(2), b"a longer second body")?;
    let third = store.persist(None, 3, hash(3), b"third")?;

    assert_eq!(first.file_no, 0);
    assert_eq!(second.file_no, 0);
    assert_eq!(third.file_no, 1);
    assert_eq!(store.load(first, 1, hash(1))?, Some(b"first".to_vec()));
    assert_eq!(
        store.load(second, 2, hash(2))?,
        Some(b"a longer second body".to_vec())
    );
    assert_eq!(store.load(third, 3, hash(3))?, Some(b"third".to_vec()));
    assert_eq!(
        store.load_prefix(second, 2, hash(2), 4)?,
        Some(b"a lo".to_vec())
    );
    Ok(())
}

#[test]
fn load_range_agrees_with_slicing_the_whole_body() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let store = FlatFileBlockStore::open(data_dir.path())?;
    let body: Vec<u8> = (0..=255_u8).cycle().take(1_000).collect();
    let position = store.persist(None, 9, hash(9), &body)?;

    for offset in (0_u32..1_000).step_by(37) {
        for len in [0_u32, 1, 2, 33, 256, 999] {
            let Some(end) = offset.checked_add(len) else {
                continue;
            };
            let ranged = store.load_range(position, 9, hash(9), offset, len)?;
            if end > 1_000 {
                assert_eq!(
                    ranged, None,
                    "a range past the body end must not be served short"
                );
                continue;
            }
            let start = usize::try_from(offset).unwrap_or_default();
            let stop = usize::try_from(end).unwrap_or_default();
            assert_eq!(
                ranged.as_deref(),
                Some(&body[start..stop]),
                "load_range({offset}, {len}) diverged from slicing load()"
            );
        }
    }
    Ok(())
}

#[test]
fn load_range_refuses_a_frame_that_is_not_the_requested_block() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let store = FlatFileBlockStore::open(data_dir.path())?;
    let position = store.persist(None, 11, hash(11), b"the original body")?;

    assert_eq!(store.load_range(position, 12, hash(11), 0, 4)?, None);
    assert_eq!(store.load_range(position, 11, hash(12), 0, 4)?, None);
    assert_eq!(
        store.load_range(position, 11, hash(11), 0, 4)?,
        Some(b"the ".to_vec())
    );
    Ok(())
}

#[test]
fn load_range_rejects_out_of_bounds_and_overflowing_ranges() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let store = FlatFileBlockStore::open(data_dir.path())?;
    let position = store.persist(None, 5, hash(5), b"0123456789")?;

    assert_eq!(store.load_range(position, 5, hash(5), 10, 1)?, None);
    assert_eq!(store.load_range(position, 5, hash(5), 11, 0)?, None);
    assert_eq!(store.load_range(position, 5, hash(5), 0, 11)?, None);
    assert_eq!(store.load_range(position, 5, hash(5), u32::MAX, 1)?, None);
    assert_eq!(
        store.load_range(position, 5, hash(5), 10, 0)?,
        Some(Vec::new())
    );
    assert_eq!(
        store.load_range(position, 5, hash(5), 9, 1)?,
        Some(b"9".to_vec())
    );
    Ok(())
}

#[test]
fn reader_matches_one_shot_across_order_and_rollover() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let store = FlatFileBlockStore::open_with_max_file_bytes(data_dir.path(), 120, None)?;
    let first = store.persist(None, 1, hash(1), b"first")?;
    let second = store.persist(None, 2, hash(2), b"a longer second body")?;
    let third = store.persist(None, 3, hash(3), b"third")?;
    let mut reader = store.reader();

    assert_eq!(reader.load(first, 1, hash(1))?, Some(b"first".to_vec()));
    assert_eq!(
        reader.load(second, 2, hash(2))?,
        Some(b"a longer second body".to_vec())
    );
    assert_eq!(reader.load(third, 3, hash(3))?, Some(b"third".to_vec()));
    assert_eq!(
        reader.load(second, 2, hash(2))?,
        store.load(second, 2, hash(2))?
    );
    assert_eq!(
        reader.load_prefix(second, 2, hash(2), 4)?,
        Some(b"a lo".to_vec())
    );
    assert_eq!(reader.load(first, 2, hash(1))?, None);
    assert_eq!(reader.load(first, 1, hash(1))?, Some(b"first".to_vec()));
    Ok(())
}

#[test]
fn reader_observes_a_later_append_to_the_open_file() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let store = FlatFileBlockStore::open(data_dir.path())?;
    let first = store.append(1, hash(1), b"first")?;
    let mut reader = store.reader();
    assert_eq!(reader.load(first, 1, hash(1))?, Some(b"first".to_vec()));

    let second = store.append(2, hash(2), b"second")?;
    assert_eq!(reader.load(second, 2, hash(2))?, Some(b"second".to_vec()));
    Ok(())
}

#[test]
fn reader_and_one_shot_reject_a_short_record() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let store = FlatFileBlockStore::open(data_dir.path())?;
    let position = store.append(11, hash(1), b"expected")?;
    let record_end = position
        .offset
        .checked_add(RECORD_HEADER_LEN_U64 + u64::from(position.len))
        .ok_or(crate::StorageError::InvalidOperation(
            "test record end overflow",
        ))?;
    OpenOptions::new()
        .write(true)
        .open(store.file_path(position.file_no))?
        .set_len(record_end - 1)?;

    assert_eq!(store.load(position, 11, hash(1))?, None);
    assert_eq!(store.reader().load(position, 11, hash(1))?, None);
    Ok(())
}

#[test]
fn reorg_hashes_at_one_height_remain_independent() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let store = FlatFileBlockStore::open(data_dir.path())?;
    let original = store.persist(None, 42, hash(1), b"original branch")?;
    let replacement = store.persist(None, 42, hash(2), b"replacement branch")?;

    assert_eq!(
        store.load(original, 42, hash(1))?,
        Some(b"original branch".to_vec())
    );
    assert_eq!(
        store.load(replacement, 42, hash(2))?,
        Some(b"replacement branch".to_vec())
    );
    Ok(())
}

#[test]
fn recovery_discards_a_torn_tail_before_the_next_append() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let position = {
        let store = FlatFileBlockStore::open(data_dir.path())?;
        store.append(7, hash(7), b"complete")?
    };
    let path = data_dir.path().join("blocks/blk00000.dat");
    let complete_end = std::fs::metadata(&path)?.len();
    let mut file = OpenOptions::new().append(true).open(&path)?;
    file.write_all(&BLOCK_FILE_MAGIC[..2])?;
    file.flush()?;

    let reopened = FlatFileBlockStore::open(data_dir.path())?;
    assert_eq!(
        reopened.load(position, 7, hash(7))?,
        Some(b"complete".to_vec())
    );
    let replacement = reopened.append(8, hash(8), b"replacement")?;
    assert_eq!(replacement.offset, complete_end);
    assert_eq!(
        std::fs::metadata(path)?.len(),
        complete_end + RECORD_HEADER_LEN_U64 + u64::from(replacement.len)
    );
    Ok(())
}

#[test]
fn committed_extent_refuses_corruption_without_changing_any_file() -> Result<(), crate::StorageError>
{
    for corrupt_length in [false, true] {
        for newer_orphan in [false, true] {
            let dir = tempdir()?;
            let store = FlatFileBlockStore::open(dir.path())?;
            store.append(1, hash(1), b"first")?;
            let middle = store.append(2, hash(2), b"middle")?;
            store.append(3, hash(3), b"last")?;
            let extent = crate::BodyExtent {
                file_no: store.current_file_number(),
                offset: store.append_offset(),
            };
            let path = store.file_path(extent.file_no);
            drop(store);
            let mut damaged = std::fs::read(&path)?;
            let offset = usize::try_from(middle.offset)
                .map_err(|_| crate::StorageError::InvalidOperation("test offset exceeds usize"))?;
            if corrupt_length {
                damaged[offset + 4..offset + 8].copy_from_slice(&u32::MAX.to_le_bytes());
            } else {
                damaged[offset] ^= 0xff;
            }
            std::fs::write(&path, &damaged)?;
            let orphan = dir.path().join("blocks/blk00001.dat");
            if newer_orphan {
                std::fs::write(&orphan, b"BR")?;
            }
            assert!(matches!(
                FlatFileBlockStore::open_with_committed_extent(dir.path(), extent),
                Err(crate::StorageError::IncompatibleData(_))
            ));
            assert_eq!(std::fs::read(path)?, damaged);
            if newer_orphan {
                assert_eq!(std::fs::read(orphan)?, b"BR");
            }
        }
    }
    Ok(())
}

#[test]
fn missing_or_short_committed_file_is_not_recreated_or_repaired() -> Result<(), crate::StorageError>
{
    for missing in [false, true] {
        let dir = tempdir()?;
        let store = FlatFileBlockStore::open(dir.path())?;
        store.append(1, hash(1), b"committed")?;
        let extent = crate::BodyExtent {
            file_no: store.current_file_number(),
            offset: store.append_offset(),
        };
        let path = store.file_path(extent.file_no);
        drop(store);
        if missing {
            std::fs::remove_file(&path)?;
        } else {
            std::fs::write(&path, b"BR")?;
        }
        assert!(matches!(
            FlatFileBlockStore::open_with_committed_extent(dir.path(), extent),
            Err(crate::StorageError::IncompatibleData(_))
        ));
        if missing {
            assert!(!path.exists());
        } else {
            assert_eq!(std::fs::read(path)?, b"BR");
        }
    }
    Ok(())
}

#[test]
fn admitted_extent_preserves_bodies_and_recovers_only_the_orphan_tail()
-> Result<(), crate::StorageError> {
    for newer_orphan in [false, true] {
        let dir = tempdir()?;
        let store = FlatFileBlockStore::open(dir.path())?;
        let committed = store.append(1, hash(1), b"committed")?;
        let extent = crate::BodyExtent {
            file_no: store.current_file_number(),
            offset: store.append_offset(),
        };
        let committed_path = store.file_path(extent.file_no);
        let committed_bytes = std::fs::read(&committed_path)?;
        drop(store);
        let tail_path = if newer_orphan {
            dir.path().join("blocks/blk00001.dat")
        } else {
            committed_path.clone()
        };
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&tail_path)?
            .write_all(b"BR")?;
        let reopened = FlatFileBlockStore::open_with_committed_extent(dir.path(), extent)?;
        assert_eq!(std::fs::read(committed_path)?, committed_bytes);
        assert_eq!(
            reopened.load(committed, 1, hash(1))?,
            Some(b"committed".to_vec())
        );
        assert_eq!(reopened.disk_usage(), extent.offset);
        let next = reopened.append(2, hash(2), b"next")?;
        assert_eq!(next.offset, if newer_orphan { 0 } else { extent.offset });
        assert_eq!(reopened.load(next, 2, hash(2))?, Some(b"next".to_vec()));
    }
    Ok(())
}

#[test]
fn committed_extent_allows_pruned_older_file_gaps() -> Result<(), crate::StorageError> {
    let dir = tempdir()?;
    let store = FlatFileBlockStore::open_with_max_file_bytes(dir.path(), 60, None)?;
    let old = store.append(1, hash(1), b"older")?;
    let retained = store.append(2, hash(2), b"retained")?;
    assert!(retained.file_no > old.file_no);
    let extent = crate::BodyExtent {
        file_no: store.current_file_number(),
        offset: store.append_offset(),
    };
    assert!(store.delete_file_if_not_current(old.file_no)?);
    drop(store);
    let reopened = FlatFileBlockStore::open_with_committed_extent(dir.path(), extent)?;
    assert_eq!(
        reopened.load(retained, 2, hash(2))?,
        Some(b"retained".to_vec())
    );
    Ok(())
}

#[test]
fn wrong_target_returns_none_instead_of_foreign_bytes() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let store = FlatFileBlockStore::open(data_dir.path())?;
    let position = store.append(11, hash(1), b"expected")?;

    assert_eq!(store.load(position, 12, hash(1))?, None);
    assert_eq!(store.load(position, 11, hash(2))?, None);
    Ok(())
}

#[test]
fn overflowing_position_returns_none() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let store = FlatFileBlockStore::open(data_dir.path())?;
    let _ = store.append(11, hash(1), b"expected")?;

    assert_eq!(
        store.load(
            BlockFilePosition {
                file_no: 0,
                offset: u64::MAX,
                len: 1,
            },
            11,
            hash(1),
        )?,
        None
    );
    Ok(())
}

#[test]
fn persist_reuses_only_a_matching_existing_position() -> Result<(), crate::StorageError> {
    let data_dir = tempdir()?;
    let store = FlatFileBlockStore::open(data_dir.path())?;
    let position = store.append(11, hash(1), b"expected")?;
    let before = std::fs::metadata(store.file_path(position.file_no))?.len();

    assert_eq!(
        store.persist(Some(position), 11, hash(1), b"expected")?,
        position
    );
    assert_eq!(
        std::fs::metadata(store.file_path(position.file_no))?.len(),
        before
    );

    let corrected = store.persist(Some(position), 11, hash(1), b"replaced")?;
    assert_ne!(corrected, position);
    assert_eq!(
        store.load(corrected, 11, hash(1))?.as_deref(),
        Some(b"replaced".as_slice())
    );

    let replacement = store.persist(Some(position), 11, hash(2), b"expected")?;
    assert_ne!(replacement, position);
    assert!(std::fs::metadata(store.file_path(position.file_no))?.len() > before);
    assert_eq!(
        store.load(replacement, 11, hash(2))?.as_deref(),
        Some(b"expected".as_slice())
    );
    Ok(())
}
