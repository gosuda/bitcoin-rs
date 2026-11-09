use super::super::spill::{SpillBudget, SpillSet};
use super::{StreamedFamily, stage_streamed};
use crate::IndexError;
use bitcoin_rs_storage::{ColumnFamily, RocksDbStore, StorageError};
use std::io::ErrorKind;

#[derive(Debug, thiserror::Error)]
enum StageError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("stage_streamed accepted a short key")]
    ShortKeyAccepted,
}

fn keyed(prefix: u8, suffix: u8) -> Vec<u8> {
    let mut key = vec![0u8; 8];
    key.extend_from_slice(&[prefix, suffix]);
    key
}

// SNP-05
#[test]
fn short_key_fails_stage_streamed() -> Result<(), StageError> {
    let scratch = tempfile::tempdir()?;
    let budget = SpillBudget::new(u64::MAX);
    let set = SpillSet::new(&budget, scratch.path().to_path_buf());
    let mut sorter = set.sorter("short-key");
    sorter.push(keyed(0, 1), vec![1u8; 4])?;
    sorter.push(keyed(0, 2), vec![2u8; 4])?;
    sorter.push(vec![0xFFu8; 7], vec![3u8; 4])?;
    let runs = sorter.finish()?;
    let family = StreamedFamily { runs, rows: 3 };
    let dir = tempfile::tempdir()?;
    let store = RocksDbStore::open(dir.path())?;
    match stage_streamed(&store, 7, ColumnFamily::TxDir, &family, scratch.path()) {
        Ok(_) => Err(StageError::ShortKeyAccepted),
        Err(IndexError::Storage(StorageError::Io(error))) => {
            assert_eq!(error.kind(), ErrorKind::InvalidData);
            Ok(())
        }
        Err(error) => panic!("short keys must fail as invalid data, got {error:?}"),
    }
}
