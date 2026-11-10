use super::{SpillBudget, SpillSet, cursor_peak, merge, reset_cursor_peak};
use std::io::Result as IoResult;

// PRJ-09
#[test]
fn bounded_merge_matches_sorted_reference() -> IoResult<()> {
    reset_cursor_peak();
    const ROWS: u64 = 21;
    let scratch = tempfile::tempdir()?;
    let budget = SpillBudget::new(0);
    let set = SpillSet::new(&budget, scratch.path().to_path_buf());
    let mut sorter = set.sorter("fanin");
    let mut pushed: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for order in 0..ROWS {
        let key = ((order * 5) % ROWS).to_be_bytes().to_vec();
        let value = (((order * 5) % ROWS) ^ 0x9e37).to_be_bytes().to_vec();
        sorter.push(key.clone(), value.clone())?;
        pushed.push((key, value));
    }
    let runs = sorter.finish()?;
    assert!(
        runs.len() > 16,
        "the test needs more runs than the fan-in bound"
    );
    let merged: Vec<(Vec<u8>, Vec<u8>)> = merge(&runs)?.collect::<IoResult<_>>()?;
    let mut expected = pushed;
    expected.sort();
    assert_eq!(merged, expected);
    assert!(
        cursor_peak() <= 16,
        "merge held more open runs than the fan-in bound"
    );
    Ok(())
}

// PRJ-09
#[test]
fn dropped_spill_set_removes_run_files() -> IoResult<()> {
    let scratch = tempfile::tempdir()?;
    {
        let budget = SpillBudget::new(0);
        let set = SpillSet::new(&budget, scratch.path().to_path_buf());
        let mut sorter = set.sorter("drop");
        sorter.push(vec![0u8; 8], vec![1u8])?;
        sorter.push(vec![1u8; 8], vec![2u8])?;
    }
    let leftover: Vec<_> = std::fs::read_dir(scratch.path())?.collect::<IoResult<_>>()?;
    assert!(
        leftover.is_empty(),
        "dropping the spill set must remove its run files"
    );
    Ok(())
}
// PRJ-09
#[test]
fn three_level_merge_keeps_only_final_intermediates() -> IoResult<()> {
    const ROWS: u64 = 300;
    let scratch = tempfile::tempdir()?;
    let budget = SpillBudget::new(0);
    let set = SpillSet::new(&budget, scratch.path().to_path_buf());
    let mut sorter = set.sorter("levels");
    let mut pushed: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for order in 0..ROWS {
        let key = ((order * 5) % ROWS).to_be_bytes().to_vec();
        let value = (((order * 5) % ROWS) ^ 0x9e37).to_be_bytes().to_vec();
        sorter.push(key.clone(), value.clone())?;
        pushed.push((key, value));
    }
    let runs = sorter.finish()?;
    assert!(
        runs.len() > 256,
        "the test needs more runs than two fan-in levels hold"
    );
    let merge_handle = merge(&runs)?;
    let mut final_outputs = runs.len();
    while final_outputs > 16 {
        final_outputs = final_outputs.div_ceil(16);
    }
    let entries = std::fs::read_dir(scratch.path())?.collect::<IoResult<Vec<_>>>()?;
    let intermediates = entries
        .iter()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("spill-merge-")
        })
        .count();
    assert_eq!(intermediates, final_outputs);
    assert_eq!(entries.len(), runs.len() + final_outputs);
    let merged: Vec<(Vec<u8>, Vec<u8>)> = merge_handle.collect::<IoResult<_>>()?;
    let mut expected = pushed;
    expected.sort();
    assert_eq!(merged, expected);
    let entries = std::fs::read_dir(scratch.path())?.collect::<IoResult<Vec<_>>>()?;
    assert!(
        entries.iter().all(|entry| !entry
            .file_name()
            .to_string_lossy()
            .starts_with("spill-merge-")),
        "dropping the merge must remove its intermediate files"
    );
    assert_eq!(entries.len(), runs.len());
    Ok(())
}

// PRJ-09
#[test]
fn failed_chunk_removes_earlier_intermediates() -> IoResult<()> {
    const ROWS: u64 = 20;
    let scratch = tempfile::tempdir()?;
    let budget = SpillBudget::new(0);
    let set = SpillSet::new(&budget, scratch.path().to_path_buf());
    let mut sorter = set.sorter("fault");
    for order in 0..ROWS {
        sorter.push(order.to_be_bytes().to_vec(), vec![0u8; 8])?;
    }
    let runs = sorter.finish()?;
    assert!(
        runs.len() > 16,
        "the test needs more runs than one chunk holds"
    );
    let Some(last) = runs.last() else {
        return Err(std::io::Error::other("the test needs at least one run"));
    };
    std::fs::remove_file(last.path())?;
    let result = merge(&runs);
    assert!(
        result.is_err(),
        "merge must fail while a later chunk input is missing"
    );
    let entries = std::fs::read_dir(scratch.path())?.collect::<IoResult<Vec<_>>>()?;
    assert!(
        entries.iter().all(|entry| !entry
            .file_name()
            .to_string_lossy()
            .starts_with("spill-merge-")),
        "a failed merge must leave zero intermediate files"
    );
    Ok(())
}

// PRJ-09
#[test]
fn oversized_row_header_is_refused() -> IoResult<()> {
    let scratch = tempfile::tempdir()?;
    let budget = SpillBudget::new(u64::MAX);
    let set = SpillSet::new(&budget, scratch.path().to_path_buf());
    let mut sorter = set.sorter("bound");
    sorter.push(vec![7u8; 8], vec![9u8; 8])?;
    let runs = sorter.finish()?;
    assert_eq!(runs.len(), 1);
    let mut bad = Vec::new();
    bad.extend_from_slice(&u32::MAX.to_le_bytes());
    bad.extend_from_slice(&0u32.to_le_bytes());
    bad.extend_from_slice(&[0u8; 8]);
    let Some(first) = runs.first() else {
        return Err(std::io::Error::other("the test needs at least one run"));
    };
    std::fs::write(first.path(), &bad)?;
    let result = merge(&runs);
    let Err(error) = result else {
        return Err(std::io::Error::other(
            "merge accepted a row header longer than the file",
        ));
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    Ok(())
}
