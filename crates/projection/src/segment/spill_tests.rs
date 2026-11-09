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
