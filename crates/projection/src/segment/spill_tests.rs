use super::{MAX_MERGE_FAN_IN, SpillBudget, SpillSet, cursor_peak, merge, reset_cursor_peak};
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
        runs.len() > MAX_MERGE_FAN_IN,
        "the test needs more runs than the fan-in bound"
    );
    let merged: Vec<(Vec<u8>, Vec<u8>)> = merge(&runs)?.collect::<IoResult<_>>()?;
    let mut expected = pushed;
    expected.sort();
    assert_eq!(merged, expected);
    assert!(
        cursor_peak() <= MAX_MERGE_FAN_IN,
        "merge held more open runs than the fan-in bound"
    );
    Ok(())
}
