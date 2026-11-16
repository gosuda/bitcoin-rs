use super::{
    MAX_MERGE_FAN_IN, RunFile, SpillBudget, SpillSet, cursor_peak, merge, reset_cursor_peak,
};
use std::io::Result as IoResult;

fn retained_capacity(buffer: &Vec<(Vec<u8>, Vec<u8>)>) -> IoResult<u64> {
    let retained = buffer.capacity() * std::mem::size_of::<(Vec<u8>, Vec<u8>)>()
        + buffer
            .iter()
            .map(|(key, value)| key.capacity() + value.capacity())
            .sum::<usize>();
    u64::try_from(retained).map_err(std::io::Error::other)
}

fn single_row_runs(
    scratch: &std::path::Path,
    rows: &[(Vec<u8>, Vec<u8>)],
) -> IoResult<Vec<RunFile>> {
    rows.iter()
        .enumerate()
        .map(|(index, (key, value))| {
            let path = scratch.join(format!("input-{index}.bin"));
            let mut file = std::fs::File::create(&path)?;
            super::write_row(&mut file, key, value)?;
            Ok(RunFile { path, level: 0 })
        })
        .collect()
}

// SNP-05, PRJ-09
#[test]
fn retained_row_capacity_is_charged_and_released() -> IoResult<()> {
    let scratch = tempfile::tempdir()?;
    let budget = SpillBudget::new(4096);
    let set = SpillSet::new(&budget, scratch.path().to_path_buf());
    let mut sorter = set.sorter("capacity");
    let mut key = Vec::with_capacity(71);
    key.push(2);
    let mut value = Vec::with_capacity(113);
    value.push(9);
    sorter.push(key, value)?;
    for key in [1, 2, 0, 3] {
        sorter.push(vec![key], vec![9])?;
    }
    {
        let sorters = set.sorters.borrow();
        let state = &sorters[0];
        let retained = retained_capacity(&state.buffer)?;
        assert_eq!(budget.current_bytes(), retained);
        assert_eq!(state.buffered, retained);
        assert!(budget.current_bytes() <= budget.limit);
    }
    let runs = sorter.finish()?;
    assert_eq!(set.sorters.borrow()[0].buffer.capacity(), 0);
    assert_eq!(budget.current_bytes(), 0);
    let rows = merge(&runs)?.collect::<IoResult<Vec<_>>>()?;
    assert_eq!(
        rows,
        vec![
            (vec![0], vec![9]),
            (vec![1], vec![9]),
            (vec![2], vec![9]),
            (vec![2], vec![9]),
            (vec![3], vec![9])
        ]
    );
    Ok(())
}

// SNP-05, PRJ-09
#[test]
fn backing_slots_force_spill_before_another_sorter_is_admitted() -> IoResult<()> {
    let scratch = tempfile::tempdir()?;
    let slot = std::mem::size_of::<(Vec<u8>, Vec<u8>)>();
    let budget = SpillBudget::new(u64::try_from(4 * slot + 17).map_err(std::io::Error::other)?);
    let set = SpillSet::new(&budget, scratch.path().to_path_buf());
    let mut first = set.sorter("first");
    let mut second = set.sorter("second");
    first.push(vec![1], vec![7; 16])?;
    second.push(vec![2], vec![8; 16])?;
    let sorters = set.sorters.borrow();
    assert_eq!(sorters[0].buffer.capacity(), 0);
    assert_eq!(sorters[0].buffered, 0);
    assert_eq!(sorters[0].runs.len(), 1);
    assert_eq!(
        budget.current_bytes(),
        retained_capacity(&sorters[1].buffer)?
    );
    assert!(budget.peak_bytes() <= budget.limit);
    drop(sorters);
    drop(set);
    assert_eq!(budget.current_bytes(), 0);
    Ok(())
}

// SNP-05, PRJ-09
#[test]
fn refused_spill_keeps_existing_capacity_charged_until_drop() -> IoResult<()> {
    let scratch = tempfile::tempdir()?;
    let slot = std::mem::size_of::<(Vec<u8>, Vec<u8>)>();
    let budget = SpillBudget::new(u64::try_from(4 * slot + 17).map_err(std::io::Error::other)?);
    let set = SpillSet::new(&budget, scratch.path().join("missing"));
    let mut sorter = set.sorter("refused");
    sorter.push(vec![1], vec![7; 16])?;
    assert!(sorter.push(vec![2], vec![8; 16]).is_err());
    {
        let sorters = set.sorters.borrow();
        let state = &sorters[0];
        assert_eq!(state.buffer.len(), 1);
        assert_eq!(budget.current_bytes(), retained_capacity(&state.buffer)?);
        assert!(state.runs.is_empty());
    }
    drop(set);
    assert_eq!(budget.current_bytes(), 0);
    Ok(())
}

// PRJ-09
#[test]
fn bounded_merge_matches_sorted_reference() -> IoResult<()> {
    reset_cursor_peak();
    const ROWS: u64 = 21;
    let scratch = tempfile::tempdir()?;
    let mut pushed: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for order in 0..ROWS {
        let key = ((order * 5) % ROWS).to_be_bytes().to_vec();
        let value = (((order * 5) % ROWS) ^ 0x9e37).to_be_bytes().to_vec();
        pushed.push((key, value));
    }
    let runs = single_row_runs(scratch.path(), &pushed)?;
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
    let mut pushed: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for order in 0..ROWS {
        let key = ((order * 5) % ROWS).to_be_bytes().to_vec();
        let value = (((order * 5) % ROWS) ^ 0x9e37).to_be_bytes().to_vec();
        pushed.push((key, value));
    }
    let runs = single_row_runs(scratch.path(), &pushed)?;
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
    let pushed = (0..ROWS)
        .map(|order| (order.to_be_bytes().to_vec(), vec![0u8; 8]))
        .collect::<Vec<_>>();
    let runs = single_row_runs(scratch.path(), &pushed)?;
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

#[test]
fn online_compaction_bounds_live_runs_and_preserves_equal_key_order() -> IoResult<()> {
    const ROWS: u64 = 4097;
    reset_cursor_peak();
    let scratch = tempfile::tempdir()?;
    let budget = SpillBudget::new(0);
    let set = SpillSet::new(&budget, scratch.path().to_path_buf());
    let mut sorter = set.sorter("online");
    let levels =
        usize::try_from(u64::BITS / MAX_MERGE_FAN_IN.ilog2()).map_err(std::io::Error::other)?;
    let live_run_bound = (MAX_MERGE_FAN_IN - 1) * levels;
    for sequence in 0..ROWS {
        sorter.push(
            (sequence % 7).to_be_bytes().to_vec(),
            sequence.to_be_bytes().to_vec(),
        )?;
        let live_files = std::fs::read_dir(scratch.path())?.collect::<IoResult<Vec<_>>>()?;
        assert!(
            live_files.len() <= live_run_bound,
            "online run ownership exceeded its integer-domain metadata bound"
        );
    }
    assert!(cursor_peak() > 0, "ingestion must actually compact runs");
    assert!(cursor_peak() <= MAX_MERGE_FAN_IN);
    let runs = sorter.finish()?;
    let mut rows = merge(&runs)?;
    for key in 0..7_u64 {
        for sequence in (key..ROWS).step_by(7) {
            assert_eq!(
                rows.next().transpose()?,
                Some((key.to_be_bytes().to_vec(), sequence.to_be_bytes().to_vec())),
                "equal keys retain original run order and every value"
            );
        }
    }
    assert!(rows.next().is_none());
    assert!(cursor_peak() <= MAX_MERGE_FAN_IN);
    Ok(())
}

#[test]
fn failed_online_compaction_cleans_partial_output_and_owned_inputs() -> IoResult<()> {
    let scratch = tempfile::tempdir()?;
    let budget = SpillBudget::new(0);
    let set = SpillSet::new(&budget, scratch.path().to_path_buf());
    let mut sorter = set.sorter("online-fault");
    for sequence in 0..MAX_MERGE_FAN_IN {
        sorter.push(sequence.to_be_bytes().to_vec(), vec![1])?;
    }
    let first = std::fs::read_dir(scratch.path())?
        .next()
        .ok_or_else(|| std::io::Error::other("spill input missing"))??;
    std::fs::remove_file(first.path())?;
    assert!(sorter.push(vec![255], vec![2]).is_err());
    drop(set);
    assert_eq!(budget.current_bytes(), 0);
    assert!(std::fs::read_dir(scratch.path())?.next().is_none());
    Ok(())
}
