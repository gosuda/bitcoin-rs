use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};

pub const RESTORE_SPILL_BUDGET_BYTES: u64 = 64 << 20;

pub struct SpillBudget {
    limit: u64,
    current: AtomicU64,
    peak: AtomicU64,
}

impl SpillBudget {
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            current: AtomicU64::new(0),
            peak: AtomicU64::new(0),
        }
    }

    pub fn peak_bytes(&self) -> u64 {
        self.peak.load(SeqCst)
    }

    fn current_bytes(&self) -> u64 {
        self.current.load(SeqCst)
    }

    fn add(&self, bytes: u64) {
        let current = self.current.fetch_add(bytes, SeqCst).saturating_add(bytes);
        self.peak.fetch_max(current, SeqCst);
    }

    fn sub(&self, bytes: u64) {
        self.current.fetch_sub(bytes, SeqCst);
    }
}

pub struct SpillSet<'a> {
    budget: &'a SpillBudget,
    dir: PathBuf,
    sorters: std::cell::RefCell<Vec<SorterState>>,
}

struct SorterState {
    prefix: String,
    buffer: Vec<(Vec<u8>, Vec<u8>)>,
    buffered: u64,
    runs: Vec<RunFile>,
    next_run: u64,
}

pub struct SpillSorter<'a> {
    set: &'a SpillSet<'a>,
    id: usize,
}

#[derive(Clone, Debug)]
pub struct RunFile {
    path: PathBuf,
    level: u32,
}

impl RunFile {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}
impl<'a> SpillSet<'a> {
    pub fn new(budget: &'a SpillBudget, dir: PathBuf) -> Self {
        Self {
            budget,
            dir,
            sorters: std::cell::RefCell::new(Vec::new()),
        }
    }

    pub fn sorter(&self, prefix: &str) -> SpillSorter<'_> {
        let mut sorters = self.sorters.borrow_mut();
        let id = sorters.len();
        sorters.push(SorterState {
            prefix: prefix.to_owned(),
            buffer: Vec::new(),
            buffered: 0,
            runs: Vec::new(),
            next_run: 0,
        });
        SpillSorter { set: self, id }
    }

    fn push(&self, id: usize, key: Vec<u8>, value: Vec<u8>) -> std::io::Result<()> {
        let payload_bytes =
            u64::try_from(key.capacity().saturating_add(value.capacity())).unwrap_or(u64::MAX);
        loop {
            let (mut replacement, slot_bytes) = {
                let sorters = self.sorters.borrow();
                let buffer = &sorters[id].buffer;
                if buffer.len() == buffer.capacity() {
                    let capacity = buffer.capacity().saturating_mul(2).max(4);
                    let replacement = Vec::with_capacity(capacity);
                    let slots = replacement.capacity().saturating_sub(buffer.capacity());
                    let bytes = slots.saturating_mul(std::mem::size_of::<(Vec<u8>, Vec<u8>)>());
                    (Some(replacement), u64::try_from(bytes).unwrap_or(u64::MAX))
                } else {
                    (None, 0)
                }
            };
            let bytes = payload_bytes.saturating_add(slot_bytes);
            if self.budget.current_bytes().saturating_add(bytes) > self.budget.limit
                && self.spill_largest()?
            {
                continue;
            }
            let mut sorters = self.sorters.borrow_mut();
            let state = &mut sorters[id];
            if let Some(mut buffer) = replacement.take() {
                buffer.append(&mut state.buffer);
                state.buffer = buffer;
            }
            state.buffer.push((key, value));
            state.buffered = state.buffered.saturating_add(bytes);
            self.budget.add(bytes);
            break;
        }
        Ok(())
    }

    fn spill_largest(&self) -> std::io::Result<bool> {
        let victim = {
            let sorters = self.sorters.borrow();
            sorters
                .iter()
                .enumerate()
                .filter(|(_, state)| !state.buffer.is_empty())
                .max_by_key(|(_, state)| state.buffered)
                .map(|(id, _)| id)
        };
        let Some(id) = victim else {
            return Ok(false);
        };
        self.spill(id)?;
        Ok(true)
    }

    fn spill(&self, id: usize) -> std::io::Result<()> {
        let path = {
            let mut sorters = self.sorters.borrow_mut();
            let state = &mut sorters[id];
            state
                .buffer
                .sort_unstable_by(|left, right| left.0.cmp(&right.0));
            let path = self
                .dir
                .join(format!("{}-{:06}.bin", state.prefix, state.next_run));
            state.next_run = state.next_run.checked_add(1).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "spill run sequence overflow",
                )
            })?;
            path
        };
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let result = (|| -> std::io::Result<()> {
            let mut out = BufWriter::new(file);
            for (key, value) in &self.sorters.borrow()[id].buffer {
                write_row(&mut out, key, value)?;
            }
            out.flush()?;
            Ok(())
        })();
        if result.is_err() {
            let _unused = std::fs::remove_file(&path);
        }
        result?;
        {
            let mut sorters = self.sorters.borrow_mut();
            let state = &mut sorters[id];
            state.runs.push(RunFile { path, level: 0 });
            drop(std::mem::take(&mut state.buffer));
            self.budget.sub(std::mem::take(&mut state.buffered));
        }
        self.compact(id)
    }

    fn compact(&self, id: usize) -> std::io::Result<()> {
        loop {
            let (chunk, level, path) = {
                let sorters = self.sorters.borrow();
                let state = &sorters[id];
                let Some(last) = state.runs.last() else {
                    return Ok(());
                };
                let count = state
                    .runs
                    .iter()
                    .rev()
                    .take_while(|run| run.level == last.level)
                    .count();
                if count < MAX_MERGE_FAN_IN {
                    return Ok(());
                }
                let start = state.runs.len() - MAX_MERGE_FAN_IN;
                let sequence = MERGE_TMP_ID.fetch_add(1, SeqCst);
                (
                    state.runs[start..].to_vec(),
                    last.level + 1,
                    self.dir
                        .join(format!("{}-compact-{sequence:016x}.bin", state.prefix)),
                )
            };
            let output = OwnedIntermediates {
                paths: vec![path.clone()],
            };
            merge_chunk(&chunk, &path)?;
            for run in &chunk {
                std::fs::remove_file(&run.path)?;
            }
            let mut sorters = self.sorters.borrow_mut();
            let state = &mut sorters[id];
            let start = state.runs.len() - MAX_MERGE_FAN_IN;
            state.runs.truncate(start);
            state.runs.push(RunFile { path, level });
            let _ = output.disarm();
        }
    }

    fn finish(&self, id: usize) -> std::io::Result<Vec<RunFile>> {
        let empty = self.sorters.borrow()[id].buffer.is_empty();
        if !empty {
            self.spill(id)?;
        }
        Ok(std::mem::take(&mut self.sorters.borrow_mut()[id].runs))
    }
}

impl Drop for SpillSet<'_> {
    fn drop(&mut self) {
        let Ok(mut sorters) = self.sorters.try_borrow_mut() else {
            return;
        };
        for state in sorters.iter_mut() {
            drop(std::mem::take(&mut state.buffer));
            self.budget.sub(std::mem::take(&mut state.buffered));
            for run in std::mem::take(&mut state.runs) {
                let _unused = std::fs::remove_file(&run.path);
            }
        }
    }
}

impl SpillSorter<'_> {
    pub fn push(&mut self, key: Vec<u8>, value: Vec<u8>) -> std::io::Result<()> {
        self.set.push(self.id, key, value)
    }

    pub fn finish(self) -> std::io::Result<Vec<RunFile>> {
        self.set.finish(self.id)
    }
}

fn write_row(out: &mut impl Write, key: &[u8], value: &[u8]) -> std::io::Result<()> {
    let key_len = u32::try_from(key.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "spill row key is too long",
        )
    })?;
    let value_len = u32::try_from(value.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "spill row value is too long",
        )
    })?;
    out.write_all(&key_len.to_le_bytes())?;
    out.write_all(&value_len.to_le_bytes())?;
    out.write_all(key)?;
    out.write_all(value)?;
    Ok(())
}

fn read_row(reader: &mut impl Read) -> std::io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut lens = [0u8; 8];
    match reader.read_exact(&mut lens[..1]) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    }
    reader.read_exact(&mut lens[1..])?;
    let key_len = usize::try_from(u32::from_le_bytes([lens[0], lens[1], lens[2], lens[3]]))
        .unwrap_or(usize::MAX);
    let value_len = usize::try_from(u32::from_le_bytes([lens[4], lens[5], lens[6], lens[7]]))
        .unwrap_or(usize::MAX);
    let mut key = Vec::new();
    reader
        .by_ref()
        .take(u64::try_from(key_len).unwrap_or(u64::MAX))
        .read_to_end(&mut key)?;
    if key.len() != key_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "spill row is truncated",
        ));
    }
    let mut value = Vec::new();
    reader
        .by_ref()
        .take(u64::try_from(value_len).unwrap_or(u64::MAX))
        .read_to_end(&mut value)?;
    if value.len() != value_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "spill row is truncated",
        ));
    }
    Ok(Some((key, value)))
}

#[cfg(test)]
thread_local! {
    static OPEN_RUN_CURSORS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PEAK_RUN_CURSORS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_cursor_peak() {
    OPEN_RUN_CURSORS.with(|open| open.set(0));
    PEAK_RUN_CURSORS.with(|peak| peak.set(0));
}

#[cfg(test)]
pub(crate) fn cursor_peak() -> usize {
    PEAK_RUN_CURSORS.with(|peak| peak.get())
}

struct RunCursor {
    reader: BufReader<File>,
    current: Option<(Vec<u8>, Vec<u8>)>,
}

impl RunCursor {
    fn open(path: &Path) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let current = read_row(&mut reader)?;
        #[cfg(test)]
        OPEN_RUN_CURSORS.with(|open| {
            let held = open.get().saturating_add(1);
            open.set(held);
            PEAK_RUN_CURSORS.with(|peak| peak.set(peak.get().max(held)));
        });
        Ok(Self { reader, current })
    }

    fn advance(&mut self) -> std::io::Result<()> {
        self.current = read_row(&mut self.reader)?;
        Ok(())
    }
}

#[cfg(test)]
impl Drop for RunCursor {
    fn drop(&mut self) {
        OPEN_RUN_CURSORS.with(|open| open.set(open.get().saturating_sub(1)));
    }
}

struct HeapRow {
    key: Vec<u8>,
    value: Vec<u8>,
    run: usize,
}

impl PartialEq for HeapRow {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for HeapRow {}

impl PartialOrd for HeapRow {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapRow {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key.cmp(&other.key).then(self.run.cmp(&other.run))
    }
}

const MAX_MERGE_FAN_IN: usize = 16;

static MERGE_TMP_ID: AtomicU64 = AtomicU64::new(0);

struct OwnedIntermediates {
    paths: Vec<PathBuf>,
}

impl OwnedIntermediates {
    fn disarm(mut self) -> Vec<PathBuf> {
        std::mem::take(&mut self.paths)
    }
}

impl Drop for OwnedIntermediates {
    fn drop(&mut self) {
        for path in std::mem::take(&mut self.paths) {
            let _unused = std::fs::remove_file(path);
        }
    }
}

pub struct Merge {
    sources: Vec<RunCursor>,
    heap: BinaryHeap<Reverse<HeapRow>>,
    failed: bool,
    owned: Vec<PathBuf>,
}

impl Merge {
    fn open(runs: &[RunFile], owned: Vec<PathBuf>) -> std::io::Result<Self> {
        let mut sources = Vec::with_capacity(runs.len());
        let mut heap = BinaryHeap::with_capacity(runs.len());
        for (index, run) in runs.iter().enumerate() {
            let mut source = RunCursor::open(&run.path)?;
            if let Some((key, value)) = source.current.take() {
                heap.push(Reverse(HeapRow {
                    key,
                    value,
                    run: index,
                }));
            }
            sources.push(source);
        }
        Ok(Merge {
            sources,
            heap,
            failed: false,
            owned,
        })
    }
}

impl Drop for Merge {
    fn drop(&mut self) {
        for path in std::mem::take(&mut self.owned) {
            let _unused = std::fs::remove_file(path);
        }
    }
}

pub fn merge(runs: &[RunFile]) -> std::io::Result<Merge> {
    let mut owned = OwnedIntermediates { paths: Vec::new() };
    let mut current: Vec<RunFile> = runs.to_vec();
    while current.len() > MAX_MERGE_FAN_IN {
        let dir = current
            .first()
            .and_then(|run| run.path.parent())
            .map(Path::to_path_buf)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "merge needs run files")
            })?;
        let mut next: Vec<RunFile> = Vec::new();
        for chunk in current.chunks(MAX_MERGE_FAN_IN) {
            let id = MERGE_TMP_ID.fetch_add(1, SeqCst);
            let out = dir.join(format!("spill-merge-{id:016x}.bin"));
            merge_chunk(chunk, &out)?;
            for input in chunk {
                if let Some(pos) = owned.paths.iter().position(|path| path == &input.path) {
                    let path = owned.paths.remove(pos);
                    let _unused = std::fs::remove_file(path);
                }
            }
            owned.paths.push(out.clone());
            next.push(RunFile {
                path: out,
                level: 0,
            });
        }
        current = next;
    }
    match Merge::open(&current, Vec::new()) {
        Ok(mut merged) => {
            merged.owned = owned.disarm();
            Ok(merged)
        }
        Err(error) => Err(error),
    }
}

fn merge_chunk(chunk: &[RunFile], out: &Path) -> std::io::Result<()> {
    let merged = Merge::open(chunk, Vec::new())?;
    let result = (|| -> std::io::Result<()> {
        let file = OpenOptions::new().write(true).create_new(true).open(out)?;
        let mut writer = BufWriter::new(file);
        for row in merged {
            let (key, value) = row?;
            write_row(&mut writer, &key, &value)?;
        }
        writer.flush()?;
        Ok(())
    })();
    if result.is_err() {
        let _unused = std::fs::remove_file(out);
    }
    result
}

impl Iterator for Merge {
    type Item = std::io::Result<(Vec<u8>, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let Reverse(head) = self.heap.pop()?;
        match self.sources[head.run].advance() {
            Ok(()) => {}
            Err(error) => {
                self.failed = true;
                return Some(Err(error));
            }
        }
        if let Some((key, value)) = self.sources[head.run].current.take() {
            self.heap.push(Reverse(HeapRow {
                key,
                value,
                run: head.run,
            }));
        }
        Some(Ok((head.key, head.value)))
    }
}

#[cfg(test)]
mod tests {

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
        let bytes = std::fs::read(first.path())?;
        let key_len = usize::try_from(u32::from_le_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| std::io::Error::other("spill header missing"))?,
        ))
        .map_err(|_| std::io::Error::other("spill header overflow"))?;
        let value_len = usize::try_from(u32::from_le_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| std::io::Error::other("spill header missing"))?,
        ))
        .map_err(|_| std::io::Error::other("spill header overflow"))?;
        let mut truncated = bytes[..8 + key_len + value_len].to_vec();
        truncated.extend_from_slice(&[0x02, 0x00]);
        std::fs::write(first.path(), &truncated)?;
        assert!(sorter.push(vec![255], vec![2]).is_err());
        drop(set);
        assert_eq!(budget.current_bytes(), 0);
        assert!(std::fs::read_dir(scratch.path())?.next().is_none());
        Ok(())
    }
}
