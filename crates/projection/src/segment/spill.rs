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
    next_run: u32,
}

pub struct SpillSorter<'a> {
    set: &'a SpillSet<'a>,
    id: usize,
}

#[derive(Clone, Debug)]
pub struct RunFile {
    path: PathBuf,
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
            state.next_run = state.next_run.saturating_add(1);
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
        let mut sorters = self.sorters.borrow_mut();
        let state = &mut sorters[id];
        state.runs.push(RunFile { path });
        drop(std::mem::take(&mut state.buffer));
        self.budget.sub(std::mem::take(&mut state.buffered));
        Ok(())
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
    let mut first = [0u8; 1];
    match reader.read_exact(&mut first) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    }
    let mut rest = [0u8; 7];
    reader.read_exact(&mut rest)?;
    let mut lens = [0u8; 8];
    lens[0] = first[0];
    lens[1..].copy_from_slice(&rest);
    let key_len = usize::try_from(u32::from_le_bytes(lens[..4].try_into().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "spill row is truncated")
    })?))
    .unwrap_or(usize::MAX);
    let value_len = usize::try_from(u32::from_le_bytes(lens[4..].try_into().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "spill row is truncated")
    })?))
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
            next.push(RunFile { path: out });
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
#[path = "spill_tests.rs"]
mod tests;
