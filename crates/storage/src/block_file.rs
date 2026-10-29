//! Append-only framed block-body files and compact position records.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
};

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::{BodyExtent, StorageError};

/// Fixed magic at the start of every flat-file block record.
pub(crate) const BLOCK_FILE_MAGIC: [u8; 4] = *b"BRSB";
/// Maximum size of a normal block-body file: 128 MiB.
pub(crate) const BLOCK_FILE_MAX_BYTES: u64 = 128 * 1024 * 1024;

/// Directory name for append-only block-body files under a data directory.
pub(crate) const BLOCK_FILE_DIRECTORY: &str = "blocks";
const BLOCK_FILE_PREFIX: &str = "blk";
const BLOCK_FILE_SUFFIX: &str = ".dat";
const FILE_MAX_HEIGHT_PREFIX: &[u8; 7] = b"blkfile";
const RECORD_HEADER_LEN: usize = 44;
#[expect(
    clippy::as_conversions,
    reason = "the fixed 44-byte record header fits in u64"
)]
const RECORD_HEADER_LEN_U64: u64 = RECORD_HEADER_LEN as u64;
const BLOCK_READER_BUFFER_BYTES: usize = 256 << 10;

/// A fixed-width pointer to a framed block body in a flat file.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BlockFilePosition {
    /// Number of the `blkNNNNN.dat` file.
    pub file_no: u32,
    /// Byte offset of the record header, not its body.
    pub offset: u64,
    /// Byte length of the body.
    pub len: u32,
}

impl BlockFilePosition {
    /// Exact byte width of an encoded block-file position.
    pub(crate) const ENCODED_LEN: usize = 16;

    /// Encodes this position into the 16-byte little-endian index value.
    #[must_use]
    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0_u8; Self::ENCODED_LEN];
        bytes[..4].copy_from_slice(&self.file_no.to_le_bytes());
        bytes[4..12].copy_from_slice(&self.offset.to_le_bytes());
        bytes[12..].copy_from_slice(&self.len.to_le_bytes());
        bytes
    }

    /// Decodes an exact 16-byte little-endian index value.
    #[must_use]
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::ENCODED_LEN {
            return None;
        }
        Some(Self {
            file_no: u32::from_le_bytes(bytes[..4].try_into().ok()?),
            offset: u64::from_le_bytes(bytes[4..12].try_into().ok()?),
            len: u32::from_le_bytes(bytes[12..].try_into().ok()?),
        })
    }
}

/// Builds the per-file maximum-height key stored alongside block positions.
#[must_use]
pub fn block_file_max_height_key(file_no: u32) -> [u8; 11] {
    let mut key = [0_u8; 11];
    key[..FILE_MAX_HEIGHT_PREFIX.len()].copy_from_slice(FILE_MAX_HEIGHT_PREFIX);
    key[FILE_MAX_HEIGHT_PREFIX.len()..].copy_from_slice(&file_no.to_be_bytes());
    key
}

#[must_use]
pub fn encode_block_file_max_height(height: u32) -> [u8; 4] {
    height.to_le_bytes()
}

#[must_use]
pub fn decode_block_file_max_height(bytes: &[u8]) -> Option<u32> {
    if bytes.len() != 4 {
        return None;
    }
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// Append-only store for block bodies kept outside the key-value store.
pub struct FlatFileBlockStore {
    blocks_dir: PathBuf,
    max_file_bytes: u64,
    writer: Mutex<WriterState>,
    usage: AtomicU64,
    /// Set only when a failed append could not restore the old file length.
    usage_dirty: AtomicBool,
    /// Last field: drops after the writer's file handle above has closed.
    guard: Option<crate::StoreGuard>,
}

struct WriterState {
    file: File,
    file_no: u32,
    append_offset: u64,
    directory_dirty: bool,
    rollback_offset: Option<u64>,
}
pub(crate) struct FlatFileBlockReader {
    blocks_dir: PathBuf,
    state: Option<ReaderState>,
}

struct ReaderState {
    file_no: u32,
    file_len: u64,
    reader: BufReader<File>,
    cursor: Option<u64>,
}

impl FlatFileBlockStore {
    /// Keeps `guard` alive until this store's block-file handle is closed.
    ///
    /// Panics when a guard is already installed: replacing it would release the first
    /// guard while the block-file handle it protects is still open.
    #[must_use]
    pub fn guarded_by(self, guard: crate::StoreGuard) -> Self {
        assert!(
            self.guard.is_none(),
            "a flat-file block store takes exactly one lifetime guard"
        );
        Self {
            guard: Some(guard),
            ..self
        }
    }

    /// Opens a store with no committed body extent, recovering an incomplete tail.
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_with_max_file_bytes(data_dir.as_ref(), BLOCK_FILE_MAX_BYTES, None)
    }

    /// Opens a store after admitting the durable head's committed body extent.
    ///
    /// The extent file must contain complete frames through the committed offset.
    /// Corruption in that prefix refuses open without changing any
    pub fn open_with_committed_extent(
        data_dir: impl AsRef<Path>,
        committed: BodyExtent,
    ) -> Result<Self, StorageError> {
        Self::open_with_max_file_bytes(data_dir.as_ref(), BLOCK_FILE_MAX_BYTES, Some(committed))
    }

    /// Persists a block body unless `existing` already names its complete matching
    /// record.
    ///
    /// `hash` is the 32-byte consensus little-endian hash representation. Callers
    /// normally obtain `existing` from their key-value index before calling this
    /// method. Supplying it makes replay after an interrupted index update idempotent
    /// without making this store depend on a particular key-value backend.
    pub fn persist(
        &self,
        existing: Option<BlockFilePosition>,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<BlockFilePosition, StorageError> {
        let body_len = body_len(body)?;
        if let Some(position) = existing
            && position.len == body_len
            && self.load(position, height, hash)?.as_deref() == Some(body)
        {
            return Ok(position);
        }
        self.append(height, hash, body)
    }

    /// Appends one framed block body and flushes it to the operating system.
    pub fn append(
        &self,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<BlockFilePosition, StorageError> {
        let len = body_len(body)?;
        let record_len = record_len(len)?;
        let mut writer = self.writer.lock();
        self.recover_failed_append(&mut writer)?;

        if writer.append_offset > 0
            && writer
                .append_offset
                .checked_add(record_len)
                .is_none_or(|end| end > self.max_file_bytes)
        {
            writer.file.flush()?;
            writer.file.sync_data()?;
            let file_no = writer
                .file_no
                .checked_add(1)
                .ok_or(StorageError::InvalidOperation("block file number overflow"))?;
            let file = open_new_block_file(&self.blocks_dir, file_no)?;
            writer.file = file;
            writer.file_no = file_no;
            writer.append_offset = 0;
            writer.directory_dirty = true;
            sync_blocks_dir(&self.blocks_dir)?;
            writer.directory_dirty = false;
        }

        let position = BlockFilePosition {
            file_no: writer.file_no,
            offset: writer.append_offset,
            len,
        };
        let mut header = [0_u8; RECORD_HEADER_LEN];
        header[..4].copy_from_slice(&BLOCK_FILE_MAGIC);
        header[4..8].copy_from_slice(&len.to_le_bytes());
        header[8..12].copy_from_slice(&height.to_le_bytes());
        header[12..].copy_from_slice(&hash);

        let next_offset = position
            .offset
            .checked_add(record_len)
            .ok_or(StorageError::InvalidOperation("block file offset overflow"))?;
        let append_result =
            write_record(&mut writer.file, &header, body).and_then(|()| writer.file.flush());
        if let Err(append_error) = append_result {
            writer.rollback_offset = Some(position.offset);
            self.usage_dirty.store(true, Ordering::Release);
            if let Err(rollback_error) = writer
                .file
                .set_len(position.offset)
                .and_then(|()| writer.file.seek(SeekFrom::Start(position.offset)).map(drop))
            {
                return Err(io::Error::new(
                    rollback_error.kind(),
                    format!(
                        "failed to roll back block file after append error ({append_error}): \
                         {rollback_error}"
                    ),
                )
                .into());
            }
            writer.rollback_offset = None;
            self.usage_dirty.store(false, Ordering::Release);
            return Err(append_error.into());
        }
        writer.append_offset = next_offset;
        let _ = self.usage.fetch_add(record_len, Ordering::Relaxed);
        Ok(position)
    }

    /// Bytes this store's block files currently occupy on disk.
    #[must_use]
    pub(crate) fn disk_usage(&self) -> u64 {
        if self.usage_dirty.load(Ordering::Acquire) {
            let _writer = self.writer.lock();
            if self.usage_dirty.load(Ordering::Relaxed) {
                if let Ok(usage) = measure_blocks_dir(&self.blocks_dir) {
                    self.usage.store(usage, Ordering::Relaxed);
                    self.usage_dirty.store(false, Ordering::Release);
                    return usage;
                }
                return self.usage.load(Ordering::Relaxed);
            }
        }

        #[cfg(debug_assertions)]
        {
            let _writer = self.writer.lock();
            let usage = self.usage.load(Ordering::Relaxed);
            debug_assert_eq!(
                usage,
                measure_blocks_dir(&self.blocks_dir).unwrap_or(usage),
                "running block-file usage drifted from the files on disk"
            );
            usage
        }
        #[cfg(not(debug_assertions))]
        {
            self.usage.load(Ordering::Relaxed)
        }
    }

    /// Flushes the current append file to stable storage.
    pub(crate) fn sync(&self) -> Result<(), StorageError> {
        let mut writer = self.writer.lock();
        self.recover_failed_append(&mut writer)?;
        writer.file.flush()?;
        writer.file.sync_data()?;
        if writer.directory_dirty {
            sync_blocks_dir(&self.blocks_dir)?;
            writer.directory_dirty = false;
        }
        Ok(())
    }

    #[must_use]
    pub(crate) fn reader(&self) -> FlatFileBlockReader {
        FlatFileBlockReader {
            blocks_dir: self.blocks_dir.clone(),
            state: None,
        }
    }

    /// Loads a body only when its frame completely matches the requested height and hash.
    /// Missing files, malformed frames, mismatched targets, and short reads return `Ok(None)`.
    pub fn load(
        &self,
        position: BlockFilePosition,
        height: u32,
        hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.reader().load(position, height, hash)
    }

    /// Preserves corrupt referenced frames as errors, separately from missing files.
    pub(crate) fn load_for_verification(
        &self,
        position: BlockFilePosition,
        height: u32,
        hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.reader()
            .load_frame_bytes(position, height, hash, 0, None)
    }

    /// Loads at most `limit` body bytes after validating the complete frame header.
    /// The returned prefix is bound to `height` and `hash`; malformed, missing,
    /// mismatched, or short records return `Ok(None)`.
    pub(crate) fn load_prefix(
        &self,
        position: BlockFilePosition,
        height: u32,
        hash: [u8; 32],
        limit: usize,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.reader().load_prefix(position, height, hash, limit)
    }

    /// Loads `len` body bytes starting `offset` bytes into the body.
    ///
    /// `offset` is relative to the **body**, not to the record header, so a caller
    /// holding a transaction's offset within the serialized block passes it unchanged.
    /// Missing files, malformed frames, mismatched targets, out-of-bounds ranges and
    /// short reads all return `Ok(None)`.
    pub fn load_range(
        &self,
        position: BlockFilePosition,
        height: u32,
        hash: [u8; 32],
        offset: u32,
        len: u32,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.reader()
            .load_range(position, height, hash, offset, len)
    }

    #[must_use]
    pub(crate) fn current_file_number(&self) -> u32 {
        self.writer.lock().file_no
    }

    #[must_use]
    pub(crate) fn append_offset(&self) -> u64 {
        self.writer.lock().append_offset
    }

    #[must_use]
    pub fn file_path(&self, file_no: u32) -> PathBuf {
        block_file_path(&self.blocks_dir, file_no)
    }

    pub(crate) fn delete_file_if_not_current(&self, file_no: u32) -> Result<bool, StorageError> {
        let writer = self.writer.lock();
        if writer.file_no == file_no {
            return Ok(false);
        }
        let path = block_file_path(&self.blocks_dir, file_no);
        let reclaimed = fs::metadata(&path).map(|metadata| metadata.len()).ok();
        match fs::remove_file(path) {
            Ok(()) => {
                if let Some(bytes) = reclaimed {
                    let _ = self.usage.fetch_sub(bytes, Ordering::Relaxed);
                }
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn recover_failed_append(&self, writer: &mut WriterState) -> Result<(), StorageError> {
        let Some(offset) = writer.rollback_offset else {
            return Ok(());
        };
        self.usage_dirty.store(true, Ordering::Release);
        writer.file.set_len(offset)?;
        writer.file.seek(SeekFrom::Start(offset))?;
        let usage = measure_blocks_dir(&self.blocks_dir)?;
        writer.append_offset = offset;
        writer.rollback_offset = None;
        self.usage.store(usage, Ordering::Relaxed);
        self.usage_dirty.store(false, Ordering::Release);
        Ok(())
    }

    fn open_with_max_file_bytes(
        data_dir: &Path,
        max_file_bytes: u64,
        committed: Option<BodyExtent>,
    ) -> Result<Self, StorageError> {
        if max_file_bytes < RECORD_HEADER_LEN_U64 {
            return Err(StorageError::InvalidOperation(
                "block file cap is smaller than a header",
            ));
        }
        let blocks_dir = data_dir.join(BLOCK_FILE_DIRECTORY);
        if let Some(extent) = committed {
            validate_committed_extent(&blocks_dir, extent)?;
        }
        fs::create_dir_all(&blocks_dir)?;
        sync_blocks_dir(data_dir)?;
        let file_no = highest_block_file_number(&blocks_dir)?.unwrap_or(0);
        let path = block_file_path(&blocks_dir, file_no);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        sync_blocks_dir(&blocks_dir)?;
        let file_len = file.metadata()?.len();
        let scan_start = committed
            .filter(|extent| extent.file_no == file_no)
            .map_or(0, |extent| extent.offset);
        if file_len < scan_start {
            return Err(StorageError::IncompatibleData(
                "committed block file shortened after extent admission; preserving block files"
                    .to_owned(),
            ));
        }
        let recovered_offset = framed_stats_between(&mut file, scan_start, file_len)?.1;
        if recovered_offset != file_len {
            tracing::info!(
                target: "bitcoin_rs_storage::block_file",
                file_no,
                recovered_offset,
                file_len,
                "discarding incomplete block-file tail"
            );
            file.set_len(recovered_offset)?;
        }
        file.seek(SeekFrom::Start(recovered_offset))?;

        let usage = AtomicU64::new(measure_blocks_dir(&blocks_dir)?);

        Ok(Self {
            blocks_dir,
            max_file_bytes,
            writer: Mutex::new(WriterState {
                file,
                file_no,
                append_offset: recovered_offset,
                directory_dirty: false,
                rollback_offset: None,
            }),
            usage,
            usage_dirty: AtomicBool::new(false),
            guard: None,
        })
    }
}

impl FlatFileBlockReader {
    pub(crate) fn load(
        &mut self,
        position: BlockFilePosition,
        height: u32,
        hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.load_bytes(position, height, hash, 0, None)
    }

    pub(crate) fn load_prefix(
        &mut self,
        position: BlockFilePosition,
        height: u32,
        hash: [u8; 32],
        limit: usize,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let take = u64::try_from(limit)
            .map_err(|_| StorageError::InvalidOperation("block prefix limit does not fit u64"))?;
        self.load_bytes(position, height, hash, 0, Some(take))
    }

    pub(crate) fn load_range(
        &mut self,
        position: BlockFilePosition,
        height: u32,
        hash: [u8; 32],
        offset: u32,
        len: u32,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let Some(end) = offset.checked_add(len) else {
            return Ok(None);
        };
        if end > position.len {
            return Ok(None);
        }
        self.load_bytes(
            position,
            height,
            hash,
            u64::from(offset),
            Some(u64::from(len)),
        )
    }

    fn load_bytes(
        &mut self,
        position: BlockFilePosition,
        height: u32,
        hash: [u8; 32],
        skip: u64,
        take: Option<u64>,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        match self.load_frame_bytes(position, height, hash, skip, take) {
            Err(StorageError::CorruptBlockFrame(_)) => Ok(None),
            result => result,
        }
    }

    fn load_frame_bytes(
        &mut self,
        position: BlockFilePosition,
        height: u32,
        hash: [u8; 32],
        skip: u64,
        take: Option<u64>,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        if !self.select_file(position.file_no)? {
            return Ok(None);
        }
        let Some(state) = self.state.as_mut() else {
            unreachable!("selected file has reader state");
        };
        let Some(record_end) = record_end(position) else {
            return Err(StorageError::CorruptBlockFrame("record end overflow"));
        };
        if record_end > state.file_len {
            state.file_len = state.reader.get_ref().metadata()?.len();
            if record_end > state.file_len {
                return Err(StorageError::CorruptBlockFrame("truncated record"));
            }
        }
        if state.cursor != Some(position.offset) {
            if let Err(error) = state.reader.seek(SeekFrom::Start(position.offset)) {
                state.cursor = None;
                return Err(error.into());
            }
            state.cursor = Some(position.offset);
        }

        let Some(body_offset) = body_offset(position.offset) else {
            return Err(StorageError::CorruptBlockFrame("body offset overflow"));
        };
        let mut header = [0_u8; RECORD_HEADER_LEN];
        let header_complete = match read_exact_or_none(&mut state.reader, &mut header) {
            Ok(complete) => complete,
            Err(error) => {
                state.cursor = None;
                return Err(error);
            }
        };
        if !header_complete {
            state.cursor = None;
            return Err(StorageError::CorruptBlockFrame("truncated header"));
        }
        state.cursor = Some(body_offset);
        if header[..4] != BLOCK_FILE_MAGIC
            || header[4..8] != position.len.to_le_bytes()
            || header[8..12] != height.to_le_bytes()
            || header[12..] != hash
        {
            return Err(StorageError::CorruptBlockFrame("frame header mismatch"));
        }

        let body_len = u64::from(position.len);
        if skip > body_len {
            return Ok(None);
        }
        let max_len = body_len - skip;
        let read_len = take.map_or(max_len, |take| take.min(max_len));

        let target = if skip == 0 {
            body_offset
        } else {
            let Some(target) = body_offset.checked_add(skip) else {
                return Ok(None);
            };
            target
        };

        if state.cursor != Some(target) {
            if let Err(error) = state.reader.seek(SeekFrom::Start(target)) {
                state.cursor = None;
                return Err(error.into());
            }
            state.cursor = Some(target);
        }

        if read_len == 0 {
            return Ok(Some(Vec::new()));
        }

        let read_len_usize = usize::try_from(read_len)
            .map_err(|_| StorageError::InvalidOperation("block read length does not fit usize"))?;
        let mut bytes = vec![0_u8; read_len_usize];
        let body_complete = match read_exact_or_none(&mut state.reader, &mut bytes) {
            Ok(complete) => complete,
            Err(error) => {
                state.cursor = None;
                return Err(error);
            }
        };
        if !body_complete {
            state.cursor = None;
            return Err(StorageError::CorruptBlockFrame("truncated body"));
        }
        state.cursor = Some(
            target
                .checked_add(read_len)
                .ok_or(StorageError::InvalidOperation("block read end overflow"))?,
        );
        Ok(Some(bytes))
    }

    fn select_file(&mut self, file_no: u32) -> Result<bool, StorageError> {
        if self
            .state
            .as_ref()
            .is_some_and(|state| state.file_no == file_no)
        {
            return Ok(true);
        }

        let path = block_file_path(&self.blocks_dir, file_no);
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.state = None;
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        let file_len = file.metadata()?.len();
        self.state = Some(ReaderState {
            file_no,
            file_len,
            reader: BufReader::with_capacity(BLOCK_READER_BUFFER_BYTES, file),
            cursor: None,
        });
        Ok(true)
    }
}

#[cfg(unix)]
fn sync_blocks_dir(blocks_dir: &Path) -> Result<(), StorageError> {
    File::open(blocks_dir)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_blocks_dir(blocks_dir: &Path) -> Result<(), StorageError> {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(blocks_dir)?
        .sync_all()?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
#[expect(clippy::unnecessary_wraps)]
fn sync_blocks_dir(_blocks_dir: &Path) -> Result<(), StorageError> {
    Ok(())
}

fn body_len(body: &[u8]) -> Result<u32, StorageError> {
    u32::try_from(body.len())
        .map_err(|_| StorageError::InvalidOperation("block body exceeds u32 length"))
}

fn record_len(len: u32) -> Result<u64, StorageError> {
    RECORD_HEADER_LEN_U64
        .checked_add(u64::from(len))
        .ok_or(StorageError::InvalidOperation(
            "block record length overflow",
        ))
}

fn body_offset(offset: u64) -> Option<u64> {
    offset.checked_add(RECORD_HEADER_LEN_U64)
}

fn record_end(position: BlockFilePosition) -> Option<u64> {
    body_offset(position.offset)?.checked_add(u64::from(position.len))
}

fn write_record(writer: &mut impl io::Write, header: &[u8], body: &[u8]) -> io::Result<()> {
    let mut slices: &mut [io::IoSlice<'_>] =
        &mut [io::IoSlice::new(header), io::IoSlice::new(body)];
    while !slices.is_empty() {
        match writer.write_vectored(slices) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write whole block record",
                ));
            }
            Ok(written) => io::IoSlice::advance_slices(&mut slices, written),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn validate_committed_extent(blocks_dir: &Path, extent: BodyExtent) -> Result<(), StorageError> {
    let path = block_file_path(blocks_dir, extent.file_no);
    let corrupt = || {
        StorageError::IncompatibleData(format!(
            "committed block-file extent {}:{} is missing or malformed; preserving block files",
            extent.file_no, extent.offset,
        ))
    };
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(corrupt()),
        Err(error) => return Err(error.into()),
    };
    if file.metadata()?.len() < extent.offset
        || framed_stats_between(&mut file, 0, extent.offset)?.1 != extent.offset
    {
        return Err(corrupt());
    }
    Ok(())
}

fn framed_stats_between(
    file: &mut File,
    mut offset: u64,
    file_len: u64,
) -> Result<(u64, u64), StorageError> {
    let mut rows = 0_u64;
    while offset < file_len {
        let remaining = file_len
            .checked_sub(offset)
            .ok_or(StorageError::InvalidOperation(
                "block file offset exceeds file length",
            ))?;
        if remaining < RECORD_HEADER_LEN_U64 {
            break;
        }

        let mut header = [0_u8; RECORD_HEADER_LEN];
        file.seek(SeekFrom::Start(offset))?;
        if !read_exact_or_none(file, &mut header)? || header[..4] != BLOCK_FILE_MAGIC {
            break;
        }
        let len = u32::from_le_bytes(header[4..8].try_into().map_err(|_| {
            StorageError::InvalidOperation("block file header length is malformed")
        })?);
        let next = match offset.checked_add(RECORD_HEADER_LEN_U64 + u64::from(len)) {
            Some(next) if next <= file_len => next,
            _ => break,
        };
        offset = next;
        rows = rows.saturating_add(1);
    }
    Ok((rows, offset))
}

fn read_exact_or_none(reader: &mut impl io::Read, bytes: &mut [u8]) -> Result<bool, StorageError> {
    match reader.read_exact(bytes) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn measure_blocks_dir(blocks_dir: &Path) -> Result<u64, StorageError> {
    let mut total = 0_u64;
    for entry in fs::read_dir(blocks_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if parse_block_file_name(name).is_none() {
            continue;
        }
        total = total.saturating_add(fs::metadata(entry.path())?.len());
    }
    Ok(total)
}

fn highest_block_file_number(blocks_dir: &Path) -> Result<Option<u32>, StorageError> {
    let mut highest = None;
    for entry in fs::read_dir(blocks_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(file_no) = parse_block_file_name(name) else {
            continue;
        };
        highest = Some(highest.map_or(file_no, |current: u32| current.max(file_no)));
    }
    Ok(highest)
}

fn parse_block_file_name(name: &str) -> Option<u32> {
    let digits = name
        .strip_prefix(BLOCK_FILE_PREFIX)?
        .strip_suffix(BLOCK_FILE_SUFFIX)?;
    if digits.len() < 5 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn block_file_path(blocks_dir: &Path, file_no: u32) -> PathBuf {
    blocks_dir.join(format!(
        "{BLOCK_FILE_PREFIX}{file_no:05}{BLOCK_FILE_SUFFIX}"
    ))
}

fn open_new_block_file(blocks_dir: &Path, file_no: u32) -> Result<File, StorageError> {
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(block_file_path(blocks_dir, file_no))
        .map_err(StorageError::from)
}

#[cfg(test)]
mod tests;
