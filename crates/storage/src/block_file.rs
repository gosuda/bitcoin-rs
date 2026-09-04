//! Append-only framed block-body files and compact position records.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
};

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::StorageError;

/// Fixed magic at the start of every flat-file block record.
pub const BLOCK_FILE_MAGIC: [u8; 4] = *b"BRSB";
/// Maximum size of a normal block-body file: 128 MiB.
pub const BLOCK_FILE_MAX_BYTES: u64 = 128 * 1024 * 1024;

const BLOCK_FILE_DIRECTORY: &str = "blocks";
const BLOCK_FILE_PREFIX: &str = "blk";
const BLOCK_FILE_SUFFIX: &str = ".dat";
const FILE_MAX_HEIGHT_PREFIX: &[u8; 7] = b"blkfile";
const RECORD_HEADER_LEN: usize = 44;
const RECORD_HEADER_LEN_U64: u64 = 44;
const BLOCK_READER_BUFFER_BYTES: usize = 256 << 10;

/// A fixed-width pointer to a framed block body in a flat file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    pub const ENCODED_LEN: usize = 16;

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
    pub fn decode(bytes: &[u8]) -> Option<Self> {
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

/// Encodes a per-file maximum height value.
#[must_use]
pub fn encode_block_file_max_height(height: u32) -> [u8; 4] {
    height.to_le_bytes()
}

/// Decodes an exact per-file maximum height value.
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
    /// Bytes currently occupied by this store's block files.
    ///
    /// Seeded by walking the directory once at open, then maintained by the two
    /// operations that change it: `append` adds a framed record, and
    /// `delete_file_if_not_current` subtracts a whole file. Every deletion in
    /// the workspace goes through that one method, so there is no second path
    /// to forget.
    ///
    /// Maintained rather than measured because the caller is
    /// `getblockchaininfo`. Walking the directory costs one `stat` per file —
    /// thousands at a mainnet-sized chain — and that call has just been made
    /// independent of chain length; putting a directory walk back into it would
    /// undo that. `disk_usage` checks the running figure against a real walk
    /// under `debug_assert`.
    usage: AtomicU64,
    /// Set only when a failed append could not restore the old file length.
    ///
    /// Normal reads remain lock-free. Recovery reads take `writer` once and
    /// replace `usage` with a directory measurement.
    usage_dirty: AtomicBool,
}

struct WriterState {
    file: File,
    file_no: u32,
    append_offset: u64,
    directory_dirty: bool,
    rollback_offset: Option<u64>,
}
/// Reusable reader for framed block bodies.
pub struct FlatFileBlockReader {
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
    /// Opens the flat-file store rooted at `data_dir`, recovering the last file if needed.
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_with_max_file_bytes(data_dir.as_ref(), BLOCK_FILE_MAX_BYTES)
    }

    /// Persists a block body unless `existing` already names its complete matching record.
    ///
    /// `hash` is the 32-byte consensus little-endian hash representation.
    ///
    /// Callers normally obtain `existing` from their key-value index before calling this method.
    /// Supplying it makes replay after an interrupted index update idempotent without making this
    /// store depend on a particular key-value backend.
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
    ///
    /// `hash` is the 32-byte consensus little-endian hash representation.
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
            // Install a self-consistent new writer before syncing its directory
            // entry. A sync error therefore leaves a retryable dirty state, not
            // a new file paired with the old append offset.
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

        writer.file.seek(SeekFrom::Start(position.offset))?;
        let next_offset = position
            .offset
            .checked_add(record_len)
            .ok_or(StorageError::InvalidOperation("block file offset overflow"))?;
        let append_result = writer
            .file
            .write_all(&header)
            .and_then(|()| writer.file.write_all(body))
            .and_then(|()| writer.file.flush());
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
    ///
    /// This is what `getblockchaininfo` reports as `size_on_disk`: bytes that
    /// are actually there, so pruning a file makes it fall. It is not the sum of
    /// the block sizes the node has seen — that figure keeps counting blocks
    /// whose bytes have been deleted, which is the opposite of what the field
    /// is read for.
    ///
    /// Undo data is not included. It lives in the key-value store rather than in
    /// files here, so this store cannot see it; Bitcoin Core counts its undo
    /// files in the same number and this does not.
    #[must_use]
    pub fn disk_usage(&self) -> u64 {
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
    pub fn sync(&self) -> Result<(), StorageError> {
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

    /// Creates a reusable block-body reader.
    #[must_use]
    pub fn reader(&self) -> FlatFileBlockReader {
        FlatFileBlockReader {
            blocks_dir: self.blocks_dir.clone(),
            state: None,
        }
    }

    /// Loads a body only when its frame completely matches the requested height and hash.
    ///
    /// `hash` is the 32-byte consensus little-endian hash representation.
    ///
    /// Missing files, malformed frames, mismatched targets, and short reads return `Ok(None)`.
    pub fn load(
        &self,
        position: BlockFilePosition,
        height: u32,
        hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.reader().load(position, height, hash)
    }

    /// Loads at most `limit` body bytes after validating the complete frame header.
    ///
    /// The returned prefix is bound to `height` and `hash`; malformed, missing,
    /// mismatched, or short records return `Ok(None)`.
    pub fn load_prefix(
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
    /// `offset` is relative to the **body**, not to the record header, so a
    /// caller holding a transaction's offset within the serialized block passes
    /// it unchanged.
    ///
    /// The complete frame is validated first, exactly as [`Self::load`] does, so
    /// a range is never served out of a record that does not belong to `height`
    /// and `hash`. A range extending past the body's end returns `Ok(None)`
    /// rather than a short read: a truncated transaction would decode into
    /// something other than the transaction the caller asked for.
    ///
    /// Missing files, malformed frames, mismatched targets, out-of-bounds ranges
    /// and short reads all return `Ok(None)`.
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

    /// Returns the file currently receiving appends.
    #[must_use]
    pub fn current_file_number(&self) -> u32 {
        self.writer.lock().file_no
    }

    /// Returns the path of a numbered flat file.
    #[must_use]
    pub fn file_path(&self, file_no: u32) -> PathBuf {
        block_file_path(&self.blocks_dir, file_no)
    }

    /// Deletes a numbered file unless it is the current append target.
    ///
    /// Returns `true` only when a file was removed; a missing or current file returns `false`.
    pub fn delete_file_if_not_current(&self, file_no: u32) -> Result<bool, StorageError> {
        let writer = self.writer.lock();
        if writer.file_no == file_no {
            return Ok(false);
        }
        let path = block_file_path(&self.blocks_dir, file_no);
        // Sized before the unlink, because afterwards there is nothing to size.
        // A file that cannot be sized is removed without adjusting the running
        // figure rather than guessed at; `disk_usage`'s `debug_assert` is what
        // notices if that ever happens.
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
    ) -> Result<Self, StorageError> {
        if max_file_bytes < RECORD_HEADER_LEN_U64 {
            return Err(StorageError::InvalidOperation(
                "block file cap is smaller than a header",
            ));
        }
        let blocks_dir = data_dir.join(BLOCK_FILE_DIRECTORY);
        fs::create_dir_all(&blocks_dir)?;
        // Persist the blocks-directory entry in its parent. This runs once per
        // store open, not on the append path.
        sync_blocks_dir(data_dir)?;
        let file_no = highest_block_file_number(&blocks_dir)?.unwrap_or(0);
        let path = block_file_path(&blocks_dir, file_no);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        // The file may have been created above; persist its directory entry.
        sync_blocks_dir(&blocks_dir)?;
        let file_len = file.metadata()?.len();
        let recovered_offset = recover_append_offset(&mut file, file_len)?;
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

        // Seeded from the files themselves, once. A store reopened over an
        // existing directory has to start from what is there, and an incomplete
        // tail was just truncated above, so this runs after that.
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
        })
    }
}

impl FlatFileBlockReader {
    /// Loads a body only when its frame completely matches the requested height and hash.
    pub fn load(
        &mut self,
        position: BlockFilePosition,
        height: u32,
        hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.load_bytes(position, height, hash, 0, None)
    }

    /// Loads at most `limit` body bytes after validating the complete frame header.
    pub fn load_prefix(
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

    /// Loads `len` body bytes starting `offset` bytes into the body.
    ///
    /// `offset` is relative to the **body**, not to the record header, so a
    /// caller holding a transaction's offset within the serialized block passes
    /// it unchanged.
    ///
    /// The complete frame is validated first, exactly as [`Self::load`] does, so
    /// a range is never served out of a record that does not belong to `height`
    /// and `hash`. A range extending past the body's end returns `Ok(None)`
    /// rather than a short read.
    ///
    /// Missing files, malformed frames, mismatched targets, out-of-bounds ranges
    /// and short reads all return `Ok(None)`.
    pub fn load_range(
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
        if !self.select_file(position.file_no)? {
            return Ok(None);
        }
        let Some(state) = self.state.as_mut() else {
            unreachable!("selected file has reader state");
        };
        let Some(record_end) = record_end(position) else {
            return Ok(None);
        };
        if record_end > state.file_len {
            state.file_len = state.reader.get_ref().metadata()?.len();
            if record_end > state.file_len {
                return Ok(None);
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
            return Ok(None);
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
            return Ok(None);
        }
        state.cursor = Some(body_offset);
        if header[..4] != BLOCK_FILE_MAGIC
            || header[4..8] != position.len.to_le_bytes()
            || header[8..12] != height.to_le_bytes()
            || header[12..] != hash
        {
            return Ok(None);
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
            return Ok(None);
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

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_blocks_dir(_blocks_dir: &Path) -> Result<(), StorageError> {
    // std has no portable primitive for opening and syncing a directory.
    // Keep the durability boundary explicit where the platform supports it.
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

fn recover_append_offset(file: &mut File, file_len: u64) -> Result<u64, StorageError> {
    let mut offset = 0_u64;
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
    }
    Ok(offset)
}

fn read_exact_or_none(reader: &mut impl io::Read, bytes: &mut [u8]) -> Result<bool, StorageError> {
    match reader.read_exact(bytes) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Sums the sizes of every block file in `blocks_dir`.
///
/// The truth `disk_usage`'s running figure is kept honest against, and how that
/// figure is seeded at open. Costs one `stat` per file, which is why it is not
/// what `getblockchaininfo` calls.
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
        total = total.saturating_add(entry.metadata()?.len());
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
mod tests {
    use std::{fs::OpenOptions, io::Write as _};

    use tempfile::tempdir;

    use super::{BLOCK_FILE_MAGIC, BlockFilePosition, FlatFileBlockStore, RECORD_HEADER_LEN_U64};

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// `disk_usage` reports bytes that are there, and stops reporting them when
    /// they are deleted.
    ///
    /// This is what `getblockchaininfo` calls `size_on_disk`. The figure it
    /// replaces was the sum of every block's serialized length, which pruning
    /// could not move: records are kept when their bodies are dropped, so a
    /// pruned node went on reporting bytes it no longer had — under a field name
    /// that is read precisely to check whether pruning is working.
    ///
    /// Compared against a fresh walk of the directory at every step, so it pins
    /// the number against the files rather than against itself.
    #[test]
    fn disk_usage_follows_the_files_through_appends_and_deletion() -> Result<(), crate::StorageError>
    {
        let data_dir = tempdir()?;
        let store = FlatFileBlockStore::open_with_max_file_bytes(data_dir.path(), 120)?;
        let blocks_dir = data_dir.path().join(super::BLOCK_FILE_DIRECTORY);
        assert_eq!(store.disk_usage(), 0, "a fresh store occupies nothing");

        let _first = store.persist(None, 1, hash(1), b"first")?;
        let after_first = store.disk_usage();
        assert_eq!(after_first, super::measure_blocks_dir(&blocks_dir)?);
        assert!(after_first > 0, "an appended body occupies bytes");

        // Past the 120-byte cap, so this rolls into a second file.
        let third = store.persist(None, 2, hash(2), b"a longer second body")?;
        let third = store.persist(None, 3, hash(3), b"third").map(|_| third)?;
        assert_eq!(third.file_no, 0, "the fixture must roll over");
        let after_rollover = store.disk_usage();
        assert_eq!(after_rollover, super::measure_blocks_dir(&blocks_dir)?);
        assert!(after_rollover > after_first, "appends add bytes");

        // File 0 is complete, so it is prunable; file 1 is the current one.
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

    /// A failed rollback must not leave a later append behind a torn frame.
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

    /// Only block files count, and a stray file must not be mistaken for one.
    ///
    /// The seeding walk and the running figure have to agree about what a block
    /// file is: `append` counts framed records and nothing else, so a walk that
    /// counted every directory entry would seed a number the maintained one can
    /// never match — and `disk_usage`'s guard would fire on a node that had
    /// nothing wrong with it. Backup copies, editor scratch files and the
    /// operating system's own directory droppings all land here.
    #[test]
    fn disk_usage_counts_only_block_files() -> Result<(), crate::StorageError> {
        let data_dir = tempdir()?;
        let blocks_dir = data_dir.path().join(super::BLOCK_FILE_DIRECTORY);
        let expected = {
            let store = FlatFileBlockStore::open_with_max_file_bytes(data_dir.path(), 120)?;
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
        let reopened = FlatFileBlockStore::open_with_max_file_bytes(data_dir.path(), 120)?;
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
            let store = FlatFileBlockStore::open_with_max_file_bytes(data_dir.path(), 120)?;
            let _ = store.persist(None, 1, hash(1), b"first")?;
            let _ = store.persist(None, 2, hash(2), b"second")?;
            store.disk_usage()
        };
        assert!(expected > 0, "the fixture must write something");

        let reopened = FlatFileBlockStore::open_with_max_file_bytes(data_dir.path(), 120)?;
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
        let store = FlatFileBlockStore::open_with_max_file_bytes(data_dir.path(), 120)?;
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

        // Exhaustive over a coarse grid rather than a handful of cases: an
        // off-by-one in the header skip shows up only at specific offsets.
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
    fn load_range_refuses_a_frame_that_is_not_the_requested_block()
    -> Result<(), crate::StorageError> {
        let data_dir = tempdir()?;
        let store = FlatFileBlockStore::open(data_dir.path())?;
        let position = store.persist(None, 11, hash(11), b"the original body")?;

        // Same frame, wrong identity: a range must be as strongly bound to
        // (height, hash) as a whole-body load is, or a reorged-away block could
        // serve bytes for a height it no longer owns.
        assert_eq!(store.load_range(position, 12, hash(11), 0, 4)?, None);
        assert_eq!(store.load_range(position, 11, hash(12), 0, 4)?, None);
        assert_eq!(
            store.load_range(position, 11, hash(11), 0, 4)?,
            Some(b"the ".to_vec())
        );
        Ok(())
    }

    #[test]
    fn load_range_rejects_out_of_bounds_and_overflowing_ranges() -> Result<(), crate::StorageError>
    {
        let data_dir = tempdir()?;
        let store = FlatFileBlockStore::open(data_dir.path())?;
        let position = store.persist(None, 5, hash(5), b"0123456789")?;

        assert_eq!(store.load_range(position, 5, hash(5), 10, 1)?, None);
        assert_eq!(store.load_range(position, 5, hash(5), 11, 0)?, None);
        assert_eq!(store.load_range(position, 5, hash(5), 0, 11)?, None);
        assert_eq!(store.load_range(position, 5, hash(5), u32::MAX, 1)?, None);
        // The exact end of the body is in bounds.
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
        let store = FlatFileBlockStore::open_with_max_file_bytes(data_dir.path(), 120)?;
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
}
