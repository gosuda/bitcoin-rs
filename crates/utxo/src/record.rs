use core::ptr::{self, NonNull};
use core::slice;
use std::alloc::{Layout, alloc, dealloc, handle_alloc_error};

use bitcoin_rs_primitives::Hash256;
use smallvec::SmallVec;

use crate::{UtxoError, UtxoKey};

const TXID_LEN: usize = 32;
const OUTPUT_COUNT_OFFSET: usize = TXID_LEN;
const INLINE_LEN_OFFSET: usize = OUTPUT_COUNT_OFFSET + core::mem::size_of::<u32>();
const RECORD_HEADER_LEN: usize = INLINE_LEN_OFFSET + core::mem::size_of::<u8>();
/// Largest v5 payload prologue, for the encoder's stack buffer: 10 bytes for
/// the amount varint (or the escape sentinel), 8 for a raw escaped amount, and
/// 5 for the packed height. The script needs none — it is the rest.
const PAYLOAD_PROLOGUE_MAX_LEN: usize = crate::compress::VARINT_MAX_LEN + 8 + 5;

/// Byte holding both directory widths, immediately after the shared header.
const WIDTHS_OFFSET: usize = RECORD_HEADER_LEN;
/// First byte of the `vout` directory.
const V5_BODY_OFFSET: usize = WIDTHS_OFFSET + 1;
/// Widest directory entry. `vout` is a `u32`; a payload is at most a 10-byte
/// amount, 8 escape bytes, a 5-byte height and a `u16`-ceilinged script.
const MAX_DIR_WIDTH: usize = 4;

/// Smallest little-endian width that can hold `value`.
///
/// Minimal by construction and validated on decode: a record encoded with a
/// wider directory than it needs would be a second spelling of itself, and
/// `UtxoRecord` compares by bytes.
const fn width_for(value: u64) -> usize {
    if value <= 0xff {
        1
    } else if value <= 0xffff {
        2
    } else if value <= 0x00ff_ffff {
        3
    } else {
        MAX_DIR_WIDTH
    }
}

/// Reads a `width`-byte little-endian directory entry.
fn read_width(bytes: &[u8], offset: usize, width: usize) -> Option<u64> {
    let end = offset.checked_add(width)?;
    let slice = bytes.get(offset..end)?;
    let mut value = 0_u64;
    for (index, byte) in slice.iter().enumerate() {
        value |= u64::from(*byte) << (index * 8);
    }
    Some(value)
}

/// Where each region of a v5 body begins, and how wide its directory entries
/// are.
///
/// The whole point of the layout: every boundary here is `count * width`
/// arithmetic, so finding the directories costs no scanning, and a lookup by
/// `vout` touches one dense byte array instead of walking every output's
/// script.
#[derive(Copy, Clone)]
struct V5Layout {
    count: usize,
    vout_width: usize,
    len_width: usize,
    vout_dir: usize,
    len_dir: usize,
    payloads: usize,
}

impl V5Layout {
    fn new(count: usize, vout_width: usize, len_width: usize) -> Result<Self, UtxoError> {
        let vout_dir = V5_BODY_OFFSET;
        let len_dir = count
            .checked_mul(vout_width)
            .and_then(|span| vout_dir.checked_add(span))
            .ok_or(UtxoError::CorruptRecord)?;
        let payloads = count
            .checked_mul(len_width)
            .and_then(|span| len_dir.checked_add(span))
            .ok_or(UtxoError::CorruptRecord)?;
        Ok(Self {
            count,
            vout_width,
            len_width,
            vout_dir,
            len_dir,
            payloads,
        })
    }

    fn read(bytes: &[u8], count: usize) -> Result<Self, UtxoError> {
        let widths = *bytes.get(WIDTHS_OFFSET).ok_or(UtxoError::CorruptRecord)?;
        let vout_width = usize::from(widths & 0x0f);
        let len_width = usize::from(widths >> 4);
        if !(1..=MAX_DIR_WIDTH).contains(&vout_width) || !(1..=MAX_DIR_WIDTH).contains(&len_width) {
            return Err(UtxoError::CorruptRecord);
        }
        Self::new(count, vout_width, len_width)
    }

    fn vout_at(&self, bytes: &[u8], index: usize) -> Result<u32, UtxoError> {
        let offset = index
            .checked_mul(self.vout_width)
            .and_then(|span| self.vout_dir.checked_add(span))
            .ok_or(UtxoError::CorruptRecord)?;
        let raw = read_width(bytes, offset, self.vout_width).ok_or(UtxoError::CorruptRecord)?;
        u32::try_from(raw).map_err(|_| UtxoError::CorruptRecord)
    }

    fn payload_len_at(&self, bytes: &[u8], index: usize) -> Result<usize, UtxoError> {
        let offset = index
            .checked_mul(self.len_width)
            .and_then(|span| self.len_dir.checked_add(span))
            .ok_or(UtxoError::CorruptRecord)?;
        let raw = read_width(bytes, offset, self.len_width).ok_or(UtxoError::CorruptRecord)?;
        usize::try_from(raw).map_err(|_| UtxoError::CorruptRecord)
    }
}

/// Packs both directory widths into one byte.
fn pack_widths(vout_width: usize, len_width: usize) -> Result<u8, UtxoError> {
    let vout = u8::try_from(vout_width).map_err(|_| UtxoError::CorruptRecord)?;
    let len = u8::try_from(len_width).map_err(|_| UtxoError::CorruptRecord)?;
    Ok((len << 4) | vout)
}
/// Number of outputs kept in the inline partition before overflow outputs are
/// appended to the directory-addressed region.
const INLINE_CAPACITY: usize = 8;

/// Sentinel amount varint meaning "the next 8 bytes are a raw little-endian
/// value".
///
/// [`compress_amount`] maps the whole money supply below 2^54, so `u64::MAX` is
/// unreachable as a compressed amount and is free as an escape. No
/// consensus-valid output can need it — but `Amount` is a plain `u64`, so the
/// record codec preserves every representable value for lossless round trips.
const AMOUNT_ESCAPE: u64 = u64::MAX;

/// Packs the two per-output facts that always travel together into one varint.
///
/// `coinbase` occupies the low bit, so a height under 2^20 — every height
/// Bitcoin will reach for centuries — costs 3 bytes for both fields instead of
/// separate fixed-width fields. Kept per-output rather than hoisted into the
/// record header, which
/// would save 3 more: hoisting needs "every output of a record shares one
/// height" to hold, and BIP30's duplicate coinbase txids are exactly the case
/// where it might not.
fn pack_height(height: u32, coinbase: bool) -> u64 {
    (u64::from(height) << 1) | u64::from(coinbase)
}

/// One checked, zero-copy live output view inside a transaction-level record.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OneUtxoOut<'a> {
    /// Originating transaction output index.
    pub vout: u32,
    /// Output value in satoshis.
    pub value: u64,
    /// Script bytes owned by the enclosing record.
    pub script_pubkey: &'a [u8],
    /// Whether the originating transaction was coinbase.
    pub coinbase: bool,
    /// Block height that created the output.
    pub height: u32,
}

/// Transaction-level UTXO record encoded in one owned byte allocation.
///
/// The payload is `txid || output_count || inline_len || widths || vout_dir ||
/// len_dir || payloads`. Each output payload contains its value, height,
/// coinbase bit, and script in little-endian canonical form. The record owns
/// exactly one pointer-sized [`ThinRecordBuf`]; output views borrow directly
/// from its payload.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct UtxoRecord {
    buf: ThinRecordBuf,
}

/// Fixed 8-byte prefix stored at the front of every [`ThinRecordBuf`]
/// allocation: the immutable capacity and the current live length, both counted
/// in payload bytes. `#[repr(C)]` fixes the field order and size so the exact
/// deallocation layout is recoverable from `cap` alone.
#[repr(C)]
struct AllocHeader {
    cap: u32,
    len: u32,
}

/// Byte offset of the payload within a [`ThinRecordBuf`] allocation.
const THIN_HEADER_LEN: usize = core::mem::size_of::<AllocHeader>();
/// Allocation alignment; the header dominates (payload is raw `u8`).
const THIN_ALIGN: usize = core::mem::align_of::<AllocHeader>();

/// Pointer-sized owner of one encoded record payload.
///
/// The single `NonNull` points at a heap block laid out as
/// `AllocHeader || payload`. The header stores an immutable capacity (fixed at
/// allocation) and the current length; the payload holds `len` initialized
/// bytes followed by `cap - len` uninitialized spare capacity. Growth never
/// reallocates in place: it allocates a fresh block and drops the old one, so
/// the `(size, align)` pair used to allocate is always exactly reproducible for
/// deallocation.
///
/// # Invariants
/// - `ptr` was returned by the global allocator for
///   `Layout::from_size_align(THIN_HEADER_LEN + cap, THIN_ALIGN)` and is still
///   live and uniquely owned by this value.
/// - `len <= cap`, and the first `len` payload bytes are initialized.
/// - No interior mutability: every mutator takes `&mut self`.
#[repr(transparent)]
pub(crate) struct ThinRecordBuf {
    ptr: NonNull<u8>,
}

// SAFETY: `ThinRecordBuf` uniquely owns a heap allocation of plain bytes with no
// interior mutability, and every mutator requires `&mut self`. Moving that sole
// owner between threads is sound, exactly like the `Box<[u8]>` it replaces.
unsafe impl Send for ThinRecordBuf {}
// SAFETY: shared access (`&ThinRecordBuf`) only reads immutable bytes through
// `as_bytes`/`len`/`capacity`; with no interior mutability, concurrent shared
// reads cannot race.
unsafe impl Sync for ThinRecordBuf {}

impl ThinRecordBuf {
    /// Computes the exact allocation layout and validated `u32` capacity for
    /// `cap` payload bytes. Fails when `cap` exceeds `u32::MAX` or the total
    /// size would overflow the allocator's `isize` bound.
    fn layout_and_cap(cap: usize) -> Result<(Layout, u32), UtxoError> {
        let cap_u32 = u32::try_from(cap).map_err(|_| UtxoError::RecordTooLarge { len: cap })?;
        let size = THIN_HEADER_LEN
            .checked_add(cap)
            .ok_or(UtxoError::RecordTooLarge { len: cap })?;
        let layout = Layout::from_size_align(size, THIN_ALIGN)
            .map_err(|_| UtxoError::RecordTooLarge { len: cap })?;
        Ok((layout, cap_u32))
    }

    /// Allocates a block for `layout` (whose size is always `>= THIN_HEADER_LEN`,
    /// hence non-zero) and writes the header with `cap` capacity and zero length.
    /// Aborts via `handle_alloc_error` on allocation failure.
    fn alloc_with(layout: Layout, cap: u32) -> Self {
        // SAFETY: `layout` comes from `layout_and_cap`, so its size is
        // `THIN_HEADER_LEN + cap >= THIN_HEADER_LEN > 0`; allocating a non-zero
        // layout is the documented precondition of `alloc`.
        let raw = unsafe { alloc(layout) };
        let ptr = match NonNull::new(raw) {
            Some(ptr) => ptr,
            None => handle_alloc_error(layout),
        };
        // SAFETY: `ptr` is freshly allocated for `layout`, whose size covers a
        // whole `AllocHeader` and whose alignment is `THIN_ALIGN ==
        // align_of::<AllocHeader>()`, so this write is in-bounds and aligned.
        unsafe {
            ptr.cast::<AllocHeader>()
                .as_ptr()
                .write(AllocHeader { cap, len: 0 });
        }
        Self { ptr }
    }

    /// Allocates an owner with `cap` bytes of capacity and zero length.
    fn with_capacity(cap: usize) -> Result<Self, UtxoError> {
        let (layout, cap_u32) = Self::layout_and_cap(cap)?;
        Ok(Self::alloc_with(layout, cap_u32))
    }

    /// Allocates an exact-capacity owner (`capacity == len`) holding a copy of
    /// `src`, retaining no slack. Backs deep clones and the strict decode
    /// boundary.
    fn from_slice(src: &[u8]) -> Result<Self, UtxoError> {
        let mut buf = Self::with_capacity(src.len())?;
        buf.write_payload(src);
        Ok(buf)
    }

    fn header(&self) -> &AllocHeader {
        // SAFETY: `ptr` points at a live allocation whose first
        // `THIN_HEADER_LEN` bytes are an initialized `AllocHeader` (written at
        // construction, never deinitialized) aligned to `THIN_ALIGN`. The borrow
        // is tied to `&self`, excluding concurrent mutation.
        unsafe { self.ptr.cast::<AllocHeader>().as_ref() }
    }

    fn header_mut(&mut self) -> &mut AllocHeader {
        // SAFETY: as `header`, and `&mut self` guarantees exclusive access.
        unsafe { self.ptr.cast::<AllocHeader>().as_mut() }
    }

    fn capacity(&self) -> usize {
        usize::try_from(self.header().cap).unwrap_or(usize::MAX)
    }

    fn len(&self) -> usize {
        usize::try_from(self.header().len).unwrap_or(usize::MAX)
    }

    /// Returns the `len` initialized live payload bytes.
    fn as_bytes(&self) -> &[u8] {
        let len = self.len();
        if len == 0 {
            return &[];
        }
        // SAFETY: the payload starts `THIN_HEADER_LEN` bytes into the allocation
        // (in-bounds) and its first `len` bytes are initialized (invariant `len
        // <= cap`, and `len > 0` here implies `cap > 0`, so the pointer is
        // interior). `u8` needs only alignment 1. The slice borrows `&self`.
        unsafe { slice::from_raw_parts(self.ptr.as_ptr().add(THIN_HEADER_LEN), len) }
    }

    /// Overwrites the payload with `src` and sets the length to `src.len()`.
    /// The caller must ensure `capacity() >= src.len()`.
    fn write_payload(&mut self, src: &[u8]) {
        debug_assert!(self.capacity() >= src.len());
        if !src.is_empty() {
            // SAFETY: the destination `[THIN_HEADER_LEN, THIN_HEADER_LEN +
            // src.len())` lies within the allocation (`src.len() <= capacity`),
            // `src` is valid for `src.len()` reads, and `src` borrows a distinct
            // object from this buffer, so the ranges do not overlap. Afterwards
            // the first `src.len()` payload bytes are initialized.
            unsafe {
                ptr::copy_nonoverlapping(
                    src.as_ptr(),
                    self.ptr.as_ptr().add(THIN_HEADER_LEN),
                    src.len(),
                );
            }
        }
        // `src.len() <= capacity() <= u32::MAX`, so the conversion is lossless.
        self.header_mut().len = u32::try_from(src.len()).unwrap_or(u32::MAX);
    }
}

impl Clone for ThinRecordBuf {
    fn clone(&self) -> Self {
        // Exact-size copy: `capacity == len`, retaining no slack. `self` is a
        // live allocation whose (>=) layout already satisfied the size/align
        // bound, so the exact layout for `len` bytes is always valid; genuine
        // allocator exhaustion aborts inside `alloc_with` via
        // `handle_alloc_error` rather than reaching the fallback here.
        match Self::from_slice(self.as_bytes()) {
            Ok(buf) => buf,
            Err(_) => handle_alloc_error(Layout::new::<AllocHeader>()),
        }
    }
}

impl Drop for ThinRecordBuf {
    fn drop(&mut self) {
        if let Ok((layout, _)) = Self::layout_and_cap(self.capacity()) {
            // SAFETY: `ptr` was allocated by the global allocator for exactly
            // this layout — capacity is immutable for the allocation's lifetime,
            // so `layout_and_cap(capacity)` reproduces the original layout. The
            // block is still live and, in `drop` with `&mut self`, has no other
            // references; it is freed exactly once.
            unsafe { dealloc(self.ptr.as_ptr(), layout) }
        }
    }
}

impl PartialEq for ThinRecordBuf {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for ThinRecordBuf {}

impl core::fmt::Debug for ThinRecordBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ThinRecordBuf")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .field("bytes", &self.as_bytes())
            .finish()
    }
}

/// Cursor over a [`ThinRecordBuf`]'s capacity that copies fully-formed byte
/// segments in and, on [`RecordWriter::finish`], commits the total copied count
/// as the new length. Because the length is set only to the number of bytes
/// actually copied, uninitialized capacity is never exposed as live.
struct RecordWriter<'a> {
    buf: &'a mut ThinRecordBuf,
    written: usize,
    /// Immutable buffer capacity captured in [`new`](Self::new) from
    /// `AllocHeader.cap`, which is fixed for the buffer's lifetime. Hoisting the
    /// load out of [`push`](Self::push) keeps every existing bounds check and
    /// `CorruptRecord` branch intact.
    capacity: usize,
}

impl<'a> RecordWriter<'a> {
    /// Starts writing at offset zero. The caller must have reserved enough
    /// capacity for the whole payload; `push` still bounds-checks each segment.
    fn new(buf: &'a mut ThinRecordBuf) -> Self {
        let capacity = buf.capacity();
        buf.header_mut().len = 0;
        Self {
            buf,
            written: 0,
            capacity,
        }
    }

    /// Copies `src` into the capacity immediately after the previously written
    /// bytes. Fails if it would exceed the buffer's capacity.
    fn push(&mut self, src: &[u8]) -> Result<(), UtxoError> {
        let end = self
            .written
            .checked_add(src.len())
            .ok_or(UtxoError::RecordTooLarge { len: self.written })?;
        if end > self.capacity {
            return Err(UtxoError::CorruptRecord);
        }
        if !src.is_empty() {
            // SAFETY: the destination `[THIN_HEADER_LEN + written,
            // THIN_HEADER_LEN + end)` is within the allocation (`end <=
            // capacity`), `src` is valid for `src.len()` reads, and `src` borrows
            // a distinct object from the buffer (the encoder's sources are the
            // caller's descriptors or a different record), so the ranges do not
            // overlap. The written bytes become initialized.
            unsafe {
                ptr::copy_nonoverlapping(
                    src.as_ptr(),
                    self.buf.ptr.as_ptr().add(THIN_HEADER_LEN + self.written),
                    src.len(),
                );
            }
        }
        self.written = end;
        Ok(())
    }

    /// Commits the copied byte count as the buffer's live length.
    fn finish(self) -> Result<(), UtxoError> {
        // `written <= capacity() <= u32::MAX`, so the conversion is lossless.
        let len = u32::try_from(self.written)
            .map_err(|_| UtxoError::RecordTooLarge { len: self.written })?;
        self.buf.header_mut().len = len;
        Ok(())
    }
}

#[derive(Copy, Clone)]
struct RecordHeader {
    txid: Hash256,
    output_count: usize,
    inline_len: usize,
}

/// Iterator over checked output views from one validated record.
///
/// Walks the directory by index and the payload region by a running cursor, so
/// a full scan stays O(1) per output even though a random lookup has to sum the
/// preceding payload lengths.
pub(crate) struct UtxoOutputIter<'a> {
    bytes: &'a [u8],
    layout: V5Layout,
    index: usize,
    payload: usize,
}

impl<'a> Iterator for UtxoOutputIter<'a> {
    type Item = OneUtxoOut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.layout.count {
            return None;
        }
        let (output, next) =
            match decode_output_at(self.bytes, &self.layout, self.index, self.payload) {
                Ok(decoded) => decoded,
                // `UtxoRecord` is validated at construction (`from_encoded` runs
                // `validate_encoded`, which fully decodes every output) and its
                // `bytes` field is private and immutable afterward; a decode
                // failure here means the validated record was mutated in place,
                // which is an unrecoverable internal corrupt state.
                Err(error) => {
                    panic!("validated UTXO record output must remain decodable: {error:?}")
                }
            };
        self.payload = next;
        self.index += 1;
        Some(output)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.layout.count.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for UtxoOutputIter<'_> {}

impl UtxoRecord {
    /// Parses a complete encoded record. The returned record is always safe to
    /// expose through zero-copy output views.
    pub(crate) fn from_encoded(buf: ThinRecordBuf) -> Result<Self, UtxoError> {
        validate_encoded(buf.as_bytes())?;
        Ok(Self { buf })
    }

    /// Builds a record from snapshot-owned outputs in their serialized order.
    ///
    /// This is a snapshot/untrusted boundary, so the encoded payload is
    /// re-validated through [`Self::from_encoded`] before it is trusted.
    pub(crate) fn from_owned_outputs(
        txid: Hash256,
        outputs: &[OwnedUtxoOut],
    ) -> Result<Self, UtxoError> {
        Self::from_owned_parts(txid, outputs.len().min(INLINE_CAPACITY), outputs)
    }

    pub(crate) fn key(&self) -> UtxoKey {
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&self.buf.as_bytes()[..8]);
        UtxoKey::from_prefix(prefix)
    }

    pub(crate) fn txid(&self) -> Hash256 {
        let mut txid = [0_u8; TXID_LEN];
        txid.copy_from_slice(&self.buf.as_bytes()[..TXID_LEN]);
        Hash256::from_le_bytes(&txid)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.output_count() == 0
    }

    pub(crate) fn output_count(&self) -> usize {
        self.header().output_count
    }

    /// Returns checked, zero-copy output views in the canonical snapshot order.
    ///
    /// `UtxoRecord` is validated at construction and its `bytes` field is
    /// private and immutable afterward, so the encoded payload cannot corrupt
    /// between construction and this read. The returned iterator still fails
    /// fast (panics) if an internal invariant is ever violated.
    pub(crate) fn outputs(&self) -> UtxoOutputIter<'_> {
        let bytes = self.buf.as_bytes();
        let layout = match self.layout() {
            Ok(layout) => layout,
            Err(error) => panic!("UtxoRecord is validated at construction: {error:?}"),
        };
        UtxoOutputIter {
            bytes,
            payload: layout.payloads,
            layout,
            index: 0,
        }
    }

    /// Finds one live output by `vout`, decoding only the one that matches.
    ///
    /// This is the hot read: every spent input resolves through
    /// `Shard::get`/`get_entry`/`get_meta`, all three of which land here, so it
    /// is the operation the record layout is designed around.
    ///
    /// The search touches only the `vout` directory — one dense, fixed-width
    /// byte array — and then sums the payload lengths of the outputs before the
    /// match. Neither scan reads a script. A flat variable-length layout was
    /// built first and measured 4.4-4.9x slower here, because locating output
    /// `i` meant walking the bytes of outputs `0..i`, scripts included.
    pub(crate) fn find_output(&self, vout: u32) -> Option<OneUtxoOut<'_>> {
        let bytes = self.buf.as_bytes();
        let layout = self.layout().ok()?;
        let index = (0..layout.count)
            .find(|index| layout.vout_at(bytes, *index).is_ok_and(|c| c == vout))?;
        let payload = payload_offset(bytes, &layout, index).ok()?;
        match decode_output_at(bytes, &layout, index, payload) {
            Ok((output, _)) => Some(output),
            Err(error) => panic!("validated UTXO record output must remain decodable: {error:?}"),
        }
    }

    /// Highest live `vout`, read from the directory alone.
    pub(crate) fn max_vout(&self) -> Option<u32> {
        let bytes = self.buf.as_bytes();
        let layout = self.layout().ok()?;
        (0..layout.count)
            .filter_map(|index| layout.vout_at(bytes, index).ok())
            .max()
    }

    /// Stages an entire coalesced add run without changing this record,
    /// materializing the overwritten slots for listener/event consumers.
    ///
    /// `add_unique` is the strictly-increasing-vout fast path. Callers prove
    /// that it cannot encounter an existing vout before selecting it.
    #[cfg(test)]
    pub(crate) fn stage_add_run(
        &self,
        additions: &[OwnedUtxoOut],
        add_unique: bool,
    ) -> Result<(Self, Vec<Option<OwnedUtxoOut>>), UtxoError> {
        self.add_replacement_tracked(&owned_parts(additions), add_unique)
    }

    /// Builds the replacement record for a coalesced add run, borrowing every
    /// surviving output straight from this record's payload (no per-output
    /// script clone) and copying each addition's script exactly once. Used by
    /// the no-listener commit path, which never materializes overwritten
    /// outputs.
    pub(crate) fn add_replacement<'a>(
        &'a self,
        additions: &'a [OutputParts<'a>],
        add_unique: bool,
    ) -> Result<Self, UtxoError> {
        if add_unique {
            if let Some(record) = self.append_unique_run(additions)? {
                return Ok(record);
            }
        }
        let mut parts = self.output_parts();
        let mut inline_len = self.header().inline_len;
        apply_additions(&mut parts, &mut inline_len, additions, add_unique, None);
        Self::from_output_parts(self.txid(), inline_len, &parts)
    }

    /// Add-run replacement that also materializes the overwritten outputs (owned,
    /// so they outlive the record swap) for listener/event consumers.
    pub(crate) fn add_replacement_tracked<'a>(
        &'a self,
        additions: &'a [OutputParts<'a>],
        add_unique: bool,
    ) -> Result<(Self, Vec<Option<OwnedUtxoOut>>), UtxoError> {
        if add_unique {
            // The unique fast path can never overwrite a live vout.
            let record = self.add_replacement(additions, true)?;
            return Ok((record, vec![None; additions.len()]));
        }
        let mut parts = self.output_parts();
        let mut inline_len = self.header().inline_len;
        let mut overwritten = Vec::with_capacity(additions.len());
        apply_additions(
            &mut parts,
            &mut inline_len,
            additions,
            false,
            Some(&mut overwritten),
        );
        let record = Self::from_output_parts(self.txid(), inline_len, &parts)?;
        Ok((record, overwritten))
    }

    /// Builds a fresh record for a coalesced add run on a transaction that has
    /// no live record. Only additions contribute bytes.
    pub(crate) fn new_add_replacement(
        txid: Hash256,
        additions: &[OutputParts<'_>],
        add_unique: bool,
    ) -> Result<Self, UtxoError> {
        if add_unique {
            // Unique adds on an empty record encode in slice order with the
            // inline partition filled to capacity; no dedup pass is needed.
            let inline_len = additions.len().min(INLINE_CAPACITY);
            return Self::from_output_parts(txid, inline_len, additions);
        }
        let mut parts = Vec::with_capacity(additions.len());
        let mut inline_len = 0;
        apply_additions(&mut parts, &mut inline_len, additions, false, None);
        Self::from_output_parts(txid, inline_len, &parts)
    }

    pub(crate) fn new_add_replacement_tracked(
        txid: Hash256,
        additions: &[OutputParts<'_>],
        add_unique: bool,
    ) -> Result<(Self, Vec<Option<OwnedUtxoOut>>), UtxoError> {
        if add_unique {
            let inline_len = additions.len().min(INLINE_CAPACITY);
            let record = Self::from_output_parts(txid, inline_len, additions)?;
            return Ok((record, vec![None; additions.len()]));
        }
        let mut parts = Vec::with_capacity(additions.len());
        let mut inline_len = 0;
        let mut overwritten = Vec::with_capacity(additions.len());
        apply_additions(
            &mut parts,
            &mut inline_len,
            additions,
            false,
            Some(&mut overwritten),
        );
        let record = Self::from_output_parts(txid, inline_len, &parts)?;
        Ok((record, overwritten))
    }

    /// Increasing-unique append-copy fast path. Returns `None` when appending
    /// would reorder the inline partition bytes, or when the directories would
    /// have to widen, so the caller must rebuild.
    ///
    /// Appending is a splice of three regions rather than one, because the
    /// directories sit in front of the payloads. Every surviving output is
    /// still copied as bytes and never re-encoded, which is the point of the
    /// path; what it gives up is the case where a new `vout` or a longer
    /// payload needs a wider directory entry, since that rewrites entries the
    /// copy would otherwise preserve.
    fn append_unique_run(&self, additions: &[OutputParts<'_>]) -> Result<Option<Self>, UtxoError> {
        let header = self.header();
        let appends_at_end =
            header.output_count == header.inline_len || header.inline_len == INLINE_CAPACITY;
        if !appends_at_end {
            return Ok(None);
        }
        let old = self.layout()?;
        let bytes = self.buf.as_bytes();

        let new_count =
            header
                .output_count
                .checked_add(additions.len())
                .ok_or(UtxoError::RecordTooLarge {
                    len: header.output_count,
                })?;
        let output_count =
            u32::try_from(new_count).map_err(|_| UtxoError::RecordTooLarge { len: new_count })?;
        let inline_len = (header.inline_len + additions.len()).min(INLINE_CAPACITY);
        let inline_len_u8 = u8::try_from(inline_len).map_err(|_| UtxoError::CorruptRecord)?;

        // Widths must stay exactly as they are: narrower would be non-minimal
        // for the outputs already encoded, wider would mean rewriting every
        // existing directory entry.
        let mut additions_len = 0_usize;
        for addition in additions {
            let payload_len = addition.payload_len()?;
            if width_for(u64::from(addition.vout)) > old.vout_width
                || width_for(u64::try_from(payload_len).unwrap_or(u64::MAX)) > old.len_width
            {
                return Ok(None);
            }
            additions_len = additions_len
                .checked_add(payload_len)
                .ok_or(UtxoError::RecordTooLarge { len: additions_len })?;
        }

        let dir_growth = additions
            .len()
            .checked_mul(old.vout_width + old.len_width)
            .ok_or(UtxoError::RecordTooLarge {
                len: additions.len(),
            })?;
        let payload_len = bytes
            .len()
            .checked_add(additions_len)
            .and_then(|len| len.checked_add(dir_growth))
            .ok_or(UtxoError::RecordTooLarge { len: additions_len })?;
        if payload_len > usize::try_from(isize::MAX).unwrap_or(usize::MAX) {
            return Err(UtxoError::RecordTooLarge { len: payload_len });
        }

        let region = |from: usize, to: usize| bytes.get(from..to).ok_or(UtxoError::CorruptRecord);
        let mut buf = ThinRecordBuf::with_capacity(payload_len)?;
        let mut writer = RecordWriter::new(&mut buf);
        writer.push(&header.txid.to_le_bytes())?;
        writer.push(&output_count.to_le_bytes())?;
        writer.push(&[inline_len_u8])?;
        writer.push(&[pack_widths(old.vout_width, old.len_width)?])?;

        writer.push(region(old.vout_dir, old.len_dir)?)?;
        for addition in additions {
            push_dir_entry(&mut writer, u64::from(addition.vout), old.vout_width)?;
        }
        writer.push(region(old.len_dir, old.payloads)?)?;
        for addition in additions {
            let len = u64::try_from(addition.payload_len()?).unwrap_or(u64::MAX);
            push_dir_entry(&mut writer, len, old.len_width)?;
        }
        writer.push(region(old.payloads, bytes.len())?)?;
        for addition in additions {
            write_payload(&mut writer, addition)?;
        }
        writer.finish()?;
        debug_assert_eq!(buf.as_bytes().len(), payload_len);
        // Invariant: the copied prefix came from this validated record and every
        // appended addition was size-checked above, so the payload is canonical
        // and needs no re-decode.
        Ok(Some(Self { buf }))
    }

    /// Stages an entire coalesced remove run without changing this record,
    /// materializing the removed outputs (in request order) for listener/event
    /// consumers. Only removed outputs are cloned; survivors stay borrowed.
    pub(crate) fn stage_remove_run(
        &self,
        vouts: &[u32],
    ) -> Result<(Option<Self>, Vec<Option<OwnedUtxoOut>>), UtxoError> {
        let mut parts = self.output_parts();
        let mut inline_len = self.header().inline_len;
        let mut removed = Vec::with_capacity(vouts.len());

        for &vout in vouts {
            let output = parts
                .iter()
                .position(|part| part.vout == vout)
                .map(|index| remove_part_at(&mut parts, &mut inline_len, index));
            removed.push(output.map(OutputParts::into_owned));
        }

        if removed.iter().all(Option::is_none) {
            return Ok((None, removed));
        }

        let replacement = Self::from_output_parts(self.txid(), inline_len, &parts)?;
        Ok((Some(replacement), removed))
    }

    /// Builds the replacement for a coalesced remove run without materializing
    /// any removed output. A full removal returns [`RemovedRecord::Emptied`]
    /// with no replacement allocation. Used by the no-listener commit path.
    pub(crate) fn remove_replacement(&self, vouts: &[u32]) -> Result<RemovedRecord, UtxoError> {
        if self.is_full_removal(vouts) {
            return Ok(RemovedRecord::Emptied);
        }
        let mut parts = self.output_parts();
        let mut inline_len = self.header().inline_len;
        let mut any_removed = false;
        for &vout in vouts {
            if let Some(index) = parts.iter().position(|part| part.vout == vout) {
                remove_part_at(&mut parts, &mut inline_len, index);
                any_removed = true;
            }
        }
        if !any_removed {
            return Ok(RemovedRecord::Unchanged);
        }
        if parts.is_empty() {
            return Ok(RemovedRecord::Emptied);
        }
        let replacement = Self::from_output_parts(self.txid(), inline_len, &parts)?;
        Ok(RemovedRecord::Replaced(replacement))
    }

    /// Builds the replacement for a coalesced remove run followed by a
    /// coalesced add run on this record, in one borrowed descriptor pass with a
    /// single encode. Removes model inline-partition removal in `vouts` request
    /// order; the adds then overwrite or append in `additions` payload order.
    /// Used by the no-listener commit path when one record identity is both
    /// spent and rebuilt in the same batch; no removed or overwritten output is
    /// materialized, and each surviving output stays borrowed. A failed encode
    /// returns `Err` before any buffer is produced, so the caller's record is
    /// left byte-identical.
    pub(crate) fn edit_replacement<'a>(
        &'a self,
        vouts: &[u32],
        additions: &'a [OutputParts<'a>],
    ) -> Result<RemovedRecord, UtxoError> {
        if self.is_full_removal(vouts) {
            // Every live output is spent, so the additions alone form the final
            // record; survivors are never collected. No survivor remains to
            // dedup against, so the strictly-increasing test starts from `None`
            // and is byte-identical to the pre-removal-max form (a full removal
            // makes the dedup scan a no-op either way).
            if additions.is_empty() {
                return Ok(RemovedRecord::Emptied);
            }
            let add_unique = additions_are_strictly_increasing(None, additions);
            let record = Self::new_add_replacement(self.txid(), additions, add_unique)?;
            return Ok(RemovedRecord::Replaced(record));
        }
        let mut parts = self.output_parts();
        let mut inline_len = self.header().inline_len;
        // `add_unique` is the strictly-increasing fast path. `parts` are the
        // pre-removal live outputs, so their max is exactly the record's
        // pre-removal `max_vout`; computing it here from the already-built
        // descriptors avoids a second full decode of every output.
        let add_unique =
            additions_are_strictly_increasing(parts.iter().map(|part| part.vout).max(), additions);
        for &vout in vouts {
            if let Some(index) = parts.iter().position(|part| part.vout == vout) {
                remove_part_at(&mut parts, &mut inline_len, index);
            }
        }
        apply_additions(&mut parts, &mut inline_len, additions, add_unique, None);
        if parts.is_empty() {
            return Ok(RemovedRecord::Emptied);
        }
        let replacement = Self::from_output_parts(self.txid(), inline_len, &parts)?;
        Ok(RemovedRecord::Replaced(replacement))
    }

    /// Returns the requested outputs in request order only when the request
    /// spends this whole record exactly once per live vout. Materializes the
    /// removed outputs for listener/event consumers; survivors are never built.
    pub(crate) fn full_removals_by_vout(&self, vouts: &[u32]) -> Option<Vec<OwnedUtxoOut>> {
        if !self.is_full_removal(vouts) {
            return None;
        }
        let mut removed = Vec::with_capacity(vouts.len());
        for &vout in vouts {
            removed.push(OutputParts::from_view(&self.find_output(vout)?).into_owned());
        }
        Some(removed)
    }

    /// True when `vouts` removes every live output exactly once (no duplicate
    /// and no absent request). Borrowed header/output scan; allocates nothing.
    fn is_full_removal(&self, vouts: &[u32]) -> bool {
        if self.output_count() != vouts.len() {
            return false;
        }
        for (index, &vout) in vouts.iter().enumerate() {
            if vouts[..index].contains(&vout) || self.find_output(vout).is_none() {
                return false;
            }
        }
        true
    }

    #[cfg(test)]
    pub(crate) fn encoded_bytes(&self) -> &[u8] {
        self.buf.as_bytes()
    }

    /// Bytes this record holds from the allocator: header plus buffer capacity.
    pub(crate) fn allocation_bytes(&self) -> usize {
        THIN_HEADER_LEN.saturating_add(self.buf.capacity())
    }

    /// Live encoded payload length, excluding the allocation header and any
    /// spare capacity.
    pub(crate) fn payload_bytes(&self) -> usize {
        self.buf.len()
    }

    /// Directory widths and region offsets of this record's v5 body.
    fn layout(&self) -> Result<V5Layout, UtxoError> {
        V5Layout::read(self.buf.as_bytes(), self.header().output_count)
    }

    fn header(&self) -> RecordHeader {
        match decode_header(self.buf.as_bytes()) {
            Ok(header) => header,
            // `UtxoRecord` is only built through `from_encoded` or
            // `from_output_parts`, both of which produce a canonical payload; a
            // header decode failure means the validated record was mutated in
            // place.
            Err(error) => panic!("UtxoRecord is validated at construction: {error:?}"),
        }
    }

    /// Borrowed descriptors for every live output, in serialized order. Scripts
    /// point straight into this record's payload; nothing is cloned.
    fn output_parts(&self) -> Vec<OutputParts<'_>> {
        let mut parts = Vec::with_capacity(self.header().output_count);
        parts.extend(self.outputs().map(|output| OutputParts::from_view(&output)));
        parts
    }

    /// Snapshot/untrusted boundary constructor: re-validates through
    /// [`Self::from_encoded`].
    fn from_owned_parts(
        txid: Hash256,
        inline_len: usize,
        outputs: &[OwnedUtxoOut],
    ) -> Result<Self, UtxoError> {
        let buf = encode_record(txid, inline_len, &owned_parts(outputs))?;
        Self::from_encoded(buf)
    }

    /// Internal constructor from borrowed descriptors. Every descriptor is
    /// either a validated existing output or a prevalidated addition, so the
    /// encoded payload is canonical by construction and needs no re-decode.
    fn from_output_parts(
        txid: Hash256,
        inline_len: usize,
        outputs: &[OutputParts<'_>],
    ) -> Result<Self, UtxoError> {
        let buf = encode_record(txid, inline_len, outputs)?;
        Ok(Self { buf })
    }
}

/// Borrowed descriptor of one output to encode into a replacement buffer.
///
/// Scripts borrow from a validated source record or a prevalidated addition, so
/// building a replacement copies each script exactly once into the new buffer
/// and never clones a surviving output.
#[derive(Copy, Clone)]
pub(crate) struct OutputParts<'a> {
    pub(crate) vout: u32,
    pub(crate) value: u64,
    pub(crate) script: &'a [u8],
    pub(crate) coinbase: bool,
    pub(crate) height: u32,
}

impl<'a> OutputParts<'a> {
    pub(crate) const fn new(
        vout: u32,
        value: u64,
        script: &'a [u8],
        coinbase: bool,
        height: u32,
    ) -> Self {
        Self {
            vout,
            value,
            script,
            coinbase,
            height,
        }
    }

    fn from_owned(output: &'a OwnedUtxoOut) -> Self {
        Self::new(
            output.vout,
            output.value,
            &output.script_pubkey,
            output.coinbase,
            output.height,
        )
    }

    fn from_view(output: &OneUtxoOut<'a>) -> Self {
        Self::new(
            output.vout,
            output.value,
            output.script_pubkey,
            output.coinbase,
            output.height,
        )
    }

    fn into_owned(self) -> OwnedUtxoOut {
        OwnedUtxoOut::new(
            self.vout,
            self.value,
            self.script.to_vec(),
            self.coinbase,
            self.height,
        )
    }

    /// Validated v5 payload size of this output, excluding its two directory
    /// entries.
    ///
    /// Must agree with [`write_payload`] exactly: the record buffer is
    /// allocated at this size, the writer bounds-checks every push, and the
    /// length directory records it. An undercount turns a valid output into
    /// `CorruptRecord`; an overcount leaves slack in a structure whose whole
    /// point is to be small. `encoded_len_matches_the_bytes_written` pins the
    /// two together.
    ///
    /// The script length is not stored: the script is whatever remains of the
    /// payload, so the directory entry pays for itself.
    fn payload_len(&self) -> Result<usize, UtxoError> {
        use crate::compress::varint_len;

        let script_len = self.script.len();
        u16::try_from(script_len).map_err(|_| UtxoError::ScriptTooLarge { len: script_len })?;
        let (amount, escaped) = amount_parts(self.value);
        let prologue = varint_len(amount)
            + usize::from(escaped) * core::mem::size_of::<u64>()
            + varint_len(pack_height(self.height, self.coinbase));
        prologue
            .checked_add(script_len)
            .ok_or(UtxoError::RecordTooLarge { len: script_len })
    }
}

/// Outcome of staging a coalesced remove run without materializing removals.
pub(crate) enum RemovedRecord {
    /// No requested vout was live; the record is unchanged.
    Unchanged,
    /// Every live output was removed; the record must be deleted.
    Emptied,
    /// A partial removal produced this replacement record.
    Replaced(UtxoRecord),
}

fn owned_parts(outputs: &[OwnedUtxoOut]) -> Vec<OutputParts<'_>> {
    outputs.iter().map(OutputParts::from_owned).collect()
}

/// Applies a coalesced add run to `parts` with overwrite semantics, preserving
/// the inline/overflow partition order. When `overwritten` is supplied,
/// each displaced output is cloned owned into it in addition order.
fn apply_additions<'a>(
    parts: &mut Vec<OutputParts<'a>>,
    inline_len: &mut usize,
    additions: &[OutputParts<'a>],
    add_unique: bool,
    mut overwritten: Option<&mut Vec<Option<OwnedUtxoOut>>>,
) {
    for &addition in additions {
        let old = if add_unique {
            debug_assert!(parts.iter().all(|part| part.vout != addition.vout));
            None
        } else {
            parts
                .iter()
                .position(|part| part.vout == addition.vout)
                .map(|index| remove_part_at(parts, inline_len, index))
        };
        push_part(parts, inline_len, addition);
        if let Some(sink) = overwritten.as_deref_mut() {
            sink.push(old.map(OutputParts::into_owned));
        }
    }
}

fn push_part<'a>(parts: &mut Vec<OutputParts<'a>>, inline_len: &mut usize, part: OutputParts<'a>) {
    if *inline_len < INLINE_CAPACITY {
        parts.insert(*inline_len, part);
        *inline_len += 1;
    } else {
        parts.push(part);
    }
}

fn remove_part_at<'a>(
    parts: &mut Vec<OutputParts<'a>>,
    inline_len: &mut usize,
    index: usize,
) -> OutputParts<'a> {
    if index < *inline_len {
        let last_inline = *inline_len - 1;
        parts.swap(index, last_inline);
        *inline_len -= 1;
        parts.remove(last_inline)
    } else {
        parts.swap_remove(index)
    }
}

/// Strictly-increasing-vout test for the `add_unique` fast path, seeded with
/// the pre-removal maximum vout of the surviving set (`None` when nothing
/// survives). Mirrors `parts_are_increasing_unique` exactly: a non-strictly
/// greater addition fails on `<=`.
fn additions_are_strictly_increasing(previous: Option<u32>, additions: &[OutputParts<'_>]) -> bool {
    let mut previous = previous;
    for addition in additions {
        if previous.is_some_and(|vout| addition.vout <= vout) {
            return false;
        }
        previous = Some(addition.vout);
    }
    true
}

/// Appends one `width`-byte little-endian directory entry.
fn push_dir_entry(
    writer: &mut RecordWriter<'_>,
    value: u64,
    width: usize,
) -> Result<(), UtxoError> {
    let bytes = value.to_le_bytes();
    writer.push(bytes.get(..width).ok_or(UtxoError::CorruptRecord)?)
}

/// Encodes a canonical record payload into one exact-capacity buffer. Every
/// script must be `<= u16::MAX`; existing outputs satisfy this by construction
/// and additions are prevalidated here.
///
/// Layout: `header || widths || vout_dir || len_dir || payloads`. The
/// directories are fixed width — the narrowest that holds the record's largest
/// `vout` and largest payload — so a lookup indexes straight into them instead
/// of walking output frames.
fn encode_record(
    txid: Hash256,
    inline_len: usize,
    outputs: &[OutputParts<'_>],
) -> Result<ThinRecordBuf, UtxoError> {
    let output_count = u32::try_from(outputs.len())
        .map_err(|_| UtxoError::RecordTooLarge { len: outputs.len() })?;
    if inline_len > INLINE_CAPACITY || inline_len > outputs.len() {
        return Err(UtxoError::CorruptRecord);
    }

    // One pass for the sizes: the directory widths are a property of the whole
    // record, so nothing can be written until every payload length is known.
    let mut payload_lens: SmallVec<[u32; 16]> = SmallVec::with_capacity(outputs.len());
    let mut payload_total = 0_usize;
    let mut max_vout = 0_u64;
    let mut max_len = 0_u64;
    for output in outputs {
        let len = output.payload_len()?;
        payload_total = payload_total
            .checked_add(len)
            .ok_or(UtxoError::RecordTooLarge { len: payload_total })?;
        payload_lens.push(u32::try_from(len).map_err(|_| UtxoError::RecordTooLarge { len })?);
        max_vout = max_vout.max(u64::from(output.vout));
        max_len = max_len.max(u64::try_from(len).unwrap_or(u64::MAX));
    }
    let vout_width = width_for(max_vout);
    let len_width = width_for(max_len);
    let layout = V5Layout::new(outputs.len(), vout_width, len_width)?;

    let payload_len = layout
        .payloads
        .checked_add(payload_total)
        .ok_or(UtxoError::RecordTooLarge { len: payload_total })?;
    if payload_len > usize::try_from(isize::MAX).unwrap_or(usize::MAX) {
        return Err(UtxoError::RecordTooLarge { len: payload_len });
    }

    let inline_len_u8 = u8::try_from(inline_len).map_err(|_| UtxoError::CorruptRecord)?;
    let mut buf = ThinRecordBuf::with_capacity(payload_len)?;
    let mut writer = RecordWriter::new(&mut buf);
    writer.push(&txid.to_le_bytes())?;
    writer.push(&output_count.to_le_bytes())?;
    writer.push(&[inline_len_u8])?;
    writer.push(&[pack_widths(vout_width, len_width)?])?;
    // One `push` per directory entry is cheaper than staging both directories
    // in a scratch buffer: the entries are only one or two bytes each.
    for output in outputs {
        push_dir_entry(&mut writer, u64::from(output.vout), vout_width)?;
    }
    for len in &payload_lens {
        push_dir_entry(&mut writer, u64::from(*len), len_width)?;
    }
    for output in outputs {
        write_payload(&mut writer, output)?;
    }
    writer.finish()?;
    debug_assert_eq!(buf.as_bytes().len(), payload_len);
    Ok(buf)
}

/// The amount varint for `value`, and whether an 8-byte raw tail follows it.
fn amount_parts(value: u64) -> (u64, bool) {
    match crate::compress::compress_amount(value) {
        Ok(compressed) => (compressed, false),
        Err(_) => (AMOUNT_ESCAPE, true),
    }
}

/// Appends one output's v5 payload:
/// `varint(amount) [|| raw amount] || varint(height << 1 | coinbase) || script`.
///
/// `vout` and the payload length live in the directories, and the script length
/// is not stored at all — the script is the remainder of the payload.
///
/// The `u16` script-length ceiling bounds the remainder of the payload and
/// keeps record sizes representable by the directory.
fn write_payload(writer: &mut RecordWriter<'_>, output: &OutputParts<'_>) -> Result<(), UtxoError> {
    use crate::compress::write_varint_at;

    let script_len = output.script.len();
    u16::try_from(script_len).map_err(|_| UtxoError::ScriptTooLarge { len: script_len })?;
    let (amount, escaped) = amount_parts(output.value);

    // Lay the variable-length prologue into one stack buffer and copy it once.
    // Issuing a bounds-checked `push` per field adds overhead to every output.
    let mut prologue = [0_u8; PAYLOAD_PROLOGUE_MAX_LEN];
    let mut at = write_varint_at(amount, &mut prologue, 0).ok_or(UtxoError::CorruptRecord)?;
    if escaped {
        let end = at
            .checked_add(core::mem::size_of::<u64>())
            .ok_or(UtxoError::CorruptRecord)?;
        prologue
            .get_mut(at..end)
            .ok_or(UtxoError::CorruptRecord)?
            .copy_from_slice(&output.value.to_le_bytes());
        at = end;
    }
    let at = write_varint_at(
        pack_height(output.height, output.coinbase),
        &mut prologue,
        at,
    )
    .ok_or(UtxoError::CorruptRecord)?;

    writer.push(prologue.get(..at).ok_or(UtxoError::CorruptRecord)?)?;
    writer.push(output.script)?;
    Ok(())
}

fn validate_encoded(bytes: &[u8]) -> Result<RecordHeader, UtxoError> {
    let header = decode_header(bytes)?;
    let layout = V5Layout::read(bytes, header.output_count)?;

    // Both directory widths must be the narrowest that fits, or the record
    // would have a second, wider spelling of itself. `UtxoRecord` compares by
    // bytes, so two spellings of one record is a correctness bug, not a
    // cosmetic one.
    let mut max_vout = 0_u64;
    let mut max_len = 0_u64;
    let mut cursor = layout.payloads;
    for index in 0..layout.count {
        max_vout = max_vout.max(u64::from(layout.vout_at(bytes, index)?));
        let len = layout.payload_len_at(bytes, index)?;
        max_len = max_len.max(u64::try_from(len).unwrap_or(u64::MAX));
        let (_, next) = decode_output_at(bytes, &layout, index, cursor)?;
        cursor = next;
    }
    if width_for(max_vout) != layout.vout_width || width_for(max_len) != layout.len_width {
        return Err(UtxoError::CorruptRecord);
    }
    if cursor != bytes.len() {
        return Err(UtxoError::CorruptRecord);
    }
    Ok(header)
}

fn decode_header(bytes: &[u8]) -> Result<RecordHeader, UtxoError> {
    let txid_bytes = bytes.get(..TXID_LEN).ok_or(UtxoError::CorruptRecord)?;
    let mut txid = [0_u8; TXID_LEN];
    txid.copy_from_slice(txid_bytes);
    let output_count =
        usize::try_from(read_u32(bytes, OUTPUT_COUNT_OFFSET).ok_or(UtxoError::CorruptRecord)?)
            .map_err(|_| UtxoError::RecordTooLarge { len: usize::MAX })?;
    let inline_len = usize::from(
        *bytes
            .get(INLINE_LEN_OFFSET)
            .ok_or(UtxoError::CorruptRecord)?,
    );
    if inline_len > INLINE_CAPACITY || inline_len > output_count {
        return Err(UtxoError::CorruptRecord);
    }
    Ok(RecordHeader {
        txid: Hash256::from_le_bytes(&txid),
        output_count,
        inline_len,
    })
}

/// Byte offset of output `index`'s payload: the sum of every earlier payload
/// length.
///
/// This is what a random lookup pays instead of walking frames. The additions
/// read a dense, fixed-width array with no data dependency between entries,
/// where walking frames chased each output's length through its own bytes and
/// jumped over its script.
fn payload_offset(bytes: &[u8], layout: &V5Layout, index: usize) -> Result<usize, UtxoError> {
    let mut offset = layout.payloads;
    for earlier in 0..index {
        offset = offset
            .checked_add(layout.payload_len_at(bytes, earlier)?)
            .ok_or(UtxoError::CorruptRecord)?;
    }
    Ok(offset)
}

/// Decodes output `index`, whose payload starts at `payload`.
///
/// Returns the output and the offset just past its payload, so a sequential
/// walk never re-sums the length directory.
///
/// Every rejection here exists to keep the encoding canonical, so that equal
/// records are byte-equal, which `UtxoRecord`'s byte-wise `PartialEq` depends
/// on.
fn decode_output_at<'a>(
    bytes: &'a [u8],
    layout: &V5Layout,
    index: usize,
    payload: usize,
) -> Result<(OneUtxoOut<'a>, usize), UtxoError> {
    let vout = layout.vout_at(bytes, index)?;
    let len = layout.payload_len_at(bytes, index)?;
    let next = payload.checked_add(len).ok_or(UtxoError::CorruptRecord)?;
    let body = bytes.get(payload..next).ok_or(UtxoError::CorruptRecord)?;

    let (amount, cursor) = crate::compress::read_varint(body, 0)?;
    let (value, cursor) = if amount == AMOUNT_ESCAPE {
        let end = cursor
            .checked_add(core::mem::size_of::<u64>())
            .ok_or(UtxoError::CorruptRecord)?;
        let raw: [u8; 8] = body
            .get(cursor..end)
            .ok_or(UtxoError::CorruptRecord)?
            .try_into()
            .map_err(|_| UtxoError::CorruptRecord)?;
        let value = u64::from_le_bytes(raw);
        // An escaped value that would have compressed is a second spelling of
        // an amount the compact form already covers.
        if value <= crate::compress::MAX_COMPRESSIBLE_AMOUNT {
            return Err(UtxoError::CorruptRecord);
        }
        (value, end)
    } else {
        (
            crate::compress::decompress_amount(amount).ok_or(UtxoError::CorruptRecord)?,
            cursor,
        )
    };

    let (packed, cursor) = crate::compress::read_varint(body, cursor)?;
    let height = u32::try_from(packed >> 1).map_err(|_| UtxoError::CorruptRecord)?;
    let coinbase = packed & 1 == 1;

    // Whatever is left of the payload is the script, so no length is stored.
    // Keep the script length within the representable record bound.
    let script_pubkey = body.get(cursor..).ok_or(UtxoError::CorruptRecord)?;
    u16::try_from(script_pubkey.len()).map_err(|_| UtxoError::CorruptRecord)?;

    Ok((
        OneUtxoOut {
            vout,
            value,
            script_pubkey,
            coinbase,
            height,
        },
        next,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(core::mem::size_of::<u32>())?;
    let bytes = bytes.get(offset..end)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnedUtxoOut {
    pub(crate) vout: u32,
    pub(crate) value: u64,
    pub(crate) script_pubkey: Vec<u8>,
    pub(crate) coinbase: bool,
    pub(crate) height: u32,
}

impl OwnedUtxoOut {
    pub(crate) const fn new(
        vout: u32,
        value: u64,
        script_pubkey: Vec<u8>,
        coinbase: bool,
        height: u32,
    ) -> Self {
        Self {
            vout,
            value,
            script_pubkey,
            coinbase,
            height,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(vout: u32, script: &[u8], value: u64) -> OwnedUtxoOut {
        OwnedUtxoOut::new(vout, value, script.to_vec(), false, 1)
    }

    #[test]
    fn codec_accepts_exact_script_length_limit() -> Result<(), UtxoError> {
        let script = vec![0xA5; usize::from(u16::MAX)];
        let record = UtxoRecord::from_owned_outputs(
            Hash256::default(),
            &[OwnedUtxoOut::new(64, 42, script.clone(), false, u32::MAX)],
        )?;
        let output = record.outputs().next().ok_or(UtxoError::CorruptRecord)?;
        assert_eq!(output.script_pubkey, script.as_slice());
        assert_eq!(record.output_count(), 1);
        Ok(())
    }

    #[test]
    fn compact_owner_is_one_pointer() {
        assert_eq!(
            core::mem::size_of::<UtxoRecord>(),
            core::mem::size_of::<usize>()
        );
        assert_eq!(
            core::mem::size_of::<UtxoRecord>(),
            core::mem::size_of::<core::ptr::NonNull<u8>>()
        );
    }

    #[test]
    fn codec_keeps_canonical_metadata_and_zero_copy_script() -> Result<(), UtxoError> {
        let record = UtxoRecord::from_owned_outputs(
            Hash256::default(),
            &[OwnedUtxoOut::new(
                u32::MAX,
                42,
                vec![0x51, 0xAC],
                true,
                u32::MAX,
            )],
        )?;
        // Deliberately maxes both directory widths: `u32::MAX` in the vout and
        // height costs 5 varint bytes each, where a real output pays 1 and
        // 3. Even here the output representation is 15 metadata+script bytes.
        //   varint(u32::MAX) = 5, varint(compress(42)) = 2,
        //   varint(u32::MAX << 1 | 1) = 5, varint(2) = 1, script = 2
        assert_eq!(
            record.encoded_bytes().len(),
            RECORD_HEADER_LEN + 15,
            "v5 output layout changed"
        );
        let output = record.outputs().next().ok_or(UtxoError::CorruptRecord)?;
        assert_eq!(output.vout, u32::MAX);
        assert_eq!(output.value, 42);
        assert_eq!(output.height, u32::MAX);
        assert!(output.coinbase);
        assert_eq!(output.script_pubkey, &[0x51, 0xAC]);
        Ok(())
    }

    /// The buffer is allocated at `encoded_len` and the writer bounds-checks
    /// every push, so an undercount rejects a valid output and an overcount
    /// leaves slack in the structure this whole change exists to shrink.
    #[test]
    fn encoded_len_matches_the_bytes_written() -> Result<(), UtxoError> {
        let script = vec![0x51; 300];
        let cases = [
            OwnedUtxoOut::new(0, 0, Vec::new(), false, 0),
            OwnedUtxoOut::new(1, 1, vec![0x51], false, 1),
            OwnedUtxoOut::new(127, 100_000_000, vec![0x00; 22], true, 840_000),
            OwnedUtxoOut::new(128, 2_099_999_999_999_999, script.clone(), false, 1_048_576),
            // Above the money supply: takes the raw amount escape.
            OwnedUtxoOut::new(u32::MAX, u64::MAX, script, true, u32::MAX),
        ];
        for case in cases {
            let payload = OutputParts::from_owned(&case).payload_len()?;
            let vout_width = width_for(u64::from(case.vout));
            let len_width = width_for(u64::try_from(payload).unwrap_or(u64::MAX));
            // header || widths || one vout entry || one length entry || payload
            let expected = RECORD_HEADER_LEN + 1 + vout_width + len_width + payload;
            let record = UtxoRecord::from_owned_outputs(Hash256::default(), &[case])?;
            assert_eq!(
                record.encoded_bytes().len(),
                expected,
                "payload_len disagreed with write_payload"
            );
            // Exact-capacity buffer: no slack survives the encode.
            assert_eq!(record.buf.capacity(), record.buf.len());
        }
        Ok(())
    }

    /// An amount above the money supply cannot occur in a consensus-valid
    /// block, but the record representation still preserves it losslessly.
    #[test]
    fn an_amount_above_the_money_supply_survives_the_escape() -> Result<(), UtxoError> {
        for value in [
            crate::compress::MAX_COMPRESSIBLE_AMOUNT + 1,
            u64::MAX / 2,
            u64::MAX,
        ] {
            let record = UtxoRecord::from_owned_outputs(
                Hash256::default(),
                &[OwnedUtxoOut::new(3, value, vec![0x51], false, 7)],
            )?;
            let output = record.outputs().next().ok_or(UtxoError::CorruptRecord)?;
            assert_eq!(output.value, value, "escaped amount did not round trip");
            assert_eq!(output.vout, 3);
            assert_eq!(output.height, 7);
        }
        Ok(())
    }

    #[test]
    fn malformed_encoded_boundaries_are_rejected() -> Result<(), UtxoError> {
        let record =
            UtxoRecord::from_owned_outputs(Hash256::default(), &[output(0, &[0x51, 0xAC], 1)])?;
        let encoded = record.encoded_bytes();

        let truncated_metadata = encoded
            .get(..RECORD_HEADER_LEN + 2)
            .ok_or(UtxoError::CorruptRecord)?
            .to_vec();
        assert!(matches!(
            UtxoRecord::from_encoded(ThinRecordBuf::from_slice(&truncated_metadata)?),
            Err(UtxoError::CorruptRecord)
        ));

        let truncated_script_end = encoded
            .len()
            .checked_sub(1)
            .ok_or(UtxoError::CorruptRecord)?;
        let truncated_script = encoded
            .get(..truncated_script_end)
            .ok_or(UtxoError::CorruptRecord)?
            .to_vec();
        assert!(matches!(
            UtxoRecord::from_encoded(ThinRecordBuf::from_slice(&truncated_script)?),
            Err(UtxoError::CorruptRecord)
        ));

        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(matches!(
            UtxoRecord::from_encoded(ThinRecordBuf::from_slice(&trailing)?),
            Err(UtxoError::CorruptRecord)
        ));

        let mut count_mismatch = encoded.to_vec();
        let count = count_mismatch
            .get_mut(OUTPUT_COUNT_OFFSET..INLINE_LEN_OFFSET)
            .ok_or(UtxoError::CorruptRecord)?;
        count.copy_from_slice(&2_u32.to_le_bytes());
        assert!(matches!(
            UtxoRecord::from_encoded(ThinRecordBuf::from_slice(&count_mismatch)?),
            Err(UtxoError::CorruptRecord)
        ));

        Ok(())
    }

    /// A corrupt record must not be able to panic the decoder.
    #[test]
    fn an_absurd_compressed_amount_is_rejected_rather_than_overflowing() -> Result<(), UtxoError> {
        // `varint(u64::MAX - 1)`: ten bytes, and not the escape sentinel, so it
        // reaches the amount transform.
        let mut payload = vec![0xFE_u8];
        payload.extend_from_slice(&[0xFF; 8]);
        payload.push(0x01);
        payload.extend_from_slice(&[0x02, 0x51, 0xAC]);

        let mut bytes = Hash256::default().to_le_bytes().to_vec();
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(1);
        bytes.push(0x11);
        bytes.push(0x00);
        bytes.push(u8::try_from(payload.len()).unwrap_or(0));
        bytes.extend_from_slice(&payload);

        assert!(matches!(
            UtxoRecord::from_encoded(ThinRecordBuf::from_slice(&bytes)?),
            Err(UtxoError::CorruptRecord)
        ));
        Ok(())
    }

    /// v5 has no invalid bool byte — `coinbase` is one bit of a varint, so
    /// every value is meaningful. What it has instead is several ways to spell
    /// one output, and all of them must be refused: `UtxoRecord` compares by
    /// bytes, so a second spelling makes equal records unequal.
    #[test]
    fn non_canonical_v5_spellings_are_rejected() -> Result<(), UtxoError> {
        // Assembles a one-output record: `header || widths || vout_dir ||
        // len_dir || payload`.
        fn record(vout_width: usize, len_width: usize, vout: u64, payload: &[u8]) -> Vec<u8> {
            let mut bytes = Hash256::default().to_le_bytes().to_vec();
            bytes.extend_from_slice(&1_u32.to_le_bytes());
            bytes.push(1);
            let widths =
                (u8::try_from(len_width).unwrap_or(1) << 4) | u8::try_from(vout_width).unwrap_or(1);
            bytes.push(widths);
            bytes.extend_from_slice(&vout.to_le_bytes()[..vout_width]);
            let len = u64::try_from(payload.len()).unwrap_or(0);
            bytes.extend_from_slice(&len.to_le_bytes()[..len_width]);
            bytes.extend_from_slice(payload);
            bytes
        }

        // `vout 0, value 1, height 1, not coinbase, script 0x51 0xAC`. The
        // payload is `varint(compress(1)) || varint(1 << 1) || script`; the
        // script length is not stored, so the script is simply the remainder.
        let canonical = record(1, 1, 0, &[0x01, 0x02, 0x51, 0xAC]);
        assert!(
            UtxoRecord::from_encoded(ThinRecordBuf::from_slice(&canonical)?).is_ok(),
            "the canonical spelling must decode"
        );

        // The amount as a two-byte spelling of one.
        let non_minimal = record(1, 1, 0, &[0x81, 0x00, 0x02, 0x51, 0xAC]);
        assert!(matches!(
            UtxoRecord::from_encoded(ThinRecordBuf::from_slice(&non_minimal)?),
            Err(UtxoError::CorruptRecord)
        ));

        // The escape used for a value the compact form already covers.
        let mut escaped = [0xFF_u8; 9].to_vec();
        escaped.push(0x01);
        escaped.extend_from_slice(&1_u64.to_le_bytes());
        escaped.extend_from_slice(&[0x02, 0x51, 0xAC]);
        assert!(matches!(
            UtxoRecord::from_encoded(ThinRecordBuf::from_slice(&record(1, 1, 0, &escaped))?),
            Err(UtxoError::CorruptRecord)
        ));

        // Directories wider than this record needs. This spelling is what the
        // fixed-width layout introduced, and the reason the widths are
        // validated on decode rather than merely read.
        for (vout_width, len_width) in [(2, 1), (1, 2), (4, 4)] {
            let wide = record(vout_width, len_width, 0, &[0x01, 0x02, 0x51, 0xAC]);
            assert!(
                matches!(
                    UtxoRecord::from_encoded(ThinRecordBuf::from_slice(&wide)?),
                    Err(UtxoError::CorruptRecord)
                ),
                "an over-wide {vout_width}/{len_width} directory was accepted"
            );
        }

        // A script longer than the `u16` payload ceiling.
        let mut oversize = vec![0x01, 0x02];
        oversize.extend_from_slice(&vec![0x51; 65_536]);
        assert!(matches!(
            UtxoRecord::from_encoded(ThinRecordBuf::from_slice(&record(1, 4, 0, &oversize))?),
            Err(UtxoError::CorruptRecord)
        ));
        Ok(())
    }

    #[test]
    fn rejected_staged_add_leaves_source_record_unchanged() -> Result<(), UtxoError> {
        let record = UtxoRecord::from_owned_outputs(Hash256::default(), &[output(0, &[0x51], 1)])?;
        let original = record.clone();
        let too_large = OwnedUtxoOut::new(1, 2, vec![0_u8; usize::from(u16::MAX) + 1], false, 1);
        assert!(matches!(
            record.stage_add_run(&[too_large], true),
            Err(UtxoError::ScriptTooLarge { .. })
        ));
        assert_eq!(record, original);
        Ok(())
    }

    #[test]
    fn thin_owner_exact_constructor_has_no_slack() -> Result<(), UtxoError> {
        let record =
            UtxoRecord::from_owned_outputs(Hash256::default(), &[output(0, &[0x51, 0xAC], 1)])?;
        assert_eq!(record.buf.len(), record.encoded_bytes().len());
        assert_eq!(record.buf.capacity(), record.buf.len());
        Ok(())
    }

    #[test]
    fn thin_owner_deep_clone_is_independent_and_exact() -> Result<(), UtxoError> {
        let record = UtxoRecord::from_owned_outputs(
            Hash256::from_le_bytes(&[0x11; TXID_LEN]),
            &[output(0, &[0x51], 1), output(1, &[0x6A, 0xAC], 2)],
        )?;
        let clone = record.clone();
        assert_eq!(clone, record);
        assert_eq!(clone.encoded_bytes(), record.encoded_bytes());
        // Clones retain no slack and own a distinct allocation.
        assert_eq!(clone.buf.capacity(), clone.buf.len());
        assert_ne!(
            record.buf.as_bytes().as_ptr(),
            clone.buf.as_bytes().as_ptr()
        );
        // Dropping the source must leave the clone fully valid; Miri verifies the
        // allocations are independent.
        drop(record);
        assert_eq!(clone.output_count(), 2);
        Ok(())
    }

    #[test]
    fn thin_scratch_writer_builds_exact_payload() -> Result<(), UtxoError> {
        let mut buf = ThinRecordBuf::with_capacity(6)?;
        {
            let mut writer = RecordWriter::new(&mut buf);
            writer.push(&[1, 2, 3])?;
            writer.push(&[])?;
            writer.push(&[4, 5, 6])?;
            writer.finish()?;
        }
        assert_eq!(buf.as_bytes(), &[1, 2, 3, 4, 5, 6]);
        assert_eq!(buf.len(), 6);
        assert_eq!(buf.capacity(), 6);
        Ok(())
    }

    #[test]
    fn thin_scratch_writer_rejects_capacity_overflow() -> Result<(), UtxoError> {
        let mut buf = ThinRecordBuf::with_capacity(2)?;
        let mut writer = RecordWriter::new(&mut buf);
        writer.push(&[1, 2])?;
        assert!(matches!(writer.push(&[3]), Err(UtxoError::CorruptRecord)));
        Ok(())
    }
}
