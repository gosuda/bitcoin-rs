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

const WIDTHS_OFFSET: usize = RECORD_HEADER_LEN;
const V5_BODY_OFFSET: usize = WIDTHS_OFFSET + 1;
/// Widest directory entry. `vout` is a `u32`; a payload is at most a 10-byte
/// amount, 8 escape bytes, a 5-byte height and a `u16`-ceilinged script.
const MAX_DIR_WIDTH: usize = 4;

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

fn read_width(bytes: &[u8], offset: usize, width: usize) -> Option<u64> {
    let end = offset.checked_add(width)?;
    let slice = bytes.get(offset..end)?;
    let mut value = 0_u64;
    for (index, byte) in slice.iter().enumerate() {
        value |= u64::from(*byte) << (index * 8);
    }
    Some(value)
}

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

fn pack_widths(vout_width: usize, len_width: usize) -> Result<u8, UtxoError> {
    let vout = u8::try_from(vout_width).map_err(|_| UtxoError::CorruptRecord)?;
    let len = u8::try_from(len_width).map_err(|_| UtxoError::CorruptRecord)?;
    Ok((len << 4) | vout)
}
const INLINE_CAPACITY: usize = 8;

/// Sentinel amount varint meaning "the next 8 bytes are a raw little-endian
/// value".
const AMOUNT_ESCAPE: u64 = u64::MAX;

fn pack_height(height: u32, coinbase: bool) -> u64 {
    (u64::from(height) << 1) | u64::from(coinbase)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct OneUtxoOut<'a> {
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: &'a [u8],
    pub coinbase: bool,
    pub height: u32,
}

/// A transaction-level UTXO record encoded in one owned byte slice.
///
/// PRE: constructors receive a valid canonical encoding or validated output
/// parts.
/// POST: the slice contains the complete canonical record payload.
/// INVARIANT: the payload is immutable after construction and owns no spare
/// capacity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UtxoRecord {
    buf: Box<[u8]>,
}

#[derive(Copy, Clone)]
struct RecordHeader {
    txid: Hash256,
    output_count: usize,
    inline_len: usize,
}

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
    pub(crate) fn from_encoded(buf: Box<[u8]>) -> Result<Self, UtxoError> {
        validate_encoded(&buf)?;
        Ok(Self { buf })
    }

    fn bytes(&self) -> &[u8] {
        &self.buf
    }

    pub(crate) fn from_owned_outputs(
        txid: Hash256,
        outputs: &[OwnedUtxoOut],
    ) -> Result<Self, UtxoError> {
        let buf = encode_record(
            txid,
            outputs.len().min(INLINE_CAPACITY),
            &owned_parts(outputs),
        )?;
        Self::from_encoded(buf)
    }

    pub(crate) fn key(&self) -> UtxoKey {
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&self.bytes()[..8]);
        UtxoKey::from_prefix(prefix)
    }

    pub(crate) fn txid(&self) -> Hash256 {
        let mut txid = [0_u8; TXID_LEN];
        txid.copy_from_slice(&self.bytes()[..TXID_LEN]);
        Hash256::from_le_bytes(&txid)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.output_count() == 0
    }

    pub(crate) fn output_count(&self) -> usize {
        self.header().output_count
    }

    pub(crate) fn outputs(&self) -> UtxoOutputIter<'_> {
        let bytes = self.bytes();
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

    pub(crate) fn find_output(&self, vout: u32) -> Option<OneUtxoOut<'_>> {
        let bytes = self.bytes();
        let layout = self.layout().ok()?;
        let index = (0..layout.count)
            .find(|index| layout.vout_at(bytes, *index).is_ok_and(|c| c == vout))?;
        let payload = payload_offset(bytes, &layout, index).ok()?;
        match decode_output_at(bytes, &layout, index, payload) {
            Ok((output, _)) => Some(output),
            Err(error) => panic!("validated UTXO record output must remain decodable: {error:?}"),
        }
    }

    pub(crate) fn max_vout(&self) -> Option<u32> {
        let bytes = self.bytes();
        let layout = self.layout().ok()?;
        (0..layout.count)
            .filter_map(|index| layout.vout_at(bytes, index).ok())
            .max()
    }

    /// Builds one replacement for additions to an existing record or a new
    /// txid.
    ///
    /// PRE: `existing`, when present, has `txid`; additions and `add_unique`
    /// satisfy the checks of the current staging paths.
    /// POST: returns the canonical replacement. If `overwritten` is Some, it
    /// has one entry per addition in addition order; an append has a None
    /// entry.
    /// INVARIANT: an error leaves the source record, shard table, and any
    /// `overwritten` sink unchanged.
    pub(crate) fn add_run_replacement<'p>(
        existing: Option<&Self>,
        txid: Hash256,
        additions: &'p [OutputParts<'p>],
        add_unique: bool,
        overwritten: Option<&mut Vec<Option<OwnedUtxoOut>>>,
    ) -> Result<Self, UtxoError> {
        if add_unique {
            let appended = match existing {
                Some(record) => record.append_unique_run(additions)?,
                // Unique adds on a fresh record encode in slice order with the
                // inline partition filled to capacity; no dedup pass is
                // needed.
                None => Some(Self::from_output_parts(
                    txid,
                    additions.len().min(INLINE_CAPACITY),
                    additions,
                )?),
            };
            if let Some(record) = appended {
                // The unique fast path can never overwrite a live vout, so
                // every append slot is None.
                if let Some(sink) = overwritten {
                    sink.resize(sink.len().saturating_add(additions.len()), None);
                }
                return Ok(record);
            }
            // Appending would reorder the inline partition or widen a
            // directory: fall through to the rebuild, where the unique scan
            // overwrites nothing and every sink slot is None.
        }
        let (mut parts, mut inline_len) = match existing {
            Some(record) => (record.output_parts(), record.header().inline_len),
            None => (Vec::with_capacity(additions.len()), 0),
        };
        // Overwrite events are staged locally: `from_output_parts` can still
        // fail, and a failed add must leave the caller's sink untouched.
        let mut staged = overwritten
            .is_some()
            .then(|| Vec::with_capacity(additions.len()));
        apply_additions(
            &mut parts,
            &mut inline_len,
            additions,
            add_unique,
            staged.as_mut(),
        );
        let record = Self::from_output_parts(txid, inline_len, &parts)?;
        if let (Some(sink), Some(events)) = (overwritten, staged) {
            sink.extend(events);
        }
        Ok(record)
    }

    /// Increasing-unique append-copy fast path. Returns `None` when appending
    /// would reorder the inline partition bytes, or when the directories would
    /// have to widen, so the caller must rebuild.
    fn append_unique_run(&self, additions: &[OutputParts<'_>]) -> Result<Option<Self>, UtxoError> {
        let header = self.header();
        let appends_at_end =
            header.output_count == header.inline_len || header.inline_len == INLINE_CAPACITY;
        if !appends_at_end {
            return Ok(None);
        }
        let old = self.layout()?;
        let bytes = self.bytes();

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
        let mut buf = Vec::with_capacity(payload_len);
        buf.extend_from_slice(&header.txid.to_le_bytes());
        buf.extend_from_slice(&output_count.to_le_bytes());
        buf.push(inline_len_u8);
        buf.push(pack_widths(old.vout_width, old.len_width)?);

        buf.extend_from_slice(region(old.vout_dir, old.len_dir)?);
        for addition in additions {
            push_dir_entry(&mut buf, u64::from(addition.vout), old.vout_width)?;
        }
        buf.extend_from_slice(region(old.len_dir, old.payloads)?);
        for addition in additions {
            let len = u64::try_from(addition.payload_len()?).unwrap_or(u64::MAX);
            push_dir_entry(&mut buf, len, old.len_width)?;
        }
        buf.extend_from_slice(region(old.payloads, bytes.len())?);
        for addition in additions {
            write_payload(&mut buf, addition)?;
        }
        if buf.len() != payload_len {
            return Err(UtxoError::CorruptRecord);
        }
        // Invariant: the copied prefix came from this validated record and every
        // appended addition was size-checked above, so the payload is canonical
        // and needs no re-decode. The length check above is fail-fast in every
        // profile: a release build never constructs a validated record whose
        // written length disagrees with the sizing pass.
        Ok(Some(Self {
            buf: buf.into_boxed_slice(),
        }))
    }

    /// Builds a replacement for one ordered run of removals.
    ///
    /// PRE: `vouts` may contain absent or repeated indexes and is in request
    /// order.
    /// POST: returns Unchanged, Emptied, or Replaced as today. If `removed` is
    /// Some, it receives one slot per requested vout in request order; absent
    /// or repeated indexes have None. Exact-cover removal builds no
    /// replacement.
    /// INVARIANT: each live vout is removed at most once; an error leaves
    /// source bytes and the shard table unchanged.
    pub(crate) fn remove_run_replacement(
        &self,
        vouts: &[u32],
        mut removed: Option<&mut Vec<Option<OwnedUtxoOut>>>,
    ) -> Result<RemovedRecord, UtxoError> {
        if let Some(outputs) = self.full_removal_outputs(vouts) {
            if let Some(sink) = removed.as_deref_mut() {
                for output in &outputs {
                    sink.push(Some(OutputParts::from_view(output).into_owned()));
                }
            }
            return Ok(RemovedRecord::Emptied);
        }
        let mut parts = self.output_parts();
        let mut inline_len = self.header().inline_len;
        let mut any_removed = false;
        for &vout in vouts {
            let output = parts
                .iter()
                .position(|part| part.vout == vout)
                .map(|index| remove_part_at(&mut parts, &mut inline_len, index));
            any_removed |= output.is_some();
            if let Some(sink) = removed.as_deref_mut() {
                sink.push(output.map(OutputParts::into_owned));
            }
        }
        if !any_removed {
            return Ok(RemovedRecord::Unchanged);
        }
        if parts.is_empty() {
            return Ok(RemovedRecord::Emptied);
        }
        Ok(RemovedRecord::Replaced(Self::from_output_parts(
            self.txid(),
            inline_len,
            &parts,
        )?))
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
            let add_unique =
                vouts_are_strictly_increasing(None, additions.iter().map(|part| part.vout));
            let record = Self::add_run_replacement(None, self.txid(), additions, add_unique, None)?;
            return Ok(RemovedRecord::Replaced(record));
        }
        let mut parts = self.output_parts();
        let mut inline_len = self.header().inline_len;
        // `add_unique` is the strictly-increasing fast path. `parts` are the
        // pre-removal live outputs, so their max is exactly the record's
        // pre-removal `max_vout`; computing it here from the already-built
        // descriptors avoids a second full decode of every output.
        let add_unique = vouts_are_strictly_increasing(
            parts.iter().map(|part| part.vout).max(),
            additions.iter().map(|part| part.vout),
        );
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

    /// The exact-cover check plus the located outputs in request order, so the
    /// caller's materialization does not repeat the per-vout lookup.
    fn full_removal_outputs(&self, vouts: &[u32]) -> Option<Vec<OneUtxoOut<'_>>> {
        if self.output_count() != vouts.len() {
            return None;
        }
        let mut outputs = Vec::with_capacity(vouts.len());
        for (index, &vout) in vouts.iter().enumerate() {
            if vouts[..index].contains(&vout) {
                return None;
            }
            outputs.push(self.find_output(vout)?);
        }
        Some(outputs)
    }

    pub(crate) fn payload_bytes(&self) -> usize {
        self.buf.len()
    }

    fn layout(&self) -> Result<V5Layout, UtxoError> {
        V5Layout::read(self.bytes(), self.header().output_count)
    }

    fn header(&self) -> RecordHeader {
        match decode_header(self.bytes()) {
            Ok(header) => header,
            // `UtxoRecord` is only built through `from_encoded` or
            // `from_output_parts`, both of which produce a canonical payload; a
            // header decode failure means the validated record was mutated in
            // place.
            Err(error) => panic!("UtxoRecord is validated at construction: {error:?}"),
        }
    }

    fn output_parts(&self) -> Vec<OutputParts<'_>> {
        let mut parts = Vec::with_capacity(self.header().output_count);
        parts.extend(self.outputs().map(|output| OutputParts::from_view(&output)));
        parts
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

/// Outcome of a coalesced remove run. The optional sink materializes one slot
/// per requested vout in request order; absent or repeated slots stay None.
pub(crate) enum RemovedRecord {
    Unchanged,
    Emptied,
    Replaced(UtxoRecord),
}

fn owned_parts(outputs: &[OwnedUtxoOut]) -> Vec<OutputParts<'_>> {
    outputs.iter().map(OutputParts::from_owned).collect()
}

/// Applies a coalesced add run to `parts` with overwrite semantics, preserving
/// the inline/overflow partition order. When `overwritten` is supplied,
/// each displaced output is cloned owned into it in addition order. The
/// caller commits the sink only after the replacement record encodes: the
/// displaced outputs are staged locally and appended to the sink after the
/// whole run is applied, so an encoding failure in the caller never leaves
/// the sink partially filled.
fn apply_additions<'a>(
    parts: &mut Vec<OutputParts<'a>>,
    inline_len: &mut usize,
    additions: &[OutputParts<'a>],
    add_unique: bool,
    overwritten: Option<&mut Vec<Option<OwnedUtxoOut>>>,
) {
    let mut displaced = Vec::with_capacity(additions.len());
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
        displaced.push(old.map(OutputParts::into_owned));
    }
    if let Some(sink) = overwritten {
        sink.extend(displaced);
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
/// the maximum vout live before the additions; `None` means no seed was
/// supplied. A non-strictly-greater vout fails on `<=`.
pub(crate) fn vouts_are_strictly_increasing(
    previous: Option<u32>,
    vouts: impl IntoIterator<Item = u32>,
) -> bool {
    let mut previous = previous;
    for vout in vouts {
        if previous.is_some_and(|max| vout <= max) {
            return false;
        }
        previous = Some(vout);
    }
    true
}

fn push_dir_entry(buf: &mut Vec<u8>, value: u64, width: usize) -> Result<(), UtxoError> {
    let bytes = value.to_le_bytes();
    buf.extend_from_slice(bytes.get(..width).ok_or(UtxoError::CorruptRecord)?);
    Ok(())
}

/// Encodes a canonical record payload into one exact-size boxed slice. Every
/// script must be `<= u16::MAX`; existing outputs satisfy this by construction
/// and additions are prevalidated here.
fn encode_record(
    txid: Hash256,
    inline_len: usize,
    outputs: &[OutputParts<'_>],
) -> Result<Box<[u8]>, UtxoError> {
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
    let mut buf = Vec::with_capacity(payload_len);
    buf.extend_from_slice(&txid.to_le_bytes());
    buf.extend_from_slice(&output_count.to_le_bytes());
    buf.push(inline_len_u8);
    buf.push(pack_widths(vout_width, len_width)?);
    // One `extend` per directory entry is cheaper than staging both directories
    // in a scratch buffer: the entries are only one or two bytes each.
    for output in outputs {
        push_dir_entry(&mut buf, u64::from(output.vout), vout_width)?;
    }
    for len in &payload_lens {
        push_dir_entry(&mut buf, u64::from(*len), len_width)?;
    }
    for output in outputs {
        write_payload(&mut buf, output)?;
    }
    // Sizing and writing must agree exactly: the length directory records the
    // computed sizes, so any disagreement would corrupt the encoding.
    if buf.len() != payload_len {
        return Err(UtxoError::CorruptRecord);
    }
    Ok(buf.into_boxed_slice())
}

fn amount_parts(value: u64) -> (u64, bool) {
    match crate::compress::compress_amount(value) {
        Ok(compressed) => (compressed, false),
        Err(_) => (AMOUNT_ESCAPE, true),
    }
}

/// Appends one output's v5 payload:
/// `varint(amount) [|| raw amount] || varint(height << 1 | coinbase) || script`.
fn write_payload(buf: &mut Vec<u8>, output: &OutputParts<'_>) -> Result<(), UtxoError> {
    use crate::compress::write_varint_at;

    let script_len = output.script.len();
    u16::try_from(script_len).map_err(|_| UtxoError::ScriptTooLarge { len: script_len })?;
    let (amount, escaped) = amount_parts(output.value);

    // Lay the variable-length prologue into one stack buffer and copy it once.
    // Appending a checked byte per field adds overhead to every output.
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

    buf.extend_from_slice(prologue.get(..at).ok_or(UtxoError::CorruptRecord)?);
    buf.extend_from_slice(output.script);
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

fn payload_offset(bytes: &[u8], layout: &V5Layout, index: usize) -> Result<usize, UtxoError> {
    let mut offset = layout.payloads;
    for earlier in 0..index {
        offset = offset
            .checked_add(layout.payload_len_at(bytes, earlier)?)
            .ok_or(UtxoError::CorruptRecord)?;
    }
    Ok(offset)
}

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
            record.payload_bytes(),
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
                record.payload_bytes(),
                expected,
                "payload_len disagreed with write_payload"
            );
        }
        Ok(())
    }

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
    fn a_corrupt_encoded_record_is_refused() -> Result<(), UtxoError> {
        type Corrupt = fn(&mut Vec<u8>, usize);
        let record = UtxoRecord::from_owned_outputs(
            Hash256::default(),
            &[output(0, &[0x51], 1), output(1, &[0x52, 0xac], 2)],
        )?;
        let len_dir = record.layout()?.len_dir;
        let encoded = record.bytes().to_vec();

        let cases: [(&str, Corrupt); 10] = [
            ("metadata truncated", |bytes, _| {
                bytes.truncate(RECORD_HEADER_LEN + 2);
            }),
            ("script truncated", |bytes, _| {
                bytes.pop();
            }),
            ("trailing byte", |bytes, _| bytes.push(0)),
            ("output count above the outputs present", |bytes, _| {
                bytes[OUTPUT_COUNT_OFFSET..INLINE_LEN_OFFSET].copy_from_slice(&3_u32.to_le_bytes());
            }),
            ("zero width nibble", |bytes, _| bytes[WIDTHS_OFFSET] = 0x00),
            ("over-wide vout nibble", |bytes, _| {
                bytes[WIDTHS_OFFSET] = 0x05;
            }),
            ("over-wide length nibble", |bytes, _| {
                bytes[WIDTHS_OFFSET] = 0x50;
            }),
            ("both nibbles over-wide", |bytes, _| {
                bytes[WIDTHS_OFFSET] = 0xff;
            }),
            ("inline_len above the output count", |bytes, _| {
                bytes[INLINE_LEN_OFFSET] = 3;
            }),
            ("inline_len above INLINE_CAPACITY", |bytes, _| {
                bytes[INLINE_LEN_OFFSET] = 9;
            }),
        ];

        for (label, corrupt) in cases {
            let mut mutant = encoded.clone();
            corrupt(&mut mutant, len_dir);
            assert!(
                matches!(
                    UtxoRecord::from_encoded(mutant.into_boxed_slice()),
                    Err(UtxoError::CorruptRecord)
                ),
                "{label} was accepted"
            );
        }

        // A length-directory entry claiming a payload past the buffer end.
        let mut lying_length = encoded;
        lying_length[len_dir] = 0xf0;
        assert!(matches!(
            UtxoRecord::from_encoded(lying_length.into_boxed_slice()),
            Err(UtxoError::CorruptRecord)
        ));
        Ok(())
    }

    #[test]
    fn an_absurd_compressed_amount_is_rejected_rather_than_overflowing() {
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
            UtxoRecord::from_encoded(bytes.clone().into_boxed_slice()),
            Err(UtxoError::CorruptRecord)
        ));
    }

    /// v5 has no invalid bool byte — `coinbase` is one bit of a varint, so
    /// every value is meaningful. What it has instead is several ways to spell
    /// one output, and all of them must be refused: `UtxoRecord` compares by
    /// bytes, so a second spelling makes equal records unequal.
    #[test]
    fn non_canonical_v5_spellings_are_rejected() {
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

        let canonical = record(1, 1, 0, &[0x01, 0x02, 0x51, 0xAC]);
        assert!(
            UtxoRecord::from_encoded(canonical.into_boxed_slice()).is_ok(),
            "the canonical spelling must decode"
        );

        // The amount as a two-byte spelling of one.
        let non_minimal = record(1, 1, 0, &[0x81, 0x00, 0x02, 0x51, 0xAC]);
        assert!(matches!(
            UtxoRecord::from_encoded(non_minimal.into_boxed_slice()),
            Err(UtxoError::CorruptRecord)
        ));

        // The escape used for a value the compact form already covers.
        let mut escaped = [0xFF_u8; 9].to_vec();
        escaped.push(0x01);
        escaped.extend_from_slice(&1_u64.to_le_bytes());
        escaped.extend_from_slice(&[0x02, 0x51, 0xAC]);
        assert!(matches!(
            UtxoRecord::from_encoded(record(1, 1, 0, &escaped).into_boxed_slice()),
            Err(UtxoError::CorruptRecord)
        ));

        // Directories wider than this record needs. This spelling is what the
        // fixed-width layout introduced, and the reason the widths are
        // validated on decode rather than merely read.
        for (vout_width, len_width) in [(2, 1), (1, 2), (4, 4)] {
            let wide = record(vout_width, len_width, 0, &[0x01, 0x02, 0x51, 0xAC]);
            assert!(
                matches!(
                    UtxoRecord::from_encoded(wide.clone().into_boxed_slice()),
                    Err(UtxoError::CorruptRecord)
                ),
                "an over-wide {vout_width}/{len_width} directory was accepted"
            );
        }

        // A script longer than the `u16` payload ceiling.
        let mut oversize = vec![0x01, 0x02];
        oversize.extend_from_slice(&vec![0x51; 65_536]);
        assert!(matches!(
            UtxoRecord::from_encoded(record(1, 4, 0, &oversize).into_boxed_slice()),
            Err(UtxoError::CorruptRecord)
        ));
    }

    #[test]
    fn rejected_staged_add_leaves_source_record_unchanged() -> Result<(), UtxoError> {
        let record = UtxoRecord::from_owned_outputs(Hash256::default(), &[output(0, &[0x51], 1)])?;
        let original = record.clone();
        let too_large = OwnedUtxoOut::new(1, 2, vec![0_u8; usize::from(u16::MAX) + 1], false, 1);
        let additions = [OutputParts::from_owned(&too_large)];
        for mut overwritten in [None, Some(Vec::new())] {
            assert!(matches!(
                UtxoRecord::add_run_replacement(
                    Some(&record),
                    record.txid(),
                    &additions,
                    true,
                    overwritten.as_mut(),
                ),
                Err(UtxoError::ScriptTooLarge { .. })
            ));
        }
        assert_eq!(record, original);
        Ok(())
    }

    #[test]
    fn deep_clone_is_independent_and_byte_equal() -> Result<(), UtxoError> {
        let record = UtxoRecord::from_owned_outputs(
            Hash256::from_le_bytes(&[0x11; TXID_LEN]),
            &[output(0, &[0x51], 1), output(1, &[0x6A, 0xAC], 2)],
        )?;
        let clone = record.clone();
        assert_eq!(clone, record);
        // Clones own a distinct payload; no slack survives the copy.
        assert_eq!(clone.payload_bytes(), record.payload_bytes());
        // Dropping the source must leave the clone fully valid; Miri verifies the
        // allocations are independent.
        drop(record);
        assert_eq!(clone.output_count(), 2);
        assert!(clone.find_output(1).is_some());
        Ok(())
    }

    /// A record with no outputs is a real encoding (a fully-spent
    /// transaction); every accessor on it must stay empty-shaped.
    #[test]
    fn an_outputless_record_decodes_and_reports_empty() -> Result<(), UtxoError> {
        let record = UtxoRecord::from_owned_outputs(Hash256::default(), &[])?;
        assert!(record.is_empty());
        assert_eq!(record.output_count(), 0);
        assert_eq!(record.max_vout(), None);
        assert!(record.find_output(0).is_none());
        assert_eq!(record.outputs().len(), 0);
        let decoded = UtxoRecord::from_encoded(record.buf.clone())?;
        assert_eq!(decoded, record);
        // Removing nothing from nothing is an exact cover of an empty set.
        let mut removed = Vec::new();
        assert!(matches!(
            record.remove_run_replacement(&[], Some(&mut removed))?,
            RemovedRecord::Emptied
        ));
        assert_eq!(removed, []);
        Ok(())
    }

    /// Every removal outcome for one live record: which requests leave it
    /// unchanged, which replace it, which empty it, and what each materializes
    /// into the sink — in request order, with a `None` hole for every vout the
    /// record does not hold and no phantom removal ever fabricated.
    #[test]
    fn removal_outcome_and_materialization_follow_the_request() -> Result<(), UtxoError> {
        type Case = (&'static [u32], Outcome, &'static [Option<u32>]);
        #[derive(Debug, PartialEq, Eq)]
        enum Outcome {
            Unchanged,
            Replaced(Vec<u32>),
            Emptied,
        }
        let record = UtxoRecord::from_owned_outputs(
            Hash256::default(),
            &[
                output(0, &[0x50], 10),
                output(1, &[0x51], 11),
                output(2, &[0x52], 12),
            ],
        )?;
        let cases: [Case; 8] = [
            (&[], Outcome::Unchanged, &[]),
            (&[9], Outcome::Unchanged, &[None]),
            (&[9, 8], Outcome::Unchanged, &[None, None]),
            (&[0, 9], Outcome::Replaced(vec![1, 2]), &[Some(0), None]),
            (
                &[0, 1, 9],
                Outcome::Replaced(vec![2]),
                &[Some(0), Some(1), None],
            ),
            (
                &[0, 0, 1],
                Outcome::Replaced(vec![2]),
                &[Some(0), None, Some(1)],
            ),
            (&[2, 0, 1], Outcome::Emptied, &[Some(2), Some(0), Some(1)]),
            (
                &[0, 1, 2, 9],
                Outcome::Emptied,
                &[Some(0), Some(1), Some(2), None],
            ),
        ];
        for (request, expected, materialized) in cases {
            let mut removed = Vec::new();
            let outcome = match record.remove_run_replacement(request, Some(&mut removed))? {
                RemovedRecord::Unchanged => Outcome::Unchanged,
                RemovedRecord::Replaced(replacement) => {
                    // Survivors as a set: the replacement's iteration order is
                    // the partition's, not the vout order.
                    let mut survivors: Vec<u32> =
                        replacement.outputs().map(|out| out.vout).collect();
                    survivors.sort_unstable();
                    Outcome::Replaced(survivors)
                }
                RemovedRecord::Emptied => Outcome::Emptied,
            };
            assert_eq!(outcome, expected, "outcome for {request:?}");
            assert_eq!(
                removed
                    .iter()
                    .map(|out| out.as_ref().map(|kept| kept.vout))
                    .collect::<Vec<_>>(),
                materialized,
                "materialized vouts for {request:?}"
            );
            for kept in removed.iter().flatten() {
                assert_eq!(
                    kept.value,
                    10 + u64::from(kept.vout),
                    "materialized payload for {request:?}"
                );
            }
            // The sink is optional and must not change the outcome.
            let without_sink = record.remove_run_replacement(request, None)?;
            assert_eq!(
                matches!(without_sink, RemovedRecord::Emptied),
                matches!(expected, Outcome::Emptied),
                "sinkless outcome for {request:?}"
            );
        }
        Ok(())
    }

    /// `edit_replacement` fuses one removal run with one add run. The
    /// uniqueness score is taken against the *pre-removal* max, so an addition
    /// below it, a full removal, and a re-add of a removed vout each have to
    /// rebuild rather than append — and the survivors must be exactly the
    /// union, with the addition carrying its new payload.
    #[test]
    fn edit_replacement_fuses_removals_and_additions() -> Result<(), UtxoError> {
        type Addition = (u32, u64, &'static [u8], bool);
        type Case = (
            &'static str,
            &'static [u32],
            &'static [u32],
            Addition,
            &'static [(u32, u64)],
        );
        let cases: [Case; 4] = [
            (
                "an addition below the pre-removal max",
                &[0, 5],
                &[5],
                (3, 33, &[0x33], false),
                &[(0, 0), (3, 33)],
            ),
            (
                "an edit past full removal",
                &[0, 1],
                &[0, 1],
                (4, 44, &[0x44], true),
                &[(4, 44)],
            ),
            (
                "a duplicated remove request is not a full removal",
                &[0, 1, 2],
                &[0, 0, 1],
                (5, 55, &[0x55], false),
                &[(2, 2), (5, 55)],
            ),
            (
                "a re-add of a removed vout",
                &[0, 1],
                &[1],
                (1, 66, &[0x66, 0xac], false),
                &[(0, 0), (1, 66)],
            ),
        ];
        for (name, initial, removes, (vout, value, script, coinbase), survivors) in cases {
            let outputs: Vec<OwnedUtxoOut> = initial
                .iter()
                .map(|live| output(*live, &[0x50], u64::from(*live)))
                .collect();
            let record = UtxoRecord::from_owned_outputs(Hash256::default(), &outputs)?;
            let additions = [OutputParts::new(vout, value, script, coinbase, 1)];
            let RemovedRecord::Replaced(replacement) =
                record.edit_replacement(removes, &additions)?
            else {
                panic!("{name}: an edit with additions must be Replaced");
            };
            assert_eq!(
                replacement
                    .outputs()
                    .map(|out| (out.vout, out.value))
                    .collect::<Vec<_>>(),
                survivors,
                "{name}: survivors"
            );
            let added = replacement
                .find_output(vout)
                .ok_or(UtxoError::CorruptRecord)?;
            assert_eq!(added.script_pubkey, script, "{name}: script");
            assert_eq!(added.coinbase, coinbase, "{name}: coinbase");
        }

        // An add-only edit must stay byte-equal to the staged add path.
        let record = UtxoRecord::from_owned_outputs(
            Hash256::default(),
            &[output(0, &[0x50], 5), output(1, &[0x51], 6)],
        )?;
        let additions = [OutputParts::new(7, 77, &[0x77], false, 3)];
        let RemovedRecord::Replaced(edited) = record.edit_replacement(&[], &additions)? else {
            panic!("an add-only edit must produce a replacement");
        };
        assert_eq!(
            edited,
            UtxoRecord::add_run_replacement(Some(&record), record.txid(), &additions, false, None)?
        );
        Ok(())
    }

    /// Removing an inline output leaves `inline_len` below both the count and
    /// the partition capacity, where appends would have to rewrite the
    /// partition; the run must fall back to a rebuild and stay correct.
    #[test]
    fn add_with_an_unsaturated_inline_partition_falls_back_to_rebuild() -> Result<(), UtxoError> {
        let nine: Vec<OwnedUtxoOut> = (0..9)
            .map(|vout| output(vout, &[0x51], u64::from(vout)))
            .collect();
        let record = UtxoRecord::from_owned_outputs(Hash256::default(), &nine)?;
        let shrunk = match record.remove_run_replacement(&[0], None)? {
            RemovedRecord::Replaced(record) => record,
            _ => panic!("a partial removal must produce a replacement"),
        };
        assert_eq!(shrunk.output_count(), 8);
        assert_eq!(shrunk.header().inline_len, 7);
        let grown = UtxoRecord::add_run_replacement(
            Some(&shrunk),
            shrunk.txid(),
            &[OutputParts::new(9, 99, &[0x59], false, 2)],
            true,
            None,
        )?;
        assert_eq!(grown.output_count(), 9);
        for vout in 1..=9 {
            assert!(grown.find_output(vout).is_some(), "vout {vout} was lost");
        }
        assert!(grown.find_output(0).is_none());
        Ok(())
    }

    /// The fast-path guard itself: equal or decreasing vouts fail, strictly
    /// increasing runs after any seed pass.
    #[test]
    fn the_unique_add_guard_rejects_equal_and_decreasing_vouts() {
        assert!(vouts_are_strictly_increasing(None, [0]));
        assert!(vouts_are_strictly_increasing(Some(0), [1, 2]));
        assert!(vouts_are_strictly_increasing(Some(9), []));
        assert!(!vouts_are_strictly_increasing(Some(2), [2]));
        assert!(!vouts_are_strictly_increasing(None, [3, 3]));
        assert!(!vouts_are_strictly_increasing(None, [3, 1]));
    }

    // --- violation tests: state ---

    /// The record's boxed byte slice makes it `Send`/`Sync`: the sole owner
    /// may cross a thread boundary and stay decodable.
    #[test]
    fn a_record_moved_across_threads_stays_decodable() -> Result<(), UtxoError> {
        let record = UtxoRecord::from_owned_outputs(
            Hash256::default(),
            &[output(0, &[0x51], 1), output(3, &[0x53], 3)],
        )?;
        let txid = record.txid();
        let record = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    assert_eq!(record.output_count(), 2);
                    assert!(record.find_output(3).is_some());
                    record
                })
                .join()
                .unwrap_or_else(|_| panic!("record moved across threads must not panic"))
        });
        assert_eq!(record.txid(), txid);
        Ok(())
    }

    #[test]
    fn records_at_the_inline_partition_boundary_iterate_exactly() -> Result<(), UtxoError> {
        for count in [7_u32, 8, 9] {
            let outputs: Vec<OwnedUtxoOut> = (0..count)
                .map(|vout| {
                    output(
                        vout,
                        &[0x51, u8::try_from(vout).unwrap_or(0)],
                        u64::from(vout) * 10,
                    )
                })
                .collect();
            let record = UtxoRecord::from_owned_outputs(Hash256::default(), &outputs)?;
            assert_eq!(record.output_count(), usize::try_from(count).unwrap_or(0));
            let mut iter = record.outputs();
            assert_eq!(iter.len(), usize::try_from(count).unwrap_or(0));
            let decoded: Vec<u32> = iter.by_ref().map(|out| out.vout).collect();
            assert_eq!(decoded, (0..count).collect::<Vec<u32>>());
            assert_eq!(iter.len(), 0);
            assert!(iter.next().is_none());
            for vout in [0, count - 1, count] {
                assert_eq!(
                    record.find_output(vout).is_some(),
                    vout < count,
                    "boundary vout {vout} on a {count}-output record"
                );
            }
        }
        Ok(())
    }

    /// A failed non-unique add must leave the caller's overwrite sink
    /// untouched: the events are staged locally and reach the sink only after
    /// the replacement encodes. The oversized script fails the encode after
    /// the duplicate vout has already been merged.
    #[test]
    fn failed_non_unique_add_leaves_the_overwrite_sink_untouched() -> Result<(), UtxoError> {
        let existing = output(0, &[0x51], 10);
        let record =
            UtxoRecord::from_owned_outputs(Hash256::default(), std::slice::from_ref(&existing))?;
        let oversized = vec![0x51; usize::from(u16::MAX) + 1];
        let addition = OutputParts::new(0, 20, &oversized, false, 0);
        let mut overwritten = Vec::new();
        let result = UtxoRecord::add_run_replacement(
            Some(&record),
            Hash256::default(),
            &[addition],
            false,
            Some(&mut overwritten),
        );
        assert!(
            matches!(result, Err(UtxoError::ScriptTooLarge { .. })),
            "the oversized script must fail the encode"
        );
        assert!(
            overwritten.is_empty(),
            "a failed add must leave the overwrite sink untouched"
        );
        Ok(())
    }
}
