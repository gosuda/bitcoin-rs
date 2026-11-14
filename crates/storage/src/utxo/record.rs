use bitcoin_rs_consensus::primitives::Hash256;
use smallvec::SmallVec;
use std::sync::Arc;

use crate::utxo::{UtxoError, UtxoKey};

const TXID_LEN: usize = 32;
const OUTPUT_COUNT_OFFSET: usize = TXID_LEN;
const INLINE_LEN_OFFSET: usize = OUTPUT_COUNT_OFFSET + core::mem::size_of::<u32>();
const RECORD_HEADER_LEN: usize = INLINE_LEN_OFFSET + core::mem::size_of::<u8>();
const PAYLOAD_PROLOGUE_MAX_LEN: usize =
    crate::utxo::compress::VARINT_MAX_LEN + 8 + 5 + crate::utxo::compress::VARINT_MAX_LEN;

const WIDTHS_OFFSET: usize = RECORD_HEADER_LEN;
const V5_BODY_OFFSET: usize = WIDTHS_OFFSET + 1;
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

/// Discriminator bit on the inline_len byte (offset 36).
///
/// Invariant: byte 36 (`INLINE_LEN_OFFSET`) discriminates the record framing:
/// - If bit 7 (`0x80`) is 0: plain v5 snapshot framing. The byte directly encodes
///   `inline_len` in `0..=INLINE_CAPACITY` (`0..=8`).
/// - If bit 7 (`0x80`) is 1: b-value framing with Core-compressed txouts. The lower 7
///   bits (`byte & 0x7f`) encode `inline_len` in `0..=INLINE_CAPACITY` (`0..=8`).
/// - Any byte with `(byte & 0x7f) > INLINE_CAPACITY` or `(byte & 0x7f) > output_count`,
///   or any record with corrupted/forged discriminator or invalid Core script encoding,
///   is rejected with `CorruptRecord`.
pub const B_FRAMING_FLAG: u8 = 0x80;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecordFraming {
    V5Plain,
    B,
}

#[derive(Clone, Debug)]
pub(crate) struct DecompressedScripts {
    pub(crate) spans: Box<[(u32, u32)]>,
    pub(crate) data: Box<[u8]>,
}

const AMOUNT_ESCAPE: u64 = u64::MAX;

fn pack_height(height: u32, coinbase: bool) -> u64 {
    (u64::from(height) << 1) | u64::from(coinbase)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OneUtxoOut<'a> {
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: &'a [u8],
    pub coinbase: bool,
    pub height: u32,
}

#[derive(Clone, Debug)]
pub struct UtxoRecord {
    buf: Box<[u8]>,
    decompressed: Option<Arc<DecompressedScripts>>,
}

impl PartialEq for UtxoRecord {
    fn eq(&self, other: &Self) -> bool {
        self.txid() == other.txid()
            && self.output_count() == other.output_count()
            && self.outputs().eq(other.outputs())
    }
}

impl Eq for UtxoRecord {}

#[derive(Copy, Clone)]
struct RecordHeader {
    #[cfg(test)]
    txid: Hash256,
    #[cfg(not(test))]
    _txid: Hash256,
    output_count: usize,
    #[cfg(test)]
    inline_len: usize,
    #[cfg(not(test))]
    _inline_len: usize,
    framing: RecordFraming,
}

pub struct UtxoOutputIter<'a> {
    bytes: &'a [u8],
    layout: V5Layout,
    index: usize,
    payload: usize,
    framing: RecordFraming,
    decompressed: Option<&'a DecompressedScripts>,
}

impl<'a> Iterator for UtxoOutputIter<'a> {
    type Item = OneUtxoOut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.layout.count {
            return None;
        }
        let (output, next) = match decode_output_at(
            self.bytes,
            &self.layout,
            self.index,
            self.payload,
            self.framing,
            self.decompressed,
        ) {
            Ok(decoded) => decoded,
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
    pub fn from_encoded(buf: Box<[u8]>) -> Result<Self, UtxoError> {
        let (_header, decompressed) = validate_encoded(&buf)?;
        Ok(Self { buf, decompressed })
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    #[must_use]
    pub fn framing(&self) -> RecordFraming {
        self.header().framing
    }

    pub fn from_owned_outputs_with_framing(
        txid: Hash256,
        outputs: &[OwnedUtxoOut],
        framing: RecordFraming,
    ) -> Result<Self, UtxoError> {
        let buf = encode_record(
            txid,
            outputs.len().min(INLINE_CAPACITY),
            &owned_parts(outputs),
            framing,
        )?;
        Self::from_encoded(buf)
    }

    pub fn from_owned_outputs(txid: Hash256, outputs: &[OwnedUtxoOut]) -> Result<Self, UtxoError> {
        Self::from_owned_outputs_with_framing(txid, outputs, RecordFraming::B)
    }

    pub(crate) fn key(&self) -> UtxoKey {
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&self.bytes()[..8]);
        UtxoKey::from_prefix(prefix)
    }

    pub fn txid(&self) -> Hash256 {
        let mut txid = [0_u8; TXID_LEN];
        txid.copy_from_slice(&self.bytes()[..TXID_LEN]);
        Hash256::from_le_bytes(&txid)
    }

    pub fn is_empty(&self) -> bool {
        self.output_count() == 0
    }

    pub fn output_count(&self) -> usize {
        self.header().output_count
    }

    pub fn outputs(&self) -> UtxoOutputIter<'_> {
        let bytes = self.bytes();
        let layout = match self.layout() {
            Ok(layout) => layout,
            Err(error) => panic!("UtxoRecord is validated at construction: {error:?}"),
        };
        let framing = self.header().framing;
        UtxoOutputIter {
            bytes,
            layout,
            index: 0,
            payload: layout.payloads,
            framing,
            decompressed: self.decompressed.as_deref(),
        }
    }

    pub fn find_output(&self, vout: u32) -> Option<OneUtxoOut<'_>> {
        let bytes = self.bytes();
        let layout = self.layout().ok()?;
        let framing = self.header().framing;
        let index = (0..layout.count)
            .find(|index| layout.vout_at(bytes, *index).is_ok_and(|c| c == vout))?;
        let payload = payload_offset(bytes, &layout, index).ok()?;
        match decode_output_at(
            bytes,
            &layout,
            index,
            payload,
            framing,
            self.decompressed.as_deref(),
        ) {
            Ok((output, _)) => Some(output),
            Err(error) => panic!("validated UTXO record output must remain decodable: {error:?}"),
        }
    }

    pub fn max_vout(&self) -> Option<u32> {
        let bytes = self.bytes();
        let layout = self.layout().ok()?;
        (0..layout.count)
            .filter_map(|index| layout.vout_at(bytes, index).ok())
            .max()
    }

    #[cfg(test)]
    pub(crate) fn add_run_replacement<'p>(
        existing: Option<&Self>,
        txid: Hash256,
        additions: &'p [OutputParts<'p>],
        overwritten: Option<&mut Vec<Option<OwnedUtxoOut>>>,
    ) -> Result<Self, UtxoError> {
        if vouts_are_strictly_increasing(
            existing.and_then(Self::max_vout),
            additions.iter().map(|part| part.vout),
        ) {
            Self::append_run(existing, txid, additions, overwritten)
        } else {
            Self::overwrite_run(existing, txid, additions, overwritten)
        }
    }

    #[cfg(test)]
    fn append_run<'p>(
        existing: Option<&Self>,
        txid: Hash256,
        additions: &'p [OutputParts<'p>],
        overwritten: Option<&mut Vec<Option<OwnedUtxoOut>>>,
    ) -> Result<Self, UtxoError> {
        let framing = existing.map_or(RecordFraming::B, |r| r.framing());
        let appended = match existing {
            Some(record) => record.append_unique_run(additions)?,
            None => Some(Self::from_output_parts(
                txid,
                additions.len().min(INLINE_CAPACITY),
                additions,
                framing,
            )?),
        };
        if let Some(record) = appended {
            if let Some(sink) = overwritten {
                sink.resize(sink.len().saturating_add(additions.len()), None);
            }
            return Ok(record);
        }
        let (mut parts, mut inline_len) = match existing {
            Some(record) => (record.output_parts(), record.header().inline_len),
            None => (Vec::with_capacity(additions.len()), 0),
        };
        let mut staged = overwritten
            .is_some()
            .then(|| Vec::with_capacity(additions.len()));
        append_parts(&mut parts, &mut inline_len, additions, staged.as_mut());
        let record = Self::from_output_parts(txid, inline_len, &parts, framing)?;
        if let (Some(sink), Some(events)) = (overwritten, staged) {
            sink.extend(events);
        }
        Ok(record)
    }

    #[cfg(test)]
    fn overwrite_run<'p>(
        existing: Option<&Self>,
        txid: Hash256,
        additions: &'p [OutputParts<'p>],
        overwritten: Option<&mut Vec<Option<OwnedUtxoOut>>>,
    ) -> Result<Self, UtxoError> {
        let framing = existing.map_or(RecordFraming::B, |r| r.framing());
        let (mut parts, mut inline_len) = match existing {
            Some(record) => (record.output_parts(), record.header().inline_len),
            None => (Vec::with_capacity(additions.len()), 0),
        };
        let mut staged = overwritten
            .is_some()
            .then(|| Vec::with_capacity(additions.len()));
        overwrite_parts(&mut parts, &mut inline_len, additions, staged.as_mut());
        let record = Self::from_output_parts(txid, inline_len, &parts, framing)?;
        if let (Some(sink), Some(events)) = (overwritten, staged) {
            sink.extend(events);
        }
        Ok(record)
    }

    #[cfg(test)]
    fn append_unique_run(&self, additions: &[OutputParts<'_>]) -> Result<Option<Self>, UtxoError> {
        let header = self.header();
        let appends_at_end =
            header.output_count == header.inline_len || header.inline_len == INLINE_CAPACITY;
        if !appends_at_end {
            return Ok(None);
        }
        let old = self.layout()?;
        let bytes = self.bytes();
        let framing = header.framing;

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
        let inline_byte = match framing {
            RecordFraming::V5Plain => inline_len_u8,
            RecordFraming::B => inline_len_u8 | B_FRAMING_FLAG,
        };

        let mut additions_len = 0_usize;
        for addition in additions {
            let payload_len = addition.payload_len(framing)?;
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
        buf.push(inline_byte);
        buf.push(pack_widths(old.vout_width, old.len_width)?);

        buf.extend_from_slice(region(old.vout_dir, old.len_dir)?);
        for addition in additions {
            push_dir_entry(&mut buf, u64::from(addition.vout), old.vout_width)?;
        }
        buf.extend_from_slice(region(old.len_dir, old.payloads)?);
        for addition in additions {
            let len = u64::try_from(addition.payload_len(framing)?).unwrap_or(u64::MAX);
            push_dir_entry(&mut buf, len, old.len_width)?;
        }
        buf.extend_from_slice(region(old.payloads, bytes.len())?);
        for addition in additions {
            write_payload(&mut buf, addition, framing)?;
        }
        if buf.len() != payload_len {
            return Err(UtxoError::CorruptRecord);
        }
        Self::from_encoded(buf.into_boxed_slice()).map(Some)
    }

    #[cfg(test)]
    pub(crate) fn remove_run_replacement(
        &self,
        vouts: &[u32],
        mut removed: Option<&mut Vec<Option<OwnedUtxoOut>>>,
    ) -> Result<RemovedRecord, UtxoError> {
        let framing = self.framing();
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
            framing,
        )?))
    }

    #[cfg(test)]
    pub(crate) fn edit_replacement<'a>(
        &'a self,
        vouts: &[u32],
        additions: &'a [OutputParts<'a>],
    ) -> Result<RemovedRecord, UtxoError> {
        let framing = self.framing();
        if self.is_full_removal(vouts) {
            if additions.is_empty() {
                return Ok(RemovedRecord::Emptied);
            }
            let record = Self::from_output_parts(
                self.txid(),
                additions.len().min(INLINE_CAPACITY),
                additions,
                framing,
            )?;
            return Ok(RemovedRecord::Replaced(record));
        }
        let mut parts = self.output_parts();
        let mut inline_len = self.header().inline_len;
        let appends = vouts_are_strictly_increasing(
            parts.iter().map(|part| part.vout).max(),
            additions.iter().map(|part| part.vout),
        );
        for &vout in vouts {
            if let Some(index) = parts.iter().position(|part| part.vout == vout) {
                remove_part_at(&mut parts, &mut inline_len, index);
            }
        }
        if appends {
            append_parts(&mut parts, &mut inline_len, additions, None);
        } else {
            overwrite_parts(&mut parts, &mut inline_len, additions, None);
        }
        if parts.is_empty() {
            return Ok(RemovedRecord::Emptied);
        }
        let replacement = Self::from_output_parts(self.txid(), inline_len, &parts, framing)?;
        Ok(RemovedRecord::Replaced(replacement))
    }

    #[cfg(test)]
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
            Err(error) => panic!("UtxoRecord is validated at construction: {error:?}"),
        }
    }

    #[cfg(test)]
    fn output_parts(&self) -> Vec<OutputParts<'_>> {
        let mut parts = Vec::with_capacity(self.header().output_count);
        parts.extend(self.outputs().map(|output| OutputParts::from_view(&output)));
        parts
    }

    #[cfg(test)]
    fn from_output_parts(
        txid: Hash256,
        inline_len: usize,
        outputs: &[OutputParts<'_>],
        framing: RecordFraming,
    ) -> Result<Self, UtxoError> {
        let buf = encode_record(txid, inline_len, outputs, framing)?;
        Self::from_encoded(buf)
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

    #[cfg(test)]
    fn from_view(output: &OneUtxoOut<'a>) -> Self {
        Self::new(
            output.vout,
            output.value,
            output.script_pubkey,
            output.coinbase,
            output.height,
        )
    }

    #[cfg(test)]
    fn into_owned(self) -> OwnedUtxoOut {
        OwnedUtxoOut::new(
            self.vout,
            self.value,
            self.script.to_vec(),
            self.coinbase,
            self.height,
        )
    }

    fn payload_len(&self, framing: RecordFraming) -> Result<usize, UtxoError> {
        use crate::utxo::compress::varint_len;

        let script_len = self.script.len();
        u16::try_from(script_len).map_err(|_| UtxoError::ScriptTooLarge { len: script_len })?;
        let (amount, escaped) = amount_parts(self.value);
        let prologue = varint_len(amount)
            + usize::from(escaped) * core::mem::size_of::<u64>()
            + varint_len(pack_height(self.height, self.coinbase));

        match framing {
            RecordFraming::V5Plain => prologue
                .checked_add(script_len)
                .ok_or(UtxoError::RecordTooLarge { len: script_len }),
            RecordFraming::B => {
                let script_encoded_len = match crate::utxo::compress::compress_script(self.script) {
                    Some((tag, special_data)) => varint_len(tag) + special_data.len(),
                    None => {
                        let tag = u64::try_from(script_len)
                            .map_err(|_| UtxoError::CorruptRecord)?
                            .checked_add(crate::utxo::compress::SCRIPT_SPECIAL_SCRIPTS_COUNT)
                            .ok_or(UtxoError::CorruptRecord)?;
                        varint_len(tag) + script_len
                    }
                };
                prologue
                    .checked_add(script_encoded_len)
                    .ok_or(UtxoError::RecordTooLarge {
                        len: script_encoded_len,
                    })
            }
        }
    }
}

#[cfg(test)]
pub(crate) enum RemovedRecord {
    Unchanged,
    Emptied,
    Replaced(UtxoRecord),
}

fn owned_parts(outputs: &[OwnedUtxoOut]) -> Vec<OutputParts<'_>> {
    outputs.iter().map(OutputParts::from_owned).collect()
}

#[cfg(test)]
fn append_parts<'a>(
    parts: &mut Vec<OutputParts<'a>>,
    inline_len: &mut usize,
    additions: &[OutputParts<'a>],
    overwritten: Option<&mut Vec<Option<OwnedUtxoOut>>>,
) {
    for &addition in additions {
        debug_assert!(parts.iter().all(|part| part.vout != addition.vout));
        push_part(parts, inline_len, addition);
    }
    if let Some(sink) = overwritten {
        sink.extend(additions.iter().map(|_| None));
    }
}

#[cfg(test)]
fn overwrite_parts<'a>(
    parts: &mut Vec<OutputParts<'a>>,
    inline_len: &mut usize,
    additions: &[OutputParts<'a>],
    overwritten: Option<&mut Vec<Option<OwnedUtxoOut>>>,
) {
    let mut displaced = Vec::with_capacity(additions.len());
    for &addition in additions {
        let previous = parts
            .iter()
            .position(|part| part.vout == addition.vout)
            .map(|index| remove_part_at(parts, inline_len, index));
        push_part(parts, inline_len, addition);
        displaced.push(previous.map(OutputParts::into_owned));
    }
    if let Some(sink) = overwritten {
        sink.extend(displaced);
    }
}

#[cfg(test)]
fn push_part<'a>(parts: &mut Vec<OutputParts<'a>>, inline_len: &mut usize, part: OutputParts<'a>) {
    if *inline_len < INLINE_CAPACITY {
        parts.insert(*inline_len, part);
        *inline_len += 1;
    } else {
        parts.push(part);
    }
}

#[cfg(test)]
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

#[cfg(test)]
fn vouts_are_strictly_increasing(
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

fn encode_record(
    txid: Hash256,
    inline_len: usize,
    outputs: &[OutputParts<'_>],
    framing: RecordFraming,
) -> Result<Box<[u8]>, UtxoError> {
    let output_count = u32::try_from(outputs.len())
        .map_err(|_| UtxoError::RecordTooLarge { len: outputs.len() })?;
    if inline_len > INLINE_CAPACITY || inline_len > outputs.len() {
        return Err(UtxoError::CorruptRecord);
    }

    let mut payload_lens: SmallVec<[u32; 16]> = SmallVec::with_capacity(outputs.len());
    let mut payload_total = 0_usize;
    let mut max_vout = 0_u64;
    let mut max_len = 0_u64;
    for output in outputs {
        let len = output.payload_len(framing)?;
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
    let inline_byte = match framing {
        RecordFraming::V5Plain => inline_len_u8,
        RecordFraming::B => inline_len_u8 | B_FRAMING_FLAG,
    };

    let mut buf = Vec::with_capacity(payload_len);
    buf.extend_from_slice(&txid.to_le_bytes());
    buf.extend_from_slice(&output_count.to_le_bytes());
    buf.push(inline_byte);
    buf.push(pack_widths(vout_width, len_width)?);
    for output in outputs {
        push_dir_entry(&mut buf, u64::from(output.vout), vout_width)?;
    }
    for len in &payload_lens {
        push_dir_entry(&mut buf, u64::from(*len), len_width)?;
    }
    for output in outputs {
        write_payload(&mut buf, output, framing)?;
    }
    if buf.len() != payload_len {
        return Err(UtxoError::CorruptRecord);
    }
    Ok(buf.into_boxed_slice())
}

fn amount_parts(value: u64) -> (u64, bool) {
    match crate::utxo::compress::compress_amount(value) {
        Ok(compressed) => (compressed, false),
        Err(_) => (AMOUNT_ESCAPE, true),
    }
}

fn write_payload(
    buf: &mut Vec<u8>,
    output: &OutputParts<'_>,
    framing: RecordFraming,
) -> Result<(), UtxoError> {
    use crate::utxo::compress::write_varint_at;

    let script_len = output.script.len();
    u16::try_from(script_len).map_err(|_| UtxoError::ScriptTooLarge { len: script_len })?;
    let (amount, escaped) = amount_parts(output.value);

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

    match framing {
        RecordFraming::V5Plain => {
            buf.extend_from_slice(output.script);
        }
        RecordFraming::B => {
            let mut script_varint = [0_u8; crate::utxo::compress::VARINT_MAX_LEN];
            match crate::utxo::compress::compress_script(output.script) {
                Some((tag, special_data)) => {
                    let len = write_varint_at(tag, &mut script_varint, 0)
                        .ok_or(UtxoError::CorruptRecord)?;
                    buf.extend_from_slice(&script_varint[..len]);
                    buf.extend_from_slice(special_data);
                }
                None => {
                    let tag = u64::try_from(script_len)
                        .map_err(|_| UtxoError::CorruptRecord)?
                        .checked_add(crate::utxo::compress::SCRIPT_SPECIAL_SCRIPTS_COUNT)
                        .ok_or(UtxoError::CorruptRecord)?;
                    let len = write_varint_at(tag, &mut script_varint, 0)
                        .ok_or(UtxoError::CorruptRecord)?;
                    buf.extend_from_slice(&script_varint[..len]);
                    buf.extend_from_slice(output.script);
                }
            }
        }
    }
    Ok(())
}

fn validate_encoded(
    bytes: &[u8],
) -> Result<(RecordHeader, Option<Arc<DecompressedScripts>>), UtxoError> {
    let header = decode_header(bytes)?;
    let layout = V5Layout::read(bytes, header.output_count)?;
    let mut max_vout = 0_u64;
    let mut max_len = 0_u64;
    let mut cursor = layout.payloads;
    let mut seen = if layout.count > 16 {
        Some(hashbrown::HashSet::with_capacity(layout.count.min(1024)))
    } else {
        None
    };

    let mut spans = Vec::with_capacity(layout.count);
    let mut decompressed_data = Vec::new();
    let mut has_special_script = false;

    for index in 0..layout.count {
        let vout = layout.vout_at(bytes, index)?;
        if let Some(set) = seen.as_mut() {
            if !set.insert(vout) {
                return Err(UtxoError::CorruptRecord);
            }
        } else {
            for prior in 0..index {
                if layout.vout_at(bytes, prior)? == vout {
                    return Err(UtxoError::CorruptRecord);
                }
            }
        }
        max_vout = max_vout.max(u64::from(vout));
        let len = layout.payload_len_at(bytes, index)?;
        max_len = max_len.max(u64::try_from(len).unwrap_or(u64::MAX));

        let next = cursor.checked_add(len).ok_or(UtxoError::CorruptRecord)?;
        let body = bytes.get(cursor..next).ok_or(UtxoError::CorruptRecord)?;

        let parsed = parse_output_payload(body, header.framing)?;
        match parsed.script {
            EncodedScript::Plain(_) => {}
            EncodedScript::Core {
                tag,
                data: script_data,
            } => {
                let offset = decompressed_data.len();
                crate::utxo::compress::decompress_script_into(
                    tag,
                    script_data,
                    &mut decompressed_data,
                )?;
                let script_len = decompressed_data.len() - offset;
                u16::try_from(script_len).map_err(|_| UtxoError::CorruptRecord)?;
                spans.push((
                    u32::try_from(offset).map_err(|_| UtxoError::CorruptRecord)?,
                    u32::try_from(script_len).map_err(|_| UtxoError::CorruptRecord)?,
                ));
                if tag < crate::utxo::compress::SCRIPT_SPECIAL_SCRIPTS_COUNT {
                    has_special_script = true;
                }
            }
        }
        cursor = next;
    }
    if width_for(max_vout) != layout.vout_width || width_for(max_len) != layout.len_width {
        return Err(UtxoError::CorruptRecord);
    }
    if cursor != bytes.len() {
        return Err(UtxoError::CorruptRecord);
    }

    let decompressed = if has_special_script {
        Some(Arc::new(DecompressedScripts {
            spans: spans.into_boxed_slice(),
            data: decompressed_data.into_boxed_slice(),
        }))
    } else {
        None
    };

    Ok((header, decompressed))
}

fn decode_header(bytes: &[u8]) -> Result<RecordHeader, UtxoError> {
    let txid_bytes = bytes.get(..TXID_LEN).ok_or(UtxoError::CorruptRecord)?;
    let mut txid = [0_u8; TXID_LEN];
    txid.copy_from_slice(txid_bytes);
    let output_count =
        usize::try_from(read_u32(bytes, OUTPUT_COUNT_OFFSET).ok_or(UtxoError::CorruptRecord)?)
            .map_err(|_| UtxoError::RecordTooLarge { len: usize::MAX })?;
    let raw_inline = *bytes
        .get(INLINE_LEN_OFFSET)
        .ok_or(UtxoError::CorruptRecord)?;
    let framing = if raw_inline & B_FRAMING_FLAG != 0 {
        RecordFraming::B
    } else {
        RecordFraming::V5Plain
    };
    let inline_len = usize::from(raw_inline & 0x7f);
    if inline_len > INLINE_CAPACITY || inline_len > output_count {
        return Err(UtxoError::CorruptRecord);
    }
    Ok(RecordHeader {
        #[cfg(test)]
        txid: Hash256::from_le_bytes(&txid),
        #[cfg(not(test))]
        _txid: Hash256::from_le_bytes(&txid),
        output_count,
        #[cfg(test)]
        inline_len,
        #[cfg(not(test))]
        _inline_len: inline_len,
        framing,
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
    framing: RecordFraming,
    decompressed: Option<&'a DecompressedScripts>,
) -> Result<(OneUtxoOut<'a>, usize), UtxoError> {
    let vout = layout.vout_at(bytes, index)?;
    let len = layout.payload_len_at(bytes, index)?;
    let next = payload.checked_add(len).ok_or(UtxoError::CorruptRecord)?;
    let body = bytes.get(payload..next).ok_or(UtxoError::CorruptRecord)?;

    let parsed = parse_output_payload(body, framing)?;

    let script_pubkey: &'a [u8] = match decompressed {
        Some(dec) => {
            let &(offset, script_len) = dec.spans.get(index).ok_or(UtxoError::CorruptRecord)?;
            let offset_usize = usize::try_from(offset).map_err(|_| UtxoError::CorruptRecord)?;
            let len_usize = usize::try_from(script_len).map_err(|_| UtxoError::CorruptRecord)?;
            let end = offset_usize
                .checked_add(len_usize)
                .ok_or(UtxoError::CorruptRecord)?;
            dec.data
                .get(offset_usize..end)
                .ok_or(UtxoError::CorruptRecord)?
        }
        None => match parsed.script {
            EncodedScript::Plain(script) => script,
            EncodedScript::Core { tag, data }
                if tag >= crate::utxo::compress::SCRIPT_SPECIAL_SCRIPTS_COUNT =>
            {
                data
            }
            EncodedScript::Core { .. } => return Err(UtxoError::CorruptRecord),
        },
    };

    Ok((
        OneUtxoOut {
            vout,
            value: parsed.value,
            script_pubkey,
            coinbase: parsed.coinbase,
            height: parsed.height,
        },
        next,
    ))
}

enum EncodedScript<'a> {
    Plain(&'a [u8]),
    Core { tag: u64, data: &'a [u8] },
}

struct OutputPayload<'a> {
    value: u64,
    height: u32,
    coinbase: bool,
    script: EncodedScript<'a>,
}

fn parse_output_payload(
    body: &[u8],
    framing: RecordFraming,
) -> Result<OutputPayload<'_>, UtxoError> {
    let (amount, cursor) = crate::utxo::compress::read_varint(body, 0)?;
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
        if value <= crate::utxo::compress::MAX_COMPRESSIBLE_AMOUNT {
            return Err(UtxoError::CorruptRecord);
        }
        (value, end)
    } else {
        (
            crate::utxo::compress::decompress_amount(amount).ok_or(UtxoError::CorruptRecord)?,
            cursor,
        )
    };
    let (packed, cursor) = crate::utxo::compress::read_varint(body, cursor)?;
    let height = u32::try_from(packed >> 1).map_err(|_| UtxoError::CorruptRecord)?;
    let script = match framing {
        RecordFraming::V5Plain => {
            let script = body.get(cursor..).ok_or(UtxoError::CorruptRecord)?;
            u16::try_from(script.len()).map_err(|_| UtxoError::CorruptRecord)?;
            EncodedScript::Plain(script)
        }
        RecordFraming::B => {
            let (tag, cursor) = crate::utxo::compress::read_varint(body, cursor)?;
            let data = body.get(cursor..).ok_or(UtxoError::CorruptRecord)?;
            if tag >= crate::utxo::compress::SCRIPT_SPECIAL_SCRIPTS_COUNT {
                let raw_len =
                    usize::try_from(tag - crate::utxo::compress::SCRIPT_SPECIAL_SCRIPTS_COUNT)
                        .map_err(|_| UtxoError::CorruptRecord)?;
                u16::try_from(raw_len).map_err(|_| UtxoError::CorruptRecord)?;
                if raw_len != data.len() {
                    return Err(UtxoError::CorruptRecord);
                }
            }
            EncodedScript::Core { tag, data }
        }
    };
    Ok(OutputPayload {
        value,
        height,
        coinbase: packed & 1 == 1,
        script,
    })
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(core::mem::size_of::<u32>())?;
    let bytes = bytes.get(offset..end)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedUtxoOut {
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub coinbase: bool,
    pub height: u32,
}

impl OwnedUtxoOut {
    #[must_use]
    pub const fn new(
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
mod tests;
