//! Checked borrowed wire layout for blocks and transactions.
//!
//! This module is the sole owner of block and transaction wire parsing. Every
//! byte range it hands out is a [`ByteSpan`] that was bounds-checked against
//! one immutable byte image at parse time, and the `'a` borrow on
//! [`ParsedBlock`] and [`ParsedTransaction`] ties every offset to that image,
//! so a span can never outlive the bytes it indexes. Positions inside the
//! parsed metadata vectors use the distinct [`MetadataRange`] type, so byte
//! offsets and metadata indices can never be confused.
//!
//! Parsing establishes wire *shape* only: BIP144 marker/flag rules, canonical
//! compact-size lengths, and counts that could still fit in the remaining
//! bytes. Consensus acceptance (amounts, maturity, script validity, weight
//! limits) is deliberately not evaluated here; [`ParsedTransaction::materialize`]
//! hands the owned form to the callers that own those rules. Record counts
//! whose minimal serialized footprint already exceeds the remaining bytes are
//! rejected up front, so a malformed length can never drive an oversized
//! allocation or an out-of-bounds access.
//!
//! Span offsets are `u32` relative to the parsed image. File consumers widen
//! them to `u64` through [`ByteSpan::file_range`], which adds the image base
//! in checked `u64` arithmetic (the `u32`-to-`u64` file-offset discipline).
//! Lengths outside the representable span domain surface as an impossible
//! [`DecodeError::EndOfData`] requirement, following `read_script`'s
//! convention for lengths beyond `usize`.

use std::ops::Range;

use crate::{
    Block, DecodeError, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid,
    encode::{ConsensusDecode, read_array, read_i32_le, read_u32_le, read_u64_le},
    varint,
};

/// Serialized block header length in bytes.
const HEADER_LEN: u64 = 80;
/// Minimal serialized transaction: version, input count, output count, lock time.
const MIN_TX_LEN: u64 = 10;
/// Minimal serialized input: outpoint (36), script length prefix (1), sequence (4).
const MIN_INPUT_LEN: u64 = 41;
/// Minimal serialized output: value (8), script length prefix (1).
const MIN_OUTPUT_LEN: u64 = 9;
/// Minimal serialized witness stack item: its length prefix alone.
const MIN_WITNESS_ITEM_LEN: u64 = 1;
/// Fixed serialized input outpoint length: 32-byte txid plus 4-byte vout.
const OUTPOINT_LEN: u64 = 36;

/// A checked byte range within one parsed image.
///
/// Construction validates `start + len` in `u64` arithmetic against the image
/// limit before the range is ever used for slicing, so every [`ByteSpan`] is
/// in-bounds by construction. Offsets are `u32` relative to the image; widen
/// with [`ByteSpan::end`] or [`ByteSpan::file_range`] instead of storing
/// absolute file positions in `u32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteSpan {
    start: u32,
    len: u32,
}

impl ByteSpan {
    /// Constructs the span `[start, start + len)` against an image of `limit`
    /// bytes, rejecting ranges that leave the image, whose end overflows
    /// `u64`, or whose endpoints do not fit the `u32` span domain.
    fn checked(start: u64, len: u64, limit: u64) -> Result<Self, DecodeError> {
        let available = usize::try_from(limit.saturating_sub(start)).unwrap_or(usize::MAX);
        let end = start
            .checked_add(len)
            .ok_or_else(|| impossible(available))?;
        if end > limit {
            let shortfall = end - limit;
            return Err(DecodeError::EndOfData {
                needed: usize::try_from(shortfall).unwrap_or(usize::MAX),
                available,
            });
        }
        let start = u32::try_from(start).map_err(|_| impossible(available))?;
        let len = u32::try_from(len).map_err(|_| impossible(available))?;
        Ok(Self { start, len })
    }

    /// Offset of the first byte, relative to the owning image.
    #[must_use]
    pub const fn start(self) -> u32 {
        self.start
    }

    /// Number of bytes in the span.
    #[must_use]
    pub const fn len(self) -> u32 {
        self.len
    }

    /// Whether the span covers no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Offset one past the last byte, computed in `u64` (the sum of two
    /// `u32` offsets never overflows `u64`).
    #[must_use]
    pub fn end(self) -> u64 {
        u64::from(self.start) + u64::from(self.len)
    }

    /// The span as `u64` image-relative offsets.
    #[must_use]
    pub fn range_u64(self) -> Range<u64> {
        u64::from(self.start)..self.end()
    }

    /// Locates the span inside a segment file that starts at `base`,
    /// widening the `u32` image offset in checked `u64` arithmetic.
    ///
    /// Returns `None` when the addition would overflow `u64`; callers never
    /// silently wrap a file position.
    #[must_use]
    pub fn file_range(self, base: u64) -> Option<Range<u64>> {
        let start = u64::from(self.start).checked_add(base)?;
        let end = start.checked_add(u64::from(self.len))?;
        Some(start..end)
    }
}

/// A checked index range over one parsed metadata vector.
///
/// This is a record index, not a byte offset: it selects entries of vectors
/// such as [`ParsedTransaction::witness_spans`] and can never be mixed up
/// with a [`ByteSpan`] into the byte image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetadataRange {
    start: u32,
    end: u32,
}

impl MetadataRange {
    /// The empty range (legacy inputs carry no witness metadata).
    const EMPTY: Self = Self { start: 0, end: 0 };

    /// Constructs the record range `[start, end)` over a metadata vector of
    /// `limit` records, rejecting inverted, oversized, or unrepresentable
    /// ranges with the same impossible-requirement error as [`ByteSpan`].
    fn new(start: u64, end: u64, limit: u64) -> Result<Self, DecodeError> {
        let available = usize::try_from(limit.saturating_sub(start)).unwrap_or(usize::MAX);
        if end < start || end > limit {
            return Err(impossible(available));
        }
        let start = u32::try_from(start).map_err(|_| impossible(available))?;
        let end = u32::try_from(end).map_err(|_| impossible(available))?;
        Ok(Self { start, end })
    }

    /// Index of the first selected record.
    #[must_use]
    pub const fn start(self) -> u32 {
        self.start
    }

    /// Index one past the last selected record.
    #[must_use]
    pub const fn end(self) -> u32 {
        self.end
    }

    /// Number of selected records.
    #[must_use]
    pub const fn len(self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    /// Whether no records are selected.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.end == self.start
    }

    /// The record range as a `usize` half-open range for indexing vectors.
    #[must_use]
    pub fn as_range(self) -> Range<usize> {
        widen(self.start)..widen(self.end)
    }
}

/// Widens a span coordinate to `usize` for indexing.
///
/// Every target this crate builds for stores `usize` at least as wide as
/// `u32`, so the widening is total; the saturating fallback only satisfies
/// the workspace ban on `as` conversions and is unreachable in practice.
fn widen(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// The impossible byte requirement reported for lengths outside every
/// representable domain (`read_script` reports `usize::MAX` for lengths beyond
/// `usize` in exactly the same way).
fn impossible(available: usize) -> DecodeError {
    DecodeError::EndOfData {
        needed: usize::MAX,
        available,
    }
}

/// Widens a `usize` length into `u64`; slice and vector lengths always fit.
fn widening(len: usize) -> u64 {
    u64::try_from(len).unwrap_or_else(|_| unreachable!("usize length fits u64"))
}

/// Parse cursor over one immutable byte image: positions are `u64` and every
/// advance is bounds-checked before any slicing or reservation happens.
struct ImageCursor<'i> {
    image: &'i [u8],
    pos: u64,
}

impl ImageCursor<'_> {
    /// The image length in `u64`.
    fn limit(&self) -> u64 {
        widening(self.image.len())
    }

    /// Bytes from the cursor to the end of the image.
    fn remaining(&self) -> u64 {
        self.limit().saturating_sub(self.pos)
    }

    /// Consumes `len` bytes and returns their span, checking `offset + length`
    /// in `u64` against the image before the range is ever used.
    fn take(&mut self, len: u64) -> Result<ByteSpan, DecodeError> {
        let span = ByteSpan::checked(self.pos, len, self.limit())?;
        self.pos = span.end();
        Ok(span)
    }

    /// Reads one byte, returning it together with its span.
    fn read_u8(&mut self) -> Result<(u8, ByteSpan), DecodeError> {
        let span = self.take(1)?;
        let byte = self.image[widen(span.start())];
        Ok((byte, span))
    }

    /// Reads a compact-size integer, returning it with the span of its
    /// encoding; non-canonical and truncated lengths are rejected by the
    /// varint codec.
    fn read_compact(&mut self) -> Result<(u64, ByteSpan), DecodeError> {
        let offset = usize::try_from(self.pos)
            .unwrap_or_else(|_| unreachable!("cursor stays within its image"));
        let (value, consumed) =
            varint::decode(&self.image[offset..]).map_err(DecodeError::Varint)?;
        let span = ByteSpan::checked(self.pos, widening(consumed), self.limit())?;
        self.pos = span.end();
        Ok((value, span))
    }

    /// Rejects a record count whose minimal serialized footprint already
    /// exceeds the remaining bytes, before any per-record parsing or vector
    /// growth begins.
    fn require_count(&self, count: u64, min_item_len: u64) -> Result<(), DecodeError> {
        let min_needed = min_item_len.saturating_mul(count);
        let remaining = self.remaining();
        if min_needed > remaining {
            return Err(DecodeError::EndOfData {
                needed: usize::try_from(min_needed - remaining).unwrap_or(usize::MAX),
                available: usize::try_from(remaining).unwrap_or(usize::MAX),
            });
        }
        Ok(())
    }
}

/// Slices a span out of `image`; spans are constructed only against the image
/// they index, so the fallbacks are unreachable.
fn slice_at(image: &[u8], span: ByteSpan) -> &[u8] {
    let start = widen(span.start());
    let end = usize::try_from(span.end())
        .unwrap_or_else(|_| unreachable!("span end stays within its image"));
    image
        .get(start..end)
        .unwrap_or_else(|| unreachable!("span was checked against this image"))
}

/// Wire layout of one transaction input: byte spans into the owning image
/// plus the metadata index range of its witness stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputLayout {
    outpoint: ByteSpan,
    script_sig: ByteSpan,
    sequence: ByteSpan,
    witness: MetadataRange,
}

impl InputLayout {
    /// Span of the 36-byte outpoint: txid then vout, both little-endian.
    #[must_use]
    pub const fn outpoint(&self) -> ByteSpan {
        self.outpoint
    }

    /// Span of the scriptSig contents (without the length prefix).
    #[must_use]
    pub const fn script_sig(&self) -> ByteSpan {
        self.script_sig
    }

    /// Span of the 4-byte sequence number.
    #[must_use]
    pub const fn sequence(&self) -> ByteSpan {
        self.sequence
    }

    /// Index range of this input's witness stack items within
    /// [`ParsedTransaction::witness_spans`]; empty for legacy inputs.
    #[must_use]
    pub const fn witness(&self) -> MetadataRange {
        self.witness
    }
}

/// Wire layout of one transaction output: byte spans into the owning image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputLayout {
    value: ByteSpan,
    script_pubkey: ByteSpan,
}

impl OutputLayout {
    /// Span of the 8-byte little-endian value.
    #[must_use]
    pub const fn value(&self) -> ByteSpan {
        self.value
    }

    /// Span of the scriptPubKey contents (without the length prefix).
    #[must_use]
    pub const fn script_pubkey(&self) -> ByteSpan {
        self.script_pubkey
    }
}

/// A transaction parsed into checked borrowed spans over one immutable byte
/// image.
///
/// The struct borrows the image (`'a`), so every span it exposes is valid
/// exactly as long as the bytes it indexes. Parsing validates wire shape and
/// BIP144 encoding rules only; consensus acceptance is a separate concern of
/// the owned form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTransaction<'a> {
    /// The immutable byte owner every span indexes into.
    bytes: &'a [u8],
    /// Span of the complete transaction serialization.
    span: ByteSpan,
    version_span: ByteSpan,
    input_count_span: ByteSpan,
    output_count_span: ByteSpan,
    lock_time_span: ByteSpan,
    /// Whether the BIP144 marker/flag was present in the wire encoding.
    segwit: bool,
    inputs: Vec<InputLayout>,
    outputs: Vec<OutputLayout>,
    /// Witness stack item spans, concatenated across inputs in input order;
    /// each input's [`InputLayout::witness`] selects its slice of this vector.
    witness_spans: Vec<ByteSpan>,
}

impl<'a> ParsedTransaction<'a> {
    /// Parses one transaction from the front of `reader`, advancing `reader`
    /// past exactly the consumed bytes.
    pub fn parse(reader: &mut &'a [u8]) -> Result<Self, DecodeError> {
        let image = *reader;
        let mut cursor = 0_u64;
        let parsed = Self::parse_at(image, &mut cursor)?;
        let consumed = usize::try_from(cursor)
            .unwrap_or_else(|_| unreachable!("cursor stays within its image"));
        *reader = &image[consumed..];
        Ok(parsed)
    }

    /// Parses one transaction that must occupy exactly `bytes`; trailing
    /// bytes are a typed error.
    pub fn parse_exact(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut cursor = 0_u64;
        let parsed = Self::parse_at(bytes, &mut cursor)?;
        let consumed = usize::try_from(cursor)
            .unwrap_or_else(|_| unreachable!("cursor stays within its image"));
        if consumed != bytes.len() {
            return Err(DecodeError::TrailingBytes {
                remaining: bytes.len() - consumed,
            });
        }
        Ok(parsed)
    }

    /// Parses one transaction starting at `*cursor` inside `image` and
    /// advances `*cursor` past it; spans are absolute offsets into `image`.
    fn parse_at(image: &'a [u8], cursor: &mut u64) -> Result<Self, DecodeError> {
        let mut cur = ImageCursor {
            image,
            pos: *cursor,
        };
        let tx_start = cur.pos;

        let version_span = cur.take(4)?;
        let (mut input_count_value, mut input_count_span) = cur.read_compact()?;
        let mut segwit = false;
        if input_count_value == 0 {
            // BIP144: a zero input count is the segwit marker; the flag byte
            // must be exactly 0x01.
            let (flag, _flag_span) = cur.read_u8()?;
            if flag != 0x01 {
                return Err(DecodeError::InvalidSegwitFlag { got: flag });
            }
            segwit = true;
            let (count, span) = cur.read_compact()?;
            input_count_value = count;
            input_count_span = span;
        }
        cur.require_count(input_count_value, MIN_INPUT_LEN)?;

        let mut inputs = Vec::new();
        for _ in 0..input_count_value {
            let outpoint = cur.take(OUTPOINT_LEN)?;
            let (script_len, _len_span) = cur.read_compact()?;
            let script_sig = cur.take(script_len)?;
            let sequence = cur.take(4)?;
            inputs.push(InputLayout {
                outpoint,
                script_sig,
                sequence,
                witness: MetadataRange::EMPTY,
            });
        }

        let (output_count_value, output_count_span) = cur.read_compact()?;
        cur.require_count(output_count_value, MIN_OUTPUT_LEN)?;
        let mut outputs = Vec::new();
        for _ in 0..output_count_value {
            let value = cur.take(8)?;
            let (script_len, _len_span) = cur.read_compact()?;
            let script_pubkey = cur.take(script_len)?;
            outputs.push(OutputLayout {
                value,
                script_pubkey,
            });
        }

        let mut witness_spans = Vec::new();
        if segwit {
            for input in &mut inputs {
                let (item_count, _count_span) = cur.read_compact()?;
                cur.require_count(item_count, MIN_WITNESS_ITEM_LEN)?;
                let first = widening(witness_spans.len());
                for _ in 0..item_count {
                    let (item_len, _len_span) = cur.read_compact()?;
                    let item = cur.take(item_len)?;
                    witness_spans.push(item);
                }
                let limit = widening(witness_spans.len());
                input.witness = MetadataRange::new(first, limit, limit)?;
            }
            // BIP144 round-trip rule, checked at the same position as both
            // oracles (before the lock time): the marker/flag exists only to
            // carry witness data, so an all-empty witness section can never
            // re-encode byte-identically and is not a parseable shape.
            if inputs.iter().all(|input| input.witness.is_empty()) {
                return Err(DecodeError::SuperfluousWitness);
            }
        }

        let lock_time_span = cur.take(4)?;
        let tx_len = cur.pos.checked_sub(tx_start).ok_or_else(|| impossible(0))?;
        let span = ByteSpan::checked(tx_start, tx_len, cur.limit())?;
        *cursor = cur.pos;

        Ok(Self {
            bytes: image,
            span,
            version_span,
            input_count_span,
            output_count_span,
            lock_time_span,
            segwit,
            inputs,
            outputs,
            witness_spans,
        })
    }

    /// Span of the complete transaction serialization.
    #[must_use]
    pub const fn span(&self) -> ByteSpan {
        self.span
    }

    /// The immutable byte image every span indexes into.
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Span of the 4-byte version field.
    #[must_use]
    pub const fn version_span(&self) -> ByteSpan {
        self.version_span
    }

    /// Span of the input-count compact-size encoding.
    #[must_use]
    pub const fn input_count_span(&self) -> ByteSpan {
        self.input_count_span
    }

    /// Span of the output-count compact-size encoding.
    #[must_use]
    pub const fn output_count_span(&self) -> ByteSpan {
        self.output_count_span
    }

    /// Span of the 4-byte lock time.
    #[must_use]
    pub const fn lock_time_span(&self) -> ByteSpan {
        self.lock_time_span
    }

    /// Whether the BIP144 marker/flag was present in the wire encoding. For
    /// every parseable encoding this coincides with witness data being
    /// present, because an all-empty witness section is rejected as
    /// superfluous.
    #[must_use]
    pub const fn is_segwit(&self) -> bool {
        self.segwit
    }

    /// Parsed input layouts in wire order.
    #[must_use]
    pub fn inputs(&self) -> &[InputLayout] {
        &self.inputs
    }

    /// Parsed output layouts in wire order.
    #[must_use]
    pub fn outputs(&self) -> &[OutputLayout] {
        &self.outputs
    }

    /// Number of inputs.
    #[must_use]
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Number of outputs.
    #[must_use]
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Witness stack item spans concatenated across inputs; each input's
    /// [`InputLayout::witness`] selects its slice.
    #[must_use]
    pub fn witness_spans(&self) -> &[ByteSpan] {
        &self.witness_spans
    }

    /// Bytes this transaction occupies inside the owning image.
    #[must_use]
    pub fn consumed_len(&self) -> usize {
        widen(self.span.len())
    }

    /// Slices `span` out of the owning image.
    ///
    /// Returns `None` only when `span` was taken from a different image; a
    /// span produced by this parse always resolves.
    #[must_use]
    pub fn span_bytes(&self, span: ByteSpan) -> Option<&'a [u8]> {
        let start = widen(span.start());
        let end = usize::try_from(span.end()).ok()?;
        self.bytes.get(start..end)
    }

    /// Materializes the owned transaction from the validated spans.
    ///
    /// Infallible: every span was bounds-checked at parse time, so the scalar
    /// re-reads cannot fail.
    #[must_use]
    pub fn materialize(&self) -> Tx {
        let mut version_reader = slice_at(self.bytes, self.version_span);
        let version = read_i32_le(&mut version_reader)
            .unwrap_or_else(|_| unreachable!("validated version span"));
        let mut lock_time_reader = slice_at(self.bytes, self.lock_time_span);
        let lock_time = read_u32_le(&mut lock_time_reader)
            .unwrap_or_else(|_| unreachable!("validated lock-time span"));

        let inputs = self
            .inputs
            .iter()
            .map(|layout| {
                let mut outpoint_reader = slice_at(self.bytes, layout.outpoint);
                let txid = Txid(Hash256::from_le_bytes(
                    &read_array::<32>(&mut outpoint_reader)
                        .unwrap_or_else(|_| unreachable!("validated outpoint span")),
                ));
                let vout = read_u32_le(&mut outpoint_reader)
                    .unwrap_or_else(|_| unreachable!("validated outpoint span"));
                let mut sequence_reader = slice_at(self.bytes, layout.sequence);
                TxIn {
                    previous_output: OutPoint::new(txid, vout),
                    script_sig: slice_at(self.bytes, layout.script_sig).to_vec(),
                    sequence: read_u32_le(&mut sequence_reader)
                        .unwrap_or_else(|_| unreachable!("validated sequence span")),
                    witness: layout
                        .witness
                        .as_range()
                        .map(|index| slice_at(self.bytes, self.witness_spans[index]).to_vec())
                        .collect(),
                }
            })
            .collect();

        let outputs = self
            .outputs
            .iter()
            .map(|layout| {
                let mut value_reader = slice_at(self.bytes, layout.value);
                TxOut {
                    value: read_u64_le(&mut value_reader)
                        .unwrap_or_else(|_| unreachable!("validated value span")),
                    script_pubkey: slice_at(self.bytes, layout.script_pubkey).to_vec(),
                }
            })
            .collect();

        Tx {
            version,
            inputs,
            outputs,
            lock_time,
        }
    }
}

/// A block parsed into checked borrowed spans over one immutable byte image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedBlock<'a> {
    /// The immutable byte owner every span indexes into.
    bytes: &'a [u8],
    header_span: ByteSpan,
    tx_count_span: ByteSpan,
    tx_spans: Vec<ByteSpan>,
    txs: Vec<ParsedTransaction<'a>>,
    /// Absolute end of the parsed structure inside the image.
    consumed: u64,
}

impl<'a> ParsedBlock<'a> {
    /// Parses one block from the front of `reader`, advancing `reader` past
    /// exactly the consumed bytes.
    pub fn parse(reader: &mut &'a [u8]) -> Result<Self, DecodeError> {
        let image = *reader;
        let mut cursor = 0_u64;
        let parsed = Self::parse_at(image, &mut cursor)?;
        let consumed = usize::try_from(cursor)
            .unwrap_or_else(|_| unreachable!("cursor stays within its image"));
        *reader = &image[consumed..];
        Ok(parsed)
    }

    /// Parses one block that must occupy exactly `bytes`; trailing bytes are
    /// a typed error.
    pub fn parse_exact(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut cursor = 0_u64;
        let parsed = Self::parse_at(bytes, &mut cursor)?;
        let consumed = usize::try_from(cursor)
            .unwrap_or_else(|_| unreachable!("cursor stays within its image"));
        if consumed != bytes.len() {
            return Err(DecodeError::TrailingBytes {
                remaining: bytes.len() - consumed,
            });
        }
        Ok(parsed)
    }

    /// Parses one block starting at `*cursor` inside `image` and advances
    /// `*cursor` past it; all spans are absolute offsets into `image`.
    fn parse_at(image: &'a [u8], cursor: &mut u64) -> Result<Self, DecodeError> {
        let mut cur = ImageCursor {
            image,
            pos: *cursor,
        };
        let header_span = cur.take(HEADER_LEN)?;
        let (tx_count_value, tx_count_span) = cur.read_compact()?;
        cur.require_count(tx_count_value, MIN_TX_LEN)?;

        let mut tx_spans = Vec::new();
        let mut txs = Vec::new();
        for _ in 0..tx_count_value {
            let tx = ParsedTransaction::parse_at(image, &mut cur.pos)?;
            tx_spans.push(tx.span());
            txs.push(tx);
        }
        let consumed = cur.pos;
        *cursor = consumed;

        Ok(Self {
            bytes: image,
            header_span,
            tx_count_span,
            tx_spans,
            txs,
            consumed,
        })
    }

    /// Span of the 80-byte block header.
    #[must_use]
    pub const fn header_span(&self) -> ByteSpan {
        self.header_span
    }

    /// Span of the transaction-count compact-size encoding.
    #[must_use]
    pub const fn tx_count_span(&self) -> ByteSpan {
        self.tx_count_span
    }

    /// Number of transactions.
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.txs.len()
    }

    /// Span of every transaction, in block order.
    #[must_use]
    pub fn transaction_spans(&self) -> &[ByteSpan] {
        &self.tx_spans
    }

    /// Parsed transactions in block order, sharing this block's byte image.
    #[must_use]
    pub fn transactions(&self) -> &[ParsedTransaction<'a>] {
        &self.txs
    }

    /// The transaction at `index`, if present.
    #[must_use]
    pub fn transaction(&self, index: usize) -> Option<&ParsedTransaction<'a>> {
        self.txs.get(index)
    }

    /// The immutable byte image every span indexes into.
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Bytes this block occupies inside the owning image.
    #[must_use]
    pub fn consumed_len(&self) -> usize {
        usize::try_from(self.consumed)
            .unwrap_or_else(|_| unreachable!("consumed stays within the image"))
    }

    /// Slices `span` out of the owning image.
    ///
    /// Returns `None` only when `span` was taken from a different image; a
    /// span produced by this parse always resolves.
    #[must_use]
    pub fn span_bytes(&self, span: ByteSpan) -> Option<&'a [u8]> {
        let start = widen(span.start());
        let end = usize::try_from(span.end()).ok()?;
        self.bytes.get(start..end)
    }

    /// Materializes the owned block from the validated spans.
    ///
    /// Infallible: every span was bounds-checked at parse time.
    #[must_use]
    pub fn materialize(&self) -> Block {
        let mut header_reader = slice_at(self.bytes, self.header_span);
        let header = <Header as ConsensusDecode>::consensus_decode(&mut header_reader)
            .unwrap_or_else(|_| unreachable!("validated header span"));
        Block {
            header,
            txs: self
                .txs
                .iter()
                .map(ParsedTransaction::materialize)
                .collect(),
        }
    }
}
