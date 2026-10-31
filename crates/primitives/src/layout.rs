//! Checked borrowed wire layout for blocks and transactions.

use sha2::{Digest, Sha256};

use crate::{
    Amount, Block, DecodeError, Hash256, Header, LockTime, OutPoint, Script, Sequence, Tx, TxIn,
    TxOut, Txid, Witness,
    encode::{
        ConsensusDecode, double_sha256, finalize_double_sha256, read_array, read_u32_le,
        read_u64_le,
    },
    varint,
};

#[expect(
    clippy::as_conversions,
    reason = "the fixed 80-byte header fits in u64"
)]
const HEADER_LEN: u64 = Header::LEN as u64;
/// Wire bytes every element of a kind consumes outside the bytes of the elements it contains.
const MIN_TX_LEN: usize = 10;
const MIN_INPUT_LEN: usize = 41;
const MIN_OUTPUT_LEN: usize = 9;
const MIN_WITNESS_ITEM_LEN: usize = 1;
const MIN_SCRIPT_BYTE_LEN: usize = 1;

const TX_DECODE_BYTES: usize = core::mem::size_of::<ParsedTransaction<'static>>()
    + core::mem::size_of::<ByteSpan>()
    + core::mem::size_of::<Tx>();
const INPUT_DECODE_BYTES: usize =
    core::mem::size_of::<InputLayout>() + core::mem::size_of::<TxIn>();
const OUTPUT_DECODE_BYTES: usize =
    core::mem::size_of::<OutputLayout>() + core::mem::size_of::<TxOut>();
const WITNESS_ITEM_DECODE_BYTES: usize = core::mem::size_of::<u32>();
const SCRIPT_BYTE_DECODE_BYTES: usize = 1;

const fn larger(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}

/// Upper bound on decode heap, in multiples of the wire length, over every element kind.
const DECODE_EXPANSION: usize = larger(
    larger(
        TX_DECODE_BYTES.div_ceil(MIN_TX_LEN),
        INPUT_DECODE_BYTES.div_ceil(MIN_INPUT_LEN),
    ),
    larger(
        larger(
            OUTPUT_DECODE_BYTES.div_ceil(MIN_OUTPUT_LEN),
            WITNESS_ITEM_DECODE_BYTES.div_ceil(MIN_WITNESS_ITEM_LEN),
        ),
        SCRIPT_BYTE_DECODE_BYTES.div_ceil(MIN_SCRIPT_BYTE_LEN),
    ),
);

/// Bytes a decoder may hold live for `wire_len` wire bytes.
///
/// The bound covers the wire image, the parse scratch and the materialized block. Each element
/// kind spends at least its exclusive minimum of wire bytes, and those bytes are disjoint, so the
/// per-element factors never double count.
#[must_use]
pub const fn decode_reservation(wire_len: usize) -> usize {
    wire_len.saturating_mul(1 + DECODE_EXPANSION)
}
/// Fixed serialized input outpoint length: 32-byte txid plus 4-byte vout.
const OUTPOINT_LEN: u64 = 36;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteSpan {
    start: u32,
    len: u32,
}

#[cfg(kani)]
mod proofs;
#[cfg(test)]
mod tests;

impl ByteSpan {
    const EMPTY: Self = Self { start: 0, len: 0 };

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

    #[must_use]
    pub const fn start(self) -> u32 {
        self.start
    }

    #[must_use]
    pub const fn len(self) -> u32 {
        self.len
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub fn end(self) -> u64 {
        u64::from(self.start) + u64::from(self.len)
    }
}

fn widen(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn impossible(available: usize) -> DecodeError {
    DecodeError::EndOfData {
        needed: usize::MAX,
        available,
    }
}

fn count_capacity(count: u64) -> usize {
    usize::try_from(count).unwrap_or(usize::MAX)
}

fn widening(len: usize) -> u64 {
    u64::try_from(len).unwrap_or_else(|_| unreachable!("usize length fits u64"))
}

struct ImageCursor<'i> {
    image: &'i [u8],
    pos: u64,
}

impl ImageCursor<'_> {
    fn limit(&self) -> u64 {
        widening(self.image.len())
    }

    fn remaining(&self) -> u64 {
        self.limit().saturating_sub(self.pos)
    }

    fn take(&mut self, len: u64) -> Result<ByteSpan, DecodeError> {
        let span = ByteSpan::checked(self.pos, len, self.limit())?;
        self.pos = span.end();
        Ok(span)
    }

    fn read_u8(&mut self) -> Result<(u8, ByteSpan), DecodeError> {
        let span = self.take(1)?;
        let byte = self.image[widen(span.start())];
        Ok((byte, span))
    }

    fn read_compact(&mut self) -> Result<(u64, ByteSpan), DecodeError> {
        let offset = usize::try_from(self.pos)
            .unwrap_or_else(|_| unreachable!("cursor stays within its image"));
        let (value, consumed) =
            varint::decode(&self.image[offset..]).map_err(DecodeError::Varint)?;
        let span = ByteSpan::checked(self.pos, widening(consumed), self.limit())?;
        self.pos = span.end();
        Ok((value, span))
    }

    fn require_count(&self, count: u64, min_item_len: usize) -> Result<(), DecodeError> {
        let min_needed = widening(min_item_len).saturating_mul(count);
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

fn slice_at(image: &[u8], span: ByteSpan) -> &[u8] {
    let start = widen(span.start());
    let end = usize::try_from(span.end())
        .unwrap_or_else(|_| unreachable!("span end stays within its image"));
    image
        .get(start..end)
        .unwrap_or_else(|| unreachable!("span was checked against this image"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputLayout {
    outpoint: ByteSpan,
    script_sig: ByteSpan,
    sequence: ByteSpan,
    witness: ByteSpan,
    witness_items: u32,
}

impl InputLayout {
    /// Span of the 36-byte outpoint: txid then vout, both little-endian.
    #[must_use]
    pub const fn outpoint(&self) -> ByteSpan {
        self.outpoint
    }

    #[must_use]
    pub const fn script_sig(&self) -> ByteSpan {
        self.script_sig
    }

    /// Span of the witness item region: every item's length prefix and bytes, after the item count.
    #[must_use]
    pub const fn witness(&self) -> ByteSpan {
        self.witness
    }

    #[must_use]
    pub const fn witness_items(&self) -> u32 {
        self.witness_items
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputLayout {
    value: ByteSpan,
    script_pubkey: ByteSpan,
}

impl OutputLayout {
    #[must_use]
    pub const fn script_pubkey(&self) -> ByteSpan {
        self.script_pubkey
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTransaction<'a> {
    bytes: &'a [u8],
    span: ByteSpan,
    version_span: ByteSpan,
    input_count_span: ByteSpan,
    output_count_span: ByteSpan,
    lock_time_span: ByteSpan,
    /// Whether the BIP144 marker/flag was present in the wire encoding.
    segwit: bool,
    inputs: Vec<InputLayout>,
    outputs: Vec<OutputLayout>,
}

impl<'a> ParsedTransaction<'a> {
    pub(crate) fn parse(reader: &mut &'a [u8]) -> Result<Self, DecodeError> {
        let image = *reader;
        let mut cursor = 0_u64;
        let parsed = Self::parse_at(image, &mut cursor)?;
        let consumed = usize::try_from(cursor)
            .unwrap_or_else(|_| unreachable!("cursor stays within its image"));
        *reader = &image[consumed..];
        Ok(parsed)
    }

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

    fn parse_at(image: &'a [u8], cursor: &mut u64) -> Result<Self, DecodeError> {
        let mut cur = ImageCursor {
            image,
            pos: *cursor,
        };
        let tx_start = cur.pos;

        let version_span = cur.take(4)?;
        let (mut input_count_value, mut input_count_span) = cur.read_compact()?;
        let mut output_count_override: Option<(u64, ByteSpan)> = None;
        let mut segwit = false;
        if input_count_value == 0 {
            let (flag, flag_span) = cur.read_u8()?;
            if flag == 0 {
                output_count_override = Some((0, flag_span));
            } else if flag == 0x01 {
                segwit = true;
                let (count, span) = cur.read_compact()?;
                input_count_value = count;
                input_count_span = span;
            } else {
                return Err(DecodeError::InvalidSegwitFlag { got: flag });
            }
        }
        cur.require_count(input_count_value, MIN_INPUT_LEN)?;

        let mut inputs = Vec::with_capacity(count_capacity(input_count_value));
        for _ in 0..input_count_value {
            let outpoint = cur.take(OUTPOINT_LEN)?;
            let (script_len, _len_span) = cur.read_compact()?;
            let script_sig = cur.take(script_len)?;
            let sequence = cur.take(4)?;
            inputs.push(InputLayout {
                outpoint,
                script_sig,
                sequence,
                witness: ByteSpan::EMPTY,
                witness_items: 0,
            });
        }

        let (output_count_value, output_count_span) = match output_count_override {
            Some(pair) => pair,
            None => cur.read_compact()?,
        };
        cur.require_count(output_count_value, MIN_OUTPUT_LEN)?;
        let mut outputs = Vec::with_capacity(count_capacity(output_count_value));
        for _ in 0..output_count_value {
            let value = cur.take(8)?;
            let (script_len, _len_span) = cur.read_compact()?;
            let script_pubkey = cur.take(script_len)?;
            outputs.push(OutputLayout {
                value,
                script_pubkey,
            });
        }

        if segwit {
            for input in &mut inputs {
                let (item_count, _count_span) = cur.read_compact()?;
                cur.require_count(item_count, MIN_WITNESS_ITEM_LEN)?;
                let region_start = cur.pos;
                for _ in 0..item_count {
                    let (item_len, _len_span) = cur.read_compact()?;
                    cur.take(item_len)?;
                }
                input.witness =
                    ByteSpan::checked(region_start, cur.pos - region_start, cur.limit())?;
                input.witness_items = u32::try_from(item_count).map_err(|_| impossible(0))?;
            }
            if inputs.iter().all(|input| input.witness_items == 0) {
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
        })
    }

    #[must_use]
    pub const fn span(&self) -> ByteSpan {
        self.span
    }

    #[must_use]
    pub const fn is_segwit(&self) -> bool {
        self.segwit
    }

    #[must_use]
    pub fn inputs(&self) -> &[InputLayout] {
        &self.inputs
    }

    #[must_use]
    pub fn outputs(&self) -> &[OutputLayout] {
        &self.outputs
    }

    /// Spans of the items of one input's witness, in order. The region was validated at parse time.
    pub fn witness_item_spans(&self, input: usize) -> impl Iterator<Item = ByteSpan> + '_ {
        let layout = self.inputs.get(input);
        let (region, items) = layout.map_or((ByteSpan::EMPTY, 0), |layout| {
            (layout.witness, layout.witness_items)
        });
        let mut cursor = ImageCursor {
            image: self.bytes,
            pos: u64::from(region.start()),
        };
        (0..items).map(move |_| {
            let (len, _len_span) = cursor
                .read_compact()
                .unwrap_or_else(|_| unreachable!("witness region was validated at parse time"));
            cursor
                .take(len)
                .unwrap_or_else(|_| unreachable!("witness region was validated at parse time"))
        })
    }

    /// Heap bytes held by this parse itself, which is transient scratch beside the wire image.
    #[must_use]
    pub fn scratch_heap_bytes(&self) -> usize {
        self.inputs
            .capacity()
            .saturating_mul(core::mem::size_of::<InputLayout>())
            .saturating_add(
                self.outputs
                    .capacity()
                    .saturating_mul(core::mem::size_of::<OutputLayout>()),
            )
    }

    #[must_use]
    pub fn consumed_len(&self) -> usize {
        widen(self.span.len())
    }

    #[must_use]
    pub fn span_bytes(&self, span: ByteSpan) -> Option<&'a [u8]> {
        let start = widen(span.start());
        let end = usize::try_from(span.end()).ok()?;
        self.bytes.get(start..end)
    }

    #[must_use]
    pub fn txid(&self) -> Txid {
        if !self.segwit {
            return Txid(double_sha256(slice_at(self.bytes, self.span)));
        }
        let mut engine = Sha256::new();
        engine.update(slice_at(self.bytes, self.version_span));
        engine.update(self.segwit_base_body());
        engine.update(slice_at(self.bytes, self.lock_time_span));
        Txid(finalize_double_sha256(engine))
    }

    #[must_use]
    pub fn base_size(&self) -> usize {
        if !self.segwit {
            return widen(self.span.len());
        }
        slice_at(self.bytes, self.version_span).len()
            + self.segwit_base_body().len()
            + slice_at(self.bytes, self.lock_time_span).len()
    }

    fn segwit_base_body(&self) -> &'a [u8] {
        let body_end = self.outputs.last().map_or_else(
            || self.output_count_span.end(),
            |output| output.script_pubkey().end(),
        );
        let bytes = slice_at(self.bytes, self.span);
        let origin = u64::from(self.span.start());
        let start = usize::try_from(u64::from(self.input_count_span.start()) - origin)
            .unwrap_or_else(|_| unreachable!("body start is inside the transaction"));
        let end = usize::try_from(body_end - origin)
            .unwrap_or_else(|_| unreachable!("body end is inside the transaction"));
        &bytes[start..end]
    }

    #[must_use]
    pub fn stripped_parts(&self) -> [&'a [u8]; 3] {
        if !self.segwit {
            return [slice_at(self.bytes, self.span), &[], &[]];
        }
        [
            slice_at(self.bytes, self.version_span),
            self.segwit_base_body(),
            slice_at(self.bytes, self.lock_time_span),
        ]
    }

    fn materialize_witness(&self, input: usize) -> Witness {
        let item_bytes = self
            .witness_item_spans(input)
            .map(|span| widen(span.len()))
            .fold(0_usize, usize::saturating_add);
        let items = self
            .inputs
            .get(input)
            .map_or(0, |layout| widen(layout.witness_items));
        let mut witness = Witness::with_capacity(items, item_bytes);
        for span in self.witness_item_spans(input) {
            witness.push(slice_at(self.bytes, span));
        }
        witness
    }

    #[must_use]
    pub fn materialize(&self) -> Tx {
        let mut version_reader = slice_at(self.bytes, self.version_span);
        let version = read_u32_le(&mut version_reader)
            .unwrap_or_else(|_| unreachable!("validated version span"));
        let mut lock_time_reader = slice_at(self.bytes, self.lock_time_span);
        let lock_time = LockTime::from_consensus(
            read_u32_le(&mut lock_time_reader)
                .unwrap_or_else(|_| unreachable!("validated lock-time span")),
        );

        let inputs = self
            .inputs
            .iter()
            .enumerate()
            .map(|(index, layout)| {
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
                    script_sig: Script::from_bytes(
                        slice_at(self.bytes, layout.script_sig).to_vec(),
                    ),
                    sequence: Sequence::from_consensus(
                        read_u32_le(&mut sequence_reader)
                            .unwrap_or_else(|_| unreachable!("validated sequence span")),
                    ),
                    witness: self.materialize_witness(index),
                }
            })
            .collect();

        let outputs = self
            .outputs
            .iter()
            .map(|layout| {
                let mut value_reader = slice_at(self.bytes, layout.value);
                TxOut {
                    value: Amount::from_sat(
                        read_u64_le(&mut value_reader)
                            .unwrap_or_else(|_| unreachable!("validated value span")),
                    ),
                    script_pubkey: Script::from_bytes(
                        slice_at(self.bytes, layout.script_pubkey).to_vec(),
                    ),
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedBlock<'a> {
    bytes: &'a [u8],
    header_span: ByteSpan,
    tx_count_span: ByteSpan,
    tx_spans: Vec<ByteSpan>,
    txs: Vec<ParsedTransaction<'a>>,
    consumed: u64,
}

impl<'a> ParsedBlock<'a> {
    pub fn parse(reader: &mut &'a [u8]) -> Result<Self, DecodeError> {
        let image = *reader;
        let mut cursor = 0_u64;
        let parsed = Self::parse_at(image, &mut cursor)?;
        let consumed = usize::try_from(cursor)
            .unwrap_or_else(|_| unreachable!("cursor stays within its image"));
        *reader = &image[consumed..];
        Ok(parsed)
    }

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

    fn parse_at(image: &'a [u8], cursor: &mut u64) -> Result<Self, DecodeError> {
        let mut cur = ImageCursor {
            image,
            pos: *cursor,
        };
        let header_span = cur.take(HEADER_LEN)?;
        let (tx_count_value, tx_count_span) = cur.read_compact()?;
        cur.require_count(tx_count_value, MIN_TX_LEN)?;

        let mut tx_spans = Vec::with_capacity(count_capacity(tx_count_value));
        let mut txs = Vec::with_capacity(count_capacity(tx_count_value));
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

    #[must_use]
    pub const fn tx_count_span(&self) -> ByteSpan {
        self.tx_count_span
    }

    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.txs.len()
    }

    #[must_use]
    pub fn transaction_spans(&self) -> &[ByteSpan] {
        &self.tx_spans
    }

    #[must_use]
    pub fn transactions(&self) -> &[ParsedTransaction<'a>] {
        &self.txs
    }

    #[must_use]
    pub fn consumed_len(&self) -> usize {
        usize::try_from(self.consumed)
            .unwrap_or_else(|_| unreachable!("consumed stays within the image"))
    }

    #[must_use]
    pub fn span_bytes(&self, span: ByteSpan) -> Option<&'a [u8]> {
        let start = widen(span.start());
        let end = usize::try_from(span.end()).ok()?;
        self.bytes.get(start..end)
    }

    /// Heap bytes held by this parse itself, which is transient scratch beside the wire image.
    #[must_use]
    pub fn scratch_heap_bytes(&self) -> usize {
        self.tx_spans
            .capacity()
            .saturating_mul(core::mem::size_of::<ByteSpan>())
            .saturating_add(
                self.txs
                    .capacity()
                    .saturating_mul(core::mem::size_of::<ParsedTransaction<'_>>()),
            )
            .saturating_add(
                self.txs
                    .iter()
                    .map(ParsedTransaction::scratch_heap_bytes)
                    .fold(0_usize, usize::saturating_add),
            )
    }

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
