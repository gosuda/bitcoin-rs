//! Checked borrowed wire layout for blocks and transactions.

use std::ops::Range;

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
const MIN_TX_LEN: u64 = 10;
const MIN_INPUT_LEN: u64 = 41;
const MIN_OUTPUT_LEN: u64 = 9;
const MIN_WITNESS_ITEM_LEN: u64 = 1;
/// Fixed serialized input outpoint length: 32-byte txid plus 4-byte vout.
const OUTPOINT_LEN: u64 = 36;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteSpan {
    start: u32,
    len: u32,
}

impl ByteSpan {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetadataRange {
    start: u32,
    end: u32,
}

impl MetadataRange {
    const EMPTY: Self = Self { start: 0, end: 0 };

    fn new(start: u64, end: u64, limit: u64) -> Result<Self, DecodeError> {
        let available = usize::try_from(limit.saturating_sub(start)).unwrap_or(usize::MAX);
        if end < start || end > limit {
            return Err(impossible(available));
        }
        let start = u32::try_from(start).map_err(|_| impossible(available))?;
        let end = u32::try_from(end).map_err(|_| impossible(available))?;
        Ok(Self { start, end })
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.end == self.start
    }

    #[must_use]
    pub fn as_range(self) -> Range<usize> {
        widen(self.start)..widen(self.end)
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
    witness: MetadataRange,
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

    #[must_use]
    pub const fn witness(&self) -> MetadataRange {
        self.witness
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
    witness_spans: Vec<ByteSpan>,
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

        let (output_count_value, output_count_span) = match output_count_override {
            Some(pair) => pair,
            None => cur.read_compact()?,
        };
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

    #[must_use]
    pub fn witness_spans(&self) -> &[ByteSpan] {
        &self.witness_spans
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
                    script_sig: Script::from_bytes(
                        slice_at(self.bytes, layout.script_sig).to_vec(),
                    ),
                    sequence: Sequence::from_consensus(
                        read_u32_le(&mut sequence_reader)
                            .unwrap_or_else(|_| unreachable!("validated sequence span")),
                    ),
                    witness: Witness::from_stack(
                        layout
                            .witness
                            .as_range()
                            .map(|index| slice_at(self.bytes, self.witness_spans[index]).to_vec())
                            .collect(),
                    ),
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
