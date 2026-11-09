use sha2::{Digest, Sha256};

use crate::primitives::{
    Amount, Block, DecodeError, Hash256, Header, LockTime, OutPoint, Script, Sequence, Tx, TxIn,
    TxOut, Txid, Witness, Wtxid,
    encode::{
        ConsensusDecode, double_sha256, finalize_double_sha256, read_array, read_u32_le,
        read_u64_le,
    },
    varint,
};

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
const WITNESS_ITEM_DECODE_BYTES: usize =
    core::mem::size_of::<WitnessItemLayout>() + core::mem::size_of::<u32>();
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
pub struct WitnessItemLayout {
    item: ByteSpan,
}

impl WitnessItemLayout {
    #[must_use]
    pub const fn new(_len_prefix: ByteSpan, item: ByteSpan) -> Self {
        Self { item }
    }

    #[must_use]
    pub const fn len_prefix(&self) -> ByteSpan {
        let prefix_len = if self.item.len() < 0xfd {
            1
        } else if self.item.len() <= 0xffff {
            3
        } else {
            5
        };
        ByteSpan {
            start: self.item.start().saturating_sub(prefix_len),
            len: prefix_len,
        }
    }

    #[must_use]
    pub const fn item(&self) -> ByteSpan {
        self.item
    }

    #[must_use]
    pub const fn bytes(&self) -> ByteSpan {
        self.item
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputLayout {
    outpoint: ByteSpan,
    script_sig: ByteSpan,
    sequence: ByteSpan,
    witness: ByteSpan,
    witness_items: Box<[WitnessItemLayout]>,
    witness_item_count: u32,
}

impl InputLayout {
    #[must_use]
    pub const fn outpoint(&self) -> ByteSpan {
        self.outpoint
    }

    #[must_use]
    pub const fn script_sig(&self) -> ByteSpan {
        self.script_sig
    }

    #[must_use]
    pub const fn sequence(&self) -> ByteSpan {
        self.sequence
    }

    #[must_use]
    pub const fn witness(&self) -> ByteSpan {
        self.witness
    }

    #[must_use]
    pub fn witness_items(&self) -> &[WitnessItemLayout] {
        &self.witness_items
    }

    #[must_use]
    pub fn witness_item_count(&self) -> usize {
        if self.witness_items.is_empty() {
            widen(self.witness_item_count)
        } else {
            self.witness_items.len()
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputLayout {
    value: ByteSpan,
    script_pubkey: ByteSpan,
}

impl OutputLayout {
    #[must_use]
    pub const fn value(&self) -> ByteSpan {
        self.value
    }

    #[must_use]
    pub const fn script_pubkey(&self) -> ByteSpan {
        self.script_pubkey
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxLayout {
    span: ByteSpan,
    version: ByteSpan,
    marker_flag: Option<ByteSpan>,
    input_count: ByteSpan,
    inputs: Box<[InputLayout]>,
    output_count: ByteSpan,
    outputs: Box<[OutputLayout]>,
    lock_time: ByteSpan,
    segwit: bool,
}

impl TxLayout {
    #[must_use]
    pub const fn span(&self) -> ByteSpan {
        self.span
    }

    #[must_use]
    pub const fn version(&self) -> ByteSpan {
        self.version
    }

    #[must_use]
    pub const fn marker_flag(&self) -> Option<ByteSpan> {
        self.marker_flag
    }

    #[must_use]
    pub const fn input_count(&self) -> ByteSpan {
        self.input_count
    }

    #[must_use]
    pub fn inputs(&self) -> &[InputLayout] {
        &self.inputs
    }

    #[must_use]
    pub const fn output_count(&self) -> ByteSpan {
        self.output_count
    }

    #[must_use]
    pub fn outputs(&self) -> &[OutputLayout] {
        &self.outputs
    }

    #[must_use]
    pub const fn lock_time(&self) -> ByteSpan {
        self.lock_time
    }

    #[must_use]
    pub const fn is_segwit(&self) -> bool {
        self.segwit
    }
    #[must_use]
    pub fn retained_heap_bytes(&self) -> usize {
        self.inputs
            .len()
            .saturating_mul(core::mem::size_of::<InputLayout>())
            .saturating_add(
                self.outputs
                    .len()
                    .saturating_mul(core::mem::size_of::<OutputLayout>()),
            )
            .saturating_add(
                self.inputs
                    .iter()
                    .map(|input| {
                        input
                            .witness_items
                            .len()
                            .saturating_mul(core::mem::size_of::<WitnessItemLayout>())
                    })
                    .fold(0_usize, usize::saturating_add),
            )
    }

    pub fn parse_at(image: &[u8], cursor: &mut u64) -> Result<(Self, TxIdentity), DecodeError> {
        Self::parse_at_internal(image, cursor, true)
    }

    pub(crate) fn parse_at_internal(
        image: &[u8],
        cursor: &mut u64,
        record_witness_spans: bool,
    ) -> Result<(Self, TxIdentity), DecodeError> {
        let mut cur = ImageCursor {
            image,
            pos: *cursor,
        };
        let tx_start = cur.pos;
        let version = cur.take(4)?;
        let (mut input_count_value, mut input_count) = cur.read_compact()?;
        let mut output_count_override: Option<(u64, ByteSpan)> = None;
        let mut segwit = false;
        let mut marker_flag: Option<ByteSpan> = None;
        if input_count_value == 0 {
            let (flag, flag_span) = cur.read_u8()?;
            if flag == 0 {
                output_count_override = Some((0, flag_span));
            } else if flag == 0x01 {
                segwit = true;
                marker_flag = Some(ByteSpan::checked(version.end(), 2, cur.limit())?);
                let (count, span) = cur.read_compact()?;
                input_count_value = count;
                input_count = span;
            } else {
                return Err(DecodeError::InvalidSegwitFlag { got: flag });
            }
        }
        cur.require_count(input_count_value, MIN_INPUT_LEN)?;

        let in_count = count_capacity(input_count_value);
        let mut inputs = Vec::with_capacity(in_count);
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
                witness_items: Box::new([]),
                witness_item_count: 0,
            });
        }

        let (output_count_value, output_count) = match output_count_override {
            Some(pair) => pair,
            None => cur.read_compact()?,
        };
        cur.require_count(output_count_value, MIN_OUTPUT_LEN)?;
        let out_count = count_capacity(output_count_value);
        let mut outputs = Vec::with_capacity(out_count);
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
                let items_cap = if record_witness_spans {
                    count_capacity(item_count)
                } else {
                    0
                };
                let mut items = Vec::with_capacity(items_cap);
                for _ in 0..item_count {
                    let (item_len, len_span) = cur.read_compact()?;
                    let item_span = cur.take(item_len)?;
                    if record_witness_spans {
                        items.push(WitnessItemLayout::new(len_span, item_span));
                    }
                }
                input.witness =
                    ByteSpan::checked(region_start, cur.pos - region_start, cur.limit())?;
                input.witness_items = items.into_boxed_slice();
                input.witness_item_count = u32::try_from(item_count).map_err(|_| impossible(0))?;
            }
            if inputs.iter().all(|input| input.witness_item_count == 0) {
                return Err(DecodeError::SuperfluousWitness);
            }
        }

        let lock_time = cur.take(4)?;
        let tx_len = cur.pos.checked_sub(tx_start).ok_or_else(|| impossible(0))?;
        let span = ByteSpan::checked(tx_start, tx_len, cur.limit())?;

        let (txid, wtxid, base_size, total_size) = if !segwit {
            let tx_bytes = slice_at(image, span);
            let id = Txid(double_sha256(tx_bytes));
            (id, None, span.len(), span.len())
        } else {
            let body_end = outputs
                .last()
                .map_or_else(|| output_count.end(), |output| output.script_pubkey().end());
            let body_start = widen(input_count.start());
            let body_end_idx = usize::try_from(body_end).unwrap_or(body_start);
            let base_body = image.get(body_start..body_end_idx).unwrap_or(&[]);

            let mut engine = Sha256::new();
            engine.update(slice_at(image, version));
            engine.update(base_body);
            engine.update(slice_at(image, lock_time));
            let txid = Txid(finalize_double_sha256(engine));

            let tx_bytes = slice_at(image, span);
            let wtxid = Some(Wtxid(double_sha256(tx_bytes)));

            let base_size = u32::try_from(4 + base_body.len() + 4).map_err(|_| impossible(0))?;
            let total_size = span.len();

            (txid, wtxid, base_size, total_size)
        };

        *cursor = cur.pos;

        let identity = TxIdentity {
            txid,
            wtxid,
            base_size,
            total_size,
        };

        let layout = Self {
            span,
            version,
            marker_flag,
            input_count,
            inputs: inputs.into_boxed_slice(),
            output_count,
            outputs: outputs.into_boxed_slice(),
            lock_time,
            segwit,
        };

        Ok((layout, identity))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxIdentity {
    txid: Txid,
    wtxid: Option<Wtxid>,
    base_size: u32,
    total_size: u32,
}

impl TxIdentity {
    #[must_use]
    pub const fn new(txid: Txid, wtxid: Option<Wtxid>, base_size: u32, total_size: u32) -> Self {
        Self {
            txid,
            wtxid,
            base_size,
            total_size,
        }
    }

    #[must_use]
    pub const fn txid(&self) -> Txid {
        self.txid
    }

    #[must_use]
    pub const fn wtxid(&self) -> Option<Wtxid> {
        self.wtxid
    }

    #[must_use]
    pub const fn base_size(&self) -> u32 {
        self.base_size
    }

    #[must_use]
    pub const fn total_size(&self) -> u32 {
        self.total_size
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockLayout {
    header: ByteSpan,
    tx_count: ByteSpan,
    txs: Box<[TxLayout]>,
    consumed: u32,
}

impl BlockLayout {
    #[must_use]
    pub const fn header(&self) -> ByteSpan {
        self.header
    }

    #[must_use]
    pub const fn header_span(&self) -> ByteSpan {
        self.header
    }

    #[must_use]
    pub const fn tx_count(&self) -> ByteSpan {
        self.tx_count
    }

    #[must_use]
    pub const fn tx_count_span(&self) -> ByteSpan {
        self.tx_count
    }

    #[must_use]
    pub fn txs(&self) -> &[TxLayout] {
        &self.txs
    }

    #[must_use]
    pub const fn consumed(&self) -> u32 {
        self.consumed
    }

    #[must_use]
    pub fn consumed_len(&self) -> usize {
        widen(self.consumed)
    }
    #[must_use]
    pub fn retained_heap_bytes(&self) -> usize {
        self.txs
            .len()
            .saturating_mul(core::mem::size_of::<TxLayout>())
            .saturating_add(
                self.txs
                    .iter()
                    .map(TxLayout::retained_heap_bytes)
                    .fold(0_usize, usize::saturating_add),
            )
    }

    pub fn parse_exact(bytes: &[u8]) -> Result<(Self, Box<[TxIdentity]>), DecodeError> {
        #[cfg(any(test, feature = "test-seam"))]
        PARSE_EXACT_CALLS.with(|calls| calls.set(calls.get() + 1));
        let mut cursor = 0_u64;
        let (layout, identities) = Self::parse_at(bytes, &mut cursor)?;
        let consumed = usize::try_from(cursor).map_err(|_| impossible(0))?;
        if consumed != bytes.len() {
            return Err(DecodeError::TrailingBytes {
                remaining: bytes.len() - consumed,
            });
        }
        Ok((layout, identities))
    }

    pub fn parse_at(
        image: &[u8],
        cursor: &mut u64,
    ) -> Result<(Self, Box<[TxIdentity]>), DecodeError> {
        let mut cur = ImageCursor {
            image,
            pos: *cursor,
        };
        let start_pos = cur.pos;
        let header = cur.take(widening(Header::LEN))?;
        let (tx_count_value, tx_count) = cur.read_compact()?;
        cur.require_count(tx_count_value, MIN_TX_LEN)?;

        let count = count_capacity(tx_count_value);
        let mut txs = Vec::with_capacity(count);
        let mut identities = Vec::with_capacity(count);

        for _ in 0..tx_count_value {
            let (tx, identity) = TxLayout::parse_at(image, &mut cur.pos)?;
            txs.push(tx);
            identities.push(identity);
        }

        let consumed_u64 = cur
            .pos
            .checked_sub(start_pos)
            .ok_or_else(|| impossible(0))?;
        let consumed = u32::try_from(consumed_u64).map_err(|_| impossible(0))?;
        *cursor = cur.pos;

        let layout = BlockLayout {
            header,
            tx_count,
            txs: txs.into_boxed_slice(),
            consumed,
        };

        Ok((layout, identities.into_boxed_slice()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTransaction<'a> {
    bytes: &'a [u8],
    layout: TxLayout,
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

    pub(crate) fn parse_at(image: &'a [u8], cursor: &mut u64) -> Result<Self, DecodeError> {
        let (layout, _) = TxLayout::parse_at_internal(image, cursor, false)?;
        Ok(Self {
            bytes: image,
            layout,
        })
    }

    #[must_use]
    pub const fn span(&self) -> ByteSpan {
        self.layout.span
    }

    #[must_use]
    pub const fn is_segwit(&self) -> bool {
        self.layout.segwit
    }

    #[must_use]
    pub fn inputs(&self) -> &[InputLayout] {
        &self.layout.inputs
    }

    #[must_use]
    pub fn outputs(&self) -> &[OutputLayout] {
        &self.layout.outputs
    }

    pub fn witness_item_spans(&self, input: usize) -> impl Iterator<Item = ByteSpan> + '_ {
        let layout = self.layout.inputs.get(input);
        let items = layout.map_or(&[][..], |l| &l.witness_items);
        let count = layout.map_or(0, |l| {
            if l.witness_items.is_empty() {
                widen(l.witness_item_count)
            } else {
                l.witness_items.len()
            }
        });
        let mut cursor = ImageCursor {
            image: self.bytes,
            pos: u64::from(layout.map_or(0, |l| l.witness.start())),
        };
        (0..count).map(move |idx| {
            if idx < items.len() {
                items[idx].item
            } else {
                let (len, _) = cursor
                    .read_compact()
                    .unwrap_or_else(|_| unreachable!("witness region was validated at parse time"));
                cursor
                    .take(len)
                    .unwrap_or_else(|_| unreachable!("witness region was validated at parse time"))
            }
        })
    }

    #[must_use]
    pub fn scratch_heap_bytes(&self) -> usize {
        self.layout
            .inputs
            .len()
            .saturating_mul(core::mem::size_of::<InputLayout>())
            .saturating_add(
                self.layout
                    .outputs
                    .len()
                    .saturating_mul(core::mem::size_of::<OutputLayout>()),
            )
            .saturating_add(
                self.layout
                    .inputs
                    .iter()
                    .map(|input| {
                        input
                            .witness_items
                            .len()
                            .saturating_mul(core::mem::size_of::<WitnessItemLayout>())
                    })
                    .fold(0_usize, usize::saturating_add),
            )
    }

    #[must_use]
    pub fn consumed_len(&self) -> usize {
        widen(self.layout.span.len())
    }

    #[must_use]
    pub fn span_bytes(&self, span: ByteSpan) -> Option<&'a [u8]> {
        let start = widen(span.start());
        let end = usize::try_from(span.end()).ok()?;
        self.bytes.get(start..end)
    }

    #[must_use]
    pub fn txid(&self) -> Txid {
        if !self.layout.segwit {
            return Txid(double_sha256(slice_at(self.bytes, self.layout.span)));
        }
        let mut engine = Sha256::new();
        engine.update(slice_at(self.bytes, self.layout.version));
        engine.update(self.segwit_base_body());
        engine.update(slice_at(self.bytes, self.layout.lock_time));
        Txid(finalize_double_sha256(engine))
    }

    #[must_use]
    pub fn base_size(&self) -> usize {
        if !self.layout.segwit {
            return widen(self.layout.span.len());
        }
        slice_at(self.bytes, self.layout.version).len()
            + self.segwit_base_body().len()
            + slice_at(self.bytes, self.layout.lock_time).len()
    }

    fn segwit_base_body(&self) -> &'a [u8] {
        let body_end = self.layout.outputs.last().map_or_else(
            || self.layout.output_count.end(),
            |output| output.script_pubkey().end(),
        );
        let start = widen(self.layout.input_count.start());
        let end = usize::try_from(body_end).unwrap_or(start);
        self.bytes.get(start..end).unwrap_or(&[])
    }

    #[must_use]
    pub fn stripped_parts(&self) -> [&'a [u8]; 3] {
        if !self.layout.segwit {
            return [slice_at(self.bytes, self.layout.span), &[], &[]];
        }
        [
            slice_at(self.bytes, self.layout.version),
            self.segwit_base_body(),
            slice_at(self.bytes, self.layout.lock_time),
        ]
    }

    fn materialize_witness(&self, input: usize) -> Witness {
        let items = self
            .layout
            .inputs
            .get(input)
            .map_or(0, |layout| layout.witness_item_count());
        let item_bytes = self
            .witness_item_spans(input)
            .map(|span| widen(span.len()))
            .fold(0_usize, usize::saturating_add);
        let mut witness = Witness::with_capacity(items, item_bytes);
        for span in self.witness_item_spans(input) {
            witness.push(slice_at(self.bytes, span));
        }
        witness
    }

    #[must_use]
    pub fn materialize(&self) -> Tx {
        let mut version_reader = slice_at(self.bytes, self.layout.version);
        let version = read_u32_le(&mut version_reader)
            .unwrap_or_else(|_| unreachable!("validated version span"));
        let mut lock_time_reader = slice_at(self.bytes, self.layout.lock_time);
        let lock_time = LockTime::from_consensus(
            read_u32_le(&mut lock_time_reader)
                .unwrap_or_else(|_| unreachable!("validated lock-time span")),
        );

        let inputs = self
            .layout
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
            .layout
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
        #[cfg(any(test, feature = "test-seam"))]
        PARSE_EXACT_CALLS.with(|calls| calls.set(calls.get() + 1));
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
        let start_pos = cur.pos;
        let header_span = cur.take(widening(Header::LEN))?;
        let (tx_count_value, tx_count_span) = cur.read_compact()?;
        cur.require_count(tx_count_value, MIN_TX_LEN)?;

        let count = count_capacity(tx_count_value);
        let mut tx_spans = Vec::with_capacity(count);
        let mut txs = Vec::with_capacity(count);

        for _ in 0..tx_count_value {
            let (tx, _) = TxLayout::parse_at_internal(image, &mut cur.pos, false)?;
            tx_spans.push(tx.span);
            txs.push(ParsedTransaction {
                bytes: image,
                layout: tx,
            });
        }

        let consumed_u64 = cur
            .pos
            .checked_sub(start_pos)
            .ok_or_else(|| impossible(0))?;
        let consumed = u64::from(u32::try_from(consumed_u64).map_err(|_| impossible(0))?);
        *cursor = cur.pos;

        Ok(Self {
            bytes: image,
            header_span,
            tx_count_span,
            tx_spans,
            txs,
            consumed,
        })
    }

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
#[cfg(any(test, feature = "test-seam"))]
thread_local! {
    static PARSE_EXACT_CALLS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(any(test, feature = "test-seam"))]
#[must_use]
pub fn parse_exact_call_count() -> usize {
    PARSE_EXACT_CALLS.with(core::cell::Cell::get)
}

#[cfg(any(test, feature = "test-seam"))]
pub fn reset_parse_exact_call_count() {
    PARSE_EXACT_CALLS.with(|calls| calls.set(0));
}
