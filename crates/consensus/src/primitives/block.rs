use bytes::Bytes;

use crate::primitives::{
    Amount, BlockHash, Hash256, Header, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
    Txid, Witness, Wtxid,
    encode::{ConsensusDecode, ConsensusEncode, DecodeError, consensus_bytes, double_sha256},
    layout::{BlockLayout, ByteSpan, TxIdentity, TxLayout},
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Block {
    pub header: Header,
    pub txs: Vec<Tx>,
}

impl Block {
    #[must_use]
    pub fn block_hash(&self) -> BlockHash {
        self.header.compute_hash()
    }

    #[must_use]
    pub fn txids(&self) -> Vec<Txid> {
        self.txs.iter().map(Tx::txid).collect()
    }

    #[must_use]
    pub fn total_size(&self) -> usize {
        self.consensus_size()
    }

    #[must_use]
    pub fn stripped_size(&self) -> usize {
        Header::LEN
            .saturating_add(crate::primitives::varint::encoded_len(
                crate::primitives::encode::compact_len(self.txs.len()),
            ))
            .saturating_add(self.txs.iter().map(Tx::base_size).sum())
    }

    #[must_use]
    pub fn weight(&self) -> u64 {
        u64::try_from(self.stripped_size())
            .unwrap_or(u64::MAX)
            .saturating_mul(3)
            .saturating_add(u64::try_from(self.total_size()).unwrap_or(u64::MAX))
    }

    #[must_use]
    pub fn retained_heap_bytes(&self) -> usize {
        let mut total = self
            .txs
            .capacity()
            .saturating_mul(core::mem::size_of::<Tx>());
        for tx in &self.txs {
            total = total.saturating_add(tx.retained_heap_bytes());
        }
        total
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockImage {
    bytes: Bytes,
    layout: BlockLayout,
    identities: Box<[TxIdentity]>,
    hash: BlockHash,
}

#[cfg(any(test, feature = "test-seam"))]
static BLOCK_IMAGE_MATERIALIZATIONS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<usize, usize>>,
> = std::sync::LazyLock::new(Default::default);

#[cfg(any(test, feature = "test-seam"))]
static TRANSACTION_VIEW_MATERIALIZATIONS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<usize, usize>>,
> = std::sync::LazyLock::new(Default::default);

#[cfg(any(test, feature = "test-seam"))]
fn count_materialization(
    counts: &std::sync::Mutex<std::collections::HashMap<usize, usize>>,
    buffer: &[u8],
) {
    let mut counts = counts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(count) = counts.get_mut(&buffer.as_ptr().addr()) {
        *count += 1;
    }
}

#[cfg(any(test, feature = "test-seam"))]
fn materializations_of(
    counts: &std::sync::Mutex<std::collections::HashMap<usize, usize>>,
    image: &BlockImage,
) -> usize {
    let counts = counts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    counts
        .get(&image.bytes.as_ptr().addr())
        .copied()
        .unwrap_or(0)
}

#[cfg(any(test, feature = "test-seam"))]
#[must_use]
pub fn block_image_materialize_call_count(image: &BlockImage) -> usize {
    materializations_of(&BLOCK_IMAGE_MATERIALIZATIONS, image)
}

#[cfg(any(test, feature = "test-seam"))]
#[must_use]
pub fn transaction_view_materialize_call_count(image: &BlockImage) -> usize {
    materializations_of(&TRANSACTION_VIEW_MATERIALIZATIONS, image)
}

#[cfg(any(test, feature = "test-seam"))]
pub fn watch_materializations(image: &BlockImage) {
    let key = image.bytes.as_ptr().addr();
    for counts in [
        &BLOCK_IMAGE_MATERIALIZATIONS,
        &TRANSACTION_VIEW_MATERIALIZATIONS,
    ] {
        counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, 0);
    }
}

#[cfg(any(test, feature = "test-seam"))]
pub fn unwatch_materializations(image: &BlockImage) {
    let key = image.bytes.as_ptr().addr();
    for counts in [
        &BLOCK_IMAGE_MATERIALIZATIONS,
        &TRANSACTION_VIEW_MATERIALIZATIONS,
    ] {
        counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&key);
    }
}

impl BlockImage {
    pub fn from_raw(raw: Bytes) -> Result<Self, DecodeError> {
        let (layout, identities) = BlockLayout::parse_exact(&raw)?;
        let header_span = layout.header();
        let header_slice = bytes_at(&raw, header_span);
        let hash = BlockHash(double_sha256(header_slice));
        Ok(Self {
            bytes: raw,
            layout,
            identities,
            hash,
        })
    }
    pub fn from_prefix(raw: Bytes) -> Result<(Self, usize), DecodeError> {
        let mut cursor = 0_u64;
        let (layout, identities) = BlockLayout::parse_at(&raw, &mut cursor)?;
        let consumed =
            usize::try_from(cursor).map_err(|_| DecodeError::TrailingBytes { remaining: 0 })?;
        let bytes = Bytes::copy_from_slice(&raw[..consumed]);
        let header_span = layout.header();
        let header_slice = bytes_at(&bytes, header_span);
        let hash = BlockHash(double_sha256(header_slice));
        Ok((
            Self {
                bytes,
                layout,
                identities,
                hash,
            },
            consumed,
        ))
    }

    pub fn from_local(block: Block) -> Self {
        let bytes = Bytes::from(consensus_bytes(&block));
        Self::from_raw(bytes)
            .unwrap_or_else(|_| unreachable!("locally serialized block must parse cleanly"))
    }

    #[must_use]
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    #[must_use]
    pub fn header(&self) -> Header {
        let header_span = self.layout.header();
        let mut reader = bytes_at(&self.bytes, header_span);
        <Header as ConsensusDecode>::consensus_decode(&mut reader)
            .unwrap_or_else(|_| unreachable!("validated header span must decode"))
    }

    #[must_use]
    pub fn header_bytes(&self) -> [u8; 80] {
        let header_span = self.layout.header();
        let slice = bytes_at(&self.bytes, header_span);
        let mut arr = [0u8; 80];
        arr.copy_from_slice(slice);
        arr
    }

    #[must_use]
    pub fn block_hash(&self) -> BlockHash {
        self.hash
    }

    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.layout.txs().len()
    }

    #[must_use]
    pub fn tx(&self, index: usize) -> TransactionView<'_> {
        TransactionView {
            bytes: &self.bytes,
            layout: &self.layout.txs()[index],
            identity: &self.identities[index],
        }
    }

    #[must_use]
    pub fn identity(&self, index: usize) -> &TxIdentity {
        &self.identities[index]
    }

    #[must_use]
    pub fn identities(&self) -> &[TxIdentity] {
        &self.identities
    }

    #[must_use]
    pub fn has_witness(&self) -> bool {
        self.identities.iter().any(|id| id.wtxid().is_some())
    }

    #[must_use]
    pub fn layout(&self) -> &BlockLayout {
        &self.layout
    }

    #[must_use]
    pub fn materialize(&self) -> Block {
        #[cfg(any(test, feature = "test-seam"))]
        count_materialization(&BLOCK_IMAGE_MATERIALIZATIONS, &self.bytes);
        Block {
            header: self.header(),
            txs: (0..self.tx_count())
                .map(|i| self.tx(i).materialize())
                .collect(),
        }
    }

    #[must_use]
    pub fn into_block(self) -> Block {
        self.materialize()
    }

    #[must_use]
    pub fn retained_heap_bytes(&self) -> usize {
        self.layout.retained_heap_bytes().saturating_add(
            self.identities
                .len()
                .saturating_mul(core::mem::size_of::<TxIdentity>()),
        )
    }
}

#[inline]
fn bytes_at(bytes: &[u8], span: ByteSpan) -> &[u8] {
    debug_assert!(
        span.end() <= widening_len(bytes.len()),
        "span end exceeds byte length"
    );
    let start = usize::try_from(span.start()).unwrap_or(usize::MAX);
    let end = usize::try_from(span.end()).unwrap_or(usize::MAX);
    &bytes[start..end]
}

#[inline]
fn widening_len(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

#[derive(Clone, Copy, Debug)]
pub struct TransactionView<'a> {
    bytes: &'a [u8],
    layout: &'a TxLayout,
    identity: &'a TxIdentity,
}

impl<'a> TransactionView<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8], layout: &'a TxLayout, identity: &'a TxIdentity) -> Self {
        Self {
            bytes,
            layout,
            identity,
        }
    }

    #[must_use]
    pub fn version(&self) -> u32 {
        let b = bytes_at(self.bytes, self.layout.version());
        let mut arr = [0u8; 4];
        arr.copy_from_slice(b);
        u32::from_le_bytes(arr)
    }

    #[must_use]
    pub fn lock_time(&self) -> LockTime {
        let b = bytes_at(self.bytes, self.layout.lock_time());
        let mut arr = [0u8; 4];
        arr.copy_from_slice(b);
        LockTime::from_consensus(u32::from_le_bytes(arr))
    }

    #[must_use]
    pub fn is_coinbase(&self) -> bool {
        self.input_count() == 1 && self.input_outpoint(0).is_null()
    }

    #[must_use]
    pub fn has_witness(&self) -> bool {
        self.layout.is_segwit()
            && self
                .layout
                .inputs()
                .iter()
                .any(|input| !input.witness_items().is_empty())
    }

    #[must_use]
    pub fn base_size(&self) -> usize {
        usize::try_from(self.identity.base_size()).unwrap_or(usize::MAX)
    }

    #[must_use]
    pub fn total_size(&self) -> usize {
        usize::try_from(self.identity.total_size()).unwrap_or(usize::MAX)
    }

    #[must_use]
    pub const fn txid(&self) -> Txid {
        self.identity.txid()
    }

    #[must_use]
    pub fn wtxid(&self) -> Wtxid {
        self.identity
            .wtxid()
            .unwrap_or_else(|| Wtxid(self.identity.txid().0))
    }

    #[must_use]
    pub fn input_count(&self) -> usize {
        self.layout.inputs().len()
    }

    #[must_use]
    pub fn output_count(&self) -> usize {
        self.layout.outputs().len()
    }

    #[must_use]
    pub fn input_outpoint(&self, i: usize) -> OutPoint {
        let b = bytes_at(self.bytes, self.layout.inputs()[i].outpoint());
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&b[..32]);
        let mut vout_bytes = [0u8; 4];
        vout_bytes.copy_from_slice(&b[32..36]);
        let vout = u32::from_le_bytes(vout_bytes);
        OutPoint::new(Txid(Hash256::from_le_bytes(&hash)), vout)
    }

    #[must_use]
    pub fn input_script_sig(&self, i: usize) -> &'a [u8] {
        bytes_at(self.bytes, self.layout.inputs()[i].script_sig())
    }

    #[must_use]
    pub fn input_sequence(&self, i: usize) -> Sequence {
        let b = bytes_at(self.bytes, self.layout.inputs()[i].sequence());
        let mut arr = [0u8; 4];
        arr.copy_from_slice(b);
        Sequence::from_consensus(u32::from_le_bytes(arr))
    }

    #[must_use]
    pub fn witness_item(&self, input: usize, item: usize) -> &'a [u8] {
        let item_layout = self.layout.inputs()[input].witness_items()[item];
        bytes_at(self.bytes, item_layout.item())
    }

    #[must_use]
    pub fn witness_item_count(&self, input: usize) -> usize {
        self.layout.inputs()[input].witness_items().len()
    }

    #[must_use]
    pub fn output_value(&self, i: usize) -> Amount {
        let b = bytes_at(self.bytes, self.layout.outputs()[i].value());
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Amount::from_sat(u64::from_le_bytes(arr))
    }

    #[must_use]
    pub fn output_script(&self, i: usize) -> &'a [u8] {
        bytes_at(self.bytes, self.layout.outputs()[i].script_pubkey())
    }

    #[must_use]
    pub fn span_bytes(&self) -> &'a [u8] {
        bytes_at(self.bytes, self.layout.span())
    }

    #[must_use]
    pub const fn layout(&self) -> &'a TxLayout {
        self.layout
    }

    #[must_use]
    pub const fn identity(&self) -> &'a TxIdentity {
        self.identity
    }

    #[must_use]
    pub fn materialize(&self) -> Tx {
        #[cfg(any(test, feature = "test-seam"))]
        count_materialization(&TRANSACTION_VIEW_MATERIALIZATIONS, self.bytes);
        let version = self.version();
        let lock_time = self.lock_time();

        let inputs = (0..self.input_count())
            .map(|i| {
                let previous_output = self.input_outpoint(i);
                let script_sig = Script::from_bytes(self.input_script_sig(i).to_vec());
                let sequence = self.input_sequence(i);
                let item_count = self.witness_item_count(i);
                let total_item_bytes = (0..item_count).map(|j| self.witness_item(i, j).len()).sum();
                let mut witness = Witness::with_capacity(item_count, total_item_bytes);
                for j in 0..item_count {
                    witness.push(self.witness_item(i, j));
                }
                TxIn {
                    previous_output,
                    script_sig,
                    sequence,
                    witness,
                }
            })
            .collect();

        let outputs = (0..self.output_count())
            .map(|i| TxOut {
                value: self.output_value(i),
                script_pubkey: Script::from_bytes(self.output_script(i).to_vec()),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockBodyMetadata {
    pub body_size: usize,
    pub tx_count: usize,
}

#[cfg(test)]
mod tests;
