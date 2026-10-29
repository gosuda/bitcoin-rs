//! Native block type and block-level hashing helpers.

use bytes::Bytes;

use crate::{
    BlockHash, Header, Tx, Txid,
    encode::{ConsensusDecode, ConsensusEncode, DecodeError, consensus_bytes, deserialize},
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

    /// Full consensus serialization length, including BIP144 witness sections.
    #[must_use]
    pub fn total_size(&self) -> usize {
        self.consensus_size()
    }

    #[must_use]
    pub fn stripped_size(&self) -> usize {
        Header::LEN
            .saturating_add(crate::varint::encoded_len(crate::encode::compact_len(
                self.txs.len(),
            )))
            .saturating_add(self.txs.iter().map(Tx::base_size).sum())
    }

    /// BIP141 block weight: `stripped_size * 3 + total_size` weight units.
    #[must_use]
    pub fn weight(&self) -> u64 {
        u64::try_from(self.stripped_size())
            .unwrap_or(u64::MAX)
            .saturating_mul(3)
            .saturating_add(u64::try_from(self.total_size()).unwrap_or(u64::MAX))
    }

    /// Returns the total heap bytes allocated for this block's transaction vector,
    /// transactions, inputs, outputs, scripts, and witness stacks, including spare capacity.
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
pub struct BlockPayload {
    block: Block,
    bytes: Bytes,
}

impl BlockPayload {
    pub fn from_raw(raw: Bytes) -> Result<Self, DecodeError> {
        let block = deserialize::<Block>(&raw)?;
        Ok(Self { block, bytes: raw })
    }

    pub fn from_local(block: Block) -> Self {
        let bytes = Bytes::from(consensus_bytes(&block));
        Self { block, bytes }
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "Owning raw releases the ignored submitblock suffix after copying the consumed prefix"
    )]
    pub fn from_prefix(raw: Bytes) -> Result<(Self, usize), DecodeError> {
        let mut reader: &[u8] = &raw;
        let block = Block::consensus_decode(&mut reader)?;
        let consumed = raw.len() - reader.len();
        let bytes = Bytes::copy_from_slice(&raw[..consumed]);
        Ok((Self { block, bytes }, consumed))
    }

    #[must_use]
    pub fn block(&self) -> &Block {
        &self.block
    }

    #[must_use]
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    #[must_use]
    pub fn into_block(self) -> Block {
        self.block
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockBodyMetadata {
    pub body_size: usize,
    pub tx_count: usize,
}

#[cfg(test)]
mod tests;
