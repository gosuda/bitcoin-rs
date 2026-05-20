use core::marker::PhantomData;

use bitcoin_rs_primitives::Hash256;
use smallvec::SmallVec;
use tinyvec::ArrayVec;

use crate::{UtxoError, UtxoKey};

/// One live output inside a transaction-level UTXO record.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct OneUtxoOut {
    /// Originating transaction output index.
    pub vout: u32,
    /// Output value in satoshis.
    pub value: u64,
    /// Byte offset into the shard script slab.
    pub script_pubkey_offset: u32,
    /// Script length in bytes.
    pub script_pubkey_len: u16,
    /// Whether the originating transaction was coinbase.
    pub coinbase: bool,
    /// Block height that created the output.
    pub height: u32,
}

/// Transaction-level UTXO record stored in a shard arena.
///
/// `vouts` keeps the common case inline, `overflow` only spills when a
/// transaction has more than eight still-live outputs. Script bytes are stored
/// in the shard slab and addressed by `OneUtxoOut::{script_pubkey_offset,
/// script_pubkey_len}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoRecord<'arena> {
    pub(crate) key: UtxoKey,
    pub(crate) txid: Hash256,
    /// Bitmap of live originating transaction outputs; supports vouts `0..64`.
    pub vout_bitmap: u64,
    /// Inline live outputs.
    pub vouts: ArrayVec<[OneUtxoOut; 8]>,
    /// Spill storage for transactions with more than eight live outputs.
    pub overflow: SmallVec<[OneUtxoOut; 4]>,
    _arena: PhantomData<&'arena ()>,
}

impl UtxoRecord<'_> {
    pub(crate) fn new(key: UtxoKey, txid: Hash256) -> Self {
        Self {
            key,
            txid,
            vout_bitmap: 0,
            vouts: ArrayVec::new(),
            overflow: SmallVec::new(),
            _arena: PhantomData,
        }
    }

    pub(crate) const fn key(&self) -> UtxoKey {
        self.key
    }

    pub(crate) const fn txid(&self) -> Hash256 {
        self.txid
    }

    pub(crate) fn add_output(&mut self, output: OneUtxoOut) -> Result<(), UtxoError> {
        validate_bitmap_vout(output.vout)?;
        let _removed = self.remove_output(output.vout)?;
        self.vout_bitmap |= 1_u64 << output.vout;
        if let Some(output) = self.vouts.try_push(output) {
            self.overflow.push(output);
        }
        Ok(())
    }

    pub(crate) fn remove_output(&mut self, vout: u32) -> Result<bool, UtxoError> {
        validate_bitmap_vout(vout)?;
        let bit = 1_u64 << vout;
        if self.vout_bitmap & bit == 0 {
            return Ok(false);
        }
        self.vout_bitmap &= !bit;

        if let Some(index) = self.vouts.iter().position(|output| output.vout == vout) {
            let _removed = self.vouts.swap_remove(index);
            return Ok(true);
        }
        if let Some(index) = self.overflow.iter().position(|output| output.vout == vout) {
            let _removed = self.overflow.swap_remove(index);
            return Ok(true);
        }
        Ok(true)
    }

    pub(crate) fn find_output(&self, vout: u32) -> Option<&OneUtxoOut> {
        if vout >= 64 || self.vout_bitmap & (1_u64 << vout) == 0 {
            return None;
        }
        self.iter_outputs().find(|output| output.vout == vout)
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.vout_bitmap == 0
    }

    pub(crate) fn output_count(&self) -> usize {
        self.vouts.len() + self.overflow.len()
    }

    pub(crate) fn iter_outputs(&self) -> impl Iterator<Item = &OneUtxoOut> {
        self.vouts.iter().chain(self.overflow.iter())
    }
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

pub(crate) const fn validate_bitmap_vout(vout: u32) -> Result<(), UtxoError> {
    if vout < 64 {
        Ok(())
    } else {
        Err(UtxoError::VoutOutOfRange { vout })
    }
}
