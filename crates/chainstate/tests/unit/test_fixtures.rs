//! In-memory test doubles and fixtures shared by in-crate unit tests.

use bitcoin_rs_primitives::{Amount, Hash256, OutPoint, TxOut, Txid};
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::chainstate_journal::Coin;
use hashbrown::HashMap;
use parking_lot::RwLock;

#[derive(Default)]
pub(crate) struct MemoryBodies {
    bodies: RwLock<HashMap<(u32, Hash256), Vec<u8>>>,
}

impl BlockBodyStore for MemoryBodies {
    fn persist_block_body(
        &self,
        height: u32,
        hash: Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        self.bodies.write().insert((height, hash), body.to_vec());
        Ok(())
    }

    fn load_block_body(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.bodies.read().get(&(height, hash)).cloned())
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

/// A coinbase journal coin at vout 0 of the txid filled with `marker`, paying
/// `value` sats to `OP_TRUE`, created at `height`.
pub(crate) fn coin(marker: u8, height: u32, value: u64) -> Coin {
    Coin {
        outpoint: OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0),
        txout: TxOut {
            value: Amount::from_sat(value),
            script_pubkey: vec![0x51].into(),
        },
        height,
        coinbase: true,
    }
}
