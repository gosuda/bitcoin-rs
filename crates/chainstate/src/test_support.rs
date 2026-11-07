use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use hashbrown::HashMap;
use parking_lot::RwLock;

#[derive(Default)]
pub(crate) struct MemoryBodies {
    bodies: RwLock<HashMap<(u32, Hash256), Vec<u8>>>,
}

impl BlockBodyStore for MemoryBodies {
    fn load_block_body_bounded(
        &self,
        height: u32,
        hash: Hash256,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::BoundedReadError> {
        self.bodies
            .read()
            .get(&(height, hash))
            .map(|body| {
                if body.len() > max_bytes {
                    Err(bitcoin_rs_storage::BoundedReadError::Limit {
                        size: body.len(),
                        limit: max_bytes,
                    })
                } else {
                    Ok(body.clone())
                }
            })
            .transpose()
    }

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
