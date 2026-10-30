//! Node-wide admission for block decoding and queued decoded bodies.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Condvar, Mutex};

use crate::wire::PeerError;

// Includes peak parser metadata plus the materialized block. A maximum wire
// frame must fit on its own; retaining queued blocks can only delay decoding.
pub(crate) const BLOCK_INGRESS_BYTES: usize = 512 * 1024 * 1024;

#[derive(Debug, Default)]
pub(crate) struct BlockMemory {
    used: Mutex<usize>,
    released: Condvar,
}

impl BlockMemory {
    pub(crate) fn reserve(
        self: &Arc<Self>,
        bytes: usize,
        cancelled: impl Fn() -> bool,
    ) -> Result<BlockMemoryCredit, PeerError> {
        if bytes > BLOCK_INGRESS_BYTES {
            return Err(
                std::io::Error::other("block decode reservation exceeds ingress budget").into(),
            );
        }
        let mut used = self.used.lock();
        loop {
            if cancelled() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "block decode cancelled",
                )
                .into());
            }
            if used.saturating_add(bytes) <= BLOCK_INGRESS_BYTES {
                *used += bytes;
                return Ok(BlockMemoryCredit {
                    owner: Arc::clone(self),
                    bytes,
                });
            }
            self.released
                .wait_for(&mut used, Duration::from_millis(100));
        }
    }
}

#[derive(Debug)]
pub(crate) struct BlockMemoryCredit {
    owner: Arc<BlockMemory>,
    bytes: usize,
}

impl BlockMemoryCredit {
    pub(crate) fn retain(&mut self, bytes: usize) {
        assert!(
            bytes <= self.bytes,
            "decoded block exceeded its allocation bound"
        );
        *self.owner.used.lock() -= self.bytes - bytes;
        self.bytes = bytes;
        self.owner.released.notify_all();
    }
}

impl Drop for BlockMemoryCredit {
    fn drop(&mut self) {
        *self.owner.used.lock() -= self.bytes;
        self.owner.released.notify_all();
    }
}

#[cfg(test)]
mod tests;
