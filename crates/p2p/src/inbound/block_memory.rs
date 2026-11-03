use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Condvar, Mutex};

use crate::wire::PeerError;

pub(crate) const BLOCK_INGRESS_BYTES: usize = 512 * 1024 * 1024;

pub(crate) fn expands_on_decode(command: &str) -> bool {
    matches!(
        command,
        "block" | "cmpctblock" | "blocktxn" | "tx" | "pkgtxns"
    )
}

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
        loop {
            if cancelled() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "block decode cancelled",
                )
                .into());
            }
            let mut used = self.used.lock();
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
    pub(crate) fn retain(&mut self, bytes: usize) -> Result<(), PeerError> {
        if bytes > self.bytes {
            return Err(
                std::io::Error::other("decoded block exceeded its allocation bound").into(),
            );
        }
        *self.owner.used.lock() -= self.bytes - bytes;
        self.bytes = bytes;
        self.owner.released.notify_all();
        Ok(())
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
