use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Condvar, Mutex};

use crate::wire::PeerError;

pub const BLOCK_INGRESS_BYTES: usize = 512 * 1024 * 1024;

pub fn expands_on_decode(command: &str) -> bool {
    matches!(
        command,
        "block" | "cmpctblock" | "blocktxn" | "tx" | "pkgtxns"
    )
}

pub trait IngressLedger: Send + Sync {
    fn capacity(&self) -> usize;
    fn try_take(&self, bytes: usize) -> bool;
    fn give_back(&self, bytes: usize);
    fn wait_released(&self, timeout: Duration);
}

#[derive(Debug)]
pub struct FixedIngressLedger {
    capacity: usize,
    used: Arc<Mutex<usize>>,
    released: Arc<Condvar>,
}

impl IngressLedger for FixedIngressLedger {
    fn capacity(&self) -> usize {
        self.capacity
    }

    fn try_take(&self, bytes: usize) -> bool {
        let mut used = self.used.lock();
        if used.saturating_add(bytes) <= self.capacity {
            *used += bytes;
            true
        } else {
            false
        }
    }

    fn give_back(&self, bytes: usize) {
        let mut used = self.used.lock();
        *used = used.saturating_sub(bytes);
        drop(used);
        self.released.notify_all();
    }

    fn wait_released(&self, timeout: Duration) {
        let mut used = self.used.lock();
        self.released.wait_for(&mut used, timeout);
    }
}

#[derive(Clone)]
pub struct BlockMemory {
    ledger: Arc<dyn IngressLedger>,
    #[cfg(test)]
    pub(crate) used: Arc<Mutex<usize>>,
}
impl std::fmt::Debug for BlockMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockMemory")
            .field("capacity", &self.ledger.capacity())
            .finish()
    }
}

impl BlockMemory {
    #[must_use]
    pub fn new(ledger: Arc<dyn IngressLedger>) -> Self {
        Self {
            ledger,
            #[cfg(test)]
            used: Arc::new(Mutex::new(0)),
        }
    }

    #[must_use]
    pub fn ledger(&self) -> &Arc<dyn IngressLedger> {
        &self.ledger
    }

    pub fn reserve(
        self: &Arc<Self>,
        bytes: usize,
        cancelled: impl Fn() -> bool,
    ) -> Result<BlockMemoryCredit, PeerError> {
        let capacity = self.ledger.capacity();
        if bytes > capacity {
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
            if self.ledger.try_take(bytes) {
                return Ok(BlockMemoryCredit {
                    owner: Arc::clone(self),
                    bytes,
                });
            }
            self.ledger.wait_released(Duration::from_millis(100));
        }
    }
}

impl Default for BlockMemory {
    fn default() -> Self {
        let used = Arc::new(Mutex::new(0));
        let released = Arc::new(Condvar::new());
        let ledger = Arc::new(FixedIngressLedger {
            capacity: BLOCK_INGRESS_BYTES,
            used: Arc::clone(&used),
            released,
        });
        Self {
            ledger,
            #[cfg(test)]
            used,
        }
    }
}

#[derive(Debug)]
pub struct BlockMemoryCredit {
    owner: Arc<BlockMemory>,
    bytes: usize,
}

impl BlockMemoryCredit {
    pub fn retain(&mut self, bytes: usize) -> Result<(), PeerError> {
        if bytes > self.bytes {
            return Err(
                std::io::Error::other("decoded block exceeded its allocation bound").into(),
            );
        }
        let excess = self.bytes - bytes;
        if excess > 0 {
            self.owner.ledger.give_back(excess);
            self.bytes = bytes;
        }
        Ok(())
    }
}

impl Drop for BlockMemoryCredit {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.owner.ledger.give_back(self.bytes);
        }
    }
}

#[cfg(test)]
mod tests;
