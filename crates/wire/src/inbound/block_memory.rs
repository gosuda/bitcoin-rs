use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Condvar, Mutex};

use crate::wire::PeerError;

pub const BLOCK_INGRESS_BYTES: usize = 512 * 1024 * 1024;
pub const RECEIVE_INGRESS_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("receive or decode ingress budget unavailable")]
struct ResourceRefusal;

#[derive(Debug, Clone, Copy)]
enum Allocation {
    Image,
    Receive,
}

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
    fn receive_capacity(&self) -> usize;
    fn try_take_receive(&self, bytes: usize) -> bool;
    fn give_back_receive(&self, bytes: usize);
}

#[derive(Debug)]
pub struct FixedIngressLedger {
    capacity: usize,
    used: Arc<Mutex<usize>>,
    released: Condvar,
    receive_used: Mutex<usize>,
}

impl IngressLedger for FixedIngressLedger {
    fn capacity(&self) -> usize {
        self.capacity
    }

    fn try_take(&self, bytes: usize) -> bool {
        let mut used = self.used.lock();
        let receive_used = self.receive_used.lock();
        if used.saturating_sub(*receive_used).saturating_add(bytes) <= self.capacity {
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

    fn receive_capacity(&self) -> usize {
        RECEIVE_INGRESS_BYTES
    }

    fn try_take_receive(&self, bytes: usize) -> bool {
        let mut used = self.used.lock();
        let mut receive_used = self.receive_used.lock();
        if receive_used.saturating_add(bytes) > self.receive_capacity() {
            return false;
        }
        *receive_used += bytes;
        *used += bytes;
        true
    }

    fn give_back_receive(&self, bytes: usize) {
        let mut used = self.used.lock();
        let mut receive_used = self.receive_used.lock();
        *receive_used = receive_used.saturating_sub(bytes);
        *used = used.saturating_sub(bytes);
        drop(receive_used);
        drop(used);
        self.released.notify_all();
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

    pub(crate) fn reserve_receive(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Result<BlockMemoryCredit, std::io::Error> {
        if bytes > self.ledger.receive_capacity() || !self.ledger.try_take_receive(bytes) {
            return Err(std::io::Error::other(ResourceRefusal));
        }
        Ok(BlockMemoryCredit {
            owner: Arc::clone(self),
            bytes,
            allocation: Allocation::Receive,
        })
    }

    pub(crate) fn try_reserve_decode(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Result<BlockMemoryCredit, PeerError> {
        if bytes > self.ledger.capacity() || !self.ledger.try_take(bytes) {
            return Err(std::io::Error::other(ResourceRefusal).into());
        }
        Ok(BlockMemoryCredit {
            owner: Arc::clone(self),
            bytes,
            allocation: Allocation::Image,
        })
    }

    pub(crate) fn try_reserve(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Result<BlockMemoryCredit, PeerError> {
        if bytes > self.ledger.capacity() {
            return Err(std::io::Error::other(
                "compact reconstruction reservation exceeds ingress budget",
            )
            .into());
        }
        if !self.ledger.try_take(bytes) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "compact reconstruction ingress budget unavailable",
            )
            .into());
        }
        Ok(BlockMemoryCredit {
            owner: Arc::clone(self),
            bytes,
            allocation: Allocation::Image,
        })
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
                    allocation: Allocation::Image,
                });
            }
            self.ledger.wait_released(Duration::from_millis(100));
        }
    }
}

impl Default for BlockMemory {
    fn default() -> Self {
        let used = Arc::new(Mutex::new(0));
        let released = Condvar::new();
        let ledger = Arc::new(FixedIngressLedger {
            capacity: BLOCK_INGRESS_BYTES,
            used: Arc::clone(&used),
            released,
            receive_used: Mutex::new(0),
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
    allocation: Allocation,
}

impl BlockMemoryCredit {
    fn release(&self, bytes: usize) {
        match self.allocation {
            Allocation::Image => self.owner.ledger.give_back(bytes),
            Allocation::Receive => self.owner.ledger.give_back_receive(bytes),
        }
    }

    pub fn retain(&mut self, bytes: usize) -> Result<(), PeerError> {
        if bytes > self.bytes {
            return Err(
                std::io::Error::other("decoded block exceeded its allocation bound").into(),
            );
        }
        let excess = self.bytes - bytes;
        if excess > 0 {
            self.release(excess);
            self.bytes = bytes;
        }
        Ok(())
    }
}

impl Drop for BlockMemoryCredit {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.release(self.bytes);
        }
    }
}

#[cfg(test)]
mod tests;
