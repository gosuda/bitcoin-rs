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
    released: Condvar,
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
mod tests {
    use super::*;
    use crate::Message;
    use crate::peer::Peer;
    use bitcoin::p2p::Magic;
    use bitcoin_rs_consensus::primitives::{BlockImage, Network, varint};
    use std::io::Cursor;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Peer(#[from] crate::PeerError),
        #[error(transparent)]
        RecvTimeout(#[from] crossbeam_channel::RecvTimeoutError),
        #[error("missing: {0}")]
        Missing(&'static str),
        #[error("panic: {0}")]
        Panicked(&'static str),
    }

    type TestResult = Result<(), TestError>;

    #[test]
    fn cancellation_predicate_runs_outside_the_budget_lock_on_every_attempt() -> TestResult {
        let memory = Arc::new(BlockMemory::default());
        let _held = memory.reserve(BLOCK_INGRESS_BYTES, || false)?;
        let cancelled = AtomicBool::new(false);
        let (entered_tx, entered_rx) = crossbeam_channel::bounded(1);
        std::thread::scope(|scope| -> TestResult {
            let waiting = scope.spawn(|| {
                memory.reserve(1, || {
                    let _guard = memory
                        .used
                        .try_lock()
                        .unwrap_or_else(|| panic!("cancellation callback holds the budget mutex"));
                    let stop = cancelled.load(Ordering::Acquire);
                    let _ = entered_tx.try_send(());
                    stop
                })
            });
            entered_rx.recv_timeout(Duration::from_secs(5))?;
            cancelled.store(true, Ordering::Release);
            assert!(
                waiting
                    .join()
                    .map_err(|_| TestError::Panicked("waiter panicked"))?
                    .is_err()
            );
            Ok(())
        })?;
        assert_eq!(*memory.used.lock(), BLOCK_INGRESS_BYTES);
        Ok(())
    }

    #[test]
    fn an_underestimated_bound_is_a_local_error_and_keeps_the_original_credit() -> TestResult {
        let memory = Arc::new(BlockMemory::default());
        let mut credit = memory.reserve(64, || false)?;
        let error = credit.retain(65).err().ok_or(TestError::Missing(
            "underestimated allocation must be refused",
        ))?;
        assert!(
            matches!(PeerError::inbound(error), PeerError::Io(_)),
            "local failure must not blame the peer"
        );
        assert_eq!(*memory.used.lock(), 64);
        assert_eq!(credit.bytes, 64);
        credit.retain(32)?;
        assert_eq!(*memory.used.lock(), 32);
        drop(credit);
        assert_eq!(*memory.used.lock(), 0);
        Ok(())
    }

    fn witness_heavy_bytes() -> Vec<u8> {
        let mut bytes = vec![0; 80];
        bytes.push(1);
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&[0, 1, 1]);
        bytes.extend_from_slice(&[0; 36]);
        bytes.push(0);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&[0; 8]);
        bytes.push(0);
        let count = 3_999_000 - bytes.len() - 5 - 4;
        bytes.extend_from_slice(&varint::encode(u64::try_from(count).unwrap_or(u64::MAX)));
        bytes.resize(3_999_000, 0);
        bytes
    }

    #[test]
    fn maximum_wire_image_fits_alone_and_cannot_bypass_peak_admission() -> TestResult {
        let reservation = bitcoin_rs_consensus::primitives::layout::decode_reservation(
            crate::wire::MAX_MESSAGE_PAYLOAD,
        );
        assert!(reservation <= BLOCK_INGRESS_BYTES, "{reservation}");
        let memory = Arc::new(BlockMemory::default());
        let held = memory.reserve(BLOCK_INGRESS_BYTES, || false)?;
        let cancelled = AtomicBool::new(false);
        let (entered_tx, entered_rx) = crossbeam_channel::bounded(1);
        std::thread::scope(|scope| -> TestResult {
            let waiting = scope.spawn(|| {
                memory.reserve(reservation, || {
                    let _ = entered_tx.try_send(());
                    cancelled.load(Ordering::Acquire)
                })
            });
            entered_rx.recv_timeout(Duration::from_secs(5))?;
            cancelled.store(true, Ordering::Release);
            assert!(
                waiting
                    .join()
                    .map_err(|_| TestError::Panicked("waiter panicked"))?
                    .is_err()
            );
            assert_eq!(*memory.used.lock(), BLOCK_INGRESS_BYTES);
            Ok(())
        })?;
        drop(held);
        assert_eq!(*memory.used.lock(), 0);
        Ok(())
    }

    #[test]
    fn returned_credit_wakes_a_waiting_decoder() -> TestResult {
        let memory = Arc::new(BlockMemory::default());
        let held = memory.reserve(BLOCK_INGRESS_BYTES, || false)?;
        let (tx, rx) = crossbeam_channel::bounded(1);
        std::thread::scope(|scope| -> TestResult {
            let waiting = scope.spawn(|| {
                let credit = memory.reserve(1, || false)?;
                tx.send(())
                    .map_err(|_| std::io::Error::other("waiter receiver dropped"))?;
                Ok::<_, PeerError>(credit)
            });
            assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
            drop(held);
            rx.recv_timeout(Duration::from_secs(5))?;
            drop(
                waiting
                    .join()
                    .map_err(|_| TestError::Panicked("waiter panicked"))??,
            );
            Ok(())
        })?;
        assert_eq!(*memory.used.lock(), 0);
        Ok(())
    }

    fn framed(bytes: Vec<u8>) -> Result<Vec<u8>, PeerError> {
        let mut frame = Vec::new();
        crate::wire::write_message(
            &mut frame,
            Magic::REGTEST,
            &Message::BlockBytes(bytes.into()),
        )?;
        Ok(frame)
    }

    #[test]
    fn a_full_block_budget_does_not_block_control_messages() -> TestResult {
        let memory = Arc::new(BlockMemory::default());
        let _held = memory.reserve(BLOCK_INGRESS_BYTES, || false)?;
        let mut frame = Vec::new();
        crate::wire::write_message(&mut frame, Magic::REGTEST, &Message::Ping(42))?;
        let mut peer = Peer::new(Cursor::new(frame), Magic::REGTEST);
        let (message, _, credit) = peer
            .read_message_bounded(&memory, || true)?
            .ok_or(TestError::Missing("missing ping"))?;
        assert_eq!(message, Message::Ping(42));
        assert!(credit.is_none());
        assert_eq!(*memory.used.lock(), BLOCK_INGRESS_BYTES);
        Ok(())
    }

    #[test]
    fn witness_amplification_is_reserved_before_decode_and_retained_through_queue_drop()
    -> TestResult {
        let memory = Arc::new(BlockMemory::default());
        let frame = framed(witness_heavy_bytes())?;
        let mut peer = Peer::new(Cursor::new(frame), Magic::REGTEST);
        let (message, _, credit) = peer
            .read_message_bounded(&memory, || false)?
            .ok_or(TestError::Missing("missing block"))?;
        let Message::Block(payload) = message else {
            return Err(TestError::Missing("missing block message"));
        };
        assert_eq!(payload.tx(0).witness_item_count(0), 3_998_852);
        let retained = payload.bytes().len() + payload.retained_heap_bytes();
        assert_eq!(*memory.used.lock(), retained);
        let mut inbound = crate::InboundBlock::new(payload, None, None);
        inbound.memory_credit = credit;
        let (sender, receiver) = crossbeam_channel::bounded(1);
        sender
            .send(inbound)
            .map_err(|_| TestError::Missing("queue closed"))?;
        assert_eq!(*memory.used.lock(), retained);
        drop(sender);
        drop(receiver);
        assert_eq!(*memory.used.lock(), 0);
        Ok(())
    }

    #[test]
    fn cancellation_precedes_typed_decode_and_malformed_decode_releases_credit() -> TestResult {
        let memory = Arc::new(BlockMemory::default());
        let held = memory.reserve(BLOCK_INGRESS_BYTES, || false)?;
        let frame = framed(vec![0; 80])?;
        let mut peer = Peer::new(Cursor::new(frame.clone()), Magic::REGTEST);
        assert!(matches!(
            peer.read_message_bounded(&memory, || true),
            Err(PeerError::Io(_))
        ));
        assert_eq!(*memory.used.lock(), BLOCK_INGRESS_BYTES);
        drop(held);
        let mut peer = Peer::new(Cursor::new(frame), Magic::REGTEST);
        assert!(peer.read_message_bounded(&memory, || false).is_err());
        assert_eq!(*memory.used.lock(), 0);
        let mut frame = Vec::new();
        crate::wire::write_message(
            &mut frame,
            Magic::REGTEST,
            &Message::Block(BlockImage::from_local(Network::Regtest.genesis_block())),
        )?;
        let mut peer = Peer::new(Cursor::new(frame), Magic::REGTEST);
        drop(peer.read_message_bounded(&memory, || false)?);
        assert_eq!(*memory.used.lock(), 0);
        Ok(())
    }
}
