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
    /// Move a receive charge into the image lane without inflating the total.
    ///
    /// Takes the image charge before releasing the receive charge, so a
    /// refusal leaves the original receive charge untouched.
    fn transfer_receive_to_image(&self, bytes: usize) -> bool;

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

    /// Move a receive charge into the image lane without inflating the total:
    /// the shared `used` counter is untouched, only `receive_used` drops, so
    /// a transfer at the total cap is judged on its conserving post-state.
    fn transfer_receive_to_image(&self, bytes: usize) -> bool {
        let used = self.used.lock();
        let mut receive_used = self.receive_used.lock();
        if *receive_used < bytes {
            return false;
        }
        if used.saturating_sub(*receive_used).saturating_add(bytes) > self.capacity {
            return false;
        }
        *receive_used -= bytes;
        true
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

    /// A refused transfer preserves the full receive charge.
    pub(crate) fn transfer_to_image(&mut self) -> bool {
        if !matches!(self.allocation, Allocation::Receive) {
            return true;
        }
        if !self.owner.ledger.transfer_receive_to_image(self.bytes) {
            return false;
        }
        self.allocation = Allocation::Image;
        true
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
mod tests {
    use super::*;
    use crate::Message;
    use crate::peer::Peer;
    use bitcoin::p2p::Magic;
    use bitcoin_rs_consensus::primitives::{BlockImage, Network, varint};
    use std::io::Cursor;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Peer(#[from] crate::PeerError),
        #[error(transparent)]
        Io(#[from] std::io::Error),
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
        let charged = *memory.used.lock();
        assert!(charged >= retained);
        assert_eq!(
            credit.as_ref().map(|credit| credit.bytes),
            Some(payload.retained_heap_bytes())
        );
        let mut inbound = crate::InboundBlock::new(payload, None, None);
        inbound.memory_credit = credit;
        let (sender, receiver) = crossbeam_channel::bounded(1);
        sender
            .send(inbound)
            .map_err(|_| TestError::Missing("queue closed"))?;
        assert_eq!(*memory.used.lock(), charged);
        drop(sender);
        drop(receiver);
        assert_eq!(*memory.used.lock(), 0);
        Ok(())
    }

    // BUD-01, BUD-07
    #[test]
    fn cancellation_precedes_typed_decode_and_malformed_decode_releases_credit() -> TestResult {
        let memory = Arc::new(BlockMemory::default());
        let frame = framed(vec![0; 80])?;
        let mut peer = Peer::new(Cursor::new(frame.clone()), Magic::REGTEST);
        assert!(matches!(
            peer.read_message_bounded(&memory, || true),
            Err(PeerError::Io(error)) if error.kind() == std::io::ErrorKind::Interrupted
        ));
        assert_eq!(*memory.used.lock(), 0);
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

    struct ReceiveFrame {
        bytes: Cursor<Vec<u8>>,
        pause_at: usize,
        terminal: Option<std::io::ErrorKind>,
        max_read: usize,
    }

    impl std::io::Read for ReceiveFrame {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let position = usize::try_from(self.bytes.position())
                .map_err(|_| std::io::Error::other("frame position exceeds usize"))?;
            if position >= self.pause_at {
                return match self.terminal {
                    Some(std::io::ErrorKind::UnexpectedEof) => Ok(0),
                    Some(kind) => Err(kind.into()),
                    None => Err(std::io::ErrorKind::TimedOut.into()),
                };
            }
            let limit = output
                .len()
                .min(self.pause_at - position)
                .min(self.max_read);
            std::io::Read::read(&mut self.bytes, &mut output[..limit])
        }
    }

    impl std::io::Write for ReceiveFrame {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn legacy_receive_peer() -> Result<Peer<ReceiveFrame>, TestError> {
        let block = BlockImage::from_local(Network::Regtest.genesis_block());
        legacy_receive_block(&block)
    }

    fn legacy_receive_block(block: &BlockImage) -> Result<Peer<ReceiveFrame>, TestError> {
        Ok(receive_peer(
            framed(block.bytes().to_vec())?,
            crate::transport::Negotiated::v1(Magic::REGTEST),
        ))
    }

    fn encrypted_receive_peer() -> Result<Peer<ReceiveFrame>, TestError> {
        let block = BlockImage::from_local(Network::Regtest.genesis_block());
        encrypted_receive_block(&block)
    }

    fn encrypted_receive_block(block: &BlockImage) -> Result<Peer<ReceiveFrame>, TestError> {
        let command = "block"
            .parse::<bitcoin::p2p::message::CommandString>()
            .map_err(std::io::Error::other)?;
        let contents = crate::bip324::msg_type::encode(&command, block.bytes());
        let mut sender = crate::bip324::SendCipher::new([1; 32], [2; 32]);
        let bytes = sender
            .seal(&contents, &[], false)
            .map_err(std::io::Error::other)?;
        Ok(receive_peer(
            bytes,
            crate::transport::Negotiated {
                recv: crate::transport::RecvTransport::V2(Box::new(
                    crate::bip324::PacketReader::new(
                        crate::bip324::RecvCipher::new([1; 32], [2; 32]),
                        Vec::new(),
                    ),
                )),
                send: crate::transport::SendTransport::V2(Box::new(sender)),
                protocol: crate::transport::TransportProtocol::V2 {
                    session_id: [0; 32],
                },
            },
        ))
    }

    fn receive_peer(bytes: Vec<u8>, transport: crate::transport::Negotiated) -> Peer<ReceiveFrame> {
        let pause_at = bytes.len();
        Peer::with_transport(
            ReceiveFrame {
                bytes: Cursor::new(bytes),
                pause_at,
                terminal: None,
                max_read: usize::MAX,
            },
            Magic::REGTEST,
            transport,
        )
    }

    // BUD-01, BUD-06
    #[test]
    fn partial_receive_backing_holds_quota_until_terminal_error_or_peer_drop() -> TestResult {
        for (index, make_peer) in [legacy_receive_peer, encrypted_receive_peer]
            .into_iter()
            .enumerate()
        {
            for terminal in [
                None,
                Some(std::io::ErrorKind::UnexpectedEof),
                Some(std::io::ErrorKind::ConnectionAborted),
            ] {
                let memory = Arc::new(BlockMemory::default());
                let mut peer = make_peer()?;
                peer.stream.pause_at /= 2;
                let stalled = peer.read_message_bounded(&memory, || false);
                assert!(matches!(
                    &stalled,
                    Err(PeerError::Io(error))
                        if error.kind() == std::io::ErrorKind::TimedOut
                ));
                let received = usize::try_from(peer.stream.bytes.position())
                    .map_err(|_| TestError::Missing("received position"))?;
                let body_received = received.saturating_sub(if index == 0 { 24 } else { 3 });
                assert!(body_received > 1);
                assert!(*memory.used.lock() >= body_received);
                let capacity = memory.ledger().receive_capacity();
                let competing = memory.reserve_receive(capacity);
                assert!(
                    matches!(&competing, Err(error) if error.kind() == std::io::ErrorKind::Other),
                    "partial receive must own quota before {terminal:?}"
                );
                drop(memory.try_reserve(memory.ledger().capacity())?);
                if let Some(kind) = terminal {
                    peer.stream.terminal = Some(kind);
                    let failed = peer.read_message_bounded(&memory, || false);
                    assert!(matches!(
                        &failed,
                        Err(PeerError::Io(error)) if error.kind() == kind
                    ));
                    drop(memory.reserve_receive(capacity)?);
                }
                drop(peer);
                drop(memory.reserve_receive(capacity)?);
            }
        }
        Ok(())
    }

    #[test]
    fn completed_receive_backing_holds_quota_until_the_last_raw_slice_drops() -> TestResult {
        for (index, make_peer) in [legacy_receive_peer, encrypted_receive_peer]
            .into_iter()
            .enumerate()
        {
            let memory = Arc::new(BlockMemory::default());
            let mut peer = make_peer()?;
            let (message, raw, decoder_credit) = peer
                .read_message_bounded(&memory, || false)?
                .ok_or(TestError::Missing("received block"))?;
            let Message::Block(block) = &message else {
                return Err(TestError::Missing("decoded block"));
            };
            assert_eq!(
                block.block_hash(),
                BlockImage::from_local(Network::Regtest.genesis_block()).block_hash()
            );
            let retained = raw.clone().slice(1..raw.len() - 1);
            let received_backing_minimum = usize::try_from(peer.stream.bytes.position())
                .map_err(|_| TestError::Missing("received position"))?
                .saturating_sub(if index == 0 { 24 } else { 3 });
            drop(peer);
            drop(message);
            drop(raw);
            drop(decoder_credit);
            assert!(*memory.used.lock() >= received_backing_minimum);
            let capacity = memory.ledger().receive_capacity();
            drop(memory.reserve_receive(capacity)?);
            let competing = memory.try_reserve(memory.ledger().capacity());
            assert!(
                matches!(
                    &competing,
                    Err(PeerError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock
                ),
                "a live raw slice must own image quota after the transfer"
            );

            drop(retained);
            drop(memory.try_reserve(memory.ledger().capacity())?);
        }
        Ok(())
    }

    fn lean_big_block_bytes() -> Vec<u8> {
        const TARGET: usize = 2_100_000;
        let mut bytes = vec![0; 80];
        bytes.push(1);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&[0; 36]);
        bytes.push(0);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&[0; 8]);
        let script_len = TARGET - (bytes.len() + 5 + 4);
        bytes.extend_from_slice(&varint::encode(
            u64::try_from(script_len).unwrap_or(u64::MAX),
        ));
        bytes.extend(vec![0; script_len]);
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        assert_eq!(bytes.len(), TARGET);
        bytes
    }

    // BUD-05
    #[test]
    fn staged_successors_keep_receive_headroom_for_the_missing_frontier() -> TestResult {
        const SUCCESSORS: usize = 16;
        const FRAME_CAPACITY: usize = 4_194_304;
        let image = BlockImage::from_raw(bytes::Bytes::from(lean_big_block_bytes()))
            .map_err(|_| TestError::Missing("lean big block"))?;
        let heap = image.retained_heap_bytes();
        for make_peer in [legacy_receive_block, encrypted_receive_block] {
            let memory = Arc::new(BlockMemory::default());
            let mut staged = Vec::with_capacity(SUCCESSORS + 1);
            for _ in 0..SUCCESSORS {
                let mut peer = make_peer(&image)?;
                let received = peer
                    .read_message_bounded(&memory, || false)?
                    .ok_or(TestError::Missing("staged successor"))?;
                assert!(matches!(received.0, Message::Block(_)));
                staged.push(received);
                drop(peer);
            }
            drop(memory.reserve_receive(memory.ledger().receive_capacity())?);
            let mut peer = make_peer(&image)?;
            let frontier = peer
                .read_message_bounded(&memory, || false)?
                .ok_or(TestError::Missing("frontier block"))?;
            assert!(matches!(frontier.0, Message::Block(_)));
            staged.push(frontier);
            drop(peer);
            assert_eq!(
                *memory.used.lock(),
                (SUCCESSORS + 1) * (FRAME_CAPACITY + heap),
                "staged raw plus heap must stay exactly charged"
            );
            drop(staged);
            assert_eq!(*memory.used.lock(), 0);
        }
        Ok(())
    }

    #[test]
    fn partial_receive_resumes_and_rejects_cross_ledger_binding() -> TestResult {
        for make_peer in [legacy_receive_peer, encrypted_receive_peer] {
            for poll in [std::io::ErrorKind::TimedOut, std::io::ErrorKind::WouldBlock] {
                let memory = Arc::new(BlockMemory::default());
                let other = Arc::new(BlockMemory::default());
                let mut peer = make_peer()?;
                let end = peer.stream.pause_at;
                peer.stream.pause_at /= 2;
                peer.stream.terminal = Some(poll);
                assert!(
                    matches!(peer.read_message_bounded(&memory, || false), Err(PeerError::Io(error)) if error.kind() == poll)
                );
                let charged = *memory.used.lock();
                let position = peer.stream.bytes.position();
                assert!(charged > 1);
                assert!(
                    matches!(peer.read_message_bounded(&other, || false), Err(PeerError::Io(error)) if error.kind() == std::io::ErrorKind::Other)
                );
                assert_eq!(peer.stream.bytes.position(), position);
                assert_eq!(*memory.used.lock(), charged);
                assert_eq!(*other.used.lock(), 0);
                peer.stream.pause_at = end;
                let received = peer
                    .read_message_bounded(&memory, || false)?
                    .ok_or(TestError::Missing("resumed block"))?;
                assert!(matches!(received.0, Message::Block(_)));
                drop(received);
                drop(peer);
                assert_eq!(*memory.used.lock(), 0);
            }
        }
        Ok(())
    }

    #[test]
    fn cancelling_partial_receive_releases_backing_without_another_read() -> TestResult {
        for make_peer in [legacy_receive_peer, encrypted_receive_peer] {
            let memory = Arc::new(BlockMemory::default());
            let mut peer = make_peer()?;
            peer.stream.pause_at /= 2;
            assert!(peer.read_message_bounded(&memory, || false).is_err());
            let position = peer.stream.bytes.position();
            assert!(*memory.used.lock() > 1);
            assert!(
                matches!(peer.read_message_bounded(&memory, || true), Err(PeerError::Io(error)) if error.kind() == std::io::ErrorKind::Interrupted)
            );
            assert_eq!(peer.stream.bytes.position(), position);
            assert_eq!(*memory.used.lock(), 0);
        }
        Ok(())
    }

    struct ReceiveProbe {
        capacity: usize,
        used: Mutex<(usize, usize, usize)>,
        released: Condvar,
        refusals: AtomicUsize,
        cancel_on_retry: Option<crate::PeerLease>,
    }

    impl ReceiveProbe {
        fn new(capacity: usize) -> Self {
            Self {
                capacity,
                used: Mutex::new((0, 0, 0)),
                released: Condvar::new(),
                refusals: AtomicUsize::new(0),
                cancel_on_retry: None,
            }
        }
    }

    impl IngressLedger for ReceiveProbe {
        fn capacity(&self) -> usize {
            BLOCK_INGRESS_BYTES
        }

        fn try_take(&self, bytes: usize) -> bool {
            let mut used = self.used.lock();
            if used.0.saturating_add(bytes) > self.capacity() {
                return false;
            }
            used.0 += bytes;
            true
        }

        fn give_back(&self, bytes: usize) {
            self.used.lock().0 -= bytes;
            self.released.notify_all();
        }

        fn wait_released(&self, timeout: Duration) {
            self.released.wait_for(&mut self.used.lock(), timeout);
        }

        fn receive_capacity(&self) -> usize {
            self.capacity
        }

        fn try_take_receive(&self, bytes: usize) -> bool {
            let mut used = self.used.lock();
            if used.1.saturating_add(bytes) > self.capacity {
                if self.refusals.fetch_add(1, Ordering::Relaxed) != 0
                    && let Some(lease) = &self.cancel_on_retry
                {
                    lease.cancel();
                }
                return false;
            }
            used.1 += bytes;
            used.2 = used.2.max(used.1);
            true
        }

        fn give_back_receive(&self, bytes: usize) {
            self.used.lock().1 -= bytes;
            self.released.notify_all();
        }
        fn transfer_receive_to_image(&self, bytes: usize) -> bool {
            if !self.try_take(bytes) {
                return false;
            }
            self.give_back_receive(bytes);
            true
        }
    }

    // BUD-03, BUD-07, SYNC-03, SYNC-04
    #[test]
    fn message_loop_refuses_receive_pressure_once_and_releases_partial_backing() -> TestResult {
        let image = BlockImage::from_raw(bytes::Bytes::from(lean_big_block_bytes()))
            .map_err(|_| TestError::Missing("large block"))?;
        for make_peer in [legacy_receive_block, encrypted_receive_block] {
            let (outbound, _receiver) = crossbeam_channel::unbounded();
            let lease = crate::PeerLease::new(outbound);
            let mut probe = ReceiveProbe::new(crate::recv::RECEIVE_CHUNK * 2);
            probe.cancel_on_retry = Some(lease.clone());
            let ledger = Arc::new(probe);
            let memory = Arc::new(BlockMemory::new(ledger.clone()));
            let shared = crate::listener::ConnectionShared::new(
                Arc::new(crate::PeerTable::new()),
                crate::BannedReader::fixture_empty(),
                Arc::new(crate::NetworkActivity::from_shared(Arc::new(
                    AtomicBool::new(true),
                ))),
                bitcoin_rs_consensus::latch::LatchWriter::new().reader(),
                None,
                Magic::REGTEST,
                crossbeam_channel::unbounded().0,
                crossbeam_channel::unbounded().0,
                None,
                None,
                crate::listener::ListenerExtras {
                    block_memory: Some(memory),
                    ..Default::default()
                },
            );
            let mut peer = make_peer(&image)?;
            peer.state = crate::peer::PeerState::Ready;
            let result = crate::listener::run_message_loop(
                &mut peer,
                crate::PeerEndpoint::from((std::net::Ipv4Addr::LOCALHOST, 18_444)),
                &lease,
                &shared,
                None,
            );
            assert!(
                matches!(&result, Err(PeerError::Io(error)) if error.kind() == std::io::ErrorKind::Other)
            );
            assert!(!result.as_ref().err().is_some_and(PeerError::is_misbehavior));
            assert_eq!(ledger.refusals.load(Ordering::Relaxed), 1);
            assert_eq!(ledger.used.lock().1, 0);
            assert!(!lease.is_cancelled());
        }
        Ok(())
    }

    // BUD-01, BUD-07
    #[test]
    fn receive_capacity_and_growth_overlap_are_admitted_before_consuming_more_bytes() -> TestResult
    {
        let initial_chunk = crate::recv::RECEIVE_CHUNK;
        let mut block = Network::Regtest.genesis_block();
        let transaction = block.txs[0].clone();
        let transactions = (initial_chunk * 3).div_ceil(transaction.total_size());
        block.txs.resize(transactions, transaction);
        let block = BlockImage::from_local(block);
        assert!(block.bytes().len() > initial_chunk);
        for (index, make_peer) in [legacy_receive_block, encrypted_receive_block]
            .into_iter()
            .enumerate()
        {
            let ledger = Arc::new(ReceiveProbe::new(RECEIVE_INGRESS_BYTES));
            let memory = Arc::new(BlockMemory::new(ledger.clone()));
            let mut peer = make_peer(&block)?;
            peer.stream.max_read = 17;
            let (message, raw, decoder) = peer
                .read_message_bounded(&memory, || false)?
                .ok_or(TestError::Missing("received block"))?;
            drop(message);
            drop(decoder);
            drop(peer);
            let (image, receive, peak) = *ledger.used.lock();
            assert_eq!(
                receive, 0,
                "transferred backing leaves the receive lane free"
            );
            assert!(image > initial_chunk);
            assert!(image > raw.len(), "spare allocation capacity stays charged");
            assert!(
                peak >= image,
                "the moved charge cannot exceed the observed receive peak"
            );
            assert!(
                peak > raw.len(),
                "old and new allocations overlap during growth"
            );
            drop(raw);
            assert_eq!(ledger.used.lock().0, 0);
            assert_eq!(ledger.used.lock().1, 0);

            let ledger = Arc::new(ReceiveProbe::new(initial_chunk * 2));
            let memory = Arc::new(BlockMemory::new(ledger.clone()));
            let mut peer = make_peer(&block)?;
            peer.stream.max_read = 17;
            let end = peer.stream.pause_at;
            let refused = peer.read_message_bounded(&memory, || false);
            assert!(matches!(
                &refused,
                Err(PeerError::Io(error)) if error.kind() == std::io::ErrorKind::Other
            ));
            assert!(
                !refused
                    .as_ref()
                    .err()
                    .is_some_and(PeerError::is_misbehavior)
            );
            let received = usize::try_from(peer.stream.bytes.position())
                .map_err(|_| TestError::Missing("received position"))?;
            let received_body = received.saturating_sub(if index == 0 { 24 } else { 3 });
            assert!(
                received_body >= peer.stream.max_read,
                "receive refusal must follow admission of the first short body read"
            );
            assert!(received <= initial_chunk + crate::wire::HEADER_LEN);
            assert!(received < end);
            assert_eq!(ledger.used.lock().1, 0);
            assert_eq!(ledger.used.lock().0, 0);
        }
        Ok(())
    }

    // BUD-01, BUD-07
    #[test]
    fn raw_admission_refuses_before_reading_body_and_recovers_after_release() -> TestResult {
        for (index, make_peer) in [legacy_receive_peer, encrypted_receive_peer]
            .into_iter()
            .enumerate()
        {
            let memory = Arc::new(BlockMemory::default());
            let held = memory.reserve_receive(memory.ledger().receive_capacity())?;
            let mut peer = make_peer()?;
            let result = peer.read_message_bounded(&memory, || false);
            assert!(
                matches!(&result, Err(PeerError::Io(error)) if error.kind() == std::io::ErrorKind::Other)
            );
            assert_eq!(
                peer.stream.bytes.position(),
                if index == 0 { 24 } else { 3 }
            );
            assert_eq!(*memory.used.lock(), memory.ledger().receive_capacity());
            drop(held);
            drop(peer);
            let mut peer = make_peer()?;
            drop(
                peer.read_message_bounded(&memory, || false)?
                    .ok_or(TestError::Missing("block after release"))?,
            );
            assert_eq!(*memory.used.lock(), 0);
        }
        Ok(())
    }

    // P2P-01, BUD-07
    #[test]
    fn image_pressure_does_not_hide_pre_handshake_blocks() -> TestResult {
        for make_peer in [legacy_receive_peer, encrypted_receive_peer] {
            let memory = Arc::new(BlockMemory::default());
            let _held = memory.reserve(memory.ledger().capacity(), || false)?;
            let mut peer = make_peer()?;
            let end = peer.stream.pause_at;
            peer.stream.pause_at = 0;
            assert!(
                matches!(peer.read_message_bounded(&memory, || false), Err(PeerError::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut)
            );
            peer.stream.pause_at = end;
            let state = peer.state;
            let result = peer.read_message_admitted(
                |command, _| {
                    assert_eq!(command, "block");
                    crate::fsm::require_ready(state)
                },
                |_, _| panic!("a pre-handshake block cannot reserve decoder memory"),
            );
            assert!(result.as_ref().err().is_some_and(PeerError::is_misbehavior));
            assert_eq!(*memory.used.lock(), memory.ledger().capacity());
        }
        Ok(())
    }

    // BUD-07
    #[test]
    fn decode_admission_refuses_without_waiting_on_retained_raw_memory() -> TestResult {
        for make_peer in [legacy_receive_peer, encrypted_receive_peer] {
            let memory = Arc::new(BlockMemory::default());
            let held = memory.reserve(memory.ledger().capacity(), || false)?;
            let (sender, receiver) = crossbeam_channel::bounded(1);
            let peer = make_peer()?;
            std::thread::scope(|scope| -> TestResult {
                let memory = Arc::clone(&memory);
                let worker = scope.spawn(move || {
                    let mut peer = peer;
                    let result = peer.read_message_bounded(&memory, || false);
                    let _ = sender.send(result);
                });
                let result = receiver.recv_timeout(Duration::from_secs(5));
                drop(held);
                worker
                    .join()
                    .map_err(|_| TestError::Panicked("decoder waiter"))?;
                let refused = result?;
                assert!(matches!(&refused, Ok(None)), "{refused:?}");
                Ok(())
            })?;
            assert_eq!(*memory.used.lock(), 0);
        }
        Ok(())
    }

    #[test]
    fn bounded_receive_rejects_binding_an_uncharged_live_body() -> TestResult {
        for make_peer in [legacy_receive_peer, encrypted_receive_peer] {
            let memory = Arc::new(BlockMemory::default());
            let mut peer = make_peer()?;
            peer.stream.pause_at /= 2;
            assert!(
                matches!(peer.read_message(), Err(PeerError::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut)
            );
            let position = peer.stream.bytes.position();
            assert!(
                matches!(peer.read_message_bounded(&memory, || false), Err(PeerError::Io(error)) if error.kind() == std::io::ErrorKind::Other)
            );
            assert_eq!(peer.stream.bytes.position(), position);
            assert_eq!(*memory.used.lock(), 0);
        }
        Ok(())
    }
}
