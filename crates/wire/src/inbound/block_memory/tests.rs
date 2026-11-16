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
fn witness_amplification_is_reserved_before_decode_and_retained_through_queue_drop() -> TestResult {
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
            recv: crate::transport::RecvTransport::V2(Box::new(crate::bip324::PacketReader::new(
                crate::bip324::RecvCipher::new([1; 32], [2; 32]),
                Vec::new(),
            ))),
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
        let competing = memory.reserve_receive(capacity);
        assert!(
            matches!(&competing, Err(error) if error.kind() == std::io::ErrorKind::Other),
            "a live raw slice must own quota"
        );
        drop(memory.try_reserve(memory.ledger().capacity())?);
        drop(retained);
        drop(memory.reserve_receive(capacity)?);
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
}

impl ReceiveProbe {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            used: Mutex::new((0, 0, 0)),
            released: Condvar::new(),
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
}

#[test]
fn receive_capacity_and_growth_overlap_are_admitted_before_consuming_more_bytes() -> TestResult {
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
        let (image, retained_capacity, peak) = *ledger.used.lock();
        assert_eq!(image, 0);
        assert!(retained_capacity > initial_chunk);
        assert!(
            retained_capacity > raw.len(),
            "spare allocation capacity stays charged"
        );
        assert!(
            peak > retained_capacity,
            "old and new allocations overlap during growth"
        );
        drop(raw);
        assert_eq!(ledger.used.lock().1, 0);

        let ledger = Arc::new(ReceiveProbe::new(retained_capacity));
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
            received_body > initial_chunk,
            "refusal must follow admission and consumption of the initial body chunk"
        );
        assert!(received < end);
        assert_eq!(ledger.used.lock().1, 0);
        assert_eq!(ledger.used.lock().0, 0);
    }
    Ok(())
}

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
            assert!(
                matches!(&refused, Err(PeerError::Io(error)) if error.kind() == std::io::ErrorKind::Other)
            );
            assert!(
                !refused
                    .as_ref()
                    .err()
                    .is_some_and(PeerError::is_misbehavior)
            );
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
