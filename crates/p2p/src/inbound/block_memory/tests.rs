use super::*;
use crate::Message;
use crate::peer::Peer;
use bitcoin::p2p::Magic;
use bitcoin_rs_primitives::{BlockPayload, Network, varint};
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
        assert!(waiting.join().map_err(|_| "waiter panicked")?.is_err());
        Ok(())
    })?;
    assert_eq!(*memory.used.lock(), BLOCK_INGRESS_BYTES);
    Ok(())
}

#[test]
fn an_underestimated_bound_is_a_local_error_and_keeps_the_original_credit() -> TestResult {
    let memory = Arc::new(BlockMemory::default());
    let mut credit = memory.reserve(64, || false)?;
    let error = credit
        .retain(65)
        .err()
        .ok_or("underestimated allocation must be refused")?;
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
    let reservation = bitcoin_rs_primitives::layout::decode_reservation(crate::wire::MAX_MESSAGE_PAYLOAD);
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
        // The waiter must observe cancellation without receiving any memory.
        entered_rx.recv_timeout(Duration::from_secs(5))?;
        cancelled.store(true, Ordering::Release);
        assert!(waiting.join().map_err(|_| "waiter panicked")?.is_err());
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
        drop(waiting.join().map_err(|_| "waiter panicked")??);
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
        &Message::BlockPayload(bytes.into()),
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
        .ok_or("missing ping")?;
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
        .ok_or("missing block")?;
    let Message::Block(payload) = message else {
        return Err("missing block message".into());
    };
    assert_eq!(payload.block().txs[0].inputs[0].witness.len(), 3_998_852);
    let retained = payload.bytes().len() + payload.block().retained_heap_bytes();
    assert_eq!(*memory.used.lock(), retained);
    let mut inbound = crate::InboundBlock::new(payload, None, None);
    inbound.memory_credit = credit;
    let (sender, receiver) = crossbeam_channel::bounded(1);
    sender.send(inbound).map_err(|_| "queue closed")?;
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
    // A subsequent ordinary block still decodes and its permit releases.
    let mut frame = Vec::new();
    crate::wire::write_message(
        &mut frame,
        Magic::REGTEST,
        &Message::Block(BlockPayload::from_local(Network::Regtest.genesis_block())),
    )?;
    let mut peer = Peer::new(Cursor::new(frame), Magic::REGTEST);
    drop(peer.read_message_bounded(&memory, || false)?);
    assert_eq!(*memory.used.lock(), 0);
    Ok(())
}
