#![expect(clippy::expect_used)]

use std::collections::VecDeque;
use std::io::{self, Read};
use std::time::{Duration, Instant};

use bitcoin::p2p::Magic;
use bitcoin::secp256k1::SecretKey;
use bitcoin::secp256k1::ellswift::ElligatorSwift;
use bitcoin::secp256k1::rand::rngs::StdRng;
use bitcoin::secp256k1::rand::{RngCore as _, SeedableRng as _};
use hkdf::Hkdf;
use proptest::prelude::*;
use sha2::Sha256;

use super::{
    ELLSWIFT_LEN, Established, Handshake, MAX_GARBAGE_LEN, State, Step, V1_PREFIX_LEN, encode_key,
};
use crate::bip324::TransportError;
use crate::bip324::keys::{GARBAGE_TERMINATOR_LEN, KeyMaterial, Role, Session, shared_secret};
use crate::bip324::packet::PacketError;
use crate::bip324::reader::{MAX_RECV_CONTENTS_LEN, is_poll_timeout};
use crate::transport::establish;
use crate::{PeerError, PeerLease};

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Packet(#[from] crate::bip324::packet::PacketError),
    #[error(transparent)]
    Transport(#[from] super::super::TransportError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Peer(#[from] crate::PeerError),
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    Hkdf(#[from] hkdf::InvalidLength),
    #[error("missing: {0}")]
    Missing(&'static str),
    #[error("unexpected step: {0}")]
    UnexpectedStep(String),
    #[error("unexpected v1 peer")]
    UnexpectedV1,
    #[error("handshake did not finish")]
    HandshakeIncomplete,
    #[error("decoys alone must not establish")]
    DecoysEstablished,
}

type TestResult = Result<(), TestError>;

const MAGIC: Magic = Magic::REGTEST;

#[derive(Default)]
struct Inbox {
    bytes: VecDeque<u8>,
    closed: bool,
    max_read: usize,
}

impl Read for Inbox {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.bytes.is_empty() {
            return if self.closed {
                Ok(0)
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            };
        }
        let limit = if self.max_read == 0 {
            buffer.len()
        } else {
            buffer.len().min(self.max_read)
        };
        let read = limit.min(self.bytes.len());
        for (slot, byte) in buffer.iter_mut().zip(self.bytes.drain(..read)) {
            *slot = byte;
        }
        Ok(read)
    }
}

struct Connected {
    initiator: Established,
    responder: Established,
    to_initiator: Inbox,
    to_responder: Inbox,
}

fn connect(
    seed: u64,
    max_read: usize,
    first_message: Option<&[u8]>,
) -> Result<Connected, TestError> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut initiator = Handshake::initiator(MAGIC, &mut rng);
    let mut responder = Handshake::responder(MAGIC, &mut rng);
    let mut to_initiator = Inbox {
        max_read,
        ..Inbox::default()
    };
    let mut to_responder = Inbox {
        max_read,
        ..Inbox::default()
    };
    let (mut done_initiator, mut done_responder) = (None, None);
    for _ in 0..1_000_000 {
        if done_initiator.is_none() {
            match initiator.advance(&mut to_initiator) {
                Ok(Step::Send) => to_responder.bytes.extend(initiator.take_outbound()),
                Ok(Step::Yield) => {}
                Ok(Step::Established(mut established)) => {
                    if let Some(message) = first_message {
                        to_responder
                            .bytes
                            .extend(established.send.seal(message, &[], false)?);
                    }
                    done_initiator = Some(*established);
                }
                Ok(Step::V1(_)) => return Err(TestError::UnexpectedV1),
                Err(error) if is_poll_timeout(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if done_responder.is_none() {
            match responder.advance(&mut to_responder) {
                Ok(Step::Send) => to_initiator.bytes.extend(responder.take_outbound()),
                Ok(Step::Yield) => {}
                Ok(Step::Established(established)) => done_responder = Some(*established),
                Ok(Step::V1(_)) => return Err(TestError::UnexpectedV1),
                Err(error) if is_poll_timeout(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if done_initiator.is_some() && done_responder.is_some() {
            break;
        }
    }
    match (done_initiator, done_responder) {
        (Some(initiator), Some(responder)) => Ok(Connected {
            initiator,
            responder,
            to_initiator,
            to_responder,
        }),
        _ => Err(TestError::HandshakeIncomplete),
    }
}

#[test]
fn handshakes_agree_on_a_session_and_carry_packets_both_ways() -> TestResult {
    let mut connected = connect(1, 0, Some(b"first"))?;
    assert_eq!(
        connected.initiator.session_id,
        connected.responder.session_id
    );

    let first = connected
        .responder
        .recv
        .read_contents(&mut connected.to_responder)?
        .ok_or_else(|| io::Error::other("the initiator's first packet"))?;
    assert_eq!(first.as_ref(), b"first");

    let reply = connected.responder.send.seal(b"reply", &[], false)?;
    connected.to_initiator.bytes.extend(reply);
    let received = connected
        .initiator
        .recv
        .read_contents(&mut connected.to_initiator)?
        .ok_or_else(|| io::Error::other("the responder's reply packet"))?;
    assert_eq!(received.as_ref(), b"reply");
    Ok(())
}

#[test]
fn handshakes_resume_through_single_byte_reads() -> TestResult {
    let mut connected = connect(2, 1, Some(b"after"))?;
    assert_eq!(
        connected.initiator.session_id,
        connected.responder.session_id
    );
    let first = connected
        .responder
        .recv
        .read_contents(&mut connected.to_responder)?
        .ok_or_else(|| io::Error::other("the initiator's packet"))?;
    assert_eq!(first.as_ref(), b"after");
    Ok(())
}

#[test]
fn established_reader_refuses_an_oversized_length_before_its_body() -> TestResult {
    let mut connected = connect(3, 0, None)?;
    let packet = connected
        .initiator
        .send
        .seal(&vec![0; MAX_RECV_CONTENTS_LEN + 1], &[], false)?;
    connected.to_responder.bytes.extend(&packet[..3]);
    let result = connected
        .responder
        .recv
        .read_contents(&mut connected.to_responder);
    assert!(
        matches!(result, Err(TransportError::PacketTooLarge(len)) if len == MAX_RECV_CONTENTS_LEN + 1),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn established_reader_rejects_a_tampered_packet() -> TestResult {
    let mut connected = connect(4, 0, None)?;
    let mut packet = connected.initiator.send.seal(b"payload", &[], false)?;
    let last = packet.len() - 1;
    packet[last] ^= 1;
    connected.to_responder.bytes.extend(packet);
    let result = connected
        .responder
        .recv
        .read_contents(&mut connected.to_responder);
    assert!(
        matches!(
            result,
            Err(TransportError::Packet(PacketError::AuthFailed(_)))
        ),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn responder_hands_a_v1_peer_back_after_sixteen_bytes() -> TestResult {
    let mut rng = StdRng::seed_from_u64(5);
    let mut responder = Handshake::responder(MAGIC, &mut rng);
    let mut header = MAGIC.to_bytes().to_vec();
    header.extend_from_slice(b"version\0\0\0\0\0");
    header.extend_from_slice(&[0x66, 0, 0, 0, 1, 2, 3, 4, 0xaa]);
    let mut inbox = Inbox {
        bytes: header.iter().copied().collect(),
        ..Inbox::default()
    };
    match responder.advance(&mut inbox)? {
        Step::V1(prefix) => assert_eq!(prefix[..], header[..V1_PREFIX_LEN]),
        other => return Err(TestError::UnexpectedStep(format!("{other:?}"))),
    }
    assert_eq!(
        responder.take_outbound(),
        Vec::<u8>::new(),
        "nothing was sent to a v1 peer"
    );
    assert_eq!(
        inbox.bytes.len(),
        header.len() - V1_PREFIX_LEN,
        "the rest is unread"
    );
    Ok(())
}

#[test]
fn responder_refuses_a_v1_version_from_another_network() {
    let mut rng = StdRng::seed_from_u64(6);
    let mut responder = Handshake::responder(MAGIC, &mut rng);
    let mut header = Magic::BITCOIN.to_bytes().to_vec();
    header.extend_from_slice(b"version\0\0\0\0\0");
    let mut inbox = Inbox {
        bytes: header.into_iter().collect(),
        ..Inbox::default()
    };
    assert!(matches!(
        responder.advance(&mut inbox),
        Err(TransportError::WrongNetworkV1)
    ));
    assert_eq!(responder.take_outbound(), Vec::<u8>::new());
}

#[test]
fn an_initiator_knows_whether_its_peer_answered() -> TestResult {
    let mut rng = StdRng::seed_from_u64(16);
    let mut silent = Handshake::initiator(MAGIC, &mut rng);
    let mut inbox = Inbox::default();
    assert!(matches!(silent.advance(&mut inbox)?, Step::Send));
    drop(silent.take_outbound());
    let stalled = silent.advance(&mut inbox);
    assert!(stalled.as_ref().is_err_and(is_poll_timeout), "{stalled:?}");
    inbox.closed = true;
    let closed = silent.advance(&mut inbox);
    assert!(
        matches!(&closed, Err(TransportError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof),
        "{closed:?}"
    );
    assert!(!silent.received_any());

    let mut answered = Handshake::initiator(MAGIC, &mut rng);
    drop(answered.take_outbound());
    let mut inbox = Inbox {
        bytes: VecDeque::from([0u8]),
        ..Inbox::default()
    };
    let stalled = answered.advance(&mut inbox);
    assert!(stalled.as_ref().is_err_and(is_poll_timeout), "{stalled:?}");
    assert!(answered.received_any());
    Ok(())
}

struct ScriptedInitiator {
    secret_key: SecretKey,
    ellswift: ElligatorSwift,
    garbage: Vec<u8>,
}

impl ScriptedInitiator {
    fn new(rng: &mut StdRng, garbage_len: usize) -> Self {
        let secret_key = SecretKey::new(rng);
        let mut aux = [0u8; 32];
        rng.fill_bytes(&mut aux);
        let mut garbage = vec![0u8; garbage_len];
        rng.fill_bytes(&mut garbage);
        Self {
            secret_key,
            ellswift: encode_key(secret_key, aux),
            garbage,
        }
    }

    fn open(&self, responder: &mut Handshake, inbox: &mut Inbox) -> Result<Session, TestError> {
        inbox.bytes.extend(self.ellswift.to_array());
        inbox.bytes.extend(&self.garbage);
        let mut sent = Vec::new();
        loop {
            match responder.advance(inbox) {
                Ok(Step::Send) => sent.extend(responder.take_outbound()),
                Err(error) if is_poll_timeout(&error) => break,
                other => return Err(TestError::UnexpectedStep(format!("{other:?}"))),
            }
        }
        let theirs: [u8; ELLSWIFT_LEN] = sent
            .get(..ELLSWIFT_LEN)
            .ok_or(TestError::Missing("responder sent no key"))?
            .try_into()?;
        let secret = shared_secret(
            self.secret_key,
            self.ellswift,
            ElligatorSwift::from_array(theirs),
            Role::Initiator,
        );
        Ok(Session::new(
            &KeyMaterial::derive(&secret, MAGIC)?,
            Role::Initiator,
        ))
    }
}

fn finish(
    responder: &mut Handshake,
    inbox: &mut Inbox,
    bytes: &[u8],
) -> Result<Step, TransportError> {
    inbox.bytes.extend(bytes);
    inbox.closed = true;
    loop {
        match responder.advance(inbox) {
            Ok(Step::Send) => drop(responder.take_outbound()),
            Ok(Step::Yield) => {}
            other => return other,
        }
    }
}

fn scripted(
    seed: u64,
    garbage_len: usize,
) -> Result<(ScriptedInitiator, Handshake, Inbox, Session), TestError> {
    let mut rng = StdRng::seed_from_u64(seed);
    let initiator = ScriptedInitiator::new(&mut rng, garbage_len);
    let mut responder = Handshake::responder(MAGIC, &mut rng);
    let mut inbox = Inbox::default();
    let session = initiator.open(&mut responder, &mut inbox)?;
    Ok((initiator, responder, inbox, session))
}

#[test]
fn the_largest_garbage_is_accepted() -> TestResult {
    let (initiator, mut responder, mut inbox, mut session) = scripted(7, MAX_GARBAGE_LEN)?;
    let mut tail = session.send_garbage_terminator.to_vec();
    tail.extend(session.send.seal(&[], &initiator.garbage, false)?);
    assert!(matches!(
        finish(&mut responder, &mut inbox, &tail)?,
        Step::Established(_)
    ));
    Ok(())
}

#[test]
fn the_smallest_garbage_zero_bytes_is_accepted() -> TestResult {
    let (initiator, mut responder, mut inbox, mut session) = scripted(6, 0)?;
    let mut tail = session.send_garbage_terminator.to_vec();
    tail.extend(session.send.seal(&[], &initiator.garbage, false)?);
    assert!(matches!(
        finish(&mut responder, &mut inbox, &tail)?,
        Step::Established(_)
    ));
    Ok(())
}

#[test]
fn garbage_beyond_the_limit_is_refused() -> TestResult {
    let (initiator, mut responder, mut inbox, mut session) = scripted(8, MAX_GARBAGE_LEN + 1)?;
    let mut tail = session.send_garbage_terminator.to_vec();
    tail.extend(session.send.seal(&[], &initiator.garbage, false)?);
    let result = finish(&mut responder, &mut inbox, &tail);
    assert!(
        matches!(result, Err(TransportError::TerminatorNotFound)),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn a_wrong_garbage_terminator_is_never_found() -> TestResult {
    let (initiator, mut responder, mut inbox, mut session) = scripted(9, 20)?;
    let mut tail = session.send_garbage_terminator.to_vec();
    tail[0] ^= 1;
    tail.extend(session.send.seal(&[], &initiator.garbage, false)?);
    tail.extend(vec![0u8; MAX_GARBAGE_LEN]);
    let result = finish(&mut responder, &mut inbox, &tail);
    assert!(
        matches!(result, Err(TransportError::TerminatorNotFound)),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn the_first_packet_must_authenticate_the_garbage_sent() -> TestResult {
    for aad in [Vec::new(), b"other garbage".to_vec()] {
        let (_, mut responder, mut inbox, mut session) = scripted(10, 30)?;
        let mut tail = session.send_garbage_terminator.to_vec();
        tail.extend(session.send.seal(&[], &aad, false)?);
        let result = finish(&mut responder, &mut inbox, &tail);
        assert!(
            matches!(
                result,
                Err(TransportError::Packet(PacketError::AuthFailed(_)))
            ),
            "aad {aad:?}: {result:?}"
        );
    }
    Ok(())
}

#[test]
fn version_contents_are_ignored() -> TestResult {
    let (initiator, mut responder, mut inbox, mut session) = scripted(11, 5)?;
    let mut tail = session.send_garbage_terminator.to_vec();
    tail.extend(
        session
            .send
            .seal(b"a future version", &initiator.garbage, false)?,
    );
    assert!(matches!(
        finish(&mut responder, &mut inbox, &tail)?,
        Step::Established(_)
    ));
    Ok(())
}

#[test]
fn decoys_before_the_version_packet_are_skipped() -> TestResult {
    let (initiator, mut responder, mut inbox, mut session) = scripted(12, 5)?;
    let mut tail = session.send_garbage_terminator.to_vec();
    tail.extend(session.send.seal(&[0; 100], &initiator.garbage, true)?);
    tail.extend(session.send.seal(&[0; 7], &[], true)?);
    tail.extend(session.send.seal(&[], &[], false)?);
    assert!(matches!(
        finish(&mut responder, &mut inbox, &tail)?,
        Step::Established(_)
    ));
    Ok(())
}

#[test]
fn each_decoy_before_the_version_yields_once() -> TestResult {
    let (initiator, mut responder, mut inbox, mut session) = scripted(17, 5)?;
    let mut wire = session.send_garbage_terminator.to_vec();
    wire.extend(session.send.seal(&[0; 100], &initiator.garbage, true)?);
    wire.extend(session.send.seal(&[0; 7], &[], true)?);
    let version = session.send.seal(&[], &[], false)?;
    inbox.bytes.extend(&wire);
    let mut yielded = 0;
    loop {
        match responder.advance(&mut inbox) {
            Ok(Step::Send) => drop(responder.take_outbound()),
            Ok(Step::Yield) => yielded += 1,
            Ok(Step::Established(_)) => return Err(TestError::DecoysEstablished),
            Ok(Step::V1(_)) => return Err(TestError::UnexpectedV1),
            Err(error) if is_poll_timeout(&error) => break,
            Err(error) => return Err(error.into()),
        }
    }
    assert_eq!(yielded, 2, "one yield per decoy packet");
    inbox.bytes.extend(version);
    inbox.closed = true;
    loop {
        match responder.advance(&mut inbox)? {
            Step::Send => drop(responder.take_outbound()),
            Step::Yield => yielded += 1,
            Step::Established(_) => break,
            Step::V1(_) => return Err(TestError::UnexpectedV1),
        }
    }
    assert_eq!(
        yielded, 2,
        "the version packet establishes without another yield"
    );
    Ok(())
}

struct DecoyDribble {
    blobs: Vec<Vec<u8>>,
    released: usize,
    consumed: usize,
    next_at: Instant,
    interval: Duration,
    pending: VecDeque<u8>,
    written: Vec<u8>,
}

impl DecoyDribble {
    fn new(blobs: Vec<Vec<u8>>, interval: Duration) -> Self {
        let mut dribble = Self {
            blobs,
            released: 0,
            consumed: 0,
            next_at: Instant::now() + interval,
            interval,
            pending: VecDeque::new(),
            written: Vec::new(),
        };
        dribble.release_one();
        dribble
    }

    fn release_one(&mut self) {
        let at = self.released;
        if at < self.blobs.len() {
            let blob = core::mem::take(&mut self.blobs[at]);
            self.pending.extend(blob);
            self.released = at + 1;
        }
    }
}

impl Read for DecoyDribble {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let now = Instant::now();
        while self.released < self.blobs.len() && now >= self.next_at {
            self.next_at += self.interval;
            self.release_one();
        }
        if self.pending.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let read = buffer.len().min(self.pending.len());
        for (slot, byte) in buffer.iter_mut().zip(self.pending.drain(..read)) {
            *slot = byte;
        }
        self.consumed += read;
        Ok(read)
    }
}

impl std::io::Write for DecoyDribble {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn decoys_never_hold_the_handshake_past_the_deadline() -> TestResult {
    let (initiator, mut responder, _, mut session) = scripted(18, 5)?;
    let mut blobs = vec![session.send_garbage_terminator.to_vec()];
    blobs.push(session.send.seal(&[0; 16], &initiator.garbage, true)?);
    for _ in 0..120 {
        blobs.push(session.send.seal(&[0; 16], &[], true)?);
    }
    let through_first_decoy = blobs[0].len() + blobs[1].len();
    let mut stream = DecoyDribble::new(blobs, Duration::from_millis(10));
    let lease = PeerLease::new(crossbeam_channel::unbounded().0);
    let started = Instant::now();
    let result = establish(
        &mut stream,
        &mut responder,
        MAGIC,
        &lease,
        started + Duration::from_millis(500),
    );
    assert!(
        matches!(&result, Err(PeerError::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut),
        "{result:?}"
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(400),
        "the handshake must wait out its deadline, not fail fast: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "decoys must not hold the handshake past its deadline"
    );
    assert!(responder.received_any(), "the decoys did arrive");
    assert!(
        stream.consumed > through_first_decoy,
        "the responder must have consumed a complete decoy past the terminator and yielded for the next: consumed {} of the first {through_first_decoy}",
        stream.consumed
    );
    Ok(())
}

#[test]
fn only_the_first_packet_carries_the_garbage_as_aad() -> TestResult {
    let (initiator, mut responder, mut inbox, mut session) = scripted(13, 5)?;
    let mut tail = session.send_garbage_terminator.to_vec();
    tail.extend(session.send.seal(&[0; 4], &initiator.garbage, true)?);
    tail.extend(session.send.seal(&[], &initiator.garbage, false)?);
    let result = finish(&mut responder, &mut inbox, &tail);
    assert!(
        matches!(
            result,
            Err(TransportError::Packet(PacketError::AuthFailed(_)))
        ),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn a_stream_cut_anywhere_never_establishes() -> TestResult {
    let (initiator, _, _, mut session) = scripted(14, 9)?;
    let mut stream = initiator.ellswift.to_array().to_vec();
    stream.extend(&initiator.garbage);
    stream.extend(session.send_garbage_terminator);
    stream.extend(session.send.seal(&[], &initiator.garbage, false)?);
    for cut in 0..stream.len() {
        let mut rng = StdRng::seed_from_u64(14);
        let _initiator = ScriptedInitiator::new(&mut rng, 9);
        let mut responder = Handshake::responder(MAGIC, &mut rng);
        let mut inbox = Inbox::default();
        let result = finish(&mut responder, &mut inbox, &stream[..cut]);
        assert!(
            matches!(&result, Err(TransportError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof),
            "cut at {cut}: {result:?}"
        );
    }
    let mut rng = StdRng::seed_from_u64(14);
    let _initiator = ScriptedInitiator::new(&mut rng, 9);
    let mut responder = Handshake::responder(MAGIC, &mut rng);
    assert!(matches!(
        finish(&mut responder, &mut Inbox::default(), &stream)?,
        Step::Established(_)
    ));
    Ok(())
}

fn bip324_proptest_cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|c| c.parse().ok())
        .unwrap_or(1024)
}

struct CustomParty {
    sk: SecretKey,
    aux: [u8; 32],
    garbage: Vec<u8>,
}

fn connect_custom(
    initiator: CustomParty,
    responder: CustomParty,
    max_read: usize,
) -> Result<(Established, Established), TestError> {
    let initiator_ellswift = encode_key(initiator.sk, initiator.aux);
    let responder_ellswift = encode_key(responder.sk, responder.aux);
    let mut initiator = Handshake {
        role: Role::Initiator,
        magic: MAGIC,
        secret_key: initiator.sk,
        ellswift: initiator_ellswift,
        garbage: initiator.garbage,
        outbound: Vec::new(),
        received_any: false,
        state: State::ReadKey {
            key: [0; ELLSWIFT_LEN],
            filled: 0,
        },
    };
    initiator.queue_key();
    let mut responder = Handshake {
        role: Role::Responder,
        magic: MAGIC,
        secret_key: responder.sk,
        ellswift: responder_ellswift,
        garbage: responder.garbage,
        outbound: Vec::new(),
        received_any: false,
        state: State::DetectV1 {
            prefix: [0; V1_PREFIX_LEN],
            filled: 0,
        },
    };
    let mut to_initiator = Inbox {
        max_read,
        ..Inbox::default()
    };
    let mut to_responder = Inbox {
        max_read,
        ..Inbox::default()
    };
    let (mut done_initiator, mut done_responder) = (None, None);
    for _ in 0..1_000_000 {
        if done_initiator.is_none() {
            match initiator.advance(&mut to_initiator) {
                Ok(Step::Send) => to_responder.bytes.extend(initiator.take_outbound()),
                Ok(Step::Yield) => {}
                Ok(Step::Established(established)) => done_initiator = Some(*established),
                Ok(Step::V1(_)) => return Err(TestError::UnexpectedV1),
                Err(error) if is_poll_timeout(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if done_responder.is_none() {
            match responder.advance(&mut to_responder) {
                Ok(Step::Send) => to_initiator.bytes.extend(responder.take_outbound()),
                Ok(Step::Yield) => {}
                Ok(Step::Established(established)) => done_responder = Some(*established),
                Ok(Step::V1(_)) => return Err(TestError::UnexpectedV1),
                Err(error) if is_poll_timeout(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if done_initiator.is_some() && done_responder.is_some() {
            break;
        }
    }
    match (done_initiator, done_responder) {
        (Some(i), Some(r)) => Ok((i, r)),
        _ => Err(TestError::HandshakeIncomplete),
    }
}

/// Official BIP324 packet test vectors (mainnet magic), rows 1 and 999 of
/// `packet_encoding_test_vectors.csv`, as embedded in Bitcoin Core
/// `src/test/bip324_tests.cpp`. The expected values come from the vectors, so
/// the oracle stays independent of the production derivation.
#[test]
fn bip324_session_id_matches_official_packet_test_vectors() {
    const MAINNET_MAGIC_BYTES: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

    struct PacketVector {
        privkey: [u8; 32],
        ellswift_ours: [u8; 64],
        ellswift_theirs: [u8; 64],
        initiating: bool,
        session_id: [u8; 32],
        send_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
        recv_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    }

    struct PacketVectorFixture {
        privkey: &'static str,
        ellswift_ours: &'static str,
        ellswift_theirs: &'static str,
        initiating: bool,
        session_id: &'static str,
        send_garbage_terminator: &'static str,
        recv_garbage_terminator: &'static str,
    }

    fn fixture_bytes(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|index| {
                u8::from_str_radix(&text[2 * index..2 * index + 2], 16)
                    .expect("fixture hex decodes")
            })
            .collect()
    }

    fn fixture_array<const LEN: usize>(text: &str) -> [u8; LEN] {
        let bytes = fixture_bytes(text);
        let array = <[u8; LEN]>::try_from(bytes.as_slice()).expect("fixture hex length");
        array
    }

    fn decode_fixture(text: &str) -> String {
        text.chars().filter(|ch| *ch != '_').collect()
    }

    let fixtures = [
        PacketVectorFixture {
            privkey: "61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7",
            ellswift_ours: "ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa1_\
                            86f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b",
            ellswift_theirs: "a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafa_\
                              ffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5",
            initiating: true,
            session_id: "ce72dffb015da62b0d0f5474cab8bc72605225b0cee3f62312ec680ec5f41ba5",
            send_garbage_terminator: "faef555dfcdb936425d84aba524758f3",
            recv_garbage_terminator: "02cb8ff24307a6e27de3b4e7ea3fa65b",
        },
        PacketVectorFixture {
            privkey: "6f312890ec83bbb26798abaadd574684a53e74ccef7953b790fcc29409080246",
            ellswift_ours: "a8785af31c029efc82fa9fc677d7118031358d7c6a25b5779a9b900e5ccd94aa_\
                            c97eb36a3c5dbcdb2ca5843cc4c2fe0aaa46d10eb3d233a81c3dde476da00eef",
            ellswift_theirs: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_\
                              0000000000000000000000000000000000000000000000000000000000000000",
            initiating: false,
            session_id: "b0490e26111cb2d55bbff2ace00f7f644f64006539abb4e7513f05107bb10608",
            send_garbage_terminator: "44737108aec5f8b6c1c277b31bbce9c1",
            recv_garbage_terminator: "ca29b3a35237f8212bd13ed187a1da2e",
        },
    ];

    for (index, fixture) in fixtures.iter().enumerate() {
        let expected = PacketVector {
            privkey: fixture_array(&decode_fixture(fixture.privkey)),
            ellswift_ours: fixture_array(&decode_fixture(fixture.ellswift_ours)),
            ellswift_theirs: fixture_array(&decode_fixture(fixture.ellswift_theirs)),
            initiating: fixture.initiating,
            session_id: fixture_array(&decode_fixture(fixture.session_id)),
            send_garbage_terminator: fixture_array(&decode_fixture(
                fixture.send_garbage_terminator,
            )),
            recv_garbage_terminator: fixture_array(&decode_fixture(
                fixture.recv_garbage_terminator,
            )),
        };
        let secret_key = SecretKey::from_slice(&expected.privkey).expect("vector key is valid");
        let role = if expected.initiating {
            Role::Initiator
        } else {
            Role::Responder
        };
        let shared = shared_secret(
            secret_key,
            ElligatorSwift::from_array(expected.ellswift_ours),
            ElligatorSwift::from_array(expected.ellswift_theirs),
            role,
        );

        let mut salt = Vec::with_capacity(28);
        salt.extend_from_slice(b"bitcoin_v2_shared_secret");
        salt.extend_from_slice(&MAINNET_MAGIC_BYTES);
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &shared);
        let mut session_id = [0u8; 32];
        hkdf.expand(b"session_id", &mut session_id)
            .expect("32-byte expand");
        let mut terminators = [0u8; 2 * GARBAGE_TERMINATOR_LEN];
        hkdf.expand(b"garbage_terminators", &mut terminators)
            .expect("32-byte expand");
        let (send, recv) = if expected.initiating {
            let (send, recv) = terminators.split_at(GARBAGE_TERMINATOR_LEN);
            (send, recv)
        } else {
            let (recv, send) = terminators.split_at(GARBAGE_TERMINATOR_LEN);
            (send, recv)
        };

        assert_eq!(
            session_id, expected.session_id,
            "independent BIP324 key schedule must reproduce the official session id (vector {index})"
        );
        assert_eq!(
            send, expected.send_garbage_terminator,
            "independent key schedule must reproduce the send garbage terminator (vector {index})"
        );
        assert_eq!(
            recv, expected.recv_garbage_terminator,
            "independent key schedule must reproduce the receive garbage terminator (vector {index})"
        );

        let material = KeyMaterial::derive(&shared, Magic::from_bytes(MAINNET_MAGIC_BYTES))
            .expect("production derivation succeeds");
        assert_eq!(
            material.session_id, expected.session_id,
            "production derivation must match the official session id (vector {index})"
        );
        let session = Session::new(&material, role);
        assert_eq!(
            session.session_id, expected.session_id,
            "established session id must match the official session id (vector {index})"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: bip324_proptest_cases(), ..ProptestConfig::default() })]

    #[test]
    fn bip324_in_memory_handshake_establishes_and_agrees_with_spec_oracle(
        init_seed in any::<u64>(),
        resp_seed in any::<u64>(),
        init_garbage_len in prop_oneof![
            Just(0usize), Just(1), Just(15), Just(16), Just(64), Just(4094), Just(4095), 0..=4095usize
        ],
        resp_garbage_len in prop_oneof![
            Just(0usize), Just(1), Just(15), Just(16), Just(64), Just(4094), Just(4095), 0..=4095usize
        ],
        max_read in prop_oneof![
            Just(0usize), Just(1), Just(2), Just(7), Just(16), Just(64), Just(256)
        ],
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut init_rng = StdRng::seed_from_u64(init_seed);
        let init_sk = SecretKey::new(&mut init_rng);
        let mut init_aux = [0u8; 32];
        init_rng.fill_bytes(&mut init_aux);
        let mut init_garbage = vec![0u8; init_garbage_len];
        init_rng.fill_bytes(&mut init_garbage);

        let mut resp_rng = StdRng::seed_from_u64(resp_seed);
        let resp_sk = SecretKey::new(&mut resp_rng);
        let mut resp_aux = [0u8; 32];
        resp_rng.fill_bytes(&mut resp_aux);
        let mut resp_garbage = vec![0u8; resp_garbage_len];
        resp_rng.fill_bytes(&mut resp_garbage);

        let init_ellswift = encode_key(init_sk, init_aux);
        let resp_ellswift = encode_key(resp_sk, resp_aux);

        let secret = shared_secret(init_sk, init_ellswift, resp_ellswift, Role::Initiator);
        let material = KeyMaterial::derive(&secret, MAGIC).expect("valid key material derivation");
        let expected_session = Session::new(&material, Role::Initiator);
        let (mut init_est, mut resp_est) = connect_custom(
            CustomParty {
                sk: init_sk,
                aux: init_aux,
                garbage: init_garbage,
            },
            CustomParty {
                sk: resp_sk,
                aux: resp_aux,
                garbage: resp_garbage,
            },
            max_read,
        ).expect("handshake must establish");

        prop_assert_eq!(init_est.session_id, resp_est.session_id, "initiator and responder session IDs must match");
        prop_assert_eq!(init_est.session_id, expected_session.session_id, "session ID must match BIP324 specification oracle");

        let mut pipe = Inbox { max_read, ..Inbox::default() };
        let sealed = init_est.send.seal(&payload, &[], false).expect("initiator seals packet");
        pipe.bytes.extend(sealed);
        let decrypted = resp_est.recv.read_contents(&mut pipe).expect("responder reads packet");
        prop_assert_eq!(decrypted.as_deref(), Some(payload.as_slice()), "decrypted payload must match sent payload");

        let mut reverse_pipe = Inbox { max_read, ..Inbox::default() };
        let reply_sealed = resp_est.send.seal(&payload, &[], false).expect("responder seals packet");
        reverse_pipe.bytes.extend(reply_sealed);
        let reply_decrypted = init_est.recv.read_contents(&mut reverse_pipe).expect("initiator reads packet");
        prop_assert_eq!(reply_decrypted.as_deref(), Some(payload.as_slice()), "reverse decrypted payload must match sent payload");
    }

    #[test]
    fn bip324_handshake_rejects_corrupted_and_boundary_violating_inputs(
        seed in any::<u64>(),
        mode in 0..5u8,
        garbage_len in prop_oneof![Just(0usize), Just(1), Just(64), Just(4095)],
        mutate_byte_idx in 0..64usize,
        raw_bytes in prop::collection::vec(any::<u8>(), 0..6_000),
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        match mode {
            0 => {
                let mut responder = Handshake::responder(MAGIC, &mut rng);
                let result = finish(&mut responder, &mut Inbox::default(), &raw_bytes);
                prop_assert!(!matches!(result, Ok(Step::Established(_))), "hostile bytes must never establish: {result:?}");
            }
            1 => {
                let initiator = ScriptedInitiator::new(&mut rng, garbage_len);
                let mut responder = Handshake::responder(MAGIC, &mut rng);
                let mut inbox = Inbox::default();
                let mut session = initiator.open(&mut responder, &mut inbox).expect("initiator opens");
                let mut tail = session.send_garbage_terminator.to_vec();
                tail.extend(session.send.seal(&[], &initiator.garbage, false).expect("seal version"));
                let idx = mutate_byte_idx % GARBAGE_TERMINATOR_LEN;
                tail[idx] ^= 0x55;
                tail.extend(vec![0u8; MAX_GARBAGE_LEN]);
                let result = finish(&mut responder, &mut inbox, &tail);
                prop_assert!(
                    matches!(result, Err(TransportError::TerminatorNotFound)),
                    "mutated terminator must fail terminator scan: {result:?}"
                );
            }
            2 => {
                let initiator = ScriptedInitiator::new(&mut rng, garbage_len);
                let mut responder = Handshake::responder(MAGIC, &mut rng);
                let mut inbox = Inbox::default();
                let mut session = initiator.open(&mut responder, &mut inbox).expect("initiator opens");
                let mut tail = session.send_garbage_terminator.to_vec();
                let mut version_packet = session.send.seal(&[], &initiator.garbage, false).expect("seal version");
                let idx = mutate_byte_idx % version_packet.len();
                version_packet[idx] ^= 0xaa;
                tail.extend(version_packet);
                let result = finish(&mut responder, &mut inbox, &tail);
                prop_assert!(
                    !matches!(result, Ok(Step::Established(_))),
                    "mutated version packet must fail authentication and not establish: {result:?}"
                );
            }
            3 => {
                let mut prefix = [0u8; 16];
                let magic_bytes = if mutate_byte_idx % 2 == 0 {
                    MAGIC.to_bytes()
                } else {
                    [0xde, 0xad, 0xbe, 0xef]
                };
                prefix[..4].copy_from_slice(&magic_bytes);
                prefix[4..].copy_from_slice(b"version\0\0\0\0\0");
                let mut responder = Handshake::responder(MAGIC, &mut rng);
                let result = finish(&mut responder, &mut Inbox::default(), &prefix);
                if magic_bytes == MAGIC.to_bytes() {
                    prop_assert!(matches!(result, Ok(Step::V1(_))), "matching magic version prefix must detect V1 fallback");
                } else {
                    prop_assert!(matches!(result, Err(TransportError::WrongNetworkV1)), "wrong magic version prefix must reject WrongNetworkV1");
                }
            }
            _ => {
                let extra = 1 + (mutate_byte_idx % 100);
                let initiator = ScriptedInitiator::new(&mut rng, MAX_GARBAGE_LEN + extra);
                let mut responder = Handshake::responder(MAGIC, &mut rng);
                let mut inbox = Inbox::default();
                match initiator.open(&mut responder, &mut inbox) {
                    Ok(mut session) => {
                        let mut tail = session.send_garbage_terminator.to_vec();
                        tail.extend(session.send.seal(&[], &initiator.garbage, false).expect("seal version"));
                        let result = finish(&mut responder, &mut inbox, &tail);
                        prop_assert!(
                            matches!(result, Err(TransportError::TerminatorNotFound)),
                            "garbage beyond limit in finish must fail with TerminatorNotFound: {result:?}"
                        );
                    }
                    Err(TestError::UnexpectedStep(err)) => {
                        prop_assert!(
                            err.contains("TerminatorNotFound"),
                            "garbage beyond limit in open must fail with TerminatorNotFound: {err}"
                        );
                    }
                    Err(other) => {
                        return Err(proptest::test_runner::TestCaseError::fail(format!(
                            "unexpected error for oversized garbage: {other:?}"
                        )));
                    }
                }
            }
        }
    }
}
