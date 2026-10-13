use std::collections::VecDeque;
use std::error::Error;
use std::io::{self, Read};

use bitcoin::p2p::Magic;
use bitcoin::secp256k1::SecretKey;
use bitcoin::secp256k1::ellswift::ElligatorSwift;
use bitcoin::secp256k1::rand::rngs::StdRng;
use bitcoin::secp256k1::rand::{RngCore as _, SeedableRng as _};
use proptest::prelude::*;

use super::{
    ELLSWIFT_LEN, Established, Handshake, MAX_GARBAGE_LEN, Step, V1_PREFIX_LEN, encode_key,
};
use crate::bip324::TransportError;
use crate::bip324::keys::{KeyMaterial, Role, Session, shared_secret};
use crate::bip324::packet::PacketError;
use crate::bip324::reader::{MAX_RECV_CONTENTS_LEN, is_poll_timeout};

type TestResult = Result<(), Box<dyn Error>>;

const MAGIC: Magic = Magic::REGTEST;

/// Bytes in flight toward one side. An empty inbox reads as a poll timeout,
/// a closed and empty one as end of stream.
#[derive(Default)]
struct Inbox {
    bytes: VecDeque<u8>,
    closed: bool,
    /// Largest read served; zero serves whatever is asked.
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

/// A connected initiator and responder, with the bytes each still has to read.
struct Connected {
    initiator: Established,
    responder: Established,
    to_initiator: Inbox,
    to_responder: Inbox,
}

/// Runs both handshakes to completion, carrying every send to the other side.
/// `first_message` is sealed by the initiator the moment it is established,
/// before the responder has read the initiator's version packet.
fn connect(
    seed: u64,
    max_read: usize,
    first_message: Option<&[u8]>,
) -> Result<Connected, Box<dyn Error>> {
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
                Ok(Step::Established(mut established)) => {
                    if let Some(message) = first_message {
                        to_responder
                            .bytes
                            .extend(established.send.seal(message, &[], false)?);
                    }
                    done_initiator = Some(*established);
                }
                Ok(Step::V1(_)) => return Err("initiator reported a v1 peer".into()),
                Err(error) if is_poll_timeout(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if done_responder.is_none() {
            match responder.advance(&mut to_responder) {
                Ok(Step::Send) => to_initiator.bytes.extend(responder.take_outbound()),
                Ok(Step::Established(established)) => done_responder = Some(*established),
                Ok(Step::V1(_)) => return Err("responder reported a v1 peer".into()),
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
        _ => Err("handshake did not finish".into()),
    }
}

#[test]
fn handshakes_agree_on_a_session_and_carry_packets_both_ways() -> TestResult {
    let mut connected = connect(1, 0, Some(b"first"))?;
    assert_eq!(
        connected.initiator.session_id,
        connected.responder.session_id
    );

    // The initiator's first packet followed its version packet without a
    // pause; the handshake left it unread for the established reader.
    let first = connected
        .responder
        .recv
        .read_contents(&mut connected.to_responder)?;
    assert_eq!(first.as_ref(), b"first");

    let reply = connected.responder.send.seal(b"reply", &[], false)?;
    connected.to_initiator.bytes.extend(reply);
    let received = connected
        .initiator
        .recv
        .read_contents(&mut connected.to_initiator)?;
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
        .read_contents(&mut connected.to_responder)?;
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
    // Only the length field is delivered: the refusal must not wait for the body.
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
        other => return Err(format!("expected v1, got {other:?}").into()),
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
    // A peer that closes without a byte: the initiator may retry as v1.
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

    // One byte is an answer, so a later failure must not fall back.
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

/// A hand-driven initiator whose garbage, terminator, AAD, decoys, and version
/// contents each test chooses: the misbehaviours of Bitcoin Core's
/// `p2p_v2_misbehaving.py`.
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

    /// Opens `responder` with this initiator's key and garbage, and returns
    /// the initiator's session once the responder waits for its terminator.
    fn open(
        &self,
        responder: &mut Handshake,
        inbox: &mut Inbox,
    ) -> Result<Session, Box<dyn Error>> {
        inbox.bytes.extend(self.ellswift.to_array());
        inbox.bytes.extend(&self.garbage);
        let mut sent = Vec::new();
        loop {
            match responder.advance(inbox) {
                Ok(Step::Send) => sent.extend(responder.take_outbound()),
                Err(error) if is_poll_timeout(&error) => break,
                other => return Err(format!("responder left the handshake: {other:?}").into()),
            }
        }
        let theirs: [u8; ELLSWIFT_LEN] = sent
            .get(..ELLSWIFT_LEN)
            .ok_or("responder sent no key")?
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

/// Feeds `bytes` after the initiator's garbage and reports where the
/// responder's handshake ends.
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
            other => return other,
        }
    }
}

fn scripted(
    seed: u64,
    garbage_len: usize,
) -> Result<(ScriptedInitiator, Handshake, Inbox, Session), Box<dyn Error>> {
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
        // The same seed rebuilds the responder whose key the stream answers.
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Arbitrary bytes from an unauthenticated peer end the handshake as v1 or
    /// as an error, never as a session, and never panic.
    #[test]
    fn hostile_bytes_never_establish(bytes in prop::collection::vec(any::<u8>(), 0..6_000)) {
        let mut rng = StdRng::seed_from_u64(15);
        let mut responder = Handshake::responder(MAGIC, &mut rng);
        let result = finish(&mut responder, &mut Inbox::default(), &bytes);
        prop_assert!(!matches!(result, Ok(Step::Established(_))), "{result:?}");
    }
}
