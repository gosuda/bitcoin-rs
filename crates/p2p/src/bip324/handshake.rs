//! The BIP324 handshake as a resumable state machine over a blocking stream.
//!
//! The driver alternates two calls: [`Handshake::take_outbound`] for bytes
//! to send, and [`Handshake::advance`] to read. `advance` reads only the bytes
//! the handshake needs: never past the peer's version packet, so the first
//! application packet stays in the stream for the established reader. A poll
//! timeout returns with all progress kept.

use std::io::Read;

use bitcoin::p2p::Magic;
use bitcoin::secp256k1::ellswift::ElligatorSwift;
use bitcoin::secp256k1::rand::Rng;
use bitcoin::secp256k1::{Secp256k1, SecretKey};

use super::TransportError;
use super::keys::{GARBAGE_TERMINATOR_LEN, KeyMaterial, Role, Session, shared_secret};
use super::packet::{RecvCipher, SendCipher};
use super::reader::{PacketReader, is_poll_timeout};
use crate::recv::{fill, read_up_to};

/// Bytes of an `ElligatorSwift` public key encoding.
const ELLSWIFT_LEN: usize = 64;

/// Most garbage either side may send before its garbage terminator.
const MAX_GARBAGE_LEN: usize = 4095;

/// Bytes a responder compares against a v1 `version` header.
const V1_PREFIX_LEN: usize = 16;

/// The command field of a v1 `version` header.
const V1_VERSION_COMMAND: &[u8; 12] = b"version\0\0\0\0\0";

/// What one call to [`Handshake::advance`] reached.
#[derive(Debug)]
pub(crate) enum Step {
    /// Bytes are queued: send [`Handshake::take_outbound`], then advance again.
    Send,
    /// The responder's peer speaks v1; these are the first bytes of its
    /// `version` message.
    V1([u8; V1_PREFIX_LEN]),
    /// A decoy packet was consumed while reading the version; the caller may
    /// recheck its lease and deadline before the next advance.
    Yield,
    /// The encrypted session is ready.
    Established(Box<Established>),
}

/// An established BIP324 session.
#[derive(Debug)]
pub(crate) struct Established {
    pub(crate) send: SendCipher,
    pub(crate) recv: PacketReader,
    pub(crate) session_id: [u8; 32],
}

/// One side of a BIP324 handshake.
#[derive(Debug)]
pub(crate) struct Handshake {
    role: Role,
    magic: Magic,
    secret_key: SecretKey,
    ellswift: ElligatorSwift,
    garbage: Vec<u8>,
    outbound: Vec<u8>,
    received_any: bool,
    state: State,
}

#[derive(Debug)]
enum State {
    /// Responder: the first bytes decide between v1 and v2.
    DetectV1 {
        prefix: [u8; V1_PREFIX_LEN],
        filled: usize,
    },
    /// The peer's `ElligatorSwift` key.
    ReadKey {
        key: [u8; ELLSWIFT_LEN],
        filled: usize,
    },
    /// The peer's garbage, up to and including its garbage terminator.
    ScanTerminator {
        send: SendCipher,
        recv: RecvCipher,
        terminator: [u8; GARBAGE_TERMINATOR_LEN],
        session_id: [u8; 32],
        scanned: Vec<u8>,
    },
    /// Decoys, then the peer's version packet.
    ReadVersion {
        send: SendCipher,
        recv: PacketReader,
        session_id: [u8; 32],
    },
    /// The handshake ended, in a session, a v1 handoff, or an error.
    Finished,
}

impl Handshake {
    /// Opens a handshake on an outbound connection; its key and garbage are
    /// queued at once.
    pub(crate) fn initiator<G: Rng + ?Sized>(magic: Magic, rng: &mut G) -> Self {
        let mut handshake = Self::new(
            Role::Initiator,
            magic,
            rng,
            State::ReadKey {
                key: [0; ELLSWIFT_LEN],
                filled: 0,
            },
        );
        handshake.queue_key();
        handshake
    }

    /// Answers an inbound connection. Nothing is sent until the first bytes
    /// rule out a v1 peer.
    pub(crate) fn responder<G: Rng + ?Sized>(magic: Magic, rng: &mut G) -> Self {
        Self::new(
            Role::Responder,
            magic,
            rng,
            State::DetectV1 {
                prefix: [0; V1_PREFIX_LEN],
                filled: 0,
            },
        )
    }

    fn new<G: Rng + ?Sized>(role: Role, magic: Magic, rng: &mut G, state: State) -> Self {
        let secret_key = SecretKey::new(rng);
        let mut aux = [0u8; 32];
        rng.fill_bytes(&mut aux);
        let mut garbage = vec![0u8; rng.gen_range(0..=MAX_GARBAGE_LEN)];
        rng.fill_bytes(&mut garbage);
        Self {
            role,
            magic,
            secret_key,
            ellswift: encode_key(secret_key, aux),
            garbage,
            outbound: Vec::new(),
            received_any: false,
            state,
        }
    }

    /// Bytes to send before the next [`Self::advance`]; empty when none.
    pub(crate) fn take_outbound(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outbound)
    }

    /// Whether any byte has arrived from the peer. An initiator whose peer
    /// closed without sending anything may retry the connection as v1.
    pub(crate) const fn received_any(&self) -> bool {
        self.received_any
    }

    /// Reads toward the next step. A poll-timeout I/O error keeps all
    /// progress; any other error ends the handshake. [`Step::Yield`] hands
    /// control back after one decoy packet, leaving the handshake to resume.
    pub(crate) fn advance<R: Read>(&mut self, reader: &mut R) -> Result<Step, TransportError> {
        loop {
            if !self.outbound.is_empty() {
                return Ok(Step::Send);
            }
            let mut received = false;
            let mut counting = CountingReader {
                inner: &mut *reader,
                received: &mut received,
            };
            let stepped = self.step(&mut counting);
            self.received_any |= received;
            match stepped {
                // A decoy leaves the handshake running: only `Established` and
                // the v1 handoff end it, so `advance` may resume after a yield.
                Ok(Some(Step::Yield)) => return Ok(Step::Yield),
                Ok(Some(step)) => {
                    self.state = State::Finished;
                    return Ok(step);
                }
                Ok(None) => {}
                Err(error) => {
                    if !is_poll_timeout(&error) {
                        self.state = State::Finished;
                    }
                    return Err(error);
                }
            }
        }
    }

    /// Completes the current state in place; `Some` once the handshake ends.
    fn step<R: Read>(&mut self, reader: &mut R) -> Result<Option<Step>, TransportError> {
        match &mut self.state {
            State::DetectV1 { prefix, filled } => {
                fill(reader, prefix, filled)?;
                let prefix = *prefix;
                if prefix[4..] == *V1_VERSION_COMMAND {
                    if prefix[..4] == self.magic.to_bytes() {
                        return Ok(Some(Step::V1(prefix)));
                    }
                    return Err(TransportError::WrongNetworkV1);
                }
                self.queue_key();
                let mut key = [0u8; ELLSWIFT_LEN];
                key[..V1_PREFIX_LEN].copy_from_slice(&prefix);
                self.state = State::ReadKey {
                    key,
                    filled: V1_PREFIX_LEN,
                };
            }
            State::ReadKey { key, filled } => {
                fill(reader, key, filled)?;
                let key = *key;
                self.state = self.key_received(key)?;
            }
            State::ScanTerminator {
                terminator,
                scanned,
                ..
            } => {
                while !scanned.ends_with(terminator.as_slice()) {
                    let room = MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN - scanned.len();
                    if room == 0 {
                        return Err(TransportError::TerminatorNotFound);
                    }
                    // Never read past the earliest point the terminator could end.
                    let window =
                        (GARBAGE_TERMINATOR_LEN - partial_match(scanned, terminator)).min(room);
                    read_up_to(reader, scanned, window)?;
                }
                let State::ScanTerminator {
                    send,
                    recv,
                    session_id,
                    mut scanned,
                    ..
                } = core::mem::replace(&mut self.state, State::Finished)
                else {
                    return Err(TransportError::Completed);
                };
                scanned.truncate(scanned.len() - GARBAGE_TERMINATOR_LEN);
                self.state = State::ReadVersion {
                    send,
                    recv: PacketReader::new(recv, scanned),
                    session_id,
                };
            }
            State::ReadVersion { recv, .. } => {
                // The version packet's contents are reserved; receivers ignore
                // them. A decoy yields control one packet at a time so the
                // driver rechecks its lease and deadline between packets.
                if recv.read_contents(reader)?.is_none() {
                    return Ok(Some(Step::Yield));
                }
                let State::ReadVersion {
                    send,
                    recv,
                    session_id,
                } = core::mem::replace(&mut self.state, State::Finished)
                else {
                    return Err(TransportError::Completed);
                };
                return Ok(Some(Step::Established(Box::new(Established {
                    send,
                    recv,
                    session_id,
                }))));
            }
            State::Finished => return Err(TransportError::Completed),
        }
        Ok(None)
    }

    /// Derives the session from the peer's key, then queues our garbage
    /// terminator and the version packet, which authenticates our garbage.
    fn key_received(&mut self, key: [u8; ELLSWIFT_LEN]) -> Result<State, TransportError> {
        let theirs = ElligatorSwift::from_array(key);
        let secret = shared_secret(self.secret_key, self.ellswift, theirs, self.role);
        let material =
            KeyMaterial::derive(&secret, self.magic).map_err(TransportError::KeySchedule)?;
        let Session {
            mut send,
            recv,
            send_garbage_terminator,
            recv_garbage_terminator,
            session_id,
        } = Session::new(&material, self.role);
        let version = send.seal(&[], &self.garbage, false)?;
        self.outbound.extend_from_slice(&send_garbage_terminator);
        self.outbound.extend_from_slice(&version);
        Ok(State::ScanTerminator {
            send,
            recv,
            terminator: recv_garbage_terminator,
            session_id,
            scanned: Vec::new(),
        })
    }

    fn queue_key(&mut self) {
        self.outbound.extend_from_slice(&self.ellswift.to_array());
        self.outbound.extend_from_slice(&self.garbage);
    }
}

/// Encodes our public key for the wire.
///
/// `ElligatorSwift::new` in secp256k1 0.29 hands libsecp256k1 its
/// no-precomputation context, which key generation rejects as an illegal
/// argument; `from_seckey` takes a full context instead.
fn encode_key(secret_key: SecretKey, aux: [u8; 32]) -> ElligatorSwift {
    ElligatorSwift::from_seckey(&Secp256k1::verification_only(), secret_key, Some(aux))
}

/// Length of the longest proper prefix of `terminator` that `scanned` ends
/// with: a terminator ending in the future must start inside that suffix.
fn partial_match(scanned: &[u8], terminator: &[u8; GARBAGE_TERMINATOR_LEN]) -> usize {
    (1..GARBAGE_TERMINATOR_LEN)
        .rev()
        .find(|len| scanned.ends_with(&terminator[..*len]))
        .unwrap_or(0)
}

/// Records whether any byte arrived through the wrapped reader.
struct CountingReader<'a, R> {
    inner: &'a mut R,
    received: &'a mut bool,
}

impl<R: Read> Read for CountingReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        if read > 0 {
            *self.received = true;
        }
        Ok(read)
    }
}

#[cfg(test)]
mod tests;
