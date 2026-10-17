//! A connection's transport: legacy v1 framing or a BIP324 v2 session, split
//! into the receive half the connection thread keeps and the send half its
//! writer thread takes once the handshake completes.

use std::io::{self, Read, Write};
use std::time::Instant;

use bitcoin::p2p::Magic;

use crate::bip324::{
    Established, Handshake, PacketReader, SendCipher, Step, TransportError, is_poll_timeout,
    msg_type,
};
use crate::wire::{
    FramedMessage, Message, PeerError, V1Receiver, decode_payload, encode_frame, message_payload,
};

/// The transport a connection negotiated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportProtocol {
    /// Legacy v1 framing, unencrypted.
    V1,
    /// A BIP324 encrypted session.
    V2 {
        /// The id both sides derived for this session. Comparing it out of
        /// band is the only way BIP324 detects a man in the middle.
        session_id: [u8; 32],
    },
}

/// A BIP324 transport failure. It ends the connection; BIP324 does not
/// authenticate peers, so it never implicates the peer.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct TransportFailure(Box<TransportError>);

/// Maps a transport error onto the connection's error type. A poll timeout
/// stays an I/O error, so the caller's retry loop keeps working.
fn transport_error(error: TransportError) -> PeerError {
    match error {
        TransportError::Io(error) => PeerError::Io(error),
        other => PeerError::Transport(TransportFailure(Box::new(other))),
    }
}

/// The receive half of a connection's transport.
#[derive(Debug)]
pub(crate) enum RecvTransport {
    /// v1 frames.
    V1(V1Receiver),
    /// BIP324 packets.
    V2(Box<PacketReader>),
}

/// The send half of a connection's transport.
#[derive(Debug)]
pub(crate) enum SendTransport {
    /// v1 frames under the connection's magic.
    V1(Magic),
    /// BIP324 packets.
    V2(Box<SendCipher>),
}

/// Both halves of a negotiated transport.
#[derive(Debug)]
pub(crate) struct Negotiated {
    pub(crate) recv: RecvTransport,
    pub(crate) send: SendTransport,
    pub(crate) protocol: TransportProtocol,
}

impl Negotiated {
    /// The v1 transport of a connection that never attempted BIP324.
    pub(crate) fn v1(magic: Magic) -> Self {
        Self {
            recv: RecvTransport::V1(V1Receiver::default()),
            send: SendTransport::V1(magic),
            protocol: TransportProtocol::V1,
        }
    }
}

impl RecvTransport {
    /// Reads at most one message: `Ok(None)` when the v2 transport carried a
    /// decoy packet or a message of an empty or undefined type, which BIP324
    /// peers drop. A v1 frame always carries a message and is never `None`.
    ///
    /// POST: a poll-timeout I/O error keeps any partial frame or packet.
    pub(crate) fn read_message<R: Read>(
        &mut self,
        reader: &mut R,
        magic: Magic,
        observe: impl FnOnce(&str, &[u8]),
    ) -> Result<Option<(Message, bytes::Bytes)>, PeerError> {
        match self {
            Self::V1(receiver) => receiver.read_message_with(reader, magic, observe).map(Some),
            Self::V2(packets) => {
                let Some(contents) = packets.read_contents(reader).map_err(transport_error)? else {
                    return Ok(None);
                };
                let Some((command, payload)) = msg_type::decode(&contents) else {
                    return Ok(None);
                };
                observe(&command, &payload);
                let message = decode_payload(&command, &payload)?;
                Ok(Some((message, payload)))
            }
        }
    }
}

impl SendTransport {
    /// Encodes `message`: a v1 frame, or a sealed BIP324 packet.
    /// [`message_payload`] refuses a payload above the protocol message bound
    /// on either transport.
    pub(crate) fn encode(&mut self, message: &Message) -> Result<FramedMessage, PeerError> {
        match self {
            Self::V1(magic) => encode_frame(*magic, message),
            Self::V2(cipher) => {
                let payload = message_payload(message)?;
                let contents = msg_type::encode(&message.command(), &payload);
                let packet = cipher
                    .seal(&contents, &[], false)
                    .map_err(|error| transport_error(error.into()))?;
                Ok(FramedMessage::sealed(packet, payload))
            }
        }
    }
}

/// Runs `handshake` over `stream` until it establishes a session or, for a
/// responder, recognizes a v1 peer. Honors the connection's poll timeout, the
/// handshake `deadline`, and `lease` cancellation.
///
/// POST: on failure, `handshake.received_any()` tells an initiator whether
/// the peer answered at all.
pub(crate) fn establish<S: Read + Write>(
    stream: &mut S,
    handshake: &mut Handshake,
    magic: Magic,
    lease: &crate::PeerLease,
    deadline: Instant,
) -> Result<Negotiated, PeerError> {
    loop {
        if lease.is_cancelled() {
            return Err(PeerError::Protocol("peer lease revoked during handshake"));
        }
        if Instant::now() >= deadline {
            return Err(PeerError::Io(io::ErrorKind::TimedOut.into()));
        }
        match handshake.advance(stream) {
            Ok(Step::Send) => stream.write_all(&handshake.take_outbound())?,
            Ok(Step::Yield) => {}
            Ok(Step::V1(prefix)) => {
                return Ok(Negotiated {
                    recv: RecvTransport::V1(V1Receiver::with_prefix(&prefix)),
                    ..Negotiated::v1(magic)
                });
            }
            Ok(Step::Established(session)) => {
                let Established {
                    send,
                    recv,
                    session_id,
                } = *session;
                return Ok(Negotiated {
                    recv: RecvTransport::V2(Box::new(recv)),
                    send: SendTransport::V2(Box::new(send)),
                    protocol: TransportProtocol::V2 { session_id },
                });
            }
            Err(error) if is_poll_timeout(&error) => {}
            Err(error) => return Err(transport_error(error)),
        }
    }
}
