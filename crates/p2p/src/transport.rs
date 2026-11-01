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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportProtocol {
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

fn transport_error(error: TransportError) -> PeerError {
    match error {
        TransportError::Io(error) => PeerError::Io(error),
        other => PeerError::Transport(TransportFailure(Box::new(other))),
    }
}

#[derive(Debug)]
pub(crate) enum RecvTransport {
    V1(V1Receiver),
    /// BIP324 packets.
    V2(Box<PacketReader>),
}

#[derive(Debug)]
pub(crate) enum SendTransport {
    V1(Magic),
    /// BIP324 packets.
    V2(Box<SendCipher>),
}

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
    /// Reads at most one message: `Ok(None)` when the v2 transport carried a decoy
    /// packet or a message of an empty or undefined type, which BIP324 peers drop.
    /// An empty or undefined type still spent the packet's bytes on the wire, so
    /// `observe` sees it (folded into the `*other*` bucket, like a v1 frame under
    /// an unknown command) before the drop; a decoy packet carries no message and
    /// keeps no per-message charge.
    ///
    /// A v1 frame always carries a message and is never `None`. `observe`
    /// receives the command, its payload, and the frame's exact wire size:
    /// header plus payload for v1, or the BIP324 packet's ciphertext length
    /// for v2.
    pub(crate) fn read_message<R: Read>(
        &mut self,
        reader: &mut R,
        magic: Magic,
        observe: impl FnOnce(&str, &[u8], usize) -> Result<(), PeerError>,
    ) -> Result<Option<(Message, bytes::Bytes)>, PeerError> {
        match self {
            Self::V1(receiver) => receiver.read_message_with(reader, magic, observe).map(Some),
            Self::V2(packets) => {
                let Some(contents) = packets.read_contents(reader).map_err(transport_error)? else {
                    return Ok(None);
                };
                let Some((command, payload)) = msg_type::decode(&contents) else {
                    observe("", &[], crate::bip324::PACKET_OVERHEAD + contents.len())?;
                    return Ok(None);
                };
                observe(
                    &command,
                    &payload,
                    crate::bip324::PACKET_OVERHEAD + contents.len(),
                )?;
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

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use bitcoin::p2p::Magic;

    use super::RecvTransport;
    use crate::bip324::{PACKET_OVERHEAD, PacketReader, RecvCipher, SendCipher};
    use crate::counters::PeerCounters;

    fn v2_receiver() -> RecvTransport {
        RecvTransport::V2(Box::new(PacketReader::new(
            RecvCipher::new([1; 32], [2; 32]),
            Vec::new(),
        )))
    }

    #[test]
    fn a_v2_frame_of_undefined_type_charges_other_then_drops() {
        let mut cipher = SendCipher::new([1; 32], [2; 32]);
        let mut transport = v2_receiver();
        // Short id 29 is assigned to no command, so this packet carries a
        // message of undefined type.
        let contents = [29_u8, 0xde, 0xad];
        let packet = cipher.seal(&contents, &[], false).expect("seal");

        let counters = Arc::new(PeerCounters::default());
        let mut observed = Vec::new();
        let message = transport
            .read_message(
                &mut Cursor::new(packet),
                Magic::BITCOIN,
                |command, payload, len| {
                    counters.record_msg_recv(command, len);
                    observed.push((command.to_owned(), payload.to_vec(), len));
                    Ok(())
                },
            )
            .expect("an undefined type drops the message, never errors");

        assert!(message.is_none(), "an undefined-type message drops");
        assert_eq!(
            observed,
            vec![(String::new(), Vec::new(), PACKET_OVERHEAD + contents.len())],
            "the dropped frame is observed with an empty command and its wire size"
        );
        assert_eq!(
            counters.recv_per_message(),
            vec![(
                "*other*",
                u64::try_from(PACKET_OVERHEAD + contents.len()).expect("fits u64")
            )],
            "the undefined-type frame's wire bytes land in the *other* bucket"
        );
    }

    #[test]
    fn a_v2_decoy_packet_charges_nothing() {
        let mut cipher = SendCipher::new([1; 32], [2; 32]);
        let mut transport = v2_receiver();
        let decoy = cipher.seal(&[], &[], true).expect("seal decoy");

        let message = transport
            .read_message(&mut Cursor::new(decoy), Magic::BITCOIN, |_, _, _| {
                panic!("a decoy packet carries no message to account");
            })
            .expect("a decoy drops, never errors");

        assert!(message.is_none());
    }
}
