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
    V2(Box<PacketReader>),
}

#[derive(Debug)]
pub(crate) enum SendTransport {
    V1(Magic),
    V2(Box<SendCipher>),
}

#[derive(Debug)]
pub(crate) struct Negotiated {
    pub(crate) recv: RecvTransport,
    pub(crate) send: SendTransport,
    pub(crate) protocol: TransportProtocol,
}

impl Negotiated {
    pub(crate) fn v1(magic: Magic) -> Self {
        Self {
            recv: RecvTransport::V1(V1Receiver::default()),
            send: SendTransport::V1(magic),
            protocol: TransportProtocol::V1,
        }
    }
}

impl RecvTransport {
    pub(crate) fn receive_pending(&self) -> bool {
        match self {
            Self::V1(receiver) => receiver.receive_pending(),
            Self::V2(reader) => reader.receive_pending(),
        }
    }

    pub(crate) fn bind_memory(
        &mut self,
        memory: &std::sync::Arc<crate::inbound::block_memory::BlockMemory>,
    ) -> io::Result<()> {
        match self {
            Self::V1(receiver) => receiver.bind_memory(memory),
            Self::V2(reader) => reader.bind_memory(memory),
        }
    }

    pub(crate) fn cancel_receive(&mut self) {
        *self = Self::V1(V1Receiver::default());
    }

    /// Reads at most one message: `Ok(None)` when the v2 transport carried a decoy
    /// packet or a message of an empty or undefined type, which BIP324 peers drop.
    /// An empty or undefined type still spent the packet's bytes on the wire, so
    /// `account` sees it (folded into the `*other*` bucket, like a v1 frame under
    /// an unknown command) before the drop; a decoy packet carries no message and
    /// keeps no per-message charge.
    ///
    /// `account` receives the command, its payload, and the frame's exact wire
    /// size for every frame observed on the wire: header plus payload for v1,
    /// or the BIP324 packet's ciphertext length for v2. It is infallible and
    /// runs for dropped frames too.
    /// `admit` runs only for a frame about to be delivered, and its error
    /// rejects the delivery.
    /// A `block` frame refused for image budget is also `None`, after
    /// `account` sees its real command, payload, and wire size.
    pub(crate) fn read_message<R: Read>(
        &mut self,
        reader: &mut R,
        magic: Magic,
        mut account: impl FnMut(&str, &[u8], usize),
        admit: impl FnOnce(&str, &[u8]) -> Result<(), PeerError>,
    ) -> Result<Option<(Message, bytes::Bytes)>, PeerError> {
        match self {
            Self::V1(receiver) => receiver.read_message_with(reader, magic, account, admit),
            Self::V2(packets) => {
                let contents = match packets.read_contents_with_transfer(reader) {
                    Err(TransportError::BudgetDrop {
                        command,
                        payload,
                        wire_len,
                    }) => {
                        account(&command, &payload, wire_len);
                        return Ok(None);
                    }
                    contents => contents.map_err(transport_error)?,
                };
                let Some(contents) = contents else {
                    return Ok(None);
                };
                let Some((command, payload)) = msg_type::decode(&contents) else {
                    account("", &[], crate::bip324::PACKET_OVERHEAD + contents.len());
                    return Ok(None);
                };
                account(
                    &command,
                    &payload,
                    crate::bip324::PACKET_OVERHEAD + contents.len(),
                );
                admit(&command, &payload)?;
                let message = decode_payload(&command, &payload)?;
                Ok(Some((message, payload)))
            }
        }
    }
}

impl SendTransport {
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
            handshake.cancel_receive();
            return Err(PeerError::Protocol("peer lease revoked during handshake"));
        }
        if Instant::now() >= deadline {
            handshake.cancel_receive();
            return Err(PeerError::Io(io::ErrorKind::TimedOut.into()));
        }
        match handshake.advance(stream) {
            Ok(Step::Send) => stream.write_all(&handshake.take_outbound())?,
            Ok(Step::Yield) => {}
            Ok(Step::V1(prefix)) => {
                let mut negotiated = Negotiated {
                    recv: RecvTransport::V1(V1Receiver::with_prefix(&prefix)),
                    ..Negotiated::v1(magic)
                };
                if let Some(memory) = handshake.memory() {
                    negotiated.recv.bind_memory(memory)?;
                }
                return Ok(negotiated);
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
                },
                |_, _| Ok(()),
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
    fn a_v2_block_refused_for_image_budget_is_observed_then_dropped() {
        use crate::bip324::msg_type;
        use crate::inbound::block_memory::{BLOCK_INGRESS_BYTES, BlockMemory};

        let block = bitcoin_rs_consensus::primitives::BlockImage::from_local(
            bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
        );
        let payload = block.bytes().to_vec();
        let command = "block"
            .parse::<bitcoin::p2p::message::CommandString>()
            .expect("block command");
        let contents = msg_type::encode(&command, &payload);
        let mut cipher = SendCipher::new([1; 32], [2; 32]);
        let packet = cipher.seal(&contents, &[], false).expect("seal");

        let mut transport = v2_receiver();
        let memory = Arc::new(BlockMemory::default());
        let _held = memory
            .try_reserve(BLOCK_INGRESS_BYTES - 1)
            .expect("hold the image lane");
        transport.bind_memory(&memory).expect("bind memory");

        let counters = Arc::new(PeerCounters::default());
        let mut observed = Vec::new();
        let message = transport
            .read_message(
                &mut Cursor::new(packet),
                Magic::BITCOIN,
                |command, payload, len| {
                    counters.record_msg_recv(command, len);
                    observed.push((command.to_owned(), payload.to_vec(), len));
                },
                |_, _| Ok(()),
            )
            .expect("a budget refusal drops the frame, never errors");

        assert!(message.is_none(), "a refused block frame drops");
        assert_eq!(
            observed,
            vec![(
                String::from("block"),
                payload,
                PACKET_OVERHEAD + contents.len()
            )],
            "the refused frame is observed with its command, payload, and wire size"
        );
        assert_eq!(
            counters.recv_per_message(),
            vec![(
                "block",
                u64::try_from(PACKET_OVERHEAD + contents.len()).expect("fits u64")
            )],
            "the refused block's wire bytes land in the block bucket"
        );
    }

    #[test]
    fn a_v2_decoy_packet_charges_nothing() {
        let mut cipher = SendCipher::new([1; 32], [2; 32]);
        let mut transport = v2_receiver();
        let decoy = cipher.seal(&[], &[], true).expect("seal decoy");

        let message = transport
            .read_message(
                &mut Cursor::new(decoy),
                Magic::BITCOIN,
                |_, _, _| panic!("a decoy packet carries no message to account"),
                |_, _| panic!("a decoy packet carries no message to admit"),
            )
            .expect("a decoy drops, never errors");

        assert!(message.is_none());
    }
}
