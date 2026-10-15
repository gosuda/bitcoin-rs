//! Resumable reads of BIP324 packets from a blocking stream.
//!
//! Peer sockets poll with a short read timeout. A `TimedOut` or `WouldBlock`
//! read error leaves every byte already consumed in the reader, so the caller
//! retries and the same packet continues. Every other error is fatal for the
//! connection.

use std::io::Read;

use bytes::Bytes;

use super::TransportError;
use super::cipher::{LENGTH_FIELD_LEN, TAG_LEN};
use super::packet::{HEADER_LEN, RecvCipher};
use crate::recv;
use crate::wire::MAX_MESSAGE_PAYLOAD;

/// Largest contents length accepted from a peer: a type byte, a 12-byte long
/// type, and a payload of up to [`MAX_MESSAGE_PAYLOAD`] bytes, as Bitcoin Core
/// accepts.
pub(crate) const MAX_RECV_CONTENTS_LEN: usize = 1 + 12 + MAX_MESSAGE_PAYLOAD;

/// Reads one direction's packets: the receiving ciphers, the AAD owed by the
/// first packet, and any partially received packet.
#[derive(Debug)]
pub(crate) struct PacketReader {
    cipher: RecvCipher,
    aad: Vec<u8>,
    field: [u8; LENGTH_FIELD_LEN],
    field_filled: usize,
    body: Option<PendingBody>,
}

/// A packet whose length is decrypted and whose body is still arriving.
#[derive(Debug)]
struct PendingBody {
    len: usize,
    bytes: Vec<u8>,
}

impl PacketReader {
    /// `aad` authenticates the first packet: the garbage the peer sent before
    /// its garbage terminator.
    pub(crate) const fn new(cipher: RecvCipher, aad: Vec<u8>) -> Self {
        Self {
            cipher,
            aad,
            field: [0; LENGTH_FIELD_LEN],
            field_filled: 0,
            body: None,
        }
    }

    /// Reads the next packet that is not a decoy and returns its contents.
    ///
    /// A contents length above [`MAX_RECV_CONTENTS_LEN`] is refused before
    /// any byte of its body is read.
    pub(crate) fn read_contents<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> Result<Bytes, TransportError> {
        loop {
            let mut body = if let Some(body) = self.body.take() {
                body
            } else {
                self.read_length(reader)?
            };
            if let Err(error) = recv::fill_growing(reader, &mut body.bytes, body.len) {
                if recv::is_poll_timeout(&error) {
                    self.body = Some(body);
                }
                return Err(error.into());
            }
            let aad = core::mem::take(&mut self.aad);
            let opened = self.cipher.open(&aad, &mut body.bytes)?;
            if opened.ignore {
                continue;
            }
            let contents_len = opened.contents.len();
            return Ok(Bytes::from(body.bytes).slice(HEADER_LEN..HEADER_LEN + contents_len));
        }
    }

    /// Completes and decrypts the next length field. The cipher advances only
    /// once all three bytes are in.
    fn read_length<R: Read>(&mut self, reader: &mut R) -> Result<PendingBody, TransportError> {
        if let Err(error) = recv::fill(reader, &mut self.field, &mut self.field_filled) {
            if !recv::is_poll_timeout(&error) {
                self.field_filled = 0;
            }
            return Err(error.into());
        }
        self.field_filled = 0;
        let contents_len = self.cipher.decrypt_length(self.field);
        if contents_len > MAX_RECV_CONTENTS_LEN {
            return Err(TransportError::PacketTooLarge(contents_len));
        }
        Ok(PendingBody {
            len: HEADER_LEN + contents_len + TAG_LEN,
            bytes: Vec::new(),
        })
    }
}

/// The socket's poll interval elapsed; the rest of the packet may still arrive.
pub(crate) fn is_poll_timeout(error: &TransportError) -> bool {
    matches!(error, TransportError::Io(error) if recv::is_poll_timeout(error))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{self, Read};

    use super::{MAX_RECV_CONTENTS_LEN, PacketReader, is_poll_timeout};
    use crate::bip324::packet::{RecvCipher, SendCipher};
    use crate::recv::RECEIVE_CHUNK;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Serves queued bytes, then reads as a poll timeout.
    struct Dribble(VecDeque<u8>);

    impl Read for Dribble {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let read = buffer.len().min(self.0.len());
            for (slot, byte) in buffer.iter_mut().zip(self.0.drain(..read)) {
                *slot = byte;
            }
            Ok(read)
        }
    }

    fn pair() -> (SendCipher, PacketReader) {
        (
            SendCipher::new([1; 32], [2; 32]),
            PacketReader::new(RecvCipher::new([1; 32], [2; 32]), Vec::new()),
        )
    }

    #[test]
    fn a_length_field_split_by_a_timeout_decrypts_once() -> TestResult {
        let (mut sender, mut reader) = pair();
        let packet = sender.seal(b"contents", &[], false)?;
        let mut stream = Dribble(packet[..2].iter().copied().collect());
        let stalled = reader.read_contents(&mut stream);
        assert!(stalled.as_ref().is_err_and(is_poll_timeout), "{stalled:?}");
        stream.0.extend(&packet[2..]);
        assert_eq!(reader.read_contents(&mut stream)?.as_ref(), b"contents");
        Ok(())
    }

    #[test]
    fn a_stalled_packet_retains_only_what_arrived() -> TestResult {
        let (mut sender, mut reader) = pair();
        let packet = sender.seal(&vec![9; MAX_RECV_CONTENTS_LEN], &[], false)?;
        let mut stream = Dribble(packet[..103].iter().copied().collect());
        let stalled = reader.read_contents(&mut stream);
        assert!(stalled.as_ref().is_err_and(is_poll_timeout), "{stalled:?}");
        let retained = reader.body.as_ref().map_or(0, |body| body.bytes.capacity());
        assert!(
            retained <= RECEIVE_CHUNK,
            "a stalled packet retained {retained} bytes"
        );

        stream.0.extend(&packet[103..]);
        assert_eq!(
            reader.read_contents(&mut stream)?.len(),
            MAX_RECV_CONTENTS_LEN
        );
        Ok(())
    }
}
