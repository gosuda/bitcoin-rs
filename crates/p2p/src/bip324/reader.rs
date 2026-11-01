#![cfg_attr(not(feature = "fuzzing"), allow(unreachable_pub))]

use std::io::Read;

use bytes::Bytes;

use super::TransportError;
use super::cipher::{LENGTH_FIELD_LEN, TAG_LEN};
use super::packet::{HEADER_LEN, RecvCipher};
use crate::recv;
use crate::wire::MAX_MESSAGE_PAYLOAD;

pub(crate) const MAX_RECV_CONTENTS_LEN: usize = 1 + 12 + MAX_MESSAGE_PAYLOAD;

#[derive(Debug)]
pub struct PacketReader {
    cipher: RecvCipher,
    aad: Vec<u8>,
    field: [u8; LENGTH_FIELD_LEN],
    field_filled: usize,
    body: Option<PendingBody>,
    failed: bool,
}

#[derive(Debug)]
struct PendingBody {
    len: usize,
    bytes: Vec<u8>,
}

impl PacketReader {
    pub const fn new(cipher: RecvCipher, aad: Vec<u8>) -> Self {
        Self {
            cipher,
            aad,
            field: [0; LENGTH_FIELD_LEN],
            field_filled: 0,
            body: None,
            failed: false,
        }
    }

    pub fn read_contents<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<Bytes>, TransportError> {
        if self.failed {
            return Err(TransportError::Packet(
                crate::bip324::packet::PacketError::AuthFailed(crate::bip324::cipher::AuthFailed),
            ));
        }
        let mut body = match self.body.take() {
            Some(body) => body,
            None => match self.read_length(reader) {
                Ok(body) => body,
                Err(error) => {
                    if !is_poll_timeout(&error) {
                        self.failed = true;
                    }
                    return Err(error);
                }
            },
        };
        if let Err(error) = recv::fill_growing(reader, &mut body.bytes, body.len) {
            if recv::is_poll_timeout(&error) {
                self.body = Some(body);
            } else {
                self.failed = true;
            }
            return Err(error.into());
        }
        let aad = core::mem::take(&mut self.aad);
        let opened = match self.cipher.open(&aad, &mut body.bytes) {
            Ok(opened) => opened,
            Err(error) => {
                self.failed = true;
                return Err(error.into());
            }
        };
        if opened.ignore {
            return Ok(None);
        }
        let end = HEADER_LEN + opened.contents.len();
        Ok(Some(Bytes::from(body.bytes).slice(HEADER_LEN..end)))
    }

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

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Packet(#[from] crate::bip324::packet::PacketError),
        #[error(transparent)]
        Transport(#[from] super::super::TransportError),
        #[error(transparent)]
        Io(#[from] std::io::Error),
    }

    type TestResult = Result<(), TestError>;

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
        assert_eq!(
            reader
                .read_contents(&mut stream)?
                .ok_or_else(|| io::Error::other("a real packet"))?
                .as_ref(),
            b"contents"
        );
        Ok(())
    }

    #[test]
    fn a_decoy_packet_yields_none_and_the_next_packet_still_arrives() -> TestResult {
        let (mut sender, mut reader) = pair();
        let decoy = sender.seal(&[0; 100], &[], true)?;
        let real = sender.seal(b"payload", &[], false)?;
        let mut stream = Dribble(decoy[..103].iter().copied().collect());
        let stalled = reader.read_contents(&mut stream);
        assert!(stalled.as_ref().is_err_and(is_poll_timeout), "{stalled:?}");
        stream.0.extend(&decoy[103..]);
        assert_eq!(reader.read_contents(&mut stream)?, None);
        stream.0.extend(real);
        assert_eq!(
            reader
                .read_contents(&mut stream)?
                .ok_or_else(|| io::Error::other("a real packet"))?
                .as_ref(),
            b"payload"
        );
        Ok(())
    }

    #[test]
    fn three_decoys_then_one_packet() -> TestResult {
        let (mut sender, mut reader) = pair();
        let mut stream = Vec::new();
        for size in [0_usize, 7, 100] {
            stream.extend(&sender.seal(&vec![0; size], &[], true)?);
        }
        stream.extend(sender.seal(b"payload", &[], false)?);
        let mut stream = Dribble(stream.into_iter().collect());
        assert_eq!(reader.read_contents(&mut stream)?, None);
        assert_eq!(reader.read_contents(&mut stream)?, None);
        assert_eq!(reader.read_contents(&mut stream)?, None);
        assert_eq!(
            reader
                .read_contents(&mut stream)?
                .ok_or_else(|| io::Error::other("a real packet"))?
                .as_ref(),
            b"payload"
        );
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
            reader
                .read_contents(&mut stream)?
                .ok_or_else(|| io::Error::other("a real packet"))?
                .len(),
            MAX_RECV_CONTENTS_LEN
        );
        Ok(())
    }

    #[test]
    fn tag_failure_poisons_reader_so_subsequent_packets_are_never_accepted() -> TestResult {
        let (mut sender, mut reader) = pair();
        let mut corrupted = sender.seal(b"first", &[], false)?;
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0x01;
        let valid = sender.seal(b"second", &[], false)?;

        let mut stream1 = std::io::Cursor::new(corrupted);
        assert!(reader.read_contents(&mut stream1).is_err());

        let mut stream2 = std::io::Cursor::new(valid);
        assert!(
            reader.read_contents(&mut stream2).is_err(),
            "no packet may be accepted after authentication tag failure"
        );
        Ok(())
    }
}
