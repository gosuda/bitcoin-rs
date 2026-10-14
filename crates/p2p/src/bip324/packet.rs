//! BIP324 packet sealing and opening.
//!
//! A packet is the encrypted 3-byte contents length, then one header byte and
//! the contents sealed together under the packet cipher, then the tag.

use super::cipher::{AuthFailed, FsChaCha20, FsChaCha20Poly1305, LENGTH_FIELD_LEN, TAG_LEN};

/// Bytes of the header that precedes the contents inside the sealed body.
pub(crate) const HEADER_LEN: usize = 1;

/// Header bit marking a decoy packet the receiver discards.
const IGNORE_BIT: u8 = 1 << 7;

/// Largest contents length the 3-byte length field can express.
const MAX_CONTENTS_LEN: usize = (1 << 24) - 1;

/// Bytes a packet adds to its contents: length field, header byte and tag.
const PACKET_OVERHEAD: usize = LENGTH_FIELD_LEN + HEADER_LEN + TAG_LEN;

/// A packet could not be sealed or opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PacketError {
    /// The contents do not fit the 3-byte length field.
    #[error("BIP324 packet contents of {0} bytes exceed the length field")]
    ContentsTooLarge(usize),
    /// The sealed body is shorter than a header byte plus a tag.
    #[error("BIP324 sealed body of {0} bytes is shorter than its header and tag")]
    Truncated(usize),
    /// The sealed body failed authentication.
    #[error(transparent)]
    AuthFailed(#[from] AuthFailed),
}

/// One direction's sending ciphers.
#[derive(Debug)]
pub(crate) struct SendCipher {
    length: FsChaCha20,
    packet: FsChaCha20Poly1305,
}

impl SendCipher {
    pub(crate) fn new(length_key: [u8; 32], packet_key: [u8; 32]) -> Self {
        Self {
            length: FsChaCha20::new(length_key),
            packet: FsChaCha20Poly1305::new(packet_key),
        }
    }

    /// Seals one packet carrying `contents`. `aad` authenticates the garbage
    /// sent before the first packet of a direction and is empty afterwards;
    /// `ignore` marks a decoy.
    pub(crate) fn seal(
        &mut self,
        contents: &[u8],
        aad: &[u8],
        ignore: bool,
    ) -> Result<Vec<u8>, PacketError> {
        let length = u32::try_from(contents.len())
            .ok()
            .filter(|_| contents.len() <= MAX_CONTENTS_LEN)
            .ok_or(PacketError::ContentsTooLarge(contents.len()))?;
        let mut packet = Vec::with_capacity(PACKET_OVERHEAD + contents.len());
        let mut field = [0u8; LENGTH_FIELD_LEN];
        field.copy_from_slice(&length.to_le_bytes()[..LENGTH_FIELD_LEN]);
        self.length.crypt(&mut field);
        packet.extend_from_slice(&field);
        packet.push(if ignore { IGNORE_BIT } else { 0 });
        packet.extend_from_slice(contents);
        let tag = self
            .packet
            .encrypt(aad, &mut packet[LENGTH_FIELD_LEN..])
            .map_err(|_| PacketError::ContentsTooLarge(contents.len()))?;
        packet.extend_from_slice(&tag);
        Ok(packet)
    }
}

/// An authenticated packet body.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Opened<'a> {
    /// The sender marked the packet a decoy.
    pub(crate) ignore: bool,
    /// The decrypted contents.
    pub(crate) contents: &'a [u8],
}

/// One direction's receiving ciphers.
#[derive(Debug)]
pub(crate) struct RecvCipher {
    length: FsChaCha20,
    packet: FsChaCha20Poly1305,
}

impl RecvCipher {
    pub(crate) fn new(length_key: [u8; 32], packet_key: [u8; 32]) -> Self {
        Self {
            length: FsChaCha20::new(length_key),
            packet: FsChaCha20Poly1305::new(packet_key),
        }
    }

    /// Decrypts the next packet's length field: the contents length, which
    /// sizes the sealed body (`HEADER_LEN + length + TAG_LEN` bytes) that
    /// follows it.
    pub(crate) fn decrypt_length(&mut self, mut field: [u8; LENGTH_FIELD_LEN]) -> usize {
        self.length.crypt(&mut field);
        usize::from(field[0]) | (usize::from(field[1]) << 8) | (usize::from(field[2]) << 16)
    }

    /// Authenticates and decrypts a sealed body (header, contents and tag) in
    /// place.
    pub(crate) fn open<'a>(
        &mut self,
        aad: &[u8],
        body: &'a mut [u8],
    ) -> Result<Opened<'a>, PacketError> {
        let sealed_len = body
            .len()
            .checked_sub(TAG_LEN)
            .filter(|len| *len >= HEADER_LEN)
            .ok_or(PacketError::Truncated(body.len()))?;
        let (sealed, tag) = body.split_at_mut(sealed_len);
        let mut tag_bytes = [0u8; TAG_LEN];
        tag_bytes.copy_from_slice(tag);
        self.packet.decrypt(aad, sealed, &tag_bytes)?;
        let sealed: &'a [u8] = sealed;
        let (header, contents) = sealed.split_at(HEADER_LEN);
        Ok(Opened {
            ignore: header[0] & IGNORE_BIT != 0,
            contents,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthFailed, MAX_CONTENTS_LEN, PacketError, RecvCipher, SendCipher};
    use crate::bip324::cipher::{LENGTH_FIELD_LEN, TAG_LEN};

    #[test]
    fn seal_refuses_contents_beyond_the_length_field() {
        let mut sender = SendCipher::new([1; 32], [2; 32]);
        assert_eq!(
            sender.seal(&vec![0; MAX_CONTENTS_LEN + 1], &[], false),
            Err(PacketError::ContentsTooLarge(MAX_CONTENTS_LEN + 1))
        );
    }

    #[test]
    fn open_refuses_a_body_without_room_for_header_and_tag() {
        let mut receiver = RecvCipher::new([1; 32], [2; 32]);
        let mut body = [0u8; TAG_LEN];
        assert_eq!(
            receiver.open(&[], &mut body),
            Err(PacketError::Truncated(TAG_LEN))
        );
    }

    #[test]
    fn open_rejects_a_tampered_body() -> Result<(), PacketError> {
        let mut sender = SendCipher::new([1; 32], [2; 32]);
        let mut receiver = RecvCipher::new([1; 32], [2; 32]);
        let mut packet = sender.seal(b"ping", &[], false)?;
        packet[LENGTH_FIELD_LEN + 2] ^= 1;
        let mut field = [0u8; LENGTH_FIELD_LEN];
        field.copy_from_slice(&packet[..LENGTH_FIELD_LEN]);
        assert_eq!(receiver.decrypt_length(field), 4);
        assert_eq!(
            receiver.open(&[], &mut packet[LENGTH_FIELD_LEN..]),
            Err(PacketError::AuthFailed(AuthFailed))
        );
        Ok(())
    }
}
