//! The BIP324 forward-secure ciphers: `FSChaCha20` encrypts the length field,
//! `FSChaCha20Poly1305` seals the packet body.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit as _, StreamCipher as _, StreamCipherSeek as _};
use chacha20poly1305::{AeadInOut as _, ChaCha20Poly1305, KeyInit as _};

/// Length fields or packets each cipher handles before it rekeys.
const REKEY_INTERVAL: u32 = 224;

/// Bytes in the encrypted length field.
pub(crate) const LENGTH_FIELD_LEN: usize = 3;

/// Bytes in a Poly1305 authentication tag.
pub(crate) const TAG_LEN: usize = 16;

/// `ChaCha20` block 1, where `ChaCha20-Poly1305` starts its keystream.
const FIRST_PAYLOAD_BLOCK_OFFSET: u64 = 64;

/// The 96-bit `ChaCha20` nonce `LE32(prefix) || LE64(epoch)`.
fn nonce(prefix: u32, epoch: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&prefix.to_le_bytes());
    nonce[4..].copy_from_slice(&epoch.to_le_bytes());
    nonce
}

/// Each rekey epoch is one continuous `ChaCha20` keystream under nonce `LE32(0) ||
/// LE64(epoch)`.
///
/// After [`REKEY_INTERVAL`] length fields the next 32 keystream bytes key the following
/// epoch.
///
/// A field is always [`LENGTH_FIELD_LEN`] bytes, so an epoch consumes `224 * 3 + 32 =
/// 704` bytes, exactly eleven `ChaCha20` blocks: no keystream outlives its key.
pub(crate) struct FsChaCha20 {
    stream: ChaCha20,
    epoch: u64,
    fields: u32,
}

impl FsChaCha20 {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self {
            stream: length_stream(key, 0),
            epoch: 0,
            fields: 0,
        }
    }

    pub(crate) fn crypt(&mut self, field: &mut [u8; LENGTH_FIELD_LEN]) {
        self.stream.apply_keystream(field);
        self.fields += 1;
        if self.fields == REKEY_INTERVAL {
            let mut key = [0u8; 32];
            self.stream.apply_keystream(&mut key);
            self.epoch += 1;
            self.fields = 0;
            self.stream = length_stream(key, self.epoch);
        }
    }
}

impl core::fmt::Debug for FsChaCha20 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FsChaCha20")
            .field("epoch", &self.epoch)
            .field("fields", &self.fields)
            .finish_non_exhaustive()
    }
}

fn length_stream(key: [u8; 32], epoch: u64) -> ChaCha20 {
    ChaCha20::new(&key.into(), &nonce(0, epoch).into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("BIP324 packet failed authentication")]
pub(crate) struct AuthFailed;

/// Packet `i` of epoch `e` is sealed under nonce `LE32(i) || LE64(e)`.
///
/// After the last packet of an epoch the key becomes the first 32 bytes of `ChaCha20`
/// block 1 under nonce `0xffffffff || LE64(e)`. Every call advances the packet counter,
/// including a failed authentication, as the reference does.
pub(crate) struct FsChaCha20Poly1305 {
    key: [u8; 32],
    epoch: u64,
    packets: u32,
}

impl FsChaCha20Poly1305 {
    pub(crate) const fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            epoch: 0,
            packets: 0,
        }
    }

    /// `ChaCha20-Poly1305` refuses only plaintexts beyond 256 GiB.
    pub(crate) fn encrypt(
        &mut self,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], chacha20poly1305::Error> {
        let nonce = nonce(self.packets, self.epoch);
        let sealed = self
            .aead()
            .encrypt_inout_detached(&nonce.into(), aad, buffer.into());
        self.advance();
        sealed.map(Into::into)
    }

    pub(crate) fn decrypt(
        &mut self,
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), AuthFailed> {
        let nonce = nonce(self.packets, self.epoch);
        let opened =
            self.aead()
                .decrypt_inout_detached(&nonce.into(), aad, buffer.into(), &(*tag).into());
        self.advance();
        opened.map_err(|_| AuthFailed)
    }

    fn aead(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(&self.key.into())
    }

    fn advance(&mut self) {
        self.packets += 1;
        if self.packets == REKEY_INTERVAL {
            let mut stream = ChaCha20::new(&self.key.into(), &nonce(u32::MAX, self.epoch).into());
            stream.seek(FIRST_PAYLOAD_BLOCK_OFFSET);
            let mut key = [0u8; 32];
            stream.apply_keystream(&mut key);
            self.key = key;
            self.epoch += 1;
            self.packets = 0;
        }
    }
}

impl core::fmt::Debug for FsChaCha20Poly1305 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FsChaCha20Poly1305")
            .field("epoch", &self.epoch)
            .field("packets", &self.packets)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthFailed, FsChaCha20, FsChaCha20Poly1305, REKEY_INTERVAL};

    #[test]
    fn length_cipher_round_trips_across_rekeys() {
        let mut sender = FsChaCha20::new([3; 32]);
        let mut receiver = FsChaCha20::new([3; 32]);
        for value in 0..(3 * REKEY_INTERVAL + 7) {
            let plain = value.to_le_bytes();
            let mut field = [plain[0], plain[1], plain[2]];
            sender.crypt(&mut field);
            receiver.crypt(&mut field);
            assert_eq!(field, [plain[0], plain[1], plain[2]]);
        }
    }

    #[test]
    fn packet_cipher_round_trips_across_rekeys() -> Result<(), Box<dyn std::error::Error>> {
        let mut sender = FsChaCha20Poly1305::new([5; 32]);
        let mut receiver = FsChaCha20Poly1305::new([5; 32]);
        for value in 0..(2 * REKEY_INTERVAL + 3) {
            let plain = value.to_le_bytes();
            let mut buffer = plain;
            let tag = sender.encrypt(b"aad", &mut buffer)?;
            assert_ne!(buffer, plain, "packet {value} is encrypted");
            receiver.decrypt(b"aad", &mut buffer, &tag)?;
            assert_eq!(buffer, plain);
        }
        Ok(())
    }

    #[test]
    fn packet_cipher_rejects_any_tampering() -> Result<(), Box<dyn std::error::Error>> {
        let plain = *b"contents";
        for tamper in 0..3 {
            let mut sender = FsChaCha20Poly1305::new([9; 32]);
            let mut receiver = FsChaCha20Poly1305::new([9; 32]);
            let mut buffer = plain;
            let mut tag = sender.encrypt(b"garbage", &mut buffer)?;
            let mut aad = b"garbage".to_vec();
            match tamper {
                0 => buffer[0] ^= 1,
                1 => tag[15] ^= 1,
                _ => aad.push(0),
            }
            assert_eq!(receiver.decrypt(&aad, &mut buffer, &tag), Err(AuthFailed));
        }
        Ok(())
    }
}
