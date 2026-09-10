use alloc::string::String;

use anyhow::Result;

use super::error::EvidenceError;

/// A SHA-256 digest carried as 64 lowercase hex characters in evidence.
///
/// A digest is bytes, not a label: a placeholder such as "unmeasured" cannot
/// parse, so an identity is either real or absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha256Hex(pub [u8; 32]);

impl Sha256Hex {
    /// Hashes `bytes` with SHA-256.
    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        use sha2::Digest as _;
        Self(sha2::Sha256::digest(bytes).into())
    }
}

impl core::fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl core::str::FromStr for Sha256Hex {
    type Err = EvidenceError;

    fn from_str(text: &str) -> Result<Self, EvidenceError> {
        let malformed = || EvidenceError::MalformedDigest(text.into());
        if text.len() != 64 {
            return Err(malformed());
        }
        let mut bytes = [0_u8; 32];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
            let text = core::str::from_utf8(pair).map_err(|_| malformed())?;
            if text.bytes().any(|c| c.is_ascii_uppercase()) {
                return Err(malformed());
            }
            *byte = u8::from_str_radix(text, 16).map_err(|_| malformed())?;
        }
        Ok(Self(bytes))
    }
}

impl serde::Serialize for Sha256Hex {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Sha256Hex {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}
