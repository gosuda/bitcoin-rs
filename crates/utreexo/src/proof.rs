use bitcoin_rs_primitives::Hash256;
use thiserror::Error;

use crate::accumulator::{NativeHash, from_native_hash, to_native_hash};

/// Inclusion proof plus the target leaf hashes it proves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    inner: rustreexo::proof::Proof<NativeHash>,
    target_hashes: Vec<Hash256>,
}

/// Errors returned while decoding a serialized proof wrapper.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofError {
    /// The byte slice is too short for the wrapper header.
    #[error("proof bytes ended before {field}")]
    Truncated {
        /// Name of the field that could not be decoded.
        field: &'static str,
    },
    /// A length prefix does not fit in this platform's address space.
    #[error("proof length does not fit usize: {0}")]
    LengthOverflow(u64),
    /// The wrapped rustreexo proof failed to decode.
    #[error("invalid rustreexo proof: {0}")]
    Native(String),
}

impl Proof {
    /// Builds a proof wrapper from a rustreexo proof and its target hashes.
    pub(crate) const fn from_native(
        inner: rustreexo::proof::Proof<NativeHash>,
        target_hashes: Vec<Hash256>,
    ) -> Self {
        Self {
            inner,
            target_hashes,
        }
    }

    /// Returns the proven target leaf hashes in proof order.
    #[must_use]
    pub fn target_hashes(&self) -> &[Hash256] {
        &self.target_hashes
    }

    /// Returns the rustreexo target positions carried by this proof.
    #[must_use]
    pub fn targets(&self) -> &[u64] {
        &self.inner.targets
    }

    /// Returns the number of target leaves proven by this proof.
    #[must_use]
    pub fn n_targets(&self) -> usize {
        self.inner.n_targets()
    }

    /// Serializes this wrapper as target hashes followed by the native proof.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let target_len = u64::try_from(self.target_hashes.len())
            .unwrap_or_else(|_| unreachable!("usize always fits into u64"));
        bytes.extend_from_slice(&target_len.to_le_bytes());
        for hash in &self.target_hashes {
            bytes.extend_from_slice(hash.as_byte_array());
        }
        if let Err(error) = self.inner.serialize(&mut bytes) {
            unreachable!("serializing to Vec is infallible: {error}");
        }
        bytes
    }

    /// Deserializes a proof wrapper produced by [`Self::serialize`].
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProofError> {
        let (target_len, mut offset) = read_u64(bytes, 0, "target length")?;
        let target_len =
            usize::try_from(target_len).map_err(|_| ProofError::LengthOverflow(target_len))?;
        let target_bytes_len = target_len
            .checked_mul(32)
            .ok_or(ProofError::LengthOverflow(u64::MAX))?;
        let end = offset
            .checked_add(target_bytes_len)
            .ok_or(ProofError::LengthOverflow(u64::MAX))?;
        let target_bytes = bytes.get(offset..end).ok_or(ProofError::Truncated {
            field: "target hashes",
        })?;
        let target_hashes = target_bytes
            .chunks_exact(32)
            .map(|chunk| {
                let mut hash = [0_u8; 32];
                hash.copy_from_slice(chunk);
                Hash256::from_le_bytes(&hash)
            })
            .collect();
        offset = end;

        let inner = rustreexo::proof::Proof::<NativeHash>::deserialize(&bytes[offset..])
            .map_err(ProofError::Native)?;
        Ok(Self {
            inner,
            target_hashes,
        })
    }

    /// Returns the wrapped rustreexo proof.
    pub(crate) const fn native(&self) -> &rustreexo::proof::Proof<NativeHash> {
        &self.inner
    }

    /// Consumes this wrapper and returns the wrapped rustreexo proof.
    pub(crate) fn into_native(self) -> rustreexo::proof::Proof<NativeHash> {
        self.inner
    }

    /// Returns target hashes converted to rustreexo's hash representation.
    pub(crate) fn native_target_hashes(&self) -> Vec<NativeHash> {
        self.target_hashes
            .iter()
            .copied()
            .map(to_native_hash)
            .collect()
    }

    /// Returns proof hashes converted back to the project hash representation.
    #[must_use]
    pub fn proof_hashes(&self) -> Vec<Hash256> {
        self.inner
            .hashes
            .iter()
            .copied()
            .map(from_native_hash)
            .collect()
    }
}

fn read_u64(bytes: &[u8], offset: usize, field: &'static str) -> Result<(u64, usize), ProofError> {
    let end = offset
        .checked_add(8)
        .ok_or(ProofError::LengthOverflow(u64::MAX))?;
    let raw = bytes
        .get(offset..end)
        .ok_or(ProofError::Truncated { field })?;
    let mut value = [0_u8; 8];
    value.copy_from_slice(raw);
    Ok((u64::from_le_bytes(value), end))
}
