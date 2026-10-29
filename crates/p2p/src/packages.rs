//! BIP331 ancestor package relay: message codec and combined package hash.
//!
//! BIP331 adds four messages, all negotiated before `verack` through `sendpackages`:
//! Sources: BIP331 at bitcoin/bips `c0c5aea41e6a334d34db4ca87ae53bbfd7f268d1` and
//! Bitcoin Core's merged `GetPackageHash` at
//! `092c978a42e8f4a02291b994713505ba8aac8b28`.
//!
//! BIP331 publishes no test-vector section.

use bitcoin_rs_primitives::{
    ConsensusDecode, ConsensusEncode, DecodeError, Hash256, Tx, Wtxid, varint,
};
use sha2::{Digest, Sha256};

use crate::wire::MAX_MESSAGE_PAYLOAD;

pub const PKG_RELAY_PKGTXNS: u64 = 1 << 0;

pub const PKG_RELAY_ANC: u64 = 1 << 1;

/// Largest list any BIP331 list message carries on the wire.
/// BIP331 bounds `getpkgtxns` at 100 wtxids; `ancpkginfo` feeds `getpkgtxns`
/// and `pkgtxns` answers it, so all three share the bound.
pub const MAX_GETPKGTXNS: usize = 100;

pub const MSG_ANCPKGINFO: u32 = 0x7;

pub const MSG_PKGTXNS: u32 = 0x6;

const WTXID_LEN: usize = 32;

/// Errors from encoding or decoding a BIP331 message payload.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PackageError {
    #[error("truncated package payload")]
    Truncated,
    #[error("non-canonical compact size")]
    NonCanonical,
    #[error("package list is empty")]
    Empty,
    #[error("package list count {count} exceeds bound {max}")]
    TooMany { count: u64, max: usize },
    /// An `ancpkginfo` repeated a wtxid, which BIP331 defines as malformed.
    #[error("ancpkginfo repeats a wtxid")]
    DuplicateWtxid,
    #[error("trailing {0} bytes after package payload")]
    Trailing(usize),
    #[error("package payload length {0} exceeds the frame bound")]
    PayloadTooLarge(usize),
    #[error("package transaction: {0}")]
    Transaction(#[from] DecodeError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendPackages {
    pub versions: u64,
}

impl SendPackages {
    #[must_use]
    pub const fn encode(self) -> [u8; 8] {
        self.versions.to_le_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, PackageError> {
        let (versions, rest) = payload
            .split_first_chunk::<8>()
            .ok_or(PackageError::Truncated)?;
        if !rest.is_empty() {
            return Err(PackageError::Trailing(rest.len()));
        }
        Ok(Self {
            versions: u64::from_le_bytes(*versions),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AncPkgInfo {
    pub wtxids: Vec<Wtxid>,
}

impl AncPkgInfo {
    #[must_use]
    pub fn subject(&self) -> Option<Wtxid> {
        self.wtxids.last().copied()
    }

    pub fn encode(&self) -> Result<Vec<u8>, PackageError> {
        check_count(len_u64(self.wtxids.len()))?;
        if has_duplicates(&self.wtxids) {
            return Err(PackageError::DuplicateWtxid);
        }
        Ok(write_wtxids(&self.wtxids))
    }

    pub fn decode(payload: &[u8]) -> Result<Self, PackageError> {
        let wtxids = read_wtxids(payload)?;
        if has_duplicates(&wtxids) {
            return Err(PackageError::DuplicateWtxid);
        }
        Ok(Self { wtxids })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetPkgTxns {
    pub wtxids: Vec<Wtxid>,
}

impl GetPkgTxns {
    pub fn encode(&self) -> Result<Vec<u8>, PackageError> {
        check_count(len_u64(self.wtxids.len()))?;
        Ok(write_wtxids(&self.wtxids))
    }

    pub fn decode(payload: &[u8]) -> Result<Self, PackageError> {
        Ok(Self {
            wtxids: read_wtxids(payload)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PkgTxns {
    pub txs: Vec<Tx>,
}

impl PkgTxns {
    pub fn encode(&self) -> Result<Vec<u8>, PackageError> {
        let count = len_u64(self.txs.len());
        check_count(count)?;
        let mut total = varint::encoded_len(count);
        for tx in &self.txs {
            total = total.saturating_add(tx.consensus_size());
            if total > MAX_MESSAGE_PAYLOAD {
                return Err(PackageError::PayloadTooLarge(total));
            }
        }
        let mut payload = Vec::with_capacity(total);
        payload.extend_from_slice(&varint::encode(count));
        for tx in &self.txs {
            tx.consensus_encode(&mut payload);
        }
        Ok(payload)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, PackageError> {
        if payload.len() > MAX_MESSAGE_PAYLOAD {
            return Err(PackageError::PayloadTooLarge(payload.len()));
        }
        let (count, mut reader) = read_count(payload)?;
        let mut txs = Vec::with_capacity(count);
        for _ in 0..count {
            txs.push(Tx::consensus_decode(&mut reader)?);
        }
        if !reader.is_empty() {
            return Err(PackageError::Trailing(reader.len()));
        }
        Ok(Self { txs })
    }
}

#[must_use]
pub fn combined_package_hash(wtxids: &[Wtxid]) -> [u8; 32] {
    let mut ordered: Vec<&[u8; WTXID_LEN]> = wtxids.iter().map(Wtxid::as_bytes).collect();
    ordered.sort_unstable_by(|a, b| a.iter().rev().cmp(b.iter().rev()));
    let mut engine = Sha256::new();
    for wtxid in ordered {
        engine.update(wtxid);
    }
    engine.finalize().into()
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn check_count(count: u64) -> Result<usize, PackageError> {
    if count == 0 {
        return Err(PackageError::Empty);
    }
    match usize::try_from(count) {
        Ok(count) if count <= MAX_GETPKGTXNS => Ok(count),
        _ => Err(PackageError::TooMany {
            count,
            max: MAX_GETPKGTXNS,
        }),
    }
}

/// The one reader for every BIP331 list payload: minimal encoding and a count
/// from `1` through [`MAX_GETPKGTXNS`] are decided here from the prefix alone.
pub fn read_count(payload: &[u8]) -> Result<(usize, &[u8]), PackageError> {
    let (count, consumed) = varint::decode(payload).map_err(|err| match err {
        varint::VarintError::Truncated { .. } => PackageError::Truncated,
        varint::VarintError::NonCanonical { .. } => PackageError::NonCanonical,
    })?;
    Ok((check_count(count)?, &payload[consumed..]))
}

fn read_wtxids(payload: &[u8]) -> Result<Vec<Wtxid>, PackageError> {
    let (count, body) = read_count(payload)?;
    let needed = count * WTXID_LEN;
    if body.len() < needed {
        return Err(PackageError::Truncated);
    }
    if body.len() > needed {
        return Err(PackageError::Trailing(body.len() - needed));
    }
    let (wtxids, _) = body.as_chunks::<WTXID_LEN>();
    Ok(wtxids
        .iter()
        .map(|bytes| Wtxid(Hash256::from_le_bytes(bytes)))
        .collect())
}

fn write_wtxids(wtxids: &[Wtxid]) -> Vec<u8> {
    let count = len_u64(wtxids.len());
    let mut payload = Vec::with_capacity(varint::encoded_len(count) + wtxids.len() * WTXID_LEN);
    payload.extend_from_slice(&varint::encode(count));
    for wtxid in wtxids {
        payload.extend_from_slice(wtxid.as_bytes());
    }
    payload
}

fn has_duplicates(wtxids: &[Wtxid]) -> bool {
    wtxids
        .iter()
        .enumerate()
        .any(|(index, wtxid)| wtxids[index + 1..].contains(wtxid))
}

#[cfg(test)]
mod tests;
