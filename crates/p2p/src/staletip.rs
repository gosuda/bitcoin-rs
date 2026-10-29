//! BIP332 `staletip` message codec.
//!
//! Payload layout (BIP332, draft). No BIP324 short message ID is reserved for
//! `staletip`: the command travels as its twelve-byte ASCII name on both
//! transports.

use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256, Header, varint};

pub const STALETIP_COMMAND: &str = "staletip";

pub const COMPRESSED_HEADER_LEN: usize = 48;

/// (BIP332 `MAX_STALETIP_HEADERS`).
pub const MAX_STALETIP_HEADERS: usize = 20;
/// (BIP332 `STALETIP_RECENT_WINDOW`).
pub const STALETIP_RECENT_WINDOW: u32 = 1000;

/// (BIP332 `MAX_ADVERTISED_STALETIPS`).
pub const MAX_ADVERTISED_STALETIPS: usize = 10;

pub const MAX_PAYLOAD_LEN: usize =
    FORK_POINT_LEN + 1 + MAX_STALETIP_HEADERS * COMPRESSED_HEADER_LEN + 1;

const FORK_POINT_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressedHeader {
    pub version: i32,
    pub merkle_root: Hash256,
    pub time: u32,
    pub bits: CompactTarget,
    pub nonce: u32,
}

impl CompressedHeader {
    #[must_use]
    pub fn from_header(header: &Header) -> Self {
        Self {
            version: header.version,
            merkle_root: header.merkle_root,
            time: header.time,
            bits: header.bits,
            nonce: header.nonce,
        }
    }

    #[must_use]
    pub fn with_prev(self, prev: Hash256) -> Header {
        Header {
            version: self.version,
            prev_blockhash: BlockHash::from(prev),
            merkle_root: self.merkle_root,
            time: self.time,
            bits: self.bits,
            nonce: self.nonce,
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(self.merkle_root.as_byte_array());
        out.extend_from_slice(&self.time.to_le_bytes());
        out.extend_from_slice(&self.bits.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
    }

    fn read(chunk: &[u8; COMPRESSED_HEADER_LEN]) -> Option<Self> {
        let mut cursor = chunk.as_slice();
        Some(Self {
            version: i32::from_le_bytes(take(&mut cursor)?),
            merkle_root: Hash256::from_le_bytes(&take(&mut cursor)?),
            time: u32::from_le_bytes(take(&mut cursor)?),
            bits: CompactTarget::from_consensus(u32::from_le_bytes(take(&mut cursor)?)),
            nonce: u32::from_le_bytes(take(&mut cursor)?),
        })
    }
}

fn take<const N: usize>(cursor: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = cursor.split_first_chunk::<N>()?;
    *cursor = tail;
    Some(*head)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaleTipAnnouncement {
    pub fork_point: Hash256,
    pub headers: Vec<CompressedHeader>,
    pub have_block: bool,
}

impl StaleTipAnnouncement {
    #[must_use]
    pub fn reconstruct(&self) -> Vec<Header> {
        let mut prev = self.fork_point;
        self.headers
            .iter()
            .map(|compressed| {
                let header = compressed.with_prev(prev);
                prev = Hash256::from(header.compute_hash());
                header
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StaleTipError {
    #[error("truncated staletip payload")]
    Truncated,
    #[error("non-canonical compact size")]
    NonCanonical,
    #[error("staletip has no headers")]
    NoHeaders,
    #[error("staletip header count {0} exceeds bound 20")]
    TooManyHeaders(usize),
    #[error("invalid have_block byte {0:#04x}")]
    InvalidBool(u8),
    #[error("trailing {0} bytes after staletip payload")]
    Trailing(usize),
}

impl StaleTipError {
    /// BIP332 says a peer SHOULD NOT be punished solely because one
    /// announcement exceeds local policy limits, so callers ignore such a
    /// message; every other variant is a malformed payload.
    #[must_use]
    pub const fn is_policy_limit(&self) -> bool {
        matches!(self, Self::TooManyHeaders(_))
    }
}

pub fn encode(announcement: &StaleTipAnnouncement) -> Result<Vec<u8>, StaleTipError> {
    let count = announcement.headers.len();
    if count == 0 {
        return Err(StaleTipError::NoHeaders);
    }
    if count > MAX_STALETIP_HEADERS {
        return Err(StaleTipError::TooManyHeaders(count));
    }
    let count_bytes =
        varint::encode(u64::try_from(count).map_err(|_| StaleTipError::TooManyHeaders(count))?);
    let mut out =
        Vec::with_capacity(FORK_POINT_LEN + count_bytes.len() + count * COMPRESSED_HEADER_LEN + 1);
    out.extend_from_slice(announcement.fork_point.as_byte_array());
    out.extend_from_slice(&count_bytes);
    for header in &announcement.headers {
        header.write(&mut out);
    }
    out.push(u8::from(announcement.have_block));
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Result<StaleTipAnnouncement, StaleTipError> {
    let (fork_point, rest) = bytes
        .split_first_chunk::<FORK_POINT_LEN>()
        .ok_or(StaleTipError::Truncated)?;
    let (count, count_len) = varint::decode(rest).map_err(|err| match err {
        varint::VarintError::Truncated { .. } => StaleTipError::Truncated,
        varint::VarintError::NonCanonical { .. } => StaleTipError::NonCanonical,
    })?;
    let count = usize::try_from(count).unwrap_or(usize::MAX);
    if count == 0 {
        return Err(StaleTipError::NoHeaders);
    }
    if count > MAX_STALETIP_HEADERS {
        return Err(StaleTipError::TooManyHeaders(count));
    }

    let body = &rest[count_len..];
    let headers_len = count * COMPRESSED_HEADER_LEN;
    let needed = headers_len + 1;
    if body.len() < needed {
        return Err(StaleTipError::Truncated);
    }
    if body.len() > needed {
        return Err(StaleTipError::Trailing(body.len() - needed));
    }

    let (header_bytes, flag) = body.split_at(headers_len);
    let have_block = match flag {
        [0] => false,
        [1] => true,
        [other] => return Err(StaleTipError::InvalidBool(*other)),
        _ => return Err(StaleTipError::Truncated),
    };
    let (chunks, _) = header_bytes.as_chunks::<COMPRESSED_HEADER_LEN>();
    let mut headers = Vec::with_capacity(count);
    for chunk in chunks {
        headers.push(CompressedHeader::read(chunk).ok_or(StaleTipError::Truncated)?);
    }
    Ok(StaleTipAnnouncement {
        fork_point: Hash256::from_le_bytes(fork_point),
        headers,
        have_block,
    })
}

#[cfg(test)]
mod tests;
