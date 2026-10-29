//! BIP332 `staletip` message codec.
//!
//! A `staletip` announces one stale branch: the `fork_point` hash the receiver
//! already knows, up to [`MAX_STALETIP_HEADERS`] [`CompressedHeader`]s that
//! follow it in chain order, and whether the sender will serve the tip block.
//! Payload layout (BIP332, draft):
//!
//! | bytes | field |
//! | --- | --- |
//! | 32 | `fork_point`, consensus little-endian |
//! | 1, 3, 5 or 9 | minimal `CompactSize` header count, `1..=20` |
//! | 48 × count | compressed headers: header minus its previous-block hash |
//! | 1 | `have_block`, `0x00` or `0x01` |
//!
//! This module owns only the byte format. It neither validates proof of work
//! nor consults chain state; reconstructed headers enter the node through the
//! ordinary header-admission path.
//!
//! No BIP324 short message ID is reserved for `staletip`: the command travels
//! as its twelve-byte ASCII name on both transports.

use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256, Header, varint};

/// P2P command string for stale-tip announcements.
pub const STALETIP_COMMAND: &str = "staletip";

/// Serialized size of one [`CompressedHeader`]: `version`, `merkle_root`,
/// `time`, `bits`, `nonce`.
pub const COMPRESSED_HEADER_LEN: usize = 48;

/// Recommended and enforced maximum header count of one announcement
/// (BIP332 `MAX_STALETIP_HEADERS`).
pub const MAX_STALETIP_HEADERS: usize = 20;
/// Recommended maximum distance in blocks from the receiver's active tip
/// (BIP332 `STALETIP_RECENT_WINDOW`).
pub const STALETIP_RECENT_WINDOW: u32 = 1000;

/// Recommended maximum number of previously known stale tips advertised to a peer
/// (BIP332 `MAX_ADVERTISED_STALETIPS`).
pub const MAX_ADVERTISED_STALETIPS: usize = 10;

/// Largest valid payload: 32-byte fork point, one-byte count, twenty
/// compressed headers, one-byte `have_block`.
pub const MAX_PAYLOAD_LEN: usize =
    FORK_POINT_LEN + 1 + MAX_STALETIP_HEADERS * COMPRESSED_HEADER_LEN + 1;

const FORK_POINT_LEN: usize = 32;

/// A block header without its previous-block hash.
///
/// The previous hash is the hash of the preceding header, or the announcement's
/// `fork_point` for the first one, so it is redundant on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressedHeader {
    /// Block version.
    pub version: i32,
    /// Merkle root of the block's transactions.
    pub merkle_root: Hash256,
    /// Unix epoch seconds.
    pub time: u32,
    /// Compact proof-of-work target.
    pub bits: CompactTarget,
    /// Proof-of-work nonce.
    pub nonce: u32,
}

impl CompressedHeader {
    /// Drops the previous-block hash of `header`.
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

    /// Restores the full header that follows the block hashed `prev`.
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

/// Splits `N` bytes off the front of `cursor`.
fn take<const N: usize>(cursor: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = cursor.split_first_chunk::<N>()?;
    *cursor = tail;
    Some(*head)
}

/// One `staletip` announcement.
///
/// Field validity (`1..=MAX_STALETIP_HEADERS` headers) is enforced by
/// [`encode`] and [`decode`], not by construction, so a value is a plain
/// record both for the sender's planner and the receiver's decoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaleTipAnnouncement {
    /// Hash the first header follows; the receiver must already know it.
    pub fork_point: Hash256,
    /// The stale branch after `fork_point`, in chain order; the last entry is
    /// the stale tip.
    pub headers: Vec<CompressedHeader>,
    /// Whether the sender will serve the stale tip's block.
    pub have_block: bool,
}

impl StaleTipAnnouncement {
    /// Rebuilds the linear headers: header `i` extends the hash of header
    /// `i - 1`, and the first extends `fork_point`.
    ///
    /// POST: the result has `headers.len()` entries in chain order; its last
    /// header's hash is the stale tip's hash. No validation is performed.
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

/// Reasons a `staletip` payload does not encode or decode.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StaleTipError {
    /// The payload ended before the announcement was complete.
    #[error("truncated staletip payload")]
    Truncated,
    /// The header count used a non-minimal `CompactSize` encoding.
    #[error("non-canonical compact size")]
    NonCanonical,
    /// The announcement carries no headers.
    #[error("staletip has no headers")]
    NoHeaders,
    /// The announcement carries more than [`MAX_STALETIP_HEADERS`] headers.
    #[error("staletip header count {0} exceeds bound 20")]
    TooManyHeaders(usize),
    /// `have_block` was neither `0x00` nor `0x01`.
    #[error("invalid have_block byte {0:#04x}")]
    InvalidBool(u8),
    /// Bytes were left after the announcement.
    #[error("trailing {0} bytes after staletip payload")]
    Trailing(usize),
}

impl StaleTipError {
    /// Whether the input exceeded a local resource limit rather than being
    /// malformed.
    ///
    /// BIP332 says a peer SHOULD NOT be punished solely because one
    /// announcement exceeds local policy limits, so callers ignore such a
    /// message; every other variant is a malformed payload.
    #[must_use]
    pub const fn is_policy_limit(&self) -> bool {
        matches!(self, Self::TooManyHeaders(_))
    }
}

/// Encodes `announcement` into its wire payload.
///
/// Rejects an empty or over-limit header list before allocating; on success
/// the payload is at most [`MAX_PAYLOAD_LEN`] bytes.
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

/// Decodes a `staletip` payload.
///
/// Strict: requires 1 to [`MAX_STALETIP_HEADERS`] headers, a minimal
/// `CompactSize` count, a `0x00`/`0x01` `have_block`, and exact consumption.
/// The count is checked against the limit before any header storage is
/// reserved, so an attacker-chosen count never sizes an allocation; an
/// over-limit count is reported as soon as it is read, whatever follows it.
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
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    // The two serialized `staletip` payloads from the BIP332 "Test Vectors"
    // section (signet 19-block branch, BCH-fork 18-block branch). The expected
    // hashes below are the BIP's table values; `assert_published_vector`
    // re-derives the stale tip from the payload bytes alone.
    const SIGNET_STALE_BRANCH_HEX: &str = concat!(
        "1c7e50802a59c42d780861d2c154a87cb02ff42305a933af2ede2f6012000000",
        "130000002067aa2937b235e209f1ad40f37b17dcad8ca02d1fb9cf4c4928902e",
        "ab3ff853a6cda16e691658151d81ad7b0400000020721ab6f36042842bab4583",
        "f98e15181b646c47c7b9dfb07a204c4e5152e54e97fda46e691658151dd2dcec",
        "1800000020ddc6b628101b404f78d446591a623e12bb7e7cd2ae1593d0cc6ef0",
        "82e19fa81014a66e691658151d46070e10000000208be5b9607b20ac0163b885",
        "881aa6018ef60a5637b93a9cd85981515a169a31c36aab6e691658151de4e106",
        "00000000206c974ef806b2e6a21cc9a53fedcbd5d5e203b4929a1bd7c5859ec7",
        "7d0a755c1d64ae6e691658151d2a2e130e0000002039505fa2ee91f5e5b2540b",
        "4a9a7f02ed58d79fc387412cf2520a39ee16bf435f6eb16e691658151db29c83",
        "0a00000020411bce69cda2b239c74faea1f0cfaceabd90377114dc0ace14e2a5",
        "8858cd4f9a91b46e691658151d4c2d3f050000002096464a2ec42fea8419a5c6",
        "adcc41ca7dc3f53461cd0afc880f76498aa8eedbf993b56e691658151d5e9970",
        "0b00000020c3cad611ee3c7bffec3f80fc83f68192ca0a86e8c89050f8353480",
        "310d080caf08b76e691658151dbc61a6150000002079e36b5a06bb5a524a2f5b",
        "ad6725451613c354cbf64f9a0283f77fe90782d59fcbba6e691658151d6c6693",
        "00000000204c69fd467818994e7ff885181e7451d23869a7fd19447dad7a9539",
        "8077ed7774dcba6e691658151dc9c7ff02000000208ea9a871b12cd45226ab6d",
        "f280ec46b8c9ca196b98dc8adc27718cab333e19a50abc6e691658151df6bae9",
        "02000000209c182979424a5c85d55d5bddbf3b9421b01b7810edf95ad2529552",
        "dd2eec80848ebd6e691658151d439e5c0000000020cfb9f6d1643613dfdd23a6",
        "e1eabadac38c392f985f5dc05b00ef682c428922c96cbe6e691658151d278b4d",
        "1400000020eea983b8d64947368de4f7626531a3134d18f20a8d87462ba011a4",
        "f56a53b6ac4fbf6e691658151ddae8640800000020140bc70b1a3282fbebf9d4",
        "8ff40a9b73ab7c76ad522799cee73315e9c21aab50dcc06e691658151dedaae9",
        "0f000000209b91a056fe089429f2ba4298e764acb4177249ce7d68e6883836f7",
        "0d1d9218b355c16e691658151d28a4320600000020b26e80c6a12cc4595556d2",
        "318fda564ced5d2a526c7b77f57a9897a56c10539056c16e691658151dc64fb5",
        "0000000020369d36495749c96d36260d839abfa703a611aad7b3016342ef05d0",
        "412f42221e6ac56e691658151d8f8bfb0f00",
    );

    const BCH_FORK_HEADERS_HEX: &str = concat!(
        "432d350741fbf28f2e1486eabe2c4e143bfe2241af6518010000000000000000",
        "1200000020abaa4bd8a48c1c6bc08ee39b66065e5e9484304cab8b56d5eed3e4",
        "0b1ac996c899c480593547011822ca4ae80000002082afc8ef7eb41a4ecac1fe",
        "a46983742e491f804ad662e3745ab9c6c4297d8a0862c980593547011840a772",
        "cb0200002058874e50628fdf83aeea4e8cbc7ade946e9ba14bcb1d8ffb28c3da",
        "f8ade84df65fca805935470118e2f5100300000020111b85f9d3b969a1f7ff3d",
        "50af08893c500edfc5623b96dbeab6daf16a5164a40ace805935470118c4f424",
        "0a0000002040a045063b551b61d6a1c9db6d3231e2d7403185bbb2332ae1f66d",
        "b24aac7fa288d8805935470118f15dd76b0000002070cb14529e8757c359c2e8",
        "b1e987f6eee6fbc4472ee9ad4a2e5df6905c19d6d70bed80593547011885ae00",
        "d0000000209653314c1d73e4630bb485fb25ce7a2583cec7c3ccfc27a6d24163",
        "be1e9fb19530f4805935470118f17ad2c500000020cdf48b8e7ac6bf3a51d187",
        "8ee3ff7e6fd0022926dd69cc5cc8d9126e77c4dba809f58059354701188114e8",
        "3600000020890cf1dc60edbf0fd4fb667f28ac785849c031d8b24d5e5a0af56e",
        "e2bd8a739bf51081593547011812f32a9600000020ff5244613ad20fdc39b7ee",
        "6f4fbc7016432d2dbf45c2a950c59665b39c3954b5b525815935470118aa790d",
        "6600000020aeed520e7c1693de5cfe7531e7d3e73dff7858b09cb6e1ec29229a",
        "75c3da2b92453e81593547011830a4314d000000202e4a4054e64c3f5810c23e",
        "c0144d9793aab2d5a7d77d1660eee24d3d55e8b715b543815935470118da1c00",
        "e00000002073152af68778a98fd984a158aeb29d28e094e23c3a7dff02260c34",
        "5791e52498c3fb8159354701188d5abed90000002022606e744a29f9d4a67ff1",
        "fcd2f0e31300ddbd145f8f1db8a68270bfbde77dd88fff8159354701186af175",
        "f8000000209f5db27969fecc0ef71503279069b2df981ba545592a7b425f353b",
        "5060e77f3e7e13825935470118da70378e000000202f0d316b08350f5cd998c6",
        "a11762d10adb9f951b5f79ce2a073f8187c05f561f1b1c8259354701184834c6",
        "2300000020cf8fc3bad8dad139a3dd6a30481d87e1f760122573168002cc9ef7",
        "a58fc53ad387848259354701188a3b54f7000000200eae92d9b46d81a011a797",
        "26a802d4eb195a7af8b70a09b0e115c391968c50d51c8a825935470118cd786d",
        "1300",
    );

    const SIGNET_FORK_POINT: &str =
        "00000012602fde2eaf33a90523f42fb07ca854c1d26108782dc4592a80507e1c";
    const SIGNET_STALE_TIP: &str =
        "0000000024ff924ff932668d497bba7da9157559a68d9c87d2f28d22e5e4a001";
    const BCH_FORK_POINT: &str = "0000000000000000011865af4122fe3b144e2cbeea86142e8ff2fb4107352d43";
    const BCH_STALE_TIP: &str = "000000000000000001416af072f8989829f4c60a1a9658e1cec08411798e4ffa";

    fn hex_bytes(text: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16))
            .collect()
    }

    fn announcement_of(count: usize, have_block: bool) -> StaleTipAnnouncement {
        StaleTipAnnouncement {
            fork_point: Hash256::from_le_bytes(&[7; 32]),
            headers: (0..count)
                .map(|i| CompressedHeader {
                    version: 0x2000_0000,
                    merkle_root: Hash256::from_le_bytes(&[u8::try_from(i).unwrap_or(0); 32]),
                    time: 1_700_000_000 + u32::try_from(i).unwrap_or(0),
                    bits: CompactTarget::from_consensus(0x1703_4219),
                    nonce: 0xdead_0000 + u32::try_from(i).unwrap_or(0),
                })
                .collect(),
            have_block,
        }
    }

    /// Asserts the decoder reproduces one published vector end to end: field
    /// counts, the BIP's fork point and tip hashes (the tip hash is re-derived
    /// by hashing the reconstructed chain, so every header byte is covered),
    /// and a byte-identical re-encode.
    fn assert_published_vector(
        hex: &str,
        payload_len: usize,
        fork_point: &str,
        stale_tip: &str,
        count: usize,
    ) -> TestResult {
        let payload = hex_bytes(hex)?;
        assert_eq!(payload.len(), payload_len);

        let decoded = decode(&payload)?;
        assert_eq!(decoded.fork_point, Hash256::from_str_be(fork_point)?);
        assert_eq!(decoded.headers.len(), count);
        assert!(!decoded.have_block);

        let headers = decoded.reconstruct();
        let Some(tip) = headers.last() else {
            return Err("reconstructed branch is empty".into());
        };
        assert_eq!(
            Hash256::from(tip.compute_hash()),
            Hash256::from_str_be(stale_tip)?
        );
        assert_eq!(
            Hash256::from(headers[0].prev_blockhash),
            decoded.fork_point,
            "the first header extends the fork point"
        );
        for pair in headers.windows(2) {
            assert_eq!(
                Hash256::from(pair[1].prev_blockhash),
                Hash256::from(pair[0].compute_hash()),
                "each header extends its predecessor"
            );
        }

        assert_eq!(encode(&decoded)?, payload);
        Ok(())
    }

    #[test]
    fn signet_published_vector_reconstructs_to_tip() -> TestResult {
        assert_published_vector(
            SIGNET_STALE_BRANCH_HEX,
            946,
            SIGNET_FORK_POINT,
            SIGNET_STALE_TIP,
            19,
        )
    }

    #[test]
    fn bch_fork_published_vector_reconstructs_to_tip() -> TestResult {
        assert_published_vector(BCH_FORK_HEADERS_HEX, 898, BCH_FORK_POINT, BCH_STALE_TIP, 18)
    }

    #[test]
    fn compression_drops_exactly_the_previous_hash() -> TestResult {
        let payload = hex_bytes(SIGNET_STALE_BRANCH_HEX)?;
        let decoded = decode(&payload)?;
        for (header, compressed) in decoded.reconstruct().iter().zip(&decoded.headers) {
            assert_eq!(CompressedHeader::from_header(header), *compressed);
            assert_eq!(Header::LEN - COMPRESSED_HEADER_LEN, 32);
            assert_eq!(
                compressed.with_prev(Hash256::from(header.prev_blockhash)),
                *header
            );
        }
        Ok(())
    }

    #[test]
    fn maximal_announcement_is_994_bytes_and_round_trips() -> TestResult {
        assert_eq!(MAX_PAYLOAD_LEN, 994);
        for have_block in [false, true] {
            let announcement = announcement_of(MAX_STALETIP_HEADERS, have_block);
            let payload = encode(&announcement)?;
            assert_eq!(payload.len(), MAX_PAYLOAD_LEN);
            assert_eq!(payload.last().copied(), Some(u8::from(have_block)));
            assert_eq!(decode(&payload)?, announcement);
        }
        Ok(())
    }

    #[test]
    fn minimal_announcement_round_trips_with_one_byte_count() -> TestResult {
        let announcement = announcement_of(1, true);
        let payload = encode(&announcement)?;
        assert_eq!(payload.len(), 32 + 1 + COMPRESSED_HEADER_LEN + 1);
        assert_eq!(payload[32], 1);
        assert_eq!(decode(&payload)?, announcement);
        Ok(())
    }

    #[test]
    fn encoder_refuses_empty_and_over_limit_branches() {
        assert_eq!(
            encode(&announcement_of(0, false)),
            Err(StaleTipError::NoHeaders)
        );
        assert_eq!(
            encode(&announcement_of(MAX_STALETIP_HEADERS + 1, false)),
            Err(StaleTipError::TooManyHeaders(MAX_STALETIP_HEADERS + 1))
        );
    }

    #[test]
    fn decoder_rejects_truncation_at_every_boundary() -> TestResult {
        let payload = encode(&announcement_of(3, true))?;
        for len in 0..payload.len() {
            assert_eq!(
                decode(&payload[..len]),
                Err(StaleTipError::Truncated),
                "a {len}-byte prefix of a {}-byte payload",
                payload.len()
            );
        }
        Ok(())
    }

    #[test]
    fn decoder_requires_exact_consumption() -> TestResult {
        let mut payload = encode(&announcement_of(2, false))?;
        payload.push(0);
        assert_eq!(decode(&payload), Err(StaleTipError::Trailing(1)));
        payload.extend_from_slice(&[0; 9]);
        assert_eq!(decode(&payload), Err(StaleTipError::Trailing(10)));
        Ok(())
    }

    #[test]
    fn decoder_accepts_only_zero_or_one_for_have_block() -> TestResult {
        let mut payload = encode(&announcement_of(2, false))?;
        let flag = payload.len() - 1;
        for byte in [2_u8, 0x7f, 0x80, 0xff] {
            payload[flag] = byte;
            assert_eq!(decode(&payload), Err(StaleTipError::InvalidBool(byte)));
        }
        payload[flag] = 1;
        assert!(decode(&payload)?.have_block);
        Ok(())
    }

    #[test]
    fn decoder_rejects_empty_branch_and_nonminimal_counts() {
        let fork = [3_u8; 32];
        let with_count = |count: &[u8]| [fork.as_slice(), count, &[0]].concat();

        assert_eq!(decode(&with_count(&[0x00])), Err(StaleTipError::NoHeaders));
        // Every wider encoding of a value that fits a narrower one is refused,
        // including the in-range counts 1 and 20.
        for count in [
            &[0xfd, 0x01, 0x00][..],
            &[0xfd, 0x14, 0x00],
            &[0xfd, 0xfc, 0x00],
            &[0xfe, 0x01, 0x00, 0x00, 0x00],
            &[0xfe, 0xff, 0xff, 0x00, 0x00],
            &[0xff, 0x01, 0, 0, 0, 0, 0, 0, 0],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0],
        ] {
            assert_eq!(
                decode(&with_count(count)),
                Err(StaleTipError::NonCanonical),
                "count bytes {count:02x?}"
            );
        }
        // A count prefix with its operand cut off.
        for count in [
            &[0xfd][..],
            &[0xfd, 0x14],
            &[0xfe, 0, 0, 1],
            &[0xff, 1, 2, 3, 4, 5, 6, 7],
        ] {
            assert_eq!(
                decode(&[fork.as_slice(), count].concat()),
                Err(StaleTipError::Truncated),
                "count bytes {count:02x?}"
            );
        }
    }

    #[test]
    fn over_limit_count_is_reported_before_any_body_is_read_or_sized() {
        let fork = [9_u8; 32];
        // Counts that would size multi-gigabyte buffers if trusted, with no
        // body at all: the decoder must answer from the count alone.
        let cases: [(&[u8], usize); 6] = [
            (&[21], 21),
            (&[0xfc], 0xfc),
            (&[0xfd, 0xfd, 0x00], 0xfd),
            (&[0xfd, 0xff, 0xff], 0xffff),
            (&[0xfe, 0x00, 0x00, 0x01, 0x00], 0x1_0000),
            (&[0xfe, 0xff, 0xff, 0xff, 0xff], 0xffff_ffff),
        ];
        for (count, expected) in cases {
            let Err(error) = decode(&[fork.as_slice(), count].concat()) else {
                panic!("count {count:02x?} must be refused");
            };
            assert_eq!(
                error,
                StaleTipError::TooManyHeaders(expected),
                "count {count:02x?}"
            );
            assert!(error.is_policy_limit());
        }
        // The largest u64 count saturates instead of overflowing the length
        // arithmetic.
        let huge = [fork.as_slice(), &[0xff; 9]].concat();
        assert_eq!(
            decode(&huge),
            Err(StaleTipError::TooManyHeaders(usize::MAX))
        );
    }

    #[test]
    fn over_limit_is_the_only_policy_limit() {
        assert!(StaleTipError::TooManyHeaders(21).is_policy_limit());
        for malformed in [
            StaleTipError::Truncated,
            StaleTipError::NonCanonical,
            StaleTipError::NoHeaders,
            StaleTipError::InvalidBool(2),
            StaleTipError::Trailing(1),
        ] {
            assert!(!malformed.is_policy_limit(), "{malformed}");
        }
    }

    #[test]
    fn staletip_has_a_command_and_no_short_id() {
        assert_eq!(STALETIP_COMMAND, "staletip");
        assert!(STALETIP_COMMAND.len() <= 12, "fits the v1 command field");
    }
}
