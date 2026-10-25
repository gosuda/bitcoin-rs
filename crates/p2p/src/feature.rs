//! BIP434 feature negotiation message codec.
//!
//! BIP434 defines a pre-`verack` negotiation message with command string `"feature"`.
//! A feature announcement carries a feature identifier (`featureid`) and associated data
//! (`featuredata`), each prefixed with a minimal `CompactSize` integer.

use bitcoin_rs_primitives::varint;

/// Protocol version that implements BIP434 feature negotiation.
pub const FEATURE_VERSION: u32 = 70_017;

/// P2P command string for feature announcements.
pub const FEATURE_COMMAND: &str = "feature";

/// BIP324 short message type ID for the `feature` command.
pub const FEATURE_V2_SHORT_ID: u8 = 37;

/// Minimum length of a feature identifier in bytes.
pub const MIN_ID_LEN: usize = 4;

/// Maximum length of a feature identifier in bytes.
pub const MAX_ID_LEN: usize = 80;

/// Maximum length of feature data in bytes.
pub const MAX_DATA_LEN: usize = 512;

/// BIP332 stale-tip relay feature identifier.
pub(crate) const BIP332_ID: &[u8] = b"BIP332";

/// A feature identifier negotiated via BIP434.
///
/// Locally advertised identifiers must be 4 to 80 bytes of printable ASCII (`0x20..=0x7e`).
/// Inbound identifiers from remote peers may contain any byte values, provided their length
/// is within 4 to 80 bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FeatureId(Vec<u8>);

impl FeatureId {
    /// Constructs a locally advertised feature identifier.
    ///
    /// Validates that the identifier is 4 to 80 bytes long and contains only
    /// printable ASCII characters (`0x20..=0x7e`). Returns `None` if invalid.
    #[must_use]
    pub fn advertised(bytes: &[u8]) -> Option<Self> {
        if !(MIN_ID_LEN..=MAX_ID_LEN).contains(&bytes.len()) {
            return None;
        }
        if !bytes.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
            return None;
        }
        Some(Self(bytes.to_vec()))
    }

    /// Returns the raw identifier bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Internal constructor for decoded identifiers from remote peers.
    ///
    /// PRE: `bytes.len()` is within `MIN_ID_LEN..=MAX_ID_LEN`.
    pub(crate) fn from_raw_unchecked(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for FeatureId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::borrow::Borrow<[u8]> for FeatureId {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq<[u8]> for FeatureId {
    fn eq(&self, other: &[u8]) -> bool {
        self.0.as_slice() == other
    }
}

impl PartialEq<str> for FeatureId {
    fn eq(&self, other: &str) -> bool {
        self.0.as_slice() == other.as_bytes()
    }
}

/// A BIP434 feature announcement message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureAnnouncement {
    /// The feature identifier.
    pub id: FeatureId,
    /// The associated feature data (at most 512 bytes).
    pub data: Vec<u8>,
}

impl FeatureAnnouncement {
    /// Constructs a new feature announcement.
    #[must_use]
    pub const fn new(id: FeatureId, data: Vec<u8>) -> Self {
        Self { id, data }
    }

    /// Whether this node implements the announced feature and `data` is valid
    /// for it.
    ///
    /// This is the one owner of the recognised-feature set. A receiver retains
    /// only announcements for which it returns `true`, so the per-peer
    /// announcement map holds at most one entry per recognised feature
    /// whatever the peer sends. Unknown identifiers, printable or not, and
    /// recognised identifiers with invalid data are ignored (BIP434 requires
    /// ignoring the former; BIP332 the latter): a BIP332 payload is exactly
    /// one byte, `0` or `1`.
    pub(crate) fn is_supported(&self) -> bool {
        self.id.as_bytes() == BIP332_ID && matches!(self.data.as_slice(), [0 | 1])
    }
}

/// Errors occurring during BIP434 feature announcement encoding or decoding.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FeatureError {
    /// The buffer ended before the message was complete.
    #[error("truncated feature payload")]
    Truncated,
    /// A `CompactSize` integer used a non-canonical encoding.
    #[error("non-canonical compact size")]
    NonCanonical,
    /// The feature identifier length was outside `4..=80`.
    #[error("feature id length {0} outside valid range 4..=80")]
    IdLength(usize),
    /// The feature data length exceeded 512 bytes.
    #[error("feature data length {0} exceeds bound 512")]
    DataTooLong(usize),
    /// Trailing bytes were left after decoding the feature message.
    #[error("trailing {0} bytes after feature payload")]
    Trailing(usize),
}

/// Encodes a [`FeatureAnnouncement`] into wire bytes according to BIP434.
///
/// Both `featureid` and `featuredata` are prefixed with minimal `CompactSize` integers.
/// Validates bounds before allocating.
pub fn encode(announcement: &FeatureAnnouncement) -> Result<Vec<u8>, FeatureError> {
    let id_bytes = announcement.id.as_bytes();
    if !(MIN_ID_LEN..=MAX_ID_LEN).contains(&id_bytes.len()) {
        return Err(FeatureError::IdLength(id_bytes.len()));
    }
    if announcement.data.len() > MAX_DATA_LEN {
        return Err(FeatureError::DataTooLong(announcement.data.len()));
    }

    let id_len_u64 =
        u64::try_from(id_bytes.len()).map_err(|_| FeatureError::IdLength(id_bytes.len()))?;
    let data_len_u64 = u64::try_from(announcement.data.len())
        .map_err(|_| FeatureError::DataTooLong(announcement.data.len()))?;

    let total_len = varint::encoded_len(id_len_u64)
        .checked_add(id_bytes.len())
        .and_then(|l| l.checked_add(varint::encoded_len(data_len_u64)))
        .and_then(|l| l.checked_add(announcement.data.len()))
        .ok_or(FeatureError::DataTooLong(announcement.data.len()))?;

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&varint::encode(id_len_u64));
    out.extend_from_slice(id_bytes);
    out.extend_from_slice(&varint::encode(data_len_u64));
    out.extend_from_slice(&announcement.data);
    Ok(out)
}

/// Decodes a [`FeatureAnnouncement`] from wire bytes according to BIP434.
///
/// Accepts any byte values for `featureid` provided length is in `4..=80`.
/// Rejects truncation, non-canonical `CompactSize`, out-of-range lengths,
/// data exceeding 512 bytes, and trailing bytes.
/// Performs no allocation on invalid lengths.
pub fn decode(bytes: &[u8]) -> Result<FeatureAnnouncement, FeatureError> {
    // 1. Decode CompactSize length of featureid.
    let (id_len_u64, id_len_bytes) = varint::decode(bytes).map_err(|err| match err {
        varint::VarintError::Truncated { .. } => FeatureError::Truncated,
        varint::VarintError::NonCanonical { .. } => FeatureError::NonCanonical,
    })?;

    let id_len = usize::try_from(id_len_u64).map_err(|_| FeatureError::IdLength(usize::MAX))?;
    if !(MIN_ID_LEN..=MAX_ID_LEN).contains(&id_len) {
        return Err(FeatureError::IdLength(id_len));
    }

    let rest = &bytes[id_len_bytes..];
    if rest.len() < id_len {
        return Err(FeatureError::Truncated);
    }
    let id_raw = &rest[..id_len];
    let rest = &rest[id_len..];

    // 2. Decode CompactSize length of featuredata.
    let (data_len_u64, data_len_bytes) = varint::decode(rest).map_err(|err| match err {
        varint::VarintError::Truncated { .. } => FeatureError::Truncated,
        varint::VarintError::NonCanonical { .. } => FeatureError::NonCanonical,
    })?;

    let data_len =
        usize::try_from(data_len_u64).map_err(|_| FeatureError::DataTooLong(usize::MAX))?;
    // data <= 512 checked BEFORE allocation.
    if data_len > MAX_DATA_LEN {
        return Err(FeatureError::DataTooLong(data_len));
    }

    let rest = &rest[data_len_bytes..];
    if rest.len() < data_len {
        return Err(FeatureError::Truncated);
    }
    let data_raw = &rest[..data_len];
    let tail = &rest[data_len..];

    // 3. Exact consumption: reject trailing bytes.
    if !tail.is_empty() {
        return Err(FeatureError::Trailing(tail.len()));
    }

    // 4. Construct validated announcement.
    let id = FeatureId::from_raw_unchecked(id_raw.to_vec());
    let data = data_raw.to_vec();

    Ok(FeatureAnnouncement { id, data })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertised_id_validates_length_bounds() {
        // Less than 4 bytes: rejected.
        assert_eq!(FeatureId::advertised(b""), None);
        assert_eq!(FeatureId::advertised(b"a"), None);
        assert_eq!(FeatureId::advertised(b"ab"), None);
        assert_eq!(FeatureId::advertised(b"abc"), None);

        // Exactly 4 bytes: accepted.
        let Some(id4) = FeatureId::advertised(b"abcd") else {
            panic!("4-byte advertised id should be valid");
        };
        assert_eq!(id4.as_bytes(), b"abcd");

        // Exactly 80 bytes: accepted.
        let id80_bytes = [b'x'; 80];
        let Some(id80) = FeatureId::advertised(&id80_bytes) else {
            panic!("80-byte advertised id should be valid");
        };
        assert_eq!(id80.as_bytes(), &id80_bytes);

        // 81 bytes: rejected.
        let id81_bytes = [b'x'; 81];
        assert_eq!(FeatureId::advertised(&id81_bytes), None);
    }

    #[test]
    fn advertised_id_restricts_to_printable_ascii() {
        // Range 0x20..=0x7e must be accepted.
        let min_printable = FeatureId::advertised(b"    "); // 4 spaces (0x20)
        assert!(min_printable.is_some());
        let max_printable = FeatureId::advertised(b"~~~~"); // 4 tildes (0x7e)
        assert!(max_printable.is_some());

        // Control characters (< 0x20) rejected.
        assert_eq!(FeatureId::advertised(b"abc\0"), None);
        assert_eq!(FeatureId::advertised(b"abc\x1f"), None);
        assert_eq!(FeatureId::advertised(b"\x01bcd"), None);

        // DEL (0x7f) rejected.
        assert_eq!(FeatureId::advertised(b"abc\x7f"), None);

        // Non-ASCII (>= 0x80) rejected.
        assert_eq!(FeatureId::advertised(b"abc\x80"), None);
        assert_eq!(FeatureId::advertised(b"abc\xff"), None);
    }

    #[test]
    fn decoder_accepts_arbitrary_binary_ids_within_bounds() -> Result<(), FeatureError> {
        // Remote peers can send non-printable or non-ASCII feature IDs.
        let binary_id = vec![0x00, 0x1f, 0x7f, 0xff];
        let announcement = FeatureAnnouncement {
            id: FeatureId::from_raw_unchecked(binary_id.clone()),
            data: vec![1, 2, 3],
        };
        let encoded = encode(&announcement)?;
        let decoded = decode(&encoded)?;
        assert_eq!(decoded.id.as_bytes(), binary_id.as_slice());
        assert_eq!(decoded.data, vec![1, 2, 3]);
        Ok(())
    }

    #[test]
    fn roundtrip_minimal_and_maximal_payloads() -> Result<(), FeatureError> {
        // Minimal ID (4 bytes) and empty data (0 bytes).
        let Some(min_id) = FeatureId::advertised(b"test") else {
            panic!("test id should be valid");
        };
        let min = FeatureAnnouncement {
            id: min_id,
            data: vec![],
        };
        let min_encoded = encode(&min)?;
        assert_eq!(min_encoded.len(), 1 + 4 + 1);
        assert_eq!(decode(&min_encoded)?, min);

        // Maximal ID (80 bytes) and maximal data (512 bytes).
        let Some(max_id) = FeatureId::advertised(&[b'z'; 80]) else {
            panic!("80-byte id should be valid");
        };
        let max = FeatureAnnouncement {
            id: max_id,
            data: vec![0x42; 512],
        };
        let max_encoded = encode(&max)?;
        assert_eq!(decode(&max_encoded)?, max);
        Ok(())
    }

    #[test]
    fn reject_oversized_data_before_allocation() {
        let Some(test_id) = FeatureId::advertised(b"test") else {
            panic!("test id should be valid");
        };
        let oversized = FeatureAnnouncement {
            id: test_id,
            data: vec![0u8; 513],
        };
        assert_eq!(encode(&oversized), Err(FeatureError::DataTooLong(513)));

        // Craft a wire payload declaring data_len = 513 with minimal CompactSize (0xfd, 0x01, 0x02).
        let mut wire = Vec::new();
        wire.push(4); // id len
        wire.extend_from_slice(b"test");
        wire.extend_from_slice(&varint::encode(513));
        // Even without supplying 513 bytes, DataTooLong is returned, not Truncated.
        assert_eq!(decode(&wire), Err(FeatureError::DataTooLong(513)));
    }

    #[test]
    fn reject_id_length_out_of_bounds() {
        // ID length 3 (below MIN_ID_LEN).
        let mut wire = Vec::new();
        wire.push(3);
        wire.extend_from_slice(b"abc");
        wire.push(0); // data len 0
        assert_eq!(decode(&wire), Err(FeatureError::IdLength(3)));

        // ID length 81 (above MAX_ID_LEN).
        let mut wire = Vec::new();
        wire.push(81);
        wire.extend_from_slice(&[b'x'; 81]);
        wire.push(0);
        assert_eq!(decode(&wire), Err(FeatureError::IdLength(81)));
    }

    #[test]
    fn reject_non_canonical_compact_size() {
        // Non-canonical id length: 4 encoded as 3-byte varint (0xfd, 0x04, 0x00).
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0xfd, 0x04, 0x00]);
        wire.extend_from_slice(b"test");
        wire.push(0);
        assert_eq!(decode(&wire), Err(FeatureError::NonCanonical));

        // Non-canonical data length: 0 encoded as 3-byte varint (0xfd, 0x00, 0x00).
        let mut wire = Vec::new();
        wire.push(4);
        wire.extend_from_slice(b"test");
        wire.extend_from_slice(&[0xfd, 0x00, 0x00]);
        assert_eq!(decode(&wire), Err(FeatureError::NonCanonical));
    }

    #[test]
    fn reject_truncated_payload() {
        // Empty buffer.
        assert_eq!(decode(&[]), Err(FeatureError::Truncated));

        // Incomplete varint.
        assert_eq!(decode(&[0xfd]), Err(FeatureError::Truncated));

        // ID declared length 4, but only 2 bytes present.
        assert_eq!(decode(&[4, b'a', b'b']), Err(FeatureError::Truncated));

        // Missing data length varint.
        assert_eq!(
            decode(&[4, b'a', b'b', b'c', b'd']),
            Err(FeatureError::Truncated)
        );

        // Data declared length 5, but only 2 bytes present.
        assert_eq!(
            decode(&[4, b'a', b'b', b'c', b'd', 5, 1, 2]),
            Err(FeatureError::Truncated)
        );
    }

    fn announcement(id: &[u8], data: &[u8]) -> FeatureAnnouncement {
        FeatureAnnouncement::new(FeatureId::from_raw_unchecked(id.to_vec()), data.to_vec())
    }

    #[test]
    fn only_valid_bip332_announcements_are_supported() {
        assert!(announcement(b"BIP332", &[0]).is_supported());
        assert!(announcement(b"BIP332", &[1]).is_supported());

        // Recognised identifier, invalid payload: empty, wrong length, bad bool.
        assert!(!announcement(b"BIP332", &[]).is_supported());
        assert!(!announcement(b"BIP332", &[2]).is_supported());
        assert!(!announcement(b"BIP332", &[0xff]).is_supported());
        assert!(!announcement(b"BIP332", &[0, 1]).is_supported());
        assert!(!announcement(b"BIP332", &[0; 512]).is_supported());

        // Unknown identifiers are ignored whatever the payload, including ids
        // that are not printable ASCII or differ from BIP332 by case/suffix.
        assert!(!announcement(b"BIP434", &[1]).is_supported());
        assert!(!announcement(b"bip332", &[1]).is_supported());
        assert!(!announcement(b"BIP332v2", &[1]).is_supported());
        assert!(!announcement(&[0x00, 0x1f, 0x7f, 0xff], &[1]).is_supported());
    }

    #[test]
    fn reject_trailing_bytes() -> Result<(), FeatureError> {
        let Some(test_id) = FeatureId::advertised(b"test") else {
            panic!("test id should be valid");
        };
        let mut wire = encode(&FeatureAnnouncement {
            id: test_id,
            data: vec![1, 2, 3],
        })?;
        wire.push(0xaa);
        assert_eq!(decode(&wire), Err(FeatureError::Trailing(1)));

        wire.extend_from_slice(&[0xbb, 0xcc]);
        assert_eq!(decode(&wire), Err(FeatureError::Trailing(3)));
        Ok(())
    }
}
