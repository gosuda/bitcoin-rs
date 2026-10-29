//! BIP434 feature negotiation message codec.

use bitcoin_rs_primitives::varint;

/// Protocol version that implements BIP434 feature negotiation.
pub const FEATURE_VERSION: u32 = 70_017;

pub const FEATURE_COMMAND: &str = "feature";

/// BIP324 short message type ID for the `feature` command.
pub const FEATURE_V2_SHORT_ID: u8 = 37;

pub const MIN_ID_LEN: usize = 4;

pub const MAX_ID_LEN: usize = 80;

pub const MAX_DATA_LEN: usize = 512;

/// BIP332 stale-tip relay feature identifier.
pub(crate) const BIP332_ID: &[u8] = b"BIP332";

/// A feature identifier negotiated via BIP434.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FeatureId(Vec<u8>);

impl FeatureId {
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

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

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
    pub id: FeatureId,
    pub data: Vec<u8>,
}

impl FeatureAnnouncement {
    #[must_use]
    pub const fn new(id: FeatureId, data: Vec<u8>) -> Self {
        Self { id, data }
    }

    /// This node's BIP332 stale-tip relay announcement; `prefers_blocks` is
    pub(crate) fn bip332(prefers_blocks: bool) -> Self {
        Self::new(
            FeatureId::from_raw_unchecked(BIP332_ID.to_vec()),
            vec![u8::from(prefers_blocks)],
        )
    }

    /// recognised identifiers with invalid data are ignored (BIP434 requires
    /// ignoring the former; BIP332 the latter): a BIP332 payload is exactly
    pub(crate) fn is_supported(&self) -> bool {
        self.id.as_bytes() == BIP332_ID && matches!(self.data.as_slice(), [0 | 1])
    }
}

/// Errors occurring during BIP434 feature announcement encoding or decoding.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FeatureError {
    #[error("truncated feature payload")]
    Truncated,
    #[error("non-canonical compact size")]
    NonCanonical,
    #[error("feature id length {0} outside valid range 4..=80")]
    IdLength(usize),
    #[error("feature data length {0} exceeds bound 512")]
    DataTooLong(usize),
    #[error("trailing {0} bytes after feature payload")]
    Trailing(usize),
}

/// Encodes a [`FeatureAnnouncement`] into wire bytes according to BIP434.
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
pub fn decode(bytes: &[u8]) -> Result<FeatureAnnouncement, FeatureError> {
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

    let (data_len_u64, data_len_bytes) = varint::decode(rest).map_err(|err| match err {
        varint::VarintError::Truncated { .. } => FeatureError::Truncated,
        varint::VarintError::NonCanonical { .. } => FeatureError::NonCanonical,
    })?;

    let data_len =
        usize::try_from(data_len_u64).map_err(|_| FeatureError::DataTooLong(usize::MAX))?;
    if data_len > MAX_DATA_LEN {
        return Err(FeatureError::DataTooLong(data_len));
    }

    let rest = &rest[data_len_bytes..];
    if rest.len() < data_len {
        return Err(FeatureError::Truncated);
    }
    let data_raw = &rest[..data_len];
    let tail = &rest[data_len..];

    if !tail.is_empty() {
        return Err(FeatureError::Trailing(tail.len()));
    }

    let id = FeatureId::from_raw_unchecked(id_raw.to_vec());
    let data = data_raw.to_vec();

    Ok(FeatureAnnouncement { id, data })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertised_id_validates_length_bounds() {
        assert_eq!(FeatureId::advertised(b""), None);
        assert_eq!(FeatureId::advertised(b"a"), None);
        assert_eq!(FeatureId::advertised(b"ab"), None);
        assert_eq!(FeatureId::advertised(b"abc"), None);

        let Some(id4) = FeatureId::advertised(b"abcd") else {
            panic!("4-byte advertised id should be valid");
        };
        assert_eq!(id4.as_bytes(), b"abcd");

        let id80_bytes = [b'x'; 80];
        let Some(id80) = FeatureId::advertised(&id80_bytes) else {
            panic!("80-byte advertised id should be valid");
        };
        assert_eq!(id80.as_bytes(), &id80_bytes);

        let id81_bytes = [b'x'; 81];
        assert_eq!(FeatureId::advertised(&id81_bytes), None);
    }

    #[test]
    fn advertised_id_restricts_to_printable_ascii() {
        let min_printable = FeatureId::advertised(b"    ");
        assert!(min_printable.is_some());
        let max_printable = FeatureId::advertised(b"~~~~");
        assert!(max_printable.is_some());

        assert_eq!(FeatureId::advertised(b"abc\0"), None);
        assert_eq!(FeatureId::advertised(b"abc\x1f"), None);
        assert_eq!(FeatureId::advertised(b"\x01bcd"), None);

        assert_eq!(FeatureId::advertised(b"abc\x7f"), None);

        assert_eq!(FeatureId::advertised(b"abc\x80"), None);
        assert_eq!(FeatureId::advertised(b"abc\xff"), None);
    }

    #[test]
    fn decoder_accepts_arbitrary_binary_ids_within_bounds() -> Result<(), FeatureError> {
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

        let mut wire = Vec::new();
        wire.push(4);
        wire.extend_from_slice(b"test");
        wire.extend_from_slice(&varint::encode(513));
        assert_eq!(decode(&wire), Err(FeatureError::DataTooLong(513)));
    }

    #[test]
    fn reject_id_length_out_of_bounds() {
        let mut wire = Vec::new();
        wire.push(3);
        wire.extend_from_slice(b"abc");
        wire.push(0);
        assert_eq!(decode(&wire), Err(FeatureError::IdLength(3)));

        let mut wire = Vec::new();
        wire.push(81);
        wire.extend_from_slice(&[b'x'; 81]);
        wire.push(0);
        assert_eq!(decode(&wire), Err(FeatureError::IdLength(81)));
    }

    #[test]
    fn reject_non_canonical_compact_size() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0xfd, 0x04, 0x00]);
        wire.extend_from_slice(b"test");
        wire.push(0);
        assert_eq!(decode(&wire), Err(FeatureError::NonCanonical));

        let mut wire = Vec::new();
        wire.push(4);
        wire.extend_from_slice(b"test");
        wire.extend_from_slice(&[0xfd, 0x00, 0x00]);
        assert_eq!(decode(&wire), Err(FeatureError::NonCanonical));
    }

    #[test]
    fn reject_truncated_payload() {
        assert_eq!(decode(&[]), Err(FeatureError::Truncated));

        assert_eq!(decode(&[0xfd]), Err(FeatureError::Truncated));

        assert_eq!(decode(&[4, b'a', b'b']), Err(FeatureError::Truncated));

        assert_eq!(
            decode(&[4, b'a', b'b', b'c', b'd']),
            Err(FeatureError::Truncated)
        );

        assert_eq!(
            decode(&[4, b'a', b'b', b'c', b'd', 5, 1, 2]),
            Err(FeatureError::Truncated)
        );
    }

    #[test]
    fn local_bip332_announcement_is_advertisable_supported_and_one_byte() -> Result<(), FeatureError>
    {
        for prefers_blocks in [false, true] {
            let local = FeatureAnnouncement::bip332(prefers_blocks);
            assert!(local.is_supported());
            assert_eq!(local.data, vec![u8::from(prefers_blocks)]);
            assert!(
                FeatureId::advertised(local.id.as_bytes()).is_some(),
                "a locally advertised id is printable ASCII within the length bounds"
            );
            assert_eq!(decode(&encode(&local)?)?, local);
        }
        Ok(())
    }

    fn announcement(id: &[u8], data: &[u8]) -> FeatureAnnouncement {
        FeatureAnnouncement::new(FeatureId::from_raw_unchecked(id.to_vec()), data.to_vec())
    }

    #[test]
    fn only_valid_bip332_announcements_are_supported() {
        assert!(announcement(b"BIP332", &[0]).is_supported());
        assert!(announcement(b"BIP332", &[1]).is_supported());

        assert!(!announcement(b"BIP332", &[]).is_supported());
        assert!(!announcement(b"BIP332", &[2]).is_supported());
        assert!(!announcement(b"BIP332", &[0xff]).is_supported());
        assert!(!announcement(b"BIP332", &[0, 1]).is_supported());
        assert!(!announcement(b"BIP332", &[0; 512]).is_supported());

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
