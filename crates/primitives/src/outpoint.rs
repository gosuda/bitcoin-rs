use core::{
    fmt,
    mem::{align_of, size_of},
};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::Txid;

/// A Bitcoin transaction outpoint in consensus byte layout.
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct OutPoint {
    /// The referenced transaction id in little-endian consensus byte order.
    pub txid: Txid,
    /// The referenced output index.
    pub vout: u32,
}

const _: () = assert!(size_of::<OutPoint>() == 36);
const _: () = assert!(size_of::<Txid>() == 32);
const _: () = assert!(align_of::<OutPoint>() == 1);

impl OutPoint {
    /// Constructs a new outpoint.
    #[must_use]
    pub const fn new(txid: Txid, vout: u32) -> Self {
        Self { txid, vout }
    }

    /// Bitcoin's null / coinbase prevout: an all-zero txid with `vout == u32::MAX`.
    ///
    /// `OutPoint::default()` is the derived all-zero layout (`vout == 0`) and
    /// is not null. Consensus coinbase detection uses this predicate.
    #[must_use]
    pub fn is_null(self) -> bool {
        self.vout == u32::MAX && self.txid.as_bytes().iter().all(|&byte| byte == 0)
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let txid = self.txid;
        let vout = self.vout;
        write!(f, "{txid}:{vout}")
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::IntoBytes;

    use super::OutPoint;
    use crate::{Hash256, Txid};

    #[test]
    fn outpoint_bytes_are_txid_then_vout_little_endian() {
        let mut txid = [0_u8; 32];
        for (slot, value) in txid.iter_mut().zip(0_u8..32) {
            *slot = value;
        }
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&txid)), 0x0a0b_0c0d);

        let bytes = outpoint.as_bytes();

        assert_eq!(bytes.len(), 36);
        assert_eq!(&bytes[..32], &txid);
        assert_eq!(&bytes[32..], &[0x0d, 0x0c, 0x0b, 0x0a]);
        assert_eq!(
            outpoint.to_string(),
            Txid(Hash256::from_le_bytes(&txid)).to_string() + ":168496141"
        );
    }

    #[test]
    fn null_outpoint_is_zero_txid_and_max_vout() {
        let coinbase = OutPoint::new(Txid::default(), u32::MAX);
        assert!(coinbase.is_null());
        assert!(!OutPoint::default().is_null());
        assert!(!OutPoint::new(Txid::default(), 0).is_null());
    }
}
