use core::{
    fmt,
    mem::{align_of, size_of},
};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::Hash256;

/// A Bitcoin transaction outpoint in consensus byte layout.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(C, packed)]
pub struct OutPoint {
    /// The referenced transaction id in little-endian consensus byte order.
    pub txid: Hash256,
    /// The referenced output index.
    pub vout: u32,
}

const _: () = assert!(size_of::<OutPoint>() == 36);
const _: () = assert!(size_of::<Hash256>() == 32);
const _: () = assert!(align_of::<OutPoint>() == 1);

impl OutPoint {
    /// Constructs a new outpoint.
    #[must_use]
    pub const fn new(txid: Hash256, vout: u32) -> Self {
        Self { txid, vout }
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
    use crate::Hash256;

    #[test]
    fn outpoint_bytes_are_txid_then_vout_little_endian() {
        let mut txid = [0_u8; 32];
        for (slot, value) in txid.iter_mut().zip(0_u8..32) {
            *slot = value;
        }
        let outpoint = OutPoint::new(Hash256::from_le_bytes(&txid), 0x0a0b_0c0d);

        let bytes = outpoint.as_bytes();

        assert_eq!(bytes.len(), 36);
        assert_eq!(&bytes[..32], &txid);
        assert_eq!(&bytes[32..], &[0x0d, 0x0c, 0x0b, 0x0a]);
    }
}
