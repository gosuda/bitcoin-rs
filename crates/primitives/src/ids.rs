//! Identifier newtypes over [`Hash256`]: transaction, witness-transaction, and block hashes.
//!
//! Each newtype is `#[repr(transparent)]` over [`Hash256`] and deliberately implements **no**
//! `Deref`: mixing a [`Txid`] with a [`Wtxid`] or a [`BlockHash`] is a compile error rather
//! than a silent coercion. Storage seams that need the raw 32-byte consensus encoding call
//! `as_bytes()`; packed key layouts are unchanged.

use core::fmt;
use core::str::FromStr;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{Hash256, HashError};

macro_rules! identifier_newtype {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(
            Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash,
            FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
        )]
        #[repr(transparent)]
        pub struct $name(pub Hash256);

        impl $name {
            /// Returns the 32-byte consensus (little-endian) encoding.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_byte_array()
            }
        }

        impl From<Hash256> for $name {
            fn from(hash: Hash256) -> Self {
                Self(hash)
            }
        }

        impl From<$name> for Hash256 {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = HashError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(Hash256::from_str_be(s)?))
            }
        }
    };
}

identifier_newtype!(
    /// The double-SHA256 of a transaction's non-witness serialization.
    Txid
);

identifier_newtype!(
    /// The double-SHA256 of a transaction's full serialization including witness data.
    Wtxid
);

identifier_newtype!(
    /// The double-SHA256 of an 80-byte block header.
    BlockHash
);

#[cfg(test)]
mod tests {
    use super::{BlockHash, Txid, Wtxid};
    use crate::Hash256;

    #[test]
    fn as_bytes_exposes_consensus_byte_order() {
        let bytes = [0x07_u8; 32];
        let txid = Txid::from(Hash256::from_le_bytes(&bytes));

        assert_eq!(txid.as_bytes(), &bytes);
        assert_eq!(Wtxid::default().as_bytes(), &[0_u8; 32]);
    }

    #[test]
    fn identifier_types_are_distinct_despite_same_layout() {
        let hash = Hash256::from_le_bytes(&[0x0b_u8; 32]);
        // No `From`/`Deref` conversion exists between identifier types; mixing is a compile
        // error. The assertions below only pin that each wraps the same 32 bytes.
        assert_eq!(
            Txid::from(hash).as_bytes(),
            BlockHash::from(hash).as_bytes()
        );
    }
}
