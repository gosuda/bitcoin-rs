//! Identifier newtypes over [`Hash256`]: transaction, witness-transaction, and block hashes.
//!
//! Each newtype is `#[repr(transparent)]` over [`Hash256`] and deliberately implements **no**
//! `Deref`: mixing a [`Txid`] with a [`Wtxid`] or a [`BlockHash`] is a compile error rather
//! than a silent coercion. Storage seams that need the raw 32-byte consensus encoding call
//! `as_bytes()`.

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
