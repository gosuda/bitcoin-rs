use std::fmt::{self, Write as _};

use bitcoin::hashes::{Hash as _, HashEngine as _, sha256};
use serde::{Deserialize, Serialize};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// SHA256 hash used by Electrum's scripthash subscription status.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
)]
#[repr(C)]
pub struct StatusHash {
    bytes: [u8; 32],
}

impl StatusHash {
    /// Creates a status hash from raw SHA256 bytes.
    pub const fn from_byte_array(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Returns the raw SHA256 bytes.
    pub const fn to_byte_array(self) -> [u8; 32] {
        self.bytes
    }
}

impl fmt::Display for StatusHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Confirmation state encoded in Electrum history status strings.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum HistoryHeight {
    /// Confirmed transaction at the contained block height.
    Confirmed(u32),
    /// Unconfirmed transaction; `true` maps to `-1`, `false` maps to `0`.
    Unconfirmed {
        /// Whether this transaction spends an unconfirmed parent.
        has_unconfirmed_inputs: bool,
    },
}

impl HistoryHeight {
    /// Returns the integer value used in Electrum history and status hashing.
    pub fn as_i64(self) -> i64 {
        match self {
            Self::Confirmed(height) => i64::from(height),
            Self::Unconfirmed {
                has_unconfirmed_inputs: true,
            } => -1,
            Self::Unconfirmed {
                has_unconfirmed_inputs: false,
            } => 0,
        }
    }
}

impl fmt::Display for HistoryHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_i64().fmt(f)
    }
}

/// Transaction history entry contributing to a scripthash status hash.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Transaction id in Bitcoin display order.
    pub txid: bitcoin::Txid,
    /// Confirmed or mempool height state.
    pub height: HistoryHeight,
}

impl HistoryEntry {
    /// Creates a confirmed history entry.
    pub const fn confirmed(txid: bitcoin::Txid, height: u32) -> Self {
        Self {
            txid,
            height: HistoryHeight::Confirmed(height),
        }
    }

    /// Creates an unconfirmed history entry.
    pub const fn unconfirmed(txid: bitcoin::Txid, has_unconfirmed_inputs: bool) -> Self {
        Self {
            txid,
            height: HistoryHeight::Unconfirmed {
                has_unconfirmed_inputs,
            },
        }
    }

    fn hash(self, engine: &mut sha256::HashEngine) -> fmt::Result {
        let mut writer = EngineWriter { engine };
        write!(writer, "{}:{}:", self.txid, self.height)
    }
}

/// Computes Electrum's scripthash status hash for already ordered history entries.
pub fn compute_status_hash(history: &[HistoryEntry]) -> Option<StatusHash> {
    if history.is_empty() {
        return None;
    }
    let mut engine = sha256::Hash::engine();
    for entry in history {
        entry.hash(&mut engine).ok()?;
    }
    Some(StatusHash::from_byte_array(
        sha256::Hash::from_engine(engine).to_byte_array(),
    ))
}

struct EngineWriter<'a> {
    engine: &'a mut sha256::HashEngine,
}

impl fmt::Write for EngineWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.engine.input(s.as_bytes());
        Ok(())
    }
}
