//! Snapshot identity and validation state committed with the authoritative head.

use bitcoin_rs_primitives::Hash256;

/// One body durably retained before validation, but not exposed to index readers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingHistoricalBlock {
    /// Expected historical height.
    pub height: u32,
    /// Identity of the body being checked.
    #[serde(with = "serde_hash256")]
    pub hash: Hash256,
    /// Staged flat-file position; volatile stores have no position.
    pub position: Option<crate::BlockFilePosition>,
}

/// The latest complete historical checkpoint accepted by the durable head.
///
/// The checkpoint files are recovery artifacts.  The durable head remains the
/// authority for whether this generation may be used and how far historical
/// validation has durably progressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoricalCheckpointRef {
    /// Published generation and manifest digest in the historical namespace.
    pub checkpoint: crate::checkpoint::CheckpointReference,
    /// Historical applied height represented by the checkpoint.
    pub height: u32,
    /// Historical applied block hash represented by the checkpoint.
    #[serde(with = "serde_hash256")]
    pub hash: Hash256,
}

mod serde_hash256 {
    use bitcoin_rs_primitives::Hash256;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(hash: &Hash256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hash.to_string())
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Hash256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<Hash256>().map_err(serde::de::Error::custom)
    }
}

/// The persistent lifecycle status of `AssumeUTXO` coordination.
/// The durable head owns this record; commitments use
/// Bitcoin Core's serialized-set hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AssumeUtxoDiskStatus {
    /// No `AssumeUTXO` snapshot has been activated.
    Uninitialized,
    /// Snapshot is active; background historical validation is progressing towards `base_height`.
    Validating {
        /// Block height of the snapshot base.
        base_height: u32,
        /// Block hash of the snapshot base.
        #[serde(with = "serde_hash256")]
        base_hash: Hash256,
        /// Pinned expected UTXO commitment (`hash_serialized_3`) at `base_height`.
        #[serde(with = "serde_hash256")]
        expected_hash_serialized: Hash256,
        /// Cumulative transaction count through `base_height`.
        chain_tx_count: u64,
        /// Last durably archived historical height; live coins may be replaying below it.
        historical_height: u32,
        /// Hash of the last durably archived historical block.
        #[serde(with = "serde_hash256")]
        historical_hash: Hash256,
        /// Unfinished validation must complete during startup before serving.
        pending: Option<PendingHistoricalBlock>,
        /// Latest complete historical checkpoint accepted by the durable head.
        checkpoint: Option<HistoricalCheckpointRef>,
    },
    /// Background historical validation succeeded and matched the pinned commitment.
    /// Chainstate roles have converged to `Ordinary`.
    Finalized {
        /// Block height of the validated snapshot base.
        base_height: u32,
        /// Block hash of the validated snapshot base.
        #[serde(with = "serde_hash256")]
        base_hash: Hash256,
        /// Verified UTXO commitment (`hash_serialized_3`) at `base_height`.
        #[serde(with = "serde_hash256")]
        validated_hash_serialized: Hash256,
    },
    /// Background validation failed (e.g. commitment mismatch). The node must fail closed.
    Failed {
        /// Block height of the snapshot base.
        base_height: u32,
        /// Block hash of the snapshot base.
        #[serde(with = "serde_hash256")]
        base_hash: Hash256,
        /// Expected UTXO commitment (`hash_serialized_3`).
        #[serde(with = "serde_hash256")]
        expected_hash_serialized: Hash256,
        /// Reconstructed actual UTXO commitment (`hash_serialized_3`).
        #[serde(with = "serde_hash256")]
        actual_hash_serialized: Hash256,
    },
}

impl AssumeUtxoDiskStatus {
    const CHECKPOINT_ENCODED_LEN: usize = 77;
    pub(crate) const ENCODED_LEN: usize = 166 + Self::CHECKPOINT_ENCODED_LEN;

    pub(crate) fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0; Self::ENCODED_LEN];
        match self {
            Self::Uninitialized => {}
            Self::Validating {
                base_height,
                base_hash,
                expected_hash_serialized,
                chain_tx_count,
                historical_height,
                historical_hash,
                pending,
                checkpoint,
            } => {
                out[0] = 1;
                out[1..5].copy_from_slice(&base_height.to_be_bytes());
                out[5..37].copy_from_slice(base_hash.as_byte_array());
                out[37..69].copy_from_slice(expected_hash_serialized.as_byte_array());
                out[69..77].copy_from_slice(&chain_tx_count.to_be_bytes());
                out[77..81].copy_from_slice(&historical_height.to_be_bytes());
                out[81..113].copy_from_slice(historical_hash.as_byte_array());
                if let Some(pending) = pending {
                    out[113] = if pending.position.is_some() { 2 } else { 1 };
                    out[114..118].copy_from_slice(&pending.height.to_be_bytes());
                    out[118..150].copy_from_slice(pending.hash.as_byte_array());
                    if let Some(position) = pending.position {
                        out[150..166].copy_from_slice(&position.encode());
                    }
                }
                if let Some(checkpoint) = checkpoint {
                    out[166] = 1;
                    out[167..175].copy_from_slice(&checkpoint.checkpoint.generation.to_be_bytes());
                    out[175..179].copy_from_slice(&checkpoint.height.to_be_bytes());
                    out[179..211].copy_from_slice(checkpoint.hash.as_byte_array());
                    out[211..243].copy_from_slice(&checkpoint.checkpoint.manifest_sha256);
                }
            }
            Self::Finalized {
                base_height,
                base_hash,
                validated_hash_serialized,
            } => {
                out[0] = 2;
                out[1..5].copy_from_slice(&base_height.to_be_bytes());
                out[5..37].copy_from_slice(base_hash.as_byte_array());
                out[37..69].copy_from_slice(validated_hash_serialized.as_byte_array());
            }
            Self::Failed {
                base_height,
                base_hash,
                expected_hash_serialized,
                actual_hash_serialized,
            } => {
                out[0] = 3;
                out[1..5].copy_from_slice(&base_height.to_be_bytes());
                out[5..37].copy_from_slice(base_hash.as_byte_array());
                out[37..69].copy_from_slice(expected_hash_serialized.as_byte_array());
                out[81..113].copy_from_slice(actual_hash_serialized.as_byte_array());
            }
        }
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::ENCODED_LEN {
            return None;
        }
        let base_height = u32::from_be_bytes(bytes[1..5].try_into().ok()?);
        let base_hash = Hash256::from_le_bytes(bytes[5..37].try_into().ok()?);
        let commitment = Hash256::from_le_bytes(bytes[37..69].try_into().ok()?);
        let tail_hash = Hash256::from_le_bytes(bytes[81..113].try_into().ok()?);
        let status = match bytes[0] {
            0 => Self::Uninitialized,
            1 => Self::Validating {
                base_height,
                base_hash,
                expected_hash_serialized: commitment,
                chain_tx_count: u64::from_be_bytes(bytes[69..77].try_into().ok()?),
                historical_height: u32::from_be_bytes(bytes[77..81].try_into().ok()?),
                historical_hash: tail_hash,
                pending: match bytes[113] {
                    0 => None,
                    tag @ (1 | 2) => Some(PendingHistoricalBlock {
                        height: u32::from_be_bytes(bytes[114..118].try_into().ok()?),
                        hash: Hash256::from_le_bytes(bytes[118..150].try_into().ok()?),
                        position: if tag == 2 {
                            Some(crate::BlockFilePosition::decode(&bytes[150..166])?)
                        } else {
                            None
                        },
                    }),
                    _ => return None,
                },
                checkpoint: match bytes[166] {
                    0 => None,
                    1 => Some(HistoricalCheckpointRef {
                        checkpoint: crate::checkpoint::CheckpointReference {
                            generation: u64::from_be_bytes(bytes[167..175].try_into().ok()?),
                            manifest_sha256: bytes[211..243].try_into().ok()?,
                        },
                        height: u32::from_be_bytes(bytes[175..179].try_into().ok()?),
                        hash: Hash256::from_le_bytes(&bytes[179..211].try_into().ok()?),
                    }),
                    _ => return None,
                },
            },
            2 => Self::Finalized {
                base_height,
                base_hash,
                validated_hash_serialized: commitment,
            },
            3 => Self::Failed {
                base_height,
                base_hash,
                expected_hash_serialized: commitment,
                actual_hash_serialized: tail_hash,
            },
            _ => return None,
        };
        (status.encode() == bytes).then_some(status)
    }
}
