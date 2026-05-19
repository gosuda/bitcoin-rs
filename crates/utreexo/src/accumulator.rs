use bitcoin_rs_primitives::Hash256;
use rustreexo::node_hash::BitcoinNodeHash;
use rustreexo::pollard::{Pollard, PollardAddition, PollardError};
use rustreexo::stump::{Stump, StumpError};
use thiserror::Error;

use crate::proof::Proof;

pub(crate) type NativeHash = BitcoinNodeHash;
type NativeStump = Stump<NativeHash>;
type NativePollard = Pollard<NativeHash>;

/// Selects which rustreexo accumulator state is retained by [`Accumulator`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccumulatorKind {
    /// Keep only the compact Stump state.
    Stump,
    /// Keep a Pollard beside the Stump so proofs can be cached/generated for remembered leaves.
    Pollard,
}

/// Errors returned by the Utreexo accumulator wrappers.
#[derive(Debug, Error)]
pub enum UtreexoError {
    /// The serialized accumulator state has an unknown type marker.
    #[error("unknown accumulator state marker {0}")]
    UnknownStateMarker(u8),
    /// The serialized accumulator state is empty.
    #[error("serialized accumulator state is empty")]
    EmptyState,
    /// The proof set does not match the requested deletion set.
    #[error("delete requested {requested} targets but proofs contain {proven}")]
    DeleteTargetMismatch {
        /// Number of deletion targets requested by the caller.
        requested: usize,
        /// Number of targets carried by the provided proofs.
        proven: usize,
    },
    /// A rustreexo Stump operation failed.
    #[error("stump error: {0:?}")]
    Stump(StumpError),
    /// A rustreexo Pollard operation failed.
    #[error("pollard error: {0}")]
    Pollard(PollardError<NativeHash>),
}

impl From<StumpError> for UtreexoError {
    fn from(error: StumpError) -> Self {
        Self::Stump(error)
    }
}

impl From<PollardError<NativeHash>> for UtreexoError {
    fn from(error: PollardError<NativeHash>) -> Self {
        Self::Pollard(error)
    }
}

/// Utreexo accumulator wrapper backed by rustreexo's Stump and optional Pollard.
#[derive(Clone, Debug)]
pub struct Accumulator {
    stump: NativeStump,
    pollard: Option<NativePollard>,
}

impl Accumulator {
    /// Creates an empty compact Stump accumulator.
    #[must_use]
    pub fn new_stump() -> Self {
        Self {
            stump: NativeStump::new(),
            pollard: None,
        }
    }

    /// Creates an empty Pollard accumulator and keeps its Stump roots in sync.
    #[must_use]
    pub fn new_pollard() -> Self {
        Self {
            stump: NativeStump::new(),
            pollard: Some(NativePollard::new()),
        }
    }

    /// Returns the retained accumulator kind.
    #[must_use]
    pub const fn kind(&self) -> AccumulatorKind {
        if self.pollard.is_some() {
            AccumulatorKind::Pollard
        } else {
            AccumulatorKind::Stump
        }
    }

    /// Adds leaf hashes to the accumulator.
    pub fn add(&mut self, hashes: &[Hash256]) -> Result<(), UtreexoError> {
        let adds = hashes
            .iter()
            .copied()
            .map(to_native_hash)
            .collect::<Vec<_>>();
        let (stump, _) = self
            .stump
            .modify(&adds, &[], &rustreexo::proof::Proof::default())?;
        self.stump = stump;

        if let Some(pollard) = &mut self.pollard {
            let additions = adds
                .iter()
                .copied()
                .map(|hash| PollardAddition {
                    hash,
                    remember: true,
                })
                .collect::<Vec<_>>();
            pollard.modify(&additions, &[], rustreexo::proof::Proof::default())?;
        }

        Ok(())
    }

    /// Deletes leaves proven by the supplied proofs.
    pub fn delete(&mut self, indexes: &[usize], proofs: &[Proof]) -> Result<(), UtreexoError> {
        let proven = proofs.iter().map(Proof::n_targets).sum::<usize>();
        if proven != indexes.len() {
            return Err(UtreexoError::DeleteTargetMismatch {
                requested: indexes.len(),
                proven,
            });
        }

        for proof in proofs {
            let del_hashes = proof.native_target_hashes();
            let (stump, _) = self.stump.modify(&[], &del_hashes, proof.native())?;
            self.stump = stump;

            if let Some(pollard) = &mut self.pollard {
                pollard.modify(&[], &del_hashes, proof.clone().into_native())?;
            }
        }

        Ok(())
    }

    /// Returns the current accumulator roots.
    #[must_use]
    pub fn roots(&self) -> Vec<Hash256> {
        self.stump
            .roots
            .iter()
            .copied()
            .map(from_native_hash)
            .collect()
    }

    /// Serializes the retained accumulator state.
    #[must_use]
    pub fn serialize_state(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        if let Some(pollard) = &self.pollard {
            bytes.push(1);
            if let Err(error) = pollard.serialize(&mut bytes) {
                unreachable!("serializing to Vec is infallible: {error}");
            }
        } else {
            bytes.push(0);
            if let Err(error) = self.stump.serialize(&mut bytes) {
                unreachable!("serializing to Vec is infallible: {error:?}");
            }
        }
        bytes
    }

    /// Deserializes an accumulator state produced by [`Self::serialize_state`].
    pub fn deserialize_state(bytes: &[u8]) -> Result<Self, UtreexoError> {
        let (marker, state) = bytes.split_first().ok_or(UtreexoError::EmptyState)?;
        match *marker {
            0 => {
                let stump = NativeStump::deserialize(state)?;
                Ok(Self {
                    stump,
                    pollard: None,
                })
            }
            1 => {
                let pollard = NativePollard::deserialize(&mut &state[..])?;
                let stump = NativeStump {
                    leaves: pollard.leaves(),
                    roots: pollard.roots(),
                };
                Ok(Self {
                    stump,
                    pollard: Some(pollard),
                })
            }
            other => Err(UtreexoError::UnknownStateMarker(other)),
        }
    }
}

pub(crate) fn to_native_hash(hash: Hash256) -> NativeHash {
    NativeHash::new(hash.to_le_bytes())
}

pub(crate) fn from_native_hash(hash: NativeHash) -> Hash256 {
    Hash256::from_le_bytes(&hash)
}
