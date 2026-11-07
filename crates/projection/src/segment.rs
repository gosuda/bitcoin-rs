pub mod format;
#[cfg(any(test, verification, kani))]
pub mod proofs;
#[cfg(test)]
mod tests;

use crate::IndexCapability;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coverage {
    pub first_height: u32,
    pub last_height: u32,
    pub last_hash: [u8; 32],
}

impl Coverage {
    #[must_use]
    pub const fn new(first_height: u32, last_height: u32, last_hash: [u8; 32]) -> Self {
        Self {
            first_height,
            last_height,
            last_hash,
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[0..4].copy_from_slice(&self.first_height.to_le_bytes());
        out[4..8].copy_from_slice(&self.last_height.to_le_bytes());
        out[8..40].copy_from_slice(&self.last_hash);
        out
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 40 {
            return None;
        }
        let first_height = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        let last_height = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        let mut last_hash = [0u8; 32];
        last_hash.copy_from_slice(&bytes[8..40]);
        Some(Self {
            first_height,
            last_height,
            last_hash,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TailDescriptor {
    pub tail_lo: u32,
    pub tail_hi: u32,
    pub tail_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationDescriptor {
    pub gen_id: u64,
    pub coverage: Coverage,
    pub tail: TailDescriptor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentRef {
    pub gen_id: u64,
    pub capability: IndexCapability,
    pub coverage: Coverage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexGeneration {
    pub id: u64,
    pub segments: [Option<SegmentRef>; 4],
    pub tail: TailDescriptor,
}

impl IndexGeneration {
    pub const VALUE_LEN: usize = 88;

    #[must_use]
    pub fn encode_meta_value(desc: &GenerationDescriptor) -> [u8; Self::VALUE_LEN] {
        let mut out = [0u8; Self::VALUE_LEN];
        out[0..8].copy_from_slice(&desc.gen_id.to_le_bytes());
        out[8..48].copy_from_slice(&desc.coverage.to_bytes());
        out[48..52].copy_from_slice(&desc.tail.tail_lo.to_le_bytes());
        out[52..56].copy_from_slice(&desc.tail.tail_hi.to_le_bytes());
        out[56..88].copy_from_slice(&desc.tail.tail_hash);
        out
    }

    #[must_use]
    pub fn decode_meta_value(bytes: &[u8]) -> Option<GenerationDescriptor> {
        if bytes.len() < Self::VALUE_LEN {
            return None;
        }
        let gen_id = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let coverage = Coverage::from_bytes(&bytes[8..48])?;
        let tail_lo = u32::from_le_bytes(bytes[48..52].try_into().ok()?);
        let tail_hi = u32::from_le_bytes(bytes[52..56].try_into().ok()?);
        let mut tail_hash = [0u8; 32];
        tail_hash.copy_from_slice(&bytes[56..88]);
        Some(GenerationDescriptor {
            gen_id,
            coverage,
            tail: TailDescriptor {
                tail_lo,
                tail_hi,
                tail_hash,
            },
        })
    }
}

#[must_use]
pub fn meta_gen_key(capability: IndexCapability) -> Vec<u8> {
    let mut key = b"gen/".to_vec();
    key.extend_from_slice(capability.name().as_bytes());
    key
}
