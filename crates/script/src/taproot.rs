use std::sync::LazyLock;

use bitcoin_rs_primitives::Hash256;
use secp256k1::{Parity, Scalar, XOnlyPublicKey};
use sha2::{Digest, Sha256};

pub(crate) const ANNEX_TAG: u8 = 0x50;

pub(crate) const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
pub(crate) const TAPROOT_CONTROL_NODE_SIZE: usize = 32;

pub(crate) const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
pub(crate) const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

pub(crate) const TAPROOT_LEAF_MASK: u8 = 0xfe;
pub(crate) const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;

static TAPBRANCH_ENGINE: LazyLock<Sha256> = LazyLock::new(|| tagged_hash_engine(b"TapBranch"));
static TAPTWEAK_ENGINE: LazyLock<Sha256> = LazyLock::new(|| tagged_hash_engine(b"TapTweak"));

fn tagged_hash_engine(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut engine = Sha256::new();
    Digest::update(&mut engine, tag_hash);
    Digest::update(&mut engine, tag_hash);
    engine
}

fn compute_tapbranch_hash(prefix: &Sha256, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let mut engine = prefix.clone();
    Digest::update(&mut engine, first);
    Digest::update(&mut engine, second);
    engine.finalize().into()
}

#[must_use]
pub(crate) fn compute_taproot_merkle_root(control: &[u8], tapleaf_hash: &Hash256) -> Hash256 {
    let mut k = *tapleaf_hash.as_byte_array();
    let path = control.get(TAPROOT_CONTROL_BASE_SIZE..).unwrap_or(&[]);
    let nodes = path.as_chunks::<TAPROOT_CONTROL_NODE_SIZE>().0;
    if nodes.is_empty() {
        return *tapleaf_hash;
    }
    let prefix = LazyLock::force(&TAPBRANCH_ENGINE);
    for node in nodes {
        k = compute_tapbranch_hash(prefix, &k, node);
    }
    Hash256::from_le_bytes(&k)
}

#[must_use]
pub(crate) fn verify_taproot_commitment(
    control: &[u8],
    program: &[u8],
    tapleaf_hash: &Hash256,
) -> bool {
    let Some(internal_bytes) = control.get(1..TAPROOT_CONTROL_BASE_SIZE) else {
        return false;
    };
    let Ok(internal) = XOnlyPublicKey::from_slice(internal_bytes) else {
        return false;
    };
    let Ok(output) = XOnlyPublicKey::from_slice(program) else {
        return false;
    };
    let merkle_root = compute_taproot_merkle_root(control, tapleaf_hash);
    let mut engine = LazyLock::force(&TAPTWEAK_ENGINE).clone();
    Digest::update(&mut engine, internal.serialize());
    Digest::update(&mut engine, merkle_root.as_byte_array());
    let tweak_bytes = engine.finalize().into();
    let Ok(tweak) = Scalar::from_be_bytes(tweak_bytes) else {
        return false;
    };
    let parity = if control[0] & 1 == 0 {
        Parity::Even
    } else {
        Parity::Odd
    };
    internal.tweak_add_check(secp256k1::SECP256K1, &output, parity, tweak)
}

#[cfg(test)]
mod tests;
