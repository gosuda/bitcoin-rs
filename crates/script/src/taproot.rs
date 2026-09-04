use bitcoin_rs_primitives::Hash256;
use secp256k1::{Message, Parity, Scalar, XOnlyPublicKey, schnorr::Signature};
use sha2::{Digest, Sha256};

/// BIP341 annex tag prefix (Core `ANNEX_TAG`).
pub const ANNEX_TAG: u8 = 0x50;

/// Control block base size: 1 leaf-version/parity byte + 32-byte x-only internal key.
pub const TAPROOT_CONTROL_BASE_SIZE: usize = 33;

/// Each merkle-path node is 32 bytes.
pub const TAPROOT_CONTROL_NODE_SIZE: usize = 32;

/// Maximum number of merkle-path nodes in a control block (BIP341).
pub const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;

/// Maximum control block size: base + up to 128 nodes.
pub const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

/// Mask isolating the leaf version from the control block's first byte.
pub const TAPROOT_LEAF_MASK: u8 = 0xfe;

/// Leaf version for BIP342 tapscript.
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;

/// Verifies a taproot key-path Schnorr signature.
#[must_use]
pub fn verify_taproot_keypath(
    signature: &Signature,
    message: &Message,
    public_key: &XOnlyPublicKey,
) -> bool {
    secp256k1::SECP256K1
        .verify_schnorr(signature, message, public_key)
        .is_ok()
}

/// Verifies a tapscript Schnorr signature.
///
/// BIP342 changes the message construction and script rules, but the final
/// Schnorr verification primitive is identical to key-path verification.
#[must_use]
pub fn verify_taproot_scriptpath(
    signature: &Signature,
    message: &Message,
    public_key: &XOnlyPublicKey,
) -> bool {
    verify_taproot_keypath(signature, message, public_key)
}

/// Tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut engine = Sha256::new();
    Digest::update(&mut engine, tag_hash);
    Digest::update(&mut engine, tag_hash);
    Digest::update(&mut engine, msg);
    engine.finalize().into()
}

/// Computes the `TapBranch` hash: `TaggedHash("TapBranch", min(a,b) || max(a,b))`.
///
/// Mirrors Core's `ComputeTapbranchHash`. The two 32-byte hashes are
/// serialized in lexicographic order (comparing the raw byte arrays).
fn compute_tapbranch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let mut msg = [0u8; 64];
    msg[..32].copy_from_slice(first);
    msg[32..].copy_from_slice(second);
    tagged_hash(b"TapBranch", &msg)
}

/// Walks the merkle path from `tapleaf_hash` through the control block's
/// nodes, returning the computed merkle root.
///
/// Mirrors Core's `ComputeTaprootMerkleRoot`. The caller must have already
/// validated the control block size.
#[must_use]
pub fn compute_taproot_merkle_root(control: &[u8], tapleaf_hash: &Hash256) -> Hash256 {
    let mut k = *tapleaf_hash.as_byte_array();
    let path = control.get(TAPROOT_CONTROL_BASE_SIZE..).unwrap_or(&[]);
    for node in path.chunks_exact(TAPROOT_CONTROL_NODE_SIZE) {
        let mut sibling = [0_u8; TAPROOT_CONTROL_NODE_SIZE];
        sibling.copy_from_slice(node);
        k = compute_tapbranch_hash(&k, &sibling);
    }
    Hash256::from_le_bytes(&k)
}

/// Verifies the taproot commitment: that the output pubkey (`program`) equals
/// the internal pubkey tweaked by the merkle root.
///
/// Mirrors Core's `VerifyTaprootCommitment` / `XOnlyPubKey::CheckTapTweak`.
/// Returns `false` (not an error) when the internal pubkey is invalid or the
/// tweak check fails, matching Core's behavior.
#[must_use]
pub fn verify_taproot_commitment(control: &[u8], program: &[u8], tapleaf_hash: &Hash256) -> bool {
    // Internal x-only pubkey: bytes 1..33 of the control block.
    let Some(internal_bytes) = control.get(1..TAPROOT_CONTROL_BASE_SIZE) else {
        return false;
    };
    let Ok(internal) = XOnlyPublicKey::from_slice(internal_bytes) else {
        return false;
    };
    // Output x-only pubkey: the 32-byte witness program.
    let Ok(output) = XOnlyPublicKey::from_slice(program) else {
        return false;
    };
    let merkle_root = compute_taproot_merkle_root(control, tapleaf_hash);
    // TapTweak hash: TaggedHash("TapTweak", internal_pubkey || merkle_root).
    // The internal pubkey is serialized in big-endian (standard x-only form);
    // the merkle root is serialized in little-endian (matching Core's uint256
    // memory layout).
    let mut tweak_msg = internal.serialize().to_vec();
    tweak_msg.extend_from_slice(merkle_root.as_byte_array());
    let tweak_bytes = tagged_hash(b"TapTweak", &tweak_msg);
    let Ok(tweak) = Scalar::from_be_bytes(tweak_bytes) else {
        return false;
    };
    // Parity bit from the control block's first byte.
    let parity = if control[0] & 1 == 0 {
        Parity::Even
    } else {
        Parity::Odd
    };
    internal.tweak_add_check(secp256k1::SECP256K1, &output, parity, tweak)
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_primitives::Hash256;
    use secp256k1::{Keypair, Message, Parity, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
    use sha2::{Digest, Sha256};

    use super::{
        TAPROOT_LEAF_TAPSCRIPT, compute_taproot_merkle_root, verify_taproot_commitment,
        verify_taproot_keypath, verify_taproot_scriptpath,
    };

    fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
        let tag_hash = Sha256::digest(tag);
        let mut engine = Sha256::new();
        Digest::update(&mut engine, tag_hash);
        Digest::update(&mut engine, tag_hash);
        Digest::update(&mut engine, msg);
        engine.finalize().into()
    }

    /// Builds a valid single-leaf taproot commitment and returns all the
    /// pieces needed for script-path tests.
    struct TaprootFixture {
        control: Vec<u8>,
        output: [u8; 32],
        tapleaf: Hash256,
    }

    impl TaprootFixture {
        fn build(script: &[u8]) -> Self {
            let secp = Secp256k1::new();
            let secret = match SecretKey::from_slice(&[3u8; 32]) {
                Ok(s) => s,
                Err(e) => panic!("fixed test key is valid: {e}"),
            };
            let kp = Keypair::from_secret_key(&secp, &secret);
            let (internal, _) = XOnlyPublicKey::from_keypair(&kp);

            let leaf_version = TAPROOT_LEAF_TAPSCRIPT;
            let mut tapleaf_msg = vec![leaf_version];
            tapleaf_msg.extend(compact_size(script.len()));
            tapleaf_msg.extend_from_slice(script);
            let tapleaf_bytes = tagged_hash(b"TapLeaf", &tapleaf_msg);
            let tapleaf = Hash256::from_le_bytes(&tapleaf_bytes);

            // Single leaf: merkle root = tapleaf
            let mut tweak_msg = internal.serialize().to_vec();
            tweak_msg.extend_from_slice(&tapleaf_bytes);
            let tweak_bytes = tagged_hash(b"TapTweak", &tweak_msg);
            let tweak = match Scalar::from_be_bytes(tweak_bytes) {
                Ok(t) => t,
                Err(e) => panic!("tweak is valid scalar: {e}"),
            };
            let (output, parity) = match internal.add_tweak(&secp, &tweak) {
                Ok(v) => v,
                Err(e) => panic!("tweak add succeeds for valid key: {e}"),
            };

            let parity_byte = leaf_version | u8::from(parity != Parity::Even);
            let mut control = vec![parity_byte];
            control.extend(internal.serialize());

            Self {
                control,
                output: output.serialize(),
                tapleaf,
            }
        }
    }

    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "test helper for small sizes"
    )]
    fn compact_size(n: usize) -> Vec<u8> {
        if n < 0xfd { vec![n as u8] } else { vec![] }
    }

    #[test]
    fn taproot_helpers_accept_valid_schnorr_signature() {
        let secp = Secp256k1::new();
        let secret = match SecretKey::from_slice(&[1u8; 32]) {
            Ok(secret) => secret,
            Err(error) => panic!("fixed secret key should be valid: {error}"),
        };
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (public_key, _) = XOnlyPublicKey::from_keypair(&keypair);
        let message = Message::from_digest([2; 32]);
        let signature = secp.sign_schnorr(&message, &keypair);

        assert!(verify_taproot_keypath(&signature, &message, &public_key));
        assert!(verify_taproot_scriptpath(&signature, &message, &public_key));
    }

    /// Rule: a control block of an invalid size must be rejected.
    ///
    /// Mirrors Core's `TAPROOT_WRONG_CONTROL_SIZE` check in
    /// `VerifyWitnessProgram`. The driver rejects control blocks smaller
    /// than the base size, larger than the max, or not a multiple of the
    /// node size.
    #[test]
    fn control_block_wrong_size_is_rejected() {
        let fixture = TaprootFixture::build(&[0x51]);

        // Valid control block passes.
        assert!(verify_taproot_commitment(
            &fixture.control,
            &fixture.output,
            &fixture.tapleaf
        ));

        // Too small: 32 bytes (one less than base).
        let mut too_small = fixture.control.clone();
        too_small.pop();
        assert!(!verify_taproot_commitment(
            &too_small,
            &fixture.output,
            &fixture.tapleaf
        ));

        // Too large: base + 33 bytes (not a multiple of node size).
        let mut too_large = fixture.control.clone();
        too_large.extend(vec![0u8; 33]);
        assert!(!verify_taproot_commitment(
            &too_large,
            &fixture.output,
            &fixture.tapleaf
        ));
    }

    /// Rule: a merkle path that does not reconstruct the output key must be
    /// rejected.
    ///
    /// Mirrors Core's `VerifyTaprootCommitment` / `XOnlyPubKey::CheckTapTweak`.
    /// A control block with a wrong internal key or a corrupted merkle node
    /// produces a different tweaked output and must fail the commitment check.
    #[test]
    fn merkle_path_mismatch_is_rejected() {
        let fixture = TaprootFixture::build(&[0x51]);

        // Valid commitment passes.
        assert!(verify_taproot_commitment(
            &fixture.control,
            &fixture.output,
            &fixture.tapleaf
        ));

        // Wrong output key: flip a bit in the output.
        let mut wrong_output = fixture.output;
        wrong_output[0] ^= 1;
        assert!(!verify_taproot_commitment(
            &fixture.control,
            &wrong_output,
            &fixture.tapleaf
        ));

        // Wrong internal key: flip a bit in the control block's key portion.
        let mut wrong_control = fixture.control.clone();
        wrong_control[1] ^= 1;
        assert!(!verify_taproot_commitment(
            &wrong_control,
            &fixture.output,
            &fixture.tapleaf
        ));
    }

    /// Rule: a valid script-path spend must be accepted.
    ///
    /// Mirrors Core's `VerifyTaprootCommitment` succeeding for a correctly
    /// constructed single-leaf taproot tree. The merkle root recomputed from
    /// the control block must match the output key's tweak.
    #[test]
    fn valid_script_path_commitment_is_accepted() {
        let fixture = TaprootFixture::build(&[0x51, 0x52, 0x53]);

        // The commitment check must pass for a valid control block + output.
        assert!(verify_taproot_commitment(
            &fixture.control,
            &fixture.output,
            &fixture.tapleaf
        ));

        // The merkle root for a single leaf equals the tapleaf hash.
        let merkle = compute_taproot_merkle_root(&fixture.control, &fixture.tapleaf);
        assert_eq!(merkle.as_byte_array(), fixture.tapleaf.as_byte_array());
    }
}
