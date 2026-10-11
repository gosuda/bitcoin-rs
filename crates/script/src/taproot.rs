use std::sync::LazyLock;

use bitcoin_rs_primitives::Hash256;
use secp256k1::{Parity, Scalar, XOnlyPublicKey};
use sha2::{Digest, Sha256};

/// BIP341 annex tag prefix (Core `ANNEX_TAG`).
pub(crate) const ANNEX_TAG: u8 = 0x50;

/// Control block base size: 1 leaf-version/parity byte + 32-byte x-only internal key.
pub(crate) const TAPROOT_CONTROL_BASE_SIZE: usize = 33;

/// Each merkle-path node is 32 bytes.
pub(crate) const TAPROOT_CONTROL_NODE_SIZE: usize = 32;

/// Maximum number of merkle-path nodes in a control block (BIP341).
pub(crate) const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;

/// Maximum control block size: base + up to 128 nodes.
pub(crate) const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

/// Mask isolating the leaf version from the control block's first byte.
pub(crate) const TAPROOT_LEAF_MASK: u8 = 0xfe;

/// Leaf version for BIP342 tapscript.
pub(crate) const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;

// BIP340 "Tagged Hashes": the doubled tag digest is exactly one SHA256
// block. Keep only these two fixed public prefixes, never request data.
static TAPBRANCH_ENGINE: LazyLock<Sha256> = LazyLock::new(|| tagged_hash_engine(b"TapBranch"));
static TAPTWEAK_ENGINE: LazyLock<Sha256> = LazyLock::new(|| tagged_hash_engine(b"TapTweak"));

/// Initializes SHA256 after `SHA256(tag) || SHA256(tag)`, before any message.
fn tagged_hash_engine(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut engine = Sha256::new();
    Digest::update(&mut engine, tag_hash);
    Digest::update(&mut engine, tag_hash);
    engine
}

/// BIP341 `TapBranch`: raw-byte lexicographic ordering, not display order.
fn compute_tapbranch_hash(prefix: &Sha256, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let mut engine = prefix.clone();
    Digest::update(&mut engine, first);
    Digest::update(&mut engine, second);
    engine.finalize().into()
}

/// Walks the merkle path from `tapleaf_hash` through the control block's
/// nodes, returning the computed merkle root.
///
/// Mirrors Core's `ComputeTaprootMerkleRoot`. The caller must have already
/// validated the control block size.
#[must_use]
pub(crate) fn compute_taproot_merkle_root(control: &[u8], tapleaf_hash: &Hash256) -> Hash256 {
    let mut k = *tapleaf_hash.as_byte_array();
    let path = control.get(TAPROOT_CONTROL_BASE_SIZE..).unwrap_or(&[]);
    let nodes = path.as_chunks::<TAPROOT_CONTROL_NODE_SIZE>().0;
    if nodes.is_empty() {
        return *tapleaf_hash;
    }
    // Resolve lazy initialization once per path, not once per Merkle node.
    let prefix = LazyLock::force(&TAPBRANCH_ENGINE);
    for node in nodes {
        k = compute_tapbranch_hash(prefix, &k, node);
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
pub(crate) fn verify_taproot_commitment(
    control: &[u8],
    program: &[u8],
    tapleaf_hash: &Hash256,
) -> bool {
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
    let mut engine = LazyLock::force(&TAPTWEAK_ENGINE).clone();
    Digest::update(&mut engine, internal.serialize());
    Digest::update(&mut engine, merkle_root.as_byte_array());
    let tweak_bytes = engine.finalize().into();
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
    use bitcoin::hex::FromHex;
    use bitcoin_rs_primitives::Hash256;
    use secp256k1::{Keypair, Parity, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
    use sha2::{Digest, Sha256};

    use super::{TAPROOT_LEAF_TAPSCRIPT, compute_taproot_merkle_root, verify_taproot_commitment};

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

    /// BIP341 commitment rules: the valid single-leaf tree verifies, its
    /// merkle root is the tapleaf hash, and every perturbation of the control
    /// block or output key fails the tweak check.
    #[test]
    fn taproot_commitment_accepts_the_valid_tree_and_rejects_perturbations() {
        for script in [[0x51].as_slice(), &[0x51, 0x52, 0x53]] {
            let fixture = TaprootFixture::build(script);
            assert!(verify_taproot_commitment(
                &fixture.control,
                &fixture.output,
                &fixture.tapleaf
            ));
            assert_eq!(
                compute_taproot_merkle_root(&fixture.control, &fixture.tapleaf).as_byte_array(),
                fixture.tapleaf.as_byte_array(),
            );

            let mut too_small = fixture.control.clone();
            too_small.pop();
            let mut padded = fixture.control.clone();
            padded.extend([0_u8; 33]);
            let mut extra_node = fixture.control.clone();
            extra_node.extend([0xab_u8; 32]);
            let mut wrong_internal = fixture.control.clone();
            wrong_internal[1] ^= 1;
            let mut flipped_parity = fixture.control.clone();
            flipped_parity[0] ^= 1;
            let mut wrong_output = fixture.output;
            wrong_output[0] ^= 1;

            let rejected: [(&str, &[u8], &[u8]); 6] = [
                ("control block one byte short", &too_small, &fixture.output),
                (
                    "control block padded past a node boundary",
                    &padded,
                    &fixture.output,
                ),
                (
                    "extra merkle node in the path",
                    &extra_node,
                    &fixture.output,
                ),
                ("internal key bit flipped", &wrong_internal, &fixture.output),
                ("parity bit flipped", &flipped_parity, &fixture.output),
                ("output key bit flipped", &fixture.control, &wrong_output),
            ];
            for (label, control, program) in rejected {
                assert!(
                    !verify_taproot_commitment(control, program, &fixture.tapleaf),
                    "{label}"
                );
            }
        }
    }

    fn fixture_hex(text: &str) -> Vec<u8> {
        Vec::from_hex(text).unwrap_or_else(|error| panic!("bad fixture hex: {error}"))
    }

    struct CommitmentVector {
        control: &'static str,
        leaf: &'static str,
        root: &'static str,
        tweak: &'static str,
        output: &'static str,
    }

    // BIP341 wallet-test-vectors.json, scriptPubKey cases 1, 3 and 5.
    // Source Git blob: 11261b00ba24afb90b62109505d9ca5ddd773b3b.
    // Expected roots/output keys are published bytes, not candidate outputs.
    const BIP341_VECTORS: [CommitmentVector; 6] = [
        CommitmentVector {
            control: concat!(
                "c1187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf",
                "27",
            ),
            leaf: "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21",
            root: "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21",
            tweak: "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001",
            output: "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
        },
        CommitmentVector {
            control: concat!(
                "c0ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf37865",
                "92f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a11",
                "2a",
            ),
            leaf: "8ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7",
            root: "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef",
            tweak: "9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9",
            output: "712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
        },
        CommitmentVector {
            control: concat!(
                "faee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf37865",
                "928ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47",
                "a7",
            ),
            leaf: "f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a",
            root: "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef",
            tweak: "9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9",
            output: "712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
        },
        CommitmentVector {
            control: concat!(
                "c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e",
                "6fffe578e9ea769027e4f5a3de40732f75a88a6353a09d767ddeb66accef85e5",
                "53",
            ),
            leaf: "2645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817",
            root: "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2",
            tweak: "b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4",
            output: "91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
        },
        CommitmentVector {
            control: concat!(
                "c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e",
                "6f9e31407bffa15fefbf5090b149d53959ecdf3f62b1246780238c24501d5cea",
                "f62645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b98",
                "17",
            ),
            leaf: "ba982a91d4fc552163cb1c0da03676102d5b7a014304c01f0c77b2b8e888de1c",
            root: "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2",
            tweak: "b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4",
            output: "91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
        },
        CommitmentVector {
            control: concat!(
                "c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e",
                "6fba982a91d4fc552163cb1c0da03676102d5b7a014304c01f0c77b2b8e888de",
                "1c2645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b98",
                "17",
            ),
            leaf: "9e31407bffa15fefbf5090b149d53959ecdf3f62b1246780238c24501d5ceaf6",
            root: "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2",
            tweak: "b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4",
            output: "91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
        },
    ];

    #[test]
    fn bip341_published_commitment_vectors() -> Result<(), Box<dyn std::error::Error>> {
        for CommitmentVector {
            control,
            leaf,
            root,
            tweak,
            output,
        } in BIP341_VECTORS
        {
            let mut control = fixture_hex(control);
            let leaf: [u8; 32] = fixture_hex(leaf).try_into().map_err(|_| "leaf width")?;
            let leaf = Hash256::from_le_bytes(&leaf);
            let expected_root = fixture_hex(root);
            let actual = compute_taproot_merkle_root(&control, &leaf);
            assert_eq!(actual.as_byte_array().as_slice(), expected_root);
            let mut engine = std::sync::LazyLock::force(&super::TAPTWEAK_ENGINE).clone();
            Digest::update(&mut engine, &control[1..33]);
            Digest::update(&mut engine, actual.as_byte_array());
            assert_eq!(engine.finalize().as_slice(), fixture_hex(tweak));
            let output = fixture_hex(output);
            assert!(verify_taproot_commitment(&control, &output, &leaf));
            control[0] ^= 1;
            assert!(!verify_taproot_commitment(&control, &output, &leaf));
        }
        Ok(())
    }

    // BIP340 Tagged Hashes and BIP341 Script validation rules: compare with
    // the direct formula at every legal Merkle depth, including equal nodes.
    #[test]
    fn cached_branch_prefix_matches_direct_hash_at_every_control_depth() {
        let leaf = Hash256::from_le_bytes(&[0x5a; 32]);
        let mut control = vec![0; super::TAPROOT_CONTROL_BASE_SIZE];
        let mut expected = *leaf.as_byte_array();
        for depth in 0..=super::TAPROOT_CONTROL_MAX_NODE_COUNT {
            assert_eq!(
                compute_taproot_merkle_root(&control, &leaf).as_byte_array(),
                &expected,
                "depth={depth}"
            );
            if depth == super::TAPROOT_CONTROL_MAX_NODE_COUNT {
                break;
            }
            let sibling: [u8; 32] = if depth.is_multiple_of(3) {
                expected
            } else {
                Sha256::digest(depth.to_le_bytes()).into()
            };
            let (first, second) = if expected <= sibling {
                (expected, sibling)
            } else {
                (sibling, expected)
            };
            let mut branch = [0_u8; 64];
            branch[..32].copy_from_slice(&first);
            branch[32..].copy_from_slice(&second);
            expected = tagged_hash(b"TapBranch", &branch);
            control.extend_from_slice(&sibling);
        }
    }

    // BIP340 domain separation: concurrent callers must not contaminate the
    // two fixed prefixes or carry one message into the next message's state.
    #[test]
    fn cached_tag_prefixes_are_independent_across_threads() {
        std::thread::scope(|scope| {
            for seed in 0_u8..8 {
                scope.spawn(move || {
                    for byte in 0_u8..=u8::MAX {
                        let message = [seed, byte].repeat(32);
                        for (prefix, tag) in [
                            (&super::TAPBRANCH_ENGINE, b"TapBranch".as_slice()),
                            (&super::TAPTWEAK_ENGINE, b"TapTweak".as_slice()),
                        ] {
                            let mut engine = std::sync::LazyLock::force(prefix).clone();
                            Digest::update(&mut engine, &message[..32]);
                            Digest::update(&mut engine, &message[32..]);
                            let actual: [u8; 32] = engine.finalize().into();
                            assert_eq!(actual, tagged_hash(tag, &message));
                        }
                    }
                });
            }
        });
    }
}
