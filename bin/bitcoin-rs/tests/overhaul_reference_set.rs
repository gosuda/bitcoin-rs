//! T00 — the reference set is load-bearing, not documentary.
//!
//! The `[reference]` table in `docs/api/core-compat.toml` (embedded as
//! [`MANIFEST_TOML`]) must load into a full identity record: the released
//! Core 31.1 product with its binary digests, the 31.99.0 kernel tree as
//! oracle evidence only, both consumer identities, both corpus stop
//! identities, and the formal tool pin. Every way a reference can quietly
//! degrade into a label fails with the exact typed error, and the released
//! product is never mistaken for the kernel tree.
//!
//! Variants are string edits of the embedded manifest, never restatements of
//! it: if the manifest moves, the edits move with it or fail loudly here.
//!
//! Contract: `docs/contracts/reference-set.md` — `REF-01`..`REF-07`.

#![expect(
    clippy::expect_used,
    reason = "failure-path fixtures assert typed rejections by construction"
)]

use bitcoin_rs_rpc::compat_manifest::{
    CorpusCustody, MANIFEST_TOML, ReferenceError, Status, load_reference_set, reference_set,
};

/// Pinned release archive digest, restated only to compare parsed bytes
/// against the identity — never to build a manifest.
const RELEASE_ARCHIVE_SHA256: &str =
    "b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e";

/// Pinned `bitcoind` digest; see [`RELEASE_ARCHIVE_SHA256`].
const RELEASE_BITCOIND_SHA256: &str =
    "986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08";

/// Pinned formal-tool archive digest; see [`RELEASE_ARCHIVE_SHA256`].
const FORMAL_ARCHIVE_SHA256: &str =
    "7cfadf6e8c04c63f05ac907ec9541c66297005c8cb5efb1731f6a838dfc3fad2";

/// Pinned formal-tool jar digest; see [`RELEASE_ARCHIVE_SHA256`].
const FORMAL_JAR_SHA256: &str = "079b6c2320252469dcf79afec6886b8255d3dd1b34a9484433c88986752efaa8";

/// Stand-in digest used to prove a corpus can be pinned once exported.
const SAMPLE_CORPUS_MANIFEST_SHA256: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

/// Decodes a 64-hex-character literal into the digest bytes a loader must
/// produce.
fn digest(text: &str) -> [u8; 32] {
    let bytes = text.as_bytes();
    assert_eq!(bytes.len(), 64, "digest literal must be 64 hex characters");
    let mut out = [0_u8; 32];
    for (at, pair) in bytes.chunks_exact(2).enumerate() {
        let nibble = |byte: u8| {
            u8::try_from(char::from(byte).to_digit(16).expect("hex nibble")).expect("nibble fits")
        };
        out[at] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    out
}

/// Replaces the single occurrence of `target` in the embedded manifest with
/// `replacement`, failing if the edit is ambiguous or absent.
fn edit_manifest(target: &str, replacement: &str) -> String {
    let (count, edited) = replace_once(MANIFEST_TOML, target, replacement);
    assert_eq!(
        count, 1,
        "edit target must appear exactly once in the manifest: {target:?}"
    );
    edited
}

fn replace_once(haystack: &str, target: &str, replacement: &str) -> (usize, String) {
    let Some(at) = haystack.find(target) else {
        return (0, haystack.to_owned());
    };
    let mut edited = String::with_capacity(haystack.len() - target.len() + replacement.len());
    edited.push_str(&haystack[..at]);
    edited.push_str(replacement);
    edited.push_str(&haystack[at + target.len()..]);
    (1, edited)
}

/// The embedded manifest loads and carries every pinned identity in full:
/// released product with source commit and both binary digests, the kernel
/// tree as separate evidence, both consumers, both corpora, and the formal
/// tool.
#[test]
fn the_embedded_manifest_loads_the_full_reference_set() {
    let set = reference_set().expect("the embedded manifest carries a complete reference set");

    assert_eq!(set.release.core_version, "31.1");
    assert_eq!(set.release.git_tag, "v31.1");
    assert_eq!(
        set.release.source_commit,
        "9be056a8a72b624dae9623b2f7bded92c2a21c91"
    );
    assert_eq!(set.release.archive, "bitcoin-31.1-x86_64-linux-gnu.tar.gz");
    assert_eq!(set.release.archive_sha256, digest(RELEASE_ARCHIVE_SHA256));
    assert_eq!(set.release.bitcoind_sha256, digest(RELEASE_BITCOIND_SHA256));
    assert_eq!(
        set.release.version_output,
        "Bitcoin Core daemon version v31.1.0"
    );

    assert_eq!(set.kernel.core_version, "31.99.0");
    assert_eq!(set.kernel.kernel_crate, "bitcoinkernel");
    assert_eq!(set.kernel.kernel_crate_version, "0.2.1");
    assert_eq!(set.kernel.kernel_sys_crate, "libbitcoinkernel-sys");
    assert_eq!(set.kernel.kernel_sys_crate_version, "0.3.0");
    assert!(!set.kernel.differential_harness);

    assert_eq!(
        set.consumers.mempool.backend_image,
        "mempool/backend:v3.3.1"
    );
    assert_eq!(
        set.consumers.mempool.frontend_image,
        "mempool/frontend:v3.3.1"
    );
    assert_eq!(
        set.consumers.mempool.tag_commit,
        "9332d9db97bcc7beed079acc8f79aa21c9b12a3b"
    );
    assert_eq!(set.consumers.wallet.repository, "gosuda/bitcoin-wallet");
    assert_eq!(set.consumers.wallet.repository_id, 885_198_873);
    assert_eq!(
        set.consumers.wallet.commit,
        "2fe2af12c721bdf2cd4af7801146bda40fa15429"
    );
    assert_eq!(set.consumers.wallet.cli, "btcw");

    assert_eq!(set.corpora.len(), 2);
    let c150 = &set.corpora[0];
    assert_eq!(c150.id, "C150");
    assert_eq!(c150.stop_height, 150_000);
    assert_eq!(
        c150.stop_hash,
        "0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b"
    );
    let cmodern = &set.corpora[1];
    assert_eq!(cmodern.id, "Cmodern");
    assert_eq!(cmodern.stop_height, 709_635);
    assert_eq!(
        cmodern.stop_hash,
        "00000000000000000001f9ee4f69cbc75ce61db5178175c2ad021fe1df5bad8f"
    );

    assert_eq!(set.formal_tool.name, "apalache-mc");
    assert_eq!(set.formal_tool.version, "0.62.2");
    assert_eq!(
        set.formal_tool.archive_sha256,
        digest(FORMAL_ARCHIVE_SHA256)
    );
    assert_eq!(set.formal_tool.jar_sha256, digest(FORMAL_JAR_SHA256));
}

/// The release digest removed leaves only a version label, which is not a
/// reference.
#[test]
fn a_release_digest_removed_is_version_label_only() {
    let edited = edit_manifest(
        "archive_sha256 = \"b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e\"\n",
        "",
    );
    assert_eq!(
        load_reference_set(&edited),
        Err(ReferenceError::VersionLabelOnly {
            field: "archive_sha256"
        })
    );
}

/// A digest of the wrong length, and a digest carrying a non-hex character,
/// are both rejected as malformed rather than silently truncated or coerced.
#[test]
fn a_malformed_release_digest_is_digest_malformed() {
    let quoted = format!("\"{RELEASE_ARCHIVE_SHA256}\"");
    let wrong_length = edit_manifest(&quoted, &format!("\"{}\"", &RELEASE_ARCHIVE_SHA256[..63]));
    assert_eq!(
        load_reference_set(&wrong_length),
        Err(ReferenceError::DigestMalformed {
            field: "archive_sha256"
        })
    );

    let mut non_hex = RELEASE_ARCHIVE_SHA256.to_owned();
    non_hex.replace_range(..1, "g");
    let non_hex_manifest = edit_manifest(&quoted, &format!("\"{non_hex}\""));
    assert_eq!(
        load_reference_set(&non_hex_manifest),
        Err(ReferenceError::DigestMalformed {
            field: "archive_sha256"
        })
    );
}

/// A wallet named without its commit is not a consumer identity.
#[test]
fn a_wallet_without_its_commit_is_missing_consumer_identity() {
    let edited = edit_manifest(
        "commit = \"2fe2af12c721bdf2cd4af7801146bda40fa15429\"\n",
        "",
    );
    assert_eq!(
        load_reference_set(&edited),
        Err(ReferenceError::MissingConsumerIdentity { consumer: "wallet" })
    );
}

/// Writing the kernel tree's version as the release is exactly the confusion
/// the reference set exists to prevent.
#[test]
fn the_kernel_tree_written_as_the_release_is_identity_confusion() {
    let edited = edit_manifest("core_version = \"31.1\"", "core_version = \"31.99.0\"");
    assert_eq!(
        load_reference_set(&edited),
        Err(ReferenceError::IdentityConfusion)
    );
}

/// A corpus dropped from the manifest is reported by its id, not silently
/// forgiven.
#[test]
fn a_missing_corpus_is_named_by_id() {
    let edited = edit_manifest(
        concat!(
            "[[reference.corpora]]\n",
            "id = \"Cmodern\"\n",
            "stop_height = 709635\n",
            "stop_hash = ",
            "\"00000000000000000001f9ee4f69cbc75ce61db5178175c2ad021fe1df5bad8f\"\n",
        ),
        "",
    );
    assert_eq!(
        load_reference_set(&edited),
        Err(ReferenceError::MissingCorpus {
            id: "Cmodern".to_owned()
        })
    );
}

/// Custody is honest about what is absent: today both corpora await their
/// export-time manifest digest, and pinning one flips exactly that one.
#[test]
fn corpus_custody_distinguishes_pinned_from_blocked() {
    let blocked = CorpusCustody::Blocked {
        missing: "manifest_sha256",
    };
    let set = reference_set().expect("the embedded manifest carries a complete reference set");
    assert_eq!(
        set.corpus_custody(),
        vec![
            ("C150".to_owned(), blocked.clone()),
            ("Cmodern".to_owned(), blocked),
        ]
    );

    let pinned_manifest = edit_manifest(
        "id = \"C150\"\n",
        &format!("id = \"C150\"\nmanifest_sha256 = \"{SAMPLE_CORPUS_MANIFEST_SHA256}\"\n"),
    );
    let set =
        load_reference_set(&pinned_manifest).expect("a pinned corpus manifest digest still loads");
    assert_eq!(
        set.corpus_custody(),
        vec![
            ("C150".to_owned(), CorpusCustody::Pinned),
            (
                "Cmodern".to_owned(),
                CorpusCustody::Blocked {
                    missing: "manifest_sha256"
                }
            ),
        ]
    );
}

/// The deviation ledger stays explicit: a `deviation` status without a stated
/// deviation is the least useful thing a compatibility manifest can say, so
/// every such entry in every surface carries a non-empty one.
#[test]
fn every_deviation_entry_states_its_deviation() {
    let table: toml::Table = toml::from_str(MANIFEST_TOML).expect("the manifest parses");
    let mut deviations = 0_usize;
    for kind in ["rpc", "rest", "zmq"] {
        let Some(array) = table.get(kind).and_then(toml::Value::as_array) else {
            panic!("the manifest must carry a `{kind}` array");
        };
        for entry in array {
            let status = entry
                .get("status")
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("a `{kind}` entry carries no status"));
            if Status::parse(status) != Some(Status::Deviation) {
                continue;
            }
            let deviation = entry
                .get("deviation")
                .and_then(toml::Value::as_str)
                .expect("a deviation entry carries a deviation field");
            assert!(
                !deviation.is_empty(),
                "the {kind} entry {entry:?} claims a deviation without stating it"
            );
            deviations = deviations.saturating_add(1);
        }
    }
    assert!(deviations > 0, "the manifest must record its deviations");
}
