from pathlib import Path
import subprocess


def run(*args: str) -> str:
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        print(result.stdout, flush=True)
        raise SystemExit(result.returncode)
    return result.stdout


def replace(path: str, old: str, new: str) -> None:
    file = Path(path)
    text = file.read_text()
    assert text.count(old) == 1, (path, text.count(old), old)
    file.write_text(text.replace(old, new, 1))


base = "f846c7fbeed40e70431cf83ab4f2cb656bf9ea0b"
branch = "fix/reference-set-identity-validation"
assert run("git", "rev-parse", "HEAD").strip() == base
assert not run("git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}").strip()
run("git", "switch", "-c", branch)

support = "bin/bitcoin-rs/tests/support/reference_set.rs"
replace(
    support,
    "use bitcoin_rs_rpc::compat_manifest::MANIFEST_TOML;\n",
    "use std::collections::BTreeSet;\n\nuse bitcoin_rs_rpc::compat_manifest::MANIFEST_TOML;\n",
)
replace(
    support,
    '''    MissingCorpus {
        /// The corpus identifier that is missing.
        id: String,
    },
}
''',
    '''    MissingCorpus {
        /// The corpus identifier that is missing.
        id: String,
    },
    /// A corpus identifier appears more than once in the reference set.
    #[error("the `{id}` corpus appears more than once in the reference set")]
    DuplicateCorpus {
        /// The duplicated corpus identifier.
        id: String,
    },
}
''',
)
replace(
    support,
    '''    let mut corpora = Vec::with_capacity(array.len());
    for value in array {
        let entry = value
            .as_table()
            .ok_or(ReferenceError::VersionLabelOnly { field: "corpora" })?;
        let id = required_str(entry, "id")?;
        let stop_height = required_u64(entry, "stop_height")?;
        let stop_hash = required_str(entry, "stop_hash")?;
''',
    '''    let mut corpora = Vec::with_capacity(array.len());
    let mut ids = BTreeSet::new();
    for value in array {
        let entry = value
            .as_table()
            .ok_or(ReferenceError::VersionLabelOnly { field: "corpora" })?;
        let id = required_str(entry, "id")?;
        if !ids.insert(id.clone()) {
            return Err(ReferenceError::DuplicateCorpus { id });
        }
        let stop_height = required_u64(entry, "stop_height")?;
        let stop_hash = required_str(entry, "stop_hash")?;
        parse_sha256("stop_hash", &stop_hash)?;
''',
)
replace(
    support,
    '''fn check_identity_confusion(release: &str, kernel: &str) -> Result<(), ReferenceError> {
    let released = release.split('.').count() == 2
        && release
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
    if release == kernel || !released {
        return Err(ReferenceError::IdentityConfusion);
    }
    Ok(())
}
''',
    '''fn check_identity_confusion(release: &str, kernel: &str) -> Result<(), ReferenceError> {
    let released = release.split('.').count() == 2
        && release
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
    let mut kernel_parts = kernel.split('.');
    let development_tree = kernel_parts.next() == Some("31")
        && kernel_parts.next() == Some("99")
        && kernel_parts
            .next()
            .is_some_and(|patch| !patch.is_empty() && patch.bytes().all(|byte| byte.is_ascii_digit()))
        && kernel_parts.next().is_none();
    if release == kernel || !released || !development_tree {
        return Err(ReferenceError::IdentityConfusion);
    }
    Ok(())
}
''',
)

tests = "bin/bitcoin-rs/tests/overhaul_reference_set.rs"
anchor = '''#[test]
fn the_kernel_tree_written_as_the_release_is_identity_confusion() {
    let edited = edit_manifest("core_version = \\"31.1\\"", "core_version = \\"31.99.0\\"");
    assert_eq!(
        load_reference_set(&edited),
        Err(ReferenceError::IdentityConfusion)
    );
}
'''
addition = anchor + '''
/// REF-03: an oracle tree must be the 31.99.x development shape, not merely
/// a version string different from the released product.
#[test]
fn kernel_identity_requires_the_31_99_development_shape() {
    let target = "core_version = \\"31.99.0\\"\\nkernel_crate = ";
    for invalid in ["32.0.0", "31.98.0", "31.99.x", "31.99.0.1"] {
        let replacement = format!("core_version = \\"{invalid}\\"\\nkernel_crate = ");
        let edited = edit_manifest(target, &replacement);
        assert_eq!(
            load_reference_set(&edited),
            Err(ReferenceError::IdentityConfusion),
            "kernel version {invalid:?} must not load as development-tree evidence"
        );
    }
}
'''
replace(tests, anchor, addition)

anchor = '''#[test]
fn a_missing_corpus_is_named_by_id() {
    let edited = edit_manifest(
        concat!(
            "[[reference.corpora]]\\n",
            "id = \\"Cmodern\\"\\n",
            "stop_height = 709635\\n",
            "stop_hash = ",
            "\\"00000000000000000001f9ee4f69cbc75ce61db5178175c2ad021fe1df5bad8f\\"\\n",
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
'''
addition = anchor + '''
/// REF-04: a well-formed stop identity needs a canonical block-hash string.
#[test]
fn malformed_corpus_stop_hash_is_rejected() {
    let target = "stop_hash = \\"0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b\\"";
    for invalid in [
        "0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884",
        "g000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b",
        "0000000000000A3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b",
    ] {
        let edited = edit_manifest(target, &format!("stop_hash = \\"{invalid}\\""));
        assert_eq!(
            load_reference_set(&edited),
            Err(ReferenceError::DigestMalformed { field: "stop_hash" }),
            "stop hash {invalid:?} must be rejected"
        );
    }
}

/// REF-04: corpus presence cannot be satisfied twice by one identifier.
#[test]
fn duplicate_corpus_identifier_is_rejected_before_presence_accounting() {
    let edited = edit_manifest("id = \\"Cmodern\\"\\nstop_height = 709635", "id = \\"C150\\"\\nstop_height = 709635");
    assert_eq!(
        load_reference_set(&edited),
        Err(ReferenceError::DuplicateCorpus {
            id: "C150".to_owned()
        })
    );
}
'''
replace(tests, anchor, addition)

contract = "docs/contracts/reference-set.md"
replace(
    contract,
    '''- `bin/bitcoin-rs/tests/support/reference_set.rs` is the typed parser that
  enforces required identities, digest formats, corpus presence, and product
  versus kernel-tree separation.
''',
    '''- `bin/bitcoin-rs/tests/support/reference_set.rs` is the typed parser that
  enforces required identities, digest formats, unique corpus ids and stop-hash
  syntax, corpus presence, and product versus kernel-tree separation.
''',
)
replace(
    contract,
    '''This identity is used only for differential evidence. It is not a policy pin,
it is not a stable release, and it must never be read as the `REF-02` product
reference.
''',
    '''This identity is used only for differential evidence. It is not a policy pin,
it is not a stable release, and it must never be read as the `REF-02` product
reference. The parser requires the development-tree version to have the
`31.99.x` shape with a numeric patch component; being merely different from the
release version is insufficient.
''',
)
replace(
    contract,
    '''`[[reference.corpora]]` rows pinned by `id`, `stop_height`, and `stop_hash`:
''',
    '''`[[reference.corpora]]` rows pinned by `id`, `stop_height`, and `stop_hash`.
Corpus ids are unique, and each `stop_hash` is exactly 64 lowercase hexadecimal
characters:
''',
)
replace(
    contract,
    '''- `bin/bitcoin-rs/tests/overhaul_reference_set.rs`: rejects label-only and
  digest-mismatch identities, and pins `corpus_custody()` honesty.
''',
    '''- `bin/bitcoin-rs/tests/overhaul_reference_set.rs`: rejects label-only and
  malformed-digest identities, duplicate corpus ids, malformed corpus stop
  hashes, and non-`31.99.x` kernel identities, and pins `corpus_custody()`
  honesty.
''',
)

run("rustfmt", "--edition", "2024", support, tests)
run("git", "diff", "--check")
changed = run("git", "diff", "--name-only").splitlines()
assert set(changed) == {support, tests, contract}, changed
print(run("git", "diff", "--stat"), flush=True)
print(run("git", "diff", "--", support, tests, contract), flush=True)
run("git", "add", "--", support, tests, contract)
run(
    "git",
    "-c",
    "user.name=github-actions[bot]",
    "-c",
    "user.email=41898282+github-actions[bot]@users.noreply.github.com",
    "commit",
    "-m",
    "test(reference): validate corpus and kernel identities",
)
run("git", "push", "origin", f"HEAD:refs/heads/{branch}")
print("PUBLISHED_SHA=" + run("git", "rev-parse", "HEAD").strip(), flush=True)
