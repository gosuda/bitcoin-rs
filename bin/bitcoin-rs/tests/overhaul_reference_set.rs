//! REF-02/REF-03/REF-07: reference identities fail closed when malformed,
//! unbound to their artifacts, or confused with a different reference.
//! The manifest owns pin values; these tests mutate its parsed fields.

#![expect(clippy::expect_used, reason = "reference identity rejection tests")]

#[path = "support/reference_set.rs"]
mod reference_set;

use bitcoin::hashes::{Hash, sha256};
use bitcoin_rs_rpc::compat_manifest::MANIFEST_TOML;
use reference_set::{CorpusCustody, ReferenceError, load_reference_set, reference_set};

fn edit_reference(section: Option<&str>, edit: impl FnOnce(&mut toml::Table)) -> String {
    let mut manifest: toml::Table = toml::from_str(MANIFEST_TOML).expect("manifest parses");
    let reference = manifest["reference"]
        .as_table_mut()
        .expect("reference table");
    let target = match section {
        Some(section) => reference
            .get_mut(section)
            .expect("reference section")
            .as_table_mut()
            .expect("section table"),
        None => reference,
    };
    edit(target);
    toml::to_string(&manifest).expect("edited manifest")
}

/// REF-03: the oracle package checksum must belong to the locked package.
#[test]
fn kernel_package_custody_matches_the_lockfile() {
    let set = reference_set().expect("complete reference set");
    let lock: toml::Table =
        toml::from_str(include_str!("../../../Cargo.lock")).expect("Cargo.lock parses");
    let kernel = lock["package"]
        .as_array()
        .expect("locked packages")
        .iter()
        .find(|package| package["name"].as_str() == Some(set.kernel.kernel_sys_crate.as_str()))
        .expect("the oracle package is locked");
    assert_eq!(
        kernel["version"].as_str(),
        Some(set.kernel.kernel_sys_crate_version.as_str())
    );
    let checksum = sha256::Hash::from_byte_array(set.kernel.kernel_sys_crate_sha256).to_string();
    assert_eq!(kernel["checksum"].as_str(), Some(checksum.as_str()));
}

/// REF-02/REF-03: labels, missing fields and malformed revisions are not pins.
#[test]
fn source_revisions_require_immutable_complete_identities() {
    let malformed = "g".repeat(40);
    for (section, field) in [
        (Some("release"), "source_commit"),
        (None, "kernel_source_commit"),
        (None, "kernel_vendor_commit"),
    ] {
        for revision in [
            None,
            Some(""),
            Some("master"),
            Some("fb0e8612"),
            Some(malformed.as_str()),
        ] {
            let edited = edit_reference(section, |table| {
                if let Some(revision) = revision {
                    table.insert(field.to_owned(), revision.into());
                } else {
                    table.remove(field);
                }
            });
            let expected = if revision.is_none_or(str::is_empty) {
                ReferenceError::VersionLabelOnly { field }
            } else {
                ReferenceError::RevisionMalformed { field }
            };
            assert_eq!(load_reference_set(&edited), Err(expected));
        }
    }
}

/// REF-02/REF-03: syntactically valid replacements still need artifact custody.
#[test]
fn unbound_source_and_artifact_identities_are_rejected() {
    for (section, field, width, identity) in [
        (Some("release"), "source_commit", 40, "reference.release"),
        (None, "kernel_source_commit", 40, "reference.kernel"),
        (None, "kernel_vendor_commit", 40, "reference.kernel"),
        (Some("release"), "archive_sha256", 64, "reference.release"),
        (Some("release"), "bitcoind_sha256", 64, "reference.release"),
        (None, "kernel_sys_crate_sha256", 64, "reference.kernel"),
    ] {
        let edited = edit_reference(section, |table| {
            table.insert(field.to_owned(), "0".repeat(width).into());
        });
        assert_eq!(
            load_reference_set(&edited),
            Err(ReferenceError::CustodyMismatch { identity }),
            "{field}"
        );
    }
}

/// REF-02: missing, short and non-hex digests retain their typed refusal.
#[test]
fn malformed_release_digests_are_rejected() {
    for digest in [None, Some("1".repeat(63)), Some("g".repeat(64))] {
        let edited = edit_reference(Some("release"), |table| {
            if let Some(digest) = digest.as_ref() {
                table.insert("archive_sha256".to_owned(), digest.as_str().into());
            } else {
                table.remove("archive_sha256");
            }
        });
        let expected = if digest.is_none() {
            ReferenceError::VersionLabelOnly {
                field: "archive_sha256",
            }
        } else {
            ReferenceError::DigestMalformed {
                field: "archive_sha256",
            }
        };
        assert_eq!(load_reference_set(&edited), Err(expected));
    }
}

/// REF-02: the kernel oracle is not the released product comparator.
#[test]
fn the_kernel_tree_written_as_the_release_is_identity_confusion() {
    let set = reference_set().expect("reference set");
    let edited = edit_reference(Some("release"), |table| {
        table.insert("core_version".to_owned(), set.kernel.core_version.into());
    });
    assert_eq!(
        load_reference_set(&edited),
        Err(ReferenceError::IdentityConfusion)
    );
}

/// REF-04: absent corpora are named; absent export pins mean blocked custody.
#[test]
fn corpus_custody_distinguishes_missing_unpinned_and_pinned() {
    let set = reference_set().expect("reference set");
    assert!(
        set.corpus_custody()
            .iter()
            .all(|(_, custody)| *custody == CorpusCustody::Pinned)
    );
    for corpus in &set.corpora {
        let edited = edit_reference(None, |table| {
            table["corpora"]
                .as_array_mut()
                .expect("corpora")
                .retain(|entry| entry["id"].as_str() != Some(corpus.id.as_str()));
        });
        assert_eq!(
            load_reference_set(&edited),
            Err(ReferenceError::MissingCorpus {
                id: corpus.id.clone()
            })
        );
        let edited = edit_reference(None, |table| {
            table["corpora"]
                .as_array_mut()
                .expect("corpora")
                .iter_mut()
                .find(|entry| entry["id"].as_str() == Some(corpus.id.as_str()))
                .expect("selected corpus")
                .as_table_mut()
                .expect("corpus table")
                .remove("manifest_sha256");
        });
        let changed = load_reference_set(&edited).expect("unpinned corpus loads as blocked");
        for (id, custody) in changed.corpus_custody() {
            let expected = if id == corpus.id {
                CorpusCustody::Blocked {
                    missing: "manifest_sha256",
                }
            } else {
                CorpusCustody::Pinned
            };
            assert_eq!(custody, expected, "{id}");
        }
    }
}

/// REF-07: a declared public deviation must explain its different behavior.
#[test]
fn every_deviation_entry_states_its_deviation() {
    let mut deviations = 0_usize;
    for entry in bitcoin_rs_rpc::manifest::MANIFEST {
        if entry.status != bitcoin_rs_rpc::manifest::Status::Deviation {
            continue;
        }
        assert!(
            !entry.notes.trim().is_empty(),
            "row `{}` claims a deviation without stating it",
            entry.name
        );
        deviations = deviations.saturating_add(1);
    }
    assert!(deviations > 0, "the registry must record its deviations");
}
