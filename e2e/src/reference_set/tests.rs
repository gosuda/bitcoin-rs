#![expect(clippy::expect_used, reason = "reference identity rejection tests")]

use super::{CorpusCustody, ReferenceError, load_reference_set, reference_set};
use bitcoin::hashes::{Hash, sha256};
use bitcoin_rs_rpc::manifest::{MANIFEST, MANIFEST_TOML, Status};

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

#[test]
fn platform_artifacts_join_custody_and_reject_duplicate_targets() {
    let edit_platform_target = |target: &str| {
        edit_reference(Some("release"), |table| {
            table
                .get_mut("platforms")
                .and_then(toml::Value::as_array_mut)
                .expect("platform rows")[0]
                .as_table_mut()
                .expect("platform row")
                .insert("target".to_owned(), target.into());
        })
    };

    assert_eq!(
        load_reference_set(&edit_platform_target("x86_64-apple-darwin")),
        Err(ReferenceError::CustodyMismatch {
            identity: "reference.release",
        })
    );

    assert_eq!(
        load_reference_set(&edit_platform_target("x86_64-linux-gnu")),
        Err(ReferenceError::DuplicateArtifactTarget {
            target: "x86_64-linux-gnu".to_owned(),
        })
    );
}

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

#[test]
fn every_deviation_entry_states_its_deviation() {
    let mut deviations = 0_usize;
    for entry in MANIFEST {
        if entry.status != Status::Deviation {
            continue;
        }
        assert!(
            !entry.notes.trim().is_empty(),
            "the {} row `{}` claims a deviation without stating it",
            entry.kind.label(),
            entry.name
        );
        deviations += 1;
    }
    assert!(deviations > 0, "the registry must record its deviations");
}
