//! Reference identities and validation used by the process and formal gates.
//! The production RPC module owns the embedded manifest, not test orchestration.

use std::collections::BTreeSet;

use bitcoin_rs_rpc::compat_manifest::MANIFEST_TOML;

/// The corpus identifiers every reference set must carry.
const REQUIRED_CORPORA: [&str; 2] = ["C150", "Cmodern"];

/// The immutable reference identities the compatibility manifest is claimed
/// against.
///
/// `docs/contracts/reference-set.md` is a readable projection of this record;
/// on conflict, `docs/api/core-compat.toml` as parsed here governs. A version
/// label alone is never custody: every identity carries its digest, and
/// [`load_reference_set`] rejects anything less.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReferenceSet {
    /// The released Bitcoin Core product: the behavioral reference.
    pub(crate) release: ReleaseIdentity,
    /// The Core development tree the oracle lane links. Oracle evidence only:
    /// not a release, and never a policy pin.
    pub(crate) kernel: KernelIdentity,
    /// Replay corpora with their pinned stop identities.
    pub(crate) corpora: Vec<CorpusPin>,
    /// The formal model checker pin.
    pub(crate) formal_tool: FormalTool,
}

impl ReferenceSet {
    /// Reports, per corpus, whether its manifest digest is pinned today.
    ///
    /// `Blocked` names the absent artifact instead of inventing one: corpus
    /// manifest digests are produced at export time and are legitimately
    /// absent until the archive exists.
    #[must_use]
    pub(crate) fn corpus_custody(&self) -> Vec<(String, CorpusCustody)> {
        self.corpora
            .iter()
            .map(|corpus| {
                let custody = match corpus.manifest_sha256 {
                    Some(_) => CorpusCustody::Pinned,
                    None => CorpusCustody::Blocked {
                        missing: "manifest_sha256",
                    },
                };
                (corpus.id.clone(), custody)
            })
            .collect()
    }
}

/// The released Bitcoin Core product identity.
///
/// `core_version` is a released `MAJOR.MINOR` product (e.g. `31.1`), pinned
/// by source commit and by the digests of the archive and the `bitcoind`
/// binary inside it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReleaseIdentity {
    /// Released product version, `MAJOR.MINOR`.
    pub(crate) core_version: String,
    /// Release tag (e.g. `v31.1`).
    pub(crate) git_tag: String,
    /// Source commit the release was built from.
    pub(crate) source_commit: String,
    /// Release archive the binary digest is taken from.
    pub(crate) archive: String,
    /// SHA-256 of the release archive.
    pub(crate) archive_sha256: [u8; 32],
    /// SHA-256 of the `bitcoind` binary inside the archive.
    pub(crate) bitcoind_sha256: [u8; 32],
    /// The exact `bitcoind -version` line the pinned binary must print.
    pub(crate) version_output: String,
}

/// The Core development tree the oracle lane links.
///
/// `core_version` follows Core's master convention ("after 31.x, before
/// 32.0" is `31.99.x`): a moving tree, not a release. This identity is
/// evidence about the oracle lane only and must never be read as the product
/// reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KernelIdentity {
    /// Core tree version (e.g. `31.99.0`).
    pub(crate) core_version: String,
    /// Safe wrapper crate pinned in the manifest.
    pub(crate) kernel_crate: String,
    /// Locked version of the wrapper crate.
    pub(crate) kernel_crate_version: String,
    /// `-sys` crate vendoring the Core source.
    pub(crate) kernel_sys_crate: String,
    /// Locked version of the `-sys` crate.
    pub(crate) kernel_sys_crate_version: String,
    /// Whether a differential harness compares *values* against a running
    /// reference. `false` means no entry may claim `supported`.
    pub(crate) differential_harness: bool,
}

/// A replay corpus pinned by its stop identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CorpusPin {
    /// Corpus identifier (e.g. `C150`).
    pub(crate) id: String,
    /// Last mainnet height the corpus covers.
    pub(crate) stop_height: u64,
    /// Block hash at `stop_height`.
    pub(crate) stop_hash: String,
    /// SHA-256 of the corpus manifest, produced at export time. Absent until
    /// the archive exists; a placeholder here would be an invented digest.
    pub(crate) manifest_sha256: Option<[u8; 32]>,
}

/// The formal model checker pin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FormalTool {
    /// Tool name (e.g. `apalache-mc`).
    pub(crate) name: String,
    /// Released tool version.
    pub(crate) version: String,
    /// SHA-256 of the release archive.
    pub(crate) archive_sha256: [u8; 32],
    /// SHA-256 of the checker jar inside the archive.
    pub(crate) jar_sha256: [u8; 32],
}

/// Custody state of a corpus archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CorpusCustody {
    /// The manifest digest is pinned; the corpus is held end to end.
    Pinned,
    /// A required custody artifact is absent, named by `missing`.
    Blocked {
        /// The absent artifact.
        missing: &'static str,
    },
}

/// Why a reference identity failed to load.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ReferenceError {
    /// The manifest does not parse as TOML.
    #[error("the compatibility manifest does not parse: {detail}")]
    ManifestUnreadable {
        /// The parser's own message.
        detail: String,
    },
    /// An identity field is absent, leaving a version label without the
    /// digest or record that makes it custody.
    #[error("`reference.{field}` is absent: a version label alone is not a reference")]
    VersionLabelOnly {
        /// The absent identity field.
        field: &'static str,
    },
    /// A digest is present but is not 64 lowercase hex characters.
    #[error("`{field}` must be 64 lowercase hex characters")]
    DigestMalformed {
        /// The malformed digest field.
        field: &'static str,
    },
    /// The released product and the kernel development tree were confused.
    #[error(
        "the released product identity and the 31.99.x kernel tree identity were \
         confused: the release must be a MAJOR.MINOR product version distinct from \
         the kernel tree"
    )]
    IdentityConfusion,
    /// A required corpus is absent from the reference set.
    #[error("the `{id}` corpus is missing from the reference set")]
    MissingCorpus {
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

/// Parses the `[reference]` record out of a compatibility manifest.
///
/// Every digest is decoded to bytes and every identity is required in full;
/// this is where "a version label alone" stops being a reference.
pub(crate) fn load_reference_set(manifest: &str) -> Result<ReferenceSet, ReferenceError> {
    let table: toml::Table =
        toml::from_str(manifest).map_err(|err| ReferenceError::ManifestUnreadable {
            detail: err.to_string(),
        })?;
    let reference = table
        .get("reference")
        .and_then(toml::Value::as_table)
        .ok_or(ReferenceError::VersionLabelOnly { field: "reference" })?;

    let release_table = sub_table(reference, "release")?;
    let release = ReleaseIdentity {
        core_version: required_str(release_table, "core_version")?,
        git_tag: required_str(release_table, "git_tag")?,
        source_commit: required_str(release_table, "source_commit")?,
        archive: required_str(release_table, "archive")?,
        archive_sha256: required_sha256(release_table, "archive_sha256")?,
        bitcoind_sha256: required_sha256(release_table, "bitcoind_sha256")?,
        version_output: required_str(release_table, "version_output")?,
    };

    let kernel = KernelIdentity {
        core_version: required_str(reference, "core_version")?,
        kernel_crate: required_str(reference, "kernel_crate")?,
        kernel_crate_version: required_str(reference, "kernel_crate_version")?,
        kernel_sys_crate: required_str(reference, "kernel_sys_crate")?,
        kernel_sys_crate_version: required_str(reference, "kernel_sys_crate_version")?,
        differential_harness: required_bool(reference, "differential_harness")?,
    };

    let corpora = corpora(reference)?;
    let formal_tool = formal_tool(reference)?;

    check_identity_confusion(&release.core_version, &kernel.core_version)?;

    Ok(ReferenceSet {
        release,
        kernel,
        corpora,
        formal_tool,
    })
}

/// Loads the reference set from the manifest embedded at compile time.
pub(crate) fn reference_set() -> Result<ReferenceSet, ReferenceError> {
    load_reference_set(MANIFEST_TOML)
}

fn corpora(reference: &toml::Table) -> Result<Vec<CorpusPin>, ReferenceError> {
    let array = reference
        .get("corpora")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| ReferenceError::MissingCorpus {
            id: REQUIRED_CORPORA[0].to_owned(),
        })?;

    let mut corpora = Vec::with_capacity(array.len());
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
        let manifest_sha256 = match entry.get("manifest_sha256") {
            None => None,
            Some(toml::Value::String(text)) => Some(parse_sha256("manifest_sha256", text)?),
            Some(_) => {
                return Err(ReferenceError::DigestMalformed {
                    field: "manifest_sha256",
                });
            }
        };
        corpora.push(CorpusPin {
            id,
            stop_height,
            stop_hash,
            manifest_sha256,
        });
    }

    for id in REQUIRED_CORPORA {
        if !corpora.iter().any(|corpus| corpus.id == id) {
            return Err(ReferenceError::MissingCorpus { id: id.to_owned() });
        }
    }
    Ok(corpora)
}

fn formal_tool(reference: &toml::Table) -> Result<FormalTool, ReferenceError> {
    let section = sub_table(reference, "formal_tool")?;
    Ok(FormalTool {
        name: required_str(section, "name")?,
        version: required_str(section, "version")?,
        archive_sha256: required_sha256(section, "archive_sha256")?,
        jar_sha256: required_sha256(section, "jar_sha256")?,
    })
}

fn sub_table<'a>(
    parent: &'a toml::Table,
    field: &'static str,
) -> Result<&'a toml::Table, ReferenceError> {
    parent
        .get(field)
        .and_then(toml::Value::as_table)
        .ok_or(ReferenceError::VersionLabelOnly { field })
}

fn required_str(section: &toml::Table, field: &'static str) -> Result<String, ReferenceError> {
    section
        .get(field)
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or(ReferenceError::VersionLabelOnly { field })
}

fn required_bool(section: &toml::Table, field: &'static str) -> Result<bool, ReferenceError> {
    section
        .get(field)
        .and_then(toml::Value::as_bool)
        .ok_or(ReferenceError::VersionLabelOnly { field })
}

fn required_u64(section: &toml::Table, field: &'static str) -> Result<u64, ReferenceError> {
    section
        .get(field)
        .and_then(toml::Value::as_integer)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(ReferenceError::VersionLabelOnly { field })
}

fn required_sha256(section: &toml::Table, field: &'static str) -> Result<[u8; 32], ReferenceError> {
    let text = required_str(section, field)?;
    parse_sha256(field, &text)
}

/// Decodes exactly 64 lowercase hex characters into a 32-byte digest.
fn parse_sha256(field: &'static str, text: &str) -> Result<[u8; 32], ReferenceError> {
    let mut digest = [0_u8; 32];
    let mut characters = text.chars();
    for byte in &mut digest {
        let high = hex_digit(field, characters.next())?;
        let low = hex_digit(field, characters.next())?;
        *byte = (high << 4) | low;
    }
    if characters.next().is_some() {
        return Err(ReferenceError::DigestMalformed { field });
    }
    Ok(digest)
}

fn hex_digit(field: &'static str, character: Option<char>) -> Result<u8, ReferenceError> {
    // Lowercase only: an uppercase digest is a different byte string from the
    // one the release page publishes, and custody compares strings.
    character
        .filter(|digit| digit.is_ascii_digit() || ('a'..='f').contains(digit))
        .and_then(|digit| digit.to_digit(16))
        .and_then(|value| u8::try_from(value).ok())
        .ok_or(ReferenceError::DigestMalformed { field })
}

/// Rejects the one way a reference set can quietly lie: reading the 31.99.x
/// kernel development tree as if it were the released product, or writing a
/// release whose version is not a `MAJOR.MINOR` product at all.
fn check_identity_confusion(release: &str, kernel: &str) -> Result<(), ReferenceError> {
    let released = release.split('.').count() == 2
        && release
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
    let mut kernel_parts = kernel.split('.');
    let development_tree = kernel_parts.next() == Some("31")
        && kernel_parts.next() == Some("99")
        && kernel_parts.next().is_some_and(|patch| {
            !patch.is_empty() && patch.bytes().all(|byte| byte.is_ascii_digit())
        })
        && kernel_parts.next().is_none();
    if release == kernel || !released || !development_tree {
        return Err(ReferenceError::IdentityConfusion);
    }
    Ok(())
}
