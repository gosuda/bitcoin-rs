//! Reference identities and validation used by the process and formal gates.
//! The production RPC module owns the embedded manifest, not test orchestration.

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin_rs_rpc::manifest::MANIFEST_TOML;

/// The corpus identifiers every reference set must carry.
const REQUIRED_CORPORA: [&str; 2] = ["C150", "Cmodern"];

/// Audited fingerprints of the complete release and kernel identity tuples.
///
/// These are trust anchors, not a second registry of the tuple fields. The
/// manifest remains their value owner; changing any value requires reviewing
/// the external artifact evidence and deliberately updating its fingerprint.
const RELEASE_CUSTODY_SHA256: &str =
    "19c4f540d597ff5482cb39fdeccba654b26dda24a601115cd0db6bc3f10d4eaf";
const KERNEL_CUSTODY_SHA256: &str =
    "567455b412b76af4b394b371defc42f7e01c2a4e1dd2cdd1b891ca549c775f3b";

/// The immutable reference identities the compatibility manifest is claimed
/// against.
///
/// `docs/contracts/reference-set.md` is a readable projection of this record;
/// on conflict, `crates/rpc/core-compat.toml` as parsed here governs. A version
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

/// One pinned release artifact: a bitcoincore.org archive and the digests
/// of the tarball and the `bitcoind` binary inside it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReleaseArtifact {
    /// The archive's platform suffix (e.g. `x86_64-linux-gnu`).
    pub(crate) target: String,
    /// Release archive the binary digest is taken from.
    pub(crate) archive: String,
    /// SHA-256 of the release archive.
    pub(crate) archive_sha256: [u8; 32],
    /// SHA-256 of the `bitcoind` binary inside the archive.
    pub(crate) bitcoind_sha256: [u8; 32],
}

/// The released Bitcoin Core product identity.
///
/// `core_version` is a released `MAJOR.MINOR` product (e.g. `31.1`), pinned
/// by source commit and by digested artifacts: the canonical one whose
/// `bitcoind` captured the checked-in fixtures, plus one row per additional
/// platform a lane may run on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReleaseIdentity {
    /// Released product version, `MAJOR.MINOR`.
    pub(crate) core_version: String,
    /// Release tag (e.g. `v31.1`).
    pub(crate) git_tag: String,
    /// Source commit the release was built from.
    pub(crate) source_commit: String,
    /// The canonical artifact: the fixture-capture platform's pinning.
    pub(crate) canonical: ReleaseArtifact,
    /// Additional runnable artifacts keyed by `target`; no target may repeat
    /// the canonical one or a sibling's.
    pub(crate) platforms: Vec<ReleaseArtifact>,
    /// The exact `bitcoind -version` line the pinned binary must print.
    pub(crate) version_output: String,
}

impl ReleaseIdentity {
    /// The pinned artifact runnable on `target`: the canonical artifact when
    /// it names the target, else the matching `platforms` row. `None` means
    /// the manifest pins no artifact for the platform — an identity failure,
    /// never a skipped check.
    pub(crate) fn artifact_for(&self, target: &str) -> Option<&ReleaseArtifact> {
        if self.canonical.target == target {
            return Some(&self.canonical);
        }
        self.platforms.iter().find(|row| row.target == target)
    }

    /// The `bitcoind` digest that captured the checked-in fixtures: always
    /// the canonical artifact's, regardless of the platform running this
    /// suite.
    pub(crate) fn capture_bitcoind_sha256(&self) -> [u8; 32] {
        self.canonical.bitcoind_sha256
    }

    /// The pinned artifact runnable on the host platform, when the manifest
    /// carries one.
    pub(crate) fn current_artifact(&self) -> Option<&ReleaseArtifact> {
        self.artifact_for(current_platform_target()?)
    }
}

/// The host platform's release-archive suffix, mirroring the uname mapping in
/// `scripts/install-bitcoind.sh`. `None` on platforms no pinned artifact can
/// execute on.
pub(crate) fn current_platform_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-linux-gnu"),
        ("macos", "aarch64") => Some("arm64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        _ => None,
    }
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
    /// Published `-sys` crate's `.cargo_vcs_info.json` source revision.
    pub(crate) kernel_vendor_commit: String,
    /// Bitcoin Core commit imported by that crate's vendored subtree.
    pub(crate) kernel_source_commit: String,
    /// Published `-sys` package checksum, checked against `Cargo.lock`.
    pub(crate) kernel_sys_crate_sha256: [u8; 32],
    /// Whether a differential harness compares *values* against a running
    /// reference. `false` means no entry may claim `supported`.
    pub(crate) differential_harness: bool,
}

/// A replay corpus pinned by its manifest digest. The manifest also
/// carries the replay stop height and hash; the gate requires their
/// presence at load but no consumer reads them back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CorpusPin {
    /// Corpus identifier (e.g. `C150`).
    pub(crate) id: String,
    /// SHA-256 of the corpus manifest, produced at export time. Absent until
    /// the archive exists; a placeholder here would be an invented digest.
    pub(crate) manifest_sha256: Option<[u8; 32]>,
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
    /// A source identity is a mutable name or malformed commit hash.
    #[error("`{field}` must be a full 40-character lowercase hex commit")]
    RevisionMalformed {
        /// The malformed source revision field.
        field: &'static str,
    },
    /// A syntactically valid identity does not match the audited artifact
    /// tuple selected by this test gate.
    #[error("`{identity}` does not match its audited artifact custody binding")]
    CustodyMismatch {
        /// The complete identity tuple that did not match.
        identity: &'static str,
    },
    /// Two artifact rows pin the same platform target, making the runnable
    /// artifact ambiguous.
    #[error("more than one release artifact pins target `{target}`")]
    DuplicateArtifactTarget {
        /// The repeated platform target.
        target: String,
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
        source_commit: required_commit(release_table, "source_commit")?,
        canonical: release_artifact(release_table)?,
        platforms: release_platforms(release_table)?,
        version_output: required_str(release_table, "version_output")?,
    };
    if release
        .platforms
        .iter()
        .any(|row| row.target == release.canonical.target)
    {
        return Err(ReferenceError::DuplicateArtifactTarget {
            target: release.canonical.target,
        });
    }
    for (index, row) in release.platforms.iter().enumerate() {
        if release.platforms[..index]
            .iter()
            .any(|prior| prior.target == row.target)
        {
            return Err(ReferenceError::DuplicateArtifactTarget {
                target: row.target.clone(),
            });
        }
    }

    let kernel = KernelIdentity {
        core_version: required_str(reference, "core_version")?,
        kernel_crate: required_str(reference, "kernel_crate")?,
        kernel_crate_version: required_str(reference, "kernel_crate_version")?,
        kernel_sys_crate: required_str(reference, "kernel_sys_crate")?,
        kernel_sys_crate_version: required_str(reference, "kernel_sys_crate_version")?,
        kernel_vendor_commit: required_commit(reference, "kernel_vendor_commit")?,
        kernel_source_commit: required_commit(reference, "kernel_source_commit")?,
        kernel_sys_crate_sha256: required_sha256(reference, "kernel_sys_crate_sha256")?,
        differential_harness: required_bool(reference, "differential_harness")?,
    };

    let corpora = corpora(reference)?;
    check_formal_tool(reference)?;

    check_identity_confusion(&release.core_version, &kernel.core_version)?;
    check_custody_bindings(&release, &kernel)?;

    Ok(ReferenceSet {
        release,
        kernel,
        corpora,
    })
}

/// Binds human-readable revisions to the package and binary digests that
/// provide their custody. A full, well-formed but unrelated commit must not
/// silently pass merely because it looks like a Git object id.
fn check_custody_bindings(
    release: &ReleaseIdentity,
    kernel: &KernelIdentity,
) -> Result<(), ReferenceError> {
    // v2 tuple layout: the product identity fields, then each pinned
    // artifact (canonical first, `platforms` rows in manifest order).
    let artifact_fields = |artifact: &ReleaseArtifact| {
        format!(
            "{}\0{}\0{}\0{}",
            artifact.target,
            artifact.archive,
            sha256::Hash::from_byte_array(artifact.archive_sha256),
            sha256::Hash::from_byte_array(artifact.bitcoind_sha256),
        )
    };
    let mut release_tuple = format!(
        "bitcoin-rs/reference-release/v2\0{}\0{}\0{}\0{}\0{}",
        release.core_version,
        release.git_tag,
        release.source_commit,
        release.version_output,
        artifact_fields(&release.canonical),
    );
    for row in &release.platforms {
        release_tuple.push('\0');
        release_tuple.push_str(&artifact_fields(row));
    }
    check_custody_fingerprint("reference.release", &release_tuple, RELEASE_CUSTODY_SHA256)?;

    let kernel_package = sha256::Hash::from_byte_array(kernel.kernel_sys_crate_sha256).to_string();
    let differential_harness = kernel.differential_harness.to_string();
    let kernel_tuple = [
        "bitcoin-rs/reference-kernel/v1",
        kernel.core_version.as_str(),
        kernel.kernel_crate.as_str(),
        kernel.kernel_crate_version.as_str(),
        kernel.kernel_sys_crate.as_str(),
        kernel.kernel_sys_crate_version.as_str(),
        kernel.kernel_vendor_commit.as_str(),
        kernel.kernel_source_commit.as_str(),
        kernel_package.as_str(),
        differential_harness.as_str(),
    ]
    .join("\0");
    check_custody_fingerprint("reference.kernel", &kernel_tuple, KERNEL_CUSTODY_SHA256)
}

/// One `[reference.release]`-shaped table as a digested artifact: the
/// canonical table and each `[[reference.release.platforms]]` row share it.
fn release_artifact(section: &toml::Table) -> Result<ReleaseArtifact, ReferenceError> {
    Ok(ReleaseArtifact {
        target: required_str(section, "target")?,
        archive: required_str(section, "archive")?,
        archive_sha256: required_sha256(section, "archive_sha256")?,
        bitcoind_sha256: required_sha256(section, "bitcoind_sha256")?,
    })
}

/// The optional `[[reference.release.platforms]]` rows; absent means only the
/// canonical artifact may execute.
fn release_platforms(section: &toml::Table) -> Result<Vec<ReleaseArtifact>, ReferenceError> {
    let Some(rows) = section.get("platforms") else {
        return Ok(Vec::new());
    };
    let rows = rows
        .as_array()
        .ok_or(ReferenceError::VersionLabelOnly { field: "platforms" })?;
    rows.iter()
        .map(|value| {
            release_artifact(
                value
                    .as_table()
                    .ok_or(ReferenceError::VersionLabelOnly { field: "platforms" })?,
            )
        })
        .collect()
}

fn check_custody_fingerprint(
    identity: &'static str,
    tuple: &str,
    expected: &'static str,
) -> Result<(), ReferenceError> {
    let actual = sha256::Hash::hash(tuple.as_bytes()).to_byte_array();
    if actual != parse_sha256("custody_sha256", expected)? {
        return Err(ReferenceError::CustodyMismatch { identity });
    }
    Ok(())
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
    for value in array {
        let entry = value
            .as_table()
            .ok_or(ReferenceError::VersionLabelOnly { field: "corpora" })?;
        let id = required_str(entry, "id")?;
        required_u64(entry, "stop_height")?;
        required_str(entry, "stop_hash")?;
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

/// The formal model checker section must be a complete digested pin even
/// though no consumer reads it back: its absence or malformed digests are
/// the same rejections as any other reference field's.
fn check_formal_tool(reference: &toml::Table) -> Result<(), ReferenceError> {
    let section = sub_table(reference, "formal_tool")?;
    required_str(section, "name")?;
    required_str(section, "version")?;
    required_sha256(section, "archive_sha256")?;
    required_sha256(section, "jar_sha256")?;
    Ok(())
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
        .filter(|text| !text.trim().is_empty())
        .map(str::to_owned)
        .ok_or(ReferenceError::VersionLabelOnly { field })
}

fn required_commit(section: &toml::Table, field: &'static str) -> Result<String, ReferenceError> {
    let text = required_str(section, field)?;
    if text.len() != 40
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ReferenceError::RevisionMalformed { field });
    }
    Ok(text)
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
    if release == kernel || !released {
        return Err(ReferenceError::IdentityConfusion);
    }
    Ok(())
}
