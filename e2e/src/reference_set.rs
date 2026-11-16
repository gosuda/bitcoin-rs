use bitcoin::hashes::{Hash as _, sha256};
use bitcoin_rs_rpc::manifest::MANIFEST_TOML;

const REQUIRED_CORPORA: [&str; 2] = ["C150", "Cmodern"];

const RELEASE_CUSTODY_SHA256: &str =
    "55517009bc1f8e0ae610c2ff346ec8ecd434c3d82c7944ac4a3a8a0491704aa5";
const KERNEL_CUSTODY_SHA256: &str =
    "c3af66539bbb49d08f268b569cbbeddf38b20487ccef8dee3916b048e2a1e366";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceSet {
    pub release: ReleaseIdentity,
    pub kernel: KernelIdentity,
    pub corpora: Vec<CorpusPin>,
}

impl ReferenceSet {
    #[must_use]
    pub fn corpus_custody(&self) -> Vec<(String, CorpusCustody)> {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseArtifact {
    pub target: String,
    pub archive: String,
    pub archive_sha256: [u8; 32],
    pub bitcoind_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseIdentity {
    pub core_version: String,
    pub git_tag: String,
    pub source_commit: String,
    pub canonical: ReleaseArtifact,
    pub platforms: Vec<ReleaseArtifact>,
    pub version_output: String,
}

impl ReleaseIdentity {
    pub fn artifact_for(&self, target: &str) -> Option<&ReleaseArtifact> {
        if self.canonical.target == target {
            return Some(&self.canonical);
        }
        self.platforms.iter().find(|row| row.target == target)
    }

    pub fn capture_bitcoind_sha256(&self) -> [u8; 32] {
        self.canonical.bitcoind_sha256
    }

    pub fn current_artifact(&self) -> Option<&ReleaseArtifact> {
        self.artifact_for(current_platform_target()?)
    }
}

pub fn current_platform_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-linux-gnu"),
        ("macos", "aarch64") => Some("arm64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("windows", "x86_64") => Some("win64"),
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelIdentity {
    pub core_version: String,
    pub kernel_crate: String,
    pub kernel_crate_version: String,
    pub kernel_sys_crate: String,
    pub kernel_sys_crate_version: String,
    pub kernel_vendor_commit: String,
    pub kernel_source_commit: String,
    pub kernel_sys_crate_sha256: [u8; 32],
    pub differential_harness: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorpusPin {
    pub id: String,
    pub manifest_sha256: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CorpusCustody {
    Pinned,
    Blocked { missing: &'static str },
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReferenceError {
    #[error("the compatibility manifest does not parse: {detail}")]
    ManifestUnreadable { detail: String },
    #[error("`reference.{field}` is absent: a version label alone is not a reference")]
    VersionLabelOnly { field: &'static str },
    #[error("`{field}` must be 64 lowercase hex characters")]
    DigestMalformed { field: &'static str },
    #[error("`{field}` must be a full 40-character lowercase hex commit")]
    RevisionMalformed { field: &'static str },
    #[error("`{identity}` does not match its audited artifact custody binding")]
    CustodyMismatch { identity: &'static str },
    #[error("more than one release artifact pins target `{target}`")]
    DuplicateArtifactTarget { target: String },
    #[error(
        "the released product identity and the 31.99.x kernel tree identity were \
         confused: the release must be a MAJOR.MINOR product version distinct from \
         the kernel tree"
    )]
    IdentityConfusion,
    #[error("the `{id}` corpus is missing from the reference set")]
    MissingCorpus { id: String },
}

pub fn load_reference_set(manifest: &str) -> Result<ReferenceSet, ReferenceError> {
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

fn check_custody_bindings(
    release: &ReleaseIdentity,
    kernel: &KernelIdentity,
) -> Result<(), ReferenceError> {
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

fn release_artifact(section: &toml::Table) -> Result<ReleaseArtifact, ReferenceError> {
    Ok(ReleaseArtifact {
        target: required_str(section, "target")?,
        archive: required_str(section, "archive")?,
        archive_sha256: required_sha256(section, "archive_sha256")?,
        bitcoind_sha256: required_sha256(section, "bitcoind_sha256")?,
    })
}

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

pub fn reference_set() -> Result<ReferenceSet, ReferenceError> {
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
    character
        .filter(|digit| digit.is_ascii_digit() || ('a'..='f').contains(digit))
        .and_then(|digit| digit.to_digit(16))
        .and_then(|value| u8::try_from(value).ok())
        .ok_or(ReferenceError::DigestMalformed { field })
}

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

#[cfg(test)]
mod tests;
