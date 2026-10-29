//! Strict bounded loader for the checked-in Core 31.1 fixture corpus.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_rpc::manifest::{MANIFEST, SurfaceKind};
use serde::Deserialize;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

use super::compare::EnvelopeCheck;
use super::limits::{MAX_CORPUS_BYTES, MAX_FIXTURE_BYTES, MAX_FIXTURE_COUNT, MAX_JSON_DEPTH};
use super::manifest_check;

use bitcoin_rs_e2e::reference_set;

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum Relation {
    Exact,
    #[serde(rename = "known_gap")]
    KnownGap,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// Provenance pinned by every fixture; the loader refuses a fixture that
/// drifts from the audited Core 31.1 binary or the regtest network.
pub(crate) struct Provenance {
    /// Pinned Core version string; must be `31.1.0`.
    pub core_version: String,
    pub core_source_commit: String,
    /// SHA-256 of the exact `bitcoind` binary the probe captured.
    pub core_binary_sha256: String,
    /// Network the capture ran on; must be `regtest`.
    pub network: String,
    pub tip_height: u64,
    pub tip_hash: String,
    pub evidence: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum RequestAuth {
    Valid,
    Invalid,
    Absent,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestSpec {
    pub auth: RequestAuth,
    pub body: String,
    pub methods: Vec<String>,
    pub expect_methods_in_manifest: bool,
    pub fragment_at: Option<usize>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpTuple {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body_len: Option<u64>,
    pub body: BodyForm,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "form", rename_all = "snake_case")]
pub(crate) enum BodyForm {
    /// Zero-length body (204 notifications, 401 auth failures).
    Empty,
    Text {
        text: String,
    },
    Json {
        #[serde(deserialize_with = "super::compare::json_value")]
        value: Value,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fixture {
    pub id: String,
    pub case_ordinal: String,
    pub description: String,
    pub provenance: Provenance,
    pub request: RequestSpec,
    pub core: HttpTuple,
    #[serde(default)]
    pub current: Option<HttpTuple>,
    pub relation: Relation,
    #[serde(default)]
    pub gap: Option<String>,
    #[serde(default)]
    pub gap_paths: Vec<String>,
    pub checks: Checks,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeaderClass {
    Exact,
    Volatile,
    Gap,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeaderCheck {
    #[serde(default)]
    pub(crate) exact: Vec<String>,
    #[serde(default)]
    pub(crate) volatile: Vec<String>,
    #[serde(default)]
    pub(crate) gap: Vec<String>,
    #[serde(default)]
    pub(crate) body_length: bool,
}

impl HeaderCheck {
    #[must_use]
    pub(crate) fn class_of(&self, lower_name: &str) -> Option<HeaderClass> {
        let matches = |list: &[String]| {
            list.iter()
                .any(|name| name.eq_ignore_ascii_case(lower_name))
        };
        if matches(&self.exact) {
            Some(HeaderClass::Exact)
        } else if matches(&self.volatile) {
            Some(HeaderClass::Volatile)
        } else if matches(&self.gap) {
            Some(HeaderClass::Gap)
        } else {
            None
        }
    }

    #[must_use]
    pub(crate) fn classes(&self) -> [&[String]; 3] {
        [&self.exact, &self.volatile, &self.gap]
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checks {
    pub http_status: bool,
    pub headers: HeaderCheck,
    pub body: BodyCheck,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum BodyCheck {
    Empty,
    Text,
    Single { envelope: EnvelopeCheck },
    Batch { elements: Vec<EnvelopeCheck> },
}

pub(crate) const PINNED_NETWORK: &str = "regtest";

#[derive(Debug)]
/// Load error: every refusal names the ceiling or rule it hit.
pub(crate) enum LoadError {
    Violation(String),
    Io(std::io::Error),
}

impl core::fmt::Display for LoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Violation(why) => write!(f, "corpus violation: {why}"),
            Self::Io(error) => write!(f, "corpus io error: {error}"),
        }
    }
}

pub(crate) const PINNED_TIP_HEIGHT: u64 = 0;

pub(crate) const PINNED_TIP_HASH: &str =
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
impl std::error::Error for LoadError {}

pub(crate) fn load_corpus() -> Result<BTreeMap<String, Fixture>, LoadError> {
    let reference =
        reference_set::reference_set().map_err(|error| LoadError::Violation(error.to_string()))?;
    load_corpus_from(&corpus_dir(), &reference.release)
}

fn load_corpus_from(
    dir: &Path,
    release: &reference_set::ReleaseIdentity,
) -> Result<BTreeMap<String, Fixture>, LoadError> {
    let corpus_dir = corpus_io::open(dir)?;
    let entries = corpus_io::entries(&corpus_dir, dir)?;
    let mut fixture_count = 0_usize;
    let mut corpus_bytes = 0_u64;
    let mut fixtures = BTreeMap::new();
    for name in entries {
        let name = name?;
        fixture_count += 1;
        if fixture_count > MAX_FIXTURE_COUNT {
            return Err(LoadError::Violation(format!(
                "corpus holds more than the ceiling of {MAX_FIXTURE_COUNT} entries"
            )));
        }
        let path = dir.join(&name);
        if path
            .extension()
            .is_none_or(|ext| ext.to_string_lossy() != "json")
        {
            return Err(LoadError::Violation(format!(
                "{}: the corpus carries fixtures only; non-JSON entries are refused",
                path.display()
            )));
        }
        let bytes = corpus_io::read_regular_bounded(&corpus_dir, &name, &path)?;
        let actual = len_u64(bytes.len());
        corpus_bytes += actual;
        if corpus_bytes > MAX_CORPUS_BYTES {
            return Err(LoadError::Violation(format!(
                "corpus exceeds the total ceiling of {MAX_CORPUS_BYTES} actual bytes"
            )));
        }
        let text = String::from_utf8(bytes).map_err(|error| {
            LoadError::Violation(format!("{}: not valid utf-8: {error}", path.display()))
        })?;
        enforce_depth(&text, &path)?;
        let mut fixture: Fixture = sonic_rs::from_str(&text)
            .map_err(|error| LoadError::Violation(format!("{}: {error}", path.display())))?;
        settle_body_lengths(&mut fixture);
        validate_fixture(&fixture, &path, release)?;
        if fixtures.insert(fixture.id.clone(), fixture).is_some() {
            return Err(LoadError::Violation(format!(
                "duplicate fixture id in {}",
                path.display()
            )));
        }
    }
    if fixtures.is_empty() {
        return Err(LoadError::Violation("corpus is empty".to_owned()));
    }
    Ok(fixtures)
}

#[cfg(unix)]
mod corpus_io {
    use std::io::Read as _;
    use std::path::Path;

    use super::{LoadError, MAX_FIXTURE_BYTES, len_u64};

    pub(super) type CorpusDir = rustix::fd::OwnedFd;

    pub(super) fn open(dir: &Path) -> Result<CorpusDir, LoadError> {
        rustix::fs::open(
            dir,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| {
            LoadError::Violation(format!(
                "{}: corpus directory could not be opened no-follow: {error}",
                dir.display()
            ))
        })
    }

    pub(super) fn entries<'a>(
        dir: &'a CorpusDir,
        path: &'a Path,
    ) -> Result<Box<dyn Iterator<Item = Result<String, LoadError>> + 'a>, LoadError> {
        let inner = rustix::fs::Dir::read_from(dir).map_err(|error| {
            LoadError::Violation(format!(
                "{}: corpus directory could not be enumerated: {error}",
                path.display()
            ))
        })?;
        Ok(Box::new(inner.filter_map(move |entry| match entry {
            Err(error) => Some(Err(LoadError::Violation(format!(
                "{}: corpus directory entry could not be read: {error}",
                path.display()
            )))),
            Ok(entry) => {
                let name = entry.file_name().to_string_lossy().into_owned();
                (!matches!(name.as_str(), "." | "..")).then_some(Ok(name))
            }
        })))
    }

    pub(super) fn read_regular_bounded(
        dir: &CorpusDir,
        name: &str,
        path: &Path,
    ) -> Result<Vec<u8>, LoadError> {
        let refuse = |why: &str| {
            LoadError::Violation(format!(
                "{}: only regular files may carry fixtures; symlinks and directories are \
                 refused ({why})",
                path.display()
            ))
        };
        let file_fd = rustix::fs::openat(
            dir,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| {
            if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::MLINK {
                refuse("is a symbolic link")
            } else {
                LoadError::Violation(format!("{}: could not be opened: {error}", path.display()))
            }
        })?;
        let stat = rustix::fs::fstat(&file_fd).map_err(|error| {
            LoadError::Violation(format!("{}: fstat failed: {error}", path.display()))
        })?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
            return Err(refuse("is not a regular file"));
        }
        let mut bytes = Vec::new();
        std::fs::File::from(file_fd)
            .take(MAX_FIXTURE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(LoadError::Io)?;
        if len_u64(bytes.len()) > MAX_FIXTURE_BYTES {
            return Err(LoadError::Violation(format!(
                "{} is above the per-fixture ceiling of {MAX_FIXTURE_BYTES} bytes",
                path.display()
            )));
        }
        Ok(bytes)
    }
}

#[cfg(windows)]
mod corpus_io {
    use std::io::Read as _;
    use std::path::Path;

    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
    use cap_std::fs::{Dir, OpenOptions};

    use super::{LoadError, MAX_FIXTURE_BYTES, len_u64};

    pub(super) type CorpusDir = Dir;

    pub(super) fn open(dir: &Path) -> Result<CorpusDir, LoadError> {
        use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};

        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

        let file = std::fs::File::options()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir)
            .map_err(|error| {
                LoadError::Violation(format!(
                    "{}: corpus directory could not be opened no-follow: {error}",
                    dir.display()
                ))
            })?;
        let metadata = file.metadata().map_err(|error| {
            LoadError::Violation(format!(
                "{}: corpus directory could not be opened no-follow: {error}",
                dir.display()
            ))
        })?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir() {
            return Err(LoadError::Violation(format!(
                "{}: corpus directory could not be opened no-follow: not a directory",
                dir.display()
            )));
        }
        Ok(Dir::from_std_file(file))
    }

    pub(super) fn entries<'a>(
        dir: &'a CorpusDir,
        path: &'a Path,
    ) -> Result<Box<dyn Iterator<Item = Result<String, LoadError>> + 'a>, LoadError> {
        let inner = dir.entries().map_err(|error| {
            LoadError::Violation(format!(
                "{}: corpus directory could not be enumerated: {error}",
                path.display()
            ))
        })?;
        Ok(Box::new(inner.map(move |entry| {
            entry
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .map_err(|error| {
                    LoadError::Violation(format!(
                        "{}: corpus directory entry could not be read: {error}",
                        path.display()
                    ))
                })
        })))
    }

    pub(super) fn read_regular_bounded(
        dir: &CorpusDir,
        name: &str,
        path: &Path,
    ) -> Result<Vec<u8>, LoadError> {
        let refuse = |why: &str| {
            LoadError::Violation(format!(
                "{}: only regular files may carry fixtures; symlinks and directories are \
                 refused ({why})",
                path.display()
            ))
        };
        let metadata = dir.symlink_metadata(name).map_err(|error| {
            LoadError::Violation(format!("{}: could not be opened: {error}", path.display()))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(refuse("is a symbolic link"));
        }
        if !metadata.is_file() {
            return Err(refuse("is not a regular file"));
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = dir.open_with(name, &options).map_err(|error| {
            LoadError::Violation(format!("{}: could not be opened: {error}", path.display()))
        })?;
        if !file
            .metadata()
            .map_err(|error| {
                LoadError::Violation(format!("{}: fstat failed: {error}", path.display()))
            })?
            .is_file()
        {
            return Err(refuse("is not a regular file"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_FIXTURE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(LoadError::Io)?;
        if len_u64(bytes.len()) > MAX_FIXTURE_BYTES {
            return Err(LoadError::Violation(format!(
                "{} is above the per-fixture ceiling of {MAX_FIXTURE_BYTES} bytes",
                path.display()
            )));
        }
        Ok(bytes)
    }
}

#[must_use]
pub(crate) fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/core-31.1")
}

fn enforce_depth(text: &str, path: &Path) -> Result<(), LoadError> {
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in text.bytes() {
        match byte {
            b'\\' if in_string => escaped = !escaped,
            b'"' if !escaped => in_string = !in_string,
            b'{' | b'[' if !in_string => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return Err(LoadError::Violation(format!(
                        "{} exceeds the nesting ceiling of {MAX_JSON_DEPTH}",
                        path.display()
                    )));
                }
            }
            b'}' | b']' if !in_string => depth = depth.saturating_sub(1),
            _ => {}
        }
        if byte != b'\\' {
            escaped = false;
        }
    }
    Ok(())
}

fn settle_body_lengths(fixture: &mut Fixture) {
    let settle = |tuple: &mut HttpTuple| match &tuple.body {
        BodyForm::Empty => tuple.body_len = Some(0),
        BodyForm::Text { text } => tuple.body_len = Some(len_u64(text.len())),
        BodyForm::Json { .. } => tuple.body_len = None,
    };
    settle(&mut fixture.core);
    if let Some(current) = fixture.current.as_mut() {
        settle(current);
    }
}

fn validate_tuple_content_length(
    tuple: &HttpTuple,
    label: &str,
    path: &Path,
) -> Result<(), LoadError> {
    let declared: Vec<&str> = tuple
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.as_str())
        .collect();
    let fail = |why: String| LoadError::Violation(format!("{}: {label}: {why}", path.display()));
    if declared.len() > 1 {
        return Err(fail("duplicate Content-Length headers".to_owned()));
    }
    if tuple.status == 204 {
        if tuple.body_len != Some(0) {
            return Err(fail("204 response must have an empty body".to_owned()));
        }
        if let Some(value) = declared.first() {
            if *value != "0" || declared.len() != 1 {
                return Err(fail(
                    "204 Content-Length must be absent or exactly \"0\"".to_owned(),
                ));
            }
        }
        return Ok(());
    }
    match (declared.first(), tuple.body_len) {
        (None, _) => Ok(()),
        (Some(_), None) => Err(fail(String::from(
            "Content-Length is pinned on a JSON-body tuple, but that wire length is \
             derived framing; remove the literal and rely on the live invariant",
        ))),
        (Some(value), Some(length)) => {
            let parsed: Option<u64> = (*value)
                .parse()
                .ok()
                .filter(|_| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()));
            match parsed {
                Some(parsed) if parsed == length => Ok(()),
                Some(parsed) => Err(fail(format!(
                    "Content-Length {parsed} does not equal the body's actual {length} bytes"
                ))),
                None => Err(fail("Content-Length must be ASCII digits only".to_owned())),
            }
        }
    }
}

fn validate_fixture(
    fixture: &Fixture,
    path: &Path,
    release: &reference_set::ReleaseIdentity,
) -> Result<(), LoadError> {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| LoadError::Violation(format!("{}: unreadable file stem", path.display())))?;
    if stem != fixture.id {
        return Err(LoadError::Violation(format!(
            "{}: id {:?} does not match the file stem",
            path.display(),
            fixture.id
        )));
    }
    if fixture.description.trim().is_empty() {
        return Err(LoadError::Violation(format!(
            "{}: every fixture must describe what its case proves",
            path.display()
        )));
    }

    let derived = derive_request_methods(&fixture.request.body, fixture.core.status)
        .map_err(|why| LoadError::Violation(format!("{}: {why}", path.display())))?;
    if derived != fixture.request.methods {
        return Err(LoadError::Violation(format!(
            "{}: request methods {:?} do not match the methods derived from the body {:?}",
            path.display(),
            fixture.request.methods,
            derived
        )));
    }

    validate_provenance(&fixture.provenance, path, release)?;
    match (
        &fixture.relation,
        &fixture.current,
        &fixture.gap,
        &fixture.gap_paths,
    ) {
        (Relation::Exact, None, None, paths) if paths.is_empty() => {}
        (Relation::Exact, _, _, _) => {
            return Err(LoadError::Violation(format!(
                "{}: an exact relation must not pin a current tuple, a gap id or gap paths",
                path.display()
            )));
        }
        (Relation::KnownGap, Some(_), Some(gap), paths)
            if !gap.trim().is_empty() && !paths.is_empty() => {}
        (Relation::KnownGap, _, _, _) => {
            return Err(LoadError::Violation(format!(
                "{}: a known gap must pin the current tuple, one concrete gap id and at \
                 least one gap path",
                path.display()
            )));
        }
    }
    manifest_check::check_fixture_methods(fixture, MANIFEST, SurfaceKind::Rpc)
        .map_err(|why| LoadError::Violation(format!("{}: {why}", path.display())))?;
    validate_tuple_content_length(&fixture.core, "core", path)?;
    if let Some(current) = fixture.current.as_ref() {
        validate_tuple_content_length(current, "current", path)?;
    }
    validate_header_partition(fixture, path)?;
    validate_result_partition(fixture, path)
}

fn validate_provenance(
    provenance: &Provenance,
    path: &Path,
    release: &reference_set::ReleaseIdentity,
) -> Result<(), LoadError> {
    if provenance.core_version != format!("{}.0", release.core_version)
        || format!(
            "Bitcoin Core daemon version v{} bitcoind",
            provenance.core_version
        ) != release.version_output
    {
        return Err(LoadError::Violation(format!(
            "{}: pinned version {:?} does not match selected release {:?}",
            path.display(),
            provenance.core_version,
            release.version_output
        )));
    }
    if provenance.core_source_commit != release.source_commit {
        return Err(LoadError::Violation(format!(
            "{}: pinned source commit does not match the selected Core release",
            path.display()
        )));
    }
    if provenance.tip_height != PINNED_TIP_HEIGHT || provenance.tip_hash != PINNED_TIP_HASH {
        return Err(LoadError::Violation(format!(
            "{}: pinned tip identity does not match the captured regtest genesis",
            path.display()
        )));
    }
    if provenance.evidence.trim().is_empty() {
        return Err(LoadError::Violation(format!(
            "{}: every fixture must cite the probe evidence it was transcribed from",
            path.display()
        )));
    }
    if provenance.core_binary_sha256 != release.capture_bitcoind_sha256().to_lower_hex_string() {
        return Err(LoadError::Violation(format!(
            "{}: pinned binary digest does not match the selected Core release",
            path.display()
        )));
    }
    if provenance.network != PINNED_NETWORK {
        return Err(LoadError::Violation(format!(
            "{}: capture network {:?} is not {PINNED_NETWORK}",
            path.display(),
            provenance.network
        )));
    }
    Ok(())
}

fn validate_header_partition(fixture: &Fixture, path: &Path) -> Result<(), LoadError> {
    let fail = |why: String| LoadError::Violation(format!("{}: {why}", path.display()));
    let pinned = match (&fixture.relation, &fixture.current) {
        (Relation::Exact, _) => &fixture.core,
        (Relation::KnownGap, Some(current)) => current,
        (Relation::KnownGap, None) => {
            return Err(fail("known gap without a pinned current tuple".to_owned()));
        }
    };
    if fixture.checks.headers.body_length
        && fixture.checks.headers.class_of("content-length").is_some()
    {
        return Err(fail(
            "header Content-Length is owned by the derived body_length class and \
             must not also be classified exact, volatile or gap"
                .to_owned(),
        ));
    }
    let headers = &fixture.checks.headers;
    let mut claimed: std::collections::BTreeMap<String, &str> = std::collections::BTreeMap::new();
    for (index, class) in headers.classes().into_iter().enumerate() {
        let class_name = ["exact", "volatile", "gap"][index];
        for name in class {
            let lower = name.to_ascii_lowercase();
            if let Some(previous) = claimed.insert(lower.clone(), class_name) {
                return Err(fail(format!(
                    "header {name:?} is classified both {previous:?} and {class_name:?}"
                )));
            }
            if class_name != "volatile"
                && pinned
                    .headers
                    .iter()
                    .all(|(candidate, _)| !candidate.eq_ignore_ascii_case(&lower))
            {
                return Err(fail(format!(
                    "header {name:?} is classified {class_name:?} but the pinned tuple \
                     does not carry it, so nothing can be compared there"
                )));
            }
            if class_name == "gap" {
                let declared = format!("headers.{lower}");
                if !fixture.gap_paths.contains(&declared) {
                    return Err(fail(format!(
                        "gap header {name:?} must be declared as {declared:?} in gap_paths"
                    )));
                }
            }
        }
    }
    if matches!(fixture.relation, Relation::Exact) && !headers.gap.is_empty() {
        return Err(fail(
            "an exact relation must not classify any header as gap".to_owned(),
        ));
    }
    Ok(())
}

fn validate_result_partition(fixture: &Fixture, path: &Path) -> Result<(), LoadError> {
    let fail = |why: String| LoadError::Violation(format!("{}: {why}", path.display()));
    let pairs: Vec<(usize, &EnvelopeCheck, Option<&Value>)> =
        match (&fixture.checks.body, &fixture.core.body) {
            (BodyCheck::Single { envelope }, BodyForm::Json { value }) => {
                vec![(0_usize, envelope, Some(value))]
            }
            (BodyCheck::Batch { elements }, BodyForm::Json { value }) => {
                let Some(rows) = value.as_array() else {
                    return Err(fail(
                        "pinned Core batch body is not a JSON array".to_owned(),
                    ));
                };
                if rows.len() != elements.len() {
                    return Err(fail(format!(
                        "batch checks cover {} elements but the pinned Core body holds {}",
                        elements.len(),
                        rows.len()
                    )));
                }
                rows.iter()
                    .zip(elements)
                    .enumerate()
                    .map(|(index, (value, envelope))| (index, envelope, Some(value)))
                    .collect()
            }
            (BodyCheck::Empty | BodyCheck::Text, _) => Vec::new(),
            _ => {
                return Err(fail(
                    "check form does not match the pinned Core body form".to_owned(),
                ));
            }
        };
    for (envelope_index, envelope, core_envelope) in pairs {
        let Some(result) = core_envelope.and_then(|row| row.get("result")) else {
            continue;
        };
        let Some(result_object) = result.as_object() else {
            continue;
        };
        let mut claimed: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
        for (class, keys) in envelope.result.classes() {
            for key in keys {
                if let Some(previous) = claimed.insert(key.as_str(), class) {
                    return Err(fail(format!(
                        "result key {key:?} is classified both {previous:?} and {class:?}"
                    )));
                }
                if class == "gap" {
                    if fixture.relation != Relation::KnownGap {
                        return Err(fail(
                            "gap classification requires a known-gap relation".to_owned(),
                        ));
                    }
                    let Some(current_result) = pinned_current_result(fixture, envelope_index)
                    else {
                        return Err(fail(
                            "gap classification requires a pinned current tuple".to_owned(),
                        ));
                    };
                    let current_value = current_result.get(key.as_str());
                    let Some(current_value) = current_value else {
                        return Err(fail(format!(
                            "result key {key:?} is classified \"gap\" but the pinned current \
                             result does not carry the live shape"
                        )));
                    };
                    let Some(core_value) = result_object.get(key) else {
                        continue;
                    };
                    if super::compare::value_equal(core_value, current_value) {
                        return Err(fail(format!(
                            "result key {key:?} is classified \"gap\" but the pinned Core and \
                             current values are identical, so nothing diverges there"
                        )));
                    }
                    continue;
                }
                if !result_object.contains_key(key) {
                    return Err(fail(format!(
                        "result key {key:?} is classified {class:?} but the pinned Core result \
                         does not carry it"
                    )));
                }
            }
        }
        for (key, _) in result_object {
            if !claimed.contains_key(&key) {
                return Err(fail(format!(
                    "pinned Core result key {key:?} is not classified exactly once"
                )));
            }
        }
    }
    Ok(())
}

fn derive_request_methods(body: &str, status: u16) -> Result<Vec<String>, String> {
    let parsed: Value = match sonic_rs::from_str(body) {
        Ok(parsed) => parsed,
        Err(_) if status == 500 => return Ok(Vec::new()),
        Err(_) => {
            return Err(
                "request body is not valid JSON; only the parse-error case may send malformed              bytes"
                    .to_owned(),
            );
        }
    };
    if let Some(request) = parsed.as_object() {
        return Ok(vec![request_method(request, "request")?]);
    }
    if let Some(requests) = parsed.as_array() {
        let mut methods = Vec::with_capacity(requests.len());
        for (index, request) in requests.iter().enumerate() {
            let Some(request) = request.as_object() else {
                return Err(format!(
                    "batch element {index} is not a JSON-RPC request object"
                ));
            };
            methods.push(request_method(request, &format!("batch element {index}"))?);
        }
        return Ok(methods);
    }
    Err("request body must be a JSON-RPC object or a batch array".to_owned())
}

fn request_method(request: &sonic_rs::Object, what: &str) -> Result<String, String> {
    let Some(method) = request.get(&"method") else {
        return Err(format!("{what} carries no method member"));
    };
    let Some(method) = method.as_str() else {
        return Err(format!("{what} method member is not a string"));
    };
    Ok(method.to_owned())
}

fn pinned_current_result(fixture: &Fixture, envelope_index: usize) -> Option<&Value> {
    let current = &fixture.current.as_ref()?.body;
    let BodyForm::Json { value } = current else {
        return None;
    };
    if let Some(rows) = value.as_array() {
        rows.get(envelope_index)?.get("result")
    } else {
        value.get("result")
    }
}

#[cfg(test)]
mod tests {
    use sonic_rs::{JsonValueMutTrait as _, JsonValueTrait as _, Value};

    use super::{load_corpus_from, reference_set};

    const FIXTURE_NAME: &str = "01_getblockchaininfo_v2_positional.json";
    const CAPTURED_FIXTURE: &str =
        include_str!("../corpus/core-31.1/01_getblockchaininfo_v2_positional.json");

    fn captured_fixture() -> Result<Value, sonic_rs::Error> {
        sonic_rs::from_str(CAPTURED_FIXTURE)
    }

    fn assert_reference_rejected(
        fixture: &Value,
        reason: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join(FIXTURE_NAME), sonic_rs::to_vec(fixture)?)?;
        let Err(error) = load_corpus_from(dir.path(), &reference_set::reference_set()?.release)
        else {
            return Err("invalid Core reference was accepted".into());
        };
        let message = error.to_string();
        assert!(message.contains(FIXTURE_NAME), "{message}");
        assert!(message.contains(reason), "expected {reason:?}: {message}");
        Ok(())
    }

    #[test]
    fn copied_fixture_preserves_core_reference() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let fixture = captured_fixture()?;
        std::fs::write(dir.path().join(FIXTURE_NAME), sonic_rs::to_vec(&fixture)?)?;
        let corpus = load_corpus_from(dir.path(), &reference_set::reference_set()?.release)?;
        assert_eq!(corpus.len(), 1);
        Ok(())
    }

    #[test]
    fn corpus_rejects_missing_core_reference_fields() -> Result<(), Box<dyn std::error::Error>> {
        for field in ["core_version", "core_source_commit", "core_binary_sha256"] {
            let mut fixture = captured_fixture()?;
            fixture["provenance"]
                .as_object_mut()
                .ok_or("captured provenance must be an object")?
                .remove(&field);
            assert_reference_rejected(&fixture, &format!("missing field `{field}`"))?;
        }
        Ok(())
    }

    #[test]
    fn corpus_rejects_non_pinned_core_version() -> Result<(), Box<dyn std::error::Error>> {
        for version in ["31.0.0", "31.99.0", ""] {
            let mut fixture = captured_fixture()?;
            fixture["provenance"]["core_version"] = Value::from(version);
            assert_reference_rejected(&fixture, "pinned version")?;
        }
        Ok(())
    }

    #[test]
    fn corpus_rejects_mismatched_or_empty_core_digest() -> Result<(), Box<dyn std::error::Error>> {
        let original = captured_fixture()?;
        let digest = original["provenance"]["core_binary_sha256"]
            .as_str()
            .ok_or("captured binary digest must be a string")?;
        let mut changed = digest.to_owned();
        changed.replace_range(..1, if digest.starts_with('0') { "1" } else { "0" });
        for digest in [changed.as_str(), ""] {
            let mut fixture = original.clone();
            fixture["provenance"]["core_binary_sha256"] = Value::from(digest);
            assert_reference_rejected(&fixture, "pinned binary digest")?;
        }
        Ok(())
    }

    #[test]
    fn exact_401_tuple_checks_volatile_presence_on_the_live_reply_only()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::super::compare::{LiveChain, compare};
        use super::{BodyForm, Fixture, HttpTuple};

        const AUTH_401: &str = include_str!("../corpus/core-31.1/17_auth_absent.json");
        let fixture: Fixture = sonic_rs::from_str(AUTH_401)?;
        let chain = LiveChain {
            blocks: 0,
            headers: 0,
            best_block_hash: String::new(),
        };
        let live = |headers: &[(&str, &str)]| HttpTuple {
            status: 401,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            body_len: Some(0),
            body: BodyForm::Empty,
        };
        let full = live(&[
            ("WWW-Authenticate", "Basic realm=\"jsonrpc\""),
            ("Content-Length", "0"),
            ("Content-Type", "text/html; charset=ISO-8859-1"),
            ("Connection", "close"),
        ]);
        compare(&fixture, &full, &chain)
            .map_err(|mismatch| format!("full 401 tuple rejected: {mismatch}"))?;

        let mut without_connection = full.clone();
        without_connection
            .headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("connection"));
        let mut without_challenge = full.clone();
        without_challenge
            .headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("www-authenticate"));
        let mut wrong_type = full;
        wrong_type
            .headers
            .iter_mut()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .ok_or("live tuple must carry a content type")?
            .1 = "application/json".to_owned();
        for (label, tuple) in [
            ("declared volatile header", without_connection),
            ("exact challenge", without_challenge),
            ("exact content type", wrong_type),
        ] {
            assert!(
                compare(&fixture, &tuple, &chain).is_err(),
                "a live reply with a bad {label} must be rejected"
            );
        }
        Ok(())
    }

    #[test]
    fn corpus_rejects_stale_fixture_after_reference_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join(FIXTURE_NAME), CAPTURED_FIXTURE)?;
        let reference = reference_set::load_reference_set(bitcoin_rs_rpc::manifest::MANIFEST_TOML)?;
        for (field, reason) in [
            ("core_version", "pinned version"),
            ("source_commit", "pinned source commit"),
            ("bitcoind_sha256", "pinned binary digest"),
            ("version_output", "pinned version"),
        ] {
            let mut edited = reference.release.clone();
            match field {
                "core_version" => edited.core_version = "31.2".to_owned(),
                "source_commit" => {
                    edited.source_commit = "0000000000000000000000000000000000000000".to_owned();
                }
                "bitcoind_sha256" => edited.canonical.bitcoind_sha256 = [0; 32],
                "version_output" => {
                    edited.version_output = "Bitcoin Core daemon version v31.2.0".to_owned();
                }
                _ => unreachable!(),
            }
            let Err(error) = load_corpus_from(dir.path(), &edited) else {
                return Err(format!("old fixture was accepted after changing {field}").into());
            };
            let message = error.to_string();
            assert!(message.contains(FIXTURE_NAME), "{message}");
            assert!(message.contains(reason), "{message}");
        }
        Ok(())
    }
}
