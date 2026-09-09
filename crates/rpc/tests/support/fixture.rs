//! Strict bounded loader for the checked-in Core 31.1 fixture corpus.
//!
//! The corpus under `crates/rpc/tests/corpus/core-31.1/` is custody, not a
//! second method manifest: the const [`bitcoin_rs_rpc::manifest::MANIFEST`]
//! stays the sole method authority and [`manifest_check`] only proves every
//! replayed method exists there. Loading enforces every ceiling from
//! [`super::limits`], parses with `sonic-rs` into types that reject unknown
//! fields, measures JSON depth on the raw bytes before parsing, and pins the
//! exact Core provenance (version, binary digest, network).

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use bitcoin_rs_rpc::manifest::{MANIFEST, SurfaceKind};
use serde::Deserialize;
use serde_json::Value;

use super::compare::EnvelopeCheck;
use super::limits::{MAX_CORPUS_BYTES, MAX_FIXTURE_BYTES, MAX_FIXTURE_COUNT, MAX_JSON_DEPTH};
use super::manifest_check;

/// Converts an in-memory byte length to `u64` for ceiling comparisons; a
/// length that does not fit is above every ceiling and is refused by them.
fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// How the pinned Core result relates to the live bitcoin-rs result.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum Relation {
    /// The live tuple must match the Core tuple structurally.
    Exact,
    /// A recorded production divergence: the fixture pins both sides.
    #[serde(rename = "known_gap")]
    KnownGap,
}

/// Provenance pinned by every fixture; the loader refuses a fixture that
/// drifts from the audited Core 31.1 binary or the regtest network.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Provenance {
    /// Pinned Core version string; must be `31.1.0`.
    pub core_version: String,
    /// SHA-256 of the exact `bitcoind` binary the probe captured.
    pub core_binary_sha256: String,
    /// Network the capture ran on; must be `regtest`.
    pub network: String,
    /// Tip height at capture time.
    pub tip_height: u64,
    /// Tip hash (RPC display form) at capture time.
    pub tip_hash: String,
    /// Probe evidence files this fixture was transcribed from.
    pub evidence: String,
}

/// Auth posture of the replayed request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum RequestAuth {
    /// Correct Basic credentials.
    Valid,
    /// Deliberately wrong Basic credentials.
    Invalid,
    /// No `Authorization` header at all.
    Absent,
}

/// The replayed request, verbatim bytes included.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestSpec {
    /// Auth posture of the replayed request.
    pub auth: RequestAuth,
    /// Exact JSON-RPC body bytes to send.
    pub body: String,
    /// Method names the request carries (empty for parse errors).
    pub methods: Vec<String>,
    /// Whether every listed method must exist in the const manifest.
    pub expect_methods_in_manifest: bool,
    /// Byte offset at which the request write is split into two TCP
    /// fragments; `null` sends it in one write.
    pub fragment_at: Option<usize>,
}

/// A captured HTTP response side: status, the pinned header pairs, and the
/// body in one of three exact forms.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpTuple {
    /// HTTP status code.
    pub status: u16,
    /// Exact header pairs captured for this side (case preserved).
    pub headers: Vec<(String, String)>,
    /// Wire body byte length when it is derivable: empty and text bodies
    /// are exact; JSON bodies are `None` because the wire serialization of
    /// an insertion-order server value cannot be reproduced offline. The
    /// live replay always knows the wire length.
    #[serde(default)]
    pub body_len: Option<u64>,
    /// Body form: `empty`, `text`, or `json` with the decoded value.
    pub body: BodyForm,
}

/// Body side of an [`HttpTuple`].
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "form", rename_all = "snake_case")]
pub(crate) enum BodyForm {
    /// Zero-length body (204 notifications, 401 auth failures).
    Empty,
    /// Non-JSON plain-text body, compared byte for byte.
    Text {
        /// The exact body bytes as utf-8.
        text: String,
    },
    /// JSON body carried as the decoded `sonic-rs` value.
    Json {
        /// The decoded value (object, array, or scalar).
        value: Value,
    },
}

/// One checked-in fixture: provenance, request, the pinned Core tuple, the
/// optional pinned current tuple, the relation, and the structural checks.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fixture {
    /// Stable fixture identifier; must equal the file stem.
    pub id: String,
    /// Probe case ordinal this fixture was transcribed from.
    pub case_ordinal: String,
    /// Human-readable description of what the case proves.
    pub description: String,
    /// Pinned Core provenance.
    pub provenance: Provenance,
    /// Request to replay.
    pub request: RequestSpec,
    /// The captured Core response tuple.
    pub core: HttpTuple,
    /// The pinned current bitcoin-rs tuple; required exactly when the
    /// relation is a known gap.
    pub current: Option<HttpTuple>,
    /// How Core relates to live.
    pub relation: Relation,
    /// The single concrete gap identifier; required exactly for known gaps.
    pub gap: Option<String>,
    /// The complete structural paths (from `structural_diff_paths`) at
    /// which the pinned Core and pinned current tuples diverge; required
    /// exactly for known gaps, and the comparator proves the observed diff
    /// equals it with nothing extra. Defaults to empty, which only exact
    /// relations may carry.
    #[serde(default)]
    pub gap_paths: Vec<String>,
    /// Structural checks applied to the live replay.
    pub checks: Checks,
}

/// Classification class of one header name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeaderClass {
    /// Value must be present and equal on both sides.
    Exact,
    /// Value is wall-clock or connection dependent: presence only.
    Volatile,
    /// Declared live divergence: values must be present and differ.
    Gap,
}

/// Complete header classification: every header name on the pinned side
/// and on the live side must appear in exactly one of these lists.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeaderCheck {
    /// Names compared for exact structural equality.
    #[serde(default)]
    pub(crate) exact: Vec<String>,
    /// Names whose value is wall-clock or connection dependent:
    /// classified, presence-checked, deliberately not value-compared.
    #[serde(default)]
    pub(crate) volatile: Vec<String>,
    /// Declared divergence names (known-gap fixtures only).
    #[serde(default)]
    pub(crate) gap: Vec<String>,
    /// `Content-Length` is derived framing, not pinned data: it is absent on
    /// 204 responses and otherwise exactly one ASCII-decimal header per tuple
    /// whose value equals that tuple's actual raw body byte length.
    #[serde(default)]
    pub(crate) body_length: bool,
}

impl HeaderCheck {
    /// The class of one lower-cased header name, if it is classified.
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

    /// Every classified name list, in declaration order.
    #[must_use]
    pub(crate) fn classes(&self) -> [&[String]; 3] {
        [&self.exact, &self.volatile, &self.gap]
    }
}

/// Structural checks for one replayed fixture.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checks {
    /// Whether the live HTTP status must equal the pinned Core status.
    pub http_status: bool,
    /// Complete header classification.
    pub headers: HeaderCheck,
    /// Body-level check.
    pub body: BodyCheck,
}

/// Body-level structural check.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum BodyCheck {
    /// The body must be zero bytes.
    Empty,
    /// The body is plain text compared byte for byte against the pinned
    /// current side (known-gap cases only).
    Text,
    /// One JSON-RPC envelope.
    Single {
        /// Envelope and result checks.
        envelope: EnvelopeCheck,
    },
    /// A JSON array of envelopes, compared element by element in order.
    Batch {
        /// Envelope and result checks per response element, in request order.
        elements: Vec<EnvelopeCheck>,
    },
}

/// Version the corpus is pinned to.
pub(crate) const PINNED_CORE_VERSION: &str = "31.1.0";

/// SHA-256 of the exact `bitcoind` binary the probe captured.
pub(crate) const PINNED_CORE_SHA256: &str =
    "986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08";

/// The one supported capture network.
pub(crate) const PINNED_NETWORK: &str = "regtest";

/// Load error: every refusal names the ceiling or rule it hit.
#[derive(Debug)]
pub(crate) enum LoadError {
    /// Corpus or fixture exceeded a ceiling, or provenance drifted.
    Violation(String),
    /// Reading the corpus directory failed.
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

/// Tip height Core was captured at: the regtest genesis on an empty chain.
pub(crate) const PINNED_TIP_HEIGHT: u64 = 0;

/// Tip hash, in RPC display form, Core was captured at.
pub(crate) const PINNED_TIP_HASH: &str =
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
impl std::error::Error for LoadError {}

/// Loads and validates every fixture under `tests/corpus/core-31.1/`,
/// returning them keyed by fixture id in deterministic file-name order.
///
/// # Errors
/// [`LoadError::Violation`] when any ceiling, strict-parse rule or provenance
/// pin fails; [`LoadError::Io`] when the corpus directory cannot be read.
pub(crate) fn load_corpus() -> Result<BTreeMap<String, Fixture>, LoadError> {
    load_corpus_from(&corpus_dir())
}

fn load_corpus_from(dir: &Path) -> Result<BTreeMap<String, Fixture>, LoadError> {
    // Root custody: the corpus directory itself is opened no-follow, and
    // every entry is read from and opened relative to that one descriptor.
    // A replacement of the directory name after this point cannot redirect
    // any child open, because no child is ever resolved by full pathname.
    let dir_fd = rustix::fs::open(
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
    })?;
    let entries = rustix::fs::Dir::read_from(&dir_fd).map_err(|error| {
        LoadError::Violation(format!(
            "{}: corpus directory could not be enumerated: {error}",
            dir.display()
        ))
    })?;
    let mut fixture_count = 0_usize;
    let mut corpus_bytes = 0_u64;
    let mut fixtures = BTreeMap::new();
    // One dirfd walk does both custody accounting and reading: there is no
    // second pathname-based pass whose view could disagree with this one.
    for entry in entries {
        let entry = entry.map_err(|error| {
            LoadError::Violation(format!(
                "{}: corpus directory entry could not be read: {error}",
                dir.display()
            ))
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "." || name == ".." {
            continue;
        }
        // Every entry counts against the ceiling BEFORE any name-shape
        // filtering: unlimited non-JSON junk can no longer bypass the cap.
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
        let bytes = read_regular_bounded(&dir_fd, &name, &path)?;
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
        validate_fixture(&fixture, &path)?;
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

/// Reads one fixture from the corpus directory descriptor with no window
/// between the type check and the read: `openat` refuses to follow a final
/// symlink, `fstat` interrogates the *same* descriptor the bytes come from,
/// and the read is bounded by one extra byte past the ceiling so a lying
/// `st_size` cannot widen it.
///
/// # Errors
/// [`LoadError::Violation`] when the entry is not a regular file or exceeds
/// the per-fixture ceiling.
pub(crate) fn read_regular_bounded(
    dir_fd: &rustix::fd::OwnedFd,
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
    // `NOFOLLOW` refuses a final symlink outright; `NONBLOCK` keeps a FIFO
    // from blocking the open itself, so its type can be judged by `fstat`.
    let file_fd = rustix::fs::openat(
        dir_fd,
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
    // The type is now a property of this open description, not of a name
    // that another process could have replaced in the meantime.
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

/// Absolute path of the checked-in corpus.
#[must_use]
pub(crate) fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/core-31.1")
}

/// Measures object/array nesting on the raw fixture bytes, honoring string
/// and escape state, before the parser runs. A fixture may not smuggle
/// parser-exhausting nesting past the ceiling.
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

/// Derives each pinned tuple's wire body length where the body form makes
/// it exact: empty bodies are zero bytes and text bodies are their utf-8
/// byte length. JSON bodies stay `None`: the server serializes an
/// insertion-order value, so the wire length cannot be reproduced from the
/// decoded fixture value offline.
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

/// Custody rule for one pinned tuple's `Content-Length`: a 204 must have an
/// empty body and omit the header. Otherwise at most one header is accepted;
/// when the wire body length is derivable its value must match. A literal on
/// a JSON-body tuple is refused because the wire length cannot be reproduced.
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
        return if declared.is_empty() {
            Ok(())
        } else {
            Err(fail(
                "204 response must not carry Content-Length".to_owned(),
            ))
        };
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

fn validate_fixture(fixture: &Fixture, path: &Path) -> Result<(), LoadError> {
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

    // The replayed body must itself be a valid single or batch JSON-RPC
    // request, and the derived method names must equal `request.methods`
    // exactly. Malformed bytes are only accepted for the parse-error case:
    // an HTTP 500 capture with an empty derived method list.
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

    let provenance = &fixture.provenance;
    if provenance.core_version != PINNED_CORE_VERSION {
        return Err(LoadError::Violation(format!(
            "{}: pinned version {:?} is not {PINNED_CORE_VERSION}",
            path.display(),
            provenance.core_version
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
    if provenance.core_binary_sha256 != PINNED_CORE_SHA256 {
        return Err(LoadError::Violation(format!(
            "{}: pinned binary digest does not match the audited Core 31.1 build",
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

/// Every header name on the pinned side (current for a known gap, core for
/// an exact relation) must be classified exactly once; exact and volatile
/// names must be present on the pinned side, and gap names are only legal
/// on known-gap fixtures and must be declared in `gap_paths`.
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
        // `Content-Length` is owned by the derived body_length invariant:
        // classifying it again as exact, volatile or gap would be stale
        // dual ownership.
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
            if pinned
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

/// Every key of every pinned result must be classified exactly once across
/// the five classes, gap keys are only legal on known-gap fixtures, and no
/// two classes may claim the same key.
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
                    // A gap key is exactly a position where the live node
                    // answers differently from Core (a different value, or a
                    // member Core omits): the pinned current tuple must carry
                    // the live shape, and the divergence must be real.
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
                    let Some(core_value) = result_object.get(key.as_str()) else {
                        // Core omits the member entirely while this node
                        // answers: a real divergence at this path.
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
                if !result_object.contains_key(key.as_str()) {
                    return Err(fail(format!(
                        "result key {key:?} is classified {class:?} but the pinned Core result \
                         does not carry it"
                    )));
                }
            }
        }
        for key in result_object.keys() {
            if !claimed.contains_key(key.as_str()) {
                return Err(fail(format!(
                    "pinned Core result key {key:?} is not classified exactly once"
                )));
            }
        }
    }
    Ok(())
}

/// Parses a replayed request body and derives the JSON-RPC method names it
/// carries, in request order: one for a single request object, one per
/// element for a batch array. Malformed bytes are refused unless the case is
/// the parse-error capture (`status` 500), the only sanctioned malformed
/// path.
fn derive_request_methods(body: &str, status: u16) -> Result<Vec<String>, String> {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(request)) => Ok(vec![request_method(&request, "request")?]),
        Ok(serde_json::Value::Array(requests)) => {
            let mut methods = Vec::with_capacity(requests.len());
            for (index, request) in requests.iter().enumerate() {
                let serde_json::Value::Object(request) = request else {
                    return Err(format!(
                        "batch element {index} is not a JSON-RPC request object"
                    ));
                };
                methods.push(request_method(request, &format!("batch element {index}"))?);
            }
            Ok(methods)
        }
        Ok(_) => Err("request body must be a JSON-RPC object or a batch array".to_owned()),
        Err(_) if status == 500 => Ok(Vec::new()),
        Err(_) => Err(
            "request body is not valid JSON; only the parse-error case may send malformed              bytes"
                .to_owned(),
        ),
    }
}

/// Extracts the `method` member of one request object.
fn request_method(
    request: &serde_json::Map<String, serde_json::Value>,
    what: &str,
) -> Result<String, String> {
    let Some(method) = request.get("method") else {
        return Err(format!("{what} carries no method member"));
    };
    let Some(method) = method.as_str() else {
        return Err(format!("{what} method member is not a string"));
    };
    Ok(method.to_owned())
}

/// Resolves the pinned current-tuple result value for one batch element (or
/// the single envelope when the body is not a batch).
fn pinned_current_result(fixture: &Fixture, envelope_index: usize) -> Option<&serde_json::Value> {
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
    use serde_json::Value;

    use super::load_corpus_from;

    const FIXTURE_NAME: &str = "01_getblockchaininfo_v2_positional.json";
    const CAPTURED_FIXTURE: &str =
        include_str!("../corpus/core-31.1/01_getblockchaininfo_v2_positional.json");

    fn captured_fixture() -> Result<Value, serde_json::Error> {
        serde_json::from_str(CAPTURED_FIXTURE)
    }

    fn assert_reference_rejected(
        fixture: &Value,
        reason: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join(FIXTURE_NAME), serde_json::to_vec(fixture)?)?;
        let Err(error) = load_corpus_from(dir.path()) else {
            return Err("invalid Core reference was accepted".into());
        };
        let message = error.to_string();
        assert!(message.contains(FIXTURE_NAME), "{message}");
        assert!(message.contains(reason), "expected {reason:?}: {message}");
        Ok(())
    }

    /// API-07: the control uses the same directory loader as each refusal.
    #[test]
    fn copied_fixture_preserves_core_reference() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let fixture = captured_fixture()?;
        std::fs::write(dir.path().join(FIXTURE_NAME), serde_json::to_vec(&fixture)?)?;
        let corpus = load_corpus_from(dir.path())?;
        assert_eq!(corpus.len(), 1);
        Ok(())
    }

    /// API-07: absent identities cannot silently acquire default values.
    #[test]
    fn corpus_rejects_missing_core_reference_fields() -> Result<(), Box<dyn std::error::Error>> {
        for field in ["core_version", "core_binary_sha256"] {
            let mut fixture = captured_fixture()?;
            fixture["provenance"]
                .as_object_mut()
                .ok_or("captured provenance must be an object")?
                .remove(field);
            assert_reference_rejected(&fixture, &format!("missing field `{field}`"))?;
        }
        Ok(())
    }

    /// API-07: a release or kernel version cannot relabel an old capture.
    #[test]
    fn corpus_rejects_stale_or_empty_core_version() -> Result<(), Box<dyn std::error::Error>> {
        for version in ["31.0.0", "31.99.0", ""] {
            let mut fixture = captured_fixture()?;
            fixture["provenance"]["core_version"] = Value::from(version);
            assert_reference_rejected(&fixture, "pinned version")?;
        }
        Ok(())
    }

    /// API-07: even a well-formed, one-nibble digest change must be refused.
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
}
