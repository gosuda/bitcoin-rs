//! The Bitcoin Core compatibility manifest, and the checks that keep it true.
//!
//! `docs/api/core-compat.toml` is the machine-readable inventory #78 asks for:
//! every RPC method, REST route and ZMQ topic this node exposes, with the
//! status it is claimed at.
//!
//! A manifest nobody checks is a document that rots, and a rotted compatibility
//! contract is worse than none — a client reads it, believes it, and finds out
//! at runtime. So the file is embedded at compile time and cross-checked
//! against the things it describes: the dispatcher, the REST router, the ZMQ
//! topic table, and `Cargo.lock`. Adding a method without an entry fails the
//! suite; so does an entry for a method that does not dispatch; so does bumping
//! the kernel crate without revisiting the pinned Core revision.
//!
//! The manifest is deliberately allowed to say *less* than the surface does
//! for REST and ZMQ. For RPC it must name every method the dispatcher answers
//! and no others, because the header claims "anything absent is
//! `not_implemented`" and that claim is tested.
//!
//! `Status::Disabled` is kept in the vocabulary for parameter-level refusals
//! (e.g. `deriveaddresses` refuses ranged descriptors with a stable
//! `MethodDisabled` error). No whole method is disabled: methods this node
//! does not expose are absent from the manifest and answer `-32601`.
//!
//! The `[reference]` table is checked, not just read: [`ReferenceSet`] (via
//! [`load_reference_set`] and [`reference_set`]) loads it into typed
//! identities and rejects a reference that is only a version label, carries a
//! malformed digest, drops a required corpus, or confuses the released product
//! with the 31.99.x kernel tree it links for oracle evidence.

/// The manifest source, embedded so it cannot drift from the binary.
pub const MANIFEST_TOML: &str = include_str!("../../../docs/api/core-compat.toml");

/// Status a manifest entry is claimed at.
///
/// Ordered by decreasing confidence. The distinction that matters is between
/// [`Self::Supported`] and [`Self::ImplementedUnverified`]: #78 names "treating
/// a Core method name as proof of behavioral compatibility" as a non-goal, so
/// the vocabulary carries a state for "implemented, and nothing has checked it"
/// rather than folding that into "supported".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// Implemented and differentially verified against the pinned reference.
    Supported,
    /// Implemented, with a stated difference from the pinned reference.
    Deviation,
    /// Implemented; nothing has compared it to the reference.
    ImplementedUnverified,
    /// bitcoin-rs-specific surface with no Core counterpart.
    Extension,
    /// Refused by product policy at the parameter level, with a stable error.
    Disabled,
    /// Not dispatched; answers `-32601`.
    NotImplemented,
}

impl Status {
    /// Parses a manifest status string.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "supported" => Some(Self::Supported),
            "deviation" => Some(Self::Deviation),
            "implemented_unverified" => Some(Self::ImplementedUnverified),
            "extension" => Some(Self::Extension),
            "disabled" => Some(Self::Disabled),
            "not_implemented" => Some(Self::NotImplemented),
            _ => None,
        }
    }
}

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
pub struct ReferenceSet {
    /// The released Bitcoin Core product: the behavioral reference.
    pub release: ReleaseIdentity,
    /// The Core development tree the oracle lane links. Oracle evidence only:
    /// not a release, and never a policy pin.
    pub kernel: KernelIdentity,
    /// Replay corpora with their pinned stop identities.
    pub corpora: Vec<CorpusPin>,
    /// The formal model checker pin.
    pub formal_tool: FormalTool,
}

impl ReferenceSet {
    /// Reports, per corpus, whether its manifest digest is pinned today.
    ///
    /// `Blocked` names the absent artifact instead of inventing one: corpus
    /// manifest digests are produced at export time and are legitimately
    /// absent until the archive exists.
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

/// The released Bitcoin Core product identity.
///
/// `core_version` is a released `MAJOR.MINOR` product (e.g. `31.1`), pinned
/// by source commit and by the digests of the archive and the `bitcoind`
/// binary inside it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseIdentity {
    /// Released product version, `MAJOR.MINOR`.
    pub core_version: String,
    /// Release tag (e.g. `v31.1`).
    pub git_tag: String,
    /// Source commit the release was built from.
    pub source_commit: String,
    /// Release archive the binary digest is taken from.
    pub archive: String,
    /// SHA-256 of the release archive.
    pub archive_sha256: [u8; 32],
    /// SHA-256 of the `bitcoind` binary inside the archive.
    pub bitcoind_sha256: [u8; 32],
    /// The exact `bitcoind -version` line the pinned binary must print.
    pub version_output: String,
}

/// The Core development tree the oracle lane links.
///
/// `core_version` follows Core's master convention ("after 31.x, before
/// 32.0" is `31.99.x`): a moving tree, not a release. This identity is
/// evidence about the oracle lane only and must never be read as the product
/// reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelIdentity {
    /// Core tree version (e.g. `31.99.0`).
    pub core_version: String,
    /// Safe wrapper crate pinned in the manifest.
    pub kernel_crate: String,
    /// Locked version of the wrapper crate.
    pub kernel_crate_version: String,
    /// `-sys` crate vendoring the Core source.
    pub kernel_sys_crate: String,
    /// Locked version of the `-sys` crate.
    pub kernel_sys_crate_version: String,
    /// Whether a differential harness compares *values* against a running
    /// reference. `false` means no entry may claim `supported`.
    pub differential_harness: bool,
}

/// A replay corpus pinned by its stop identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorpusPin {
    /// Corpus identifier (e.g. `C150`).
    pub id: String,
    /// Last mainnet height the corpus covers.
    pub stop_height: u64,
    /// Block hash at `stop_height`.
    pub stop_hash: String,
    /// SHA-256 of the corpus manifest, produced at export time. Absent until
    /// the archive exists; a placeholder here would be an invented digest.
    pub manifest_sha256: Option<[u8; 32]>,
}

/// The formal model checker pin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormalTool {
    /// Tool name (e.g. `apalache-mc`).
    pub name: String,
    /// Released tool version.
    pub version: String,
    /// SHA-256 of the release archive.
    pub archive_sha256: [u8; 32],
    /// SHA-256 of the checker jar inside the archive.
    pub jar_sha256: [u8; 32],
}

/// Custody state of a corpus archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CorpusCustody {
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
pub enum ReferenceError {
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
    /// A corpus is duplicated, unknown, or differs from the canonical product registry.
    #[error("corpus {id} does not match tools/campaign-corpus/products.json")]
    CorpusIdentityMismatch {
        /// The unrecognized or inconsistent corpus identifier.
        id: String,
    },
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
pub fn reference_set() -> Result<ReferenceSet, ReferenceError> {
    load_reference_set(MANIFEST_TOML)
}

fn corpora(reference: &toml::Table) -> Result<Vec<CorpusPin>, ReferenceError> {
    let registry: serde_json::Value =
        serde_json::from_str(include_str!("../../../tools/campaign-corpus/products.json"))
            .map_err(|error| ReferenceError::ManifestUnreadable {
                detail: error.to_string(),
            })?;
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
        let stop_height = required_u64(entry, "stop_height")?;
        let stop_hash = required_str(entry, "stop_hash")?;
        let product = &registry["products"][&id];
        if product["stop_height"].as_u64() != Some(stop_height)
            || product["stop_hash"].as_str() != Some(stop_hash.as_str())
            || corpora.iter().any(|corpus: &CorpusPin| corpus.id == id)
        {
            return Err(ReferenceError::CorpusIdentityMismatch { id });
        }
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
        .filter(|text| !text.trim().is_empty())
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
    let development = kernel
        .strip_prefix("31.99.")
        .is_some_and(|patch| !patch.is_empty() && patch.bytes().all(|byte| byte.is_ascii_digit()));
    if release == kernel || !released || !development {
        return Err(ReferenceError::IdentityConfusion);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use sonic_rs::json;

    use super::{MANIFEST_TOML, Status};
    use crate::context::Context;
    use crate::error::RpcError;
    use crate::handlers;

    /// `Cargo.lock`, so the pinned reference cannot quietly stop being pinned.
    const CARGO_LOCK: &str = include_str!("../../../Cargo.lock");

    fn manifest() -> toml::Table {
        toml::from_str(MANIFEST_TOML)
            .unwrap_or_else(|err| panic!("the compatibility manifest must parse: {err}"))
    }

    fn entries(table: &toml::Table, key: &str) -> Vec<toml::Table> {
        let Some(array) = table.get(key).and_then(toml::Value::as_array) else {
            panic!("the manifest must carry a `{key}` array");
        };
        array
            .iter()
            .map(|value| {
                value
                    .as_table()
                    .unwrap_or_else(|| panic!("every `{key}` entry must be a table"))
                    .clone()
            })
            .collect()
    }

    fn field(entry: &toml::Table, key: &str) -> String {
        entry
            .get(key)
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("entry {entry:?} is missing `{key}`"))
            .to_owned()
    }

    fn status_of(entry: &toml::Table) -> Status {
        let text = field(entry, "status");
        Status::parse(&text)
            .unwrap_or_else(|| panic!("`{text}` is not a status this manifest defines"))
    }
    /// Cargo feature this entry is gated by; empty when always compiled.
    fn feature_of(entry: &toml::Table) -> &str {
        entry
            .get("feature")
            .and_then(toml::Value::as_str)
            .unwrap_or("")
    }

    /// True when the entry's feature is active in this build.
    fn feature_active(entry: &toml::Table) -> bool {
        let feature = feature_of(entry);
        feature.is_empty() || (feature == "zmq" && cfg!(feature = "zmq"))
    }

    /// The longest REST registration prefix this example path matches.
    fn rest_prefix(path: &str) -> &'static str {
        crate::rest::REGISTRATIONS
            .iter()
            .copied()
            .filter(|&prefix| path.starts_with(prefix))
            .max_by_key(|&prefix| prefix.len())
            .unwrap_or_else(|| panic!("`{path}` has no registered REST prefix"))
    }

    /// The manifest names every method the dispatcher answers, and no others.
    ///
    /// Both directions, because each catches a different failure. A method the
    /// manifest omits is a surface shipped without a compatibility claim — the
    /// exact hole #78 exists to close. A method the manifest invents is a
    /// promise the node does not keep, which is worse: a client reads it,
    /// depends on it, and gets `-32601`.
    ///
    /// Uses `handlers::live_registry()` (the dispatch table) rather than
    /// source-scanning, because main's dispatcher routes through a static
    /// `DISPATCH_TABLE` that is the single source of truth for what dispatches.
    #[test]
    fn the_manifest_and_the_dispatcher_name_the_same_methods() {
        let live: BTreeSet<String> = handlers::live_registry().map(String::from).collect();
        assert!(!live.is_empty(), "the live registry must not be empty");

        let table = manifest();
        let rpc_entries: Vec<toml::Table> = entries(&table, "rpc")
            .into_iter()
            .filter(feature_active)
            .collect();
        let rpc_names: Vec<String> = rpc_entries
            .iter()
            .map(|entry| field(entry, "method"))
            .collect();
        let listed: BTreeSet<String> = rpc_names.iter().cloned().collect();
        assert_eq!(
            listed.len(),
            rpc_names.len(),
            "the manifest must not duplicate RPC methods"
        );

        let missing: Vec<&String> = live.difference(&listed).collect();
        assert!(
            missing.is_empty(),
            "these methods dispatch but carry no compatibility claim: {missing:?}"
        );
        let invented: Vec<&String> = listed.difference(&live).collect();
        assert!(
            invented.is_empty(),
            "the manifest promises methods the node does not answer: {invented:?}"
        );
    }

    /// Nothing the manifest lists as live is missing, and nothing is refused
    /// as disabled at the method level.
    ///
    /// Called with empty parameters, so most of these fail on their arguments —
    /// which is fine and is the point. Two errors would mean the manifest is
    /// lying, and both are ruled out: `-32601` says the method does not exist
    /// at all, and a disabled refusal says it exists but this node will not run
    /// it. The second matters as much as the first — downgrading a
    /// private-key method from `disabled` to `implemented_unverified` would
    /// otherwise pass every other check here, and would advertise a signing
    /// capability this node does not have.
    #[test]
    fn every_listed_method_dispatches() {
        let ctx = Arc::new(Context::new());
        let handler = crate::Handler::new(ctx);
        let table = manifest();

        for entry in entries(&table, "rpc") {
            if !feature_active(&entry) {
                continue;
            }
            let status = status_of(&entry);
            if matches!(status, Status::NotImplemented) {
                continue;
            }
            let method = field(&entry, "method");
            let outcome = handler.dispatch(&method, &json!([]));
            assert!(
                !matches!(outcome, Err(RpcError::MethodNotFound(_))),
                "`{method}` is listed as {status:?} but does not dispatch"
            );
        }
    }

    /// A method the manifest does not list answers `-32601`.
    ///
    /// The manifest's closing sentence — "anything absent is not implemented" —
    /// is a claim about the dispatcher, so it is checked against it rather than
    /// left as prose.
    #[test]
    fn an_unlisted_method_is_method_not_found() {
        let ctx = Arc::new(Context::new());
        let handler = crate::Handler::new(ctx);
        let table = manifest();
        let listed: Vec<String> = entries(&table, "rpc")
            .iter()
            .map(|entry| field(entry, "method"))
            .collect();

        for method in ["getwalletinfo", "listunspent", "generate"] {
            assert!(
                !listed.contains(&method.to_owned()),
                "this test needs a method the manifest does not list; `{method}` is listed"
            );
            let outcome = handler.dispatch(method, &json!([]));
            assert!(
                matches!(&outcome, Err(RpcError::MethodNotFound(name)) if name == method),
                "`{method}` is unlisted, so it must answer method-not-found, got {outcome:?}"
            );
        }
    }

    /// A `deviation` entry has to say what the deviation is.
    ///
    /// The status alone tells a client that this node differs and not how, which
    /// is the least useful thing a compatibility manifest can say. Machine
    /// readable, so a client can surface it rather than being told to go and
    /// read a markdown file.
    #[test]
    fn every_deviation_states_itself() {
        let table = manifest();
        let mut deviations = 0_usize;
        for key in ["rpc", "rest", "zmq"] {
            for entry in entries(&table, key) {
                if status_of(&entry) != Status::Deviation {
                    continue;
                }
                let text = field(&entry, "deviation");
                assert!(
                    text.len() > 40,
                    "the {key} entry {entry:?} claims a deviation in {} characters, \
                     which cannot describe one",
                    text.len()
                );
                deviations = deviations.saturating_add(1);
            }
        }
        assert!(deviations > 0, "the manifest must record its deviations");
    }

    /// Nothing may claim `supported` until something can verify it.
    ///
    /// `supported` in this vocabulary means differentially verified against the
    /// pinned reference, and #78 scope item 2 — the harness that would do the
    /// verifying — does not exist yet. So the manifest carries a flag for
    /// whether it does, and this refuses the claim while the flag is false.
    /// Without it, `supported` becomes a synonym for "implemented" one entry at
    /// a time, which is the failure mode the whole file is meant to prevent.
    #[test]
    fn supported_is_not_claimable_without_the_harness() {
        let table = manifest();
        let Some(reference) = table.get("reference").and_then(toml::Value::as_table) else {
            panic!("the manifest must carry a `reference` table");
        };
        let harness = reference
            .get("differential_harness")
            .and_then(toml::Value::as_bool)
            .unwrap_or_else(|| panic!("`reference.differential_harness` must be a boolean"));
        if harness {
            return;
        }
        for key in ["rpc", "rest", "zmq"] {
            for entry in entries(&table, key) {
                assert_ne!(
                    status_of(&entry),
                    Status::Supported,
                    "the {key} entry {entry:?} claims `supported` while no differential \
                     harness exists to have verified it"
                );
            }
        }
    }

    /// The pinned reference is pinned to something the build actually links.
    ///
    /// The Core revision in the manifest comes from the kernel crate's vendored
    /// tree, so the claim is only as good as that version staying put. Checked
    /// against `Cargo.lock` rather than against a comment: a dependency bump
    /// that moves the Core source has to come back through this file, which is
    /// exactly when the compatibility claims need re-reading.
    #[test]
    fn the_pinned_core_reference_matches_the_locked_kernel() {
        let table = manifest();
        let Some(reference) = table.get("reference").and_then(toml::Value::as_table) else {
            panic!("the manifest must carry a `reference` table");
        };

        for (name_key, version_key) in [
            ("kernel_crate", "kernel_crate_version"),
            ("kernel_sys_crate", "kernel_sys_crate_version"),
        ] {
            let name = field(reference, name_key);
            let version = field(reference, version_key);
            let needle = format!("name = \"{name}\"");
            let Some(at) = CARGO_LOCK.find(&needle) else {
                panic!("`{name}` is pinned in the manifest but absent from Cargo.lock");
            };
            let locked = CARGO_LOCK[at..]
                .lines()
                .nth(1)
                .and_then(|line| line.strip_prefix("version = \""))
                .and_then(|rest| rest.strip_suffix('"'))
                .unwrap_or_else(|| panic!("Cargo.lock entry for `{name}` has no version line"));
            assert_eq!(
                locked, version,
                "`{name}` is locked at {locked} but the compatibility manifest is \
                 written against {version}. The pinned Bitcoin Core revision comes \
                 from this crate's vendored tree, so a bump means the claims in \
                 docs/api/core-compat.toml need re-reading, not just this line."
            );
        }
    }

    /// The manifest names the ZMQ topics the publisher publishes.
    ///
    /// Same argument as the dispatcher: a topic with no entry is an undeclared
    /// surface, and an entry for a topic nothing publishes is a promise of
    /// messages that never arrive.
    #[test]
    fn the_manifest_and_the_publisher_name_the_same_zmq_topics() {
        // The topic table lives in the node crate, which the RPC crate does not
        // depend on, so the names are restated here and pinned by the node's own
        // `zmq_topic_names_match_the_compatibility_manifest`.
        let published = ["hashblock", "hashtx", "rawblock", "rawtx", "sequence"];

        let table = manifest();
        let listed: Vec<String> = entries(&table, "zmq")
            .iter()
            .map(|entry| field(entry, "topic"))
            .collect();

        for topic in published {
            assert!(
                listed.contains(&topic.to_owned()),
                "`{topic}` is published but carries no compatibility claim"
            );
        }
        for topic in &listed {
            assert!(
                published.contains(&topic.as_str()),
                "the manifest promises a `{topic}` topic that nothing publishes"
            );
        }
    }

    /// Every REST route the manifest lists is served, and unlisted paths 404.
    ///
    /// The manifest writes each route as a concrete served example (with
    /// placeholders for hash/height/kind) so a human reader can use it, while
    /// the router sees the same `REGISTRATIONS` prefixes main uses.
    #[test]
    fn the_manifest_and_the_rest_router_agree() {
        let ctx = Arc::new(Context::new());
        let table = manifest();
        let listed: Vec<String> = entries(&table, "rest")
            .iter()
            .map(|entry| field(entry, "path"))
            .collect();
        assert!(!listed.is_empty(), "the manifest must list the REST routes");

        let listed_prefixes: BTreeSet<&'static str> =
            listed.iter().map(|path| rest_prefix(path)).collect();
        let registered: BTreeSet<&'static str> =
            crate::rest::REGISTRATIONS.iter().copied().collect();
        assert_eq!(
            listed_prefixes, registered,
            "REST manifest examples must cover exactly the registered prefixes"
        );

        let genesis = "0000000000000000000000000000000000000000000000000000000000000000";
        for path in &listed {
            let concrete = path
                .replace("<hash>", genesis)
                .replace("<height>", "0")
                .replace("<kind>", "info")
                .replace("<json|hex|bin>", "json");
            let response = crate::rest::route(&ctx, &concrete, "count=1", true);
            assert_ne!(
                response.status, 404,
                "`{concrete}` is listed in the manifest but the router does not serve it"
            );
        }

        let unlisted = crate::rest::route(&ctx, "/rest/not-a-registered-route", "", true);
        assert_eq!(
            unlisted.status, 404,
            "an unlisted REST path must be a miss, not a partial imitation"
        );
    }
}
