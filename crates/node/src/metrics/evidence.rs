//! Typed measurement identity, interval accounting, and append-only ledgers.

use anyhow::Result;

/// A SHA-256 digest carried as 64 lowercase hex characters in evidence.
///
/// A digest is bytes, not a label: a placeholder such as "unmeasured" cannot
/// parse, so an identity is either real or absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha256Hex(pub [u8; 32]);

impl Sha256Hex {
    /// Hashes `bytes` with SHA-256.
    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        use sha2::Digest as _;
        Self(sha2::Sha256::digest(bytes).into())
    }
}

impl core::fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl core::str::FromStr for Sha256Hex {
    type Err = EvidenceError;

    fn from_str(text: &str) -> Result<Self, EvidenceError> {
        let malformed = || EvidenceError::MalformedDigest(text.into());
        if text.len() != 64 {
            return Err(malformed());
        }
        let mut bytes = [0_u8; 32];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
            let text = core::str::from_utf8(pair).map_err(|_| malformed())?;
            if text.bytes().any(|c| c.is_ascii_uppercase()) {
                return Err(malformed());
            }
            *byte = u8::from_str_radix(text, 16).map_err(|_| malformed())?;
        }
        Ok(Self(bytes))
    }
}

impl serde::Serialize for Sha256Hex {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Sha256Hex {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// The corpus a measurement replayed.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusIdentity {
    /// Corpus identifier from `docs/contracts/campaign-corpora.md`.
    pub id: String,
    /// Digest of the corpus manifest.
    pub manifest_sha256: Sha256Hex,
}

/// Everything a measurement was taken under.
///
/// A number without this record is a rumor: it cannot be matched against a
/// control cell or regenerated later.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIdentity {
    /// Digest of the executable that produced the sample.
    pub binary_sha256: Sha256Hex,
    /// Crate version of that executable.
    pub version: String,
    /// Digest of the fully resolved configuration.
    pub config_sha256: Sha256Hex,
    /// Replayed corpus. A live node has none; a product cell always has one.
    pub corpus: Option<CorpusIdentity>,
    /// Storage backend that held the state.
    pub backend: String,
    /// Durability policy in force, for example `journal:500b/5s`.
    pub durability: String,
    /// Hardware the sample ran on: CPU model and logical core count.
    pub hardware: String,
}

/// CPU model and core count, the two hardware facts a matched treatment
/// must share before its numbers are comparable.
fn hardware_identity() -> String {
    let model = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|info| {
            info.lines()
                .find_map(|line| line.strip_prefix("model name"))
                .and_then(|rest| rest.split_once(':'))
                .map(|(_, model)| model.trim().to_owned())
        })
        .unwrap_or_else(|| "unknown-cpu".into());
    let cores = std::thread::available_parallelism().map_or(0, usize::from);
    format!("{model} x{cores}")
}

impl EvidenceIdentity {
    /// Identity for the running process under `config`.
    ///
    /// The digest covers the executable file on disk and the resolved
    /// configuration's debug rendering, which is the one canonical form the
    /// runtime already owns.
    pub fn of_process(config: &crate::config::NodeConfig) -> Result<Self> {
        let executable = std::env::current_exe()?;
        let binary_sha256 = Sha256Hex::digest(&std::fs::read(&executable)?);
        let journal = config.chainstate_journal;
        let durability = if journal.enabled {
            format!("journal:{}b/{}s", journal.blocks, journal.seconds)
        } else {
            "checkpoint-only".into()
        };
        Ok(Self {
            binary_sha256,
            version: env!("CARGO_PKG_VERSION").into(),
            config_sha256: Sha256Hex::digest(format!("{config:?}").as_bytes()),
            corpus: None,
            backend: config.storage.backend.as_str().into(),
            durability,
            hardware: hardware_identity(),
        })
    }

    /// The identity as Prometheus global labels.
    #[must_use]
    pub fn labels(&self) -> Vec<(&'static str, String)> {
        let mut labels = vec![
            ("binary_sha256", self.binary_sha256.to_string()),
            ("version", self.version.clone()),
            ("config_sha256", self.config_sha256.to_string()),
            ("backend", self.backend.clone()),
            ("durability", self.durability.clone()),
            ("hardware", self.hardware.clone()),
        ];
        if let Some(corpus) = &self.corpus {
            labels.push(("corpus_id", corpus.id.clone()));
            labels.push(("corpus_manifest_sha256", corpus.manifest_sha256.to_string()));
        }
        labels
    }
}

/// Where a timed interval sits relative to the measured product.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntervalKind {
    /// Inside the node process.
    Inside,
    /// Outside the node process, for example harness setup.
    Outside,
    /// A duration the domain defines without wall-clock placement.
    DomainDefined,
}

/// A half-open timed interval in nanoseconds on the run's clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interval {
    /// Placement of the interval.
    pub kind: IntervalKind,
    /// Start offset.
    pub start_ns: u64,
    /// End offset, never before the start.
    pub end_ns: u64,
}

impl Interval {
    fn check(self) -> Result<(), EvidenceError> {
        if self.end_ns < self.start_ns {
            return Err(EvidenceError::InvertedInterval(self));
        }
        Ok(())
    }

    /// True when the intervals share any instant, which covers both nesting
    /// and concurrency.
    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        self.start_ns < other.end_ns && other.start_ns < self.end_ns
    }
}

/// One measurement of one cell by one owner.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    /// Ledger path the interval measures, for example `cell.wall`.
    pub path: String,
    /// Component that owns the measured resources, for example `node`.
    pub owner: String,
    /// Identity the sample was taken under.
    pub identity: EvidenceIdentity,
    /// Timed interval the resources were consumed in.
    pub interval: Interval,
    /// CPU time consumed, when the owner measured it.
    pub cpu_ns: Option<u64>,
    /// Wall time consumed.
    pub elapsed_ns: u64,
    /// Peak resident set, when the owner measured it.
    pub rss_peak_bytes: Option<u64>,
    /// Bytes read plus written, when the owner measured it.
    pub io_bytes: Option<u64>,
    /// Physical storage held at the end of the interval, when measured.
    pub storage_bytes: Option<u64>,
}

/// Combines two optional measurements; an absent side cannot silently absorb
/// a present one, because that would collapse coverage into a number.
fn combine(
    left: Option<u64>,
    right: Option<u64>,
    join: impl Fn(u64, u64) -> Option<u64>,
) -> Result<Option<u64>, EvidenceError> {
    match (left, right) {
        (None, None) => Ok(None),
        (Some(left), Some(right)) => join(left, right).map(Some).ok_or(EvidenceError::Overflow),
        _ => Err(EvidenceError::MismatchedTreatment),
    }
}

impl Sample {
    fn check(&self) -> Result<(), EvidenceError> {
        if self.identity.corpus.is_none() {
            return Err(EvidenceError::MissingCorpus);
        }
        self.interval.check()
    }

    /// Adds two disjoint samples of the same owner and identity.
    ///
    /// Nested and concurrent intervals share instants, so their resources
    /// were consumed once and cannot be added; extrema take the maximum.
    pub fn sum(&self, other: &Self) -> Result<Self, EvidenceError> {
        if self.path != other.path || self.owner != other.owner || self.identity != other.identity {
            return Err(EvidenceError::MismatchedTreatment);
        }
        if self.interval.overlaps(other.interval) {
            return Err(EvidenceError::OverlappingIntervals(
                self.interval,
                other.interval,
            ));
        }
        Ok(Self {
            path: self.path.clone(),
            owner: self.owner.clone(),
            identity: self.identity.clone(),
            interval: Interval {
                kind: self.interval.kind,
                start_ns: self.interval.start_ns.min(other.interval.start_ns),
                end_ns: self.interval.end_ns.max(other.interval.end_ns),
            },
            cpu_ns: combine(self.cpu_ns, other.cpu_ns, u64::checked_add)?,
            elapsed_ns: self
                .elapsed_ns
                .checked_add(other.elapsed_ns)
                .ok_or(EvidenceError::Overflow)?,
            rss_peak_bytes: combine(self.rss_peak_bytes, other.rss_peak_bytes, |a, b| {
                Some(a.max(b))
            })?,
            io_bytes: combine(self.io_bytes, other.io_bytes, u64::checked_add)?,
            storage_bytes: combine(self.storage_bytes, other.storage_bytes, |a, b| {
                Some(a.max(b))
            })?,
        })
    }
}

/// One product cell and every sample ever recorded for it.
///
/// An empty history is the honest state of an unmeasured cell; it is kept,
/// never dropped or defaulted.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    /// Cell identifier from the ledger matrix.
    pub id: String,
    /// Append-only sample history.
    pub samples: Vec<Sample>,
}

/// Schema tag every ledger and evidence file must carry.
pub const LEDGER_SCHEMA: &str = "bitcoin-rs-hot-path-ledger-v2";

/// The cell histories of `docs/benchmarks/hot-path-ledger.toml`.
///
/// Other top-level tables of that file belong to the attribution contract and
/// pass through untouched; this type owns only what a run may append to.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Ledger {
    /// Must equal [`LEDGER_SCHEMA`].
    pub schema: String,
    /// Every declared cell, measured or not.
    pub cells: Vec<Cell>,
    /// Top-level attribution-contract tables owned outside the benchmark tool.
    #[serde(flatten)]
    pub contract: std::collections::BTreeMap<String, toml::Value>,
}

impl Ledger {
    /// Parses ledger TOML and rejects any sample that lacks a full identity.
    pub fn parse(text: &str) -> Result<Self, EvidenceError> {
        let ledger: Self =
            toml::from_str(text).map_err(|error| EvidenceError::Schema(error.to_string()))?;
        if ledger.schema != LEDGER_SCHEMA {
            return Err(EvidenceError::Schema(format!(
                "schema {} is not {LEDGER_SCHEMA}",
                ledger.schema
            )));
        }
        for cell in &ledger.cells {
            for sample in &cell.samples {
                sample.check()?;
            }
        }
        Ok(ledger)
    }

    /// Appends a sample to a declared cell. Repeats are kept: a second run is
    /// evidence, not a correction.
    pub fn record(&mut self, cell: &str, sample: Sample) -> Result<(), EvidenceError> {
        sample.check()?;
        let cell = self
            .cells
            .iter_mut()
            .find(|candidate| candidate.id == cell)
            .ok_or_else(|| EvidenceError::UnknownCell(cell.into()))?;
        cell.samples.push(sample);
        Ok(())
    }

    /// Renders the ledger as TOML.
    pub fn render(&self) -> Result<String, EvidenceError> {
        toml::to_string(self).map_err(|error| EvidenceError::Schema(error.to_string()))
    }
}

/// Why evidence was refused.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum EvidenceError {
    /// A digest was not 64 lowercase hex characters.
    #[error("digest {0:?} is not 64 lowercase hex characters")]
    MalformedDigest(String),
    /// The ledger text did not match the schema.
    #[error("ledger schema: {0}")]
    Schema(String),
    /// A product sample named no corpus.
    #[error("product sample carries no corpus identity")]
    MissingCorpus,
    /// An interval ended before it started.
    #[error("interval {0:?} ends before it starts")]
    InvertedInterval(Interval),
    /// The two samples were not taken under one treatment.
    #[error("samples differ in path, owner or identity")]
    MismatchedTreatment,
    /// The two intervals share instants.
    #[error("intervals {0:?} and {1:?} overlap; nested or concurrent work is not an addend")]
    OverlappingIntervals(Interval, Interval),
    /// A summed counter exceeded `u64`.
    #[error("summed measurement overflows u64")]
    Overflow,
    /// The cell is not declared in the ledger.
    #[error("cell {0:?} is not declared in the ledger")]
    UnknownCell(String),
}
