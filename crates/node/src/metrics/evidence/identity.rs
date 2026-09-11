use alloc::string::String;
use alloc::vec::Vec;

use anyhow::Result;

use super::digest::Sha256Hex;

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
