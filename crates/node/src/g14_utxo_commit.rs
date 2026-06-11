//! G14 UTXO commit timing sample emission for applied-block evidence.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail, ensure};
use bitcoin_rs_primitives::Hash256;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct G14UtxoCommitSample {
    height: u32,
    block_hash: String,
    block_size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    utxo_commit_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    utxo_commit_ms: Option<f64>,
}

type Samples = BTreeMap<u32, G14UtxoCommitSample>;

pub(crate) struct G14UtxoCommitSampler {
    path: PathBuf,
    ibd_start_height: u32,
    ibd_stop_height: u32,
    ibd_start_hash: String,
    ibd_stop_hash: String,
    state: Mutex<G14UtxoCommitSamplerState>,
}

#[derive(Default)]
struct G14UtxoCommitSamplerState {
    samples: Samples,
}

impl G14UtxoCommitSampler {
    pub(crate) fn open(
        path: impl Into<PathBuf>,
        ibd_start_height: u32,
        ibd_stop_height: u32,
        ibd_start_hash: String,
        ibd_stop_hash: String,
    ) -> Result<Self> {
        ensure!(
            ibd_stop_height >= ibd_start_height,
            "g14_utxo_commit_ibd_stop_height must be greater than or equal to g14_utxo_commit_ibd_start_height"
        );
        validate_block_hash(&ibd_start_hash, "g14_utxo_commit_ibd_start_hash")?;
        validate_block_hash(&ibd_stop_hash, "g14_utxo_commit_ibd_stop_hash")?;
        let path = path.into();
        let samples = load_validated_samples(
            &path,
            ibd_start_height,
            ibd_stop_height,
            &ibd_start_hash,
            &ibd_stop_hash,
        )?;
        Ok(Self {
            path,
            ibd_start_height,
            ibd_stop_height,
            ibd_start_hash,
            ibd_stop_hash,
            state: Mutex::new(G14UtxoCommitSamplerState { samples }),
        })
    }

    pub(crate) fn wants_height(&self, height: u32) -> bool {
        (self.ibd_start_height..=self.ibd_stop_height).contains(&height)
    }

    pub(crate) fn record(
        &self,
        height: u32,
        block_hash: Hash256,
        block_size_bytes: usize,
        utxo_commit_dur: Duration,
    ) -> Result<()> {
        if !self.wants_height(height) {
            return Ok(());
        }
        let block_hash = block_hash.to_string_be();
        self.validate_bound_hash(height, &block_hash)?;
        let block_size_bytes = u64::try_from(block_size_bytes)
            .with_context(|| format!("block_size_bytes overflow at height {height}"))?;
        let utxo_commit_us = u64::try_from(utxo_commit_dur.as_micros())
            .with_context(|| format!("utxo_commit_us overflow at height {height}"))
            .map(|micros| micros.max(1))?;
        let sample = G14UtxoCommitSample {
            height,
            block_hash,
            block_size_bytes,
            utxo_commit_us: Some(utxo_commit_us),
            utxo_commit_ms: None,
        };
        self.record_sample(sample)
    }

    fn validate_bound_hash(&self, height: u32, block_hash: &str) -> Result<()> {
        if height == self.ibd_start_height {
            ensure!(
                block_hash == self.ibd_start_hash,
                "G14 UTXO commit sample at start height {height} has hash {block_hash}, expected {}",
                self.ibd_start_hash
            );
        }
        if height == self.ibd_stop_height {
            ensure!(
                block_hash == self.ibd_stop_hash,
                "G14 UTXO commit sample at stop height {height} has hash {block_hash}, expected {}",
                self.ibd_stop_hash
            );
        }
        Ok(())
    }

    fn record_sample(&self, sample: G14UtxoCommitSample) -> Result<()> {
        let height = sample.height;
        let mut state = self.state.lock();
        if let Some(existing) = state.samples.get(&height) {
            ensure!(
                existing == &sample,
                "G14 UTXO commit sample height {height} changed"
            );
            return Ok(());
        }
        validate_sample(
            &sample,
            self.ibd_start_height,
            self.ibd_stop_height,
            &self.ibd_start_hash,
            &self.ibd_stop_hash,
        )?;
        state.samples.insert(height, sample);
        if height == self.ibd_stop_height {
            validate_samples(
                &state.samples,
                self.ibd_start_height,
                self.ibd_stop_height,
                &self.ibd_start_hash,
                &self.ibd_stop_hash,
            )?;
            write_samples(&self.path, &state.samples)?;
        }
        Ok(())
    }
}

fn validate_block_hash(value: &str, name: &str) -> Result<()> {
    ensure!(
        is_lower_hex_hash(value),
        "{name} must be 64 lowercase hex characters"
    );
    Ok(())
}

fn validate_samples(
    samples: &Samples,
    ibd_start_height: u32,
    ibd_stop_height: u32,
    ibd_start_hash: &str,
    ibd_stop_hash: &str,
) -> Result<()> {
    for (height, sample) in samples {
        ensure!(
            *height == sample.height,
            "G14 UTXO commit sample map key {height} must match sample height {}",
            sample.height
        );
        validate_sample(
            sample,
            ibd_start_height,
            ibd_stop_height,
            ibd_start_hash,
            ibd_stop_hash,
        )?;
    }
    Ok(())
}

fn validate_sample(
    sample: &G14UtxoCommitSample,
    ibd_start_height: u32,
    ibd_stop_height: u32,
    ibd_start_hash: &str,
    ibd_stop_hash: &str,
) -> Result<()> {
    let height = sample.height;
    ensure!(
        height >= ibd_start_height && height <= ibd_stop_height,
        "G14 UTXO commit sample height {height} is outside configured IBD window [{ibd_start_height}, {ibd_stop_height}]"
    );
    validate_block_hash(&sample.block_hash, "sample block_hash")?;
    if height == ibd_start_height {
        ensure!(
            sample.block_hash == ibd_start_hash,
            "G14 UTXO commit sample at start height {height} has hash {}, expected {ibd_start_hash}",
            sample.block_hash
        );
    }
    if height == ibd_stop_height {
        ensure!(
            sample.block_hash == ibd_stop_hash,
            "G14 UTXO commit sample at stop height {height} has hash {}, expected {ibd_stop_hash}",
            sample.block_hash
        );
    }
    if sample.utxo_commit_us.is_some() && sample.utxo_commit_ms.is_some() {
        bail!(
            "G14 UTXO commit sample at height {height} must not include both utxo_commit_us and utxo_commit_ms"
        );
    }
    if let Some(us) = sample.utxo_commit_us {
        ensure!(us > 0, "utxo_commit_us must be positive at height {height}");
    }
    if let Some(ms) = sample.utxo_commit_ms {
        ensure!(
            ms.is_finite() && ms > 0.0,
            "utxo_commit_ms must be finite and positive at height {height}"
        );
    }
    if sample.utxo_commit_us.is_none() && sample.utxo_commit_ms.is_none() {
        bail!(
            "G14 UTXO commit sample at height {height} must include utxo_commit_us or utxo_commit_ms"
        );
    }
    Ok(())
}

fn parent_dir(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn prepare_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = parent_dir(path) {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "create G14 UTXO commit sample directory {}",
                parent.display()
            )
        })?;
    }
    Ok(())
}

fn load_validated_samples(
    path: &Path,
    ibd_start_height: u32,
    ibd_stop_height: u32,
    ibd_start_hash: &str,
    ibd_stop_hash: &str,
) -> Result<Samples> {
    let samples = load_samples(path)?;
    validate_samples(
        &samples,
        ibd_start_height,
        ibd_stop_height,
        ibd_start_hash,
        ibd_stop_hash,
    )?;
    Ok(samples)
}

fn load_samples(path: &Path) -> Result<Samples> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_samples(&text, path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Samples::new()),
        Err(error) => {
            Err(error).with_context(|| format!("read G14 UTXO commit samples {}", path.display()))
        }
    }
}

fn parse_samples(text: &str, path: &Path) -> Result<Samples> {
    let payload: serde_json::Value = serde_json::from_str(text)
        .with_context(|| format!("parse G14 UTXO commit samples JSON {}", path.display()))?;
    let entries = match payload {
        serde_json::Value::Array(entries) => entries,
        serde_json::Value::Object(map) => {
            let Some(serde_json::Value::Array(entries)) = map.get("samples").cloned() else {
                bail!(
                    "G14 UTXO commit samples {} must contain a samples array",
                    path.display()
                );
            };
            entries
        }
        _ => bail!(
            "G14 UTXO commit samples {} must be a JSON array or object with samples array",
            path.display()
        ),
    };
    let mut samples = Samples::new();
    for (index, entry) in entries.into_iter().enumerate() {
        let sample: G14UtxoCommitSample = serde_json::from_value(entry).with_context(|| {
            format!(
                "parse G14 UTXO commit samples[{index}] in {}",
                path.display()
            )
        })?;
        ensure!(
            samples.insert(sample.height, sample).is_none(),
            "duplicate G14 UTXO commit sample height in {}",
            path.display()
        );
    }
    Ok(samples)
}

fn write_samples(path: &Path, samples: &Samples) -> Result<()> {
    prepare_parent_dir(path)?;
    let body = serde_json::to_vec_pretty(&samples.values().collect::<Vec<&G14UtxoCommitSample>>())
        .with_context(|| format!("encode G14 UTXO commit samples {}", path.display()))?;
    let tmp = temp_path(path, "samples");
    {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
            .with_context(|| format!("open tmp G14 UTXO commit samples {}", tmp.display()))?;
        std::io::Write::write_all(&mut file, &body)
            .with_context(|| format!("write tmp G14 UTXO commit samples {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("fsync tmp G14 UTXO commit samples {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("atomic rename G14 UTXO commit samples {}", path.display()))?;
    if let Some(parent) = parent_dir(path)
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn temp_path(path: &Path, tag: &str) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map_or_else(|| OsString::from("g14-utxo.samples.json"), OsString::from);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    file_name.push(format!(".{}.{}.{}.tmp", std::process::id(), nonce, tag));
    path.with_file_name(file_name)
}

fn is_lower_hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const START_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const STOP_HASH: &str = "000000000000000000000000000000000000000000000000000000000000000a";

    fn open_sampler(path: &Path) -> Result<G14UtxoCommitSampler> {
        G14UtxoCommitSampler::open(path, 0, 10, START_HASH.to_owned(), STOP_HASH.to_owned())
    }

    #[test]
    fn writes_measurement_compatible_json() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("utxo.samples.json");
        let sampler =
            G14UtxoCommitSampler::open(&path, 0, 2, START_HASH.to_owned(), STOP_HASH.to_owned())?;
        sampler.record(
            0,
            Hash256::from_le_bytes(&[0; 32]),
            4 * 1024 * 1024,
            Duration::from_micros(10),
        )?;
        assert!(
            !path.exists(),
            "sample file must not exist before stop height"
        );
        sampler.record(
            1,
            Hash256::from_le_bytes(&[1; 32]),
            4 * 1024 * 1024,
            Duration::from_micros(11),
        )?;
        assert!(
            !path.exists(),
            "sample file must not exist before stop height"
        );
        {
            let mut stop_bytes = [0_u8; 32];
            stop_bytes[0] = 0x0a;
            sampler.record(
                2,
                Hash256::from_le_bytes(&stop_bytes),
                4 * 1024 * 1024,
                Duration::from_micros(12_500),
            )?;
        }

        let payload: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        let samples = payload
            .as_array()
            .unwrap_or_else(|| panic!("samples array"));
        assert_eq!(samples.len(), 3);
        let sample = samples
            .iter()
            .find(|entry| entry["height"] == 2)
            .unwrap_or_else(|| panic!("stop-height sample"));
        assert_eq!(sample["block_size_bytes"], 4 * 1024 * 1024);
        assert_eq!(sample["utxo_commit_us"], 12_500);
        Ok(())
    }

    #[test]
    fn rejects_window_hash_mismatch_on_open() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("utxo.samples.json");
        std::fs::write(
            &path,
            r#"[{"height":0,"block_hash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","block_size_bytes":4194304,"utxo_commit_us":1}]"#,
        )?;
        let result =
            G14UtxoCommitSampler::open(&path, 0, 10, START_HASH.to_owned(), STOP_HASH.to_owned());
        let Err(error) = result else {
            panic!("expected open failure");
        };
        assert!(error.to_string().contains("start height"));
        Ok(())
    }

    #[test]
    fn rejects_inconsistent_existing_sample() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("utxo.samples.json");
        let sampler = open_sampler(&path)?;
        sampler.record(
            1,
            Hash256::from_le_bytes(&[1; 32]),
            4 * 1024 * 1024,
            Duration::from_micros(10),
        )?;
        let error = match sampler.record(
            1,
            Hash256::from_le_bytes(&[2; 32]),
            4 * 1024 * 1024,
            Duration::from_micros(10),
        ) {
            Err(e) => e,
            Ok(()) => panic!("expected record to fail on inconsistent sample"),
        };
        assert!(error.to_string().contains("changed"));
        Ok(())
    }
}
