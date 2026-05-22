//! G2 `MuHash` sample emission for applied-block evidence.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail, ensure};
use parking_lot::Mutex;

const SAMPLE_INTERVAL: u32 = 10_000;

type Samples = BTreeMap<u32, String>;

pub(crate) struct G2MuhashSampler {
    path: PathBuf,
    target_tip_height: Option<u32>,
    state: Mutex<G2MuhashSamplerState>,
}

#[derive(Default)]
struct G2MuhashSamplerState {
    samples: Samples,
}

impl G2MuhashSampler {
    pub(crate) fn open(path: impl Into<PathBuf>, target_tip_height: Option<u32>) -> Result<Self> {
        let path = path.into();
        let samples = load_validated_samples(&path, target_tip_height)?;
        Ok(Self {
            path,
            target_tip_height,
            state: Mutex::new(G2MuhashSamplerState { samples }),
        })
    }

    pub(crate) fn record(&self, stats: &bitcoin_rs_coinstats::CoinStats) -> Result<()> {
        if !should_record(stats.height, self.target_tip_height) {
            return Ok(());
        }
        let hash = stats.muhash.finalize_hash().to_string_be();
        self.record_sample(stats.height, hash)
    }

    fn record_sample(&self, height: u32, hash: String) -> Result<()> {
        let mut state = self.state.lock();
        if let Some(existing) = state.samples.get(&height) {
            ensure!(
                existing == &hash,
                "G2 MuHash sample height {height} changed: existing {existing}, computed {hash}"
            );
            return Ok(());
        }
        let mut samples = state.samples.clone();
        samples.insert(height, hash);
        validate_samples(&samples, self.target_tip_height)?;
        write_samples(&self.path, &samples)?;
        state.samples = samples;
        Ok(())
    }
}

const fn should_sample(height: u32) -> bool {
    height.is_multiple_of(SAMPLE_INTERVAL)
}

fn should_record(height: u32, target_tip_height: Option<u32>) -> bool {
    if target_tip_height.is_some_and(|target| height > target) {
        return false;
    }
    should_sample(height) || target_tip_height == Some(height)
}

fn validate_samples(samples: &Samples, target_tip_height: Option<u32>) -> Result<()> {
    let Some(max_height) = samples.keys().next_back().copied() else {
        return Ok(());
    };

    for height in samples.keys().copied() {
        ensure!(
            sample_height_allowed(height, target_tip_height),
            "G2 MuHash sample height {height} is outside height 0, 10000-interval, and configured tip samples"
        );
        if let Some(target) = target_tip_height {
            ensure!(
                height <= target,
                "G2 MuHash sample height {height} exceeds configured tip height {target}"
            );
        }
    }

    let required_until = target_tip_height
        .filter(|target| samples.contains_key(target))
        .unwrap_or(max_height);
    let mut height = 0_u32;
    loop {
        ensure!(
            samples.contains_key(&height),
            "G2 MuHash samples missing required height {height}"
        );
        let Some(next) = height.checked_add(SAMPLE_INTERVAL) else {
            break;
        };
        if next > required_until {
            break;
        }
        height = next;
    }
    Ok(())
}

fn sample_height_allowed(height: u32, target_tip_height: Option<u32>) -> bool {
    should_sample(height) || target_tip_height == Some(height)
}

fn parent_dir(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn prepare_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = parent_dir(path) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create G2 MuHash sample directory {}", parent.display()))?;
    }
    Ok(())
}

fn load_validated_samples(path: &Path, target_tip_height: Option<u32>) -> Result<Samples> {
    let samples = load_samples(path)?;
    validate_samples(&samples, target_tip_height)?;
    Ok(samples)
}

fn load_samples(path: &Path) -> Result<Samples> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_samples(&text, path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Samples::new()),
        Err(error) => {
            Err(error).with_context(|| format!("read G2 MuHash samples {}", path.display()))
        }
    }
}

fn parse_samples(text: &str, path: &Path) -> Result<Samples> {
    let mut samples = Samples::new();
    let text = text.trim();
    if text.is_empty() {
        return Ok(samples);
    }
    for entry in text.split(',') {
        let entry = entry.trim();
        ensure!(
            !entry.is_empty(),
            "empty G2 MuHash sample in {}",
            path.display()
        );
        let Some((height_raw, hash_raw)) = entry.split_once(':') else {
            bail!(
                "G2 MuHash sample {entry:?} in {} must use height:64-lowerhex",
                path.display()
            );
        };
        let height = height_raw.trim().parse::<u32>().with_context(|| {
            format!(
                "parse G2 MuHash sample height {height_raw:?} in {}",
                path.display()
            )
        })?;
        let hash = hash_raw.trim();
        ensure!(
            is_lower_hex_hash(hash),
            "G2 MuHash sample at height {height} in {} must be 64 lowercase hex characters",
            path.display()
        );
        ensure!(
            samples.insert(height, hash.to_owned()).is_none(),
            "duplicate G2 MuHash sample height {height} in {}",
            path.display()
        );
    }
    Ok(samples)
}

fn write_samples(path: &Path, samples: &Samples) -> Result<()> {
    prepare_parent_dir(path)?;
    let tmp = temp_path(path, "samples");
    let body = samples
        .iter()
        .map(|(height, hash)| format!("{height}:{hash}"))
        .collect::<Vec<_>>()
        .join(",");

    {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
            .with_context(|| format!("open tmp G2 MuHash samples {}", tmp.display()))?;
        file.write_all(body.as_bytes())
            .with_context(|| format!("write tmp G2 MuHash samples {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("fsync tmp G2 MuHash samples {}", tmp.display()))?;
    }

    std::fs::rename(&tmp, path)
        .with_context(|| format!("atomic rename G2 MuHash samples {}", path.display()))?;
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
        .map_or_else(|| OsString::from("g2.samples"), OsString::from);
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
    use bitcoin_rs_coinstats::CoinStats;

    #[test]
    fn writes_env_compatible_interval_samples() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("g2.samples");
        let sampler = G2MuhashSampler::open(&path, None)?;

        let mut stats = CoinStats::default();
        sampler.record(&stats)?;
        stats.finish_block(1, 1);
        sampler.record(&stats)?;
        stats.finish_block(SAMPLE_INTERVAL, 1);
        sampler.record(&stats)?;

        let hash = stats.muhash.finalize_hash().to_string_be();
        let text = std::fs::read_to_string(&path)?;
        assert_eq!(text, format!("0:{hash},{SAMPLE_INTERVAL}:{hash}"));
        Ok(())
    }

    #[test]
    fn writes_configured_tip_sample() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("g2.samples");
        let sampler = G2MuhashSampler::open(&path, Some(2))?;
        let hash = CoinStats::default().muhash.finalize_hash().to_string_be();

        let mut stats = CoinStats::default();
        sampler.record(&stats)?;
        stats.finish_block(1, 1);
        sampler.record(&stats)?;
        assert_eq!(std::fs::read_to_string(&path)?, format!("0:{hash}"));

        stats.finish_block(2, 1);
        sampler.record(&stats)?;
        assert_eq!(
            std::fs::read_to_string(&path)?,
            format!("0:{hash},2:{hash}")
        );
        Ok(())
    }

    #[test]
    fn opens_bare_relative_sample_path() -> Result<()> {
        static CWD_LOCK: std::sync::LazyLock<Mutex<()>> =
            std::sync::LazyLock::new(|| Mutex::new(()));

        let _guard = CWD_LOCK.lock();
        let dir = tempfile::tempdir()?;
        let previous = std::env::current_dir()?;
        std::env::set_current_dir(dir.path())?;
        let open_result = G2MuhashSampler::open(PathBuf::from("g2.samples"), None);
        let restore_result = std::env::set_current_dir(previous);
        restore_result?;
        let _sampler = open_result?;

        assert!(!dir.path().join("g2.samples").exists());
        Ok(())
    }

    #[test]
    fn rejects_non_contract_sample_height() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("g2.samples");
        let hash = CoinStats::default().muhash.finalize_hash().to_string_be();
        std::fs::write(&path, format!("0:{hash},41:{hash}"))?;

        let Err(error) = G2MuhashSampler::open(&path, Some(42)) else {
            panic!("non-interval sample not at the configured tip must be rejected");
        };

        assert!(error.to_string().contains("outside height 0"));
        Ok(())
    }

    #[test]
    fn rejects_skipped_interval_sample() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("g2.samples");
        let hash = CoinStats::default().muhash.finalize_hash().to_string_be();
        std::fs::write(&path, format!("0:{hash},20000:{hash}"))?;

        let Err(error) = G2MuhashSampler::open(&path, None) else {
            panic!("skipped interval sample must be rejected");
        };

        assert!(error.to_string().contains("missing required height 10000"));
        Ok(())
    }

    #[test]
    fn rejects_sample_above_configured_tip() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("g2.samples");
        let hash = CoinStats::default().muhash.finalize_hash().to_string_be();
        std::fs::write(&path, format!("0:{hash},10000:{hash}"))?;

        let Err(error) = G2MuhashSampler::open(&path, Some(42)) else {
            panic!("sample beyond configured tip must be rejected");
        };

        assert!(
            error
                .to_string()
                .contains("exceeds configured tip height 42")
        );
        Ok(())
    }

    #[test]
    fn reopens_existing_samples_without_duplicates() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("g2.samples");
        let hash = CoinStats::default().muhash.finalize_hash().to_string_be();
        std::fs::write(&path, format!("0:{hash}"))?;

        let sampler = G2MuhashSampler::open(&path, None)?;
        sampler.record(&CoinStats::default())?;

        assert_eq!(std::fs::read_to_string(&path)?, format!("0:{hash}"));
        Ok(())
    }

    #[test]
    fn rejects_stale_existing_sample() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("g2.samples");
        let stale = "0".repeat(64);
        std::fs::write(&path, format!("0:{stale}"))?;

        let sampler = G2MuhashSampler::open(&path, None)?;
        let error = sampler.record(&CoinStats::default());
        let Err(error) = error else {
            panic!("stale sample must be rejected");
        };

        assert!(error.to_string().contains("sample height 0 changed"));
        Ok(())
    }
}
