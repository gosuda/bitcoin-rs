use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Output};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::error::{TestError, TestResult};
use super::oracle::KvRow;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct FamilyReport {
    pub(crate) family: String,
    #[serde(alias = "count")]
    pub(crate) row_count: u64,
    pub(crate) digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct NamespaceReport {
    pub(crate) namespace: String,
    pub(crate) engine: String,
    pub(crate) families: Vec<FamilyReport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct CopiedFileReport {
    pub(crate) path: String,
    pub(crate) bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct CoinStatsReport {
    pub(crate) height: u32,
    pub(crate) utxo_count: u64,
    pub(crate) total_amount: u64,
    pub(crate) muhash: String,
    pub(crate) tx_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct NormalizedUndoRowReport {
    pub(crate) height: u32,
    pub(crate) hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct ConversionReport {
    pub(crate) source_epoch: u32,
    pub(crate) target_epoch: u32,
    pub(crate) namespaces: Vec<NamespaceReport>,
    pub(crate) copied_files: Vec<CopiedFileReport>,
    #[serde(default)]
    pub(crate) checkpoint_stats: Option<CoinStatsReport>,
    #[serde(default)]
    pub(crate) final_stats: Option<CoinStatsReport>,
    #[serde(default)]
    pub(crate) normalized_undo_rows: Vec<NormalizedUndoRowReport>,
    #[serde(default)]
    pub(crate) carried_markers: Vec<String>,
    #[serde(default)]
    pub(crate) published_checkpoint: bool,
}

pub(crate) fn run_converter(args: &[&str]) -> io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_bitcoin-rs-storage-convert"))
        .args(args)
        .output()
}

pub(crate) fn parse_report(output: &Output) -> TestResult<ConversionReport> {
    if !output.status.success() {
        return Err(TestError::Assertion(format!(
            "converter exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let report: ConversionReport = sonic_rs::from_slice(&output.stdout)?;
    Ok(report)
}

pub(crate) fn compute_oracle_digest(rows: &[KvRow]) -> String {
    let mut sorted = rows.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    for (k, v) in &sorted {
        let k_len = u32::try_from(k.len()).expect("key length fits u32");
        let v_len = u32::try_from(v.len()).expect("val length fits u32");
        hasher.update(k_len.to_le_bytes());
        hasher.update(k);
        hasher.update(v_len.to_le_bytes());
        hasher.update(v);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

pub(crate) fn recursive_dir_digest(root: &Path) -> TestResult<String> {
    let mut entries = Vec::new();
    collect_files_recursive(root, root, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    for (rel_path, bytes) in entries {
        let path_len = u32::try_from(rel_path.len()).expect("path length fits u32");
        let bytes_len = u64::try_from(bytes.len()).expect("file length fits u64");
        hasher.update(path_len.to_le_bytes());
        hasher.update(rel_path.as_bytes());
        hasher.update(bytes_len.to_le_bytes());
        hasher.update(&bytes);
    }

    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

fn collect_files_recursive(
    base: &Path,
    current: &Path,
    out: &mut Vec<(String, Vec<u8>)>,
) -> TestResult<()> {
    if !current.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_files_recursive(base, &path, out)?;
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(base)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .to_string_lossy()
                .to_string();
            let bytes = fs::read(&path)?;
            out.push((rel, bytes));
        }
    }
    Ok(())
}
