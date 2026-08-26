//! Untimed durability and reorg-custody verification for a manifest-replayed state.
//!
//! `--data-dir` must point to a disposable copy made by the trial controller. This
//! executable deliberately mutates that copy; it must never receive the original
//! timed-trial store.

#![allow(missing_docs)]
#![allow(clippy::print_stdout)]

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, Result, bail, ensure};
use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_node::Network;
use bitcoin_rs_node::config::Config;
use bitcoin_rs_node::state::NodeState;
use bitcoin_rs_primitives::Hash256;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

const VALIDATION_SCHEMA: &str = "mainnet-prefix-replay-validation-v1";
const PROOF_SCHEMA: &str = "verify-replay-durability-proof-v1";

fn main() -> Result<()> {
    let args = Args::parse(std::env::args_os().skip(1))?;
    ensure_output_absent(&args.output)?;

    let validation_bytes = fs::read(&args.validation)
        .with_context(|| format!("read validation file {}", args.validation.display()))?;
    let validation_file_size =
        u64::try_from(validation_bytes.len()).context("validation file length does not fit u64")?;
    let validation_file_sha256 = Sha256::digest(&validation_bytes)
        .as_slice()
        .to_lower_hex_string();
    let validation: Validation = serde_json::from_slice(&validation_bytes)
        .with_context(|| format!("parse strict validation JSON {}", args.validation.display()))?;
    validation.validate()?;

    let config = node_config(&args);
    let before = {
        let state = NodeState::open(config.clone()).with_context(|| {
            format!(
                "open checkpointed mainnet state in disposable copy {} using {}",
                args.data_dir.display(),
                args.storage_backend
            )
        })?;
        let captured =
            capture_invariants(&state).context("capture invariants before reorg probe")?;
        captured
            .invariants
            .ensure_matches_validation(&validation)
            .context("checkpointed state does not match replay validation")?;
        captured
    };

    let checkpoint_generation = verify_durable_reorg(&args, &config, &validation, &before)?;

    let after = {
        let state = NodeState::open(config).with_context(|| {
            format!(
                "reopen post-reorg checkpoint in disposable copy {}",
                args.data_dir.display()
            )
        })?;
        capture_invariants(&state)
            .context("capture invariants after final checkpoint reopen")?
            .invariants
    };
    after
        .ensure_matches_validation(&validation)
        .context("post-reorg checkpoint does not match replay validation")?;
    ensure!(
        after == before.invariants,
        "post-reorg invariants differ from the pre-reorg checkpoint: before={:?}, after={after:?}",
        before.invariants
    );

    let proof = Proof {
        schema: PROOF_SCHEMA,
        version: 1,
        network: "mainnet",
        backend: &args.storage_backend,
        validation: ValidationFileProof {
            size_bytes: validation_file_size,
            sha256: &validation_file_sha256,
        },
        before: &before.invariants,
        after: &after,
        checkpoint_generation,
        durable_body_roundtrip: true,
        durable_undo_roundtrip: true,
        mutated_copy_only: true,
        reopen_count: 2,
    };
    let rendered = serde_json::to_vec_pretty(&proof).context("render durability proof JSON")?;
    write_atomic_noclobber(&args.output, &rendered)
        .with_context(|| format!("publish durability proof {}", args.output.display()))?;

    println!("wrote durability proof {}", args.output.display());
    Ok(())
}

fn verify_durable_reorg(
    args: &Args,
    config: &Config,
    validation: &Validation,
    before: &CapturedInvariants,
) -> Result<u64> {
    let state = NodeState::open(config.clone()).with_context(|| {
        format!(
            "reopen checkpointed state for durability probe in {}",
            args.data_dir.display()
        )
    })?;
    let mut handles = state.apply_handles();
    // Full verification, same as the timed trial that produced the validation artifact.
    handles.assume_valid_height = 0;
    handles.assume_valid_gate =
        Arc::new(bitcoin_rs_node::apply::AssumeValidGate::with_anchor(None));

    let (original_tip_id, parent_id, parent_hash) = {
        let tree = state.block_tree();
        let tree = tree.read();
        let original_tip_id = tree.lookup(before.tip_hash).with_context(|| {
            format!(
                "resolve original tip {} in reopened block tree",
                before.tip_hash
            )
        })?;
        let parent_id = tree
            .parent_id(original_tip_id)
            .context("resolve original tip parent in reopened block tree")?
            .context("validation names a genesis-only state; no parent exists")?;
        let parent_hash = tree
            .node(parent_id)
            .context("resolve original tip parent node in reopened block tree")?
            .hash;
        (original_tip_id, parent_id, parent_hash)
    };

    bitcoin_rs_node::reorg::switch_to_branch(&handles, parent_id, |_| None, |_| {})
        .context("switch durable state from original tip to its parent")?;
    ensure_applied_tip(&state, validation.stop_height - 1, parent_hash)
        .context("verify applied parent after durable disconnect")?;

    bitcoin_rs_node::reorg::switch_to_branch(&handles, original_tip_id, |_| None, |_| {})
        .context("switch durable state from parent back to original tip")?;
    ensure_applied_tip(&state, validation.stop_height, before.tip_hash)
        .context("verify applied original tip after durable reconnect")?;

    state
        .publish_checkpoint()
        .context("publish clean checkpoint after durable reconnect")
}

fn node_config(args: &Args) -> Config {
    let mut config = Config::default_for_network(Network::Mainnet);
    config.data_dir.clone_from(&args.data_dir);
    config.storage_backend.clone_from(&args.storage_backend);
    config.p2p_listen.clear();
    config.dns_seeds_enabled = false;
    config.txindex = false;
    // Mirror the timed-trial replay default: full script verification on every block.
    config.assume_valid_height = 0;
    config
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Validation {
    schema: String,
    stop_height: u32,
    #[serde(deserialize_with = "deserialize_lower_hash")]
    stop_hash: Hash256,
    #[serde(deserialize_with = "deserialize_lower_hash")]
    utxo_hash_serialized_3: Hash256,
    #[serde(deserialize_with = "deserialize_lower_hash")]
    muhash: Hash256,
    utxo_count: u64,
    total_amount: u64,
}

impl Validation {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == VALIDATION_SCHEMA,
            "unsupported validation schema {:?}; expected {VALIDATION_SCHEMA:?}",
            self.schema
        );
        ensure!(
            self.stop_height > 0,
            "validation stop_height must be greater than zero; genesis-only validation is unsupported"
        );
        Ok(())
    }
}

fn deserialize_lower_hash<'de, D>(deserializer: D) -> core::result::Result<Hash256, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(serde::de::Error::custom(
            "hash must be exactly 64 lowercase hexadecimal characters",
        ));
    }
    Hash256::from_str_be(&value).map_err(serde::de::Error::custom)
}

#[derive(Debug)]
struct CapturedInvariants {
    tip_hash: Hash256,
    invariants: Invariants,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct Invariants {
    tip_height: u32,
    tip_hash: String,
    utxo_count: u64,
    total_amount: u64,
    muhash: String,
    utxo_hash_serialized_3: String,
    tx_count: u64,
    bogo_size: u64,
}

impl Invariants {
    fn ensure_matches_validation(&self, expected: &Validation) -> Result<()> {
        ensure!(
            self.tip_height == expected.stop_height,
            "tip height mismatch: expected {}, found {}",
            expected.stop_height,
            self.tip_height
        );
        ensure!(
            self.tip_hash == expected.stop_hash.to_string_be(),
            "tip hash mismatch: expected {}, found {}",
            expected.stop_hash,
            self.tip_hash
        );
        ensure!(
            self.utxo_count == expected.utxo_count,
            "UTXO count mismatch: expected {}, found {}",
            expected.utxo_count,
            self.utxo_count
        );
        ensure!(
            self.total_amount == expected.total_amount,
            "total amount mismatch: expected {}, found {} sat",
            expected.total_amount,
            self.total_amount
        );
        ensure!(
            self.muhash == expected.muhash.to_string_be(),
            "MuHash mismatch: expected {}, found {}",
            expected.muhash,
            self.muhash
        );
        ensure!(
            self.utxo_hash_serialized_3 == expected.utxo_hash_serialized_3.to_string_be(),
            "aggregate UTXO hash mismatch: expected {}, found {}",
            expected.utxo_hash_serialized_3,
            self.utxo_hash_serialized_3
        );
        Ok(())
    }
}

fn capture_invariants(state: &NodeState) -> Result<CapturedInvariants> {
    let applied = state
        .applied_tip()
        .load_full()
        .context("checkpoint has no applied tip")?;
    let tip_height = applied.height;
    let tip_hash = applied.hash;
    drop(applied);

    let utxo = state.utxo();
    let stats = utxo
        .with_stable_view(|view| bitcoin_rs_utxo::stats::scan_coin_stats(view, tip_height, true))
        .context("scan full UTXO coin statistics with MuHash")?;
    ensure!(
        stats.height == tip_height,
        "coin-stat height mismatch: applied tip is {tip_height}, scan reports {}",
        stats.height
    );
    let aggregate = bitcoin_rs_utxo::aggregate_hash(&utxo)
        .context("compute deterministic aggregate UTXO hash")?;
    drop(utxo);

    Ok(CapturedInvariants {
        tip_hash,
        invariants: Invariants {
            tip_height,
            tip_hash: tip_hash.to_string_be(),
            utxo_count: stats.utxo_count,
            total_amount: stats.total_amount,
            muhash: stats.muhash.finalize_hash().to_string_be(),
            utxo_hash_serialized_3: aggregate.to_string_be(),
            tx_count: stats.tx_count,
            bogo_size: stats.bogo_size,
        },
    })
}

fn ensure_applied_tip(
    state: &NodeState,
    expected_height: u32,
    expected_hash: Hash256,
) -> Result<()> {
    let applied = state
        .applied_tip()
        .load_full()
        .context("state has no applied tip after branch switch")?;
    ensure!(
        applied.height == expected_height,
        "applied height mismatch: expected {expected_height}, found {}",
        applied.height
    );
    ensure!(
        applied.hash == expected_hash,
        "applied hash mismatch: expected {expected_hash}, found {}",
        applied.hash
    );
    Ok(())
}

#[derive(Serialize)]
struct Proof<'a> {
    schema: &'static str,
    version: u32,
    network: &'static str,
    backend: &'a str,
    validation: ValidationFileProof<'a>,
    before: &'a Invariants,
    after: &'a Invariants,
    checkpoint_generation: u64,
    durable_body_roundtrip: bool,
    durable_undo_roundtrip: bool,
    mutated_copy_only: bool,
    reopen_count: u8,
}

#[derive(Serialize)]
struct ValidationFileProof<'a> {
    size_bytes: u64,
    sha256: &'a str,
}

#[derive(Debug)]
struct Args {
    data_dir: PathBuf,
    storage_backend: String,
    validation: PathBuf,
    output: PathBuf,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let mut data_dir = None;
        let mut storage_backend = None;
        let mut validation = None;
        let mut output = None;
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            let arg = arg
                .into_string()
                .map_err(|value| anyhow::anyhow!("argument is not UTF-8: {}", value.display()))?;
            match arg.as_str() {
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                "--data-dir" => set_once(
                    &mut data_dir,
                    PathBuf::from(next_arg(&mut args, "--data-dir")?),
                    "--data-dir",
                )?,
                "--storage-backend" => set_once(
                    &mut storage_backend,
                    next_arg(&mut args, "--storage-backend")?,
                    "--storage-backend",
                )?,
                "--validation" => set_once(
                    &mut validation,
                    PathBuf::from(next_arg(&mut args, "--validation")?),
                    "--validation",
                )?,
                "--output" => set_once(
                    &mut output,
                    PathBuf::from(next_arg(&mut args, "--output")?),
                    "--output",
                )?,
                other => {
                    bail!("unknown argument {other:?}; --data-dir must name a disposable copy")
                }
            }
        }

        Ok(Self {
            data_dir: data_dir.context(
                "missing --data-dir <disposable-copy>; the controller must copy the timed-trial store",
            )?,
            storage_backend: storage_backend.context("missing --storage-backend <backend>")?,
            validation: validation.context("missing --validation <path>")?,
            output: output.context("missing --output <path>")?,
        })
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<()> {
    ensure!(slot.is_none(), "duplicate argument {name}");
    *slot = Some(value);
    Ok(())
}

fn next_arg(args: &mut impl Iterator<Item = OsString>, name: &str) -> Result<String> {
    args.next()
        .with_context(|| format!("{name} requires a value"))?
        .into_string()
        .map_err(|value| anyhow::anyhow!("{name} value is not UTF-8: {}", value.display()))
}

fn print_usage() {
    println!(
        "Usage: verify_replay_durability --data-dir <disposable-copy> --storage-backend <backend> \\\n\
         --validation <mainnet-prefix-replay-validation-v1.json> --output <proof.json>\n\
         WARNING: --data-dir is mutated and must be a controller-created copy of the timed-trial store."
    );
}

struct TempOutput {
    path: PathBuf,
    armed: bool,
}

impl TempOutput {
    fn create(target: &Path) -> Result<(Self, File)> {
        static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
        let file_name = target
            .file_name()
            .with_context(|| format!("output path {} has no file name", target.display()))?;
        for _ in 0..128 {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let mut temp_name = file_name.to_os_string();
            temp_name.push(format!(".tmp.{}.{id}", std::process::id()));
            let path = target.with_file_name(temp_name);
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((Self { path, armed: true }, file)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("create temporary proof {}", path.display()));
                }
            }
        }
        bail!(
            "could not reserve a temporary proof name beside {} after 128 attempts",
            target.display()
        )
    }

    fn publish(&mut self, target: &Path) -> Result<()> {
        rename_noreplace(&self.path, target).with_context(|| {
            format!(
                "atomically publish {} without replacing {}",
                self.path.display(),
                target.display()
            )
        })?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for TempOutput {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn ensure_output_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("refusing to replace existing output {}", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("inspect output destination {}", path.display()))
        }
    }
}

fn write_atomic_noclobber(path: &Path, bytes: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .with_context(|| format!("output path {} has no file name", path.display()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create proof output directory {}", parent.display()))?;
    let path = fs::canonicalize(parent)
        .with_context(|| format!("canonicalize proof output directory {}", parent.display()))?
        .join(file_name);
    ensure_output_absent(&path)?;

    let (mut temp, mut file) = TempOutput::create(&path)?;
    file.write_all(bytes)
        .with_context(|| format!("write temporary proof {}", temp.path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("terminate temporary proof {}", temp.path.display()))?;
    file.flush()
        .with_context(|| format!("flush temporary proof {}", temp.path.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync temporary proof {}", temp.path.display()))?;
    drop(file);

    temp.publish(&path)?;
    File::open(parent)
        .with_context(|| format!("open proof output directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("fsync proof output directory {}", parent.display()))?;
    Ok(())
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        from,
        rustix::fs::CWD,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(Into::into)
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
)))]
fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    fs::hard_link(from, to)?;
    fs::remove_file(from)
}
