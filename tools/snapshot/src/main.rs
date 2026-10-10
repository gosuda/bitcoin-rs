//! Read-only inspection and verification of Bitcoin Core portable snapshots.

use std::{
    fs::{self, File},
    io::{self, BufReader, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

use bitcoin_rs_primitives::{AssumeUtxoData, Network};
use bitcoin_rs_utxo::core_snapshot::{
    SnapshotError, SnapshotLimits, SnapshotMetadata, read_and_verify, read_metadata,
};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use thiserror::Error;

#[derive(Parser)]
#[command(
    about = "Inspect or verify a Bitcoin Core v2 snapshot without starting a node",
    version
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read header metadata only; this does not verify the snapshot contents.
    Inspect {
        /// Existing Bitcoin Core dumptxoutset file (opened read-only).
        file: PathBuf,
        /// Emit a machine-readable report.
        #[arg(long)]
        json: bool,
    },
    /// Verify all coins against a compiled network anchor, without historical validation.
    Verify {
        /// Existing Bitcoin Core dumptxoutset file (opened read-only).
        file: PathBuf,
        /// Expected network; never inferred as a trust decision from the file.
        #[arg(long, value_enum)]
        network: NetworkArg,
        /// Emit a machine-readable report.
        #[arg(long)]
        json: bool,
        /// Override the shared decoder's input byte limit.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        max_file_bytes: Option<u64>,
        /// Override the shared decoder's coin-count limit (the set is held in memory).
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        max_coins: Option<u64>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum NetworkArg {
    Mainnet,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
}

impl From<NetworkArg> for Network {
    fn from(value: NetworkArg) -> Self {
        match value {
            NetworkArg::Mainnet => Self::Mainnet,
            NetworkArg::Testnet3 => Self::Testnet3,
            NetworkArg::Testnet4 => Self::Testnet4,
            NetworkArg::Signet => Self::Signet,
            NetworkArg::Regtest => Self::Regtest,
        }
    }
}

const NETWORKS: [Network; 5] = [
    Network::Mainnet,
    Network::Testnet3,
    Network::Testnet4,
    Network::Signet,
    Network::Regtest,
];

#[derive(Debug, Error)]
enum Error {
    #[error("{path}: {source}")]
    Input { path: PathBuf, source: io::Error },
    #[error("snapshot input must be a regular file: {0}")]
    NotRegularFile(PathBuf),
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    #[error("cannot write report: {0}")]
    Output(#[from] io::Error),
    #[error("cannot serialize report: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    const fn exit_code(&self) -> u8 {
        match self {
            Self::Snapshot(_) => 4,
            Self::Input { .. } | Self::NotRegularFile(_) | Self::Output(_) | Self::Json(_) => 3,
        }
    }
}

#[derive(Serialize)]
struct Report {
    format: &'static str,
    validation: &'static str,
    historical_validation_performed: bool,
    path: String,
    file_bytes: u64,
    version: u16,
    network: Option<&'static str>,
    network_magic: String,
    base_block_hash: String,
    declared_coins: u64,
    known_anchor: Option<AnchorReport>,
    verification: Option<VerificationReport>,
}

#[derive(Serialize)]
struct AnchorReport {
    height: u32,
    hash_serialized_3: String,
    chain_tx_count: u64,
}

impl From<&AssumeUtxoData> for AnchorReport {
    fn from(anchor: &AssumeUtxoData) -> Self {
        Self {
            height: anchor.height,
            hash_serialized_3: anchor.hash_serialized.to_string(),
            chain_tx_count: anchor.chain_tx_count,
        }
    }
}

#[derive(Serialize)]
struct VerificationReport {
    actual_coins: u64,
    hash_serialized_3: String,
    bytes_read: u64,
    elapsed_seconds: f64,
}

impl Report {
    fn from_metadata(path: &Path, file_bytes: u64, metadata: &SnapshotMetadata) -> Self {
        let network = NETWORKS
            .into_iter()
            .find(|network| network.magic() == metadata.network_magic);
        let anchor =
            network.and_then(|network| network.assume_utxo_for_hash(metadata.base_block_hash));
        let [a, b, c, d] = metadata.network_magic;
        Self {
            format: "bitcoin-core-v2",
            validation: "metadata_only",
            historical_validation_performed: false,
            path: path.display().to_string(),
            file_bytes,
            version: metadata.version,
            network: network.map(Network::identity_name),
            network_magic: format!("{a:02x}{b:02x}{c:02x}{d:02x}"),
            base_block_hash: metadata.base_block_hash.to_string(),
            declared_coins: metadata.coins_count,
            known_anchor: anchor.map(AnchorReport::from),
            verification: None,
        }
    }

    fn write_text(&self, out: &mut impl Write) -> io::Result<()> {
        writeln!(out, "Format: Bitcoin Core v{}", self.version)?;
        writeln!(out, "File: {} ({} bytes)", self.path, self.file_bytes)?;
        writeln!(out, "Network: {}", self.network.unwrap_or("unknown"))?;
        writeln!(out, "Network magic: {}", self.network_magic)?;
        writeln!(out, "Base block: {}", self.base_block_hash)?;
        writeln!(out, "Declared coins: {}", self.declared_coins)?;
        if let Some(anchor) = &self.known_anchor {
            writeln!(out, "Known pinned base height: {}", anchor.height)?;
            writeln!(
                out,
                "Pinned chain transaction count: {}",
                anchor.chain_tx_count
            )?;
        } else {
            writeln!(out, "Known pinned base: none")?;
        }
        if let Some(verification) = &self.verification {
            writeln!(out, "Validation: pinned state verified")?;
            writeln!(out, "Actual coins: {}", verification.actual_coins)?;
            writeln!(out, "hash_serialized_3: {}", verification.hash_serialized_3)?;
            writeln!(out, "Elapsed seconds: {:.3}", verification.elapsed_seconds)?;
            writeln!(
                out,
                "Historical genesis-to-base validation was not performed."
            )?;
        } else {
            writeln!(
                out,
                "Validation: metadata only; snapshot contents are NOT verified."
            )?;
        }
        Ok(())
    }
}

fn open_input(path: &Path) -> Result<(File, u64), Error> {
    let input_error = |source| Error::Input {
        path: path.to_path_buf(),
        source,
    };
    // Reject directories/devices/pipes before opening; the held handle is checked again.
    if !fs::metadata(path).map_err(input_error)?.is_file() {
        return Err(Error::NotRegularFile(path.to_path_buf()));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A path swapped to a FIFO must not block before the held-handle check.
        let flags = i32::try_from(rustix::fs::OFlags::NONBLOCK.bits())
            .map_err(io::Error::other)
            .map_err(input_error)?;
        options.custom_flags(flags);
    }
    let file = options.open(path).map_err(input_error)?;
    let metadata = file.metadata().map_err(input_error)?;
    if !metadata.is_file() {
        return Err(Error::NotRegularFile(path.to_path_buf()));
    }
    Ok((file, metadata.len()))
}

fn run(command: Command) -> Result<(), Error> {
    let (report, json) = match command {
        Command::Inspect { file, json } => {
            let (mut reader, file_bytes) = open_input(&file)?;
            let metadata = read_metadata(&mut reader)?;
            (Report::from_metadata(&file, file_bytes, &metadata), json)
        }
        Command::Verify {
            file,
            network,
            json,
            max_file_bytes,
            max_coins,
        } => {
            let mut limits = SnapshotLimits::default();
            if let Some(value) = max_file_bytes {
                limits.max_file_bytes = value;
            }
            if let Some(value) = max_coins {
                limits.max_coins = value;
            }
            let (reader, file_bytes) = open_input(&file)?;
            let start = Instant::now();
            let snapshot = read_and_verify(&mut BufReader::new(reader), network.into(), limits)?;
            let mut report = Report::from_metadata(&file, file_bytes, &snapshot.metadata);
            report.validation = "pinned_state_verified";
            report.known_anchor = Some(AnchorReport::from(snapshot.anchor));
            report.verification = Some(VerificationReport {
                actual_coins: u64::try_from(snapshot.set.len()).map_err(io::Error::other)?,
                hash_serialized_3: snapshot.hash_serialized.to_string(),
                bytes_read: snapshot.bytes_read,
                elapsed_seconds: start.elapsed().as_secs_f64(),
            });
            (report, json)
        }
    };
    let mut out = io::stdout().lock();
    if json {
        serde_json::to_writer_pretty(&mut out, &report)?;
        writeln!(out)?;
    } else {
        report.write_text(&mut out)?;
    }
    out.flush()?;
    Ok(())
}

fn main() -> ExitCode {
    match run(Args::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "bitcoin-rs-snapshot: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}
