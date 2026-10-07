//! CLI entry point for custody-grade storage-footprint evidence collection.

#[cfg(unix)]
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "storage-footprint")]
#[command(
    about = "Custody-grade physical and logical storage-footprint measurement for bitcoin-rs"
)]
struct Cli {
    /// Data directory to measure.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Optional path to TOML configuration file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Network name (mainnet, testnet, testnet4, signet, regtest).
    #[arg(long)]
    network: Option<String>,

    /// Storage backend (fjall, redb, rocksdb).
    #[arg(long)]
    storage_backend: Option<String>,

    /// Write evidence JSON to this path instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Conservative peak allocated bytes from an isolated filesystem or project quota.
    #[arg(long = "high-water-bytes", alias = "storage-high-water-bytes")]
    storage_high_water_bytes: Option<u64>,

    /// Pinned stop height. Pairing and hash format: `FP-03`.
    #[arg(long = "stop-height", alias = "measure-storage-stop-height")]
    measure_storage_stop_height: Option<u32>,

    /// Pinned stop hash. Pairing and hash format: `FP-03`.
    #[arg(long = "stop-hash", alias = "measure-storage-stop-hash")]
    measure_storage_stop_hash: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    #[cfg(not(unix))]
    {
        let _ = cli;
        anyhow::bail!(
            "physical storage-footprint measurement requires POSIX st_blocks and is only supported on Unix/Linux platforms"
        )
    }

    #[cfg(unix)]
    {
        use bitcoin_rs_node::config::NodeConfig;
        use bitcoin_rs_node::options::{parse_network, parse_storage_backend};
        use bitcoin_rs_storage_footprint::{
            MeasureStorageRequest, measure_storage_footprint, storage_footprint_json,
        };

        let mut config = if let Some(config_path) = &cli.config {
            let text = std::fs::read_to_string(config_path)
                .with_context(|| format!("failed to read config file {}", config_path.display()))?;
            let user_config: bitcoin_rs_node::UserConfig =
                toml::from_str(&text).with_context(|| {
                    format!("failed to parse TOML config {}", config_path.display())
                })?;
            bitcoin_rs_node::resolve(&[&user_config])?
        } else {
            let net_name = cli.network.as_deref().unwrap_or("mainnet");
            let net =
                parse_network(net_name).map_err(|e| anyhow::anyhow!("invalid network: {e}"))?;
            NodeConfig::default_for_network(net.consensus_network())
        };

        if let Some(net_name) = &cli.network {
            let net =
                parse_network(net_name).map_err(|e| anyhow::anyhow!("invalid network: {e}"))?;
            config.network = net.consensus_network();
        }
        if let Some(data_dir) = cli.data_dir {
            config.data_dir = data_dir;
        } else if cli.config.is_none() {
            config.data_dir = PathBuf::from(".bitcoin-rs");
        }
        if let Some(storage_backend) = &cli.storage_backend {
            config.storage.backend = parse_storage_backend(storage_backend)
                .map_err(|e| anyhow::anyhow!("invalid storage backend: {e}"))?;
        }

        let request = MeasureStorageRequest {
            high_water_allocated_bytes: cli.storage_high_water_bytes,
            stop_height: cli.measure_storage_stop_height,
            stop_hash: cli.measure_storage_stop_hash,
        };

        let evidence = measure_storage_footprint(&config, &request)?;
        let json = storage_footprint_json(&evidence)?;

        if let Some(out_path) = cli.output {
            std::fs::write(&out_path, json).with_context(|| {
                format!(
                    "failed to write storage footprint to {}",
                    out_path.display()
                )
            })?;
        } else {
            println!("{json}");
        }

        Ok(())
    }
}
