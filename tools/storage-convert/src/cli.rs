use bitcoin_rs_storage::StorageBackend;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::error::ConvertError;

#[derive(Parser, Debug)]
#[command(
    name = "bitcoin-rs-storage-convert",
    about = "Offline datadir storage migration and format conversion tool",
    subcommand_negates_reqs = true
)]
pub(crate) struct CliArgs {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,

    /// Path to the source datadir.
    #[arg(long = "from", value_name = "DIR")]
    pub(crate) from: Option<PathBuf>,

    /// Path to the destination datadir.
    #[arg(long = "to", value_name = "DIR")]
    pub(crate) to: Option<PathBuf>,
    /// Target storage engine (rocksdb, surrealkv, mdbx).
    #[arg(long = "to-engine", value_name = "ENGINE", default_value = "rocksdb")]
    pub(crate) to_engine: String,

    /// Path to the source pool datadir (optional, requires --pool-to).
    #[arg(long = "pool-from", value_name = "DIR")]
    pub(crate) pool_from: Option<PathBuf>,

    /// Path to the destination pool datadir (optional, requires --pool-from).
    #[arg(long = "pool-to", value_name = "DIR")]
    pub(crate) pool_to: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Rebuild the derived-index projection from the retained block archive
    /// and its undo rows, then publish one sealed generation.
    RebuildIndex {
        /// Datadir whose `txindex` namespace is rebuilt in place.
        #[arg(long = "datadir", value_name = "DIR")]
        datadir: PathBuf,

        /// Builder memory budget in MiB; the builder spills sorted runs beyond it.
        #[arg(long = "budget-mb", value_name = "MIB", default_value_t = 64)]
        budget_mb: u64,
    },
}

impl CliArgs {
    /// The convert-mode roots; `None` when the invoked subcommand replaces
    /// the default conversion flow.
    pub(crate) fn convert_roots(&self) -> Result<(&PathBuf, &PathBuf), ConvertError> {
        let Some(from) = self.from.as_ref() else {
            return Err(ConvertError::InvalidOperation(
                "--from is required for datadir conversion".into(),
            ));
        };
        let Some(to) = self.to.as_ref() else {
            return Err(ConvertError::InvalidOperation(
                "--to is required for datadir conversion".into(),
            ));
        };
        Ok((from, to))
    }
}

impl CliArgs {
    pub(crate) fn target_backend(&self) -> Result<StorageBackend, ConvertError> {
        let backend = match self.to_engine.trim().to_ascii_lowercase().as_str() {
            "rocksdb" => StorageBackend::RocksDb,
            "surrealkv" => StorageBackend::SurrealKv,
            "mdbx" => StorageBackend::Mdbx,
            _ => {
                return Err(ConvertError::InvalidOperation(format!(
                    "unsupported target storage engine '{}'; accepts rocksdb, surrealkv, or mdbx",
                    self.to_engine
                )));
            }
        };

        match backend {
            StorageBackend::RocksDb => Ok(backend),
            StorageBackend::SurrealKv => {
                #[cfg(feature = "surrealkv")]
                {
                    Ok(backend)
                }
                #[cfg(not(feature = "surrealkv"))]
                {
                    Err(ConvertError::EngineNotCompiled {
                        engine: "surrealkv".to_string(),
                        feature: "surrealkv",
                    })
                }
            }
            StorageBackend::Mdbx => {
                #[cfg(feature = "mdbx")]
                {
                    Ok(backend)
                }
                #[cfg(not(feature = "mdbx"))]
                {
                    Err(ConvertError::EngineNotCompiled {
                        engine: "mdbx".to_string(),
                        feature: "mdbx",
                    })
                }
            }
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConvertError> {
        self.target_backend()?;

        match (&self.pool_from, &self.pool_to) {
            (Some(_), None) => {
                return Err(ConvertError::InvalidOperation(
                    "--pool-from was provided without --pool-to; pool datadirs must be paired"
                        .into(),
                ));
            }
            (None, Some(_)) => {
                return Err(ConvertError::InvalidOperation(
                    "--pool-to was provided without --pool-from; pool datadirs must be paired"
                        .into(),
                ));
            }
            _ => {}
        }

        Ok(())
    }
}
