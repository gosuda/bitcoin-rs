use bitcoin_rs_storage::StorageBackend;
use clap::Parser;
use std::path::{Path, PathBuf};

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
    #[arg(long = "from", value_name = "DIR", required = true)]
    pub(crate) from: Option<PathBuf>,

    /// Path to the destination datadir.
    #[arg(long = "to", value_name = "DIR", required = true)]
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

#[derive(clap::Subcommand, Debug)]
pub(crate) enum Command {
    /// Rebuild index into an unpublished generation and publish.
    RebuildIndex {
        #[arg(long = "datadir", value_name = "DIR")]
        datadir: PathBuf,
    },
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

    pub(crate) fn source_path(&self) -> Result<&Path, ConvertError> {
        self.from.as_deref().ok_or_else(|| {
            ConvertError::InvalidOperation("missing required argument --from".into())
        })
    }

    pub(crate) fn destination_path(&self) -> Result<&Path, ConvertError> {
        self.to
            .as_deref()
            .ok_or_else(|| ConvertError::InvalidOperation("missing required argument --to".into()))
    }
}
