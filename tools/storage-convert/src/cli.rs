use bitcoin_rs_storage::StorageBackend;
use clap::Parser;
use std::path::PathBuf;

use crate::error::ConvertError;

#[derive(Parser, Debug)]
#[command(
    name = "bitcoin-rs-storage-convert",
    about = "Offline datadir storage migration and format conversion tool"
)]
pub(crate) struct CliArgs {
    /// Path to the source datadir.
    #[arg(long = "from", value_name = "DIR")]
    pub(crate) from: PathBuf,

    /// Path to the destination datadir.
    #[arg(long = "to", value_name = "DIR")]
    pub(crate) to: PathBuf,

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
