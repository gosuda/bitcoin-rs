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

    /// Target storage engine (accepts only 'rocksdb').
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
    pub(crate) fn validate(&self) -> Result<(), ConvertError> {
        if !self.to_engine.eq_ignore_ascii_case("rocksdb") {
            return Err(ConvertError::InvalidOperation(format!(
                "unsupported target storage engine '{}'; accepts only 'rocksdb'",
                self.to_engine
            )));
        }

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
