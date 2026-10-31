#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

use std::process::ExitCode;

mod config;
use config::BinError;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(test)]
fn load(
    args: impl IntoIterator<Item = impl Into<std::ffi::OsString> + Clone>,
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Result<bitcoin_rs_node::NodeConfig, tests::TestError> {
    let cli = <config::CliArgs as clap::Parser>::try_parse_from(args)?;
    Ok(config::resolve(cli, vars)?)
}

struct ErrorChain<'a>(&'a dyn std::error::Error);

impl std::fmt::Display for ErrorChain<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)?;
        let mut current = self.0.source();
        while let Some(source) = current {
            write!(f, ": {source}")?;
            current = source.source();
        }
        Ok(())
    }
}

fn main() -> ExitCode {
    let cli = match <config::CliArgs as clap::Parser>::try_parse() {
        Ok(cli) => cli,
        Err(error) => error.exit(),
    };
    let import = (cli.corpus.clone(), cli.manifest.clone(), cli.state.clone());
    let result = config::resolve(cli, std::env::vars_os()).and_then(|config| match import {
        (Some(corpus), Some(manifest), Some(state)) => {
            bitcoin_rs_node::offline_import::run_offline_import(config, &corpus, &manifest, &state)
                .map_err(BinError::from)
        }
        (None, None, None) => {
            bitcoin_rs_node::run(config, bitcoin_rs_node::RuntimeInputs::default())
                .map_err(BinError::from)
        }
        _ => Err(BinError::IncompleteOfflineImportArguments),
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bitcoin-rs: {}", ErrorChain(&error));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
