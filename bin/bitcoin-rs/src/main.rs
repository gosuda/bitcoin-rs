#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

use std::process::ExitCode;

mod config;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(test)]
fn load(
    args: impl IntoIterator<Item = impl Into<std::ffi::OsString> + Clone>,
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> anyhow::Result<bitcoin_rs_node::NodeConfig> {
    let cli = <config::CliArgs as clap::Parser>::try_parse_from(args)?;
    config::resolve(cli, vars)
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
        }
        (None, None, None) => {
            bitcoin_rs_node::run(config, bitcoin_rs_node::RuntimeInputs::default())
        }
        _ => Err(anyhow::anyhow!(
            "--corpus, --manifest, and --state must be given together"
        )),
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bitcoin-rs: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
