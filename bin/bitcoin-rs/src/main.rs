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

/// The `-version` output: one line carrying this node's own name and
/// workspace version. Core's `feature_help.py` (v31.1) asserts only exit 0
/// and the word "version" on stdout, so Core's license paragraph is not
/// imitated (a fixed copyright year would also go stale).
fn version_notice() -> String {
    format!(
        "bitcoin-rs daemon version {version}\n",
        version = env!("CARGO_PKG_VERSION")
    )
}

fn main() -> ExitCode {
    let cli = match <config::CliArgs as clap::Parser>::try_parse() {
        Ok(cli) => cli,
        Err(error) => error.exit(),
    };
    if cli.version {
        print!("{}", version_notice());
        return ExitCode::SUCCESS;
    }
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
            // Core's init errors print `Error: <message>` on stderr
            // (`InitError` -> `noui.cpp`); the functional framework matches
            // startup failures against exactly that shape.
            eprintln!("Error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
