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

/// Core's `-version` output shape (`src/bitcoind.cpp` `ProcessInitCommands`: a
/// `<client> daemon version <version>` line followed by the license paragraph
/// from `src/common/license_info.cpp`), rendered with this node's own
/// identity, workspace version, and license. Core's version number is never
/// imitated.
fn version_notice() -> String {
    format!(
        "bitcoin-rs daemon version {version}\n\
         Copyright (C) 2026 The bitcoin-rs developers\n\
         \n\
         Please contribute if you find bitcoin-rs useful. \
         Visit <https://github.com/gosuda/bitcoin-rs> for further information about the software.\n\
         The source code is available from <https://github.com/gosuda/bitcoin-rs>.\n\
         \n\
         This is experimental software.\n\
         Distributed under the Apache License 2.0, see the accompanying file LICENSE \
         or <https://www.apache.org/licenses/LICENSE-2.0>\n",
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
