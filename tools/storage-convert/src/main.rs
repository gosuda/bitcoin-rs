mod cli;
mod convert;
mod error;
mod fs_util;
mod legacy_undo;
mod rebuild;
mod report;
mod source;
mod target;

use clap::Parser;
use std::io::{self, Write};
use std::process::ExitCode;

use cli::{CliArgs, Command};
use convert::run_conversion;
use rebuild::run_rebuild_index;

fn main() -> ExitCode {
    let args = CliArgs::parse();

    let outcome = match &args.command {
        Some(Command::RebuildIndex { datadir, budget_mb }) => {
            let budget_bytes =
                usize::try_from(budget_mb.saturating_mul(1024 * 1024)).unwrap_or(usize::MAX);
            run_rebuild_index(datadir, budget_bytes).map(|report| {
                sonic_rs::to_string_pretty(&report).map(|json| (json, "rebuild-index report"))
            })
        }
        None => run_conversion(args).map(|report| {
            sonic_rs::to_string_pretty(&report).map(|json| (json, "conversion report"))
        }),
    };

    match outcome {
        Ok(Ok((json, label))) => {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            match writeln!(handle, "{json}").and_then(|()| handle.flush()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    let _ = writeln!(
                        io::stderr().lock(),
                        "bitcoin-rs-storage-convert: {label} output failed: {err}"
                    );
                    ExitCode::FAILURE
                }
            }
        }
        Ok(Err(err)) => {
            let stderr = io::stderr();
            let mut handle = stderr.lock();
            let _ = writeln!(
                handle,
                "bitcoin-rs-storage-convert: failed to serialize report: {err}"
            );
            ExitCode::FAILURE
        }
        Err(err) => {
            let stderr = io::stderr();
            let mut handle = stderr.lock();
            let _ = writeln!(handle, "bitcoin-rs-storage-convert: {err}");
            ExitCode::FAILURE
        }
    }
}
