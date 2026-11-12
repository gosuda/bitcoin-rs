mod cli;
mod convert;
mod error;
mod fs_util;
mod report;
mod source;
mod target;

use clap::Parser;
use std::io::{self, Write};
use std::process::ExitCode;

use cli::CliArgs;
use convert::run_conversion;

fn main() -> ExitCode {
    let args = CliArgs::parse();

    match run_conversion(args) {
        Ok(report) => match sonic_rs::to_string_pretty(&report) {
            Ok(json) => {
                let stdout = io::stdout();
                let mut handle = stdout.lock();
                match writeln!(handle, "{json}").and_then(|()| handle.flush()) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(err) => {
                        let _ = writeln!(
                            io::stderr().lock(),
                            "bitcoin-rs-storage-convert: conversion completed but report output failed: {err}"
                        );
                        ExitCode::FAILURE
                    }
                }
            }
            Err(err) => {
                let stderr = io::stderr();
                let mut handle = stderr.lock();
                let _ = writeln!(
                    handle,
                    "bitcoin-rs-storage-convert: failed to serialize report: {err}"
                );
                ExitCode::FAILURE
            }
        },
        Err(err) => {
            let stderr = io::stderr();
            let mut handle = stderr.lock();
            let _ = writeln!(handle, "bitcoin-rs-storage-convert: {err}");
            ExitCode::FAILURE
        }
    }
}
