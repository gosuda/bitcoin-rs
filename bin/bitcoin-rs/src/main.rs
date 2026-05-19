//! `bitcoin-rs` — node binary entry point.
//!
//! Starts the configured `bitcoin-rs` node with crash recovery, signal handling,
//! metrics/tracing setup, and graceful shutdown.

#![allow(missing_docs)]
#![allow(unreachable_pub)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

use std::process::ExitCode;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> ExitCode {
    match bitcoin_rs_node::Config::load_from_args(std::env::args_os())
        .and_then(bitcoin_rs_node::run)
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bitcoin-rs: {error:#}");
            ExitCode::FAILURE
        }
    }
}
