//! `bitcoin-rs` — node binary entry point.
//!
//! Starts the configured `bitcoin-rs` node with crash recovery, signal handling,
//! metrics/tracing setup, and graceful shutdown.

#![allow(missing_docs)]
#![allow(unreachable_pub)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

use std::process::ExitCode;

use bitcoin_rs::load_node_config;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> ExitCode {
    match load_node_config(std::env::args_os())
        .and_then(|config| bitcoin_rs_node::run(config, bitcoin_rs_node::RuntimeInputs::default()))
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bitcoin-rs: {error:#}");
            ExitCode::FAILURE
        }
    }
}
