//! `bitcoin-rs` — node binary entry point.
//!
//! Task 19 in `PLAN.md` wires the real `crates/node::run` event loop. This file
//! at the workspace-bootstrap stage installs the global allocator and returns
//! success so that `cargo build --workspace` validates the skeleton.

#![allow(missing_docs)]
#![allow(unreachable_pub)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]
#![allow(clippy::missing_const_for_fn)] // Task 19 makes main non-const.

use std::process::ExitCode;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> ExitCode {
    // Bootstrap-only placeholder; Task 19 replaces this with the node event loop.
    ExitCode::SUCCESS
}
