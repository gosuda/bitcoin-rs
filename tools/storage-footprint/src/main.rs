//! Offline allocation snapshot; never opens a database or starts a node.

#![allow(clippy::print_stdout, clippy::print_stderr)]

#[cfg(target_os = "linux")]
mod linux;

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("storage-footprint: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let root = args
        .next()
        .ok_or("usage: storage-footprint <offline-data-directory>")?;
    if args.next().is_some() {
        return Err("usage: storage-footprint <offline-data-directory>".into());
    }
    let report = linux::measure(std::path::Path::new(&root))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    Err("allocation measurement is supported only on Linux".into())
}
