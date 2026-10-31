//! Offline allocation snapshot; never opens a database or starts a node.

#![allow(clippy::print_stdout, clippy::print_stderr)]

#[cfg(target_os = "linux")]
mod frames;
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

#[derive(Debug)]
enum FootprintError {
    Usage,
    Io(std::io::Error),
    Json(sonic_rs::Error),
    #[cfg(not(target_os = "linux"))]
    UnsupportedPlatform,
}

impl std::fmt::Display for FootprintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage => write!(f, "usage: storage-footprint <offline-data-directory>"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Json(err) => write!(f, "{err}"),
            #[cfg(not(target_os = "linux"))]
            Self::UnsupportedPlatform => {
                write!(f, "allocation measurement is supported only on Linux")
            }
        }
    }
}

impl std::error::Error for FootprintError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Json(err) => Some(err),
            Self::Usage => None,
            #[cfg(not(target_os = "linux"))]
            Self::UnsupportedPlatform => None,
        }
    }
}

impl From<std::io::Error> for FootprintError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<sonic_rs::Error> for FootprintError {
    fn from(err: sonic_rs::Error) -> Self {
        Self::Json(err)
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), FootprintError> {
    let mut args = std::env::args_os().skip(1);
    let root = args.next().ok_or(FootprintError::Usage)?;
    if args.next().is_some() {
        return Err(FootprintError::Usage);
    }
    let report = linux::measure(std::path::Path::new(&root))?;
    println!("{}", sonic_rs::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<(), FootprintError> {
    Err(FootprintError::UnsupportedPlatform)
}
