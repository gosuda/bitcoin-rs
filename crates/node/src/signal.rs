use std::thread::{self, JoinHandle};

use anyhow::Result;
use crossbeam_channel::Sender;

/// Installs SIGINT/SIGTERM handling on a dedicated forwarding thread.
///
/// signal-hook has no signal-iterator support on Windows, so the handler is
/// unix-only; Windows callers get a no-op thread that keeps the returned
/// join handle shape intact.
#[cfg(not(windows))]
pub fn install_shutdown_handler(shutdown_tx: Sender<()>) -> Result<JoinHandle<()>> {
    use signal_hook::{
        consts::signal::{SIGINT, SIGTERM},
        iterator::Signals,
    };
    let mut signals = Signals::new([SIGTERM, SIGINT])?;
    let handle = thread::spawn(move || {
        for _signal in signals.forever() {
            if shutdown_tx.try_send(()).is_err() {
                break;
            }
        }
    });
    Ok(handle)
}

/// Windows stub for [`install_shutdown_handler`]: no signal iterator exists
/// there, so this only parks a thread and never delivers a shutdown signal.
#[cfg(windows)]
pub fn install_shutdown_handler(shutdown_tx: Sender<()>) -> Result<JoinHandle<()>> {
    Ok(thread::spawn(move || {
        let _guard = shutdown_tx;
        loop {
            thread::park();
        }
    }))
}
