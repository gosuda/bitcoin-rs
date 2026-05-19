use std::thread::{self, JoinHandle};

use anyhow::Result;
use crossbeam_channel::Sender;
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::Signals,
};

/// Installs SIGINT/SIGTERM handling on a dedicated forwarding thread.
pub fn install_shutdown_handler(shutdown_tx: Sender<()>) -> Result<JoinHandle<()>> {
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
