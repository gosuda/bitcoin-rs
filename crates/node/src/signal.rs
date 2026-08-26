use std::thread::{self, JoinHandle};

use anyhow::Result;
use crossbeam_channel::Sender;
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::Signals,
};

/// Installs SIGINT/SIGTERM handling on a dedicated forwarding thread.
///
/// The forwarding thread also trips the process-wide shutdown broadcast so
/// waiters parked in [`crate::shutdown::wait_for_shutdown`] wake at signal
/// receipt — even when the bounded channel into the event loop is already
/// full and the `try_send` below would be dropped.
pub fn install_shutdown_handler(shutdown_tx: Sender<()>) -> Result<JoinHandle<()>> {
    let mut signals = Signals::new([SIGTERM, SIGINT])?;
    let handle = thread::spawn(move || {
        for _signal in signals.forever() {
            crate::shutdown::request_shutdown();
            if shutdown_tx.try_send(()).is_err() {
                break;
            }
        }
    });
    Ok(handle)
}
