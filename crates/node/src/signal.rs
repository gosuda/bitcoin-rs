use anyhow::Result;
use crossbeam_channel::Sender;

/// Installs cross-platform process termination handling.
pub fn install_shutdown_handler(shutdown_tx: Sender<()>) -> Result<()> {
    ctrlc::set_handler(move || {
        let _ = shutdown_tx.try_send(());
    })?;
    Ok(())
}
