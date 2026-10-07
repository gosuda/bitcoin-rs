//! CRT SIGINT/SIGTERM bridge where signal-hook's Unix iterator is unavailable.
//! This does not implement console close, logoff, or shutdown-event semantics.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::Result;
use crossbeam_channel::Sender;
use signal_hook::consts::signal::{SIGINT, SIGTERM};

pub(crate) struct ShutdownHandler {
    registrations: Vec<signal_hook::SigId>,
    stop: Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl ShutdownHandler {
    pub(crate) fn install(shutdown: Arc<AtomicBool>, shutdown_tx: Sender<()>) -> Result<Self> {
        let received = Arc::new(AtomicBool::new(false));
        let mut registrations = Vec::new();
        for signal in [SIGINT, SIGTERM] {
            match signal_hook::flag::register(signal, Arc::clone(&received)) {
                Ok(id) => registrations.push(id),
                Err(error) => {
                    for id in registrations {
                        signal_hook::low_level::unregister(id);
                    }
                    return Err(error.into());
                }
            }
        }
        let (stop, stopped) = crossbeam_channel::bounded(1);
        let thread = std::thread::spawn(move || {
            while matches!(
                stopped.recv_timeout(Duration::from_millis(50)),
                Err(crossbeam_channel::RecvTimeoutError::Timeout)
            ) {
                if received.swap(false, Ordering::Acquire) {
                    shutdown.store(true, Ordering::Release);
                    let _ = shutdown_tx.try_send(());
                }
            }
        });
        #[cfg(test)]
        testing::note_installed();
        Ok(Self {
            registrations,
            stop,
            thread: Some(thread),
        })
    }

    pub(crate) fn close_and_join(&mut self) -> Result<()> {
        for id in self.registrations.drain(..) {
            signal_hook::low_level::unregister(id);
        }
        let _ = self.stop.try_send(());
        if let Some(thread) = self.thread.take() {
            #[cfg(test)]
            testing::note_closed();
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("signal forwarding thread panicked"))?;
        }
        Ok(())
    }
}

impl Drop for ShutdownHandler {
    fn drop(&mut self) {
        let _ = self.close_and_join();
    }
}

#[cfg(test)]
#[path = "../tests/unit/signal_counters.rs"]
pub(crate) mod testing;

#[cfg(test)]
mod tests {
    /// Raise a real CRT signal in a child process so unrelated lifecycle tests
    /// cannot observe its process-global signal registrations.
    #[test]
    fn crt_signal_reaches_shutdown_receiver() -> anyhow::Result<()> {
        const CHILD: &str = "BITCOIN_RS_TEST_CRT_SIGNAL_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (sender, receiver) = crossbeam_channel::bounded(1);
            let mut handler = super::ShutdownHandler::install(shutdown.clone(), sender)?;
            signal_hook::low_level::raise(signal_hook::consts::signal::SIGTERM)?;
            receiver.recv_timeout(std::time::Duration::from_secs(2))?;
            assert!(shutdown.load(std::sync::atomic::Ordering::Acquire));
            handler.close_and_join()?;
            return Ok(());
        }
        let test_name = concat!(module_path!(), "::crt_signal_reaches_shutdown_receiver")
            .split("::")
            .skip(1)
            .collect::<Vec<_>>()
            .join("::");
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", &test_name])
            .env(CHILD, "1")
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "CRT signal child failed: {output:?}"
        );
        Ok(())
    }

    #[test]
    fn close_joins_once_and_allows_reinstallation() -> anyhow::Result<()> {
        for _ in 0..2 {
            let (sender, _receiver) = crossbeam_channel::bounded(1);
            let mut handler = super::ShutdownHandler::install(
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                sender,
            )?;
            handler.close_and_join()?;
            handler.close_and_join()?;
            assert!(handler.thread.is_none());
            assert!(handler.registrations.is_empty());
        }
        Ok(())
    }
}
