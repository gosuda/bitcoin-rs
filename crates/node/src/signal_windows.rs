use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use crossbeam_channel::Sender;

use crate::run::RunError;
use signal_hook::consts::signal::{SIGBREAK, SIGINT, SIGTERM};

pub(crate) struct ShutdownHandler {
    registrations: Vec<signal_hook::SigId>,
    stop: Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl ShutdownHandler {
    pub(crate) fn install(request_shutdown: impl Fn() + Send + 'static) -> std::io::Result<Self> {
        let received = Arc::new(AtomicBool::new(false));
        let mut registrations = Vec::new();
        for signal in [SIGINT, SIGTERM, SIGBREAK] {
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
                    request_shutdown();
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

    pub(crate) fn close_and_join(&mut self) -> Result<(), RunError> {
        for id in self.registrations.drain(..) {
            signal_hook::low_level::unregister(id);
        }
        let _receiver_gone = self.stop.try_send(());
        if let Some(thread) = self.thread.take() {
            #[cfg(test)]
            testing::note_closed();
            thread
                .join()
                .map_err(|_| RunError::SignalForwardingPanicked)?;
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
#[path = "signal/testing.rs"]
pub(crate) mod testing;

#[cfg(test)]
mod tests {
    use crate::test_support::TestError;
    type TestResult<T> = core::result::Result<T, TestError>;

    #[test]
    fn crt_signal_reaches_shutdown_receiver() -> TestResult<()> {
        const CHILD: &str = "BITCOIN_RS_TEST_CRT_SIGNAL_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let shutdown_clone = std::sync::Arc::clone(&shutdown);
            let mut handler = super::ShutdownHandler::install(move || {
                shutdown_clone.store(true, std::sync::atomic::Ordering::Release);
            })?;
            signal_hook::low_level::raise(signal_hook::consts::signal::SIGTERM)?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !shutdown.load(std::sync::atomic::Ordering::Acquire) {
                if std::time::Instant::now() >= deadline {
                    return Err(TestError::Timeout("CRT signal child"));
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
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
        assert!(
            output.status.success(),
            "CRT signal child failed: {output:?}"
        );
        Ok(())
    }

    #[test]
    fn close_joins_once_and_allows_reinstallation() -> TestResult<()> {
        for _ in 0..2 {
            let mut handler = super::ShutdownHandler::install(|| {})?;
            handler.close_and_join()?;
            handler.close_and_join()?;
            assert!(handler.thread.is_none());
            assert_eq!(handler.registrations, Vec::new());
        }
        Ok(())
    }
}
