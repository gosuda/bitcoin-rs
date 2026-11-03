use std::thread::{self, JoinHandle};

use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::Signals,
};

use crate::run::RunError;

pub(crate) struct ShutdownHandler {
    handle: signal_hook::iterator::Handle,
    thread: Option<JoinHandle<()>>,
}

impl ShutdownHandler {
    pub(crate) fn install(request_shutdown: impl Fn() + Send + 'static) -> std::io::Result<Self> {
        let mut signals = Signals::new([SIGTERM, SIGINT])?;
        let handle = signals.handle();
        let thread = thread::spawn(move || {
            for _signal in signals.forever() {
                request_shutdown();
            }
        });
        #[cfg(test)]
        testing::note_installed();
        Ok(Self {
            handle,
            thread: Some(thread),
        })
    }

    pub(crate) fn close_and_join(&mut self) -> Result<(), RunError> {
        self.handle.close();
        match self.thread.take() {
            Some(thread) => {
                #[cfg(test)]
                testing::note_closed();
                thread
                    .join()
                    .map_err(|_| RunError::SignalForwardingPanicked)
            }
            None => Ok(()),
        }
    }
}

impl Drop for ShutdownHandler {
    fn drop(&mut self) {
        let _ = self.close_and_join();
    }
}

#[cfg(test)]
pub(crate) mod testing;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestError;
    type TestResult<T> = core::result::Result<T, TestError>;

    #[test]
    fn close_and_join_releases_the_forwarding_thread() -> TestResult<()> {
        let mut handler = ShutdownHandler::install(|| {})?;
        assert!(handler.thread.is_some(), "the forwarding thread is running");

        handler.close_and_join()?;

        assert!(
            handler.thread.is_none(),
            "close_and_join must join and release the forwarding thread"
        );
        Ok(())
    }

    #[test]
    fn signal_handler_supports_repeated_lifecycles() -> TestResult<()> {
        let installed_before = testing::installed_total();
        let closed_before = testing::closed_total();

        for _ in 0..2 {
            let mut handler = ShutdownHandler::install(|| {})?;
            handler.close_and_join()?;
        }

        assert_eq!(
            testing::installed_total(),
            installed_before + 2,
            "each lifecycle installs exactly one handler"
        );
        assert_eq!(
            testing::closed_total(),
            closed_before + 2,
            "each lifecycle must close and join its handler"
        );
        Ok(())
    }
}
