//! Bounded observation of a non-cancellable backend open.

use super::{DerivedIndexWorkerError, OpenDerivedIndex};
use std::time::{Duration, Instant};

/// Maximum gap between cancellation checks while backend recovery is pending.
const OPEN_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The caller must retain namespace exclusion for abandoned-open errors.
pub(super) fn wait_for_open_result(
    receiver: &std::sync::mpsc::Receiver<Result<OpenDerivedIndex, DerivedIndexWorkerError>>,
    timeout: Duration,
    should_stop: impl Fn() -> bool,
) -> Result<OpenDerivedIndex, DerivedIndexWorkerError> {
    let deadline = Instant::now() + timeout;
    loop {
        // Shutdown wins even when its observation coincides with the deadline.
        if should_stop() {
            return Err(DerivedIndexWorkerError::OpenStopped);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(DerivedIndexWorkerError::OpenTimeout {
                secs: timeout.as_secs(),
            });
        }
        match receiver.recv_timeout(remaining.min(OPEN_POLL_INTERVAL)) {
            Ok(result) => return result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(DerivedIndexWorkerError::Storage(
                    bitcoin_rs_storage::StorageError::Backend(
                        "txindex open helper thread exited without result".to_owned(),
                    ),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests;
