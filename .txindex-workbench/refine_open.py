from pathlib import Path
import sys
root=Path(sys.argv[1]); node=root/'crates/node/src'; work=node/'txindex_worker'
f=node/'txindex_worker.rs'; s=f.read_text(); s=s.replace('    Stopped,','    Stopped,\n    #[error("txindex store open abandoned on shutdown")]\n    OpenStopped,',1)
s=s.replace('impl TxIndexWorkerError {','''impl TxIndexWorkerError {
    /// The backend helper may still hold or acquire the store after this error.
    fn abandoned_open(&self) -> bool {
        matches!(self, Self::OpenStopped | Self::OpenTimeout { .. })
    }
''',1)
a=s.index('/// Maximum time the txindex worker waits'); b=s.index('const TXINDEX_OPEN_TIMEOUT',a)
s=s[:a]+'''/// Upper bound on waiting for backend recovery. Timeout isolates the index
/// failure from the node; it does not prove recovery stopped making progress.
/// The backend helper cannot be cancelled, so abandonment poisons its namespace.
'''+s[b:]; f.write_text(s)
f=work/'startup.rs'; s=f.read_text(); s=s.replace('use std::time::Instant;\n','')
a=s.index('    match worker_result {'); b=s.index('\n/// Fails the worker as one unit:',a)
s=s[:a]+'''    finish_worker(runtime, lifecycle, generation, &namespace_key, worker_result);
}

/// Report the terminal outcome before releasing its namespace claim.
/// An abandoned backend may still touch the store, so its claim must stay
/// poisoned for the process lifetime (`IDX-07`).
fn finish_worker(
    runtime: &TxIndexRuntime,
    lifecycle: &Arc<ArcSwap<TxIndexLifecycle>>,
    generation: &Generation,
    namespace_key: &Path,
    result: Result<(), TxIndexWorkerError>,
) {
    let registry = &*NAMESPACE_REGISTRY;
    if let Err(error) = result {
        if error.abandoned_open() {
            registry.poison(namespace_key, generation.id());
        }
        tracing::error!(%error, "txindex worker open or run failed");
        fail_worker(runtime, lifecycle, generation, &error.to_string());
    }
    // Release is generation-checked and never removes a poisoned claim.
    registry.release(namespace_key, generation.id());
}
'''+s[b:]
a=s.index('    let open: OpenTxIndex = open_tx_index_with_timeout('); b=s.index('    )?;',a)
s=s[:a]+s[a:b].replace('        shutdown,','        || shutdown.load(Ordering::Acquire) || generation.is_revoked() || runtime.should_stop(),')+s[b:]
s=s.replace('    shutdown: &Arc<AtomicBool>,\n) -> Result<OpenTxIndex, TxIndexWorkerError>', '    should_stop: impl Fn() -> bool,\n) -> Result<OpenTxIndex, TxIndexWorkerError>',1)
a=s.index('    let (tx, rx) = std::sync::mpsc::channel();'); s=s[:a]+'''    // No helper exists yet: cancellation here can release the namespace.
    if should_stop() {
        return Err(TxIndexWorkerError::Stopped);
    }
'''+s[a:]
a=s.index('    // Poll in short slices'); b=s.index('\n/// Opens the txindex store on the worker thread',a)
s=s[:a]+'''    let result = open_wait::wait_for_open_result(&rx, open_timeout, should_stop);
    if matches!(&result, Err(TxIndexWorkerError::OpenTimeout { .. })) {
        tracing::error!(
            timeout_secs = open_timeout.as_secs(),
            backend = %storage_backend,
            dir = %txindex_dir.display(),
            "txindex store open timed out; detaching the open helper and poisoning its namespace"
        );
    }
    result
}
'''+s[b:]; s+='\nmod open_wait;\n\n#[cfg(test)]\nmod tests;\n'; f.write_text(s)
f=work/'startup/open_wait.rs'; f.parent.mkdir(parents=True,exist_ok=True); f.write_text('''//! Bounded observation of a non-cancellable backend open.

use super::{OpenTxIndex, TxIndexWorkerError};
use std::time::{Duration, Instant};

/// Maximum gap between cancellation checks while backend recovery is pending.
const OPEN_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The caller must retain namespace exclusion for abandoned-open errors.
pub(super) fn wait_for_open_result(
    receiver: &std::sync::mpsc::Receiver<Result<OpenTxIndex, TxIndexWorkerError>>,
    timeout: Duration,
    should_stop: impl Fn() -> bool,
) -> Result<OpenTxIndex, TxIndexWorkerError> {
    let deadline = Instant::now() + timeout;
    loop {
        // Shutdown wins even when its observation coincides with the deadline.
        if should_stop() {
            return Err(TxIndexWorkerError::OpenStopped);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(TxIndexWorkerError::OpenTimeout { secs: timeout.as_secs() });
        }
        match receiver.recv_timeout(remaining.min(OPEN_POLL_INTERVAL)) {
            Ok(result) => return result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(TxIndexWorkerError::Storage(
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
''')
f=node/'txindex_worker_integration_tests.rs'; s=f.read_text(); a=s.index('fn open_timeout_publishes_error_not_infinite_spin()'); s=s[:a]+s[a:].replace('        &shutdown,','        || shutdown.load(Ordering::Acquire),'); f.write_text(s)
f=work/'startup/tests.rs'; f.write_text('//! IDX-07: supervision owns namespace release after terminal worker outcomes.\n\nuse super::*;\n\n'+(Path(__file__).parent/'open_supervisor_tests.rs').read_text())
f=work/'startup/open_wait/tests.rs'; f.parent.mkdir(parents=True,exist_ok=True); f.write_text((Path(__file__).parent/'open_wait_tests.rs').read_text().replace('use super::*;', 'use super::*;\nuse super::super::open_tx_index_with_timeout;'))
f=root/'docs/contracts/indexing.md'; s=f.read_text(); s+='''
### Store-open cancellation evidence

The store-open wait polls node shutdown, runtime stop, and generation revocation
at bounded intervals. Once the helper has started, cancellation and timeout are
typed abandoned-open outcomes: startup poisons the namespace before releasing
the worker's claim. Cancellation before helper creation may release normally.
These paths do not cancel the underlying storage-engine call.

Evidence for `IDX-07` abandonment and `IDX-08` shutdown:
`crates/node/src/txindex_worker/startup/open_wait/tests.rs` covers bounded
cancellation, deadline precedence, disconnection, and backend error propagation;
`crates/node/src/txindex_worker/startup/tests.rs` covers namespace poisoning and
clean release. The query-budget limits and on-disk formats are unchanged.
'''; f.write_text(s)
