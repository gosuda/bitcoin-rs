//! Deadline polling for the live-wire process tests.
//!
//! Included by `#[path]` from each test that polls; every item is used by
//! every includer, so no `dead_code` allowance is needed.

use std::time::{Duration, Instant};

/// Polls an RPC predicate until it holds or `dur` elapses.
pub(crate) fn wait_for(dur: Duration, check: &mut dyn FnMut() -> bool) -> bool {
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}
