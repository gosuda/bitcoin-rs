//! Budget-driven window fill limits.
//!
//! The node injects a [`WindowLimitsSource`] built from the one resource
//! budget; the constants here remain the hard ceilings (`BUD-06`), never
//! the fill rule.

use std::sync::Arc;

pub const DURABLE_HEAD_GROUP_BLOCKS: usize = 64;
pub const DURABLE_HEAD_GROUP_MAX_BYTES: usize = 8 << 20;
pub const SCRIPT_BATCH_WINDOW: usize = 1024;
pub const SCRIPT_BATCH_MAX_BYTES: usize = 64 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowLimits {
    pub max_blocks: usize,
    pub max_bytes: usize,
}

impl WindowLimits {
    #[must_use]
    pub const fn durable_head_defaults() -> Self {
        Self {
            max_blocks: DURABLE_HEAD_GROUP_BLOCKS,
            max_bytes: DURABLE_HEAD_GROUP_MAX_BYTES,
        }
    }

    #[must_use]
    pub const fn script_batch_defaults() -> Self {
        Self {
            max_blocks: SCRIPT_BATCH_WINDOW,
            max_bytes: SCRIPT_BATCH_MAX_BYTES,
        }
    }
}

pub type WindowLimitsSource = Arc<dyn Fn() -> WindowLimits + Send + Sync>;

#[must_use]
pub fn window_len_within(sizes: impl IntoIterator<Item = usize>, limits: WindowLimits) -> usize {
    let mut count = 0_usize;
    let mut bytes = 0_usize;
    for size in sizes {
        if count >= limits.max_blocks {
            break;
        }
        let next = bytes.saturating_add(size);
        if count > 0 && next > limits.max_bytes {
            break;
        }
        bytes = next;
        count = count.saturating_add(1);
    }
    count
}

#[must_use]
pub fn default_window_limits_source() -> WindowLimitsSource {
    Arc::new(WindowLimits::durable_head_defaults)
}

#[cfg(test)]
mod tests {
    use super::{WindowLimits, window_len_within};

    // BUD-06
    #[test]
    fn window_fill_stops_at_budget_bytes_not_fixed_count() {
        let limits = WindowLimits {
            max_blocks: 16,
            max_bytes: 300,
        };
        assert_eq!(window_len_within([100, 100, 100, 100], limits), 3);
        assert_eq!(window_len_within([100, 100, 100], limits), 3);
    }

    #[test]
    fn window_fill_stops_at_budget_blocks() {
        let limits = WindowLimits {
            max_blocks: 2,
            max_bytes: usize::MAX,
        };
        assert_eq!(window_len_within([1, 1, 1, 1], limits), 2);
    }

    #[test]
    fn first_block_alone_exceeding_bytes_still_fills() {
        let limits = WindowLimits {
            max_blocks: 4,
            max_bytes: 8,
        };
        assert_eq!(window_len_within([64, 1, 1], limits), 1);
    }
}
