use thiserror::Error;

/// Mempool ancestor, descendant, and replacement limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MempoolLimits {
    /// Maximum number of transactions in an ancestor package, including the transaction itself.
    pub max_ancestors: u32,
    /// Maximum ancestor package virtual size in vbytes.
    pub max_ancestor_size: u64,
    /// Maximum number of transactions in a descendant package, including the transaction itself.
    pub max_descendants: u32,
    /// Maximum number of transactions a single BIP125 replacement may evict.
    pub max_replacement_evictions: u32,
}

impl Default for MempoolLimits {
    fn default() -> Self {
        Self {
            max_ancestors: 25,
            max_ancestor_size: 101_000,
            max_descendants: 25,
            max_replacement_evictions: 100,
        }
    }
}

/// Policy rejection reason for non-consensus mempool limits.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PolicyError {
    /// The transaction would exceed the configured ancestor count limit.
    #[error("too many unconfirmed ancestors")]
    TooManyAncestors,
    /// The transaction would exceed the configured ancestor package size limit.
    #[error("ancestor package is too large")]
    AncestorSizeLimit,
    /// The transaction would exceed a configured descendant count limit.
    #[error("too many unconfirmed descendants")]
    TooManyDescendants,
}
