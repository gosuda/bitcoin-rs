//! ZMQ publisher trait foundation for the node's notification subsystem.
//!
//! Bitcoin Core publishes "hashblock", "hashtx", "rawblock", and "rawtx" events
//! via ZMQ for client subscribers. `bitcoin-rs` exposes a trait surface so the
//! apply pipeline can fire publish calls without binding to a specific transport
//! (raw socket, in-process channel, ZMQ daemon).
//!
//! `NoOpZmqPublisher` is the default impl; production deployments swap in a real
//! ZMQ-backed implementation via constructor injection.

use bitcoin::Txid;
use bitcoin_rs_primitives::Hash256;

/// Publishes block + transaction notification events.
///
/// Implementations should be best-effort — publish failures must NOT propagate
/// into the apply pipeline. Use interior mutability + atomics if state is
/// needed; the trait is `&self`-only.
pub trait ZmqPublisher: Send + Sync + core::fmt::Debug {
    /// Publish a `hashblock` notification (block hash big-endian display).
    fn publish_hashblock(&self, hash: Hash256);

    /// Publish a `hashtx` notification (transaction id big-endian display).
    fn publish_hashtx(&self, txid: Txid);

    /// Publish a `rawblock` notification with the serialized block bytes.
    fn publish_rawblock(&self, bytes: &[u8]);

    /// Publish a `rawtx` notification with the serialized transaction bytes.
    fn publish_rawtx(&self, bytes: &[u8]);
}

/// Default no-op implementation. All methods discard their input silently.
///
/// Use this when ZMQ notifications are not configured; production deployments
/// inject a real transport-backed publisher.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoOpZmqPublisher;

impl ZmqPublisher for NoOpZmqPublisher {
    fn publish_hashblock(&self, _hash: Hash256) {}

    fn publish_hashtx(&self, _txid: Txid) {}

    fn publish_rawblock(&self, _bytes: &[u8]) {}

    fn publish_rawtx(&self, _bytes: &[u8]) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    #[test]
    fn noop_publisher_methods_are_callable() {
        let publisher = NoOpZmqPublisher;
        publisher.publish_hashblock(Hash256::default());
        publisher.publish_hashtx(bitcoin::Txid::from_byte_array([0; 32]));
        publisher.publish_rawblock(&[]);
        publisher.publish_rawtx(&[]);
    }
}
