use std::sync::Arc;

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Txid;
use parking_lot::Mutex;

#[derive(Debug, Default)]
struct TaggedPublisher {
    tag: Mutex<u32>,
}

impl crate::ZmqPublisher for TaggedPublisher {
    fn publish_hashblock(&self, _: Hash256) {
        *self.tag.lock() = 42;
    }

    fn publish_hashtx(&self, _: Txid) {}

    fn publish_rawblock(&self, _: &[u8]) {}

    fn publish_rawtx(&self, _: &[u8]) {}
}

#[test]
// ARCH-07 evidence: derived ZMQ consumers are configured outside apply.
fn with_zmq_publisher_swaps_handle() {
    let tagged = Arc::new(TaggedPublisher::default());
    let publisher: Arc<dyn crate::ZmqPublisher> = tagged.clone();
    let effects = crate::chain_effects::ChainEffects::noop().with_zmq_publisher(publisher);
    effects.emit_connected(Hash256::default(), &[], &[], None);
    assert_eq!(*tagged.tag.lock(), 42);
}
