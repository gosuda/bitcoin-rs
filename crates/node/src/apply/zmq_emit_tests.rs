use super::*;
use parking_lot::Mutex as TestMutex;

#[derive(Debug, Default)]
struct CapturingPublisher {
    events: TestMutex<Vec<String>>,
}

impl crate::ZmqPublisher for CapturingPublisher {
    fn publish_hashblock(&self, hash: bitcoin_rs_primitives::Hash256) {
        self.events
            .lock()
            .push(format!("hashblock:{}", hash.to_string_be()));
    }

    fn publish_hashtx(&self, txid: Txid) {
        self.events.lock().push(format!("hashtx:{txid}"));
    }

    fn publish_rawblock(&self, _bytes: &[u8]) {
        self.events.lock().push("rawblock".to_owned());
    }

    fn publish_rawtx(&self, _bytes: &[u8]) {
        self.events.lock().push("rawtx".to_owned());
    }
}

#[test]
fn captures_event_count_smoke() {
    let capturing = Arc::new(CapturingPublisher::default());
    let publisher: Arc<dyn crate::ZmqPublisher> = capturing.clone();

    publisher.publish_hashblock(bitcoin_rs_primitives::Hash256::default());
    publisher.publish_hashtx(Txid::default());
    publisher.publish_rawblock(&[]);
    publisher.publish_rawtx(&[]);

    let events = capturing.events.lock().clone();
    assert_eq!(
        events,
        vec![
            format!(
                "hashblock:{}",
                bitcoin_rs_primitives::Hash256::default().to_string_be()
            ),
            format!("hashtx:{}", Txid::default()),
            "rawblock".to_owned(),
            "rawtx".to_owned(),
        ]
    );
}
