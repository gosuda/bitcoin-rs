//! ZMQ publisher trait and transport-backed implementation for node notifications.
//!
//! Bitcoin Core publishes "hashblock", "hashtx", "rawblock", and "rawtx" events
//! via ZMQ for client subscribers. `bitcoin-rs` keeps the apply path behind a
//! small trait so notification failures cannot affect block connection.

#[cfg(feature = "zmq")]
use crate::config::ZmqPublication;
#[cfg(feature = "zmq")]
use anyhow::{Context as _, Result, bail};
use bitcoin::Txid;
#[cfg(any(feature = "zmq", test))]
use bitcoin::hashes::Hash as _;
use bitcoin_rs_primitives::Hash256;
#[cfg(feature = "zmq")]
use core::fmt;
#[cfg(feature = "zmq")]
use hashbrown::{HashMap, HashSet};
#[cfg(feature = "zmq")]
use parking_lot::Mutex;
#[cfg(feature = "zmq")]
use std::sync::atomic::{AtomicU32, Ordering};

/// ZMQ PUB notification topic.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ZmqTopic {
    /// Block hash notification.
    HashBlock,
    /// Transaction id notification.
    HashTx,
    /// Raw serialized block notification.
    RawBlock,
    /// Raw serialized transaction notification.
    RawTx,
    /// Block sequence notification.
    Sequence,
}

impl ZmqTopic {
    /// Returns the Core topic string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HashBlock => "hashblock",
            Self::HashTx => "hashtx",
            Self::RawBlock => "rawblock",
            Self::RawTx => "rawtx",
            Self::Sequence => "sequence",
        }
    }

    /// Returns the Core notifier name reported by `getzmqnotifications`.
    #[must_use]
    pub const fn notifier_type(self) -> &'static str {
        match self {
            Self::HashBlock => "pubhashblock",
            Self::HashTx => "pubhashtx",
            Self::RawBlock => "pubrawblock",
            Self::RawTx => "pubrawtx",
            Self::Sequence => "pubsequence",
        }
    }

    #[cfg(feature = "zmq")]
    const fn index(self) -> usize {
        match self {
            Self::HashBlock => 0,
            Self::HashTx => 1,
            Self::RawBlock => 2,
            Self::RawTx => 3,
            Self::Sequence => 4,
        }
    }
}

/// Event published on Core's unified `sequence` topic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequenceEvent {
    /// A block was connected.
    Connected(Hash256),
    /// A block was disconnected.
    Disconnected(Hash256),
}

impl SequenceEvent {
    fn hash(self) -> Hash256 {
        match self {
            Self::Connected(hash) | Self::Disconnected(hash) => hash,
        }
    }

    const fn label(self) -> u8 {
        match self {
            Self::Connected(_) => b'C',
            Self::Disconnected(_) => b'D',
        }
    }
}

/// One live bound notifier, the fact Core's `getzmqnotifications` reports per
/// active notifier.
///
/// Core enumerates `CZMQNotificationInterface::GetActiveNotifiers()` at call
/// time, each carrying its type, address, and high-water mark. The projection
/// layer owns the JSON rendering: `topic` maps to the `pub…` type string and
/// `endpoint` to the `address` key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZmqNotifier {
    /// Topic this notifier publishes.
    pub topic: ZmqTopic,
    /// Endpoint the PUB socket bound.
    pub endpoint: String,
    /// PUB socket send high-water mark.
    pub hwm: u32,
}

/// Publishes block + transaction notification events.
///
/// Implementations should be best-effort — publish failures must NOT propagate
/// into the apply pipeline. Use interior mutability + atomics if state is
/// needed; the trait is `&self`-only.
pub trait ZmqPublisher: Send + Sync + core::fmt::Debug {
    /// Returns whether any ZMQ notification emitted by the apply path is observable.
    ///
    /// The default is conservative for external implementations: keep invoking
    /// publisher methods unless an implementation proves the whole publisher is
    /// a no-op.
    fn wants_notifications(&self) -> bool {
        true
    }

    /// Returns whether the publisher can consume per-transaction raw bytes.
    ///
    /// The default is conservative for external implementations: keep producing
    /// rawtx payloads unless an implementation proves they are unobservable.
    fn wants_rawtx(&self) -> bool {
        true
    }

    /// Returns whether the publisher can consume full serialized block bytes.
    ///
    /// The default is conservative for external implementations: keep producing
    /// rawblock payloads unless an implementation proves they are unobservable.
    fn wants_rawblock(&self) -> bool {
        true
    }

    /// Returns the notifiers this publisher has live-bound, enumerated at
    /// call time.
    ///
    /// The default reports none: publishers without enumerable bound
    /// endpoints (the no-op and tracing publishers) have no live notifier,
    /// matching Core's empty result when the ZMQ notification interface is
    /// absent.
    fn active_notifiers(&self) -> Vec<ZmqNotifier> {
        Vec::new()
    }

    /// Publish a `hashblock` notification (block hash big-endian display bytes).
    fn publish_hashblock(&self, hash: Hash256);

    /// Publish a `hashtx` notification (transaction id big-endian display bytes).
    fn publish_hashtx(&self, txid: Txid);

    /// Publish a `rawblock` notification with the serialized block bytes.
    fn publish_rawblock(&self, bytes: &[u8]);

    /// Publish a `rawtx` notification with the serialized transaction bytes.
    fn publish_rawtx(&self, bytes: &[u8]);

    /// Publish a block event on Core's unified `sequence` topic.
    fn publish_sequence(&self, _event: SequenceEvent) {}
}

/// Default no-op implementation. All methods discard their input silently.
///
/// Use this when ZMQ notifications are not configured.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoOpZmqPublisher;

impl ZmqPublisher for NoOpZmqPublisher {
    fn wants_notifications(&self) -> bool {
        false
    }

    fn wants_rawtx(&self) -> bool {
        false
    }

    fn wants_rawblock(&self) -> bool {
        false
    }

    fn publish_hashblock(&self, _hash: Hash256) {}

    fn publish_hashtx(&self, _txid: Txid) {}

    fn publish_rawblock(&self, _bytes: &[u8]) {}

    fn publish_rawtx(&self, _bytes: &[u8]) {}

    fn publish_sequence(&self, _event: SequenceEvent) {}
}

/// `ZmqPublisher` that emits each event via `tracing::info!`.
///
/// Useful in tests and diagnostics that want notification visibility without
/// opening sockets.
#[derive(Clone, Copy, Debug, Default)]
pub struct TracingZmqPublisher;

impl ZmqPublisher for TracingZmqPublisher {
    fn publish_hashblock(&self, hash: Hash256) {
        tracing::info!(
            target: "bitcoin_rs_node::zmq",
            topic = "hashblock",
            hash = %hash.to_string_be(),
        );
    }

    fn publish_hashtx(&self, txid: Txid) {
        tracing::info!(
            target: "bitcoin_rs_node::zmq",
            topic = "hashtx",
            txid = %txid,
        );
    }

    fn publish_rawblock(&self, bytes: &[u8]) {
        tracing::info!(
            target: "bitcoin_rs_node::zmq",
            topic = "rawblock",
            len = bytes.len(),
        );
    }

    fn publish_rawtx(&self, bytes: &[u8]) {
        tracing::info!(
            target: "bitcoin_rs_node::zmq",
            topic = "rawtx",
            len = bytes.len(),
        );
    }

    fn publish_sequence(&self, event: SequenceEvent) {
        tracing::info!(
            target: "bitcoin_rs_node::zmq",
            topic = "sequence",
            hash = %event.hash().to_string_be(),
            label = event.label(),
        );
    }
}

#[cfg(feature = "zmq")]
struct EndpointSocket {
    endpoint: String,
    socket: Mutex<zmq::Socket>,
}

/// Socket-backed ZMQ PUB publisher.
#[cfg(feature = "zmq")]
pub struct SocketZmqPublisher {
    _context: zmq::Context,
    endpoints: Vec<EndpointSocket>,
    hashblock_endpoints: Vec<usize>,
    hashtx_endpoints: Vec<usize>,
    rawblock_endpoints: Vec<usize>,
    rawtx_endpoints: Vec<usize>,
    sequence_endpoints: Vec<usize>,
    notifiers: Vec<ZmqNotifier>,
    counters: [AtomicU32; 5],
}

#[cfg(feature = "zmq")]
impl fmt::Debug for SocketZmqPublisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketZmqPublisher")
            .field("endpoints", &self.endpoints.len())
            .field("notifiers", &self.notifiers.len())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "zmq")]
impl SocketZmqPublisher {
    /// Binds one PUB socket per unique endpoint in `publications`.
    ///
    /// Exact `(topic, endpoint)` pairs are recorded once so layered duplicate
    /// config cannot double-publish or double-report the same notifier, while
    /// distinct topics sharing an endpoint remain separate.
    pub fn bind(publications: &[ZmqPublication]) -> Result<Self> {
        let context = zmq::Context::new();
        let mut endpoints = Vec::new();
        let mut endpoint_indices = HashMap::<String, usize>::new();
        let mut endpoint_hwms = HashMap::<String, u32>::new();
        let mut hashblock_endpoints = Vec::new();
        let mut hashtx_endpoints = Vec::new();
        let mut rawblock_endpoints = Vec::new();
        let mut rawtx_endpoints = Vec::new();
        let mut sequence_endpoints = Vec::new();
        let mut notifiers = Vec::new();
        let mut seen_notifiers = HashSet::<(ZmqTopic, String)>::new();

        for publication in publications {
            if let Some(existing_hwm) = endpoint_hwms.get(&publication.endpoint) {
                if *existing_hwm != publication.hwm {
                    bail!(
                        "conflicting ZMQ HWM for endpoint {}: {} vs {}",
                        publication.endpoint,
                        existing_hwm,
                        publication.hwm
                    );
                }
            } else {
                endpoint_hwms.insert(publication.endpoint.clone(), publication.hwm);
            }

            let endpoint_index = if let Some(index) = endpoint_indices.get(&publication.endpoint) {
                *index
            } else {
                let socket = context.socket(zmq::PUB).context("create ZMQ PUB socket")?;
                let hwm = i32::try_from(publication.hwm).context("ZMQ HWM exceeds i32")?;
                socket.set_sndhwm(hwm).with_context(|| {
                    format!("set ZMQ SNDHWM for endpoint {}", publication.endpoint)
                })?;
                socket.set_linger(0).with_context(|| {
                    format!("set ZMQ LINGER for endpoint {}", publication.endpoint)
                })?;
                if is_ipv6_tcp_endpoint(&publication.endpoint) {
                    socket.set_ipv6(true).with_context(|| {
                        format!("set ZMQ IPv6 for endpoint {}", publication.endpoint)
                    })?;
                }
                socket
                    .bind(&publication.endpoint)
                    .with_context(|| format!("bind ZMQ PUB endpoint {}", publication.endpoint))?;
                let index = endpoints.len();
                endpoints.push(EndpointSocket {
                    endpoint: publication.endpoint.clone(),
                    socket: Mutex::new(socket),
                });
                endpoint_indices.insert(publication.endpoint.clone(), index);
                index
            };

            // Recorded in publication order so enumeration mirrors Core's
            // notifier creation order; the facts are read live from the bound
            // publisher, never from pre-bind configuration elsewhere.
            // Exact `(topic, endpoint)` duplicates are skipped so layered
            // config cannot invent a second identical notifier or publish path.
            if !seen_notifiers.insert((publication.topic, publication.endpoint.clone())) {
                continue;
            }

            notifiers.push(ZmqNotifier {
                topic: publication.topic,
                endpoint: publication.endpoint.clone(),
                hwm: publication.hwm,
            });

            match publication.topic {
                ZmqTopic::HashBlock => hashblock_endpoints.push(endpoint_index),
                ZmqTopic::HashTx => hashtx_endpoints.push(endpoint_index),
                ZmqTopic::RawBlock => rawblock_endpoints.push(endpoint_index),
                ZmqTopic::RawTx => rawtx_endpoints.push(endpoint_index),
                ZmqTopic::Sequence => sequence_endpoints.push(endpoint_index),
            }
        }

        Ok(Self {
            _context: context,
            endpoints,
            hashblock_endpoints,
            hashtx_endpoints,
            rawblock_endpoints,
            rawtx_endpoints,
            sequence_endpoints,
            notifiers,
            counters: core::array::from_fn(|_| AtomicU32::new(0)),
        })
    }

    fn publish(&self, topic: ZmqTopic, body: &[u8]) {
        let sequence_value = self.counters[topic.index()].fetch_add(1, Ordering::Relaxed);
        let sequence = sequence_body(sequence_value);
        let topic_bytes = topic.as_str().as_bytes();
        for endpoint_index in self.endpoints_for(topic) {
            let endpoint = &self.endpoints[*endpoint_index];
            let socket = endpoint.socket.lock();
            if let Err(error) =
                socket.send_multipart([topic_bytes, body, sequence.as_slice()], zmq::DONTWAIT)
            {
                tracing::debug!(
                    target: "bitcoin_rs_node::zmq",
                    %error,
                    endpoint = %endpoint.endpoint,
                    topic = topic.as_str(),
                    "dropping ZMQ notification"
                );
            }
        }
    }

    fn endpoints_for(&self, topic: ZmqTopic) -> &[usize] {
        match topic {
            ZmqTopic::HashBlock => &self.hashblock_endpoints,
            ZmqTopic::HashTx => &self.hashtx_endpoints,
            ZmqTopic::RawBlock => &self.rawblock_endpoints,
            ZmqTopic::RawTx => &self.rawtx_endpoints,
            ZmqTopic::Sequence => &self.sequence_endpoints,
        }
    }
}

#[cfg(feature = "zmq")]
impl ZmqPublisher for SocketZmqPublisher {
    fn wants_notifications(&self) -> bool {
        !self.endpoints.is_empty()
    }

    fn wants_rawtx(&self) -> bool {
        !self.rawtx_endpoints.is_empty()
    }

    fn wants_rawblock(&self) -> bool {
        !self.rawblock_endpoints.is_empty()
    }

    fn active_notifiers(&self) -> Vec<ZmqNotifier> {
        self.notifiers.clone()
    }

    fn publish_hashblock(&self, hash: Hash256) {
        let body = hash_body_from_hash(hash);
        self.publish(ZmqTopic::HashBlock, &body);
    }

    fn publish_hashtx(&self, txid: Txid) {
        let body = hash_body_from_txid(txid);
        self.publish(ZmqTopic::HashTx, &body);
    }

    fn publish_rawblock(&self, bytes: &[u8]) {
        self.publish(ZmqTopic::RawBlock, bytes);
    }

    fn publish_rawtx(&self, bytes: &[u8]) {
        self.publish(ZmqTopic::RawTx, bytes);
    }

    fn publish_sequence(&self, event: SequenceEvent) {
        self.publish(ZmqTopic::Sequence, &sequence_payload(event));
    }
}

#[cfg(any(feature = "zmq", test))]
pub(crate) fn hash_body_from_hash(hash: Hash256) -> [u8; 32] {
    let mut body = hash.to_le_bytes();
    body.reverse();
    body
}

#[cfg(any(feature = "zmq", test))]
pub(crate) fn sequence_payload(event: SequenceEvent) -> [u8; 33] {
    let mut body = [0_u8; 33];
    body[..32].copy_from_slice(&hash_body_from_hash(event.hash()));
    body[32] = event.label();
    body
}

#[cfg(feature = "zmq")]
pub(crate) fn hash_body_from_txid(txid: Txid) -> [u8; 32] {
    let mut body = *txid.as_byte_array();
    body.reverse();
    body
}

#[cfg(any(feature = "zmq", test))]
pub(crate) const fn sequence_body(sequence: u32) -> [u8; 4] {
    sequence.to_le_bytes()
}

#[cfg(any(feature = "zmq", test))]
fn is_ipv6_tcp_endpoint(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("tcp://[") else {
        return false;
    };
    let Some((host, tail)) = rest.split_once(']') else {
        return false;
    };
    host.contains(':') && tail.starts_with(':') && tail.len() > 1
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "zmq")]
    use std::thread;
    #[cfg(feature = "zmq")]
    use std::time::{Duration, Instant};

    #[test]
    fn noop_publisher_methods_are_callable() {
        let publisher = NoOpZmqPublisher;
        assert!(!publisher.wants_notifications());
        assert!(!publisher.wants_rawtx());
        assert!(!publisher.wants_rawblock());
        publisher.publish_hashblock(Hash256::default());
        publisher.publish_hashtx(bitcoin::Txid::from_byte_array([0; 32]));
        publisher.publish_rawblock(&[]);
        publisher.publish_rawtx(&[]);
        publisher.publish_sequence(SequenceEvent::Connected(Hash256::default()));
    }

    #[test]
    fn tracing_publisher_methods_are_callable() {
        let publisher = TracingZmqPublisher;
        assert!(publisher.wants_notifications());
        assert!(publisher.wants_rawtx());
        assert!(publisher.wants_rawblock());
        publisher.publish_hashblock(Hash256::default());
        publisher.publish_hashtx(bitcoin::Txid::from_byte_array([0; 32]));
        publisher.publish_rawblock(&[1, 2, 3]);
        publisher.publish_rawtx(&[4, 5, 6]);
        publisher.publish_sequence(SequenceEvent::Disconnected(Hash256::default()));
    }

    #[test]
    fn helper_reverses_hash_body_and_encodes_sequence_little_endian() {
        let mut le = [0_u8; 32];
        for (index, byte) in le.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap_or_else(|err| panic!("index fits: {err}"));
        }
        let hash = Hash256::from_le_bytes(&le);
        let mut expected = le;
        expected.reverse();

        assert_eq!(hash_body_from_hash(hash), expected);
        assert_eq!(sequence_body(0x0102_0304), [0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn sequence_event_payload_uses_core_hash_orientation_and_label() {
        let le = core::array::from_fn(|index| u8::try_from(index).unwrap_or_default());
        let hash = Hash256::from_le_bytes(&le);
        assert_eq!(
            sequence_payload(SequenceEvent::Connected(hash)),
            [
                31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
                10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, b'C'
            ]
        );
        assert_eq!(
            sequence_payload(SequenceEvent::Disconnected(hash)),
            [
                31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
                10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, b'D'
            ]
        );
    }

    #[test]
    fn detects_ipv6_tcp_endpoints_requiring_zmq_ipv6() {
        assert!(is_ipv6_tcp_endpoint("tcp://[::1]:28332"));
        assert!(is_ipv6_tcp_endpoint("tcp://[2001:db8::1]:28332"));
        assert!(!is_ipv6_tcp_endpoint("tcp://127.0.0.1:28332"));
        assert!(!is_ipv6_tcp_endpoint("tcp://localhost:28332"));
        assert!(!is_ipv6_tcp_endpoint("tcp://[::1]"));
        assert!(!is_ipv6_tcp_endpoint("ipc://[::1]:28332"));
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn socket_publisher_rejects_conflicting_hwm_for_same_endpoint() {
        let endpoint = "inproc://bitcoin-rs-zmq-conflict".to_owned();
        let publications = vec![
            ZmqPublication {
                topic: ZmqTopic::HashBlock,
                endpoint: endpoint.clone(),
                hwm: 1,
            },
            ZmqPublication {
                topic: ZmqTopic::RawBlock,
                endpoint,
                hwm: 2,
            },
        ];

        assert!(SocketZmqPublisher::bind(&publications).is_err());
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn socket_publisher_reports_rawtx_interest_from_configured_topics() -> anyhow::Result<()> {
        let without_rawtx = SocketZmqPublisher::bind(&[ZmqPublication {
            topic: ZmqTopic::HashBlock,
            endpoint: "inproc://bitcoin-rs-zmq-hashblock-only".to_owned(),
            hwm: 1,
        }])?;
        assert!(without_rawtx.wants_notifications());
        assert!(!without_rawtx.wants_rawtx());
        assert!(!without_rawtx.wants_rawblock());

        let with_rawtx = SocketZmqPublisher::bind(&[ZmqPublication {
            topic: ZmqTopic::RawTx,
            endpoint: "inproc://bitcoin-rs-zmq-rawtx".to_owned(),
            hwm: 1,
        }])?;
        assert!(with_rawtx.wants_notifications());
        assert!(with_rawtx.wants_rawtx());
        assert!(!with_rawtx.wants_rawblock());

        let with_rawblock = SocketZmqPublisher::bind(&[ZmqPublication {
            topic: ZmqTopic::RawBlock,
            endpoint: "inproc://bitcoin-rs-zmq-rawblock".to_owned(),
            hwm: 1,
        }])?;
        assert!(with_rawblock.wants_notifications());
        assert!(!with_rawblock.wants_rawtx());
        assert!(with_rawblock.wants_rawblock());
        Ok(())
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn socket_publisher_delivers_pub_sub_multipart_notification() -> anyhow::Result<()> {
        let socket_dir = tempfile::tempdir()?;
        let socket_path = socket_dir.path().join("hashblock.sock");
        let endpoint = format!("ipc://{}", socket_path.display());
        let publications = vec![ZmqPublication {
            topic: ZmqTopic::HashBlock,
            endpoint: endpoint.clone(),
            hwm: 10,
        }];
        let publisher = SocketZmqPublisher::bind(&publications)?;
        let context = zmq::Context::new();
        let subscriber = context.socket(zmq::SUB)?;
        subscriber.set_subscribe(ZmqTopic::HashBlock.as_str().as_bytes())?;
        subscriber.connect(&endpoint)?;

        let hash = Hash256::from_le_bytes(&[0x11_u8; 32]);
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            publisher.publish_hashblock(hash);
            match subscriber.recv_multipart(zmq::DONTWAIT) {
                Ok(frames) => {
                    assert_eq!(frames.len(), 3);
                    assert_eq!(frames[0].as_slice(), b"hashblock");
                    assert_eq!(frames[1].as_slice(), hash_body_from_hash(hash).as_slice());
                    assert_eq!(frames[2].len(), 4);
                    return Ok(());
                }
                Err(zmq::Error::EAGAIN) => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error.into()),
            }
        }

        anyhow::bail!("timed out waiting for ZMQ PUB/SUB notification")
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn socket_publisher_delivers_shared_sequence_stream() -> anyhow::Result<()> {
        let socket_dir = tempfile::tempdir()?;
        let socket_path = socket_dir.path().join("sequence.sock");
        let endpoint = format!("ipc://{}", socket_path.display());
        let publisher = SocketZmqPublisher::bind(&[ZmqPublication {
            topic: ZmqTopic::Sequence,
            endpoint: endpoint.clone(),
            hwm: 10,
        }])?;
        let context = zmq::Context::new();
        let subscriber = context.socket(zmq::SUB)?;
        subscriber.set_subscribe(b"sequence")?;
        subscriber.connect(&endpoint)?;

        let hash = Hash256::from_le_bytes(&[0x22_u8; 32]);
        thread::sleep(Duration::from_millis(100));
        publisher.publish_sequence(SequenceEvent::Connected(hash));
        publisher.publish_sequence(SequenceEvent::Disconnected(hash));
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut received = Vec::new();
        while Instant::now() < deadline && received.len() < 2 {
            match subscriber.recv_multipart(zmq::DONTWAIT) {
                Ok(frames) => received.push(frames),
                Err(zmq::Error::EAGAIN) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error.into()),
            }
        }
        assert_eq!(received.len(), 2);
        let connected = &received[0];
        let disconnected = &received[1];
        assert_eq!(connected[0], b"sequence");
        assert_eq!(connected[1].len(), 33);
        assert_eq!(connected[1][..32], hash_body_from_hash(hash));
        assert_eq!(connected[1][32], b'C');
        assert_eq!(disconnected[1][..32], hash_body_from_hash(hash));
        assert_eq!(disconnected[1][32], b'D');
        let connected_sequence = u32::from_le_bytes(connected[2].as_slice().try_into()?);
        let disconnected_sequence = u32::from_le_bytes(disconnected[2].as_slice().try_into()?);
        assert_eq!(disconnected_sequence, connected_sequence + 1);
        Ok(())
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn socket_publisher_enumerates_live_notifiers_in_publication_order() -> anyhow::Result<()> {
        use std::sync::Arc;

        let shared = "inproc://bitcoin-rs-zmq-enumerate-shared".to_owned();
        let dedicated = "inproc://bitcoin-rs-zmq-enumerate-dedicated".to_owned();
        let publisher = SocketZmqPublisher::bind(&[
            ZmqPublication {
                topic: ZmqTopic::HashBlock,
                endpoint: shared.clone(),
                hwm: 5,
            },
            ZmqPublication {
                topic: ZmqTopic::RawTx,
                endpoint: shared.clone(),
                hwm: 5,
            },
            ZmqPublication {
                topic: ZmqTopic::Sequence,
                endpoint: dedicated.clone(),
                hwm: 9,
            },
        ])?;

        // Read through the trait object — the path RPC consumers take — so the
        // enumeration is proven to live on the `dyn ZmqPublisher` surface.
        let publisher: Arc<dyn ZmqPublisher> = Arc::new(publisher);
        assert_eq!(
            publisher.active_notifiers(),
            vec![
                ZmqNotifier {
                    topic: ZmqTopic::HashBlock,
                    endpoint: shared.clone(),
                    hwm: 5,
                },
                ZmqNotifier {
                    topic: ZmqTopic::RawTx,
                    endpoint: shared,
                    hwm: 5,
                },
                ZmqNotifier {
                    topic: ZmqTopic::Sequence,
                    endpoint: dedicated,
                    hwm: 9,
                },
            ],
            "enumeration must report every bound publication in bind order with its own hwm"
        );
        Ok(())
    }

    #[test]
    fn non_socket_publishers_report_no_live_notifiers() {
        use std::sync::Arc;

        let noop: Arc<dyn ZmqPublisher> = Arc::new(NoOpZmqPublisher);
        assert!(
            noop.active_notifiers().is_empty(),
            "a publisher with no bound endpoints has no live notifier"
        );
        let tracing: Arc<dyn ZmqPublisher> = Arc::new(TracingZmqPublisher);
        assert!(tracing.active_notifiers().is_empty());
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn socket_publisher_deduplicates_exact_topic_endpoint_pairs() -> anyhow::Result<()> {
        use std::sync::Arc;

        let shared = "inproc://bitcoin-rs-zmq-dedupe-shared".to_owned();
        let other = "inproc://bitcoin-rs-zmq-dedupe-other".to_owned();
        let publisher = SocketZmqPublisher::bind(&[
            ZmqPublication {
                topic: ZmqTopic::HashBlock,
                endpoint: shared.clone(),
                hwm: 5,
            },
            // Layered duplicate of the exact (topic, endpoint) pair.
            ZmqPublication {
                topic: ZmqTopic::HashBlock,
                endpoint: shared.clone(),
                hwm: 5,
            },
            // Distinct topic on the same endpoint must remain separate.
            ZmqPublication {
                topic: ZmqTopic::RawTx,
                endpoint: shared.clone(),
                hwm: 5,
            },
            // Same topic on a different endpoint remains separate.
            ZmqPublication {
                topic: ZmqTopic::HashBlock,
                endpoint: other.clone(),
                hwm: 5,
            },
        ])?;

        let publisher: Arc<dyn ZmqPublisher> = Arc::new(publisher);
        assert_eq!(
            publisher.active_notifiers(),
            vec![
                ZmqNotifier {
                    topic: ZmqTopic::HashBlock,
                    endpoint: shared.clone(),
                    hwm: 5,
                },
                ZmqNotifier {
                    topic: ZmqTopic::RawTx,
                    endpoint: shared,
                    hwm: 5,
                },
                ZmqNotifier {
                    topic: ZmqTopic::HashBlock,
                    endpoint: other,
                    hwm: 5,
                },
            ],
            "exact (topic, endpoint) duplicates collapse; distinct topics/endpoints remain"
        );
        Ok(())
    }
}
