//! ZMQ publisher trait and transport-backed implementation for node notifications.
//!
//! Bitcoin Core publishes "hashblock", "hashtx", "rawblock", and "rawtx" events
//! via ZMQ for client subscribers. `bitcoin-rs` keeps the apply path behind a
//! small trait so notification failures cannot affect block connection.

#[cfg(feature = "zmq")]
use anyhow::{Context as _, Result, bail, ensure};
#[cfg(not(feature = "zmq"))]
use anyhow::{Result, ensure};
use bitcoin_rs_primitives::{Hash256, Txid};
#[cfg(feature = "zmq")]
use core::fmt;
#[cfg(feature = "zmq")]
use hashbrown::HashSet;
#[cfg(feature = "zmq")]
use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::HashSet as StdHashSet;
#[cfg(feature = "zmq")]
use std::sync::atomic::{AtomicU32, Ordering};

/// ZMQ PUB notification topic.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
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

/// Default outbound queue limit for one ZMQ PUB endpoint.
pub const DEFAULT_ZMQ_HWM: u32 = 1_000;

/// Configuration for one ZMQ PUB socket.
///
/// Topics sharing an endpoint necessarily share its socket-level HWM.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ZmqEndpointConfig {
    /// ZMQ endpoint to bind.
    pub endpoint: String,
    /// Notification topics published through this endpoint.
    pub topics: Vec<ZmqTopic>,
    /// Optional override for the publisher-owned queue limit.
    #[serde(default)]
    pub hwm: Option<u32>,
}

impl ZmqEndpointConfig {
    /// Returns the socket HWM after applying the publisher default.
    #[must_use]
    pub fn effective_hwm(&self) -> u32 {
        self.hwm.unwrap_or(DEFAULT_ZMQ_HWM)
    }
}

/// Validates grouped ZMQ configuration before it reaches a runtime boundary.
pub fn validate_endpoint_configs(configs: &[ZmqEndpointConfig]) -> Result<()> {
    let mut endpoints = StdHashSet::new();
    for config in configs {
        ensure!(
            !config.endpoint.trim().is_empty(),
            "ZMQ endpoint must not be empty"
        );
        ensure!(
            !config.topics.is_empty(),
            "ZMQ endpoint {} must have at least one topic",
            config.endpoint
        );
        ensure!(
            endpoints.insert(&config.endpoint),
            "duplicate ZMQ endpoint: {}",
            config.endpoint
        );
        ensure!(
            i32::try_from(config.effective_hwm()).is_ok(),
            "ZMQ HWM exceeds libzmq's signed SNDHWM range: {}",
            config.effective_hwm()
        );
        let mut topics = StdHashSet::new();
        for topic in &config.topics {
            ensure!(
                topics.insert(topic),
                "duplicate ZMQ topic on endpoint: {}",
                config.endpoint
            );
        }
    }
    Ok(())
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
    /// A transaction was admitted to the mempool, with the mempool sequence
    /// assigned to the admission.
    Added(Txid, u64),
    /// A transaction left the mempool, with the mempool sequence assigned to
    /// the removal. Block-inclusion removals never publish this event: Core
    /// suppresses `R` when the block's own `C` event already covers the
    /// departure.
    Removed(Txid, u64),
}

impl SequenceEvent {
    const fn label(self) -> u8 {
        match self {
            Self::Connected(_) => b'C',
            Self::Disconnected(_) => b'D',
            Self::Added(..) => b'A',
            Self::Removed(..) => b'R',
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
        let subject = match event {
            SequenceEvent::Connected(hash) | SequenceEvent::Disconnected(hash) => {
                hash.to_string_be()
            }
            SequenceEvent::Added(txid, _) | SequenceEvent::Removed(txid, _) => txid.to_string(),
        };
        tracing::info!(
            target: "bitcoin_rs_node::zmq",
            topic = "sequence",
            hash = %subject,
            label = char::from(event.label()).to_string(),
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
    /// Binds one PUB socket per endpoint group.
    ///
    /// Duplicate endpoint groups are rejected because one endpoint identifies
    /// one owned socket and one HWM. Duplicate topics inside a group are
    /// recorded once.
    pub fn bind(endpoint_configs: &[ZmqEndpointConfig]) -> Result<Self> {
        let deduped_configs: Vec<ZmqEndpointConfig> = endpoint_configs
            .iter()
            .map(|config| {
                let mut seen = StdHashSet::new();
                ZmqEndpointConfig {
                    endpoint: config.endpoint.clone(),
                    topics: config
                        .topics
                        .iter()
                        .filter(|&&topic| seen.insert(topic))
                        .copied()
                        .collect(),
                    hwm: config.hwm,
                }
            })
            .collect();
        validate_endpoint_configs(&deduped_configs)?;
        let context = zmq::Context::new();
        let mut endpoints = Vec::new();
        let mut bound_endpoints = HashSet::<String>::new();
        let mut hashblock_endpoints = Vec::new();
        let mut hashtx_endpoints = Vec::new();
        let mut rawblock_endpoints = Vec::new();
        let mut rawtx_endpoints = Vec::new();
        let mut sequence_endpoints = Vec::new();
        let mut notifiers = Vec::new();
        let mut seen_notifiers = HashSet::<(ZmqTopic, String)>::new();

        for endpoint_config in &deduped_configs {
            if !bound_endpoints.insert(endpoint_config.endpoint.clone()) {
                bail!("duplicate ZMQ endpoint {}", endpoint_config.endpoint);
            }
            let hwm = endpoint_config.effective_hwm();
            let socket = context.socket(zmq::PUB).context("create ZMQ PUB socket")?;
            socket
                .set_sndhwm(i32::try_from(hwm).context("ZMQ HWM exceeds i32")?)
                .with_context(|| {
                    format!("set ZMQ SNDHWM for endpoint {}", endpoint_config.endpoint)
                })?;
            socket.set_linger(0).with_context(|| {
                format!("set ZMQ LINGER for endpoint {}", endpoint_config.endpoint)
            })?;
            if is_ipv6_tcp_endpoint(&endpoint_config.endpoint) {
                socket.set_ipv6(true).with_context(|| {
                    format!("set ZMQ IPv6 for endpoint {}", endpoint_config.endpoint)
                })?;
            }
            socket
                .bind(&endpoint_config.endpoint)
                .with_context(|| format!("bind ZMQ PUB endpoint {}", endpoint_config.endpoint))?;
            let endpoint_index = endpoints.len();
            endpoints.push(EndpointSocket {
                endpoint: endpoint_config.endpoint.clone(),
                socket: Mutex::new(socket),
            });
            for &topic in &endpoint_config.topics {
                if !seen_notifiers.insert((topic, endpoint_config.endpoint.clone())) {
                    continue;
                }
                notifiers.push(ZmqNotifier {
                    topic,
                    endpoint: endpoint_config.endpoint.clone(),
                    hwm,
                });
                match topic {
                    ZmqTopic::HashBlock => hashblock_endpoints.push(endpoint_index),
                    ZmqTopic::HashTx => hashtx_endpoints.push(endpoint_index),
                    ZmqTopic::RawBlock => rawblock_endpoints.push(endpoint_index),
                    ZmqTopic::RawTx => rawtx_endpoints.push(endpoint_index),
                    ZmqTopic::Sequence => sequence_endpoints.push(endpoint_index),
                }
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

/// Body frame for a `sequence` topic event: the reversed hash/txid bytes and
/// the label byte, plus — for mempool `A`/`R` events — the mempool sequence
/// as a little-endian u64. The transport's own 4-byte counter stays in its
/// separate trailing frame.
#[cfg(any(feature = "zmq", test))]
pub(crate) fn sequence_payload(event: SequenceEvent) -> Vec<u8> {
    match event {
        SequenceEvent::Added(txid, mempool_sequence)
        | SequenceEvent::Removed(txid, mempool_sequence) => {
            let mut body = Vec::with_capacity(41);
            body.extend_from_slice(&hash_body_from_txid(txid));
            body.push(event.label());
            body.extend_from_slice(&mempool_sequence.to_le_bytes());
            body
        }
        SequenceEvent::Connected(hash) | SequenceEvent::Disconnected(hash) => {
            let mut body = Vec::with_capacity(33);
            body.extend_from_slice(&hash_body_from_hash(hash));
            body.push(event.label());
            body
        }
    }
}

#[cfg(any(feature = "zmq", test))]
pub(crate) fn hash_body_from_txid(txid: Txid) -> [u8; 32] {
    let mut body = *txid.as_bytes();
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

    #[cfg(feature = "zmq")]
    fn endpoint(endpoint: impl Into<String>, topics: Vec<ZmqTopic>, hwm: u32) -> ZmqEndpointConfig {
        ZmqEndpointConfig {
            endpoint: endpoint.into(),
            topics,
            hwm: Some(hwm),
        }
    }

    #[test]
    fn noop_publisher_methods_are_callable() {
        let publisher = NoOpZmqPublisher;
        assert!(!publisher.wants_notifications());
        assert!(!publisher.wants_rawtx());
        assert!(!publisher.wants_rawblock());
        publisher.publish_hashblock(Hash256::default());
        publisher.publish_hashtx(Txid(Hash256::from_le_bytes(&[0; 32])));
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
        publisher.publish_hashtx(Txid(Hash256::from_le_bytes(&[0; 32])));
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
    fn mempool_event_payloads_carry_reversed_txid_label_and_le_sequence() {
        let txid = Txid(Hash256::from_le_bytes(&[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]));
        let mut reversed = *txid.as_bytes();
        reversed.reverse();

        let added = sequence_payload(SequenceEvent::Added(txid, 1));
        assert_eq!(added.len(), 41);
        assert_eq!(added[..32], reversed);
        assert_eq!(added[32], b'A');
        assert_eq!(added[33..], 0x0000_0000_0000_0001_u64.to_le_bytes());

        let removed = sequence_payload(SequenceEvent::Removed(txid, 0xFF00_0000_0000_0042));
        assert_eq!(removed.len(), 41);
        assert_eq!(removed[..32], reversed);
        assert_eq!(removed[32], b'R');
        assert_eq!(removed[33..], 0xFF00_0000_0000_0042_u64.to_le_bytes());

        // A hash256 conversion round-trips through the observer's mapping.
        assert_eq!(Txid(Hash256::from_le_bytes(txid.as_bytes())), txid);
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
    fn socket_publisher_rejects_duplicate_endpoint_groups() {
        let endpoint = "inproc://bitcoin-rs-zmq-conflict".to_owned();
        let publications = vec![
            self::endpoint(endpoint.clone(), vec![ZmqTopic::HashBlock], 1),
            self::endpoint(endpoint, vec![ZmqTopic::RawBlock], 2),
        ];

        assert!(SocketZmqPublisher::bind(&publications).is_err());
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn socket_publisher_reports_rawtx_interest_from_configured_topics() -> anyhow::Result<()> {
        let without_rawtx = SocketZmqPublisher::bind(&[endpoint(
            "inproc://bitcoin-rs-zmq-hashblock-only",
            vec![ZmqTopic::HashBlock],
            1,
        )])?;
        assert!(without_rawtx.wants_notifications());
        assert!(!without_rawtx.wants_rawtx());
        assert!(!without_rawtx.wants_rawblock());

        let with_rawtx = SocketZmqPublisher::bind(&[endpoint(
            "inproc://bitcoin-rs-zmq-rawtx",
            vec![ZmqTopic::RawTx],
            1,
        )])?;
        assert!(with_rawtx.wants_notifications());
        assert!(with_rawtx.wants_rawtx());
        assert!(!with_rawtx.wants_rawblock());

        let with_rawblock = SocketZmqPublisher::bind(&[endpoint(
            "inproc://bitcoin-rs-zmq-rawblock",
            vec![ZmqTopic::RawBlock],
            1,
        )])?;
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
        let publications = vec![self::endpoint(
            endpoint.clone(),
            vec![ZmqTopic::HashBlock],
            10,
        )];
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
        let publisher = SocketZmqPublisher::bind(&[self::endpoint(
            endpoint.clone(),
            vec![ZmqTopic::Sequence],
            10,
        )])?;
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
            endpoint(
                shared.clone(),
                vec![ZmqTopic::HashBlock, ZmqTopic::RawTx],
                5,
            ),
            endpoint(dedicated.clone(), vec![ZmqTopic::Sequence], 9),
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
            endpoint(
                shared.clone(),
                vec![ZmqTopic::HashBlock, ZmqTopic::HashBlock, ZmqTopic::RawTx],
                5,
            ),
            endpoint(other.clone(), vec![ZmqTopic::HashBlock], 5),
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

#[cfg(test)]
mod compat_manifest_tests {
    use super::ZmqTopic;

    /// The compatibility manifest, embedded rather than read at runtime.
    const MANIFEST_TOML: &str = include_str!("../../../docs/api/core-compat.toml");

    /// Every topic this publisher publishes carries a compatibility claim.
    ///
    /// The RPC crate checks the manifest against a restated list, because it
    /// does not depend on this crate and cannot see [`ZmqTopic`]. This is the
    /// half that closes that gap: the names here are the ones that go on the
    /// wire, and a topic added without a manifest entry is an undeclared
    /// surface — which is exactly what the manifest exists to make impossible.
    ///
    /// Both the wire topic and the `getzmqnotifications` notifier name are
    /// checked. They differ by Core's `pub` prefix, and a client discovers a
    /// topic through the second in order to subscribe to the first, so a
    /// manifest that got either wrong would send it to the wrong socket.
    #[test]
    fn zmq_topic_names_match_the_compatibility_manifest() {
        let table: toml::Table = toml::from_str(MANIFEST_TOML)
            .unwrap_or_else(|err| panic!("the compatibility manifest must parse: {err}"));
        let Some(entries) = table.get("zmq").and_then(toml::Value::as_array) else {
            panic!("the manifest must carry a `zmq` array");
        };

        let published = [
            ZmqTopic::HashBlock,
            ZmqTopic::HashTx,
            ZmqTopic::RawBlock,
            ZmqTopic::RawTx,
            ZmqTopic::Sequence,
        ];
        assert_eq!(
            entries.len(),
            published.len(),
            "the manifest lists {} ZMQ topics and the publisher has {}",
            entries.len(),
            published.len()
        );

        for topic in published {
            let Some(entry) = entries.iter().find(|entry| {
                entry
                    .get("topic")
                    .and_then(toml::Value::as_str)
                    .is_some_and(|listed| listed == topic.as_str())
            }) else {
                panic!(
                    "`{}` is published but carries no compatibility claim",
                    topic.as_str()
                );
            };
            assert_eq!(
                entry.get("notifier").and_then(toml::Value::as_str),
                Some(topic.notifier_type()),
                "the manifest's notifier name for `{}` is not the one \
                 `getzmqnotifications` reports, so a client would subscribe \
                 to the wrong socket",
                topic.as_str()
            );
        }
    }
}
