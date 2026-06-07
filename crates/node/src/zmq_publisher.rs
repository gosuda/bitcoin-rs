//! ZMQ publisher trait and transport-backed implementation for node notifications.
//!
//! Bitcoin Core publishes "hashblock", "hashtx", "rawblock", and "rawtx" events
//! via ZMQ for client subscribers. `bitcoin-rs` keeps the apply path behind a
//! small trait so notification failures cannot affect block connection.

use core::fmt;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Context as _, Result, bail};
use bitcoin::Txid;
use bitcoin::hashes::Hash as _;
use bitcoin_rs_primitives::Hash256;
use hashbrown::HashMap;
use parking_lot::Mutex;

use crate::config::ZmqPublication;

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
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::HashBlock => 0,
            Self::HashTx => 1,
            Self::RawBlock => 2,
            Self::RawTx => 3,
        }
    }
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

    /// Publish a `hashblock` notification (block hash big-endian display bytes).
    fn publish_hashblock(&self, hash: Hash256);

    /// Publish a `hashtx` notification (transaction id big-endian display bytes).
    fn publish_hashtx(&self, txid: Txid);

    /// Publish a `rawblock` notification with the serialized block bytes.
    fn publish_rawblock(&self, bytes: &[u8]);

    /// Publish a `rawtx` notification with the serialized transaction bytes.
    fn publish_rawtx(&self, bytes: &[u8]);
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
}

struct EndpointSocket {
    endpoint: String,
    socket: Mutex<zmq::Socket>,
}

/// Socket-backed ZMQ PUB publisher.
pub struct SocketZmqPublisher {
    _context: zmq::Context,
    endpoints: Vec<EndpointSocket>,
    hashblock_endpoints: Vec<usize>,
    hashtx_endpoints: Vec<usize>,
    rawblock_endpoints: Vec<usize>,
    rawtx_endpoints: Vec<usize>,
    counters: [AtomicU32; 4],
}

impl fmt::Debug for SocketZmqPublisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketZmqPublisher")
            .field("endpoints", &self.endpoints.len())
            .finish_non_exhaustive()
    }
}

impl SocketZmqPublisher {
    /// Binds one PUB socket per unique endpoint in `publications`.
    pub fn bind(publications: &[ZmqPublication]) -> Result<Self> {
        let context = zmq::Context::new();
        let mut endpoints = Vec::new();
        let mut endpoint_indices = HashMap::<String, usize>::new();
        let mut endpoint_hwms = HashMap::<String, u32>::new();
        let mut hashblock_endpoints = Vec::new();
        let mut hashtx_endpoints = Vec::new();
        let mut rawblock_endpoints = Vec::new();
        let mut rawtx_endpoints = Vec::new();

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

            match publication.topic {
                ZmqTopic::HashBlock => hashblock_endpoints.push(endpoint_index),
                ZmqTopic::HashTx => hashtx_endpoints.push(endpoint_index),
                ZmqTopic::RawBlock => rawblock_endpoints.push(endpoint_index),
                ZmqTopic::RawTx => rawtx_endpoints.push(endpoint_index),
            }
        }

        Ok(Self {
            _context: context,
            endpoints,
            hashblock_endpoints,
            hashtx_endpoints,
            rawblock_endpoints,
            rawtx_endpoints,
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
        }
    }
}

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
}

pub(crate) fn hash_body_from_hash(hash: Hash256) -> [u8; 32] {
    let mut body = hash.to_le_bytes();
    body.reverse();
    body
}

pub(crate) fn hash_body_from_txid(txid: Txid) -> [u8; 32] {
    let mut body = *txid.as_byte_array();
    body.reverse();
    body
}

pub(crate) const fn sequence_body(sequence: u32) -> [u8; 4] {
    sequence.to_le_bytes()
}

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
    use std::thread;
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
    fn detects_ipv6_tcp_endpoints_requiring_zmq_ipv6() {
        assert!(is_ipv6_tcp_endpoint("tcp://[::1]:28332"));
        assert!(is_ipv6_tcp_endpoint("tcp://[2001:db8::1]:28332"));
        assert!(!is_ipv6_tcp_endpoint("tcp://127.0.0.1:28332"));
        assert!(!is_ipv6_tcp_endpoint("tcp://localhost:28332"));
        assert!(!is_ipv6_tcp_endpoint("tcp://[::1]"));
        assert!(!is_ipv6_tcp_endpoint("ipc://[::1]:28332"));
    }

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
}
