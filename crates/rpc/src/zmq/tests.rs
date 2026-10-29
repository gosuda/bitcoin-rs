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
fn rejects_zero_zmq_hwm_before_socket_binding() {
    let config = ZmqEndpointConfig {
        endpoint: "inproc://bitcoin-rs-zmq-zero-hwm".to_owned(),
        topics: vec![ZmqTopic::RawBlock],
        hwm: Some(0),
    };
    let Err(error) = validate_endpoint_configs(std::slice::from_ref(&config)) else {
        panic!("zero HWM must fail configuration validation");
    };
    assert!(
        error.to_string().contains("ZMQ HWM must be positive"),
        "{error}"
    );

    #[cfg(feature = "zmq")]
    {
        let Err(error) = SocketZmqPublisher::bind(&[config]) else {
            panic!("zero HWM must also fail socket binding");
        };
        assert!(
            error.to_string().contains("ZMQ HWM must be positive"),
            "{error}"
        );
    }
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

    assert_eq!(reversed_hash_body(hash.to_le_bytes()), expected);
    assert_eq!(sequence_body(0x0102_0304), [0x04, 0x03, 0x02, 0x01]);
}

#[test]
fn sequence_event_payload_uses_core_hash_orientation_and_label() {
    let le = core::array::from_fn(|index| u8::try_from(index).unwrap_or_default());
    let hash = Hash256::from_le_bytes(&le);
    assert_eq!(
        sequence_payload(SequenceEvent::Connected(hash)),
        [
            31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
            9, 8, 7, 6, 5, 4, 3, 2, 1, 0, b'C'
        ]
    );
    assert_eq!(
        sequence_payload(SequenceEvent::Disconnected(hash)),
        [
            31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
            9, 8, 7, 6, 5, 4, 3, 2, 1, 0, b'D'
        ]
    );
}

#[test]
fn mempool_event_payloads_carry_reversed_txid_label_and_le_sequence() {
    let txid = Txid(Hash256::from_le_bytes(&[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
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
                assert_eq!(
                    frames[1].as_slice(),
                    reversed_hash_body(hash.to_le_bytes()).as_slice()
                );
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
    assert_eq!(connected[1][..32], reversed_hash_body(hash.to_le_bytes()));
    assert_eq!(connected[1][32], b'C');
    assert_eq!(
        disconnected[1][..32],
        reversed_hash_body(hash.to_le_bytes())
    );
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
