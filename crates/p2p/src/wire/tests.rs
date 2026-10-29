use std::io::{Cursor, Read};

use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::Magic;

use super::{
    HEADER_LEN, MAX_MESSAGE_PAYLOAD, PeerError, encode_payload, read_message, wire_len,
    write_message,
};

struct HeaderOnlyReader {
    header: Cursor<Vec<u8>>,
}

impl Read for HeaderOnlyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.header.read(buf)?;
        if n == 0 {
            return Err(std::io::Error::other("read past 24-byte header"));
        }
        Ok(n)
    }
}

fn header_declaring(payload_len: usize) -> Result<Vec<u8>, PeerError> {
    let len = u32::try_from(payload_len)
        .map_err(|_| PeerError::Protocol("payload length does not fit in u32"))?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&Magic::REGTEST.to_bytes());
    header.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
    header.extend_from_slice(&len.to_le_bytes());
    header.extend_from_slice(&[0u8; 4]);
    Ok(header)
}

#[test]
fn observer_sees_valid_wire_payload_before_typed_decode() {
    let mut frame = Vec::with_capacity(HEADER_LEN);
    frame.extend_from_slice(&Magic::REGTEST.to_bytes());
    frame.extend_from_slice(b"version\0\0\0\0\0");
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&super::checksum(&[]));

    let mut observed = None;
    let result = super::V1Receiver::default().read_message_with(
        &mut Cursor::new(&frame),
        Magic::REGTEST,
        |command, payload| observed = Some((command.to_owned(), payload.to_vec())),
    );
    assert!(matches!(result, Err(PeerError::Encode(_))));
    assert_eq!(observed, Some(("version".to_owned(), Vec::new())));

    frame[20] ^= 1;
    let mut observed_bad_checksum = false;
    let result = super::V1Receiver::default().read_message_with(
        &mut Cursor::new(frame),
        Magic::REGTEST,
        |_, _| {
            observed_bad_checksum = true;
        },
    );
    assert!(matches!(result, Err(PeerError::BadChecksum)));
    assert!(!observed_bad_checksum);
}

#[test]
fn receiver_resumes_a_frame_split_by_poll_timeouts() -> Result<(), PeerError> {
    use crate::test_support::{Inbound, StallingStream};
    use std::io::ErrorKind;

    let mut ping = Vec::new();
    write_message(&mut ping, Magic::REGTEST, &super::Message::Ping(42))?;
    let mut pong = Vec::new();
    write_message(&mut pong, Magic::REGTEST, &super::Message::Pong(7))?;
    let mut stream = StallingStream::new([
        Inbound::Bytes(ping[..10].to_vec()),
        Inbound::Stall(ErrorKind::TimedOut),
        Inbound::Bytes(ping[10..HEADER_LEN + 3].to_vec()),
        Inbound::Stall(ErrorKind::WouldBlock),
        Inbound::Bytes([&ping[HEADER_LEN + 3..], pong.as_slice()].concat()),
    ]);

    let mut receiver = super::V1Receiver::default();
    for stall in [ErrorKind::TimedOut, ErrorKind::WouldBlock] {
        let result = receiver.read_message_with(&mut stream, Magic::REGTEST, |_, _| {});
        assert!(
            matches!(&result, Err(PeerError::Io(error)) if error.kind() == stall),
            "a stall surfaces as a retryable timeout, got {result:?}"
        );
    }
    let (first, _) = receiver.read_message_with(&mut stream, Magic::REGTEST, |_, _| {})?;
    assert_eq!(first, super::Message::Ping(42));
    let (second, _) = receiver.read_message_with(&mut stream, Magic::REGTEST, |_, _| {})?;
    assert_eq!(second, super::Message::Pong(7));
    Ok(())
}

#[test]
fn receiver_retains_only_received_bytes_for_a_stalled_frame() -> Result<(), PeerError> {
    use crate::test_support::{Inbound, OrFail, StallingStream};
    use std::io::ErrorKind;

    let dribble = [7u8; 100];
    let mut stream = StallingStream::new([
        Inbound::Bytes(header_declaring(MAX_MESSAGE_PAYLOAD)?),
        Inbound::Bytes(dribble.to_vec()),
        Inbound::Stall(ErrorKind::TimedOut),
    ]);
    let mut receiver = super::V1Receiver::default();
    let result = receiver.read_message_with(&mut stream, Magic::REGTEST, |_, _| {});
    assert!(
        matches!(&result, Err(PeerError::Io(error)) if error.kind() == ErrorKind::TimedOut),
        "a stall surfaces as a retryable timeout, got {result:?}"
    );
    let body = receiver
        .body
        .as_ref()
        .or_fail("the partial frame is retained across the timeout");
    assert_eq!(body.payload.len(), dribble.len());
    assert!(
        body.payload.capacity() <= crate::recv::RECEIVE_CHUNK,
        "no full-size allocation is retained for a stalled declared payload"
    );
    Ok(())
}

#[test]
fn receiver_restarts_at_a_frame_boundary_after_a_rejected_frame() -> Result<(), PeerError> {
    let mut corrupt = Vec::new();
    write_message(&mut corrupt, Magic::REGTEST, &super::Message::Ping(1))?;
    corrupt[HEADER_LEN] ^= 1;
    let mut valid = Vec::new();
    write_message(&mut valid, Magic::REGTEST, &super::Message::Pong(2))?;
    let mut stream = Cursor::new([corrupt, valid].concat());

    let mut receiver = super::V1Receiver::default();
    let rejected = receiver.read_message_with(&mut stream, Magic::REGTEST, |_, _| {});
    assert!(matches!(rejected, Err(PeerError::BadChecksum)));
    let (message, _) = receiver.read_message_with(&mut stream, Magic::REGTEST, |_, _| {})?;
    assert_eq!(message, super::Message::Pong(2));
    Ok(())
}

#[test]
fn block_message_roundtrip_preserves_wire_payload() -> Result<(), super::PeerError> {
    use bitcoin_rs_primitives::BlockPayload;

    let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let block_bytes = serialize(&block);
    let message = super::Message::Block(
        BlockPayload::from_raw(bytes::Bytes::from(block_bytes.clone()))
            .map_err(super::PeerError::NativeDecode)?,
    );
    let payload = encode_payload(&message)?;
    let expected_hash = block.block_hash();

    let mut wire = Vec::new();
    write_message(&mut wire, Magic::REGTEST, &message)?;

    let mut cursor = Cursor::new(wire);
    let (decoded, raw) = read_message(&mut cursor, Magic::REGTEST)?;

    let super::Message::Block(decoded_payload) = decoded else {
        return Err(super::PeerError::Protocol(
            "expected block message in roundtrip test",
        ));
    };

    assert_eq!(raw.as_ref(), decoded_payload.bytes().as_ref());
    assert_eq!(raw.as_ref(), payload.as_slice());
    assert_eq!(raw.as_ref(), block_bytes.as_slice());
    let native_hash = decoded_payload.block().header.compute_hash();
    assert_eq!(native_hash.as_bytes(), &expected_hash.to_byte_array());

    Ok(())
}

#[test]
fn read_message_rejects_oversized_payload_before_reading_body() -> Result<(), PeerError> {
    let oversize = MAX_MESSAGE_PAYLOAD + 1;
    let mut reader = HeaderOnlyReader {
        header: Cursor::new(header_declaring(oversize)?),
    };

    match read_message(&mut reader, Magic::REGTEST) {
        Err(PeerError::PayloadTooLarge(len)) => {
            assert_eq!(len, oversize);
            Ok(())
        }
        other => Err(PeerError::Protocol(match other {
            Err(PeerError::Io(_)) => "read past header: guard fired after body read",
            _ => "expected PayloadTooLarge for oversized payload length",
        })),
    }
}

#[test]
fn read_message_accepts_payload_length_at_exact_cap() -> Result<(), PeerError> {
    let mut reader = HeaderOnlyReader {
        header: Cursor::new(header_declaring(MAX_MESSAGE_PAYLOAD)?),
    };

    match read_message(&mut reader, Magic::REGTEST) {
        Err(PeerError::PayloadTooLarge(_)) => Err(PeerError::Protocol(
            "size guard rejected payload length exactly at the cap",
        )),
        Err(PeerError::Io(_)) => Ok(()),
        Err(_) => Err(PeerError::Protocol(
            "expected Io error from truncated body at exact cap",
        )),
        Ok(_) => Err(PeerError::Protocol(
            "truncated message unexpectedly decoded",
        )),
    }
}

#[test]
fn block_payload_writes_the_same_frame_as_decoded_block() -> Result<(), PeerError> {
    use bitcoin_rs_primitives::BlockPayload;

    let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let block_bytes = serialize(&block);
    let payload_bytes = bytes::Bytes::from(block_bytes);
    let decoded = super::Message::Block(
        BlockPayload::from_raw(payload_bytes.clone()).map_err(super::PeerError::NativeDecode)?,
    );
    let payload = super::Message::BlockPayload(payload_bytes);

    let mut decoded_wire = Vec::new();
    let mut payload_wire = Vec::new();
    write_message(&mut decoded_wire, Magic::REGTEST, &decoded)?;
    write_message(&mut payload_wire, Magic::REGTEST, &payload)?;
    assert_eq!(decoded_wire, payload_wire);
    assert_eq!(wire_len(&decoded)?, wire_len(&payload)?);
    Ok(())
}

#[test]
fn write_message_rejects_payload_exceeding_cap() -> Result<(), PeerError> {
    let oversize = MAX_MESSAGE_PAYLOAD + 1;
    let message = super::Message::Unknown {
        command: super::command_string("huge")?,
        payload: vec![0u8; oversize],
    };

    let mut sink = Vec::new();
    match write_message(&mut sink, Magic::REGTEST, &message) {
        Err(PeerError::PayloadTooLarge(len)) => {
            assert_eq!(len, oversize);
            assert!(sink.is_empty(), "nothing must be written on rejection");
            Ok(())
        }
        _ => Err(PeerError::Protocol(
            "expected PayloadTooLarge from encode path",
        )),
    }
}

#[test]
fn wire_len_matches_write_message_for_representative_messages() -> Result<(), PeerError> {
    let Some(feature_id) = crate::feature::FeatureId::advertised(b"test") else {
        return Err(PeerError::Protocol("expected valid advertised id"));
    };
    let messages = vec![
        super::Message::Tx(bitcoin_rs_primitives::Tx::default()),
        super::Message::Ping(0x1234_5678_9abc_def0),
        super::Message::Verack,
        super::Message::Headers(vec![bitcoin_rs_primitives::Header::default(); 2_000]),
        super::Message::Block(bitcoin_rs_primitives::BlockPayload::from_local(
            bitcoin_rs_primitives::Block::default(),
        )),
        super::Message::BlockPayload(bytes::Bytes::from(vec![0_u8; 80])),
        super::Message::Unknown {
            command: super::command_string("unknown")?,
            payload: vec![7; 61],
        },
        super::Message::Feature(crate::feature::FeatureAnnouncement::new(
            feature_id,
            vec![1, 2, 3],
        )),
    ];

    for message in &messages {
        let mut buffer = Vec::new();
        let written = write_message(&mut buffer, Magic::BITCOIN, message)?;
        assert_eq!(wire_len(message)?, written);
        assert_eq!(written, buffer.len());
    }
    Ok(())
}

#[test]
fn feature_message_v1_roundtrip() -> Result<(), PeerError> {
    let Some(feature_id) = crate::feature::FeatureId::advertised(b"BIP332") else {
        return Err(PeerError::Protocol("expected valid advertised id"));
    };
    let announcement = crate::feature::FeatureAnnouncement::new(feature_id, vec![1, 2, 3, 4]);
    let message = super::Message::Feature(announcement);

    let mut wire = Vec::new();
    let written = write_message(&mut wire, Magic::REGTEST, &message)?;
    assert_eq!(written, wire_len(&message)?);

    let mut cursor = Cursor::new(wire);
    let (decoded, raw) = read_message(&mut cursor, Magic::REGTEST)?;
    assert_eq!(decoded, message);

    let payload = encode_payload(&message)?;
    assert_eq!(raw.as_ref(), payload.as_slice());
    Ok(())
}

#[test]
fn feature_message_rejects_malformed_wire_payload() {
    let mut frame = Vec::with_capacity(HEADER_LEN);
    frame.extend_from_slice(&Magic::REGTEST.to_bytes());
    frame.extend_from_slice(b"feature\0\0\0\0\0");
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&super::checksum(&[]));

    let mut cursor = Cursor::new(frame);
    let result = read_message(&mut cursor, Magic::REGTEST);
    assert!(matches!(
        result,
        Err(PeerError::Feature(crate::feature::FeatureError::Truncated))
    ));
}

fn package_wtxid(tag: u8) -> bitcoin_rs_primitives::Wtxid {
    bitcoin_rs_primitives::Wtxid(bitcoin_rs_primitives::Hash256::from_le_bytes(&[tag; 32]))
}

fn package_tx(tag: u8) -> Result<bitcoin_rs_primitives::Tx, PeerError> {
    let mut raw = vec![1, 0, 0, 0, 1];
    raw.extend_from_slice(&[tag; 32]);
    raw.extend_from_slice(&0u32.to_le_bytes());
    raw.push(0);
    raw.extend_from_slice(&u32::MAX.to_le_bytes());
    raw.push(1);
    raw.extend_from_slice(&1_000u64.to_le_bytes());
    raw.push(0);
    raw.extend_from_slice(&0u32.to_le_bytes());
    Ok(bitcoin_rs_primitives::deserialize::<
        bitcoin_rs_primitives::Tx,
    >(&raw)?)
}

fn package_messages() -> Result<Vec<super::Message>, PeerError> {
    use crate::packages::{
        AncPkgInfo, GetPkgTxns, PKG_RELAY_ANC, PKG_RELAY_PKGTXNS, PkgTxns, SendPackages,
    };

    Ok(vec![
        super::Message::SendPackages(SendPackages {
            versions: PKG_RELAY_PKGTXNS | PKG_RELAY_ANC,
        }),
        super::Message::AncPkgInfo(AncPkgInfo {
            wtxids: vec![package_wtxid(1), package_wtxid(2)],
        }),
        super::Message::GetPkgTxns(GetPkgTxns {
            wtxids: vec![package_wtxid(3), package_wtxid(3), package_wtxid(4)],
        }),
        super::Message::PkgTxns(PkgTxns {
            txs: vec![package_tx(5)?, package_tx(6)?],
        }),
    ])
}

#[test]
fn package_messages_roundtrip_over_v1_with_exact_wire_len() -> Result<(), PeerError> {
    let commands = ["sendpackages", "ancpkginfo", "getpkgtxns", "pkgtxns"];
    for (message, command) in package_messages()?.iter().zip(commands) {
        assert_eq!(message.command().as_ref(), command);

        let mut wire = Vec::new();
        let written = write_message(&mut wire, Magic::REGTEST, message)?;
        assert_eq!(written, wire_len(message)?);
        assert_eq!(written, wire.len());

        let (decoded, raw) = read_message(&mut Cursor::new(wire.clone()), Magic::REGTEST)?;
        assert_eq!(raw.as_ref(), encode_payload(message)?.as_slice());
        if let super::Message::PkgTxns(package) = message {
            assert_eq!(decoded, super::Message::PkgTxnsPayload(raw.clone()));
            assert_eq!(&crate::packages::PkgTxns::decode(&raw)?, package);
            let mut rewritten = Vec::new();
            assert_eq!(
                write_message(&mut rewritten, Magic::REGTEST, &decoded)?,
                written
            );
            assert_eq!(rewritten, wire, "the raw variant writes the same frame");
            assert_eq!(wire_len(&decoded)?, written);
        } else {
            assert_eq!(&decoded, message);
        }
    }
    Ok(())
}

#[test]
fn package_messages_share_the_codec_bounds_on_every_wire_path() {
    use crate::packages::{
        AncPkgInfo, GetPkgTxns, MAX_GETPKGTXNS, PackageError, PkgTxns, SendPackages,
    };

    let over = MAX_GETPKGTXNS + 1;
    let wtxids = |count: usize| {
        (0..count)
            .map(|tag| package_wtxid(u8::try_from(tag).unwrap_or(u8::MAX)))
            .collect::<Vec<_>>()
    };
    let refused = [
        super::Message::AncPkgInfo(AncPkgInfo { wtxids: Vec::new() }),
        super::Message::AncPkgInfo(AncPkgInfo {
            wtxids: wtxids(over),
        }),
        super::Message::AncPkgInfo(AncPkgInfo {
            wtxids: vec![package_wtxid(1), package_wtxid(1)],
        }),
        super::Message::GetPkgTxns(GetPkgTxns { wtxids: Vec::new() }),
        super::Message::GetPkgTxns(GetPkgTxns {
            wtxids: wtxids(over),
        }),
        super::Message::PkgTxns(PkgTxns { txs: Vec::new() }),
    ];
    for message in &refused {
        assert!(
            matches!(wire_len(message), Err(PeerError::Package(_))),
            "wire_len {message:?}"
        );
        assert!(
            matches!(encode_payload(message), Err(PeerError::Package(_))),
            "encode_payload {message:?}"
        );
    }
    assert!(matches!(
        wire_len(&super::Message::PkgTxns(PkgTxns {
            txs: vec![bitcoin_rs_primitives::Tx::default(); over],
        })),
        Err(PeerError::Package(PackageError::TooMany { .. }))
    ));
    assert_eq!(
        wire_len(&super::Message::SendPackages(SendPackages { versions: 0 })).ok(),
        Some(HEADER_LEN + 8)
    );
}

fn frame_of(command: &[u8], payload: &[u8]) -> Result<Vec<u8>, PeerError> {
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&Magic::REGTEST.to_bytes());
    let mut field = [0u8; super::COMMAND_LEN];
    field[..command.len()].copy_from_slice(command);
    frame.extend_from_slice(&field);
    let len =
        u32::try_from(payload.len()).map_err(|_| PeerError::PayloadTooLarge(payload.len()))?;
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&super::checksum(payload));
    frame.extend_from_slice(payload);
    Ok(frame)
}

#[test]
fn malformed_package_payload_is_a_package_error() -> Result<(), PeerError> {
    use crate::packages::PackageError;

    let cases: [(&[u8], &[u8], PackageError); 4] = [
        (b"sendpackages", &[0u8; 7], PackageError::Truncated),
        (b"sendpackages", &[0u8; 9], PackageError::Trailing(1)),
        (b"ancpkginfo", &[0], PackageError::Empty),
        (
            b"getpkgtxns",
            &[0xfd, 0x01, 0x00],
            PackageError::NonCanonical,
        ),
    ];
    for (command, payload, expected) in cases {
        let frame = frame_of(command, payload)?;
        let result = read_message(&mut Cursor::new(frame), Magic::REGTEST);
        assert!(
            matches!(&result, Err(PeerError::Package(error)) if *error == expected),
            "{}: {result:?}",
            String::from_utf8_lossy(command)
        );
    }
    Ok(())
}

#[test]
fn staletip_roundtrips_and_over_limit_is_ignored_not_punished() -> Result<(), PeerError> {
    use crate::staletip::{CompressedHeader, StaleTipAnnouncement, StaleTipError};

    let announcement = StaleTipAnnouncement {
        fork_point: bitcoin_rs_primitives::Hash256::from_le_bytes(&[7; 32]),
        headers: vec![
            CompressedHeader {
                version: 0x2000_0000,
                merkle_root: bitcoin_rs_primitives::Hash256::from_le_bytes(&[1; 32]),
                time: 1_700_000_000,
                bits: bitcoin_rs_primitives::CompactTarget::from_consensus(0x1d00_ffff),
                nonce: 9,
            };
            2
        ],
        have_block: true,
    };
    let message = super::Message::StaleTip(announcement);
    assert_eq!(message.command().as_ref(), "staletip");

    let mut wire = Vec::new();
    let written = write_message(&mut wire, Magic::REGTEST, &message)?;
    assert_eq!(written, wire_len(&message)?);
    let (decoded, raw) = read_message(&mut Cursor::new(wire), Magic::REGTEST)?;
    assert_eq!(decoded, message);
    assert_eq!(raw.as_ref(), encode_payload(&message)?.as_slice());

    let mut over = vec![0u8; 32];
    over.push(21);
    let (ignored, _) = read_message(
        &mut Cursor::new(frame_of(b"staletip", &over)?),
        Magic::REGTEST,
    )?;
    assert!(
        matches!(&ignored, super::Message::Unknown { command, payload }
                if command.as_ref() == "staletip" && payload.is_empty()),
        "{ignored:?}"
    );

    let result = read_message(
        &mut Cursor::new(frame_of(b"staletip", &[0u8; 31])?),
        Magic::REGTEST,
    );
    assert!(matches!(
        result,
        Err(PeerError::StaleTip(StaleTipError::Truncated))
    ));
    Ok(())
}

#[test]
fn pkgtxns_receive_defers_every_transaction_parse() -> Result<(), PeerError> {
    let frame = frame_of(b"pkgtxns", &[0])?;
    let (message, raw) = read_message(&mut Cursor::new(frame), Magic::REGTEST)?;
    assert_eq!(raw.as_ref(), [0]);
    assert_eq!(message, super::Message::PkgTxnsPayload(raw.clone()));
    assert!(matches!(
        crate::packages::PkgTxns::decode(&raw),
        Err(crate::packages::PackageError::Empty)
    ));

    let oversize = bytes::Bytes::from(vec![0_u8; MAX_MESSAGE_PAYLOAD + 1]);
    assert!(matches!(
        super::decode_payload("pkgtxns", &oversize),
        Err(PeerError::PayloadTooLarge(len)) if len == MAX_MESSAGE_PAYLOAD + 1
    ));
    Ok(())
}

#[test]
fn empty_command_in_v1_header_is_rejected() {
    let mut frame = Vec::with_capacity(HEADER_LEN);
    frame.extend_from_slice(&Magic::REGTEST.to_bytes());
    frame.extend_from_slice(&[0u8; 12]);
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&super::checksum(&[]));

    let mut cursor = Cursor::new(frame);
    let result = read_message(&mut cursor, Magic::REGTEST);
    assert!(matches!(result, Err(PeerError::InvalidCommand(_))));
}
