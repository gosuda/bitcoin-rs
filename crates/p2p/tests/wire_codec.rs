use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use bitcoin::TxMerkleNode;
use bitcoin::Txid;
use bitcoin::bip152::{
    BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds, PrefilledTransaction, ShortId,
};
use bitcoin::block::BlockHash;
use bitcoin::block::{Header, Version};
use bitcoin::consensus::encode::{Encodable, VarInt};
use bitcoin::hashes::Hash;
use bitcoin::p2p::Magic;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
use bitcoin::pow::CompactTarget;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin_rs_p2p::PeerRole;
use bitcoin_rs_p2p::dispatch::dispatch_inbound;
use bitcoin_rs_p2p::handshake::version_message;
use bitcoin_rs_p2p::inv::MAX_INV_PER_MSG;
use bitcoin_rs_p2p::wire::{
    MAX_ADDR_MESSAGE_COUNT, MAX_BLOCK_TX_COUNT, MAX_LOCATOR_HASHES, MAX_MESSAGE_PAYLOAD, Message,
    PeerError, read_message, write_message,
};
use bitcoin_rs_p2p::{Peer, PeerState};
use sha2::{Digest, Sha256};

#[test]
fn round_trips_ping_pong_version_verack_inv_getheaders() -> Result<(), PeerError> {
    let messages = vec![
        Message::Ping(42),
        Message::Pong(42),
        Message::Version(version_message(
            99,
            123,
            PeerRole::FullRelay,
            bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
        )),
        Message::Verack,
        Message::Inv(vec![Inventory::Transaction(Txid::from_byte_array(
            [7u8; 32],
        ))]),
        Message::GetHeaders(GetHeadersMessage::new(
            vec![BlockHash::all_zeros()],
            BlockHash::all_zeros(),
        )),
    ];

    for message in messages {
        let mut cursor = Cursor::new(Vec::new());
        write_message(&mut cursor, Magic::BITCOIN, &message)?;
        cursor.set_position(0);
        let (decoded, _) = read_message(&mut cursor, Magic::BITCOIN)?;
        assert_eq!(decoded, message);
    }

    Ok(())
}

type FrameBuilder = fn(usize) -> Result<Vec<u8>, PeerError>;

#[test]
fn count_capped_messages_accept_the_cap_and_refuse_one_more() -> Result<(), PeerError> {
    let cases: [(&str, FrameBuilder, usize, &str); 8] = [
        (
            "inv",
            |n| inventory_frame(b"inv", n),
            MAX_INV_PER_MSG,
            "inventory count too large",
        ),
        (
            "getdata",
            |n| inventory_frame(b"getdata", n),
            MAX_INV_PER_MSG,
            "inventory count too large",
        ),
        (
            "notfound",
            |n| inventory_frame(b"notfound", n),
            MAX_INV_PER_MSG,
            "inventory count too large",
        ),
        (
            "addr",
            addr_frame,
            MAX_ADDR_MESSAGE_COUNT,
            "addr count too large",
        ),
        (
            "addrv2",
            addrv2_frame,
            MAX_ADDR_MESSAGE_COUNT,
            "addrv2 count too large",
        ),
        (
            "getheaders",
            |n| locator_frame(b"getheaders", n),
            MAX_LOCATOR_HASHES,
            "getheaders locator too large",
        ),
        (
            "getblocks",
            |n| locator_frame(b"getblocks", n),
            MAX_LOCATOR_HASHES,
            "getblocks locator too large",
        ),
        ("headers", headers_frame, 2_000, "headers count too large"),
    ];

    for (command, frame, cap, refusal) in cases {
        let (decoded, _) = read_message(&mut Cursor::new(frame(cap)?), Magic::BITCOIN)?;
        assert_eq!(
            decoded.command().as_ref(),
            command,
            "decode must keep the command"
        );
        let decoded_len = match decoded {
            Message::Inv(items) | Message::GetData(items) | Message::NotFound(items) => items.len(),
            Message::Addr(addresses) => addresses.len(),
            Message::AddrV2(addresses) => addresses.len(),
            Message::GetHeaders(request) => request.locator_hashes.len(),
            Message::GetBlocks(request) => request.locator_hashes.len(),
            Message::Headers(headers) => headers.len(),
            other => panic!("{command} frame decoded as {}", other.command()),
        };
        assert_eq!(
            decoded_len, cap,
            "{command} at the cap must keep every entry"
        );

        match read_message(&mut Cursor::new(frame(cap + 1)?), Magic::BITCOIN) {
            Err(PeerError::Misbehavior(message)) => assert_eq!(message, refusal, "{command}"),
            other => panic!("{command} above the cap must be refused, got {other:?}"),
        }
    }
    Ok(())
}

#[test]
fn round_trips_compact_block_messages() -> Result<(), PeerError> {
    let block_hash = BlockHash::from_byte_array([3u8; 32]);
    let transaction = compact_block_transaction();
    let messages = vec![
        Message::SendCmpct(SendCmpct {
            send_compact: false,
            version: 1,
        }),
        Message::SendCmpct(SendCmpct {
            send_compact: true,
            version: 2,
        }),
        Message::CmpctBlock(CmpctBlock {
            compact_block: HeaderAndShortIds {
                header: compact_block_header(),
                nonce: 99,
                short_ids: vec![ShortId::default()],
                prefilled_txs: vec![PrefilledTransaction {
                    idx: 0,
                    tx: transaction.clone(),
                }],
            },
        }),
        Message::GetBlockTxn(GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash,
                indexes: vec![1, 3],
            },
        }),
        Message::BlockTxn(BlockTxn {
            transactions: BlockTransactions {
                block_hash,
                transactions: vec![transaction],
            },
        }),
    ];

    for message in messages {
        let mut cursor = Cursor::new(Vec::new());
        write_message(&mut cursor, Magic::BITCOIN, &message)?;
        cursor.set_position(0);
        let (decoded, _) = read_message(&mut cursor, Magic::BITCOIN)?;
        assert_eq!(decoded, message);
    }

    Ok(())
}

fn getblocktxn_frame(deltas: &[u64]) -> Result<Vec<u8>, PeerError> {
    let mut payload = bitcoin::consensus::encode::serialize(&BlockHash::from_byte_array([3u8; 32]));
    let count =
        u64::try_from(deltas.len()).map_err(|_| PeerError::PayloadTooLarge(deltas.len()))?;
    payload.extend_from_slice(&bitcoin::consensus::encode::serialize(&VarInt(count)));
    for delta in deltas {
        payload.extend_from_slice(&bitcoin::consensus::encode::serialize(&VarInt(*delta)));
    }
    message_frame(b"getblocktxn", &payload)
}

fn decoded_getblocktxn(deltas: &[u64]) -> Result<Vec<u64>, PeerError> {
    let mut cursor = Cursor::new(getblocktxn_frame(deltas)?);
    let (decoded, _) = read_message(&mut cursor, Magic::BITCOIN)?;
    let Message::GetBlockTxn(request) = decoded else {
        panic!("a getblocktxn frame must decode as getblocktxn");
    };
    Ok(request.txs_request.indexes)
}

#[test]
fn getblocktxn_differential_indexes_decode_to_absolute_order() -> Result<(), PeerError> {
    assert_eq!(decoded_getblocktxn(&[1, 0, 0])?, vec![1, 2, 3]);
    assert_eq!(decoded_getblocktxn(&[])?, Vec::<u64>::new());

    let mut cursor = Cursor::new(getblocktxn_frame(&[0, u64::MAX])?);
    assert!(
        read_message(&mut cursor, Magic::BITCOIN).is_err(),
        "an overflowing index delta must not decode"
    );
    Ok(())
}

fn inventory_frame(command: &[u8], count: usize) -> Result<Vec<u8>, PeerError> {
    let count_u64 = u64::try_from(count).map_err(|_| PeerError::PayloadTooLarge(count))?;
    let mut payload = Vec::new();
    VarInt(count_u64)
        .consensus_encode(&mut payload)
        .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
    let inventory = Inventory::Transaction(Txid::from_byte_array([9u8; 32]));
    for _ in 0..count {
        inventory
            .consensus_encode(&mut payload)
            .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
    }

    message_frame(command, &payload)
}

fn addr_frame(count: usize) -> Result<Vec<u8>, PeerError> {
    let count_u64 = u64::try_from(count).map_err(|_| PeerError::PayloadTooLarge(count))?;
    let mut payload = Vec::new();
    VarInt(count_u64)
        .consensus_encode(&mut payload)
        .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
    let socket = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8333));
    let address = (0_u32, Address::new(&socket, ServiceFlags::NETWORK));
    for _ in 0..count {
        address
            .consensus_encode(&mut payload)
            .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
    }

    message_frame(b"addr", &payload)
}

fn addrv2_frame(count: usize) -> Result<Vec<u8>, PeerError> {
    let count_u64 = u64::try_from(count).map_err(|_| PeerError::PayloadTooLarge(count))?;
    let mut payload = Vec::new();
    VarInt(count_u64)
        .consensus_encode(&mut payload)
        .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
    let address = AddrV2Message {
        time: 0,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Ipv4(Ipv4Addr::LOCALHOST),
        port: 8333,
    };
    for _ in 0..count {
        address
            .consensus_encode(&mut payload)
            .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
    }

    message_frame(b"addrv2", &payload)
}

fn locator_frame(command: &[u8], count: usize) -> Result<Vec<u8>, PeerError> {
    let count_u64 = u64::try_from(count).map_err(|_| PeerError::PayloadTooLarge(count))?;
    let mut payload = Vec::new();
    bitcoin::p2p::PROTOCOL_VERSION
        .consensus_encode(&mut payload)
        .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
    VarInt(count_u64)
        .consensus_encode(&mut payload)
        .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
    let locator = BlockHash::from_byte_array([8u8; 32]);
    for _ in 0..count {
        locator
            .consensus_encode(&mut payload)
            .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
    }
    BlockHash::all_zeros()
        .consensus_encode(&mut payload)
        .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;

    message_frame(command, &payload)
}

fn headers_frame(count: usize) -> Result<Vec<u8>, PeerError> {
    let count_u64 = u64::try_from(count).map_err(|_| PeerError::PayloadTooLarge(count))?;
    let mut payload = Vec::new();
    VarInt(count_u64)
        .consensus_encode(&mut payload)
        .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
    let header = compact_block_header();
    for _ in 0..count {
        header
            .consensus_encode(&mut payload)
            .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
        payload.push(0);
    }

    message_frame(b"headers", &payload)
}

fn message_frame(command: &[u8], payload: &[u8]) -> Result<Vec<u8>, PeerError> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&Magic::BITCOIN.to_bytes());
    frame.extend_from_slice(command);
    frame.resize(16, 0);
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| PeerError::PayloadTooLarge(payload.len()))?;
    frame.extend_from_slice(&payload_len.to_le_bytes());
    frame.extend_from_slice(&checksum(payload));
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    [second[0], second[1], second[2], second[3]]
}

fn compact_block_header() -> Header {
    Header {
        version: Version::ONE,
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: 0,
        bits: CompactTarget::from_consensus(bitcoin_rs_chain::regtest_fixture::REGTEST_BITS),
        nonce: 0,
    }
}

fn compact_block_transaction() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

#[test]
fn command_padding_rejects_non_ascii_control_and_dirty_padding() {
    let cases = [
        (
            &b"ping\0\0\0\0\0\0\0\x01"[..],
            "dirty padding after nul terminator",
        ),
        (&b"ping\n\0\0\0\0\0\0\0"[..], "control character in command"),
        (&b"ping\x1f\0\0\0\0\0\0\0"[..], "control byte below space"),
        (&b"ping\x7f\0\0\0\0\0\0\0"[..], "del byte in command"),
        (&b"ping\x80\0\0\0\0\0\0\0"[..], "non-ascii byte in command"),
        (&b"\0\0\0\0\0\0\0\0\0\0\0\0"[..], "empty command"),
    ];

    for (cmd, desc) in cases {
        let mut frame = Vec::new();
        frame.extend_from_slice(&Magic::BITCOIN.to_bytes());
        frame.extend_from_slice(cmd);
        frame.extend_from_slice(&0u32.to_le_bytes());
        frame.extend_from_slice(&checksum(&[]));

        let res = read_message(&mut Cursor::new(frame), Magic::BITCOIN);
        assert!(
            matches!(res, Err(PeerError::InvalidCommand(_))),
            "{desc} must fail with InvalidCommand, got {res:?}"
        );
    }
}

#[test]
fn space_byte_in_command_name_is_a_valid_unknown_command() -> Result<(), PeerError> {
    let frame = message_frame(b"pi ng", &[])?;
    let (message, payload) = read_message(&mut Cursor::new(frame), Magic::BITCOIN)?;
    assert!(payload.is_empty());
    assert!(matches!(message, Message::Unknown { .. }));
    assert_eq!(message.command().as_ref(), "pi ng");

    let mut peer = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::BITCOIN);
    let responses = dispatch_inbound(
        &mut peer,
        &Message::Version(version_message(
            1,
            0,
            PeerRole::FullRelay,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        )),
    )?;
    assert_eq!(
        responses,
        vec![
            Message::WtxidRelay,
            Message::SendAddrV2,
            Message::SendHeaders,
            Message::Verack
        ]
    );
    dispatch_inbound(&mut peer, &Message::Verack)?;
    assert_eq!(peer.state, PeerState::Ready);

    let unknown = Message::Unknown {
        command: "pi ng"
            .parse()
            .map_err(|_| PeerError::InvalidCommand("pi ng".to_owned()))?,
        payload: Vec::new(),
    };
    let responses = dispatch_inbound(&mut peer, &unknown)?;
    assert_eq!(responses, []);
    assert_eq!(peer.state, PeerState::Ready);
    Ok(())
}

#[test]
fn compact_block_messages_reject_counts_exceeding_allocation_cap() -> Result<(), PeerError> {
    let mut payload = Vec::new();
    compact_block_header()
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    99u64
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    let count_over = u64::try_from(MAX_BLOCK_TX_COUNT + 1)
        .map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    VarInt(count_over)
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    let frame = message_frame(b"cmpctblock", &payload)?;
    assert!(matches!(
        read_message(&mut Cursor::new(frame), Magic::BITCOIN),
        Err(PeerError::Misbehavior(
            "cmpctblock short_ids count too large"
        ))
    ));

    let mut payload = Vec::new();
    compact_block_header()
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    99u64
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    VarInt(0)
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    let count_over = u64::try_from(MAX_BLOCK_TX_COUNT + 1)
        .map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    VarInt(count_over)
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    let frame = message_frame(b"cmpctblock", &payload)?;
    assert!(matches!(
        read_message(&mut Cursor::new(frame), Magic::BITCOIN),
        Err(PeerError::Misbehavior(
            "cmpctblock prefilled_txs count too large"
        ))
    ));

    let mut payload = Vec::new();
    compact_block_header()
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    99u64
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    VarInt(1)
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    ShortId::default()
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    let count_at_cap =
        u64::try_from(MAX_BLOCK_TX_COUNT).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    VarInt(count_at_cap)
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    let frame = message_frame(b"cmpctblock", &payload)?;
    assert!(matches!(
        read_message(&mut Cursor::new(frame), Magic::BITCOIN),
        Err(PeerError::Misbehavior(
            "cmpctblock total transactions too large"
        ))
    ));

    let mut payload = Vec::new();
    BlockHash::all_zeros()
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    let count_over = u64::try_from(MAX_BLOCK_TX_COUNT + 1)
        .map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    VarInt(count_over)
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    let frame = message_frame(b"blocktxn", &payload)?;
    assert!(matches!(
        read_message(&mut Cursor::new(frame), Magic::BITCOIN),
        Err(PeerError::Misbehavior("blocktxn count too large"))
    ));

    let mut payload = Vec::new();
    BlockHash::all_zeros()
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    let count_over = u64::try_from(MAX_BLOCK_TX_COUNT + 1)
        .map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    VarInt(count_over)
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    let frame = message_frame(b"getblocktxn", &payload)?;
    assert!(matches!(
        read_message(&mut Cursor::new(frame), Magic::BITCOIN),
        Err(PeerError::Misbehavior(
            "getblocktxn indexes count too large"
        ))
    ));

    Ok(())
}

#[test]
fn compact_block_messages_reject_trailing_bytes() -> Result<(), PeerError> {
    let mut payload = Vec::new();
    compact_block_header()
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    0u64.consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    VarInt(0)
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    VarInt(0)
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    payload.push(0x42);
    let frame = message_frame(b"cmpctblock", &payload)?;
    assert!(matches!(
        read_message(&mut Cursor::new(frame), Magic::BITCOIN),
        Err(PeerError::Misbehavior(
            "trailing bytes after cmpctblock payload"
        ))
    ));

    let mut payload = Vec::new();
    BlockHash::all_zeros()
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    VarInt(0)
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    payload.push(0x42);
    let frame = message_frame(b"blocktxn", &payload)?;
    assert!(matches!(
        read_message(&mut Cursor::new(frame), Magic::BITCOIN),
        Err(PeerError::Misbehavior(
            "trailing bytes after blocktxn payload"
        ))
    ));

    let mut payload = Vec::new();
    BlockHash::all_zeros()
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    VarInt(0)
        .consensus_encode(&mut payload)
        .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
    payload.push(0x42);
    let frame = message_frame(b"getblocktxn", &payload)?;
    assert!(matches!(
        read_message(&mut Cursor::new(frame), Magic::BITCOIN),
        Err(PeerError::Misbehavior(
            "trailing bytes after getblocktxn payload"
        ))
    ));

    Ok(())
}

#[test]
fn framing_attacks_magic_checksum_and_length_boundaries() -> Result<(), PeerError> {
    let mut frame = message_frame(b"ping", &[1; 8])?;
    frame[0] ^= 0xff;
    assert!(matches!(
        read_message(&mut Cursor::new(frame), Magic::BITCOIN),
        Err(PeerError::WrongNetwork { .. })
    ));

    let mut frame = message_frame(b"ping", &[1; 8])?;
    frame[20] ^= 1;
    assert!(matches!(
        read_message(&mut Cursor::new(frame), Magic::BITCOIN),
        Err(PeerError::BadChecksum)
    ));

    let mut frame = message_frame(b"ping", &[1; 8])?;
    frame[24] ^= 1;
    assert!(matches!(
        read_message(&mut Cursor::new(frame), Magic::BITCOIN),
        Err(PeerError::BadChecksum)
    ));

    let mut header_n_minus_1 = Vec::new();
    header_n_minus_1.extend_from_slice(&Magic::BITCOIN.to_bytes());
    header_n_minus_1.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
    let len_n_minus_1 = u32::try_from(MAX_MESSAGE_PAYLOAD - 1)
        .map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    header_n_minus_1.extend_from_slice(&len_n_minus_1.to_le_bytes());
    header_n_minus_1.extend_from_slice(&[0u8; 4]);
    assert!(matches!(
        read_message(&mut Cursor::new(header_n_minus_1), Magic::BITCOIN),
        Err(PeerError::Io(_))
    ));

    let mut header_n = Vec::new();
    header_n.extend_from_slice(&Magic::BITCOIN.to_bytes());
    header_n.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
    let len_n =
        u32::try_from(MAX_MESSAGE_PAYLOAD).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    header_n.extend_from_slice(&len_n.to_le_bytes());
    header_n.extend_from_slice(&[0u8; 4]);
    assert!(matches!(
        read_message(&mut Cursor::new(header_n), Magic::BITCOIN),
        Err(PeerError::Io(_))
    ));

    let mut header_n_plus_1 = Vec::new();
    header_n_plus_1.extend_from_slice(&Magic::BITCOIN.to_bytes());
    header_n_plus_1.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
    let len_n_plus_1 = u32::try_from(MAX_MESSAGE_PAYLOAD + 1)
        .map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    header_n_plus_1.extend_from_slice(&len_n_plus_1.to_le_bytes());
    header_n_plus_1.extend_from_slice(&[0u8; 4]);
    assert!(matches!(
        read_message(&mut Cursor::new(header_n_plus_1), Magic::BITCOIN),
        Err(PeerError::PayloadTooLarge(len)) if len == MAX_MESSAGE_PAYLOAD + 1
    ));

    let partial_header = vec![0u8; 12];
    assert!(matches!(
        read_message(&mut Cursor::new(partial_header), Magic::BITCOIN),
        Err(PeerError::Io(_))
    ));

    Ok(())
}
