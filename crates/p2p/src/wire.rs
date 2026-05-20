use std::io::{Read, Write};

use bitcoin::consensus::encode::{self, Decodable, Encodable};
use bitcoin::p2p::Magic;
use bitcoin::p2p::address::AddrV2Message;
use bitcoin::p2p::message::{CommandString, NetworkMessage};
use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
use bitcoin::p2p::message_bloom::{FilterAdd, FilterLoad};
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
use bitcoin::p2p::message_filter::{
    CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters,
};
use bitcoin::p2p::message_network::{Reject, VersionMessage};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Latest protocol version implemented by this crate.
pub const PROTOCOL_VERSION: u32 = 70_016;
/// Maximum accepted payload length for one v1 network message.
pub const MAX_MESSAGE_PAYLOAD: usize = 32 * 1024 * 1024;
const HEADER_LEN: usize = 24;
const COMMAND_LEN: usize = 12;

/// Bitcoin P2P message payload type.
pub type Message = NetworkMessage;

/// Wire and peer protocol errors.
#[derive(Debug, Error)]
pub enum PeerError {
    /// I/O failed while reading or writing the transport.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Consensus payload encoding or decoding failed.
    #[error("bitcoin consensus encoding error: {0}")]
    Encode(#[from] encode::Error),
    /// Command name is not valid for a v1 P2P header.
    #[error("invalid command `{0}`")]
    InvalidCommand(String),
    /// Peer sent a message for a different network.
    #[error("message magic {actual} does not match expected {expected}")]
    WrongNetwork {
        /// Expected magic bytes.
        expected: Magic,
        /// Actual magic bytes.
        actual: Magic,
    },
    /// Peer advertised a payload larger than the configured bound.
    #[error("payload length {0} exceeds 32 MiB bound")]
    PayloadTooLarge(usize),
    /// Payload checksum did not match the header checksum.
    #[error("invalid payload checksum")]
    BadChecksum,
    /// The finite-state machine rejected the message in the current state.
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    /// Attempted destination is currently banned.
    #[error("banned destination {0}")]
    BannedDestination(std::net::IpAddr),
    /// Ban-list persistence data was malformed.
    #[error("invalid ban-list entry: {0}")]
    InvalidBanEntry(String),
}

/// Write a Bitcoin v1 network message.
pub fn write_message<W: Write>(
    writer: &mut W,
    magic: Magic,
    message: &Message,
) -> Result<(), PeerError> {
    let command = message.command();
    let payload = encode_payload(message)?;
    if payload.len() > MAX_MESSAGE_PAYLOAD {
        return Err(PeerError::PayloadTooLarge(payload.len()));
    }

    writer.write_all(&magic.to_bytes())?;
    write_command(writer, &command)?;
    let len =
        u32::try_from(payload.len()).map_err(|_| PeerError::PayloadTooLarge(payload.len()))?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&checksum(&payload))?;
    writer.write_all(&payload)?;
    Ok(())
}

/// Read and validate a Bitcoin v1 network message.
pub fn read_message<R: Read>(reader: &mut R, expected_magic: Magic) -> Result<Message, PeerError> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header)?;

    let actual_magic = Magic::from_bytes([header[0], header[1], header[2], header[3]]);
    if actual_magic != expected_magic {
        return Err(PeerError::WrongNetwork {
            expected: expected_magic,
            actual: actual_magic,
        });
    }

    let command = read_command(&header[4..16])?;
    let payload_len_u32 = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    let payload_len =
        usize::try_from(payload_len_u32).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    if payload_len > MAX_MESSAGE_PAYLOAD {
        return Err(PeerError::PayloadTooLarge(payload_len));
    }

    let mut expected = [0u8; 4];
    expected.copy_from_slice(&header[20..24]);
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload)?;
    if checksum(&payload) != expected {
        return Err(PeerError::BadChecksum);
    }

    decode_payload(&command, &payload)
}

/// Encode only a message payload.
pub fn encode_payload(message: &Message) -> Result<Vec<u8>, PeerError> {
    let mut payload = Vec::new();
    message
        .consensus_encode(&mut payload)
        .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
    Ok(payload)
}

fn decode_payload(command: &str, payload: &[u8]) -> Result<Message, PeerError> {
    let message = match command {
        "version" => Message::Version(encode::deserialize::<VersionMessage>(payload)?),
        "verack" => empty_payload(payload, Message::Verack)?,
        "addr" => Message::Addr(encode::deserialize::<Vec<(u32, bitcoin::p2p::Address)>>(
            payload,
        )?),
        "inv" => Message::Inv(encode::deserialize::<Vec<Inventory>>(payload)?),
        "getdata" => Message::GetData(encode::deserialize::<Vec<Inventory>>(payload)?),
        "notfound" => Message::NotFound(encode::deserialize::<Vec<Inventory>>(payload)?),
        "getblocks" => Message::GetBlocks(encode::deserialize::<GetBlocksMessage>(payload)?),
        "getheaders" => Message::GetHeaders(encode::deserialize::<GetHeadersMessage>(payload)?),
        "mempool" => empty_payload(payload, Message::MemPool)?,
        "tx" => Message::Tx(encode::deserialize::<bitcoin::Transaction>(payload)?),
        "block" => Message::Block(encode::deserialize::<bitcoin::Block>(payload)?),
        "headers" => Message::Headers(decode_headers(payload)?),
        "sendheaders" => empty_payload(payload, Message::SendHeaders)?,
        "getaddr" => empty_payload(payload, Message::GetAddr)?,
        "ping" => Message::Ping(encode::deserialize::<u64>(payload)?),
        "pong" => Message::Pong(encode::deserialize::<u64>(payload)?),
        "merkleblock" => Message::MerkleBlock(encode::deserialize::<
            bitcoin::merkle_tree::MerkleBlock,
        >(payload)?),
        "filterload" => Message::FilterLoad(encode::deserialize::<FilterLoad>(payload)?),
        "filteradd" => Message::FilterAdd(encode::deserialize::<FilterAdd>(payload)?),
        "filterclear" => empty_payload(payload, Message::FilterClear)?,
        "getcfilters" => Message::GetCFilters(encode::deserialize::<GetCFilters>(payload)?),
        "cfilter" => Message::CFilter(encode::deserialize::<CFilter>(payload)?),
        "getcfheaders" => Message::GetCFHeaders(encode::deserialize::<GetCFHeaders>(payload)?),
        "cfheaders" => Message::CFHeaders(encode::deserialize::<CFHeaders>(payload)?),
        "getcfcheckpt" => Message::GetCFCheckpt(encode::deserialize::<GetCFCheckpt>(payload)?),
        "cfcheckpt" => Message::CFCheckpt(encode::deserialize::<CFCheckpt>(payload)?),
        "sendcmpct" => Message::SendCmpct(encode::deserialize::<SendCmpct>(payload)?),
        "cmpctblock" => Message::CmpctBlock(encode::deserialize::<CmpctBlock>(payload)?),
        "getblocktxn" => Message::GetBlockTxn(encode::deserialize::<GetBlockTxn>(payload)?),
        "blocktxn" => Message::BlockTxn(encode::deserialize::<BlockTxn>(payload)?),
        "reject" => Message::Reject(encode::deserialize::<Reject>(payload)?),
        "alert" => Message::Alert(encode::deserialize::<Vec<u8>>(payload)?),
        "feefilter" => Message::FeeFilter(encode::deserialize::<i64>(payload)?),
        "wtxidrelay" => empty_payload(payload, Message::WtxidRelay)?,
        "addrv2" => Message::AddrV2(encode::deserialize::<Vec<AddrV2Message>>(payload)?),
        "sendaddrv2" => empty_payload(payload, Message::SendAddrV2)?,
        _ => Message::Unknown {
            command: command_string(command)?,
            payload: payload.to_vec(),
        },
    };
    Ok(message)
}

fn decode_headers(payload: &[u8]) -> Result<Vec<bitcoin::block::Header>, PeerError> {
    let mut reader = payload;
    let count = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
    let capacity = usize::try_from(count).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    let mut headers = Vec::with_capacity(capacity.min(2_000));
    for _ in 0..count {
        headers.push(bitcoin::block::Header::consensus_decode(&mut reader)?);
        let tx_count = u8::consensus_decode(&mut reader)?;
        if tx_count != 0 {
            return Err(PeerError::Protocol("headers entry carried transactions"));
        }
    }
    if !reader.is_empty() {
        return Err(PeerError::Protocol("trailing bytes after headers payload"));
    }
    Ok(headers)
}

fn empty_payload(payload: &[u8], message: Message) -> Result<Message, PeerError> {
    if payload.is_empty() {
        Ok(message)
    } else {
        Err(PeerError::Protocol("non-empty payload for empty message"))
    }
}

fn write_command<W: Write>(writer: &mut W, command: &CommandString) -> Result<(), PeerError> {
    let command = command.as_ref().as_bytes();
    if command.len() > COMMAND_LEN || command.contains(&0) {
        return Err(PeerError::InvalidCommand(
            String::from_utf8_lossy(command).into_owned(),
        ));
    }
    let mut raw = [0u8; COMMAND_LEN];
    raw[..command.len()].copy_from_slice(command);
    writer.write_all(&raw)?;
    Ok(())
}

fn read_command(raw: &[u8]) -> Result<String, PeerError> {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    if raw[end..].iter().any(|byte| *byte != 0) {
        return Err(PeerError::InvalidCommand(
            String::from_utf8_lossy(raw).into_owned(),
        ));
    }
    std::str::from_utf8(&raw[..end])
        .map(str::to_owned)
        .map_err(|_| PeerError::InvalidCommand(String::from_utf8_lossy(raw).into_owned()))
}

fn command_string(command: &str) -> Result<CommandString, PeerError> {
    command
        .parse::<CommandString>()
        .map_err(|_| PeerError::InvalidCommand(command.to_owned()))
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    [second[0], second[1], second[2], second[3]]
}
