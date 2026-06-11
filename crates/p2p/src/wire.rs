use std::io::{Read, Write};

use bytes;

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

use crate::inv::MAX_INV_PER_MSG;

/// Latest protocol version implemented by this crate.
pub const PROTOCOL_VERSION: u32 = 70_016;
/// Maximum accepted payload length for one v1 network message.
pub const MAX_MESSAGE_PAYLOAD: usize = 32 * 1024 * 1024;
/// Maximum number of headers accepted in one `headers` message.
pub const MAX_HEADERS_MESSAGE_COUNT: usize = 2_000;
/// Maximum block locator hashes accepted in one locator-based request.
pub const MAX_LOCATOR_HASHES: usize = 101;
/// Maximum address entries accepted in one `addr` or `addrv2` message.
pub const MAX_ADDR_MESSAGE_COUNT: usize = 1_000;
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
///
/// Returns the decoded message and the raw payload bytes (checksum-validated).
pub fn read_message<R: Read>(
    reader: &mut R,
    expected_magic: Magic,
) -> Result<(Message, bytes::Bytes), PeerError> {
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

    let message = decode_payload(&command, &payload)?;
    Ok((message, bytes::Bytes::from(payload)))
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
        "addr" => Message::Addr(decode_addr(payload)?),
        "inv" => Message::Inv(decode_inventory(payload)?),
        "getdata" => Message::GetData(decode_inventory(payload)?),
        "notfound" => Message::NotFound(decode_inventory(payload)?),
        "getblocks" => Message::GetBlocks(decode_getblocks(payload)?),
        "getheaders" => Message::GetHeaders(decode_getheaders(payload)?),
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
        "addrv2" => Message::AddrV2(decode_addrv2(payload)?),
        "sendaddrv2" => empty_payload(payload, Message::SendAddrV2)?,
        _ => Message::Unknown {
            command: command_string(command)?,
            payload: payload.to_vec(),
        },
    };
    Ok(message)
}

fn decode_addr(payload: &[u8]) -> Result<Vec<(u32, bitcoin::p2p::Address)>, PeerError> {
    let mut reader = payload;
    let count = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
    let capacity = usize::try_from(count).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    if capacity > MAX_ADDR_MESSAGE_COUNT {
        return Err(PeerError::Protocol("addr count too large"));
    }
    let mut addresses = Vec::with_capacity(capacity);
    for _ in 0..count {
        addresses.push(<(u32, bitcoin::p2p::Address)>::consensus_decode(
            &mut reader,
        )?);
    }
    if !reader.is_empty() {
        return Err(PeerError::Protocol("trailing bytes after addr payload"));
    }
    Ok(addresses)
}

fn decode_addrv2(payload: &[u8]) -> Result<Vec<AddrV2Message>, PeerError> {
    let mut reader = payload;
    let count = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
    let capacity = usize::try_from(count).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    if capacity > MAX_ADDR_MESSAGE_COUNT {
        return Err(PeerError::Protocol("addrv2 count too large"));
    }
    let mut addresses = Vec::with_capacity(capacity);
    for _ in 0..count {
        addresses.push(AddrV2Message::consensus_decode(&mut reader)?);
    }
    if !reader.is_empty() {
        return Err(PeerError::Protocol("trailing bytes after addrv2 payload"));
    }
    Ok(addresses)
}

fn decode_inventory(payload: &[u8]) -> Result<Vec<Inventory>, PeerError> {
    let mut reader = payload;
    let count = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
    let capacity = usize::try_from(count).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    if capacity > MAX_INV_PER_MSG {
        return Err(PeerError::Protocol("inventory count too large"));
    }
    let mut inventory = Vec::with_capacity(capacity);
    for _ in 0..count {
        inventory.push(Inventory::consensus_decode(&mut reader)?);
    }
    if !reader.is_empty() {
        return Err(PeerError::Protocol(
            "trailing bytes after inventory payload",
        ));
    }
    Ok(inventory)
}

fn decode_getblocks(payload: &[u8]) -> Result<GetBlocksMessage, PeerError> {
    let (version, locator_hashes, stop_hash) = decode_locator_payload(payload, "getblocks")?;
    Ok(GetBlocksMessage {
        version,
        locator_hashes,
        stop_hash,
    })
}

fn decode_getheaders(payload: &[u8]) -> Result<GetHeadersMessage, PeerError> {
    let (version, locator_hashes, stop_hash) = decode_locator_payload(payload, "getheaders")?;
    Ok(GetHeadersMessage {
        version,
        locator_hashes,
        stop_hash,
    })
}

fn decode_locator_payload(
    payload: &[u8],
    command: &'static str,
) -> Result<(u32, Vec<bitcoin::BlockHash>, bitcoin::BlockHash), PeerError> {
    let mut reader = payload;
    let version = u32::consensus_decode(&mut reader)?;
    let count = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
    let capacity = usize::try_from(count).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    if capacity > MAX_LOCATOR_HASHES {
        return Err(PeerError::Protocol(match command {
            "getblocks" => "getblocks locator too large",
            "getheaders" => "getheaders locator too large",
            _ => "locator too large",
        }));
    }

    let mut locator_hashes = Vec::with_capacity(capacity);
    for _ in 0..count {
        locator_hashes.push(bitcoin::BlockHash::consensus_decode(&mut reader)?);
    }
    let stop_hash = bitcoin::BlockHash::consensus_decode(&mut reader)?;
    if !reader.is_empty() {
        return Err(PeerError::Protocol(match command {
            "getblocks" => "trailing bytes after getblocks payload",
            "getheaders" => "trailing bytes after getheaders payload",
            _ => "trailing bytes after locator payload",
        }));
    }

    Ok((version, locator_hashes, stop_hash))
}

fn decode_headers(payload: &[u8]) -> Result<Vec<bitcoin::block::Header>, PeerError> {
    let mut reader = payload;
    let count = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
    let capacity = usize::try_from(count).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    if capacity > MAX_HEADERS_MESSAGE_COUNT {
        return Err(PeerError::Protocol("headers count too large"));
    }
    let mut headers = Vec::with_capacity(capacity);
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

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::Magic;
    use bitcoin::p2p::message::NetworkMessage;

    use super::{
        HEADER_LEN, MAX_MESSAGE_PAYLOAD, PeerError, encode_payload, read_message, write_message,
    };

    /// Serves exactly one v1 wire header and fails on any read beyond it.
    ///
    /// Used to prove that `read_message` rejects oversized payload lengths
    /// before attempting to read the payload body. (The buffer allocation
    /// sits between the size guard and the body read, so guard-before-read
    /// implies guard-before-allocation in the current code; only the read
    /// ordering is directly enforced by this reader.)
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

    /// Build a regtest `ping` wire header declaring `payload_len` bytes of payload.
    fn header_declaring(payload_len: usize) -> Result<Vec<u8>, PeerError> {
        let len = u32::try_from(payload_len)
            .map_err(|_| PeerError::Protocol("payload length does not fit in u32"))?;
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&Magic::REGTEST.to_bytes());
        header.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
        header.extend_from_slice(&len.to_le_bytes());
        header.extend_from_slice(&[0u8; 4]); // checksum (never reached / wrong on purpose)
        Ok(header)
    }

    #[test]
    fn block_message_roundtrip_preserves_wire_payload() -> Result<(), super::PeerError> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let message = NetworkMessage::Block(block.clone());
        let payload = encode_payload(&message)?;
        let expected_hash = block.block_hash();

        let mut wire = Vec::new();
        write_message(&mut wire, Magic::REGTEST, &message)?;

        let mut cursor = Cursor::new(wire);
        let (decoded, raw) = read_message(&mut cursor, Magic::REGTEST)?;

        let NetworkMessage::Block(decoded_block) = decoded else {
            return Err(super::PeerError::Protocol(
                "expected block message in roundtrip test",
            ));
        };

        assert_eq!(raw.as_ref(), serialize(&decoded_block).as_slice());
        assert_eq!(raw.as_ref(), payload.as_slice());
        assert_eq!(decoded_block.block_hash(), expected_hash);

        Ok(())
    }

    #[test]
    fn read_message_rejects_oversized_payload_before_reading_body() -> Result<(), PeerError> {
        let oversize = MAX_MESSAGE_PAYLOAD + 1;
        let mut reader = HeaderOnlyReader {
            header: Cursor::new(header_declaring(oversize)?),
        };

        // `HeaderOnlyReader` errors on any read past the 24-byte header, so
        // getting `PayloadTooLarge` (not `Io`) proves the size guard fires
        // before the payload buffer is allocated or read.
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

        // Exactly MAX_MESSAGE_PAYLOAD passes the size guard; the failure must
        // come from reading the (absent) body, never from the size check.
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
    fn write_message_rejects_payload_exceeding_cap() -> Result<(), PeerError> {
        let oversize = MAX_MESSAGE_PAYLOAD + 1;
        let message = NetworkMessage::Unknown {
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
}
