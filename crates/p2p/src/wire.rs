use std::io::{IoSlice, Read, Write};

use bytes;

use bitcoin::consensus::encode::{self, Decodable};
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
use bitcoin_rs_primitives::{
    BlockPayload, ConsensusDecode, ConsensusEncode, Header, Tx, deserialize,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::inv::MAX_INV_PER_MSG;

/// `getnetworkinfo.protocolversion`. It is at least the version at which BIP434
/// `feature` negotiation starts, so a peer that honors our advertisement also
/// honors the feature handshake.
pub const PROTOCOL_VERSION: u32 = 70_017;

const _: () = assert!(PROTOCOL_VERSION >= crate::feature::FEATURE_VERSION);

pub const MAX_MESSAGE_PAYLOAD: usize = 4_000_000;
pub(crate) const MAX_WRITE_BURST: usize = 8;

pub const MAX_HEADERS_MESSAGE_COUNT: usize = 2_000;

pub const MAX_LOCATOR_HASHES: usize = 101;

pub const MAX_ADDR_MESSAGE_COUNT: usize = 1_000;

pub(crate) const HEADER_LEN: usize = 24;

const COMMAND_LEN: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Version(VersionMessage),
    Verack,
    Addr(Vec<(u32, bitcoin::p2p::Address)>),
    Inv(Vec<Inventory>),
    GetData(Vec<Inventory>),
    NotFound(Vec<Inventory>),
    GetBlocks(GetBlocksMessage),
    GetHeaders(GetHeadersMessage),
    MemPool,
    Tx(Tx),
    Block(BlockPayload),
    BlockPayload(bytes::Bytes),
    Headers(Vec<Header>),
    SendHeaders,
    GetAddr,
    Ping(u64),
    Pong(u64),
    MerkleBlock(bitcoin::merkle_tree::MerkleBlock),
    FilterLoad(FilterLoad),
    FilterAdd(FilterAdd),
    FilterClear,
    GetCFilters(GetCFilters),
    CFilter(CFilter),
    GetCFHeaders(GetCFHeaders),
    CFHeaders(CFHeaders),
    GetCFCheckpt(GetCFCheckpt),
    CFCheckpt(CFCheckpt),
    SendCmpct(SendCmpct),
    CmpctBlock(CmpctBlock),
    GetBlockTxn(GetBlockTxn),
    BlockTxn(BlockTxn),
    Alert(Vec<u8>),
    Reject(Reject),
    FeeFilter(i64),
    WtxidRelay,
    AddrV2(Vec<AddrV2Message>),
    SendAddrV2,
    /// BIP434 `feature`
    Feature(crate::feature::FeatureAnnouncement),
    /// BIP331 `sendpackages`
    SendPackages(crate::packages::SendPackages),
    /// BIP331 `ancpkginfo`
    AncPkgInfo(crate::packages::AncPkgInfo),
    /// BIP331 `getpkgtxns`
    GetPkgTxns(crate::packages::GetPkgTxns),
    /// BIP331 `pkgtxns`, typed: the serving side's encode-only variant. The
    /// decoder never produces it; decode a received frame explicitly with
    /// [`crate::packages::PkgTxns::decode`].
    PkgTxns(crate::packages::PkgTxns),
    /// BIP331 `pkgtxns` exactly as received or already serialized.
    ///
    /// The decoder produces this variant instead of parsing the transactions, so a
    /// caller charges the frame against its ingress budget before any decoded `Vec<Tx>`
    /// exists. Written as a `pkgtxns` command without re-encoding.
    PkgTxnsPayload(bytes::Bytes),
    /// BIP332 `staletip`
    StaleTip(crate::staletip::StaleTipAnnouncement),
    Unknown {
        command: CommandString,
        payload: Vec<u8>,
    },
}

impl Message {
    pub fn command(&self) -> CommandString {
        let name = match self {
            Self::Version(_) => "version",
            Self::Verack => "verack",
            Self::Addr(_) => "addr",
            Self::Inv(_) => "inv",
            Self::GetData(_) => "getdata",
            Self::NotFound(_) => "notfound",
            Self::GetBlocks(_) => "getblocks",
            Self::GetHeaders(_) => "getheaders",
            Self::MemPool => "mempool",
            Self::Tx(_) => "tx",
            Self::Block(_) | Self::BlockPayload(_) => "block",
            Self::Headers(_) => "headers",
            Self::SendHeaders => "sendheaders",
            Self::GetAddr => "getaddr",
            Self::Ping(_) => "ping",
            Self::Pong(_) => "pong",
            Self::MerkleBlock(_) => "merkleblock",
            Self::FilterLoad(_) => "filterload",
            Self::FilterAdd(_) => "filteradd",
            Self::FilterClear => "filterclear",
            Self::GetCFilters(_) => "getcfilters",
            Self::CFilter(_) => "cfilter",
            Self::GetCFHeaders(_) => "getcfheaders",
            Self::CFHeaders(_) => "cfheaders",
            Self::GetCFCheckpt(_) => "getcfcheckpt",
            Self::CFCheckpt(_) => "cfcheckpt",
            Self::SendCmpct(_) => "sendcmpct",
            Self::CmpctBlock(_) => "cmpctblock",
            Self::GetBlockTxn(_) => "getblocktxn",
            Self::BlockTxn(_) => "blocktxn",
            Self::Alert(_) => "alert",
            Self::Reject(_) => "reject",
            Self::FeeFilter(_) => "feefilter",
            Self::WtxidRelay => "wtxidrelay",
            Self::AddrV2(_) => "addrv2",
            Self::SendAddrV2 => "sendaddrv2",
            Self::Feature(_) => crate::feature::FEATURE_COMMAND,
            Self::SendPackages(_) => "sendpackages",
            Self::AncPkgInfo(_) => "ancpkginfo",
            Self::GetPkgTxns(_) => "getpkgtxns",
            Self::PkgTxns(_) | Self::PkgTxnsPayload(_) => "pkgtxns",
            Self::StaleTip(_) => crate::staletip::STALETIP_COMMAND,
            Self::Unknown { command, .. } => return command.clone(),
        };
        match CommandString::try_from_static(name) {
            Ok(command) => command,
            Err(_) => unreachable!("static P2P command name is valid"),
        }
    }

    #[must_use]
    pub(crate) const fn is_bulk_payload(&self) -> bool {
        matches!(
            self,
            Self::Tx(_)
                | Self::Block(_)
                | Self::BlockPayload(_)
                | Self::Headers(_)
                | Self::MerkleBlock(_)
                | Self::CFilter(_)
                | Self::CmpctBlock(_)
                | Self::BlockTxn(_)
                | Self::Alert(_)
                | Self::PkgTxns(_)
                | Self::PkgTxnsPayload(_)
        )
    }
}

impl Message {
    fn envelope(&self) -> NetworkMessage {
        match self {
            Self::Version(message) => NetworkMessage::Version(message.clone()),
            Self::Verack => NetworkMessage::Verack,
            Self::Addr(addresses) => NetworkMessage::Addr(addresses.clone()),
            Self::Inv(inventory) => NetworkMessage::Inv(inventory.clone()),
            Self::GetData(inventory) => NetworkMessage::GetData(inventory.clone()),
            Self::NotFound(inventory) => NetworkMessage::NotFound(inventory.clone()),
            Self::GetBlocks(message) => NetworkMessage::GetBlocks(message.clone()),
            Self::GetHeaders(message) => NetworkMessage::GetHeaders(message.clone()),
            Self::MemPool => NetworkMessage::MemPool,
            Self::Tx(_)
            | Self::Block(_)
            | Self::BlockPayload(_)
            | Self::Headers(_)
            | Self::Feature(_)
            | Self::SendPackages(_)
            | Self::AncPkgInfo(_)
            | Self::GetPkgTxns(_)
            | Self::PkgTxns(_)
            | Self::PkgTxnsPayload(_)
            | Self::StaleTip(_) => {
                unreachable!("native payloads are encoded directly")
            }
            Self::SendHeaders => NetworkMessage::SendHeaders,
            Self::GetAddr => NetworkMessage::GetAddr,
            Self::Ping(nonce) => NetworkMessage::Ping(*nonce),
            Self::Pong(nonce) => NetworkMessage::Pong(*nonce),
            Self::MerkleBlock(block) => NetworkMessage::MerkleBlock(block.clone()),
            Self::FilterLoad(filter) => NetworkMessage::FilterLoad(filter.clone()),
            Self::FilterAdd(filter) => NetworkMessage::FilterAdd(filter.clone()),
            Self::FilterClear => NetworkMessage::FilterClear,
            Self::GetCFilters(message) => NetworkMessage::GetCFilters(message.clone()),
            Self::CFilter(message) => NetworkMessage::CFilter(message.clone()),
            Self::GetCFHeaders(message) => NetworkMessage::GetCFHeaders(message.clone()),
            Self::CFHeaders(message) => NetworkMessage::CFHeaders(message.clone()),
            Self::GetCFCheckpt(message) => NetworkMessage::GetCFCheckpt(message.clone()),
            Self::CFCheckpt(message) => NetworkMessage::CFCheckpt(message.clone()),
            Self::SendCmpct(message) => NetworkMessage::SendCmpct(*message),
            Self::CmpctBlock(message) => NetworkMessage::CmpctBlock(message.clone()),
            Self::GetBlockTxn(message) => NetworkMessage::GetBlockTxn(message.clone()),
            Self::BlockTxn(message) => NetworkMessage::BlockTxn(message.clone()),
            Self::Alert(payload) => NetworkMessage::Alert(payload.clone()),
            Self::Reject(message) => NetworkMessage::Reject(message.clone()),
            Self::FeeFilter(rate) => NetworkMessage::FeeFilter(*rate),
            Self::WtxidRelay => NetworkMessage::WtxidRelay,
            Self::AddrV2(addresses) => NetworkMessage::AddrV2(addresses.clone()),
            Self::SendAddrV2 => NetworkMessage::SendAddrV2,
            Self::Unknown { command, payload } => NetworkMessage::Unknown {
                command: command.clone(),
                payload: payload.clone(),
            },
        }
    }
}

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bitcoin consensus encoding error: {0}")]
    Encode(#[from] encode::Error),
    #[error("varint decode error: {0}")]
    Varint(#[from] bitcoin_rs_primitives::varint::VarintError),
    #[error("native consensus decode error: {0}")]
    NativeDecode(#[from] bitcoin_rs_primitives::DecodeError),
    /// BIP434 feature announcement decoding or encoding failed.
    #[error("feature error: {0}")]
    Feature(#[from] crate::feature::FeatureError),
    /// BIP331 package message decoding or encoding failed.
    #[error("package error: {0}")]
    Package(#[from] crate::packages::PackageError),
    /// BIP332 stale-tip announcement decoding or encoding failed.
    #[error("staletip error: {0}")]
    StaleTip(#[from] crate::staletip::StaleTipError),
    #[error("invalid command `{0}`")]
    InvalidCommand(String),
    #[error("message magic {actual} does not match expected {expected}")]
    WrongNetwork { expected: Magic, actual: Magic },
    #[error("payload length {0} exceeds the transport's payload bound")]
    PayloadTooLarge(usize),
    #[error("invalid payload checksum")]
    BadChecksum,
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    #[error("remote protocol violation: {0}")]
    Misbehavior(&'static str),
    #[error("invalid inbound message: {0}")]
    Incoming(#[source] Box<Self>),
    #[error("discouraged destination {0}")]
    DiscouragedDestination(bitcoin_rs_primitives::PeerAddress),
    #[error("banned destination {0}")]
    BannedDestination(bitcoin_rs_primitives::PeerAddress),
    /// The BIP324 transport failed: a malformed handshake, or a packet that
    /// is oversized or fails authentication. BIP324 does not authenticate
    /// peers, so this ends the connection without implicating the peer.
    #[error(transparent)]
    Transport(#[from] crate::transport::TransportFailure),
}

impl PeerError {
    /// Attributes a receive failure to the remote, except I/O, transport failures and a
    /// frame under another network's magic.
    ///
    /// Core closes a transport on a wrong message start without `Misbehaving`, and a
    /// BIP324 key read by a node with v2 off arrives exactly this way.
    pub(crate) fn inbound(error: Self) -> Self {
        match error {
            Self::Io(_) | Self::Transport(_) | Self::WrongNetwork { .. } => error,
            _ => Self::Incoming(Box::new(error)),
        }
    }

    pub(crate) const fn is_misbehavior(&self) -> bool {
        matches!(self, Self::Misbehavior(_) | Self::Incoming(_))
    }

    pub(crate) fn recoverable_for_protected(&self) -> bool {
        match self {
            Self::Misbehavior(_) => true,
            Self::Incoming(error) => matches!(
                error.as_ref(),
                Self::BadChecksum
                    | Self::Encode(_)
                    | Self::Varint(_)
                    | Self::NativeDecode(_)
                    | Self::Feature(_)
                    | Self::Package(_)
                    | Self::StaleTip(_)
                    | Self::Misbehavior(_)
            ),
            _ => false,
        }
    }
}

fn write_all_vectored<W: Write + ?Sized>(
    writer: &mut W,
    mut slices: &mut [IoSlice<'_>],
) -> Result<(), PeerError> {
    while !slices.is_empty() {
        match writer.write_vectored(slices) {
            Ok(0) => {
                return Err(PeerError::Io(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write whole message",
                )));
            }
            Ok(written) => IoSlice::advance_slices(&mut slices, written),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(PeerError::Io(error)),
        }
    }
    Ok(())
}

pub(crate) struct FramedMessage {
    wire: FrameWire,
    payload: bytes::Bytes,
}

enum FrameWire {
    V1([u8; HEADER_LEN]),
    /// A sealed BIP324 packet, written instead of the header and payload.
    V2(Vec<u8>),
}

impl FramedMessage {
    /// A BIP324 packet carrying `payload`.
    pub(crate) const fn sealed(packet: Vec<u8>, payload: bytes::Bytes) -> Self {
        Self {
            wire: FrameWire::V2(packet),
            payload,
        }
    }

    fn wire_len(&self) -> usize {
        HEADER_LEN + self.payload.len()
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }

    fn push_slices<'a>(&'a self, slices: &mut Vec<IoSlice<'a>>) {
        match &self.wire {
            FrameWire::V1(header) => {
                slices.push(IoSlice::new(header));
                slices.push(IoSlice::new(&self.payload));
            }
            FrameWire::V2(packet) => slices.push(IoSlice::new(packet)),
        }
    }
}

pub(crate) fn message_payload(message: &Message) -> Result<bytes::Bytes, PeerError> {
    let payload = match message {
        Message::Block(block) => block.bytes().clone(),
        Message::BlockPayload(bytes) | Message::PkgTxnsPayload(bytes) => bytes.clone(),
        other => bytes::Bytes::from(encode_payload(other)?),
    };
    if payload.len() > MAX_MESSAGE_PAYLOAD {
        return Err(PeerError::PayloadTooLarge(payload.len()));
    }
    Ok(payload)
}

pub(crate) fn encode_frame(magic: Magic, message: &Message) -> Result<FramedMessage, PeerError> {
    let payload = message_payload(message)?;

    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(&magic.to_bytes());
    header[4..16].copy_from_slice(&encode_command(&message.command())?);
    header[16..20].copy_from_slice(
        &u32::try_from(payload.len())
            .map_err(|_| PeerError::PayloadTooLarge(payload.len()))?
            .to_le_bytes(),
    );
    header[20..24].copy_from_slice(&checksum(&payload));
    Ok(FramedMessage {
        wire: FrameWire::V1(header),
        payload,
    })
}

pub(crate) fn write_frame<W: Write + ?Sized>(
    writer: &mut W,
    frame: &FramedMessage,
) -> Result<usize, PeerError> {
    let mut slices = Vec::with_capacity(2);
    frame.push_slices(&mut slices);
    write_all_vectored(writer, &mut slices)?;
    Ok(frame.wire_len())
}

pub(crate) fn write_frames<W: Write + ?Sized>(
    writer: &mut W,
    frames: &[FramedMessage],
) -> Result<(), PeerError> {
    let mut slices = Vec::with_capacity(frames.len().saturating_mul(2));
    for frame in frames {
        frame.push_slices(&mut slices);
    }
    write_all_vectored(writer, &mut slices)?;
    Ok(())
}

pub fn write_message<W: Write + ?Sized>(
    writer: &mut W,
    magic: Magic,
    message: &Message,
) -> Result<usize, PeerError> {
    let frame = encode_frame(magic, message)?;
    write_frame(writer, &frame)
}

pub fn read_message<R: Read>(
    reader: &mut R,
    expected_magic: Magic,
) -> Result<(Message, bytes::Bytes), PeerError> {
    V1Receiver::default().read_message_with(reader, expected_magic, |_, _| {})
}

#[derive(Debug, Default)]
pub(crate) struct V1Receiver {
    header: [u8; HEADER_LEN],
    header_filled: usize,
    body: Option<PendingBody>,
}

#[derive(Debug)]
struct PendingBody {
    command: String,
    checksum: [u8; 4],
    expected: usize,
    payload: Vec<u8>,
}

impl V1Receiver {
    /// A receiver whose first header already holds `prefix`: the bytes a
    /// BIP324 responder read before it recognized a v1 peer.
    pub(crate) fn with_prefix(prefix: &[u8]) -> Self {
        let mut receiver = Self::default();
        let len = prefix.len().min(HEADER_LEN);
        receiver.header[..len].copy_from_slice(&prefix[..len]);
        receiver.header_filled = len;
        receiver
    }

    pub(crate) fn read_message_with<R: Read>(
        &mut self,
        reader: &mut R,
        expected_magic: Magic,
        observe: impl FnOnce(&str, &[u8]),
    ) -> Result<(Message, bytes::Bytes), PeerError> {
        let mut body = if let Some(body) = self.body.take() {
            body
        } else {
            self.read_header(reader, expected_magic)?
        };
        if let Err(error) = crate::recv::fill_growing(reader, &mut body.payload, body.expected) {
            if crate::recv::is_poll_timeout(&error) {
                self.body = Some(body);
            }
            return Err(error.into());
        }
        if checksum(&body.payload) != body.checksum {
            return Err(PeerError::BadChecksum);
        }

        observe(&body.command, &body.payload);
        let payload = bytes::Bytes::from(body.payload);
        let message = decode_payload(&body.command, &payload)?;
        Ok((message, payload))
    }

    fn read_header<R: Read>(
        &mut self,
        reader: &mut R,
        expected_magic: Magic,
    ) -> Result<PendingBody, PeerError> {
        if let Err(error) = crate::recv::fill(reader, &mut self.header, &mut self.header_filled) {
            if !crate::recv::is_poll_timeout(&error) {
                self.header_filled = 0;
            }
            return Err(error.into());
        }
        self.header_filled = 0;
        pending_body(&self.header, expected_magic)
    }
}

fn pending_body(
    header: &[u8; HEADER_LEN],
    expected_magic: Magic,
) -> Result<PendingBody, PeerError> {
    let actual_magic = Magic::from_bytes([header[0], header[1], header[2], header[3]]);
    if actual_magic != expected_magic {
        return Err(PeerError::WrongNetwork {
            expected: expected_magic,
            actual: actual_magic,
        });
    }

    let command = read_command(&header[4..16])?;
    if command.is_empty() {
        return Err(PeerError::InvalidCommand(String::new()));
    }
    let payload_len_u32 = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    let payload_len =
        usize::try_from(payload_len_u32).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    if payload_len > MAX_MESSAGE_PAYLOAD {
        return Err(PeerError::PayloadTooLarge(payload_len));
    }

    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&header[20..24]);
    Ok(PendingBody {
        command,
        checksum,
        expected: payload_len,
        payload: Vec::new(),
    })
}

pub(crate) fn wire_len(message: &Message) -> Result<usize, PeerError> {
    let payload_len = match message {
        Message::BlockPayload(payload) | Message::PkgTxnsPayload(payload) => payload.len(),
        Message::Tx(tx) => tx.total_size(),
        Message::Block(block) => block.bytes().len(),
        Message::Headers(headers) => {
            let count = u64::try_from(headers.len())
                .map_err(|_| PeerError::PayloadTooLarge(headers.len()))?;
            let count_len = bitcoin_rs_primitives::varint::encode(count).len();
            let entries_len = headers
                .len()
                .checked_mul(81)
                .ok_or(PeerError::PayloadTooLarge(usize::MAX))?;
            count_len
                .checked_add(entries_len)
                .ok_or(PeerError::PayloadTooLarge(usize::MAX))?
        }
        Message::SendPackages(_) => std::mem::size_of::<u64>(),
        Message::AncPkgInfo(info) => info.encode()?.len(),
        Message::GetPkgTxns(request) => request.encode()?.len(),
        Message::PkgTxns(package) => pkgtxns_payload_len(package)?,
        Message::StaleTip(announcement) => crate::staletip::encode(announcement)?.len(),
        Message::Feature(feature) => {
            let id_len = feature.id.as_bytes().len();
            let data_len = feature.data.len();
            let id_len_u64 =
                u64::try_from(id_len).map_err(|_| PeerError::PayloadTooLarge(id_len))?;
            let data_len_u64 =
                u64::try_from(data_len).map_err(|_| PeerError::PayloadTooLarge(data_len))?;
            bitcoin_rs_primitives::varint::encoded_len(id_len_u64)
                .checked_add(id_len)
                .and_then(|l| {
                    l.checked_add(bitcoin_rs_primitives::varint::encoded_len(data_len_u64))
                })
                .and_then(|l| l.checked_add(data_len))
                .ok_or(PeerError::PayloadTooLarge(usize::MAX))?
        }
        other => {
            let envelope = other.envelope();
            bitcoin::consensus::Encodable::consensus_encode(&envelope, &mut bitcoin::io::sink())
                .map_err(encode::Error::from)?
        }
    };
    HEADER_LEN
        .checked_add(payload_len)
        .ok_or(PeerError::PayloadTooLarge(usize::MAX))
}

pub fn encode_payload(message: &Message) -> Result<Vec<u8>, PeerError> {
    let mut payload = Vec::new();
    match message {
        Message::Tx(tx) => tx.consensus_encode(&mut payload),
        Message::Block(block) => payload.extend_from_slice(block.bytes()),
        Message::BlockPayload(bytes) | Message::PkgTxnsPayload(bytes) => {
            payload.extend_from_slice(bytes);
        }
        Message::Headers(headers) => {
            let count = u64::try_from(headers.len())
                .map_err(|_| PeerError::PayloadTooLarge(headers.len()))?;
            encode_varint(&mut payload, count);
            for header in headers {
                header.consensus_encode(&mut payload);
                payload.push(0);
            }
        }
        Message::Feature(feature) => {
            let encoded = crate::feature::encode(feature)?;
            payload.extend_from_slice(&encoded);
        }
        Message::SendPackages(message) => payload.extend_from_slice(&message.encode()),
        Message::AncPkgInfo(message) => payload.extend_from_slice(&message.encode()?),
        Message::GetPkgTxns(message) => payload.extend_from_slice(&message.encode()?),
        Message::PkgTxns(message) => payload = message.encode()?,
        Message::StaleTip(announcement) => {
            payload.extend_from_slice(&crate::staletip::encode(announcement)?);
        }
        other => payload.extend_from_slice(&encode::serialize(&other.envelope())),
    }
    Ok(payload)
}

fn pkgtxns_payload_len(package: &crate::packages::PkgTxns) -> Result<usize, PeerError> {
    use crate::packages::{MAX_GETPKGTXNS, PackageError};

    let count = package.txs.len();
    let count_u64 = u64::try_from(count).unwrap_or(u64::MAX);
    if count == 0 {
        return Err(PackageError::Empty.into());
    }
    if count > MAX_GETPKGTXNS {
        return Err(PackageError::TooMany {
            count: count_u64,
            max: MAX_GETPKGTXNS,
        }
        .into());
    }
    let mut total = bitcoin_rs_primitives::varint::encoded_len(count_u64);
    for tx in &package.txs {
        total = total.saturating_add(tx.total_size());
    }
    if total > MAX_MESSAGE_PAYLOAD {
        return Err(PackageError::PayloadTooLarge(total).into());
    }
    Ok(total)
}

fn encode_varint(payload: &mut Vec<u8>, value: u64) {
    payload.extend_from_slice(&bitcoin_rs_primitives::varint::encode(value));
}

pub(crate) fn decode_payload(command: &str, payload: &bytes::Bytes) -> Result<Message, PeerError> {
    if !crate::compat::is_typed_command(command) {
        return Ok(Message::Unknown {
            command: command_string(command)?,
            payload: payload.to_vec(),
        });
    }

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
        "tx" => Message::Tx(deserialize::<Tx>(payload)?),
        "block" => Message::Block(BlockPayload::from_raw(payload.clone())?),
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
        "feature" => Message::Feature(crate::feature::decode(payload)?),
        "sendpackages" => Message::SendPackages(crate::packages::SendPackages::decode(payload)?),
        "ancpkginfo" => Message::AncPkgInfo(crate::packages::AncPkgInfo::decode(payload)?),
        "getpkgtxns" => Message::GetPkgTxns(crate::packages::GetPkgTxns::decode(payload)?),
        "pkgtxns" if payload.len() > MAX_MESSAGE_PAYLOAD => {
            return Err(PeerError::PayloadTooLarge(payload.len()));
        }
        "pkgtxns" => Message::PkgTxnsPayload(payload.clone()),
        "staletip" => match crate::staletip::decode(payload) {
            Ok(announcement) => Message::StaleTip(announcement),
            Err(error) if error.is_policy_limit() => Message::Unknown {
                command: command_string(crate::staletip::STALETIP_COMMAND)?,
                payload: Vec::new(),
            },
            Err(error) => return Err(error.into()),
        },
        _ => {
            debug_assert!(
                !crate::compat::is_typed_command(command),
                "typed command {command} is missing from decode_payload"
            );
            Message::Unknown {
                command: command_string(command)?,
                payload: payload.to_vec(),
            }
        }
    };
    Ok(message)
}

fn decode_addr(payload: &[u8]) -> Result<Vec<(u32, bitcoin::p2p::Address)>, PeerError> {
    let mut reader = payload;
    let count = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
    let capacity = usize::try_from(count).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    if capacity > MAX_ADDR_MESSAGE_COUNT {
        return Err(PeerError::Misbehavior("addr count too large"));
    }
    let mut addresses = Vec::with_capacity(capacity);
    for _ in 0..count {
        addresses.push(<(u32, bitcoin::p2p::Address)>::consensus_decode(
            &mut reader,
        )?);
    }
    if !reader.is_empty() {
        return Err(PeerError::Misbehavior("trailing bytes after addr payload"));
    }
    Ok(addresses)
}

fn decode_addrv2(payload: &[u8]) -> Result<Vec<AddrV2Message>, PeerError> {
    let mut reader = payload;
    let count = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
    let capacity = usize::try_from(count).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    if capacity > MAX_ADDR_MESSAGE_COUNT {
        return Err(PeerError::Misbehavior("addrv2 count too large"));
    }
    let mut addresses = Vec::with_capacity(capacity);
    for _ in 0..count {
        addresses.push(AddrV2Message::consensus_decode(&mut reader)?);
    }
    if !reader.is_empty() {
        return Err(PeerError::Misbehavior(
            "trailing bytes after addrv2 payload",
        ));
    }
    Ok(addresses)
}

fn decode_inventory(payload: &[u8]) -> Result<Vec<Inventory>, PeerError> {
    let mut reader = payload;
    let count = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
    let capacity = usize::try_from(count).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    if capacity > MAX_INV_PER_MSG {
        return Err(PeerError::Misbehavior("inventory count too large"));
    }
    let mut inventory = Vec::with_capacity(capacity);
    for _ in 0..count {
        inventory.push(Inventory::consensus_decode(&mut reader)?);
    }
    if !reader.is_empty() {
        return Err(PeerError::Misbehavior(
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
        return Err(PeerError::Misbehavior(match command {
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
        return Err(PeerError::Misbehavior(match command {
            "getblocks" => "trailing bytes after getblocks payload",
            "getheaders" => "trailing bytes after getheaders payload",
            _ => "trailing bytes after locator payload",
        }));
    }

    Ok((version, locator_hashes, stop_hash))
}

fn decode_headers(payload: &[u8]) -> Result<Vec<Header>, PeerError> {
    let mut reader = payload;
    let (count, consumed) = bitcoin_rs_primitives::varint::decode(reader)?;
    reader = &reader[consumed..];
    let capacity = usize::try_from(count).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    if capacity > MAX_HEADERS_MESSAGE_COUNT {
        return Err(PeerError::Misbehavior("headers count too large"));
    }
    let mut headers = Vec::with_capacity(capacity);
    for _ in 0..count {
        headers.push(<Header as ConsensusDecode>::consensus_decode(&mut reader)?);
        let (tx_count, consumed) = bitcoin_rs_primitives::varint::decode(reader)?;
        reader = &reader[consumed..];
        if tx_count != 0 {
            return Err(PeerError::Misbehavior("headers entry carried transactions"));
        }
    }
    if !reader.is_empty() {
        return Err(PeerError::Misbehavior(
            "trailing bytes after headers payload",
        ));
    }
    Ok(headers)
}

fn empty_payload(payload: &[u8], message: Message) -> Result<Message, PeerError> {
    if payload.is_empty() {
        Ok(message)
    } else {
        Err(PeerError::Misbehavior("expected empty payload"))
    }
}

fn encode_command(command: &CommandString) -> Result<[u8; COMMAND_LEN], PeerError> {
    let command = command.as_ref().as_bytes();
    if command.len() > COMMAND_LEN || command.contains(&0) {
        return Err(PeerError::InvalidCommand(
            String::from_utf8_lossy(command).into_owned(),
        ));
    }
    let mut raw = [0u8; COMMAND_LEN];
    raw[..command.len()].copy_from_slice(command);
    Ok(raw)
}

/// Parses a 12-byte command field: a UTF-8 name, then only zero padding. The
/// v1 header and the BIP324 long message type share this encoding.
pub(crate) fn read_command(raw: &[u8]) -> Result<String, PeerError> {
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
mod tests;
