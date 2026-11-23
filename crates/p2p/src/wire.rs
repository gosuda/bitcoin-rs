use std::io::{IoSlice, Read, Write};

use bytes;

use bitcoin::Transaction;
use bitcoin::bip152::{
    BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds, PrefilledTransaction, ShortId,
};
use bitcoin::consensus::encode::{self, Decodable};
use bitcoin::p2p::Magic;
use bitcoin::p2p::address::{AddrV2Message, Address};
use bitcoin::p2p::message::CommandString;
use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
use bitcoin::p2p::message_bloom::{FilterAdd, FilterLoad};
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
use bitcoin::p2p::message_filter::{
    CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters,
};
use bitcoin::p2p::message_network::{Reject, VersionMessage};
use bitcoin_rs_consensus::primitives::{
    BlockImage, ConsensusDecode, ConsensusEncode, Header, Tx, deserialize,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::inv::MAX_INV_PER_MSG;

pub const PROTOCOL_VERSION: u32 = 70_017;

pub const MIN_PEER_PROTO_VERSION: u32 = 31_800;

const _: () = assert!(PROTOCOL_VERSION >= crate::feature::FEATURE_VERSION);

pub const MAX_MESSAGE_PAYLOAD: usize = 4_000_000;
pub(crate) const MAX_WRITE_BURST: usize = 8;

pub const MAX_HEADERS_MESSAGE_COUNT: usize = 2_000;

pub const MAX_LOCATOR_HASHES: usize = 101;

pub const MAX_BLOCK_TX_COUNT: usize = 100_000;

const MIN_TRANSACTION_WIRE_BYTES: usize = 10;

const MIN_PREFILLED_WIRE_BYTES: usize = MIN_TRANSACTION_WIRE_BYTES + 1;

const SHORT_ID_WIRE_BYTES: usize = 6;

pub const MAX_ADDR_MESSAGE_COUNT: usize = 1_000;

pub const HEADER_LEN: usize = 24;

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
    Block(BlockImage),
    BlockBytes(bytes::Bytes),
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
    Feature(crate::feature::FeatureAnnouncement),
    SendPackages(crate::packages::SendPackages),
    AncPkgInfo(crate::packages::AncPkgInfo),
    GetPkgTxns(crate::packages::GetPkgTxns),
    PkgTxns(crate::packages::PkgTxns),
    PkgTxnsPayload(bytes::Bytes),
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
            Self::Block(_) | Self::BlockBytes(_) => "block",
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
                | Self::BlockBytes(_)
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
    fn encode_bitcoin_payload<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        use bitcoin::consensus::Encodable;

        match self {
            Self::Version(message) => message.consensus_encode(writer),
            Self::Addr(addresses) => addresses.consensus_encode(writer),
            Self::Inv(inventory) | Self::GetData(inventory) | Self::NotFound(inventory) => {
                inventory.consensus_encode(writer)
            }
            Self::GetBlocks(message) => message.consensus_encode(writer),
            Self::GetHeaders(message) => message.consensus_encode(writer),
            Self::Tx(_)
            | Self::Block(_)
            | Self::BlockBytes(_)
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
            Self::Ping(nonce) | Self::Pong(nonce) => nonce.consensus_encode(writer),
            Self::MerkleBlock(block) => block.consensus_encode(writer),
            Self::FilterLoad(filter) => filter.consensus_encode(writer),
            Self::FilterAdd(filter) => filter.consensus_encode(writer),
            Self::GetCFilters(message) => message.consensus_encode(writer),
            Self::CFilter(message) => message.consensus_encode(writer),
            Self::GetCFHeaders(message) => message.consensus_encode(writer),
            Self::CFHeaders(message) => message.consensus_encode(writer),
            Self::GetCFCheckpt(message) => message.consensus_encode(writer),
            Self::CFCheckpt(message) => message.consensus_encode(writer),
            Self::SendCmpct(message) => message.consensus_encode(writer),
            Self::CmpctBlock(message) => message.consensus_encode(writer),
            Self::GetBlockTxn(message) => message.consensus_encode(writer),
            Self::BlockTxn(message) => message.consensus_encode(writer),
            Self::Alert(payload) => payload.consensus_encode(writer),
            Self::Reject(message) => message.consensus_encode(writer),
            Self::FeeFilter(rate) => rate.consensus_encode(writer),
            Self::AddrV2(addresses) => addresses.consensus_encode(writer),
            Self::Verack
            | Self::MemPool
            | Self::SendHeaders
            | Self::GetAddr
            | Self::FilterClear
            | Self::WtxidRelay
            | Self::SendAddrV2 => Ok(0),
            Self::Unknown { payload, .. } => writer.write(payload),
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
    Varint(#[from] bitcoin_rs_consensus::primitives::varint::VarintError),
    #[error("native consensus decode error: {0}")]
    NativeDecode(#[from] bitcoin_rs_consensus::primitives::DecodeError),
    #[error("feature error: {0}")]
    Feature(#[from] crate::feature::FeatureError),
    #[error("package error: {0}")]
    Package(#[from] crate::packages::PackageError),
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
    DiscouragedDestination(bitcoin_rs_consensus::primitives::PeerAddress),
    #[error("banned destination {0}")]
    BannedDestination(bitcoin_rs_consensus::primitives::PeerAddress),
    #[error(transparent)]
    Transport(#[from] crate::transport::TransportFailure),
    #[error("self-connection detected")]
    SelfConnection,
    #[error("obsolete peer protocol version {0}")]
    ObsoleteVersion(u32),
}

impl PeerError {
    pub(crate) fn inbound(error: Self) -> Self {
        match error {
            Self::Io(_)
            | Self::Transport(_)
            | Self::WrongNetwork { .. }
            | Self::SelfConnection
            | Self::ObsoleteVersion(_) => error,
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

/// `progress` runs after each accepted chunk with the cumulative byte count
/// the writer accepted so far, including the chunk that completes the write;
/// it never runs for a chunk of zero bytes (that is a `WriteZero` error).
fn write_all_vectored<W: Write + ?Sized>(
    writer: &mut W,
    mut slices: &mut [IoSlice<'_>],
    mut progress: impl FnMut(usize),
) -> Result<(), PeerError> {
    let mut accepted = 0;
    while !slices.is_empty() {
        match writer.write_vectored(slices) {
            Ok(0) => {
                return Err(PeerError::Io(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write whole message",
                )));
            }
            Ok(written) => {
                IoSlice::advance_slices(&mut slices, written);
                accepted += written;
                progress(accepted);
            }
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
    V2(Vec<u8>),
}

impl FramedMessage {
    pub(crate) const fn sealed(packet: Vec<u8>, payload: bytes::Bytes) -> Self {
        Self {
            wire: FrameWire::V2(packet),
            payload,
        }
    }

    /// The bytes this frame puts on the wire: the v1 header plus payload, or
    /// the sealed BIP324 packet as a whole.
    pub(crate) fn wire_len(&self) -> usize {
        match &self.wire {
            FrameWire::V1(_) => HEADER_LEN + self.payload.len(),
            FrameWire::V2(packet) => packet.len(),
        }
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
        Message::BlockBytes(bytes) | Message::PkgTxnsPayload(bytes) => bytes.clone(),
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
    write_all_vectored(writer, &mut slices, |_| {})?;
    Ok(frame.wire_len())
}

/// Writes every frame, reporting each one to `fully_written`, in order, once
/// the writer has accepted that frame's final byte (Core's flush semantics:
/// a message's sent bytes count only once the socket took the whole frame).
///
/// Partial acceptance is ordinary backpressure — the loop retries the
/// remainder — so every frame is reported on success. An error leaves
/// exactly the frames reported so far charged, which tracks the socket-level
/// counter: it, too, counted only the accepted prefix.
pub(crate) fn write_frames<W: Write + ?Sized>(
    writer: &mut W,
    frames: &[FramedMessage],
    mut fully_written: impl FnMut(usize),
) -> Result<(), PeerError> {
    let mut slices = Vec::with_capacity(frames.len().saturating_mul(2));
    let mut frame_ends = Vec::with_capacity(frames.len());
    let mut end = 0;
    for frame in frames {
        frame.push_slices(&mut slices);
        end += frame.wire_len();
        frame_ends.push(end);
    }
    let mut reported = 0;
    write_all_vectored(writer, &mut slices, |accepted| {
        while reported < frame_ends.len() && frame_ends[reported] <= accepted {
            fully_written(reported);
            reported += 1;
        }
    })
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
    loop {
        if let Some(message) = V1Receiver::default().read_message_with(
            reader,
            expected_magic,
            |_, _, _| {},
            |_, _| Ok(()),
            |_, _| Ok(()),
        )? {
            return Ok(message);
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct V1Receiver {
    header: [u8; HEADER_LEN],
    header_filled: usize,
    body: Option<PendingBody>,
    memory: Option<std::sync::Arc<crate::inbound::block_memory::BlockMemory>>,
}

#[derive(Debug)]
struct PendingBody {
    command: String,
    checksum: [u8; 4],
    expected: usize,
    payload: crate::recv::Backing,
}

impl V1Receiver {
    pub(crate) fn receive_pending(&self) -> bool {
        self.body.is_some()
    }

    pub(crate) fn bind_memory(
        &mut self,
        memory: &std::sync::Arc<crate::inbound::block_memory::BlockMemory>,
    ) -> std::io::Result<()> {
        if self.memory.is_none()
            && self
                .body
                .as_ref()
                .is_some_and(|body| body.payload.capacity() != 0)
        {
            return Err(std::io::Error::other(
                "cannot bind a live uncharged receive",
            ));
        }
        crate::recv::bind_memory(&mut self.memory, memory)
    }

    pub(crate) fn with_prefix(prefix: &[u8]) -> Self {
        let mut receiver = Self::default();
        let len = prefix.len().min(HEADER_LEN);
        receiver.header[..len].copy_from_slice(&prefix[..len]);
        receiver.header_filled = len;
        receiver
    }

    /// `account` receives the command, payload, and v1 header-plus-payload
    /// length of each checksum-valid frame, including a budget-refused frame.
    /// `check` validates that frame before an image-budget refusal can drop it.
    /// `admit` reserves decoder memory only for frames that will be delivered.
    ///
    /// `Ok(None)` means a completed `block` frame was dropped because the
    /// image lane refused its backing: the untouched receive charge releases
    /// with the frame, the decode reservation (if any) releases with the
    /// caller, and the connection stays up to read the next frame.
    pub(crate) fn read_message_with<R: Read>(
        &mut self,
        reader: &mut R,
        expected_magic: Magic,
        mut account: impl FnMut(&str, &[u8], usize),
        check: impl FnOnce(&str, &[u8]) -> Result<(), PeerError>,
        admit: impl FnOnce(&str, &[u8]) -> Result<(), PeerError>,
    ) -> Result<Option<(Message, bytes::Bytes)>, PeerError> {
        let mut body = if let Some(body) = self.body.take() {
            body
        } else {
            self.read_header(reader, expected_magic)?
        };
        if let Err(error) = crate::recv::fill_backing(
            reader,
            &mut body.payload,
            body.expected,
            self.memory.as_ref(),
        ) {
            if crate::recv::is_poll_timeout(&error) {
                self.body = Some(body);
            }
            return Err(error.into());
        }
        if checksum(&body.payload) != body.checksum {
            return Err(PeerError::BadChecksum);
        }

        account(
            &body.command,
            &body.payload,
            HEADER_LEN + body.payload.len(),
        );
        check(&body.command, &body.payload)?;
        if body.command == "block" && !body.payload.transfer_to_image() {
            return Ok(None);
        }
        admit(&body.command, &body.payload)?;
        let payload = body.payload.into_bytes();
        let message = decode_payload(&body.command, &payload)?;
        Ok(Some((message, payload)))
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
        command: command.to_owned(),
        checksum,
        expected: payload_len,
        payload: crate::recv::Backing::default(),
    })
}

pub fn wire_len(message: &Message) -> Result<usize, PeerError> {
    let payload_len = match message {
        Message::BlockBytes(payload) | Message::PkgTxnsPayload(payload) => payload.len(),
        Message::Tx(tx) => tx.total_size(),
        Message::Block(block) => block.bytes().len(),
        Message::Headers(headers) => {
            let count = u64::try_from(headers.len())
                .map_err(|_| PeerError::PayloadTooLarge(headers.len()))?;
            let count_len = bitcoin_rs_consensus::primitives::varint::encode(count).len();
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
            bitcoin_rs_consensus::primitives::varint::encoded_len(id_len_u64)
                .checked_add(id_len)
                .and_then(|l| {
                    l.checked_add(bitcoin_rs_consensus::primitives::varint::encoded_len(
                        data_len_u64,
                    ))
                })
                .and_then(|l| l.checked_add(data_len))
                .ok_or(PeerError::PayloadTooLarge(usize::MAX))?
        }
        other => other
            .encode_bitcoin_payload(&mut bitcoin::io::sink())
            .map_err(encode::Error::from)?,
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
        Message::BlockBytes(bytes) | Message::PkgTxnsPayload(bytes) => {
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
        other => {
            let payload_len = other
                .encode_bitcoin_payload(&mut bitcoin::io::sink())
                .map_err(encode::Error::from)?;
            payload.reserve_exact(payload_len);
            other
                .encode_bitcoin_payload(&mut payload)
                .map_err(encode::Error::from)?;
        }
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
    let mut total = bitcoin_rs_consensus::primitives::varint::encoded_len(count_u64);
    for tx in &package.txs {
        total = total.saturating_add(tx.total_size());
    }
    if total > MAX_MESSAGE_PAYLOAD {
        return Err(PackageError::PayloadTooLarge(total).into());
    }
    Ok(total)
}

fn encode_varint(payload: &mut Vec<u8>, value: u64) {
    payload.extend_from_slice(&bitcoin_rs_consensus::primitives::varint::encode(value));
}

pub(crate) fn decode_payload(command: &str, payload: &bytes::Bytes) -> Result<Message, PeerError> {
    if !crate::compat::is_typed_command(command) {
        return Ok(Message::Unknown {
            command: command_string(command)?,
            payload: payload.to_vec(),
        });
    }

    let message = match command {
        "version" => Message::Version(decode_version(payload)?),
        "verack" => empty_payload(payload, Message::Verack)?,
        "addr" => Message::Addr(decode_addr(payload)?),
        "inv" => Message::Inv(decode_inventory(payload)?),
        "getdata" => Message::GetData(decode_inventory(payload)?),
        "notfound" => Message::NotFound(decode_inventory(payload)?),
        "getblocks" => Message::GetBlocks(decode_getblocks(payload)?),
        "getheaders" => Message::GetHeaders(decode_getheaders(payload)?),
        "mempool" => empty_payload(payload, Message::MemPool)?,
        "tx" => Message::Tx(deserialize::<Tx>(payload)?),
        "block" => Message::Block(BlockImage::from_raw(payload.clone())?),
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
        "sendcmpct" => Message::SendCmpct(decode_sendcmpct(payload)?),
        "cmpctblock" => decode_cmpctblock(payload)?,
        "getblocktxn" => decode_getblocktxn(payload)?,
        "blocktxn" => decode_blocktxn(payload)?,
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
                payload: payload.to_vec(),
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
    let (count, consumed) = bitcoin_rs_consensus::primitives::varint::decode(reader)?;
    reader = &reader[consumed..];
    let capacity = usize::try_from(count).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
    if capacity > MAX_HEADERS_MESSAGE_COUNT {
        return Err(PeerError::Misbehavior("headers count too large"));
    }
    let mut headers = Vec::with_capacity(capacity);
    for _ in 0..count {
        headers.push(<Header as ConsensusDecode>::consensus_decode(&mut reader)?);
        let (tx_count, consumed) = bitcoin_rs_consensus::primitives::varint::decode(reader)?;
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

fn decode_sendcmpct(payload: &[u8]) -> Result<SendCmpct, PeerError> {
    if payload.len() < 9 {
        return Err(
            bitcoin::consensus::encode::Error::ParseFailed("sendcmpct payload too short").into(),
        );
    }
    let mut version = [0_u8; 8];
    version.copy_from_slice(&payload[1..9]);
    Ok(SendCmpct {
        send_compact: payload[0] != 0,
        version: u64::from_le_bytes(version),
    })
}

fn decode_version(payload: &[u8]) -> Result<VersionMessage, PeerError> {
    let mut reader = payload;
    let version = u32::consensus_decode(&mut reader)?;
    let services = bitcoin::p2p::ServiceFlags::consensus_decode(&mut reader)?;
    let timestamp = i64::consensus_decode(&mut reader)?;
    let receiver = if reader.is_empty() {
        unspecified_address()
    } else {
        Address::consensus_decode(&mut reader)?
    };
    let (sender, nonce) = if reader.is_empty() {
        (unspecified_address(), 1)
    } else {
        let sender = Address::consensus_decode(&mut reader)?;
        (sender, u64::consensus_decode(&mut reader)?)
    };
    let user_agent = if reader.is_empty() {
        String::new()
    } else {
        let len = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
        let len = usize::try_from(len).map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
        if len > reader.len() {
            return Err(bitcoin::consensus::encode::Error::ParseFailed(
                "version subversion exceeds the payload",
            )
            .into());
        }
        let (agent, rest) = reader.split_at(len);
        reader = rest;
        String::from_utf8_lossy(agent).into_owned()
    };
    let start_height = if reader.is_empty() {
        -1
    } else {
        i32::consensus_decode(&mut reader)?
    };
    let relay = if reader.is_empty() {
        true
    } else {
        bool::consensus_decode(&mut reader)?
    };
    Ok(VersionMessage {
        version,
        services,
        timestamp,
        receiver,
        sender,
        nonce,
        user_agent,
        start_height,
        relay,
    })
}

fn unspecified_address() -> Address {
    Address {
        services: bitcoin::p2p::ServiceFlags::NONE,
        address: [0; 8],
        port: 0,
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

pub(crate) fn read_command(raw: &[u8]) -> Result<&str, PeerError> {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    if raw[end..].iter().any(|byte| *byte != 0) {
        return Err(PeerError::InvalidCommand(
            String::from_utf8_lossy(raw).into_owned(),
        ));
    }
    let command_bytes = &raw[..end];
    if !command_bytes
        .iter()
        .all(|byte| (0x20..=0x7e).contains(byte))
    {
        return Err(PeerError::InvalidCommand(
            String::from_utf8_lossy(raw).into_owned(),
        ));
    }
    std::str::from_utf8(command_bytes)
        .map_err(|_| PeerError::InvalidCommand(String::from_utf8_lossy(raw).into_owned()))
}

/// Core reads the whole struct and throws when the declared transaction count
/// exceeds `uint16_t` or cannot fit the payload; `ProcessMessages` logs that
/// failure and keeps the connection, so the message is dropped, not punished.
fn decode_cmpctblock(payload: &bytes::Bytes) -> Result<Message, PeerError> {
    let mut reader = payload.as_ref();
    let header = bitcoin::block::Header::consensus_decode(&mut reader)?;
    let nonce = u64::consensus_decode(&mut reader)?;
    let short_ids_count = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
    let short_ids_room = u64::try_from(reader.len() / SHORT_ID_WIRE_BYTES).unwrap_or(u64::MAX);
    if short_ids_count > short_ids_room {
        return dropped_message("cmpctblock", payload);
    }
    let mut short_ids = Vec::with_capacity(usize::try_from(short_ids_count).unwrap_or(0));
    for _ in 0..short_ids_count {
        short_ids.push(ShortId::consensus_decode(&mut reader)?);
    }
    let prefilled_count = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
    if short_ids_count.saturating_add(prefilled_count) > u64::from(u16::MAX) {
        return dropped_message("cmpctblock", payload);
    }
    let prefilled_room = u64::try_from(reader.len() / MIN_PREFILLED_WIRE_BYTES).unwrap_or(u64::MAX);
    if prefilled_count > prefilled_room {
        return dropped_message("cmpctblock", payload);
    }
    let mut prefilled_txs = Vec::with_capacity(usize::try_from(prefilled_count).unwrap_or(0));
    for _ in 0..prefilled_count {
        let index = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
        let Ok(idx) = u16::try_from(index) else {
            return dropped_message("cmpctblock", payload);
        };
        let tx = decode_bounded_transaction(&mut reader)?;
        prefilled_txs.push(PrefilledTransaction { idx, tx });
    }
    Ok(Message::CmpctBlock(CmpctBlock {
        compact_block: HeaderAndShortIds {
            header,
            nonce,
            short_ids,
            prefilled_txs,
        },
    }))
}

fn decode_bounded_transaction(reader: &mut &[u8]) -> Result<Transaction, PeerError> {
    let tx = Tx::consensus_decode(reader)?;
    let raw = bitcoin_rs_consensus::primitives::consensus_bytes(&tx);
    Transaction::consensus_decode(&mut raw.as_slice()).map_err(PeerError::from)
}

fn decode_blocktxn(payload: &bytes::Bytes) -> Result<Message, PeerError> {
    let mut reader = payload.as_ref();
    let block_hash = bitcoin::BlockHash::consensus_decode(&mut reader)?;
    let count = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
    let room = u64::try_from(reader.len() / MIN_TRANSACTION_WIRE_BYTES).unwrap_or(u64::MAX);
    if count > room {
        return dropped_message("blocktxn", payload);
    }
    let mut transactions = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for _ in 0..count {
        transactions.push(decode_bounded_transaction(&mut reader)?);
    }
    Ok(Message::BlockTxn(BlockTxn {
        transactions: BlockTransactions {
            block_hash,
            transactions,
        },
    }))
}

fn decode_getblocktxn(payload: &bytes::Bytes) -> Result<Message, PeerError> {
    let mut reader = payload.as_ref();
    let block_hash = bitcoin::BlockHash::consensus_decode(&mut reader)?;
    let count = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
    let room = u64::try_from(reader.len()).unwrap_or(u64::MAX);
    if count > room {
        return dropped_message("getblocktxn", payload);
    }
    let mut indexes = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    let mut last_index: u64 = 0;
    for _ in 0..count {
        let differential = bitcoin::consensus::encode::VarInt::consensus_decode(&mut reader)?.0;
        last_index = last_index
            .checked_add(differential)
            .ok_or_else(|| PeerError::Misbehavior("getblocktxn index overflow"))?;
        indexes.push(last_index);
        last_index = last_index
            .checked_add(1)
            .ok_or_else(|| PeerError::Misbehavior("getblocktxn index overflow"))?;
    }
    Ok(Message::GetBlockTxn(GetBlockTxn {
        txs_request: BlockTransactionsRequest {
            block_hash,
            indexes,
        },
    }))
}

fn dropped_message(command: &str, payload: &bytes::Bytes) -> Result<Message, PeerError> {
    Ok(Message::Unknown {
        command: command_string(command)?,
        payload: payload.to_vec(),
    })
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
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::Magic;
    use bitcoin::p2p::ServiceFlags;

    use super::{
        HEADER_LEN, MAX_MESSAGE_PAYLOAD, Message, PeerError, encode_payload, read_message,
        wire_len, write_message,
    };

    const APPROVED_RECEIVE_READ_STEP: usize = 16 * 1024;

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
            |command, payload, _wire_len| {
                observed = Some((command.to_owned(), payload.to_vec()));
            },
            |_, _| Ok(()),
            |_, _| Ok(()),
        );
        assert!(matches!(result, Err(PeerError::Encode(_))));
        assert_eq!(observed, Some(("version".to_owned(), Vec::new())));

        frame[20] ^= 1;
        let mut observed_bad_checksum = false;
        let result = super::V1Receiver::default().read_message_with(
            &mut Cursor::new(frame),
            Magic::REGTEST,
            |_, _, _| {
                observed_bad_checksum = true;
            },
            |_, _| Ok(()),
            |_, _| Ok(()),
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
            let result = receiver.read_message_with(
                &mut stream,
                Magic::REGTEST,
                |_, _, _| {},
                |_, _| Ok(()),
                |_, _| Ok(()),
            );
            assert!(
                matches!(&result, Err(PeerError::Io(error)) if error.kind() == stall),
                "a stall surfaces as a retryable timeout, got {result:?}"
            );
        }
        let (first, _) = receiver
            .read_message_with(
                &mut stream,
                Magic::REGTEST,
                |_, _, _| {},
                |_, _| Ok(()),
                |_, _| Ok(()),
            )?
            .ok_or(PeerError::Protocol("ping frame dropped"))?;
        assert_eq!(first, super::Message::Ping(42));
        let (second, _) = receiver
            .read_message_with(
                &mut stream,
                Magic::REGTEST,
                |_, _, _| {},
                |_, _| Ok(()),
                |_, _| Ok(()),
            )?
            .ok_or(PeerError::Protocol("pong frame dropped"))?;
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
            Inbound::Stall(ErrorKind::TimedOut),
            Inbound::Bytes(dribble.to_vec()),
            Inbound::Stall(ErrorKind::TimedOut),
        ]);
        let mut receiver = super::V1Receiver::default();
        let empty = receiver.read_message_with(
            &mut stream,
            Magic::REGTEST,
            |_, _, _| {},
            |_, _| Ok(()),
            |_, _| Ok(()),
        );
        assert!(matches!(
            empty,
            Err(PeerError::Io(error)) if error.kind() == ErrorKind::TimedOut
        ));
        assert_eq!(
            receiver
                .body
                .as_ref()
                .map_or(0, |body| body.payload.capacity()),
            0
        );
        let result = receiver.read_message_with(
            &mut stream,
            Magic::REGTEST,
            |_, _, _| {},
            |_, _| Ok(()),
            |_, _| Ok(()),
        );
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
            body.payload.capacity() <= 2 * dribble.len(),
            "no full-size allocation is retained for a stalled declared payload"
        );
        Ok(())
    }

    #[test]
    fn cancelled_legacy_frame_requests_at_most_a_16_kib_body_read_step() -> Result<(), PeerError> {
        use crate::test_support::{Inbound, ReadRequests, StallingStream};
        use std::io::ErrorKind;

        let mut frame = Vec::new();
        write_message(
            &mut frame,
            Magic::REGTEST,
            &Message::BlockBytes(vec![7; 1024 * 1024].into()),
        )?;
        let mut stream = ReadRequests {
            reader: StallingStream::new([
                Inbound::Bytes(frame[..HEADER_LEN + 100].to_vec()),
                Inbound::Stall(ErrorKind::ConnectionAborted),
            ]),
            lengths: Vec::new(),
        };
        let mut receiver = super::V1Receiver::default();
        let result = receiver.read_message_with(
            &mut stream,
            Magic::REGTEST,
            |_, _, _| {},
            |_, _| Ok(()),
            |_, _| Ok(()),
        );
        assert!(matches!(
            result,
            Err(PeerError::Io(error)) if error.kind() == ErrorKind::ConnectionAborted
        ));
        assert_eq!(stream.lengths.first(), Some(&HEADER_LEN));
        let largest_body_read = stream
            .lengths
            .iter()
            .skip(1)
            .copied()
            .max()
            .ok_or(PeerError::Protocol("no legacy body read was requested"))?;
        assert!(largest_body_read > 0);
        assert!(
            largest_body_read <= APPROVED_RECEIVE_READ_STEP,
            "legacy body read requested {largest_body_read} bytes"
        );
        assert!(
            receiver
                .body
                .as_ref()
                .is_none_or(|body| body.payload.capacity() <= 2 * 100),
            "a cancelled frame must not retain an allocation sized by the declared payload"
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
        let rejected = receiver.read_message_with(
            &mut stream,
            Magic::REGTEST,
            |_, _, _| {},
            |_, _| Ok(()),
            |_, _| Ok(()),
        );
        assert!(matches!(rejected, Err(PeerError::BadChecksum)));
        let (message, _) = receiver
            .read_message_with(
                &mut stream,
                Magic::REGTEST,
                |_, _, _| {},
                |_, _| Ok(()),
                |_, _| Ok(()),
            )?
            .ok_or(PeerError::Protocol("pong frame dropped"))?;
        assert_eq!(message, super::Message::Pong(2));
        Ok(())
    }

    #[test]
    fn block_message_roundtrip_preserves_wire_payload() -> Result<(), super::PeerError> {
        use bitcoin_rs_consensus::primitives::BlockImage;

        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let block_bytes = serialize(&block);
        let message = super::Message::Block(
            BlockImage::from_raw(bytes::Bytes::from(block_bytes.clone()))
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
        let native_hash = decoded_payload.header().compute_hash();
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
        use bitcoin_rs_consensus::primitives::BlockImage;

        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let block_bytes = serialize(&block);
        let payload_bytes = bytes::Bytes::from(block_bytes);
        let decoded = super::Message::Block(
            BlockImage::from_raw(payload_bytes.clone()).map_err(super::PeerError::NativeDecode)?,
        );
        let payload = super::Message::BlockBytes(payload_bytes);

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
            super::Message::Tx(bitcoin_rs_consensus::primitives::Tx::default()),
            super::Message::Ping(0x1234_5678_9abc_def0),
            super::Message::Verack,
            super::Message::Headers(vec![
                bitcoin_rs_consensus::primitives::Header::default();
                2_000
            ]),
            super::Message::Block(bitcoin_rs_consensus::primitives::BlockImage::from_local(
                bitcoin_rs_consensus::primitives::Block::default(),
            )),
            super::Message::BlockBytes(bytes::Bytes::from(vec![0_u8; 80])),
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

        assert_eq!(
            raw.as_ref(),
            &[6, b'B', b'I', b'P', b'3', b'3', b'2', 4, 1, 2, 3, 4]
        );
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

    fn package_wtxid(tag: u8) -> bitcoin_rs_consensus::primitives::Wtxid {
        bitcoin_rs_consensus::primitives::Wtxid(
            bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[tag; 32]),
        )
    }

    fn package_tx(tag: u8) -> Result<bitcoin_rs_consensus::primitives::Tx, PeerError> {
        let mut raw = vec![1, 0, 0, 0, 1];
        raw.extend_from_slice(&[tag; 32]);
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.push(0);
        raw.extend_from_slice(&u32::MAX.to_le_bytes());
        raw.push(1);
        raw.extend_from_slice(&1_000u64.to_le_bytes());
        raw.push(0);
        raw.extend_from_slice(&0u32.to_le_bytes());
        Ok(bitcoin_rs_consensus::primitives::deserialize::<
            bitcoin_rs_consensus::primitives::Tx,
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
                txs: vec![bitcoin_rs_consensus::primitives::Tx::default(); over],
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
            fork_point: bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[7; 32]),
            headers: vec![
                CompressedHeader {
                    version: 0x2000_0000,
                    merkle_root: bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[1; 32]),
                    time: 1_700_000_000,
                    bits: bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(
                        0x1d00_ffff
                    ),
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
                if command.as_ref() == "staletip" && payload.as_slice() == over.as_slice()),
            "{ignored:?}"
        );
        let mut rewritten = Vec::new();
        write_message(&mut rewritten, Magic::REGTEST, &ignored)?;
        let (re_decoded, _) = read_message(&mut Cursor::new(rewritten), Magic::REGTEST)?;
        assert_eq!(re_decoded, ignored);

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

    // P2P-01
    #[test]
    fn version_relay_reads_any_nonzero_byte_as_true() -> Result<(), PeerError> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&Magic::REGTEST.to_bytes());
        let mut cmd = [0u8; 12];
        cmd[..7].copy_from_slice(b"version");
        frame.extend_from_slice(&cmd);

        let mut payload = Vec::new();
        payload.extend_from_slice(&70017u32.to_le_bytes());
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&0i64.to_le_bytes());
        payload.extend_from_slice(&[0u8; 26]);
        payload.extend_from_slice(&[0u8; 26]);
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&0i32.to_le_bytes());
        payload.push(2);

        let len =
            u32::try_from(payload.len()).map_err(|_| PeerError::PayloadTooLarge(payload.len()))?;
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(&super::checksum(&payload));
        frame.extend_from_slice(&payload);

        let mut cursor = Cursor::new(frame);
        let (message, _) = read_message(&mut cursor, Magic::REGTEST)?;
        let Message::Version(version) = message else {
            panic!("expected a version message");
        };
        assert!(version.relay, "Core reads any nonzero relay byte as true");
        Ok(())
    }

    fn read_version_payload(
        payload: &[u8],
    ) -> Result<bitcoin::p2p::message_network::VersionMessage, PeerError> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&Magic::REGTEST.to_bytes());
        let mut cmd = [0u8; 12];
        cmd[..7].copy_from_slice(b"version");
        frame.extend_from_slice(&cmd);
        let len =
            u32::try_from(payload.len()).map_err(|_| PeerError::PayloadTooLarge(payload.len()))?;
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(&super::checksum(payload));
        frame.extend_from_slice(payload);
        let (message, _) = read_message(&mut Cursor::new(frame), Magic::REGTEST)?;
        let Message::Version(version) = message else {
            panic!("expected a version message");
        };
        Ok(version)
    }

    // P2P-01
    #[test]
    fn version_without_optional_fields_decodes_with_core_defaults() -> Result<(), PeerError> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&70_017u32.to_le_bytes());
        payload.extend_from_slice(
            &(ServiceFlags::NETWORK | ServiceFlags::WITNESS)
                .to_u64()
                .to_le_bytes(),
        );
        payload.extend_from_slice(&0i64.to_le_bytes());

        let version = read_version_payload(&payload)?;
        assert_eq!(version.version, 70_017);
        assert_eq!(version.nonce, 1);
        assert!(version.user_agent.is_empty());
        assert_eq!(version.start_height, -1);
        assert!(version.relay);

        payload.extend_from_slice(&[0u8; 26]);
        let version = read_version_payload(&payload)?;
        assert_eq!(version.nonce, 1);
        assert!(version.user_agent.is_empty());
        assert!(version.relay);

        payload.extend_from_slice(&[0u8; 26]);
        payload.extend_from_slice(&7u64.to_le_bytes());
        let version = read_version_payload(&payload)?;
        assert_eq!(version.nonce, 7);
        assert!(version.user_agent.is_empty());
        assert_eq!(version.start_height, -1);
        assert!(version.relay);
        Ok(())
    }

    // P2P-01
    #[test]
    fn version_trailing_bytes_are_ignored_like_core() -> Result<(), PeerError> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&70_017u32.to_le_bytes());
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&0i64.to_le_bytes());
        payload.extend_from_slice(&[0u8; 26]);
        payload.extend_from_slice(&[0u8; 26]);
        payload.extend_from_slice(&9u64.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&0i32.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&[0xAA; 4]);

        let version = read_version_payload(&payload)?;
        assert_eq!(version.nonce, 9);
        assert!(!version.relay);
        assert_eq!(version.start_height, 0);
        Ok(())
    }

    // P2P-01
    #[test]
    fn sendcmpct_announce_reads_any_nonzero_byte_as_true() -> Result<(), PeerError> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&Magic::REGTEST.to_bytes());
        let mut cmd = [0u8; 12];
        cmd[..9].copy_from_slice(b"sendcmpct");
        frame.extend_from_slice(&cmd);

        let mut payload = Vec::new();
        payload.push(2);
        payload.extend_from_slice(&2u64.to_le_bytes());
        payload.push(0xAA);

        let len =
            u32::try_from(payload.len()).map_err(|_| PeerError::PayloadTooLarge(payload.len()))?;
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(&super::checksum(&payload));
        frame.extend_from_slice(&payload);

        let mut cursor = Cursor::new(frame);
        let (message, _) = read_message(&mut cursor, Magic::REGTEST)?;
        let Message::SendCmpct(sendcmpct) = message else {
            panic!("expected a sendcmpct message");
        };
        assert!(
            sendcmpct.send_compact,
            "Core reads any nonzero announce byte as true"
        );
        assert_eq!(sendcmpct.version, 2);
        Ok(())
    }

    // P2P-01
    #[test]
    fn sendcmpct_payload_shorter_than_nine_bytes_fails_to_parse() -> Result<(), PeerError> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&Magic::REGTEST.to_bytes());
        let mut cmd = [0u8; 12];
        cmd[..9].copy_from_slice(b"sendcmpct");
        frame.extend_from_slice(&cmd);

        let payload: [u8; 8] = [1, 2, 0, 0, 0, 0, 0, 0];
        let len =
            u32::try_from(payload.len()).map_err(|_| PeerError::PayloadTooLarge(payload.len()))?;
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(&super::checksum(&payload));
        frame.extend_from_slice(&payload);

        let mut cursor = Cursor::new(frame);
        let result = read_message(&mut cursor, Magic::REGTEST);
        assert!(
            matches!(result, Err(PeerError::Encode(_))),
            "a short sendcmpct payload is a parse failure, not misbehavior"
        );
        Ok(())
    }

    // P2P-01
    #[test]
    fn inbound_wrapping_keeps_an_obsolete_version_out_of_misbehavior() {
        let error = PeerError::inbound(PeerError::ObsoleteVersion(31_799));
        assert!(matches!(error, PeerError::ObsoleteVersion(31_799)));
        assert!(!error.is_misbehavior());
    }
}
