//! Per-connection traffic counters.

use bitcoin_rs_primitives::unix_time_secs;

use std::io::{IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// One per-message accounting bucket, named by its wire command.
///
/// The buckets up to and including [`MessageAccount::SendTxrcncl`] are Bitcoin
/// Core v31.1's known message commands (`ALL_NET_MESSAGE_TYPES`,
/// `src/protocol.h`): a received frame under any other command folds into
/// [`MessageAccount::Other`], exactly as `CNode::ReceiveMsgBytes` pre-seeds
/// only those commands plus the `*other*` bucket so a remote peer cannot grow
/// the map. The buckets after it are commands this node itself can put on the
/// wire that Core v31.1's known list does not carry: sent accounting
/// attributes them by their own name (as Core's `CNode::AccountForSentBytes`
/// inserts the raw command), receives still fold into `*other*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageAccount {
    Version,
    Verack,
    Addr,
    AddrV2,
    SendAddrV2,
    Inv,
    GetData,
    MerkleBlock,
    GetBlocks,
    GetHeaders,
    Tx,
    Headers,
    Block,
    GetAddr,
    MemPool,
    Ping,
    Pong,
    NotFound,
    FilterLoad,
    FilterAdd,
    FilterClear,
    SendHeaders,
    FeeFilter,
    SendCmpct,
    CmpctBlock,
    GetBlockTxn,
    BlockTxn,
    GetCFilters,
    CFilter,
    GetCFHeaders,
    CFHeaders,
    GetCFCheckpt,
    CFCheckpt,
    WtxidRelay,
    SendTxrcncl,
    Feature,
    Alert,
    Reject,
    SendPackages,
    AncPkgInfo,
    GetPkgTxns,
    PkgTxns,
    StaleTip,
    Other,
}

impl MessageAccount {
    /// Every bucket in declaration order; indexing into the per-message
    /// counter arrays uses the position here.
    const ALL: [Self; Self::COUNT] = [
        Self::Version,
        Self::Verack,
        Self::Addr,
        Self::AddrV2,
        Self::SendAddrV2,
        Self::Inv,
        Self::GetData,
        Self::MerkleBlock,
        Self::GetBlocks,
        Self::GetHeaders,
        Self::Tx,
        Self::Headers,
        Self::Block,
        Self::GetAddr,
        Self::MemPool,
        Self::Ping,
        Self::Pong,
        Self::NotFound,
        Self::FilterLoad,
        Self::FilterAdd,
        Self::FilterClear,
        Self::SendHeaders,
        Self::FeeFilter,
        Self::SendCmpct,
        Self::CmpctBlock,
        Self::GetBlockTxn,
        Self::BlockTxn,
        Self::GetCFilters,
        Self::CFilter,
        Self::GetCFHeaders,
        Self::CFHeaders,
        Self::GetCFCheckpt,
        Self::CFCheckpt,
        Self::WtxidRelay,
        Self::SendTxrcncl,
        Self::Feature,
        Self::Alert,
        Self::Reject,
        Self::SendPackages,
        Self::AncPkgInfo,
        Self::GetPkgTxns,
        Self::PkgTxns,
        Self::StaleTip,
        Self::Other,
    ];

    const COUNT: usize = 44;

    /// The bucket a frame under `command` lands in, or `None` when no bucket
    /// carries that command name.
    fn from_command(command: &str) -> Option<Self> {
        match command {
            "version" => Some(Self::Version),
            "verack" => Some(Self::Verack),
            "addr" => Some(Self::Addr),
            "addrv2" => Some(Self::AddrV2),
            "sendaddrv2" => Some(Self::SendAddrV2),
            "inv" => Some(Self::Inv),
            "getdata" => Some(Self::GetData),
            "merkleblock" => Some(Self::MerkleBlock),
            "getblocks" => Some(Self::GetBlocks),
            "getheaders" => Some(Self::GetHeaders),
            "tx" => Some(Self::Tx),
            "headers" => Some(Self::Headers),
            "block" => Some(Self::Block),
            "getaddr" => Some(Self::GetAddr),
            "mempool" => Some(Self::MemPool),
            "ping" => Some(Self::Ping),
            "pong" => Some(Self::Pong),
            "notfound" => Some(Self::NotFound),
            "filterload" => Some(Self::FilterLoad),
            "filteradd" => Some(Self::FilterAdd),
            "filterclear" => Some(Self::FilterClear),
            "sendheaders" => Some(Self::SendHeaders),
            "feefilter" => Some(Self::FeeFilter),
            "sendcmpct" => Some(Self::SendCmpct),
            "cmpctblock" => Some(Self::CmpctBlock),
            "getblocktxn" => Some(Self::GetBlockTxn),
            "blocktxn" => Some(Self::BlockTxn),
            "getcfilters" => Some(Self::GetCFilters),
            "cfilter" => Some(Self::CFilter),
            "getcfheaders" => Some(Self::GetCFHeaders),
            "cfheaders" => Some(Self::CFHeaders),
            "getcfcheckpt" => Some(Self::GetCFCheckpt),
            "cfcheckpt" => Some(Self::CFCheckpt),
            "wtxidrelay" => Some(Self::WtxidRelay),
            "sendtxrcncl" => Some(Self::SendTxrcncl),
            "feature" => Some(Self::Feature),
            "alert" => Some(Self::Alert),
            "reject" => Some(Self::Reject),
            "sendpackages" => Some(Self::SendPackages),
            "ancpkginfo" => Some(Self::AncPkgInfo),
            "getpkgtxns" => Some(Self::GetPkgTxns),
            "pkgtxns" => Some(Self::PkgTxns),
            "staletip" => Some(Self::StaleTip),
            _ => None,
        }
    }

    /// The receive-side bucket for `command`: Core's known commands count
    /// under their own name, everything else (unknown commands and this
    /// node's post-v31 extensions alike) folds into `*other*`.
    fn receive(command: &str) -> Self {
        match Self::from_command(command) {
            Some(
                Self::Feature
                | Self::Alert
                | Self::Reject
                | Self::SendPackages
                | Self::AncPkgInfo
                | Self::GetPkgTxns
                | Self::PkgTxns
                | Self::StaleTip,
            ) => Self::Other,
            account => account.unwrap_or(Self::Other),
        }
    }

    /// The send-side bucket for `command`: our own outgoing commands are
    /// attributed by name, as Core's send accounting does.
    fn send(command: &str) -> Self {
        Self::from_command(command).unwrap_or(Self::Other)
    }

    /// The wire command this bucket reports as in the per-message maps.
    const fn name(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Verack => "verack",
            Self::Addr => "addr",
            Self::AddrV2 => "addrv2",
            Self::SendAddrV2 => "sendaddrv2",
            Self::Inv => "inv",
            Self::GetData => "getdata",
            Self::MerkleBlock => "merkleblock",
            Self::GetBlocks => "getblocks",
            Self::GetHeaders => "getheaders",
            Self::Tx => "tx",
            Self::Headers => "headers",
            Self::Block => "block",
            Self::GetAddr => "getaddr",
            Self::MemPool => "mempool",
            Self::Ping => "ping",
            Self::Pong => "pong",
            Self::NotFound => "notfound",
            Self::FilterLoad => "filterload",
            Self::FilterAdd => "filteradd",
            Self::FilterClear => "filterclear",
            Self::SendHeaders => "sendheaders",
            Self::FeeFilter => "feefilter",
            Self::SendCmpct => "sendcmpct",
            Self::CmpctBlock => "cmpctblock",
            Self::GetBlockTxn => "getblocktxn",
            Self::BlockTxn => "blocktxn",
            Self::GetCFilters => "getcfilters",
            Self::CFilter => "cfilter",
            Self::GetCFHeaders => "getcfheaders",
            Self::CFHeaders => "cfheaders",
            Self::GetCFCheckpt => "getcfcheckpt",
            Self::CFCheckpt => "cfcheckpt",
            Self::WtxidRelay => "wtxidrelay",
            Self::SendTxrcncl => "sendtxrcncl",
            Self::Feature => "feature",
            Self::Alert => "alert",
            Self::Reject => "reject",
            Self::SendPackages => "sendpackages",
            Self::AncPkgInfo => "ancpkginfo",
            Self::GetPkgTxns => "getpkgtxns",
            Self::PkgTxns => "pkgtxns",
            Self::StaleTip => "staletip",
            Self::Other => "*other*",
        }
    }

    #[expect(
        clippy::as_conversions,
        reason = "the enum is field-less with implicit sequential discriminants, so the cast is the bucket's array position"
    )]
    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Debug)]
pub struct PeerCounters {
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    last_send: AtomicU64,
    last_recv: AtomicU64,
    sent_per_message: [AtomicU64; MessageAccount::COUNT],
    recv_per_message: [AtomicU64; MessageAccount::COUNT],
}

impl Default for PeerCounters {
    fn default() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            last_send: AtomicU64::new(0),
            last_recv: AtomicU64::new(0),
            sent_per_message: std::array::from_fn(|_| AtomicU64::new(0)),
            recv_per_message: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl PeerCounters {
    #[must_use]
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn bytes_recv(&self) -> u64 {
        self.bytes_recv.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn last_send(&self) -> u64 {
        self.last_send.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn last_recv(&self) -> u64 {
        self.last_recv.load(Ordering::Relaxed)
    }

    /// Per-message sent-byte totals keyed by wire command, zero buckets
    /// omitted, in bucket declaration order — what `getpeerinfo` renders as
    /// `bytessent_per_msg`.
    #[must_use]
    pub fn sent_per_message(&self) -> Vec<(&'static str, u64)> {
        per_message_snapshot(&self.sent_per_message)
    }

    /// Per-message received-byte totals keyed by wire command, zero buckets
    /// omitted, in bucket declaration order — what `getpeerinfo` renders as
    /// `bytesrecv_per_msg`.
    #[must_use]
    pub fn recv_per_message(&self) -> Vec<(&'static str, u64)> {
        per_message_snapshot(&self.recv_per_message)
    }

    /// Charges one fully framed outgoing message to its command's bucket.
    ///
    /// The connection layer's send accounting entry point; the per-message
    /// maps live beside the socket-level aggregates: this never touches
    /// `bytes_sent`, which only [`CountingStream`] counts from the bytes the
    /// socket accepted.
    pub fn record_msg_sent(&self, command: &str, framed_len: usize) {
        if framed_len == 0 {
            return;
        }
        self.sent_per_message[MessageAccount::send(command).index()]
            .fetch_add(u64::try_from(framed_len).unwrap_or(0), Ordering::Relaxed);
    }

    /// Charges one fully framed incoming message to its command's bucket:
    /// Core v31.1's known commands under their own name, anything else under
    /// `*other*`.
    ///
    /// The connection layer's receive accounting entry point, called after
    /// checksum or BIP324 authentication passed but before payload decode, so
    /// a frame that fails to decode is charged to the command it claimed
    /// rather than `*other*`.
    pub fn record_msg_recv(&self, command: &str, framed_len: usize) {
        if framed_len == 0 {
            return;
        }
        self.recv_per_message[MessageAccount::receive(command).index()]
            .fetch_add(u64::try_from(framed_len).unwrap_or(0), Ordering::Relaxed);
    }

    fn record_sent(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let _previous = self
            .bytes_sent
            .fetch_add(u64::try_from(bytes).unwrap_or(0), Ordering::Relaxed);
        self.last_send.store(unix_time_secs(), Ordering::Relaxed);
    }

    fn record_recv(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let _previous = self
            .bytes_recv
            .fetch_add(u64::try_from(bytes).unwrap_or(0), Ordering::Relaxed);
        self.last_recv.store(unix_time_secs(), Ordering::Relaxed);
    }
}

fn per_message_snapshot(counters: &[AtomicU64; MessageAccount::COUNT]) -> Vec<(&'static str, u64)> {
    MessageAccount::ALL
        .iter()
        .zip(counters)
        .filter_map(|(account, counter)| {
            let bytes = counter.load(Ordering::Relaxed);
            (bytes > 0).then_some((account.name(), bytes))
        })
        .collect()
}

fn per_message_equal(
    left: &[AtomicU64; MessageAccount::COUNT],
    right: &[AtomicU64; MessageAccount::COUNT],
) -> bool {
    left.iter()
        .zip(right)
        .all(|(left, right)| left.load(Ordering::Relaxed) == right.load(Ordering::Relaxed))
}

impl PartialEq for PeerCounters {
    fn eq(&self, other: &Self) -> bool {
        self.bytes_sent() == other.bytes_sent()
            && self.bytes_recv() == other.bytes_recv()
            && self.last_send() == other.last_send()
            && self.last_recv() == other.last_recv()
            && per_message_equal(&self.sent_per_message, &other.sent_per_message)
            && per_message_equal(&self.recv_per_message, &other.recv_per_message)
    }
}

impl Eq for PeerCounters {}

#[derive(Debug)]
pub struct CountingStream<S> {
    inner: S,
    counters: Arc<PeerCounters>,
    lease: Option<crate::PeerLease>,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_end: usize,
}

const INBOUND_READ_BUFFER: usize = 8 * 1024;

impl<S> CountingStream<S> {
    #[must_use]
    pub const fn new(inner: S, counters: Arc<PeerCounters>) -> Self {
        Self {
            inner,
            counters,
            lease: None,
            read_buf: Vec::new(),
            read_pos: 0,
            read_end: 0,
        }
    }

    #[must_use]
    pub const fn counters(&self) -> &Arc<PeerCounters> {
        &self.counters
    }

    #[must_use]
    pub(crate) fn stop_reading_when(mut self, lease: crate::PeerLease) -> Self {
        self.lease = Some(lease);
        self
    }

    fn check_cancelled(&self) -> IoResult<()> {
        if self
            .lease
            .as_ref()
            .is_some_and(crate::PeerLease::is_cancelled)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "connection cancelled",
            ));
        }
        Ok(())
    }
}

impl CountingStream<std::net::TcpStream> {
    /// # Errors
    /// Returns the error `TcpStream::set_nodelay` returned.
    pub(crate) fn from_connected(
        stream: std::net::TcpStream,
        counters: Arc<PeerCounters>,
    ) -> IoResult<Self> {
        stream.set_nodelay(true)?;
        Ok(Self::new(stream, counters))
    }

    pub fn nodelay(&self) -> IoResult<bool> {
        self.inner.nodelay()
    }

    /// # Errors
    /// Returns the error `TcpStream::try_clone` returned.
    pub fn try_clone(&self) -> IoResult<Self> {
        Ok(Self::new(
            self.inner.try_clone()?,
            Arc::clone(&self.counters),
        ))
    }

    pub fn set_read_timeout(&self, timeout: Option<core::time::Duration>) -> IoResult<()> {
        self.inner.set_read_timeout(timeout)
    }

    pub fn local_addr(&self) -> IoResult<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    pub fn shutdown(&self, how: std::net::Shutdown) -> IoResult<()> {
        self.inner.shutdown(how)
    }
}

impl<S: Read> CountingStream<S> {
    fn take_leftover(&mut self, buffer: &mut [u8]) -> Option<usize> {
        if self.read_pos >= self.read_end {
            return None;
        }
        let take = (self.read_end - self.read_pos).min(buffer.len());
        buffer[..take].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + take]);
        self.read_pos += take;
        Some(take)
    }

    fn fill_read_buf(&mut self) -> IoResult<()> {
        if self.read_buf.len() < INBOUND_READ_BUFFER {
            self.read_buf.resize(INBOUND_READ_BUFFER, 0);
        }
        let filled = self.inner.read(&mut self.read_buf)?;
        self.read_pos = 0;
        self.read_end = filled;
        Ok(())
    }

    fn read_buffered(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        if let Some(take) = self.take_leftover(buffer) {
            return Ok(take);
        }
        if buffer.len() >= INBOUND_READ_BUFFER {
            return self.inner.read(buffer);
        }
        self.fill_read_buf()?;
        Ok(self.take_leftover(buffer).unwrap_or(0))
    }
}

impl<S: Read> Read for CountingStream<S> {
    fn read(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        self.check_cancelled()?;
        if buffer.is_empty() {
            return Ok(0);
        }
        let read = self.read_buffered(buffer)?;
        self.counters.record_recv(read);
        Ok(read)
    }

    fn read_vectored(&mut self, buffers: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        self.check_cancelled()?;
        let read = self.inner.read_vectored(buffers)?;
        self.counters.record_recv(read);
        Ok(read)
    }
}
impl<S: Write> Write for CountingStream<S> {
    fn write(&mut self, buffer: &[u8]) -> IoResult<usize> {
        let written = self.inner.write(buffer)?;
        self.counters.record_sent(written);
        Ok(written)
    }

    fn write_vectored(&mut self, buffers: &[IoSlice<'_>]) -> IoResult<usize> {
        let written = self.inner.write_vectored(buffers)?;
        self.counters.record_sent(written);
        Ok(written)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests;
