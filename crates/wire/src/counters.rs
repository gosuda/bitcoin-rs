use bitcoin_rs_consensus::primitives::unix_time_secs;

use std::cell::Cell;
use std::io::{IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::Mutex;

/// Declares [`MessageAccount`]: one row per accounted wire command, plus the
/// [`MessageAccount::Other`] bucket appended last.
///
/// Each row is `classification Variant = "command"`, where the
/// classification drives both directions of accounting:
///
/// - `both` — this node receives and sends the command, so frames count
///   under the command's own name in either direction;
/// - `send_only` — this node only ever puts the command on the wire; a sent
///   frame still counts under its own name, while a received frame under it
///   folds into `Other`, the bucket every unknown command lands in.
///
/// `alert` and `reject` are decoded but never processed inbound, so they
/// stay `send_only`. The BIP331/BIP332 extension rows (`sendpackages`,
/// `ancpkginfo`, `getpkgtxns`, `pkgtxns`, `staletip`) are classified `both`
/// even though Core v31.1's known-command list omits them: this node
/// processes their inbound frames, so their received bytes keep their own
/// buckets — a deliberate divergence from Core's internal whitelist that
/// preserves the observable contract (Core-known names, the `*other*`
/// fallback, and the fixed map size all stay as they were).
///
/// The enum variants, the declaration-order bucket array, the command
/// lookup, the reporting names, and the receive-side fold are all derived
/// from the one table, so the mapping is declared exactly once.
macro_rules! message_accounts {
    (@count $classification:ident) => {
        1
    };
    (@receive_bucket both $variant:ident) => {
        Self::$variant
    };
    (@receive_bucket send_only $variant:ident) => {
        Self::Other
    };
    (
        $( $classification:ident $variant:ident = $command:literal ),* $(,)?
    ) => {
        /// One per-message accounting bucket, named by its wire command.
        ///
        /// The bucket set is fixed by the [`message_accounts`] table: a
        /// command a remote peer sends that no row carries folds into
        /// [`MessageAccount::Other`] and can never grow the map, which is
        /// why the per-peer counters stay fixed-size and bounded (the same
        /// reason `CNode::ReceiveMsgBytes` pre-seeds only a fixed command
        /// map, Core v31.1 `src/net.cpp`).
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum MessageAccount {
            $( $variant, )*
            Other,
        }

        impl MessageAccount {
            /// Every bucket in declaration order; indexing into the
            /// per-message counter arrays uses the position here.
            const ALL: [Self; Self::COUNT] = [ $( Self::$variant, )* Self::Other ];

            const COUNT: usize = 0 $( + message_accounts!(@count $classification) )* + 1;

            /// The bucket a frame under `command` lands in, or `None` when
            /// no bucket carries that command name.
            fn from_command(command: &str) -> Option<Self> {
                match command {
                    $( $command => Some(Self::$variant), )*
                    _ => None,
                }
            }

            /// The receive-side bucket for `command`: `both` rows count
            /// under their own name, `send_only` rows and unknown commands
            /// fold into `*other*`.
            fn receive(command: &str) -> Self {
                match command {
                    $( $command => message_accounts!(@receive_bucket $classification $variant), )*
                    _ => Self::Other,
                }
            }

            /// The send-side bucket for `command`: our own outgoing commands
            /// are attributed by name, as Core's send accounting does.
            fn send(command: &str) -> Self {
                Self::from_command(command).unwrap_or(Self::Other)
            }

            /// The wire command this bucket reports as in the per-message
            /// maps.
            const fn name(self) -> &'static str {
                match self {
                    $( Self::$variant => $command, )*
                    Self::Other => "*other*",
                }
            }
        }
    };
}

message_accounts! {
    both Version = "version",
    both Verack = "verack",
    both Addr = "addr",
    both AddrV2 = "addrv2",
    both SendAddrV2 = "sendaddrv2",
    both Inv = "inv",
    both GetData = "getdata",
    both MerkleBlock = "merkleblock",
    both GetBlocks = "getblocks",
    both GetHeaders = "getheaders",
    both Tx = "tx",
    both Headers = "headers",
    both Block = "block",
    both GetAddr = "getaddr",
    both MemPool = "mempool",
    both Ping = "ping",
    both Pong = "pong",
    both NotFound = "notfound",
    both FilterLoad = "filterload",
    both FilterAdd = "filteradd",
    both FilterClear = "filterclear",
    both SendHeaders = "sendheaders",
    both FeeFilter = "feefilter",
    both SendCmpct = "sendcmpct",
    both CmpctBlock = "cmpctblock",
    both GetBlockTxn = "getblocktxn",
    both BlockTxn = "blocktxn",
    both GetCFilters = "getcfilters",
    both CFilter = "cfilter",
    both GetCFHeaders = "getcfheaders",
    both CFHeaders = "cfheaders",
    both GetCFCheckpt = "getcfcheckpt",
    both CFCheckpt = "cfcheckpt",
    both WtxidRelay = "wtxidrelay",
    both SendTxrcncl = "sendtxrcncl",
    both Feature = "feature",
    both SendPackages = "sendpackages",
    both AncPkgInfo = "ancpkginfo",
    both GetPkgTxns = "getpkgtxns",
    both PkgTxns = "pkgtxns",
    both StaleTip = "staletip",
    send_only Alert = "alert",
    send_only Reject = "reject",
}

impl MessageAccount {
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
    /// commands this node receives under their own name, anything else under
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
    cancel_guard: Option<bitcoin_rs_consensus::latch::HookGuard>,
    cancel: Option<bitcoin_rs_consensus::latch::LatchReader>,
    read_timeout: Cell<Option<core::time::Duration>>,
    /// The connection's send-activity clock, shared with the lease the
    /// message loop reads it through. Stamped beside the byte counters
    /// when the socket accepts bytes, so keepalive send silence tracks
    /// actual writer progress, never queue admission.
    send_activity: Option<Arc<Mutex<Instant>>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_end: usize,
}

const INBOUND_READ_BUFFER: usize = 8 * 1024;

#[cfg(windows)]
const CANCEL_POLL: core::time::Duration = core::time::Duration::from_millis(25);

impl<S> CountingStream<S> {
    #[must_use]
    pub const fn new(inner: S, counters: Arc<PeerCounters>) -> Self {
        Self {
            inner,
            counters,
            lease: None,
            cancel_guard: None,
            cancel: None,
            read_timeout: Cell::new(None),
            send_activity: None,
            read_buf: Vec::new(),
            read_pos: 0,
            read_end: 0,
        }
    }

    #[must_use]
    pub const fn counters(&self) -> &Arc<PeerCounters> {
        &self.counters
    }

    pub(crate) fn recording_send_activity(mut self, activity: Arc<Mutex<Instant>>) -> Self {
        self.send_activity = Some(activity);
        self
    }

    /// The one point that observes the socket accepting outbound bytes:
    /// both the byte counters and the send-activity clock advance, and a
    /// zero-byte acceptance is no activity.
    fn note_send(&self, written: usize) {
        if written == 0 {
            return;
        }
        self.counters.record_sent(written);
        if let Some(activity) = &self.send_activity {
            *activity.lock() = Instant::now();
        }
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
            return Err(cancelled_read());
        }
        Ok(())
    }

    /// Windows cannot interrupt a pending `recv` (neither `shutdown` on a
    /// duplicate nor `CancelSynchronousIo` reaches it), so `with_cancel`
    /// clamps the socket's read timeout to a short poll and a `WouldBlock`
    /// retry observes the latch while the caller's deadline still stands.
    fn retry_timed_out_read(&self, error: &std::io::Error, start: Instant) -> IoResult<bool> {
        if !matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ) {
            return Ok(false);
        }
        let Some(cancel) = &self.cancel else {
            return Ok(false);
        };
        if cancel.is_triggered() {
            return Err(cancelled_read());
        }
        self.check_cancelled()?;
        Ok(match self.read_timeout.get() {
            Some(timeout) => start.elapsed() < timeout,
            None => true,
        })
    }
}

fn cancelled_read() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        "connection cancelled",
    )
}

impl CountingStream<std::net::TcpStream> {
    pub(crate) fn from_connected(
        stream: std::net::TcpStream,
        counters: Arc<PeerCounters>,
    ) -> IoResult<Self> {
        stream.set_nodelay(true)?;
        Ok(Self::new(stream, counters))
    }

    /// # Errors
    /// Returns the error `clone` returned.
    pub(crate) fn with_cancel(
        mut self,
        cancel: &bitcoin_rs_consensus::latch::LatchReader,
        clone: &dyn Fn(&std::net::TcpStream) -> IoResult<std::net::TcpStream>,
    ) -> IoResult<Self> {
        let shutdown_stream = std::sync::Arc::new(clone(&self.inner)?);
        self.cancel_guard = Some(cancel.on_cancel(move || {
            let _ = shutdown_stream.shutdown(std::net::Shutdown::Both);
        }));
        #[cfg(windows)]
        {
            self.cancel = Some(cancel.clone());
            self.inner.set_read_timeout(Some(CANCEL_POLL))?;
        }
        Ok(self)
    }

    pub fn nodelay(&self) -> IoResult<bool> {
        self.inner.nodelay()
    }

    pub fn try_clone(&self) -> IoResult<Self> {
        let mut clone = Self::new(self.inner.try_clone()?, Arc::clone(&self.counters));
        clone.send_activity = self.send_activity.clone();
        Ok(clone)
    }

    pub fn set_read_timeout(&self, timeout: Option<core::time::Duration>) -> IoResult<()> {
        #[cfg(windows)]
        if self.cancel.is_some() {
            self.read_timeout.set(timeout);
            return self.inner.set_read_timeout(Some(CANCEL_POLL));
        }
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
        let start = Instant::now();
        let read = loop {
            match self.read_buffered(buffer) {
                Err(error) if self.retry_timed_out_read(&error, start)? => continue,
                result => break result,
            }
        }?;
        self.counters.record_recv(read);
        Ok(read)
    }

    fn read_vectored(&mut self, buffers: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        self.check_cancelled()?;
        let start = Instant::now();
        let read = loop {
            match self.inner.read_vectored(buffers) {
                Err(error) if self.retry_timed_out_read(&error, start)? => continue,
                result => break result,
            }
        }?;
        self.counters.record_recv(read);
        Ok(read)
    }
}
impl<S: Write> Write for CountingStream<S> {
    fn write(&mut self, buffer: &[u8]) -> IoResult<usize> {
        let written = self.inner.write(buffer)?;
        self.note_send(written);
        Ok(written)
    }

    fn write_vectored(&mut self, buffers: &[IoSlice<'_>]) -> IoResult<usize> {
        let written = self.inner.write_vectored(buffers)?;
        self.note_send(written);
        Ok(written)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_write_counts_what_the_socket_took() {
        struct ShortWriter;
        impl Write for ShortWriter {
            fn write(&mut self, buffer: &[u8]) -> IoResult<usize> {
                Ok(buffer.len().min(3))
            }
            fn flush(&mut self) -> IoResult<()> {
                Ok(())
            }
        }

        let counters = Arc::new(PeerCounters::default());
        let mut stream = CountingStream::new(ShortWriter, Arc::clone(&counters));
        let written = stream
            .write(&[0_u8; 10])
            .unwrap_or_else(|error| panic!("write failed: {error}"));

        assert_eq!(written, 3);
        assert_eq!(counters.bytes_sent(), 3);
        assert_eq!(counters.bytes_recv(), 0);
    }

    #[test]
    fn reads_accumulate() {
        let counters = Arc::new(PeerCounters::default());
        let mut stream =
            CountingStream::new(std::io::Cursor::new(vec![7_u8; 5]), Arc::clone(&counters));

        let mut buffer = [0_u8; 2];
        for expected in [2_u64, 4, 5] {
            let _read = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("read failed: {error}"));
            assert_eq!(counters.bytes_recv(), expected);
        }
        assert_ne!(counters.last_recv(), 0, "a read must stamp the time");
    }

    #[test]
    fn leftover_bytes_do_not_revisit_the_socket() {
        struct OneShot {
            remaining: Vec<u8>,
            reads: u8,
        }
        impl Read for OneShot {
            fn read(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
                self.reads = self.reads.saturating_add(1);
                if self.reads > 1 {
                    return Err(std::io::Error::other("socket read more than once"));
                }
                let take = self.remaining.len().min(buffer.len());
                buffer[..take].copy_from_slice(&self.remaining[..take]);
                self.remaining.drain(..take);
                Ok(take)
            }
        }

        let counters = Arc::new(PeerCounters::default());
        let mut stream = CountingStream::new(
            OneShot {
                remaining: vec![1, 2, 3, 4, 5],
                reads: 0,
            },
            Arc::clone(&counters),
        );
        let mut first = [0_u8; 2];
        let read = stream
            .read(&mut first)
            .unwrap_or_else(|error| panic!("first read failed: {error}"));
        assert_eq!(read, 2);
        assert_eq!(first, [1, 2]);
        let mut second = [0_u8; 3];
        let read = stream
            .read(&mut second)
            .unwrap_or_else(|error| panic!("leftover read failed: {error}"));
        assert_eq!(read, 3);
        assert_eq!(second, [3, 4, 5]);
        assert_eq!(counters.bytes_recv(), 5);
    }

    #[test]
    fn a_timed_out_refill_does_not_replay_consumed_bytes() {
        struct TimeoutAfterFirst {
            remaining: Vec<u8>,
            reads: u8,
        }
        impl Read for TimeoutAfterFirst {
            fn read(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
                self.reads = self.reads.saturating_add(1);
                if self.reads > 1 {
                    return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
                }
                let take = self.remaining.len().min(buffer.len());
                buffer[..take].copy_from_slice(&self.remaining[..take]);
                self.remaining.drain(..take);
                Ok(take)
            }
        }

        let counters = Arc::new(PeerCounters::default());
        let mut stream = CountingStream::new(
            TimeoutAfterFirst {
                remaining: vec![1, 2, 3],
                reads: 0,
            },
            Arc::clone(&counters),
        );
        let mut first = [0_u8; 3];
        let read = stream
            .read(&mut first)
            .unwrap_or_else(|error| panic!("first read failed: {error}"));
        assert_eq!(read, 3);
        assert_eq!(first, [1, 2, 3]);

        let mut retry = [0_u8; 3];
        let error = match stream.read(&mut retry) {
            Ok(n) => panic!("refill must time out, got {n} bytes"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        let error = match stream.read(&mut retry) {
            Ok(n) => panic!("retry after timeout must not replay, got {n} bytes"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(counters.bytes_recv(), 3);
    }

    #[test]
    fn two_wire_messages_decode_from_one_socket_read() {
        struct OneShot {
            remaining: Vec<u8>,
            reads: u8,
        }
        impl Read for OneShot {
            fn read(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
                self.reads = self.reads.saturating_add(1);
                if self.reads > 1 {
                    return Err(std::io::Error::other("socket read more than once"));
                }
                let take = self.remaining.len().min(buffer.len());
                buffer[..take].copy_from_slice(&self.remaining[..take]);
                self.remaining.drain(..take);
                Ok(take)
            }
        }

        let mut frames = Vec::new();
        crate::wire::write_message(
            &mut frames,
            bitcoin::p2p::Magic::BITCOIN,
            &crate::wire::Message::Ping(1),
        )
        .unwrap_or_else(|error| panic!("encode ping 1: {error}"));
        crate::wire::write_message(
            &mut frames,
            bitcoin::p2p::Magic::BITCOIN,
            &crate::wire::Message::Ping(2),
        )
        .unwrap_or_else(|error| panic!("encode ping 2: {error}"));

        let counters = Arc::new(PeerCounters::default());
        let mut stream = CountingStream::new(
            OneShot {
                remaining: frames,
                reads: 0,
            },
            counters,
        );
        let (first, _) = crate::wire::read_message(&mut stream, bitcoin::p2p::Magic::BITCOIN)
            .unwrap_or_else(|error| panic!("decode ping 1: {error}"));
        let (second, _) = crate::wire::read_message(&mut stream, bitcoin::p2p::Magic::BITCOIN)
            .unwrap_or_else(|error| panic!("decode ping 2: {error}"));
        assert_eq!(first, crate::wire::Message::Ping(1));
        assert_eq!(second, crate::wire::Message::Ping(2));
    }

    #[test]
    fn an_empty_read_stamps_nothing() {
        let counters = Arc::new(PeerCounters::default());
        let mut stream =
            CountingStream::new(std::io::Cursor::new(Vec::new()), Arc::clone(&counters));

        let mut buffer = [0_u8; 4];
        let read = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("read failed: {error}"));

        assert_eq!(read, 0);
        assert_eq!(counters.bytes_recv(), 0);
        assert_eq!(counters.last_recv(), 0, "an empty read is not activity");
    }

    #[test]
    fn a_vectored_write_counts_every_slice() {
        struct VectoredSink {
            calls: usize,
            bytes: Vec<u8>,
        }
        impl Write for VectoredSink {
            fn write(&mut self, _buffer: &[u8]) -> IoResult<usize> {
                panic!("write_vectored must not fall back to write");
            }
            fn write_vectored(&mut self, buffers: &[IoSlice<'_>]) -> IoResult<usize> {
                self.calls += 1;
                let mut written = 0;
                for buffer in buffers {
                    self.bytes.extend_from_slice(buffer);
                    written += buffer.len();
                }
                Ok(written)
            }
            fn flush(&mut self) -> IoResult<()> {
                Ok(())
            }
        }

        let counters = Arc::new(PeerCounters::default());
        let mut stream = CountingStream::new(
            VectoredSink {
                calls: 0,
                bytes: Vec::new(),
            },
            Arc::clone(&counters),
        );
        let header = [1_u8, 2, 3, 4];
        let payload = [5_u8, 6, 7];
        let written = stream
            .write_vectored(&[IoSlice::new(&header), IoSlice::new(&payload)])
            .unwrap_or_else(|error| panic!("write_vectored failed: {error}"));

        assert_eq!(written, 7);
        assert_eq!(counters.bytes_sent(), 7);
        assert_eq!(stream.inner.calls, 1);
        assert_eq!(stream.inner.bytes, [1, 2, 3, 4, 5, 6, 7]);
    }

    // P2P-04
    #[test]
    fn write_message_through_the_wrapper_is_one_vectored_write() {
        use bitcoin::p2p::Magic;

        use crate::wire::{Message, write_message};

        struct VectoredSink {
            calls: usize,
            writes: usize,
        }
        impl Write for VectoredSink {
            fn write(&mut self, _buffer: &[u8]) -> IoResult<usize> {
                self.writes += 1;
                panic!("write_message must not fall back to write");
            }
            fn write_vectored(&mut self, buffers: &[IoSlice<'_>]) -> IoResult<usize> {
                self.calls += 1;
                Ok(buffers.iter().map(|buffer| buffer.len()).sum())
            }
            fn flush(&mut self) -> IoResult<()> {
                Ok(())
            }
        }

        let counters = Arc::new(PeerCounters::default());
        let mut stream = CountingStream::new(
            VectoredSink {
                calls: 0,
                writes: 0,
            },
            Arc::clone(&counters),
        );
        let written = write_message(&mut stream, Magic::BITCOIN, &Message::Ping(42))
            .unwrap_or_else(|error| panic!("write_message failed: {error}"));

        assert_eq!(
            u64::try_from(written).unwrap_or_else(|_| panic!("framed ping fits in u64")),
            counters.bytes_sent()
        );
        assert_eq!(stream.inner.calls, 1);
        assert_eq!(stream.inner.writes, 0);
        assert!(written > 24, "framed ping is header plus 8-byte payload");
    }

    // P2P-04
    #[test]
    fn from_connected_disables_nagle() {
        use std::net::{TcpListener, TcpStream};

        let listener =
            TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("bind failed: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("local_addr failed: {error}"));
        let accepting = std::thread::spawn(move || listener.accept());
        let client =
            TcpStream::connect(addr).unwrap_or_else(|error| panic!("connect failed: {error}"));
        assert!(
            !client
                .nodelay()
                .unwrap_or_else(|error| panic!("nodelay query failed: {error}")),
            "a raw TcpStream starts with Nagle enabled"
        );

        let wrapped = CountingStream::from_connected(client, Arc::new(PeerCounters::default()))
            .unwrap_or_else(|error| panic!("from_connected failed: {error}"));
        assert!(
            wrapped
                .nodelay()
                .unwrap_or_else(|error| panic!("wrapped nodelay query failed: {error}")),
            "from_connected owns TCP_NODELAY"
        );

        drop(wrapped);
        let _accepted = accepting.join();
    }

    // P2P-04
    #[test]
    fn a_cloned_socket_counts_into_the_same_place() {
        use std::net::{TcpListener, TcpStream};

        let listener =
            TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("bind failed: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("local_addr failed: {error}"));
        let accepting = std::thread::spawn(move || listener.accept());

        let client =
            TcpStream::connect(addr).unwrap_or_else(|error| panic!("connect failed: {error}"));
        let counters = Arc::new(PeerCounters::default());
        let mut original = CountingStream::new(client, Arc::clone(&counters));
        let mut clone = original
            .try_clone()
            .unwrap_or_else(|error| panic!("try_clone failed: {error}"));

        let _written = original
            .write(&[0_u8; 4])
            .unwrap_or_else(|error| panic!("write failed: {error}"));
        let _written = clone
            .write(&[0_u8; 6])
            .unwrap_or_else(|error| panic!("clone write failed: {error}"));

        assert_eq!(
            counters.bytes_sent(),
            10,
            "both halves must land in one count"
        );
        assert_eq!(clone.counters().bytes_sent(), 10);

        drop(original);
        drop(clone);
        let _accepted = accepting.join();
    }
    #[test]
    fn a_zero_byte_read_stamps_nothing_while_a_single_byte_write_counts() {
        let counters = Arc::new(PeerCounters::default());
        let mut stream =
            CountingStream::new(std::io::Cursor::new(vec![7_u8; 8]), Arc::clone(&counters));

        let mut empty: [u8; 0] = [];
        let read = stream
            .read(&mut empty)
            .unwrap_or_else(|error| panic!("zero-length read failed: {error}"));
        assert_eq!(read, 0);
        assert_eq!(counters.bytes_sent(), 0);
        assert_eq!(counters.bytes_recv(), 0);
        assert_eq!(counters.last_send(), 0);
        assert_eq!(counters.last_recv(), 0);

        let written = stream
            .write_vectored(&[IoSlice::new(&[9_u8; 1])])
            .unwrap_or_else(|error| panic!("single-byte write failed: {error}"));
        assert_eq!(written, 1);
        assert_eq!(counters.bytes_sent(), 1);
        assert_ne!(counters.last_send(), 0);
    }

    #[test]
    fn a_short_vectored_write_counts_what_the_socket_took() {
        struct ShortVectoredWriter;
        impl Write for ShortVectoredWriter {
            fn write(&mut self, _buffer: &[u8]) -> IoResult<usize> {
                Err(std::io::Error::other(
                    "write_vectored must not fall back to write",
                ))
            }
            fn write_vectored(&mut self, buffers: &[IoSlice<'_>]) -> IoResult<usize> {
                Ok(buffers
                    .iter()
                    .map(|buffer| buffer.len())
                    .sum::<usize>()
                    .min(3))
            }
            fn flush(&mut self) -> IoResult<()> {
                Ok(())
            }
        }

        let counters = Arc::new(PeerCounters::default());
        let mut stream = CountingStream::new(ShortVectoredWriter, Arc::clone(&counters));
        let written = stream
            .write_vectored(&[IoSlice::new(&[1_u8; 4]), IoSlice::new(&[2_u8; 6])])
            .unwrap_or_else(|error| panic!("write_vectored failed: {error}"));

        assert_eq!(written, 3);
        assert_eq!(counters.bytes_sent(), 3);
    }

    #[test]
    fn a_cancelled_stream_stops_a_payload_that_keeps_arriving() -> IoResult<()> {
        use std::sync::atomic::AtomicBool;
        for transport_failure in [false, true] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            let mut client = std::net::TcpStream::connect(listener.local_addr()?)?;
            let (server, _) = listener.accept()?;
            let alive = Arc::new(AtomicBool::new(true));
            let (tx, _rx) = crossbeam_channel::unbounded();
            let lease = crate::PeerLease::new(tx).with_transport_alive(Some(Arc::clone(&alive)));
            let mut stream = CountingStream::new(server, Arc::new(PeerCounters::default()))
                .stop_reading_when(lease.clone());
            let trickle = std::thread::spawn(move || {
                for _ in 0..200 {
                    if client.write_all(&[0]).is_err() {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            });
            let canceller = {
                let alive = Arc::clone(&alive);
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    if transport_failure {
                        alive.store(false, Ordering::Release);
                    } else {
                        lease.cancel();
                    }
                })
            };
            let mut payload = Vec::new();
            let result = crate::recv::fill_growing(&mut stream, &mut payload, 4_000_000);
            drop(stream);
            let _ = trickle.join();
            let _ = canceller.join();
            assert_eq!(
                result.map_err(|error| error.kind()),
                Err(std::io::ErrorKind::ConnectionAborted)
            );
        }
        Ok(())
    }

    #[test]
    fn an_idle_read_unblocks_on_the_cancel_latch() -> IoResult<()> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let client = std::net::TcpStream::connect(listener.local_addr()?)?;
        let (server, _) = listener.accept()?;
        let latch = bitcoin_rs_consensus::latch::LatchWriter::new();
        let mut stream = CountingStream::from_connected(server, Arc::new(PeerCounters::default()))?
            .with_cancel(&latch.reader(), &std::net::TcpStream::try_clone)?;
        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let reader = std::thread::spawn(move || {
            let mut buffer = [0_u8; 64];
            let result = stream.read(&mut buffer);
            let _ = done_tx.send(result.map_err(|error| error.kind()));
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        latch.trigger();
        let outcome = done_rx.recv_timeout(std::time::Duration::from_millis(200));
        drop(client);
        let _ = reader.join();
        assert!(
            outcome.is_ok(),
            "an idle socket read must return once the cancel latch triggers"
        );
        let result = outcome.map_err(|_| std::io::Error::other("read outcome missing"))?;
        assert!(
            result.is_err() || result == Ok(0),
            "a cancelled idle read reports end of stream, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn send_activity_advances_only_on_actual_socket_writes() {
        use std::time::{Duration, Instant};

        let (queue, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(queue);
        let stale = Instant::now()
            .checked_sub(Duration::from_secs(30))
            .unwrap_or_else(|| panic!("a 30-second backdate fits the monotonic clock"));
        *lease.send_activity().lock() = stale;

        lease
            .send(crate::Message::Ping(1))
            .unwrap_or_else(|error| panic!("queue admission failed: {error}"));
        assert_eq!(
            lease.last_send(),
            stale,
            "queue admission must not advance the send-silence clock"
        );

        let counters = Arc::new(PeerCounters::default());
        let mut stream =
            CountingStream::new(std::io::Cursor::new(Vec::new()), Arc::clone(&counters))
                .recording_send_activity(lease.send_activity());
        let written = stream
            .write(&[0_u8; 4])
            .unwrap_or_else(|error| panic!("write failed: {error}"));
        assert_eq!(written, 4);
        assert!(
            lease.last_send() > stale,
            "a socket write acceptance stamps the clock the loop observes"
        );

        // The writer-thread clone of a connected stream carries the same
        // clock, the way `run_connected_session` hands the writer its handle.
        use std::net::{TcpListener, TcpStream};
        let listener =
            TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("bind failed: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("local_addr failed: {error}"));
        let _client =
            TcpStream::connect(addr).unwrap_or_else(|error| panic!("connect failed: {error}"));
        let connected = listener
            .accept()
            .unwrap_or_else(|error| panic!("accept failed: {error}"))
            .0;
        let stream = CountingStream::new(connected, Arc::new(PeerCounters::default()))
            .recording_send_activity(lease.send_activity());
        let mut clone = stream
            .try_clone()
            .unwrap_or_else(|error| panic!("try_clone failed: {error}"));
        assert!(
            clone.send_activity.is_some(),
            "the writer-thread clone carries the same send-activity clock"
        );
        // Some clock is not enough: it must be the lease's cell. Writing
        // through the clone is the writer thread's only stamping point, so
        // backdate the shared clock and prove the clone's write moves it.
        *lease.send_activity().lock() = stale;
        let written = clone
            .write(&[0_u8; 4])
            .unwrap_or_else(|error| panic!("write through the clone failed: {error}"));
        assert_eq!(written, 4);
        assert!(
            lease.last_send() > stale,
            "a write accepted by the clone stamps the lease's own clock"
        );
    }

    #[test]
    fn message_account_names_round_trip_through_from_command() {
        for account in MessageAccount::ALL {
            if matches!(account, MessageAccount::Other) {
                continue;
            }
            assert_eq!(
                MessageAccount::from_command(account.name()),
                Some(account),
                "{} must classify back to itself",
                account.name()
            );
        }
    }

    #[test]
    fn receive_buckets_cover_core_v31_known_commands() {
        // Core v31.1 src/protocol.h ALL_NET_MESSAGE_TYPES, verbatim. Pinned as
        // compatibility evidence: every Core-known command keeps its own
        // receive bucket. The table is deliberately wider: this node's
        // supported extensions (`feature`, BIP331 `sendpackages`, `ancpkginfo`,
        // `getpkgtxns`, `pkgtxns`, BIP332 `staletip`) carry their own receive
        // buckets too, because we process them inbound — Core's internal
        // whitelist is not our receive surface.
        let core_known = [
            "version",
            "verack",
            "addr",
            "addrv2",
            "sendaddrv2",
            "inv",
            "getdata",
            "merkleblock",
            "getblocks",
            "getheaders",
            "tx",
            "headers",
            "block",
            "getaddr",
            "mempool",
            "ping",
            "pong",
            "notfound",
            "filterload",
            "filteradd",
            "filterclear",
            "sendheaders",
            "feefilter",
            "sendcmpct",
            "cmpctblock",
            "getblocktxn",
            "blocktxn",
            "getcfilters",
            "cfilter",
            "getcfheaders",
            "cfheaders",
            "getcfcheckpt",
            "cfcheckpt",
            "wtxidrelay",
            "sendtxrcncl",
        ];
        for command in core_known {
            assert_eq!(
                MessageAccount::receive(command).name(),
                command,
                "Core v31.1 known command must keep its own receive bucket"
            );
        }
    }

    #[test]
    fn feature_counts_by_name_in_both_directions() {
        // BIP434 negotiation is a command this node receives, so a received
        // feature frame keeps its own bucket instead of folding into *other*.
        assert_eq!(MessageAccount::receive("feature"), MessageAccount::Feature);
        assert_eq!(MessageAccount::receive("feature").name(), "feature");
        assert_eq!(MessageAccount::send("feature"), MessageAccount::Feature);
    }

    #[test]
    fn unknown_and_send_only_receives_fold_into_other() {
        // `alert` and `reject` are decoded but never processed inbound, so a
        // received frame under them folds exactly like an unknown command.
        for command in ["frobnicate", "", "alert", "reject"] {
            assert_eq!(
                MessageAccount::receive(command),
                MessageAccount::Other,
                "{command:?} must fold into *other* like Core's receive accounting"
            );
        }
    }

    #[test]
    fn received_extension_commands_count_under_their_own_names() {
        // BIP331/BIP332 frames this node processes inbound: a real decoded
        // frame charges its own receive bucket, not *other* the way Core
        // v31.1's known-command list would. All five `both`-classified
        // extension commands get a frame, one per bucket.
        let wtxid = bitcoin_rs_consensus::primitives::Wtxid(
            bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[1; 32]),
        );
        let tx = bitcoin_rs_consensus::primitives::Tx {
            inputs: vec![bitcoin_rs_consensus::primitives::TxIn {
                previous_output: bitcoin_rs_consensus::primitives::OutPoint::new(
                    bitcoin_rs_consensus::primitives::Txid(wtxid.0),
                    0,
                ),
                ..bitcoin_rs_consensus::primitives::TxIn::default()
            }],
            ..bitcoin_rs_consensus::primitives::Tx::default()
        };
        let staletip = crate::staletip::StaleTipAnnouncement {
            fork_point: bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[3; 32]),
            headers: vec![crate::staletip::CompressedHeader {
                version: 0x2000_0000,
                merkle_root: bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[4; 32]),
                time: 1_700_000_000,
                bits: bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(0x1703_4219),
                nonce: 1,
            }],
            have_block: true,
        };
        for (command, message) in [
            (
                "sendpackages",
                crate::wire::Message::SendPackages(crate::packages::SendPackages { versions: 3 }),
            ),
            (
                "ancpkginfo",
                crate::wire::Message::AncPkgInfo(crate::packages::AncPkgInfo {
                    wtxids: vec![wtxid],
                }),
            ),
            (
                "getpkgtxns",
                crate::wire::Message::GetPkgTxns(crate::packages::GetPkgTxns {
                    wtxids: vec![wtxid],
                }),
            ),
            (
                "pkgtxns",
                crate::wire::Message::PkgTxns(crate::packages::PkgTxns { txs: vec![tx] }),
            ),
            ("staletip", crate::wire::Message::StaleTip(staletip)),
        ] {
            // The decoder never parses a received `pkgtxns` into transactions:
            // it hands back the raw payload so ingress can charge the frame
            // first, so that command's round trip is payload bytes, not the
            // typed variant it was framed from.
            let expected = match &message {
                crate::wire::Message::PkgTxns(package) => {
                    let payload = package
                        .encode()
                        .unwrap_or_else(|error| panic!("encode {command}: {error}"));
                    crate::wire::Message::PkgTxnsPayload(bytes::Bytes::from(payload))
                }
                framed => framed.clone(),
            };
            let mut frame = Vec::new();
            crate::wire::write_message(&mut frame, bitcoin::p2p::Magic::BITCOIN, &message)
                .unwrap_or_else(|error| panic!("encode {command}: {error}"));
            let counters = Arc::new(PeerCounters::default());
            let mut peer = crate::peer::Peer::new(
                std::io::Cursor::new(frame.clone()),
                bitcoin::p2p::Magic::BITCOIN,
            );
            peer.account_message_bytes(Arc::clone(&counters));
            let (decoded, _) = peer
                .read_message()
                .unwrap_or_else(|error| panic!("decode {command}: {error}"))
                .unwrap_or_else(|| panic!("{command} decodes to a frame"));
            assert_eq!(decoded, expected, "{command} round-trips");
            let framed_len = u64::try_from(frame.len())
                .unwrap_or_else(|_| panic!("{command} framed length fits u64"));
            assert_eq!(
                counters.recv_per_message(),
                vec![(command, framed_len)],
                "{command} inbound accounting keeps its own bucket"
            );
        }
    }

    #[test]
    fn sends_are_attributed_to_their_own_command() {
        assert_eq!(MessageAccount::send("staletip"), MessageAccount::StaleTip);
        assert_eq!(
            MessageAccount::send("sendpackages"),
            MessageAccount::SendPackages
        );
        assert_eq!(MessageAccount::send("frobnicate"), MessageAccount::Other);
    }

    #[test]
    fn per_message_recording_counts_by_command_and_omits_zero_buckets() {
        let counters = PeerCounters::default();
        assert_eq!(
            counters.sent_per_message(),
            Vec::<(&'static str, u64)>::new()
        );
        assert_eq!(
            counters.recv_per_message(),
            Vec::<(&'static str, u64)>::new()
        );

        counters.record_msg_recv("pong", 32);
        counters.record_msg_recv("pong", 32);
        counters.record_msg_recv("frobnicate", 99);
        counters.record_msg_sent("verack", 24);

        assert_eq!(
            counters.recv_per_message(),
            vec![("pong", 64), ("*other*", 99)]
        );
        assert_eq!(counters.sent_per_message(), vec![("verack", 24)]);
    }

    #[test]
    fn a_framed_pong_satisfies_the_framework_wait_threshold() {
        // Core v31.1's test_framework connect_nodes polls until
        // bytesrecv_per_msg['pong'] >= 29; a pong frame is 24 header bytes
        // plus its 8-byte nonce.
        let mut frame = Vec::new();
        crate::wire::write_message(
            &mut frame,
            bitcoin::p2p::Magic::BITCOIN,
            &crate::wire::Message::Pong(0xfeed_face),
        )
        .unwrap_or_else(|error| panic!("encode pong: {error}"));

        let counters = PeerCounters::default();
        counters.record_msg_recv("pong", frame.len());

        let pong = counters
            .recv_per_message()
            .into_iter()
            .find(|(command, _)| *command == "pong")
            .unwrap_or_else(|| panic!("pong bucket missing: {:?}", counters.recv_per_message()));
        assert_eq!(pong, ("pong", 32));
        assert!(pong.1 >= 29, "framed pong must clear the wait threshold");
    }

    #[test]
    fn per_message_recording_leaves_the_socket_aggregates_alone() {
        let counters = PeerCounters::default();
        counters.record_msg_recv("version", 86);
        counters.record_msg_sent("ping", 32);
        assert_eq!(counters.bytes_recv(), 0);
        assert_eq!(counters.bytes_sent(), 0);
        assert_eq!(counters.last_recv(), 0);
        assert_eq!(counters.last_send(), 0);
    }

    #[test]
    fn equality_compares_per_message_buckets_too() {
        let left = PeerCounters::default();
        let right = PeerCounters::default();
        assert_eq!(left, right);
        right.record_msg_recv("pong", 32);
        assert_ne!(left, right);
    }
}
