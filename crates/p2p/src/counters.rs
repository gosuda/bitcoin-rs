//! Per-connection traffic counters.
//!
//! Bitcoin Core keeps these on `CNode` and `getpeerinfo` reports them as
//! `bytessent`, `bytesrecv`, `lastsend` and `lastrecv`. They are what an
//! operator reads to tell a peer that is feeding the node from one that is
//! merely connected to it.

use std::io::{IoSlice, Read, Result as IoResult, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Bytes and activity times for one peer connection.
///
/// Every field is a snapshot: a reader may see the byte count from after a
/// write and the timestamp from before it. That is what `getpeerinfo` wants --
/// the alternative is a lock on the socket path for the sake of an RPC.
#[derive(Debug, Default)]
pub struct PeerCounters {
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    last_send: AtomicU64,
    last_recv: AtomicU64,
}

impl PeerCounters {
    /// Total bytes written to the peer, wire framing included.
    #[must_use]
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Total bytes read from the peer, wire framing included.
    #[must_use]
    pub fn bytes_recv(&self) -> u64 {
        self.bytes_recv.load(Ordering::Relaxed)
    }

    /// Unix seconds of the last write, or zero if nothing has been sent.
    #[must_use]
    pub fn last_send(&self) -> u64 {
        self.last_send.load(Ordering::Relaxed)
    }

    /// Unix seconds of the last read, or zero if nothing has been received.
    #[must_use]
    pub fn last_recv(&self) -> u64 {
        self.last_recv.load(Ordering::Relaxed)
    }

    fn record_sent(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let _previous = self
            .bytes_sent
            .fetch_add(u64::try_from(bytes).unwrap_or(0), Ordering::Relaxed);
        self.last_send.store(now_seconds(), Ordering::Relaxed);
    }

    fn record_recv(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let _previous = self
            .bytes_recv
            .fetch_add(u64::try_from(bytes).unwrap_or(0), Ordering::Relaxed);
        self.last_recv.store(now_seconds(), Ordering::Relaxed);
    }
}

/// Compares the four counts, which is what a snapshot of a connection is.
impl PartialEq for PeerCounters {
    fn eq(&self, other: &Self) -> bool {
        self.bytes_sent() == other.bytes_sent()
            && self.bytes_recv() == other.bytes_recv()
            && self.last_send() == other.last_send()
            && self.last_recv() == other.last_recv()
    }
}

impl Eq for PeerCounters {}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// A stream that counts everything passing through it.
///
/// Wrapping the stream is what makes the count complete. A connection's bytes
/// move through three separate pieces of code -- the handshake, the reader
/// loop, and the writer thread that owns a cloned socket -- so a counter added
/// at any one of them would report a fraction of the traffic as though it were
/// all of it.
///
/// Reads are buffered so a kernel delivery that holds more than one message
/// does not cost a syscall per `read_exact` of the 24-byte header. Large
/// caller buffers (block payloads) bypass the cache and read into the
/// destination. The writer-side `try_clone` starts with an empty read cache.
#[derive(Debug)]
pub struct CountingStream<S> {
    inner: S,
    counters: Arc<PeerCounters>,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_end: usize,
}

/// Matches `std::io::BufReader`'s default. Unauthenticated inbound
/// connections allocate this on the first small read; a 256 KiB cache would
/// let a flood of half-open handshakes pin large RSS. Payloads whose caller
/// buffer is already this size or larger bypass the cache.
const INBOUND_READ_BUFFER: usize = 8 * 1024;

impl<S> CountingStream<S> {
    /// Wraps `inner`, counting into `counters`.
    #[must_use]
    pub const fn new(inner: S, counters: Arc<PeerCounters>) -> Self {
        Self {
            inner,
            counters,
            read_buf: Vec::new(),
            read_pos: 0,
            read_end: 0,
        }
    }

    /// The counters this stream feeds.
    #[must_use]
    pub const fn counters(&self) -> &Arc<PeerCounters> {
        &self.counters
    }
}

impl CountingStream<std::net::TcpStream> {
    /// Clones the socket, keeping the same counters.
    ///
    /// The writer thread takes a clone; both halves of the connection must
    /// count into one place or `bytessent` reports only the handshake.
    ///
    /// # Errors
    ///
    /// Returns the error `TcpStream::try_clone` returned.
    pub fn try_clone(&self) -> IoResult<Self> {
        Ok(Self::new(
            self.inner.try_clone()?,
            Arc::clone(&self.counters),
        ))
    }

    /// Applies a read timeout to the wrapped socket.
    ///
    /// # Errors
    ///
    /// Returns the error `TcpStream::set_read_timeout` returned.
    pub fn set_read_timeout(&self, timeout: Option<core::time::Duration>) -> IoResult<()> {
        self.inner.set_read_timeout(timeout)
    }

    /// The local address the connection is bound to.
    ///
    /// # Errors
    ///
    /// Returns the error `TcpStream::local_addr` returned.
    pub fn local_addr(&self) -> IoResult<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    /// Closes one or both halves of the connection.
    ///
    /// # Errors
    ///
    /// Returns the error `TcpStream::shutdown` returned.
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
        // Indices move only after a successful read. Resetting `read_pos`
        // first would make a timeout revive already-consumed leftover bytes;
        // the handshake and message loops retry TimedOut/WouldBlock.
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
        if buffer.is_empty() {
            return Ok(0);
        }
        let read = self.read_buffered(buffer)?;
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

    /// Production `write_message` emits the 24-byte header and payload as
    /// one `write_vectored` call. The default `Write` adapter would write
    /// only the first slice, splitting that into two syscalls and counting
    /// only the header if the caller treated the return as a full write.
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
mod tests {
    use super::*;

    /// The count is of bytes that actually moved, not of bytes offered.
    ///
    /// A short write is the case that separates the two: counting the buffer
    /// length would over-report every time the socket accepted less than it
    /// was given.
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

    /// Reads accumulate rather than replacing the previous count.
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

    /// Unauthenticated inbound sessions allocate this cache on the first
    /// small read. Keep it at the `BufReader` default so a flood of
    /// half-open handshakes cannot pin 256 KiB each.
    #[test]
    fn inbound_read_cache_matches_bufreader_default() {
        assert_eq!(INBOUND_READ_BUFFER, 8 * 1024);
    }

    /// One kernel delivery can contain the next message. The wrapper must
    /// keep those leftover bytes instead of asking the socket again.
    ///
    /// Contract: `docs/contracts/p2p-wire.md` `P2P-01`.
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

    /// Handshake and message loops retry `TimedOut`. A refill that fails
    /// after leftover bytes were consumed must not revive those bytes.
    ///
    /// Contract: `docs/contracts/p2p-wire.md` `P2P-01`.
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

    /// Two framed pings delivered in one inner read must both decode without
    /// a second socket read — the IBD headers path between small messages.
    ///
    /// Contract: `docs/contracts/p2p-wire.md` `P2P-01`.
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

    /// A read that moves nothing is not activity.
    ///
    /// Asserted against a *fresh* counter rather than against a timestamp taken
    /// a moment earlier: both readings would fall in the same second, so a
    /// stamp-on-every-read bug would compare equal and survive.
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

    /// A cloned socket counts into the same place as the original.
    ///
    /// The writer thread owns a clone, so if the clone carried its own counters
    /// `bytessent` would report the handshake and nothing after it -- the exact
    /// under-count this wrapper exists to avoid.
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

    /// Nothing sent means no timestamp, which is what Core reports as zero.
    #[test]
    fn an_untouched_connection_reports_no_activity() {
        let counters = PeerCounters::default();
        assert_eq!(counters.bytes_sent(), 0);
        assert_eq!(counters.last_send(), 0);
        assert_eq!(counters.last_recv(), 0);
    }

    /// Default `Write::write_vectored` writes only the first non-empty slice.
    /// Production `write_message` emits header + payload through that method,
    /// so the wrapper must forward both slices and count every byte taken.
    ///
    /// Contract: `docs/contracts/p2p-wire.md` `P2P-01`.
    #[test]
    fn a_vectored_write_counts_every_slice_the_socket_took() {
        struct VectoredWriter;
        impl Write for VectoredWriter {
            fn write(&mut self, _buffer: &[u8]) -> IoResult<usize> {
                Err(std::io::Error::other(
                    "write_vectored must not fall back to write",
                ))
            }
            fn write_vectored(&mut self, buffers: &[IoSlice<'_>]) -> IoResult<usize> {
                Ok(buffers.iter().map(|buffer| buffer.len()).sum())
            }
            fn flush(&mut self) -> IoResult<()> {
                Ok(())
            }
        }

        let counters = Arc::new(PeerCounters::default());
        let mut stream = CountingStream::new(VectoredWriter, Arc::clone(&counters));
        let written = stream
            .write_vectored(&[IoSlice::new(&[1_u8; 4]), IoSlice::new(&[2_u8; 6])])
            .unwrap_or_else(|error| panic!("write_vectored failed: {error}"));

        assert_eq!(written, 10);
        assert_eq!(counters.bytes_sent(), 10);
    }

    /// A short vectored write still counts only the bytes the inner writer
    /// accepted, matching the scalar `write` contract.
    ///
    /// Contract: `docs/contracts/p2p-wire.md` `P2P-01`.
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

    /// `write_message` must reach the inner `write_vectored` through this
    /// wrapper. Falling back to `write` would split header and payload into
    /// two syscalls and under-count if the first slice were taken as the whole
    /// message.
    ///
    /// Contract: `docs/contracts/p2p-wire.md` `P2P-01`. Syscall shape is the
    /// named invariant; elapsed time is `crates/p2p/benches/write_message.rs`.
    #[test]
    fn write_message_through_counting_stream_stays_vectored() {
        struct FailOnUnvectored {
            calls: Arc<AtomicU64>,
        }
        impl Write for FailOnUnvectored {
            fn write(&mut self, _buffer: &[u8]) -> IoResult<usize> {
                Err(std::io::Error::other(
                    "write_message must not fall back to write",
                ))
            }
            fn write_vectored(&mut self, buffers: &[IoSlice<'_>]) -> IoResult<usize> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                Ok(buffers.iter().map(|buffer| buffer.len()).sum())
            }
            fn flush(&mut self) -> IoResult<()> {
                Ok(())
            }
        }

        let counters = Arc::new(PeerCounters::default());
        let calls = Arc::new(AtomicU64::new(0));
        let mut stream = CountingStream::new(
            FailOnUnvectored {
                calls: Arc::clone(&calls),
            },
            Arc::clone(&counters),
        );
        let written = crate::wire::write_message(
            &mut stream,
            bitcoin::p2p::Magic::BITCOIN,
            &crate::wire::Message::Ping(42),
        )
        .unwrap_or_else(|error| panic!("write_message failed: {error}"));

        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "header and payload in one writev"
        );
        assert_eq!(
            counters.bytes_sent(),
            u64::try_from(written).unwrap_or(u64::MAX)
        );
    }
}
