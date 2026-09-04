//! Per-connection traffic counters.
//!
//! Bitcoin Core keeps these on `CNode` and `getpeerinfo` reports them as
//! `bytessent`, `bytesrecv`, `lastsend` and `lastrecv`. They are what an
//! operator reads to tell a peer that is feeding the node from one that is
//! merely connected to it.

use std::io::{Read, Result as IoResult, Write};
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
#[derive(Debug)]
pub struct CountingStream<S> {
    inner: S,
    counters: Arc<PeerCounters>,
}

impl<S> CountingStream<S> {
    /// Wraps `inner`, counting into `counters`.
    #[must_use]
    pub const fn new(inner: S, counters: Arc<PeerCounters>) -> Self {
        Self { inner, counters }
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
        Ok(Self {
            inner: self.inner.try_clone()?,
            counters: Arc::clone(&self.counters),
        })
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

impl<S: Read> Read for CountingStream<S> {
    fn read(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        let read = self.inner.read(buffer)?;
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
}
