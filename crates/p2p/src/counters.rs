//! Per-connection traffic counters.

use bitcoin_rs_primitives::unix_time_secs;

use std::io::{IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct PeerCounters {
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    last_send: AtomicU64,
    last_recv: AtomicU64,
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

impl PartialEq for PeerCounters {
    fn eq(&self, other: &Self) -> bool {
        self.bytes_sent() == other.bytes_sent()
            && self.bytes_recv() == other.bytes_recv()
            && self.last_send() == other.last_send()
            && self.last_recv() == other.last_recv()
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
