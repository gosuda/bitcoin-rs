//! Buffered reads that survive a peer socket's poll interval.
//!
//! Peer sockets poll with a short read timeout, so a frame or packet can
//! stop arriving anywhere inside it. Every helper here leaves the bytes
//! already consumed in place across `TimedOut`/`WouldBlock`, so the caller
//! retries and the read resumes where it stopped instead of restarting
//! mid-message. The v1 wire receiver and the BIP324 packet reader share
//! this machinery; each maps the `io::Error` onto its own error type.

use std::io::{self, Read};

/// Largest single read into a message body. The retained buffer grows only
/// with bytes actually received, so a peer that declares a large body then
/// stalls holds what it sent, not the declared length.
pub(crate) const RECEIVE_CHUNK: usize = 16 * 1024;

/// The socket's poll interval elapsed; the rest of the read may still arrive.
pub(crate) fn is_poll_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Reads until `buffer` is full, recording progress in `filled` so a poll
/// timeout resumes where it stopped.
pub(crate) fn fill<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    filled: &mut usize,
) -> io::Result<()> {
    while *filled < buffer.len() {
        match reader.read(&mut buffer[*filled..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => *filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Reads until `buffer` holds `len` bytes, at most [`RECEIVE_CHUNK`] per
/// read. Each read lands in a scratch buffer and only the bytes read are
/// appended, so a stall reserves no spare capacity for bytes that never
/// came.
pub(crate) fn fill_growing<R: Read>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    len: usize,
) -> io::Result<()> {
    let mut scratch = [0u8; RECEIVE_CHUNK];
    while buffer.len() < len {
        let wanted = (len - buffer.len()).min(RECEIVE_CHUNK);
        match reader.read(&mut scratch[..wanted]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => buffer.extend_from_slice(&scratch[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Appends at most `limit` bytes from one successful read to `buffer`.
pub(crate) fn read_up_to<R: Read>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    limit: usize,
) -> io::Result<()> {
    let start = buffer.len();
    buffer.resize(start + limit, 0);
    loop {
        match reader.read(&mut buffer[start..]) {
            Ok(0) => {
                buffer.truncate(start);
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            Ok(read) => {
                buffer.truncate(start + read);
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                buffer.truncate(start);
                return Err(error);
            }
        }
    }
}
