//! Buffered reads that survive a peer socket's poll interval.

use std::io::{self, Read};

pub(crate) const RECEIVE_CHUNK: usize = 16 * 1024;

pub(crate) fn is_poll_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

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
