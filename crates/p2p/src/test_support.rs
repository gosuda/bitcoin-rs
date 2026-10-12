//! Shared unit-test helpers.

use core::fmt::Display;

pub(crate) trait OrFail<T> {
    #[track_caller]
    fn or_fail(self, context: &str) -> T;
}

impl<T, E: Display> OrFail<T> for Result<T, E> {
    fn or_fail(self, context: &str) -> T {
        match self {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }
}

impl<T> OrFail<T> for Option<T> {
    fn or_fail(self, context: &str) -> T {
        match self {
            Some(value) => value,
            None => panic!("{context}"),
        }
    }
}

pub(crate) type TestResult = Result<(), Box<dyn std::error::Error>>;

/// One scripted step of a [`StallingStream`].
pub(crate) enum Inbound {
    /// Bytes the peer has delivered; a short read leaves the rest queued.
    Bytes(Vec<u8>),
    /// A read that fails with this kind, as a socket poll timeout does.
    Stall(std::io::ErrorKind),
}

/// Serves scripted inbound bytes with stalls between them, the way a peer
/// socket reads when a frame stops arriving part-way; records writes.
pub(crate) struct StallingStream {
    script: std::collections::VecDeque<Inbound>,
    pub(crate) written: Vec<u8>,
}

impl StallingStream {
    pub(crate) fn new(script: impl IntoIterator<Item = Inbound>) -> Self {
        Self {
            script: script.into_iter().collect(),
            written: Vec::new(),
        }
    }
}

impl std::io::Read for StallingStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        match self.script.pop_front() {
            None => Ok(0),
            Some(Inbound::Stall(kind)) => Err(kind.into()),
            Some(Inbound::Bytes(mut bytes)) => {
                let take = bytes.len().min(buffer.len());
                buffer[..take].copy_from_slice(&bytes[..take]);
                if take < bytes.len() {
                    self.script
                        .push_front(Inbound::Bytes(bytes.split_off(take)));
                }
                Ok(take)
            }
        }
    }
}

impl std::io::Write for StallingStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
