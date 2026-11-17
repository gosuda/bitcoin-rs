use std::io::{self, Read};
use std::sync::Arc;

use crate::inbound::block_memory::{BlockMemory, BlockMemoryCredit};

#[derive(Debug, Default)]
pub(crate) struct Backing {
    bytes: Vec<u8>,
    credit: Option<BlockMemoryCredit>,
}

impl AsRef<[u8]> for Backing {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::ops::Deref for Backing {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl std::ops::DerefMut for Backing {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl Backing {
    pub(crate) const fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            credit: None,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.bytes.truncate(len);
    }

    /// Move a completed frame's receive charge into the image lane.
    ///
    /// Call once, after the frame is fully read and before [`Backing::into_bytes`].
    /// The backing never grows afterwards, so the moved charge stays exact.
    /// `false` means the image lane refused: drop the frame (the untouched
    /// receive charge releases with `self`) and keep the connection.
    pub(crate) fn transfer_to_image(&mut self) -> bool {
        self.credit
            .as_mut()
            .is_none_or(BlockMemoryCredit::transfer_to_image)
    }

    pub(crate) fn into_bytes(self) -> bytes::Bytes {
        bytes::Bytes::from_owner(self)
    }

    fn growth_capacity(&self, additional: usize) -> usize {
        self.bytes
            .len()
            .saturating_add(additional)
            .max(self.bytes.capacity().saturating_mul(2))
    }

    fn growth_credit(
        &self,
        memory: Option<&Arc<BlockMemory>>,
        additional: usize,
    ) -> io::Result<Option<BlockMemoryCredit>> {
        if self.bytes.len().saturating_add(additional) <= self.bytes.capacity() {
            return Ok(None);
        }
        memory
            .map(|memory| memory.reserve_receive(self.growth_capacity(additional)))
            .transpose()
    }

    fn append(&mut self, bytes: &[u8], mut credit: Option<BlockMemoryCredit>) -> io::Result<()> {
        if self.bytes.len().saturating_add(bytes.len()) > self.bytes.capacity() {
            let capacity = self.growth_capacity(bytes.len());
            if let Some(credit) = credit.as_mut() {
                credit.retain(capacity).map_err(io::Error::other)?;
            }
            let mut replacement = Vec::with_capacity(capacity);
            if replacement.capacity() != capacity {
                return Err(io::Error::other(
                    "receive allocation exceeded reserved capacity",
                ));
            }
            replacement.extend_from_slice(&self.bytes);
            replacement.extend_from_slice(bytes);
            self.bytes = replacement;
            self.credit = credit;
        } else {
            self.bytes.extend_from_slice(bytes);
        }
        Ok(())
    }
}

pub(crate) fn bind_memory(
    current: &mut Option<Arc<BlockMemory>>,
    memory: &Arc<BlockMemory>,
) -> io::Result<()> {
    if let Some(current) = current {
        if !Arc::ptr_eq(current.ledger(), memory.ledger()) {
            return Err(io::Error::other("receive ledger cannot be rebound"));
        }
    } else {
        *current = Some(Arc::clone(memory));
    }
    Ok(())
}

pub(crate) fn fill_backing<R: Read>(
    reader: &mut R,
    buffer: &mut Backing,
    len: usize,
    memory: Option<&Arc<BlockMemory>>,
) -> io::Result<()> {
    let mut scratch = [0_u8; RECEIVE_CHUNK];
    while buffer.len() < len {
        let step = (len - buffer.len()).min(scratch.len());
        let credit = buffer.growth_credit(memory, step)?;
        match reader.read(&mut scratch[..step]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => buffer.append(&scratch[..read], credit)?,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(crate) fn read_backing_up_to<R: Read>(
    reader: &mut R,
    buffer: &mut Backing,
    limit: usize,
    memory: Option<&Arc<BlockMemory>>,
) -> io::Result<()> {
    let mut scratch = [0_u8; RECEIVE_CHUNK];
    let limit = limit.min(scratch.len());
    loop {
        let credit = buffer.growth_credit(memory, limit)?;
        match reader.read(&mut scratch[..limit]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => return buffer.append(&scratch[..read], credit),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

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

#[cfg(test)]
pub(crate) fn fill_growing<R: Read>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    len: usize,
) -> io::Result<()> {
    let mut backing = Backing::from_vec(core::mem::take(buffer));
    let result = fill_backing(reader, &mut backing, len, None);
    *buffer = backing.bytes;
    result
}
