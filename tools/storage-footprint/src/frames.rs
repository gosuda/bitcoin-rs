use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom};
use std::path::Path;

use serde::Serialize;

/// Fixed record header: `BRSB`, body length, height, block hash.
///
/// The width and layout must match `RECORD_HEADER_LEN` in
/// `crates/storage/src/block_file.rs`, which owns the on-disk frame. The tool
/// keeps no storage dependency, so no test can compare the two values.
pub(super) const RECORD_HEADER_LEN: u64 = 44;
const RECORD_HEADER_LEN_USIZE: usize = 44;
const RECORD_MAGIC: [u8; 4] = *b"BRSB";

#[derive(Default, Serialize)]
pub(super) struct FrameSplit {
    pub(super) records: u64,
    pub(super) payload_bytes: u64,
    pub(super) framing_bytes: u64,
    pub(super) unframed_bytes: u64,
}

impl FrameSplit {
    fn add_record(&mut self, body_len: u32) -> io::Result<()> {
        self.records = self
            .records
            .checked_add(1)
            .ok_or_else(|| io::Error::other("record count overflow"))?;
        self.payload_bytes = self
            .payload_bytes
            .checked_add(u64::from(body_len))
            .ok_or_else(|| io::Error::other("payload byte count overflow"))?;
        self.framing_bytes = self
            .framing_bytes
            .checked_add(RECORD_HEADER_LEN)
            .ok_or_else(|| io::Error::other("framing byte count overflow"))?;
        Ok(())
    }

    fn add_unframed(&mut self, bytes: u64) -> io::Result<()> {
        self.unframed_bytes = self
            .unframed_bytes
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("unframed byte count overflow"))?;
        Ok(())
    }
}

#[derive(Serialize)]
pub(super) struct FileFrames {
    pub(super) path: String,
    pub(super) records: u64,
    pub(super) payload_bytes: u64,
    pub(super) framing_bytes: u64,
    pub(super) unframed_bytes: u64,
}

impl FileFrames {
    pub(super) fn new(path: String, split: &FrameSplit) -> Self {
        Self {
            path,
            records: split.records,
            payload_bytes: split.payload_bytes,
            framing_bytes: split.framing_bytes,
            unframed_bytes: split.unframed_bytes,
        }
    }
}

pub(super) fn file_frames(path: &Path) -> io::Result<FrameSplit> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let mut split = FrameSplit::default();
    let mut offset = 0_u64;
    while offset < file_len {
        let remaining = file_len - offset;
        if remaining < RECORD_HEADER_LEN {
            split.add_unframed(remaining)?;
            break;
        }
        let mut header = [0_u8; RECORD_HEADER_LEN_USIZE];
        match file.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                split.add_unframed(remaining)?;
                break;
            }
            Err(error) => return Err(error),
        }
        if header[..4] != RECORD_MAGIC {
            split.add_unframed(remaining)?;
            break;
        }
        let body_len = u32::from_le_bytes(
            header[4..8]
                .try_into()
                .map_err(|_| io::Error::other("malformed record header"))?,
        );
        let record_len = RECORD_HEADER_LEN
            .checked_add(u64::from(body_len))
            .ok_or_else(|| io::Error::other("record length overflow"))?;
        if record_len > remaining {
            split.add_unframed(remaining)?;
            break;
        }
        split.add_record(body_len)?;
        offset += record_len;
        file.seek(SeekFrom::Start(offset))?;
    }
    Ok(split)
}

#[cfg(test)]
pub(super) fn encode_record(body: &[u8], height: u32) -> io::Result<Vec<u8>> {
    let claim = u32::try_from(body.len()).map_err(|_| io::Error::other("fixture too large"))?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&RECORD_MAGIC);
    bytes.extend_from_slice(&claim.to_le_bytes());
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&[0_u8; 32]);
    bytes.extend_from_slice(body);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn frame(claim: u32, body: &[u8], height: u32, hash: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&RECORD_MAGIC);
        bytes.extend_from_slice(&claim.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&[hash; 32]);
        bytes.extend_from_slice(body);
        bytes
    }

    fn block_file(contents: &[u8]) -> io::Result<(tempfile::TempDir, PathBuf)> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("blk00000.dat");
        fs::write(&path, contents)?;
        Ok((dir, path))
    }

    fn len_of(bytes: &[u8]) -> io::Result<u64> {
        u64::try_from(bytes.len()).map_err(|_| io::Error::other("fixture too large"))
    }

    #[test]
    fn record_headers_and_bodies_are_attributed_separately() -> io::Result<()> {
        let bodies: [&[u8]; 3] = [&[0x11; 100], &[0x22; 250], &[]];
        let mut contents = Vec::new();
        for (height, body) in bodies.iter().enumerate() {
            let claim = u32::try_from(body.len()).map_err(|_| io::Error::other("fixture"))?;
            let height = u32::try_from(height).map_err(|_| io::Error::other("fixture"))?;
            contents.extend_from_slice(&frame(claim, body, height, 0x5a));
        }
        let (_dir, path) = block_file(&contents)?;
        let split = file_frames(&path)?;
        assert_eq!(split.records, 3, "oracle: three framed writes");
        assert_eq!(
            split.payload_bytes, 350,
            "oracle: payload is the summed body lengths, not the file length"
        );
        assert_eq!(
            split.framing_bytes,
            3 * RECORD_HEADER_LEN,
            "oracle: framing is the 44-byte header of each record"
        );
        assert_eq!(
            split.unframed_bytes, 0,
            "a complete file must have no unframed tail"
        );
        assert_eq!(
            split.payload_bytes + split.framing_bytes + split.unframed_bytes,
            len_of(&contents)?,
            "oracle: the split must reproduce the file length"
        );
        Ok(())
    }

    #[test]
    fn an_incomplete_tail_is_unframed() -> io::Result<()> {
        let mut contents = frame(4, b"body", 7, 0x01);
        let complete_len = len_of(&contents)?;
        contents.extend_from_slice(&[0_u8; 10]);
        let (_dir, path) = block_file(&contents)?;
        let split = file_frames(&path)?;
        assert_eq!(split.records, 1, "oracle: one complete record");
        assert_eq!(split.payload_bytes, 4, "oracle: the complete body only");
        assert_eq!(split.framing_bytes, RECORD_HEADER_LEN, "oracle: one header");
        assert_eq!(
            split.unframed_bytes, 10,
            "oracle: the stopped-writer tail is neither payload nor framing"
        );
        assert_eq!(
            split.payload_bytes + split.framing_bytes + split.unframed_bytes,
            complete_len + 10
        );
        Ok(())
    }

    #[test]
    fn a_body_shorter_than_its_header_claim_is_unframed() -> io::Result<()> {
        let mut contents = frame(6, b"", 1, 0x02);
        contents.extend_from_slice(&[0x03; 5]);
        let (_dir, path) = block_file(&contents)?;
        let split = file_frames(&path)?;
        assert_eq!(
            split.records, 0,
            "oracle: a record whose body is missing is not a record"
        );
        assert_eq!(
            split.unframed_bytes,
            len_of(&contents)?,
            "oracle: the whole file is an unframed tail"
        );
        Ok(())
    }

    #[test]
    fn a_foreign_magic_stops_the_walk() -> io::Result<()> {
        let mut contents = frame(5, b"first", 3, 0x04);
        let first_len = len_of(&contents)?;
        contents.extend_from_slice(&[0xff; 60]);
        let (_dir, path) = block_file(&contents)?;
        let split = file_frames(&path)?;
        assert_eq!(
            split.records, 1,
            "oracle: only the framed prefix is a record"
        );
        assert_eq!(split.payload_bytes, 5, "oracle: the framed body only");
        assert_eq!(
            split.unframed_bytes,
            len_of(&contents)? - first_len,
            "oracle: bytes after a foreign magic are not framing"
        );
        Ok(())
    }

    #[test]
    fn an_empty_file_has_no_frames_and_no_tail() -> io::Result<()> {
        let (_dir, path) = block_file(&[])?;
        let split = file_frames(&path)?;
        assert_eq!(split.records, 0, "oracle: an empty file has no records");
        assert_eq!(
            split.payload_bytes, 0,
            "oracle: an empty file has no payload"
        );
        assert_eq!(
            split.framing_bytes, 0,
            "oracle: an empty file has no framing"
        );
        assert_eq!(split.unframed_bytes, 0, "oracle: an empty file has no tail");
        Ok(())
    }
}
