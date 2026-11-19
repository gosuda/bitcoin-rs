//! `BRSIXART` artifact codec: the 73-byte header, the `TxLookup` and `ScriptHistory` record
//! framing, and the hashed 64 KiB streams that read and verify them.
//!
//! Layout (all integers little-endian except the height):
//!
//! | bytes | field |
//! |---|---|
//! | 0..8 | magic `BRSIXART` |
//! | 8 | family (`1` `tx_lookup`, `2` `script_history`, `3` `compact_filters`) |
//! | 9..13 | artifact version |
//! | 13..17 | index format version |
//! | 17..21 | network magic, wire order |
//! | 21..25 | base height, big-endian |
//! | 25..57 | base block hash, little-endian |
//! | 57..65 | record count |
//! | 65..73 | payload bytes (everything after the header) |
//!
//! A `TxLookup` record is `txid (32, LE) || height (4, BE) || count (1) ||
//! TxPosition[count] (6 each)`.
//!
//! Records carry full transaction ids, never raw key-value rows, and appear in strictly
//! ascending `(txid[..8], height, txid[8..])` order: the stored-key order of the
//! `TxConfirmed` family refined by the full id, so prefix collisions have a total
//! order.
//!
//! A `ScriptHistory` record is `kind (1) || key || count (4, LE) || entries`. `kind` is `1` for
//! the `Funding` family and `2` for `Spending`. For `Funding`, `key` is 12 bytes: the 8-byte
//! script prefix then the history-inverted height. For `Spending`, `key` is 40 bytes: the spent
//! outpoint's txid (32, LE) then its vout (4, BE) then the spending height (4, BE). `entries`
//! holds `count` copies of one entry: a 71-byte `ScriptHistoryOccurrence` for `Funding`, a 6-byte
//! `TxPosition` for `Spending`. Records appear in strictly ascending `(kind, key)` order, the
//! key order of each family, so each family streams into `ingest_sorted` in one pass.
//!
//! A `CompactFilters` record is `height (4, BE) || block hash (32, LE) || filter hash (32, LE) ||
//! filter header (32, LE) || filter length (4, LE) || filter bytes`. Records appear in strictly
//! ascending height order, one per block from height zero to the base. Each filter hash is the
//! dSHA256 of the filter bytes, and each filter header is dSHA256(filter hash || previous header),
//! with the zero header before height zero. The live index stores these as hash-keyed rows.

use super::manifest::BundleFamily;
use crate::types::{
    HASH_PREFIX_LEN, HASH_PREFIX_ROW_SIZE, HEIGHT_SIZE, SPENDING_RECORD_KEY_LEN,
    ScriptHistoryOccurrence, TX_POSITION_SIZE, TxPosition, TxPositionValue, decode_history_height,
    positions_are_valid,
};
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use zerocopy::{FromBytes, IntoBytes};

pub(super) const HEADER_LEN: usize = 73;
pub(super) const ARTIFACT_VERSION: u32 = 2;
pub(super) const IO_BUFFER_BYTES: usize = 64 << 10;
pub(super) const CANCEL_POLL_RECORDS: u64 = 4_096;

const MAGIC: [u8; 8] = *b"BRSIXART";
const RECORD_FIXED_LEN: usize = 32 + HEIGHT_SIZE + 1;
const RECORD_KEY_LEN: usize = 32 + HEIGHT_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ArtifactHeader {
    pub(super) family: BundleFamily,
    pub(super) artifact_version: u32,
    pub(super) index_format: u32,
    pub(super) network_magic: [u8; 4],
    pub(super) base_height: u32,
    pub(super) base_hash: [u8; 32],
    pub(super) records: u64,
    pub(super) payload_bytes: u64,
}

impl ArtifactHeader {
    pub(super) fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0_u8; HEADER_LEN];
        out[0..8].copy_from_slice(&MAGIC);
        out[8] = match self.family {
            BundleFamily::TxLookup => 1,
            BundleFamily::ScriptHistory => 2,
            BundleFamily::CompactFilters => 3,
        };
        out[9..13].copy_from_slice(&self.artifact_version.to_le_bytes());
        out[13..17].copy_from_slice(&self.index_format.to_le_bytes());
        out[17..21].copy_from_slice(&self.network_magic);
        out[21..25].copy_from_slice(&self.base_height.to_be_bytes());
        out[25..57].copy_from_slice(&self.base_hash);
        out[57..65].copy_from_slice(&self.records.to_le_bytes());
        out[65..73].copy_from_slice(&self.payload_bytes.to_le_bytes());
        out
    }

    pub(super) fn decode(bytes: &[u8; HEADER_LEN]) -> Result<Self, &'static str> {
        if bytes[0..8] != MAGIC {
            return Err("magic is not BRSIXART");
        }
        let family = match bytes[8] {
            1 => BundleFamily::TxLookup,
            2 => BundleFamily::ScriptHistory,
            3 => BundleFamily::CompactFilters,
            _ => return Err("unknown artifact family"),
        };
        let mut word = [0_u8; 4];
        let mut wide = [0_u8; 8];
        word.copy_from_slice(&bytes[9..13]);
        let artifact_version = u32::from_le_bytes(word);
        word.copy_from_slice(&bytes[13..17]);
        let index_format = u32::from_le_bytes(word);
        let mut network_magic = [0_u8; 4];
        network_magic.copy_from_slice(&bytes[17..21]);
        word.copy_from_slice(&bytes[21..25]);
        let base_height = u32::from_be_bytes(word);
        let mut base_hash = [0_u8; 32];
        base_hash.copy_from_slice(&bytes[25..57]);
        wide.copy_from_slice(&bytes[57..65]);
        let records = u64::from_le_bytes(wide);
        wide.copy_from_slice(&bytes[65..73]);
        let payload_bytes = u64::from_le_bytes(wide);
        Ok(Self {
            family,
            artifact_version,
            index_format,
            network_magic,
            base_height,
            base_hash,
            records,
            payload_bytes,
        })
    }
}

pub(super) fn write_record(
    out: &mut impl Write,
    txid: &[u8; 32],
    height: u32,
    positions: &[TxPosition],
) -> io::Result<u64> {
    let count = u8::try_from(positions.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "record carries over 255 positions",
        )
    })?;
    out.write_all(txid)?;
    out.write_all(&height.to_be_bytes())?;
    out.write_all(&[count])?;
    out.write_all(positions.as_bytes())?;
    let len = RECORD_FIXED_LEN + positions.len() * TX_POSITION_SIZE;
    Ok(u64::try_from(len).unwrap_or(u64::MAX))
}

#[derive(Debug)]
pub(super) enum ReadFault {
    Io(io::Error),
    Framing { record: u64, reason: &'static str },
}

pub(super) struct TxLookupRecord<'a> {
    pub(super) txid: [u8; 32],
    pub(super) height: u32,
    pub(super) positions: &'a [TxPosition],
}

pub(super) struct RecordReader<R> {
    inner: R,
    scratch: Vec<u8>,
    records_left: u64,
    payload_left: u64,
    base_height: u32,
    floor: u32,
    previous: Option<[u8; RECORD_KEY_LEN]>,
    next_index: u64,
}

impl<R: Read> RecordReader<R> {
    pub(super) fn new(inner: R, header: &ArtifactHeader, floor: u32) -> Self {
        Self {
            inner,
            scratch: Vec::new(),
            records_left: header.records,
            payload_left: header.payload_bytes,
            base_height: header.base_height,
            floor,
            previous: None,
            next_index: 0,
        }
    }

    pub(super) fn next_record(&mut self) -> Result<Option<TxLookupRecord<'_>>, ReadFault> {
        let record = self.next_index;
        if self.records_left == 0 {
            self.expect_end(record)?;
            return Ok(None);
        }
        let total = self.read_frame(record)?;
        let (txid, height_be) = self.frame_identity();
        let key = self.check_frame(record, &txid, height_be)?;
        self.previous = Some(key);
        self.records_left -= 1;
        self.payload_left -= u64::try_from(total).unwrap_or(u64::MAX);
        self.next_index += 1;
        let positions =
            <[TxPosition]>::ref_from_bytes(&self.scratch[RECORD_FIXED_LEN..]).map_err(|_| {
                ReadFault::Framing {
                    record,
                    reason: "positions are misaligned",
                }
            })?;
        Ok(Some(TxLookupRecord {
            txid,
            height: u32::from_be_bytes(height_be),
            positions,
        }))
    }

    fn expect_end(&mut self, record: u64) -> Result<(), ReadFault> {
        let framing = |reason: &'static str| ReadFault::Framing { record, reason };
        if self.payload_left != 0 {
            return Err(framing("payload is longer than its records"));
        }
        match probe_end(&mut self.inner) {
            Ok(true) => Ok(()),
            Ok(false) => Err(framing("bytes follow the final record")),
            Err(error) => Err(ReadFault::Io(error)),
        }
    }

    fn read_frame(&mut self, record: u64) -> Result<usize, ReadFault> {
        let framing = |reason: &'static str| ReadFault::Framing { record, reason };
        self.scratch.clear();
        self.scratch.resize(RECORD_FIXED_LEN, 0);
        read_record_bytes(&mut self.inner, &mut self.scratch, record)?;
        let count = usize::from(self.scratch[RECORD_FIXED_LEN - 1]);
        if count == 0 {
            return Err(framing("record carries no positions"));
        }
        let total = RECORD_FIXED_LEN + count * TX_POSITION_SIZE;
        if u64::try_from(total).map_or(true, |total| total > self.payload_left) {
            return Err(framing("record overruns the declared payload"));
        }
        self.scratch.resize(total, 0);
        read_record_bytes(
            &mut self.inner,
            &mut self.scratch[RECORD_FIXED_LEN..],
            record,
        )?;
        Ok(total)
    }

    fn frame_identity(&self) -> ([u8; 32], [u8; HEIGHT_SIZE]) {
        let mut txid = [0_u8; 32];
        txid.copy_from_slice(&self.scratch[..32]);
        let mut height_be = [0_u8; HEIGHT_SIZE];
        height_be.copy_from_slice(&self.scratch[32..32 + HEIGHT_SIZE]);
        (txid, height_be)
    }

    fn check_frame(
        &self,
        record: u64,
        txid: &[u8; 32],
        height_be: [u8; HEIGHT_SIZE],
    ) -> Result<[u8; RECORD_KEY_LEN], ReadFault> {
        let framing = |reason: &'static str| ReadFault::Framing { record, reason };
        let height = u32::from_be_bytes(height_be);
        if height > self.base_height {
            return Err(framing("height is above the bundle base"));
        }
        if height < self.floor {
            return Err(framing("height is below the coverage floor"));
        }
        let positions = <[TxPosition]>::ref_from_bytes(&self.scratch[RECORD_FIXED_LEN..])
            .map_err(|_| framing("positions are misaligned"))?;
        if !positions_are_valid(positions) {
            return Err(framing(
                "positions are not strictly ascending inside one block",
            ));
        }
        let mut key = [0_u8; RECORD_KEY_LEN];
        key[..8].copy_from_slice(&txid[..8]);
        key[8..8 + HEIGHT_SIZE].copy_from_slice(&height_be);
        key[8 + HEIGHT_SIZE..].copy_from_slice(&txid[8..]);
        if self.previous.is_some_and(|previous| previous >= key) {
            return Err(framing("records are not strictly ascending"));
        }
        Ok(key)
    }
}

fn read_record_bytes(
    reader: &mut impl Read,
    buffer: &mut [u8],
    record: u64,
) -> Result<(), ReadFault> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            ReadFault::Framing {
                record,
                reason: "file ends inside a record",
            }
        } else {
            ReadFault::Io(error)
        }
    })
}

fn probe_end(reader: &mut impl Read) -> io::Result<bool> {
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(read) => return Ok(read == 0),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

pub(super) const FUNDING_KEY_LEN: usize = HASH_PREFIX_ROW_SIZE;
pub(super) const SPENDING_KEY_LEN: usize = SPENDING_RECORD_KEY_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum ScriptFamily {
    Funding,
    Spending,
}

impl ScriptFamily {
    const fn tag(self) -> u8 {
        match self {
            Self::Funding => 1,
            Self::Spending => 2,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Funding),
            2 => Some(Self::Spending),
            _ => None,
        }
    }

    const fn key_len(self) -> usize {
        match self {
            Self::Funding => FUNDING_KEY_LEN,
            Self::Spending => SPENDING_KEY_LEN,
        }
    }

    const fn entry_len(self) -> usize {
        match self {
            Self::Funding => ScriptHistoryOccurrence::SIZE,
            Self::Spending => TX_POSITION_SIZE,
        }
    }

    const fn header_len(self) -> usize {
        1 + self.key_len() + 4
    }
}

#[derive(Debug)]
pub(super) struct ScriptRecord {
    pub(super) family: ScriptFamily,
    pub(super) key: Vec<u8>,
    pub(super) value: Vec<u8>,
}

pub(super) fn write_script_record(
    out: &mut impl Write,
    family: ScriptFamily,
    key: &[u8],
    value: &[u8],
) -> io::Result<u64> {
    let entry_len = family.entry_len();
    if key.len() != family.key_len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "script record key has the wrong length",
        ));
    }
    if value.is_empty() || !value.len().is_multiple_of(entry_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "script record value is not a whole number of entries",
        ));
    }
    let count = u32::try_from(value.len() / entry_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "script record carries over u32::MAX entries",
        )
    })?;
    out.write_all(&[family.tag()])?;
    out.write_all(key)?;
    out.write_all(&count.to_le_bytes())?;
    out.write_all(value)?;
    Ok(u64::try_from(family.header_len() + value.len()).unwrap_or(u64::MAX))
}

pub(super) struct ScriptRecordReader<R> {
    inner: R,
    records_left: u64,
    payload_left: u64,
    base_height: u32,
    floor: u32,
    previous: Option<(ScriptFamily, Vec<u8>)>,
    next_index: u64,
}

impl<R: Read> ScriptRecordReader<R> {
    pub(super) fn new(inner: R, header: &ArtifactHeader, floor: u32) -> Self {
        Self {
            inner,
            records_left: header.records,
            payload_left: header.payload_bytes,
            base_height: header.base_height,
            floor,
            previous: None,
            next_index: 0,
        }
    }

    pub(super) fn next_record(&mut self) -> Result<Option<ScriptRecord>, ReadFault> {
        let record = self.next_index;
        if self.records_left == 0 {
            self.expect_end(record)?;
            return Ok(None);
        }
        let framing = |reason: &'static str| ReadFault::Framing { record, reason };
        let mut tag = [0_u8; 1];
        read_record_bytes(&mut self.inner, &mut tag, record)?;
        let family =
            ScriptFamily::from_tag(tag[0]).ok_or_else(|| framing("unknown script family"))?;
        let mut fixed = vec![0_u8; family.header_len() - 1];
        read_record_bytes(&mut self.inner, &mut fixed, record)?;
        let key = fixed[..family.key_len()].to_vec();
        let mut count = [0_u8; 4];
        count.copy_from_slice(&fixed[family.key_len()..]);
        let count = usize::try_from(u32::from_le_bytes(count)).unwrap_or(usize::MAX);
        if count == 0 {
            return Err(framing("record carries no entries"));
        }
        let overrun = || framing("record overruns the declared payload");
        let value_len = count.checked_mul(family.entry_len()).ok_or_else(overrun)?;
        let total = family
            .header_len()
            .checked_add(value_len)
            .ok_or_else(overrun)?;
        if u64::try_from(total).map_or(true, |total| total > self.payload_left) {
            return Err(overrun());
        }
        let mut value = vec![0_u8; value_len];
        read_record_bytes(&mut self.inner, &mut value, record)?;
        if self
            .previous
            .as_ref()
            .is_some_and(|(previous_family, previous_key)| {
                (*previous_family, previous_key.as_slice()) >= (family, key.as_slice())
            })
        {
            return Err(framing("records are not strictly ascending"));
        }
        check_script_entries(family, &key, &value, self.base_height, self.floor)
            .map_err(framing)?;
        self.previous = Some((family, key.clone()));
        self.records_left -= 1;
        self.payload_left -= u64::try_from(total).unwrap_or(u64::MAX);
        self.next_index += 1;
        Ok(Some(ScriptRecord { family, key, value }))
    }

    fn expect_end(&mut self, record: u64) -> Result<(), ReadFault> {
        let framing = |reason: &'static str| ReadFault::Framing { record, reason };
        if self.payload_left != 0 {
            return Err(framing("payload is longer than its records"));
        }
        match probe_end(&mut self.inner) {
            Ok(true) => Ok(()),
            Ok(false) => Err(framing("bytes follow the final record")),
            Err(error) => Err(ReadFault::Io(error)),
        }
    }
}

pub(super) fn record_height(family: ScriptFamily, key: &[u8]) -> Option<u32> {
    match family {
        ScriptFamily::Funding => {
            let bytes: [u8; HEIGHT_SIZE] = key.get(HASH_PREFIX_LEN..)?.try_into().ok()?;
            Some(decode_history_height(bytes))
        }
        ScriptFamily::Spending => {
            let bytes: [u8; 4] = key.get(key.len().checked_sub(4)?..)?.try_into().ok()?;
            Some(u32::from_be_bytes(bytes))
        }
    }
}

pub(super) fn check_script_entries(
    family: ScriptFamily,
    key: &[u8],
    value: &[u8],
    base_height: u32,
    floor: u32,
) -> Result<(), &'static str> {
    if key.len() != family.key_len() {
        return Err("key has the wrong length");
    }
    let height = record_height(family, key).ok_or("key has no height")?;
    if height > base_height {
        return Err("height is above the bundle base");
    }
    if height < floor {
        return Err("height is below the coverage floor");
    }
    match family {
        ScriptFamily::Funding => check_funding_entries(key, value),
        ScriptFamily::Spending => {
            let positions = TxPositionValue::decode(value).ok_or("entries are not positions")?;
            if positions_are_valid(positions) {
                Ok(())
            } else {
                Err("positions are not strictly ascending inside one block")
            }
        }
    }
}

fn check_funding_entries(key: &[u8], value: &[u8]) -> Result<(), &'static str> {
    let occurrences =
        ScriptHistoryOccurrence::decode_all(value).ok_or("entries are not history occurrences")?;
    let prefix_matches = |occurrence: &ScriptHistoryOccurrence| {
        occurrence.scripthash.to_byte_array()[..HASH_PREFIX_LEN] == key[..HASH_PREFIX_LEN]
    };
    if !occurrences.iter().all(prefix_matches) {
        return Err("entry script does not match the record key");
    }
    if occurrences
        .windows(2)
        .any(|pair| occurrence_order(&pair[0]) > occurrence_order(&pair[1]))
    {
        return Err("entries are not in ascending order");
    }
    Ok(())
}

fn occurrence_order(occurrence: &ScriptHistoryOccurrence) -> (TxPosition, [u8; 32], [u8; 32], u8) {
    (
        occurrence.position,
        occurrence.txid,
        occurrence.scripthash.to_byte_array(),
        occurrence.flags,
    )
}

pub(super) struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R> HashingReader<R> {
    pub(super) fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    pub(super) fn finish(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

pub(super) type HashedFile = BufReader<HashingReader<File>>;

pub(super) fn open_hashed(path: &Path) -> io::Result<HashedFile> {
    Ok(BufReader::with_capacity(
        IO_BUFFER_BYTES,
        HashingReader::new(File::open(path)?),
    ))
}

pub(super) fn into_digest(reader: HashedFile) -> [u8; 32] {
    reader.into_inner().finish()
}

pub(super) fn hash_file(path: &Path) -> io::Result<([u8; 32], u64)> {
    let mut reader = open_hashed(path)?;
    let bytes = io::copy(&mut reader, &mut io::sink())?;
    Ok((into_digest(reader), bytes))
}
#[cfg(test)]
#[expect(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn txid(prefix: u8, tail: u8) -> [u8; 32] {
        let mut id = [tail; 32];
        id[..8].fill(prefix);
        id
    }

    fn header(records: u64, payload_bytes: u64, base_height: u32) -> ArtifactHeader {
        ArtifactHeader {
            family: BundleFamily::TxLookup,
            artifact_version: ARTIFACT_VERSION,
            index_format: 5,
            network_magic: [0xfa, 0xbf, 0xb5, 0xda],
            base_height,
            base_hash: [7; 32],
            records,
            payload_bytes,
        }
    }

    type Record = ([u8; 32], u32, Vec<TxPosition>);

    fn stream(
        records: &[([u8; 32], u32, Vec<TxPosition>)],
        base_height: u32,
    ) -> (ArtifactHeader, Vec<u8>) {
        let mut payload = Vec::new();
        for (id, height, positions) in records {
            write_record(&mut payload, id, *height, positions).expect("in-memory write");
        }
        let header = header(
            u64::try_from(records.len()).expect("small"),
            u64::try_from(payload.len()).expect("small"),
            base_height,
        );
        (header, payload)
    }

    fn read_all(
        header: &ArtifactHeader,
        payload: &[u8],
        floor: u32,
    ) -> Result<Vec<Record>, ReadFault> {
        let mut reader = RecordReader::new(Cursor::new(payload), header, floor);
        let mut out = Vec::new();
        while let Some(record) = reader.next_record()? {
            out.push((record.txid, record.height, record.positions.to_vec()));
        }
        Ok(out)
    }

    fn reason(result: Result<Vec<Record>, ReadFault>) -> &'static str {
        match result {
            Err(ReadFault::Framing { reason, .. }) => reason,
            other => panic!(
                "expected a framing fault, got {:?}",
                other.map(|rows| rows.len())
            ),
        }
    }

    #[test]
    fn header_is_73_bytes_with_a_big_endian_height_and_round_trips() {
        let original = header(3, 129, 0x0102_0304);
        let bytes = original.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(&bytes[0..8], b"BRSIXART");
        assert_eq!(&bytes[21..25], &[1, 2, 3, 4]);
        assert_eq!(ArtifactHeader::decode(&bytes), Ok(original));
        let mut bad_magic = bytes;
        bad_magic[0] ^= 1;
        assert!(ArtifactHeader::decode(&bad_magic).is_err());
        let mut bad_family = bytes;
        bad_family[8] = 9;
        assert!(ArtifactHeader::decode(&bad_family).is_err());
    }

    #[test]
    fn framing_refuses_each_violation() {
        let position = vec![TxPosition::new(81, 60)];
        let ascending = [(txid(1, 1), 3, position.clone()), (txid(2, 1), 3, position)];

        let descending = [ascending[1].clone(), ascending[0].clone()];
        let (header_value, payload) = stream(&descending, 9);
        assert_eq!(
            reason(read_all(&header_value, &payload, 0)),
            "records are not strictly ascending"
        );

        let duplicate = [ascending[0].clone(), ascending[0].clone()];
        let (header_value, payload) = stream(&duplicate, 9);
        assert_eq!(
            reason(read_all(&header_value, &payload, 0)),
            "records are not strictly ascending"
        );

        let (header_value, payload) = stream(&ascending, 2);
        assert_eq!(
            reason(read_all(&header_value, &payload, 0)),
            "height is above the bundle base"
        );

        let (header_value, payload) = stream(&ascending, 9);
        assert_eq!(
            reason(read_all(&header_value, &payload, 4)),
            "height is below the coverage floor"
        );

        let overlapping = [(
            txid(1, 1),
            3,
            vec![TxPosition::new(81, 60), TxPosition::new(100, 60)],
        )];
        let (header_value, payload) = stream(&overlapping, 9);
        assert_eq!(
            reason(read_all(&header_value, &payload, 0)),
            "positions are not strictly ascending inside one block"
        );

        let (header_value, payload) = stream(&ascending, 9);
        assert_eq!(
            reason(read_all(&header_value, &payload[..payload.len() - 1], 0)),
            "file ends inside a record"
        );

        let mut trailing = payload.clone();
        trailing.push(0);
        assert_eq!(
            reason(read_all(&header_value, &trailing, 0)),
            "bytes follow the final record"
        );

        let mut short_payload = header_value;
        short_payload.payload_bytes -= 1;
        assert_eq!(
            reason(read_all(&short_payload, &payload, 0)),
            "record overruns the declared payload"
        );

        let mut long_payload = header_value;
        long_payload.payload_bytes += 1;
        assert_eq!(
            reason(read_all(&long_payload, &payload, 0)),
            "payload is longer than its records"
        );

        let mut empty_record = txid(3, 1).to_vec();
        empty_record.extend_from_slice(&3_u32.to_be_bytes());
        empty_record.push(0);
        let lone = header(1, u64::try_from(empty_record.len()).expect("small"), 9);
        assert_eq!(
            reason(read_all(&lone, &empty_record, 0)),
            "record carries no positions"
        );
    }

    #[test]
    fn hashing_reader_digest_equals_the_one_shot_digest() {
        let bytes: Vec<u8> = (0..200_000_u32)
            .map(|value| value.to_le_bytes()[0])
            .collect();
        let mut reader = BufReader::with_capacity(
            IO_BUFFER_BYTES,
            HashingReader::new(Cursor::new(bytes.as_slice())),
        );
        io::copy(&mut reader, &mut io::sink()).expect("in-memory read");
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(reader.into_inner().finish(), expected);
    }

    #[test]
    fn script_history_records_round_trip_and_refuse_disorder() {
        use crate::types::{ScriptHash, encode_history_height};
        let mut funding_key = vec![0x11_u8; FUNDING_KEY_LEN];
        funding_key[HASH_PREFIX_LEN..].copy_from_slice(&encode_history_height(5));
        let mut spending_key = vec![0x44_u8; SPENDING_KEY_LEN];
        spending_key[SPENDING_KEY_LEN - 4..].copy_from_slice(&7_u32.to_be_bytes());
        let mut scripthash = [0x22_u8; 32];
        scripthash[..HASH_PREFIX_LEN].fill(0x11);
        let first = ScriptHistoryOccurrence {
            scripthash: ScriptHash::from_byte_array(scripthash),
            txid: [0x01; 32],
            position: TxPosition::new(81, 10),
            flags: ScriptHistoryOccurrence::FUNDING,
        };
        let second = ScriptHistoryOccurrence {
            scripthash: ScriptHash::from_byte_array(scripthash),
            txid: [0x02; 32],
            position: TxPosition::new(200, 20),
            flags: ScriptHistoryOccurrence::FUNDING,
        };
        let funding = (
            ScriptFamily::Funding,
            funding_key,
            ScriptHistoryOccurrence::encode_all(&[first, second]),
        );
        let spending = (
            ScriptFamily::Spending,
            spending_key,
            TxPositionValue::encode(&[TxPosition::new(81, 10)]),
        );
        let frame = |records: &[&(ScriptFamily, Vec<u8>, Vec<u8>)]| {
            let mut bytes = Vec::new();
            let mut payload = 0_u64;
            for (family, key, value) in records.iter().copied() {
                payload += write_script_record(&mut bytes, *family, key, value).expect("record");
            }
            let header = ArtifactHeader {
                family: BundleFamily::ScriptHistory,
                artifact_version: ARTIFACT_VERSION,
                index_format: 5,
                network_magic: [0; 4],
                base_height: 10,
                base_hash: [0; 32],
                records: u64::try_from(records.len()).expect("count"),
                payload_bytes: payload,
            };
            (bytes, header)
        };

        let (bytes, header) = frame(&[&funding, &spending]);
        let mut reader = ScriptRecordReader::new(Cursor::new(bytes.as_slice()), &header, 0);
        for (family, key, value) in [&funding, &spending] {
            let record = reader
                .next_record()
                .expect("record reads")
                .expect("record present");
            assert_eq!(record.family, *family);
            assert_eq!(record.key, *key);
            assert_eq!(record.value, *value);
        }
        assert!(
            reader.next_record().expect("payload ends").is_none(),
            "the declared records are the whole payload"
        );

        let (bytes, header) = frame(&[&spending, &funding]);
        let mut reader = ScriptRecordReader::new(Cursor::new(bytes.as_slice()), &header, 0);
        reader.next_record().expect("first record reads");
        let disorder = reader.next_record();
        assert!(
            matches!(
                disorder,
                Err(ReadFault::Framing {
                    record: 1,
                    reason: "records are not strictly ascending",
                })
            ),
            "a family out of key order must be refused: {disorder:?}"
        );

        let (bytes, mut header) = frame(&[&funding]);
        header.base_height = 4;
        let mut reader = ScriptRecordReader::new(Cursor::new(bytes.as_slice()), &header, 0);
        let above = reader.next_record();
        assert!(
            matches!(
                above,
                Err(ReadFault::Framing {
                    record: 0,
                    reason: "height is above the bundle base",
                })
            ),
            "a record above the base must be refused: {above:?}"
        );
    }
}
