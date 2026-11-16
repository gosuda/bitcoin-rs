pub const REORG_WINDOW_BLOCKS: u32 = 144;
pub const TAIL_MAX_BLOCKS: u32 = 2_016;
pub const TAIL_MAX_BYTES: usize = 32 * 1024 * 1024;
pub const TAIL_RETAIN_MAX_BYTES: u64 = 16 * 1024 * 1024;

pub const TX_KIND_TXID: u8 = 1;
pub const TX_KIND_ORDINAL: u8 = 2;

pub const TX_DIR_KEY_LEN: usize = 45;
pub const TX_DIR_VALUE_LEN: usize = 44;

pub const SCRIPT_DICT_KEY_LEN: usize = 40;
pub const SCRIPT_DICT_VALUE_LEN: usize = 4;

pub const SCRIPT_POST_KEY_LEN: usize = 16;
pub const SCRIPT_POST_CHUNK_MAX_BYTES: usize = 4096;

pub const SPEND_DIR_KEY_LEN: usize = 15;
pub const SPEND_DIR_VALUE_LEN: usize = 4;

pub const SCRIPT_STATS_KEY_LEN: usize = 12;
pub const SCRIPT_STATS_VALUE_LEN: usize = 32;

pub const FILTER_KEY_LEN: usize = 12;
pub const FILTER_HEADER_PREFIX_LEN: usize = 96;

pub const POSTING_FLAG_FUNDING: u8 = 0b01;
pub const POSTING_FLAG_SPENDING: u8 = 0b10;

#[must_use]
pub fn gen_prefix_start(gen_id: u64) -> [u8; 8] {
    gen_id.to_be_bytes()
}

#[must_use]
pub fn gen_prefix_end(gen_id: u64) -> [u8; 8] {
    gen_id.saturating_add(1).to_be_bytes()
}

#[must_use]
pub fn tx_dir_kind_prefix(gen_id: u64, kind: u8) -> [u8; 9] {
    let mut prefix = [0u8; 9];
    prefix[0..8].copy_from_slice(&gen_id.to_be_bytes());
    prefix[8] = kind;
    prefix
}

#[must_use]
pub fn encode_tx_dir_key(gen_id: u64, txid: &[u8; 32], height: u32) -> [u8; TX_DIR_KEY_LEN] {
    let mut key = [0u8; TX_DIR_KEY_LEN];
    key[0..9].copy_from_slice(&tx_dir_kind_prefix(gen_id, TX_KIND_TXID));
    key[9..41].copy_from_slice(txid);
    key[41..45].copy_from_slice(&height.to_be_bytes());
    key
}

#[must_use]
pub fn decode_tx_dir_key(key: &[u8]) -> Option<(u64, [u8; 32], u32)> {
    if key.len() != TX_DIR_KEY_LEN || key[8] != TX_KIND_TXID {
        return None;
    }
    let gen_id = u64::from_be_bytes(key[0..8].try_into().ok()?);
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&key[9..41]);
    let height = u32::from_be_bytes(key[41..45].try_into().ok()?);
    Some((gen_id, txid, height))
}

// PRJ-06, PRJ-07
#[must_use]
pub fn encode_tx_dir_value(
    block_hash: &[u8; 32],
    ordinal: u32,
    offset: u32,
    len: u32,
) -> [u8; TX_DIR_VALUE_LEN] {
    let mut val = [0u8; TX_DIR_VALUE_LEN];
    val[0..32].copy_from_slice(block_hash);
    val[32..36].copy_from_slice(&ordinal.to_be_bytes());
    val[36..40].copy_from_slice(&offset.to_le_bytes());
    val[40..44].copy_from_slice(&len.to_le_bytes());
    val
}

// PRJ-06, PRJ-07
#[must_use]
pub fn decode_tx_dir_value(val: &[u8]) -> Option<([u8; 32], u32, u32, u32)> {
    if val.len() < TX_DIR_VALUE_LEN {
        return None;
    }
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&val[0..32]);
    let ordinal = u32::from_be_bytes(val[32..36].try_into().ok()?);
    let offset = u32::from_le_bytes(val[36..40].try_into().ok()?);
    let len = u32::from_le_bytes(val[40..44].try_into().ok()?);
    Some((block_hash, ordinal, offset, len))
}

pub const TX_ORDINAL_KEY_LEN: usize = 13;
pub const TX_ORDINAL_VALUE_LEN: usize = 44;

#[must_use]
pub fn encode_tx_ordinal_key(gen_id: u64, ordinal: u32) -> [u8; TX_ORDINAL_KEY_LEN] {
    let mut key = [0u8; TX_ORDINAL_KEY_LEN];
    key[0..9].copy_from_slice(&tx_dir_kind_prefix(gen_id, TX_KIND_ORDINAL));
    key[9..13].copy_from_slice(&ordinal.to_be_bytes());
    key
}

// PRJ-07
#[must_use]
pub fn encode_tx_ordinal_value(
    txid: &[u8; 32],
    height: u32,
    offset: u32,
    len: u32,
) -> [u8; TX_ORDINAL_VALUE_LEN] {
    let mut val = [0u8; TX_ORDINAL_VALUE_LEN];
    val[0..32].copy_from_slice(txid);
    val[32..36].copy_from_slice(&height.to_be_bytes());
    val[36..40].copy_from_slice(&offset.to_le_bytes());
    val[40..44].copy_from_slice(&len.to_le_bytes());
    val
}

// PRJ-07
#[must_use]
pub fn decode_tx_ordinal_value(val: &[u8]) -> Option<([u8; 32], u32, u32, u32)> {
    if val.len() < TX_ORDINAL_VALUE_LEN {
        return None;
    }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&val[0..32]);
    let height = u32::from_be_bytes(val[32..36].try_into().ok()?);
    let offset = u32::from_le_bytes(val[36..40].try_into().ok()?);
    let len = u32::from_le_bytes(val[40..44].try_into().ok()?);
    Some((txid, height, offset, len))
}

// PRJ-08
#[must_use]
pub fn encode_script_dict_key(gen_id: u64, script_hash: &[u8; 32]) -> [u8; SCRIPT_DICT_KEY_LEN] {
    let mut key = [0u8; SCRIPT_DICT_KEY_LEN];
    key[0..8].copy_from_slice(&gen_id.to_be_bytes());
    key[8..40].copy_from_slice(script_hash);
    key
}

// PRJ-08
#[must_use]
pub fn decode_script_dict_key(key: &[u8]) -> Option<(u64, [u8; 32])> {
    if key.len() < SCRIPT_DICT_KEY_LEN {
        return None;
    }
    let gen_id = u64::from_be_bytes(key[0..8].try_into().ok()?);
    let mut script_hash = [0u8; 32];
    script_hash.copy_from_slice(&key[8..40]);
    Some((gen_id, script_hash))
}

// PRJ-08
#[must_use]
pub fn encode_script_dict_value(script_id: u32) -> [u8; SCRIPT_DICT_VALUE_LEN] {
    script_id.to_be_bytes()
}

// PRJ-08
#[must_use]
pub fn decode_script_dict_value(val: &[u8]) -> Option<u32> {
    if val.len() < SCRIPT_DICT_VALUE_LEN {
        return None;
    }
    Some(u32::from_be_bytes(val[0..4].try_into().ok()?))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostingItem {
    pub delta_ordinal: u32,
    pub flags: u8,
}

pub fn encode_uvarint(mut val: u32, buf: &mut Vec<u8>) {
    while val >= 0x80 {
        let b = (val.to_le_bytes()[0] & 0x7f) | 0x80;
        buf.push(b);
        val >>= 7;
    }
    buf.push(val.to_le_bytes()[0]);
}

#[must_use]
pub fn decode_uvarint(bytes: &[u8]) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i >= 5 {
            return None;
        }
        result |= u32::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

// PRJ-08
#[must_use]
pub fn encode_script_post_key(
    gen_id: u64,
    script_id: u32,
    chunk: u32,
) -> [u8; SCRIPT_POST_KEY_LEN] {
    let mut key = [0u8; SCRIPT_POST_KEY_LEN];
    key[0..8].copy_from_slice(&gen_id.to_be_bytes());
    key[8..12].copy_from_slice(&script_id.to_be_bytes());
    key[12..16].copy_from_slice(&chunk.to_be_bytes());
    key
}

// PRJ-08
#[must_use]
pub fn decode_script_post_key(key: &[u8]) -> Option<(u64, u32, u32)> {
    if key.len() < SCRIPT_POST_KEY_LEN {
        return None;
    }
    let gen_id = u64::from_be_bytes(key[0..8].try_into().ok()?);
    let script_id = u32::from_be_bytes(key[8..12].try_into().ok()?);
    let chunk = u32::from_be_bytes(key[12..16].try_into().ok()?);
    Some((gen_id, script_id, chunk))
}

// PRJ-08
#[must_use]
pub fn encode_posting_items(items: &[PostingItem]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(items.len() * 3);
    for item in items {
        encode_uvarint(item.delta_ordinal, &mut buf);
        buf.push(item.flags);
    }
    buf
}

fn uvarint_len(mut val: u32) -> usize {
    let mut len = 1;
    while val >= 0x80 {
        len += 1;
        val >>= 7;
    }
    len
}

// PRJ-08
#[must_use]
pub fn encode_script_post_chunk_key(
    gen_id: u64,
    script_id: u32,
    base_ordinal: u32,
) -> [u8; SCRIPT_POST_KEY_LEN] {
    encode_script_post_key(gen_id, script_id, !base_ordinal)
}

// PRJ-08
#[must_use]
pub fn decode_script_post_chunk_key(key: &[u8]) -> Option<(u64, u32, u32)> {
    let (gen_id, script_id, inverted) = decode_script_post_key(key)?;
    Some((gen_id, script_id, !inverted))
}

// PRJ-08
#[must_use]
pub fn decode_chunk_postings(base_ordinal: u32, bytes: &[u8]) -> Option<Vec<(u32, u8)>> {
    let items = decode_posting_items(bytes)?;
    let mut ordinal = base_ordinal;
    let mut postings = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        if index == 0 {
            if item.delta_ordinal != 0 {
                return None;
            }
        } else {
            ordinal = ordinal.checked_add(item.delta_ordinal)?;
        }
        postings.push((ordinal, item.flags));
    }
    Some(postings)
}

pub struct PostingChunker {
    gen_id: u64,
    script_id: u32,
    chunk: Vec<PostingItem>,
    chunk_bytes: usize,
    base: u32,
    ordinal: u32,
}

impl PostingChunker {
    pub fn new(gen_id: u64, script_id: u32) -> Self {
        Self {
            gen_id,
            script_id,
            chunk: Vec::new(),
            chunk_bytes: 0,
            base: 0,
            ordinal: 0,
        }
    }

    pub fn push(&mut self, delta_ordinal: u32, flags: u8) -> Option<(Vec<u8>, Vec<u8>)> {
        let next = self.ordinal.saturating_add(delta_ordinal);
        let item_bytes = uvarint_len(delta_ordinal).saturating_add(1);
        let full = delta_ordinal != 0
            && self.chunk_bytes.saturating_add(item_bytes) > SCRIPT_POST_CHUNK_MAX_BYTES;
        let emitted = if self.chunk.is_empty() || full {
            let flushed = if self.chunk.is_empty() {
                None
            } else {
                let rows = chunk_row(self.gen_id, self.script_id, self.base, &self.chunk);
                self.chunk.clear();
                Some(rows)
            };
            self.base = next;
            self.chunk.push(PostingItem {
                delta_ordinal: 0,
                flags,
            });
            self.chunk_bytes = uvarint_len(0).saturating_add(1);
            flushed
        } else {
            self.chunk.push(PostingItem {
                delta_ordinal,
                flags,
            });
            self.chunk_bytes = self.chunk_bytes.saturating_add(item_bytes);
            None
        };
        self.ordinal = next;
        emitted
    }

    pub fn finish(self) -> Option<(Vec<u8>, Vec<u8>)> {
        if self.chunk.is_empty() {
            None
        } else {
            Some(chunk_row(
                self.gen_id,
                self.script_id,
                self.base,
                &self.chunk,
            ))
        }
    }
}

pub fn chunk_postings(
    gen_id: u64,
    script_id: u32,
    items: Vec<PostingItem>,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows = Vec::new();
    let mut chunker = PostingChunker::new(gen_id, script_id);
    for item in items {
        if let Some(row) = chunker.push(item.delta_ordinal, item.flags) {
            rows.push(row);
        }
    }
    if let Some(row) = chunker.finish() {
        rows.push(row);
    }
    rows
}

fn chunk_row(gen_id: u64, script_id: u32, base: u32, chunk: &[PostingItem]) -> (Vec<u8>, Vec<u8>) {
    (
        encode_script_post_chunk_key(gen_id, script_id, base).to_vec(),
        encode_posting_items(chunk),
    )
}

// PRJ-08
#[must_use]
pub fn decode_posting_items(mut bytes: &[u8]) -> Option<Vec<PostingItem>> {
    let mut items = Vec::new();
    while !bytes.is_empty() {
        let (delta, read_len) = decode_uvarint(bytes)?;
        bytes = &bytes[read_len..];
        if bytes.is_empty() {
            return None;
        }
        let flags = bytes[0];
        bytes = &bytes[1..];
        items.push(PostingItem {
            delta_ordinal: delta,
            flags,
        });
    }
    Some(items)
}

#[must_use]
pub fn encode_spend_dir_key(
    gen_id: u64,
    creation_ordinal: u32,
    vout: u32,
) -> [u8; SPEND_DIR_KEY_LEN] {
    let mut key = [0u8; SPEND_DIR_KEY_LEN];
    key[0..8].copy_from_slice(&gen_id.to_be_bytes());
    key[8..12].copy_from_slice(&creation_ordinal.to_be_bytes());
    let vout_bytes = vout.to_be_bytes();
    key[12..15].copy_from_slice(&vout_bytes[1..4]);
    key
}

#[must_use]
pub fn decode_spend_dir_key(key: &[u8]) -> Option<(u64, u32, u32)> {
    if key.len() < SPEND_DIR_KEY_LEN {
        return None;
    }
    let gen_id = u64::from_be_bytes(key[0..8].try_into().ok()?);
    let creation_ordinal = u32::from_be_bytes(key[8..12].try_into().ok()?);
    let vout = u32::from_be_bytes([0, key[12], key[13], key[14]]);
    Some((gen_id, creation_ordinal, vout))
}

#[must_use]
pub fn encode_spend_dir_value(spending_ordinal: u32) -> [u8; SPEND_DIR_VALUE_LEN] {
    spending_ordinal.to_be_bytes()
}

#[must_use]
pub fn decode_spend_dir_value(val: &[u8]) -> Option<u32> {
    if val.len() < SPEND_DIR_VALUE_LEN {
        return None;
    }
    Some(u32::from_be_bytes(val[0..4].try_into().ok()?))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScriptStats {
    pub funded_count: u64,
    pub spent_count: u64,
    pub funded_sats: u64,
    pub spent_sats: u64,
}

#[must_use]
pub fn encode_script_stats_key(gen_id: u64, script_id: u32) -> [u8; SCRIPT_STATS_KEY_LEN] {
    let mut key = [0u8; SCRIPT_STATS_KEY_LEN];
    key[0..8].copy_from_slice(&gen_id.to_be_bytes());
    key[8..12].copy_from_slice(&script_id.to_be_bytes());
    key
}

#[must_use]
pub fn decode_script_stats_key(key: &[u8]) -> Option<(u64, u32)> {
    if key.len() < SCRIPT_STATS_KEY_LEN {
        return None;
    }
    let gen_id = u64::from_be_bytes(key[0..8].try_into().ok()?);
    let script_id = u32::from_be_bytes(key[8..12].try_into().ok()?);
    Some((gen_id, script_id))
}

#[must_use]
pub fn encode_script_stats_value(stats: &ScriptStats) -> [u8; SCRIPT_STATS_VALUE_LEN] {
    let mut val = [0u8; SCRIPT_STATS_VALUE_LEN];
    val[0..8].copy_from_slice(&stats.funded_count.to_le_bytes());
    val[8..16].copy_from_slice(&stats.spent_count.to_le_bytes());
    val[16..24].copy_from_slice(&stats.funded_sats.to_le_bytes());
    val[24..32].copy_from_slice(&stats.spent_sats.to_le_bytes());
    val
}

#[must_use]
pub fn decode_script_stats_value(val: &[u8]) -> Option<ScriptStats> {
    if val.len() < SCRIPT_STATS_VALUE_LEN {
        return None;
    }
    Some(ScriptStats {
        funded_count: u64::from_le_bytes(val[0..8].try_into().ok()?),
        spent_count: u64::from_le_bytes(val[8..16].try_into().ok()?),
        funded_sats: u64::from_le_bytes(val[16..24].try_into().ok()?),
        spent_sats: u64::from_le_bytes(val[24..32].try_into().ok()?),
    })
}

#[must_use]
pub fn encode_filter_key(gen_id: u64, height: u32) -> [u8; FILTER_KEY_LEN] {
    let mut key = [0u8; FILTER_KEY_LEN];
    key[0..8].copy_from_slice(&gen_id.to_be_bytes());
    key[8..12].copy_from_slice(&height.to_be_bytes());
    key
}

#[must_use]
pub fn decode_filter_key(key: &[u8]) -> Option<(u64, u32)> {
    if key.len() < FILTER_KEY_LEN {
        return None;
    }
    let gen_id = u64::from_be_bytes(key[0..8].try_into().ok()?);
    let height = u32::from_be_bytes(key[8..12].try_into().ok()?);
    Some((gen_id, height))
}

#[must_use]
pub fn encode_filter_value(
    block_hash: &[u8; 32],
    filter_hash: &[u8; 32],
    header: &[u8; 32],
    gcs: &[u8],
) -> Vec<u8> {
    let mut val = Vec::with_capacity(FILTER_HEADER_PREFIX_LEN + gcs.len());
    val.extend_from_slice(block_hash);
    val.extend_from_slice(filter_hash);
    val.extend_from_slice(header);
    val.extend_from_slice(gcs);
    val
}

pub type DecodedFilter<'a> = ([u8; 32], [u8; 32], [u8; 32], &'a [u8]);

#[must_use]
pub fn decode_filter_value(val: &[u8]) -> Option<DecodedFilter<'_>> {
    if val.len() < FILTER_HEADER_PREFIX_LEN {
        return None;
    }
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&val[0..32]);
    let mut filter_hash = [0u8; 32];
    filter_hash.copy_from_slice(&val[32..64]);
    let mut header = [0u8; 32];
    header.copy_from_slice(&val[64..96]);
    let gcs = &val[96..];
    Some((block_hash, filter_hash, header, gcs))
}
