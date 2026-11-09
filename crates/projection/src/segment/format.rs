pub const TAIL_MAX_BLOCKS: u32 = 2_016;
pub const TAIL_MAX_BYTES: usize = 32 * 1024 * 1024;

pub const TX_DIR_KEY_LEN: usize = 44;
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

// PRJ-06, PRJ-07
#[must_use]
pub fn encode_tx_dir_key(gen_id: u64, txid: &[u8; 32], height: u32) -> [u8; TX_DIR_KEY_LEN] {
    let mut key = [0u8; TX_DIR_KEY_LEN];
    key[0..8].copy_from_slice(&gen_id.to_be_bytes());
    key[8..40].copy_from_slice(txid);
    key[40..44].copy_from_slice(&height.to_be_bytes());
    key
}

// PRJ-06, PRJ-07
#[must_use]
pub fn decode_tx_dir_key(key: &[u8]) -> Option<(u64, [u8; 32], u32)> {
    if key.len() < TX_DIR_KEY_LEN {
        return None;
    }
    let gen_id = u64::from_be_bytes(key[0..8].try_into().ok()?);
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&key[8..40]);
    let height = u32::from_be_bytes(key[40..44].try_into().ok()?);
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

pub const TX_ORDINAL_KEY_LEN: usize = 12;
pub const TX_ORDINAL_VALUE_LEN: usize = 44;

// PRJ-07
#[must_use]
pub fn encode_tx_ordinal_key(gen_id: u64, ordinal: u32) -> [u8; TX_ORDINAL_KEY_LEN] {
    let mut key = [0u8; TX_ORDINAL_KEY_LEN];
    key[0..8].copy_from_slice(&gen_id.to_be_bytes());
    key[8..12].copy_from_slice(&ordinal.to_be_bytes());
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
pub fn chunk_postings(
    gen_id: u64,
    script_id: u32,
    items: Vec<PostingItem>,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows = Vec::new();
    let mut chunk: Vec<PostingItem> = Vec::new();
    let mut chunk_bytes = 0usize;
    let mut chunk_idx = 0u32;
    for item in items {
        let item_bytes = uvarint_len(item.delta_ordinal).saturating_add(1);
        if !chunk.is_empty() && chunk_bytes.saturating_add(item_bytes) > SCRIPT_POST_CHUNK_MAX_BYTES
        {
            rows.push((
                encode_script_post_key(gen_id, script_id, chunk_idx).to_vec(),
                encode_posting_items(&chunk),
            ));
            chunk.clear();
            chunk_bytes = 0;
            chunk_idx = chunk_idx.saturating_add(1);
        }
        chunk_bytes = chunk_bytes.saturating_add(item_bytes);
        chunk.push(item);
    }
    rows.push((
        encode_script_post_key(gen_id, script_id, chunk_idx).to_vec(),
        encode_posting_items(&chunk),
    ));
    rows
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
