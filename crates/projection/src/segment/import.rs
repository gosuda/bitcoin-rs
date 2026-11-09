use super::format::{
    PostingItem, chunk_postings, encode_script_dict_key, encode_script_dict_value,
    encode_spend_dir_key, encode_spend_dir_value, encode_tx_dir_key, encode_tx_dir_value,
    encode_tx_ordinal_key, encode_tx_ordinal_value,
};
use super::tail::{self, TailBounds};
use super::{Coverage, SEAL_NEXT_GEN_KEY, SealedGen, encode_sealed_gen, sealed_gen_key};
use crate::types::{
    HASH_PREFIX_LEN, HEIGHT_SIZE, SPENDING_RECORD_KEY_LEN, ScriptHistoryOccurrence, TxPosition,
    TxPositionValue, U24_MAX, decode_history_height,
};
use crate::{IndexCapabilities, IndexCapability, IndexError};
use bitcoin_rs_storage::{
    BufferedWriteBatch, ColumnFamily, KvStore, PrefixScanLimit, StorageError,
};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ScriptHistoryImportError {
    #[error("script history record at height {height} is not importable: {reason}")]
    Record { height: u32, reason: &'static str },
    #[error(
        "the artifact names {transactions} transactions, above its chain count {chain_tx_count}"
    )]
    TooManyTransactions {
        transactions: usize,
        chain_tx_count: u64,
    },
    #[error("the verified header chain has no block at height {height}")]
    MissingHeader { height: u32 },
}

pub struct ImportedSegment {
    pub(crate) coverage: Coverage,
    pub(crate) next_ordinal: u32,
    pub(crate) records: u64,
    pub(crate) families: Vec<(ColumnFamily, Rows)>,
}

type Identity = (u32, u32, u32);
type Rows = Vec<(Vec<u8>, Vec<u8>)>;

fn record_error(height: u32, reason: &'static str) -> ScriptHistoryImportError {
    ScriptHistoryImportError::Record { height, reason }
}

fn identity_of(height: u32, position: TxPosition) -> Identity {
    (height, position.offset(), position.byte_len())
}

fn funding_height(key: &[u8]) -> Option<u32> {
    let bytes: [u8; HEIGHT_SIZE] = key.get(HASH_PREFIX_LEN..)?.try_into().ok()?;
    Some(decode_history_height(bytes))
}

struct Spend {
    txid: [u8; 32],
    vout: u32,
    height: u32,
    spender: Identity,
}

fn parse_spend(key: &[u8], value: &[u8]) -> Result<Spend, ScriptHistoryImportError> {
    if key.len() != SPENDING_RECORD_KEY_LEN {
        return Err(record_error(0, "spending key has the wrong length"));
    }
    let mut txid = [0_u8; 32];
    txid.copy_from_slice(&key[..32]);
    let vout = u32::from_be_bytes([key[32], key[33], key[34], key[35]]);
    let height = u32::from_be_bytes([key[36], key[37], key[38], key[39]]);
    let positions = TxPositionValue::decode(value)
        .ok_or_else(|| record_error(height, "entries are not positions"))?;
    let [position] = positions else {
        return Err(record_error(
            height,
            "a spent outpoint names exactly one spending transaction",
        ));
    };
    if vout > U24_MAX {
        return Err(record_error(
            height,
            "vout exceeds the spend directory range",
        ));
    }
    Ok(Spend {
        txid,
        vout,
        height,
        spender: identity_of(height, *position),
    })
}

struct Transactions {
    identities: BTreeMap<Identity, Option<[u8; 32]>>,
}

impl Transactions {
    fn name(&mut self, identity: Identity, txid: Option<[u8; 32]>) -> Result<(), &'static str> {
        let slot = self.identities.entry(identity).or_insert(None);
        match (*slot, txid) {
            (Some(known), Some(txid)) if known != txid => {
                Err("one position names two transactions")
            }
            (None, Some(txid)) => {
                *slot = Some(txid);
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

// PRJ-07
pub(crate) fn script_history_segment(
    funding: &[(Vec<u8>, Vec<u8>)],
    spending: &[(Vec<u8>, Vec<u8>)],
    coverage: Coverage,
    chain_tx_count: u64,
    block_hashes: &[[u8; 32]],
) -> Result<ImportedSegment, ScriptHistoryImportError> {
    let mut transactions = Transactions {
        identities: BTreeMap::new(),
    };
    let funded = collect_funded(funding, &mut transactions)?;
    let spends = spending
        .iter()
        .map(|(key, value)| parse_spend(key, value))
        .collect::<Result<Vec<_>, _>>()?;
    for spend in &spends {
        transactions
            .name(spend.spender, None)
            .map_err(|reason| record_error(spend.height, reason))?;
    }

    let count = transactions.identities.len();
    let too_many = || ScriptHistoryImportError::TooManyTransactions {
        transactions: count,
        chain_tx_count,
    };
    let next_ordinal = u32::try_from(chain_tx_count).map_err(|_| too_many())?;
    if u64::try_from(count).map_or(true, |count| count > chain_tx_count) {
        return Err(too_many());
    }
    let base = chain_tx_count - u64::try_from(count).map_err(|_| too_many())?;
    let mut ordinals: BTreeMap<Identity, u32> = BTreeMap::new();
    for (index, identity) in transactions.identities.keys().enumerate() {
        let index = u64::try_from(index).map_err(|_| too_many())?;
        ordinals.insert(
            *identity,
            u32::try_from(base + index).map_err(|_| too_many())?,
        );
    }

    let (tx_rows, creations) = transaction_rows(&transactions.identities, &ordinals, block_hashes)?;
    let postings = posting_rows(&funded, &ordinals).map_err(|_| too_many())?;
    let spend_dir = spend_rows(&spends, &creations, &ordinals)?;

    Ok(ImportedSegment {
        coverage,
        next_ordinal,
        records: u64::try_from(funding.len() + spending.len()).unwrap_or(u64::MAX),
        families: vec![
            (ColumnFamily::TxDir, tx_rows),
            (ColumnFamily::ScriptDict, postings.dictionary),
            (ColumnFamily::ScriptPost, postings.posts),
            (ColumnFamily::SpendDir, spend_dir),
        ],
    })
}

fn collect_funded(
    funding: &[(Vec<u8>, Vec<u8>)],
    transactions: &mut Transactions,
) -> Result<Vec<(Identity, ScriptHistoryOccurrence)>, ScriptHistoryImportError> {
    let mut funded = Vec::new();
    for (key, value) in funding {
        let height = funding_height(key).ok_or_else(|| record_error(0, "key has no height"))?;
        let occurrences = ScriptHistoryOccurrence::decode_all(value)
            .ok_or_else(|| record_error(height, "entries are not history occurrences"))?;
        for occurrence in occurrences {
            let identity = identity_of(height, occurrence.position);
            transactions
                .name(identity, Some(occurrence.txid))
                .map_err(|reason| record_error(height, reason))?;
            funded.push((identity, occurrence));
        }
    }
    Ok(funded)
}

type Creations = BTreeMap<[u8; 32], Vec<u32>>;

fn transaction_rows(
    identities: &BTreeMap<Identity, Option<[u8; 32]>>,
    ordinals: &BTreeMap<Identity, u32>,
    block_hashes: &[[u8; 32]],
) -> Result<(Rows, Creations), ScriptHistoryImportError> {
    let zero = [0_u8; 32];
    let mut rows = Vec::with_capacity(identities.len().saturating_mul(2));
    let mut creations: Creations = BTreeMap::new();
    for (identity, txid) in identities {
        let (height, offset, len) = *identity;
        let ordinal = ordinals[identity];
        rows.push((
            encode_tx_ordinal_key(0, ordinal).to_vec(),
            encode_tx_ordinal_value(&txid.unwrap_or(zero), height, offset, len).to_vec(),
        ));
        let Some(txid) = txid else {
            continue;
        };
        let block_hash = usize::try_from(height)
            .ok()
            .and_then(|index| block_hashes.get(index))
            .ok_or(ScriptHistoryImportError::MissingHeader { height })?;
        creations.entry(*txid).or_default().push(ordinal);
        rows.push((
            encode_tx_dir_key(0, txid, height).to_vec(),
            encode_tx_dir_value(block_hash, ordinal, offset, len).to_vec(),
        ));
    }
    Ok((rows, creations))
}

fn latest_creation_before(creations: &Creations, txid: &[u8; 32], spending: u32) -> Option<u32> {
    let ordinals = creations.get(txid)?;
    let earlier = ordinals.partition_point(|&creation| creation < spending);
    earlier.checked_sub(1).map(|index| ordinals[index])
}

struct PostingRows {
    dictionary: Rows,
    posts: Rows,
}

fn posting_rows(
    funded: &[(Identity, ScriptHistoryOccurrence)],
    ordinals: &BTreeMap<Identity, u32>,
) -> Result<PostingRows, std::num::TryFromIntError> {
    let mut by_script: BTreeMap<[u8; 32], Vec<(u32, u8)>> = BTreeMap::new();
    for (identity, occurrence) in funded {
        by_script
            .entry(occurrence.scripthash.to_byte_array())
            .or_default()
            .push((ordinals[identity], occurrence.flags));
    }
    let mut dictionary = Vec::with_capacity(by_script.len());
    let mut posts = Vec::new();
    for (script_index, (scripthash, mut entries)) in by_script.into_iter().enumerate() {
        let script_id = u32::try_from(script_index)?;
        entries.sort_unstable();
        let mut previous = 0_u32;
        let items = entries
            .into_iter()
            .map(|(ordinal, flags)| {
                let item = PostingItem {
                    delta_ordinal: ordinal - previous,
                    flags,
                };
                previous = ordinal;
                item
            })
            .collect();
        dictionary.push((
            encode_script_dict_key(0, &scripthash).to_vec(),
            encode_script_dict_value(script_id).to_vec(),
        ));
        posts.extend(chunk_postings(0, script_id, items));
    }
    Ok(PostingRows { dictionary, posts })
}

fn spend_rows(
    spends: &[Spend],
    creations: &Creations,
    ordinals: &BTreeMap<Identity, u32>,
) -> Result<Rows, ScriptHistoryImportError> {
    let mut rows = Vec::with_capacity(spends.len());
    for spend in spends {
        let spending = ordinals[&spend.spender];
        let Some(creation) = latest_creation_before(creations, &spend.txid, spending) else {
            continue;
        };
        rows.push((
            encode_spend_dir_key(0, creation, spend.vout).to_vec(),
            encode_spend_dir_value(spending).to_vec(),
        ));
    }
    rows.sort_unstable();
    if rows.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(record_error(0, "a spent outpoint appears twice"));
    }
    Ok(rows)
}

const SEGMENT_FAMILIES: [ColumnFamily; 6] = [
    ColumnFamily::TxDir,
    ColumnFamily::ScriptDict,
    ColumnFamily::ScriptPost,
    ColumnFamily::SpendDir,
    ColumnFamily::ScriptStats,
    ColumnFamily::Filters,
];

pub(crate) fn next_segment_id<S: KvStore>(store: &S) -> Result<u64, IndexError> {
    let snapshot = store.snapshot()?;
    crate::segment::tail::next_gen_id(snapshot.as_ref())
}

pub(crate) fn clear_unpublished_segment_rows<S: KvStore>(store: &S) -> Result<(), IndexError> {
    let start = next_segment_id(store)?.to_be_bytes();
    let end = [0xFF_u8; 8];
    let snapshot = store.snapshot()?;
    let mut staged = false;
    for cf in SEGMENT_FAMILIES {
        let probe = snapshot.scan_prefix_from_bounded(
            cf,
            &[],
            &start,
            PrefixScanLimit {
                max_rows: 1,
                max_bytes: usize::MAX,
            },
        )?;
        staged |= !probe.rows.is_empty();
    }
    drop(snapshot);
    if !staged {
        return Ok(());
    }
    for cf in SEGMENT_FAMILIES {
        store.delete_range(cf, &start, &end)?;
    }
    Ok(())
}

pub(crate) fn stage_segment<S: KvStore>(
    store: &S,
    gen_id: u64,
    segment: &ImportedSegment,
    scratch: &Path,
) -> Result<(), IndexError> {
    for (cf, rows) in &segment.families {
        let mut keyed = Vec::with_capacity(rows.len());
        for (key, value) in rows {
            let rest = key.get(8..).ok_or_else(malformed_key)?;
            let mut full = gen_id.to_be_bytes().to_vec();
            full.extend_from_slice(rest);
            keyed.push((full, value.clone()));
        }
        keyed.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let mut iter = keyed.into_iter();
        store.ingest_sorted(*cf, &mut iter, scratch)?;
    }
    Ok(())
}

pub(crate) fn put_segment(
    batch: &mut BufferedWriteBatch,
    gen_id: u64,
    segment: &ImportedSegment,
    capabilities: IndexCapabilities,
) {
    let sealed = SealedGen {
        gen_id,
        coverage: segment.coverage,
        next_ordinal: segment.next_ordinal,
    };
    let record = encode_sealed_gen(&sealed);
    let segment_caps: Vec<IndexCapability> = capabilities
        .iter()
        .filter(|capability| *capability != IndexCapability::ScriptLive)
        .collect();
    for &capability in &segment_caps {
        batch.put(
            ColumnFamily::IdxMeta,
            &sealed_gen_key(capability, gen_id),
            &record,
        );
    }
    batch.put(
        ColumnFamily::IdxMeta,
        SEAL_NEXT_GEN_KEY,
        &gen_id.saturating_add(1).to_le_bytes(),
    );
    tail::put_generation_descriptors(
        batch,
        segment_caps,
        TailBounds {
            newest: Some(sealed),
            first_height: None,
            at: Some((segment.coverage.last_height, segment.coverage.last_hash)),
        },
    );
}

fn malformed_key() -> IndexError {
    IndexError::Storage(StorageError::IncompatibleData(
        "imported segment key lacks a generation prefix".into(),
    ))
}

#[derive(Clone, Copy, Debug)]
pub struct TxOccurrence {
    pub txid: [u8; 32],
    pub height: u32,
    pub block_hash: [u8; 32],
    pub position: TxPosition,
}

// PRJ-06, PRJ-07, PRJ-09
pub(crate) fn tx_lookup_segment(
    mut occurrences: Vec<TxOccurrence>,
    coverage: Coverage,
    ordinal_base: u32,
) -> Result<ImportedSegment, IndexError> {
    occurrences.sort_unstable_by_key(|tx| (tx.height, tx.position.offset()));
    let count = u32::try_from(occurrences.len()).map_err(|_| restored_overflow())?;
    let next_ordinal = ordinal_base
        .checked_add(count)
        .ok_or_else(restored_overflow)?;
    let mut rows = Vec::with_capacity(occurrences.len().saturating_mul(2));
    for (ordinal, tx) in (ordinal_base..next_ordinal).zip(occurrences.iter()) {
        let position = tx.position;
        rows.push((
            encode_tx_dir_key(0, &tx.txid, tx.height).to_vec(),
            encode_tx_dir_value(
                &tx.block_hash,
                ordinal,
                position.offset(),
                position.byte_len(),
            )
            .to_vec(),
        ));
        rows.push((
            encode_tx_ordinal_key(0, ordinal).to_vec(),
            encode_tx_ordinal_value(&tx.txid, tx.height, position.offset(), position.byte_len())
                .to_vec(),
        ));
    }
    Ok(ImportedSegment {
        coverage,
        next_ordinal,
        records: u64::from(count),
        families: vec![(ColumnFamily::TxDir, rows)],
    })
}

fn restored_overflow() -> IndexError {
    IndexError::Storage(StorageError::IncompatibleData(
        "restored segment exceeds u32 ordinals".into(),
    ))
}
