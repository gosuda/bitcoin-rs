use crate::inv::{native_block_hash, wire_block_hash};

use hashbrown::HashMap;
use std::time::{Duration, Instant};

use bitcoin::bip152::{BlockTransactionsRequest, HeaderAndShortIds, ShortId};
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn};
use bitcoin_rs_consensus::primitives::deserialize;
use bitcoin_rs_consensus::primitives::{Block, BlockHash, BlockImage, Header, Tx, Txid, Wtxid};

pub use crate::wire::MAX_BLOCK_TX_COUNT;

pub use crate::peer::COMPACT_BLOCK_VERSION;

pub const MAX_PENDING_RECONSTRUCTIONS: usize = 4;
pub const MAX_PENDING_RETAINED_BYTES: usize = 8 * 1_024 * 1_024;
pub const PENDING_DEADLINE: Duration = Duration::from_mins(1);
pub const MAX_REQUESTED_MISSING: usize = 128;
pub const MAX_RECENT_COMPACT_BLOCKS: usize = 256;

pub trait CompactBlockHints: Send + Sync {
    fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid));

    fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx>;

    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx>;
}

#[derive(Debug)]
pub enum Outcome {
    Complete(BlockImage),
    RequestMissing(GetBlockTxn),
    Fallback(BlockHash),
    Idle,
}

#[derive(Debug, Default)]
pub struct Reconstruction {
    pending: HashMap<BlockHash, Pending>,
    recent: Vec<(BlockHash, Instant)>,
}

#[derive(Debug)]
struct Pending {
    header: Header,
    filled: Vec<Option<Tx>>,
    missing: Vec<u64>,
    retained_bytes: usize,
    deadline: Instant,
}

impl Reconstruction {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            recent: Vec::new(),
        }
    }

    pub fn receive_cmpctblock(
        &mut self,
        cmpct: &CmpctBlock,
        identity_version: u64,
        hints: &dyn CompactBlockHints,
        now: Instant,
    ) -> Outcome {
        self.prune(now);
        let compact = &cmpct.compact_block;
        let Some(header) = native_header(&compact.header) else {
            return Outcome::Fallback(native_block_hash(compact.header.block_hash()));
        };
        let hash = header.compute_hash();
        if self.recent.iter().any(|(seen, _)| *seen == hash) {
            return Outcome::Idle;
        }
        if self.recent.len() == MAX_RECENT_COMPACT_BLOCKS {
            self.recent.remove(0);
        }
        self.recent.push((hash, now));
        let Some(total) = compact
            .short_ids
            .len()
            .checked_add(compact.prefilled_txs.len())
        else {
            return Outcome::Fallback(hash);
        };
        if total > MAX_BLOCK_TX_COUNT {
            return Outcome::Fallback(hash);
        }

        let pending_bytes = self.retained_bytes();
        let slot_bytes = total.saturating_mul(core::mem::size_of::<Option<Tx>>());
        let short_id_bytes = 6_usize.saturating_mul(compact.short_ids.len());
        if self.pending.len() >= MAX_PENDING_RECONSTRUCTIONS
            || pending_bytes
                .saturating_add(slot_bytes)
                .saturating_add(short_id_bytes)
                > MAX_PENDING_RETAINED_BYTES
        {
            return Outcome::Fallback(hash);
        }

        let Some(mut filled) = place_prefills(compact, total) else {
            return Outcome::Fallback(hash);
        };
        let mut retained_bytes = short_id_bytes
            .saturating_add(
                filled
                    .capacity()
                    .saturating_mul(core::mem::size_of::<Option<Tx>>()),
            )
            .saturating_add(
                filled
                    .iter()
                    .flatten()
                    .map(retained_tx_bytes)
                    .sum::<usize>(),
            );

        if pending_bytes.saturating_add(retained_bytes) > MAX_PENDING_RETAINED_BYTES {
            return Outcome::Fallback(hash);
        }

        let identity_is_wtxid = identity_version == 2;
        let keys = ShortId::calculate_siphash_keys(&compact.header, compact.nonce);
        match fill_from_hints(
            &mut filled,
            compact,
            identity_is_wtxid,
            keys,
            hints,
            &mut retained_bytes,
        ) {
            Ok(()) => {}
            Err(()) => return Outcome::Fallback(hash),
        }

        if pending_bytes.saturating_add(retained_bytes) > MAX_PENDING_RETAINED_BYTES {
            return Outcome::Fallback(hash);
        }
        let missing_count = filled.iter().filter(|slot| slot.is_none()).count();
        if missing_count == 0 {
            return match complete_block(header, filled) {
                Ok(block) => Outcome::Complete(block),
                Err(()) => Outcome::Fallback(hash),
            };
        }
        if missing_count > MAX_REQUESTED_MISSING {
            return Outcome::Fallback(hash);
        }
        let mut missing = Vec::with_capacity(missing_count);
        missing.extend(
            filled
                .iter()
                .enumerate()
                .filter(|(_, slot)| slot.is_none())
                .map(|(index, _)| u64::try_from(index).unwrap_or(u64::MAX)),
        );
        retained_bytes = retained_bytes.saturating_add(
            missing
                .capacity()
                .saturating_mul(core::mem::size_of::<u64>()),
        );
        if pending_bytes.saturating_add(retained_bytes) > MAX_PENDING_RETAINED_BYTES {
            return Outcome::Fallback(hash);
        }
        let indexes = missing.clone();
        self.pending.insert(
            hash,
            Pending {
                header,
                filled,
                missing,
                retained_bytes,
                deadline: now + PENDING_DEADLINE,
            },
        );
        Outcome::RequestMissing(GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash: wire_block_hash(hash),
                indexes,
            },
        })
    }

    pub fn receive_blocktxn(&mut self, txn: &BlockTxn, now: Instant) -> Outcome {
        self.prune(now);
        let hash = native_block_hash(txn.transactions.block_hash);
        let Some(mut entry) = self.pending.remove(&hash) else {
            return Outcome::Idle;
        };
        if txn.transactions.transactions.len() != entry.missing.len() {
            return Outcome::Fallback(hash);
        }
        for (slot, tx) in entry.missing.iter().zip(&txn.transactions.transactions) {
            let Some(body) = native_tx(tx) else {
                return Outcome::Fallback(hash);
            };
            let Some(slot) = usize::try_from(*slot)
                .ok()
                .filter(|slot| *slot < entry.filled.len())
            else {
                return Outcome::Fallback(hash);
            };
            entry.filled[slot] = Some(body);
        }
        let filled = std::mem::take(&mut entry.filled);
        let Ok(block) = complete_block(entry.header, filled) else {
            return Outcome::Fallback(hash);
        };
        Outcome::Complete(block)
    }

    pub fn prune(&mut self, now: Instant) {
        self.pending.retain(|_, entry| now < entry.deadline);
        self.recent
            .retain(|(_, received)| now.saturating_duration_since(*received) < PENDING_DEADLINE);
    }

    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.pending
            .values()
            .map(|entry| entry.retained_bytes)
            .sum()
    }

    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

fn complete_block(header: Header, filled: Vec<Option<Tx>>) -> Result<BlockImage, ()> {
    if filled.iter().any(Option::is_none) {
        return Err(());
    }
    let txs: Vec<Tx> = filled.into_iter().flatten().collect();
    let block = Block { header, txs };
    let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
    bitcoin_rs_consensus::verify_merkle_root_with_txids(&block, &txids).map_err(|_| ())?;
    if bitcoin_rs_consensus::is_sixty_four_byte_mutation(&block.txs) {
        return Err(());
    }

    let payload_len: usize = block.txs.iter().map(Tx::total_size).sum();
    let total_capacity = 80 + 9 + payload_len;
    let mut raw = Vec::with_capacity(total_capacity);
    bitcoin_rs_consensus::primitives::encode::ConsensusEncode::consensus_encode(
        &block.header,
        &mut raw,
    );
    let tx_count = u64::try_from(block.txs.len()).map_err(|_| ())?;
    raw.extend_from_slice(bitcoin_rs_consensus::primitives::varint::encode(tx_count).as_slice());
    for tx in &block.txs {
        bitcoin_rs_consensus::primitives::encode::ConsensusEncode::consensus_encode(tx, &mut raw);
    }
    BlockImage::from_raw(bytes::Bytes::from(raw)).map_err(|_| ())
}

fn fill_from_hints(
    filled: &mut [Option<Tx>],
    compact: &HeaderAndShortIds,
    identity_is_wtxid: bool,
    keys: (u64, u64),
    hints: &dyn CompactBlockHints,
    retained_bytes: &mut usize,
) -> Result<(), ()> {
    let mut wanted: HashMap<ShortId, usize> = HashMap::new();
    let mut short_id_cursor = 0_usize;
    for (slot, slot_tx) in filled.iter().enumerate() {
        if slot_tx.is_some() {
            continue;
        }
        match compact.short_ids.get(short_id_cursor) {
            Some(short_id) => {
                wanted.insert(*short_id, slot);
                short_id_cursor += 1;
            }
            None => return Err(()),
        }
    }
    if short_id_cursor != compact.short_ids.len() || wanted.len() != compact.short_ids.len() {
        return Err(());
    }
    let mut claims: Vec<Option<(Txid, Wtxid)>> = vec![None; filled.len()];
    let mut retired = vec![false; filled.len()];
    hints.for_each_identity(&mut |txid, wtxid| {
        let identity = if identity_is_wtxid {
            wtxid.as_bytes()
        } else {
            txid.as_bytes()
        };
        let Some(&slot) = wanted.get(&ShortId::with_siphash_keys(identity, keys)) else {
            return;
        };
        if retired[slot] {
            return;
        }
        let Some((claimed_txid, claimed_wtxid)) = claims[slot] else {
            claims[slot] = Some((txid, wtxid));
            return;
        };
        if claimed_txid != txid || claimed_wtxid != wtxid {
            claims[slot] = None;
            retired[slot] = true;
        }
    });
    for (slot, claim) in claims.into_iter().enumerate() {
        let Some((txid, wtxid)) = claim else {
            continue;
        };
        let body = if identity_is_wtxid {
            hints.get_tx_by_wtxid(wtxid)
        } else {
            hints.get_tx_by_txid(txid)
        };
        let Some(body) = body else {
            continue;
        };
        *retained_bytes = retained_bytes.saturating_add(retained_tx_bytes(&body));
        filled[slot] = Some(body);
    }
    Ok(())
}

fn retained_tx_bytes(tx: &Tx) -> usize {
    core::mem::size_of::<Tx>().saturating_add(tx.retained_heap_bytes())
}

fn place_prefills(compact: &HeaderAndShortIds, total: usize) -> Option<Vec<Option<Tx>>> {
    let mut filled: Vec<Option<Tx>> = vec![None; total];
    let mut position: usize = 0;
    for prefill in &compact.prefilled_txs {
        let slot = position.checked_add(usize::from(prefill.idx))?;
        if slot >= total {
            return None;
        }
        filled[slot] = Some(native_tx(&prefill.tx)?);
        position = slot + 1;
    }
    Some(filled)
}

pub(crate) fn native_header(reg: &bitcoin::blockdata::block::Header) -> Option<Header> {
    deserialize(&bitcoin::consensus::encode::serialize(reg)).ok()
}
fn native_tx(reg: &bitcoin::Transaction) -> Option<Tx> {
    deserialize(&bitcoin::consensus::encode::serialize(reg)).ok()
}

#[cfg(test)]
mod tests;
