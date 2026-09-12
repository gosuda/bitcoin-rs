//! BIP152 compact-block reconstruction.
//!
//! One [`Reconstruction`] lives per peer message loop: it owns the bounded
//! pending-reconstruction state for that connection and hands finished
//! blocks to the caller, which delivers them through the ordinary block
//! sink — the same validation and apply path as a `block` message, with no
//! bypass. Short IDs are hints only: any ambiguity, missing piece, bound,
//! or deadline miss degrades to a full-block `getdata` fallback on the same
//! connection, so a wrong guess costs round trips, never a wrong block.
//!
//! BIP152 identity direction: a peer serializes the compact blocks it sends
//! us with the version we advertised in our own `sendcmpct`
//! ([`COMPACT_BLOCK_VERSION`], v2 = wtxid identity, witness-bearing
//! prefills). Conversely, we serve peers at the version they recorded with
//! us (`CompactBlockNegotiation::servable_version`, used by the chain
//! query). The two directions are independent; decoding incoming compact
//! blocks never reads their preference.
//!
//! State is released by completion, by the deadline, by a replacement, and
//! by dropping the owner at disconnect or session cancel — a chain change
//! cannot strand memory beyond the deadline.

use hashbrown::HashMap;
use std::time::{Duration, Instant};

use bitcoin::bip152::{BlockTransactionsRequest, HeaderAndShortIds, ShortId};
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn};
use bitcoin_rs_primitives::deserialize;
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Header, Tx, Txid, Wtxid};

/// Compact-block protocol version this node advertises: the identity
/// profile peers use for the compact blocks they send us. Re-exported from
/// `peer` as the authority.
pub use crate::peer::COMPACT_BLOCK_VERSION;

/// Concurrent pending reconstructions per peer connection.
pub const MAX_PENDING_RECONSTRUCTIONS: usize = 4;
/// Approximate retained bytes across all pending entries before new
/// `cmpctblock` messages are refused in favor of the full-block fallback.
pub const MAX_PENDING_RETAINED_BYTES: usize = 8 * 1_024 * 1_024;
/// A pending entry older than this is dropped; a chain change cannot strand
/// memory longer than one deadline.
pub const PENDING_DEADLINE: Duration = Duration::from_secs(60);
/// Above this many missing transactions the `getblocktxn` round trip is
/// skipped: a full-block `getdata` is then the cheaper request.
pub const MAX_REQUESTED_MISSING: usize = 128;
/// Sanity bound on the transaction count a `cmpctblock` may declare.
const MAX_BLOCK_TX_COUNT: usize = 100_000;

/// Transaction identities the mempool can offer a compact-block
/// reconstruction: an identity scan plus body lookup by either hash.
///
/// Implemented for the shared [`bitcoin_rs_mempool::MempoolGateway`]; the
/// p2p crate owns the protocol adapter, mempool owns admission state.
pub trait CompactBlockHints: Send + Sync {
    /// Invokes `f` for every resident transaction as `(txid, wtxid)`.
    fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid));

    /// Returns the transaction body for `txid`, if held.
    fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx>;

    /// Returns the transaction body for `wtxid`, if held.
    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx>;
}

/// What the listener must do after one receive-side BIP152 step.
#[derive(Debug)]
pub enum Outcome {
    /// Reconstruction finished; deliver through the ordinary block sink.
    Complete(Block),
    /// Request the listed missing transaction indexes on the same connection.
    RequestMissing(GetBlockTxn),
    /// Reconstruction cannot complete from this peer's messages; request the
    /// full block instead.
    Fallback(BlockHash),
    /// Nothing to do (stale or already-fallen-back `blocktxn`).
    Idle,
}

/// Bounded per-peer pending-reconstruction state.
#[derive(Debug, Default)]
pub struct Reconstruction {
    pending: HashMap<BlockHash, Pending>,
}

/// One block being reconstructed.
#[derive(Debug)]
struct Pending {
    header: Header,
    filled: Vec<Option<Tx>>,
    /// Absolute slot indexes still missing, ascending.
    missing: Vec<u64>,
    /// Approximate retained bytes (prefill bodies + short IDs + filled bodies).
    retained_bytes: usize,
    deadline: Instant,
    /// A full-block fallback was already issued; late `blocktxn` is ignored.
    fallback: bool,
}

impl Reconstruction {
    /// Creates an empty reconstruction state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }

    /// Receive-side entry for `cmpctblock`.
    ///
    /// `identity_version` is the BIP152 version the peer used to serialize
    /// this message — our own advertised [`COMPACT_BLOCK_VERSION`], per the
    /// direction rule in the module docs. Prefills are placed, remaining
    /// short IDs are matched as hints against the mempool, and the outcome
    /// is [`Outcome::Complete`] (all filled), [`Outcome::RequestMissing`]
    /// (bounded missing list), or [`Outcome::Fallback`] (ambiguity,
    /// malformed indexes, or the bounded state is exhausted).
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
        let total = compact.short_ids.len() + compact.prefilled_txs.len();
        if total > MAX_BLOCK_TX_COUNT {
            return Outcome::Fallback(hash);
        }

        let Some(mut filled) = place_prefills(compact, total) else {
            return Outcome::Fallback(hash);
        };
        let mut retained_bytes = 6 * compact.short_ids.len()
            + filled
                .iter()
                .flatten()
                .map(|tx: &Tx| tx.total_size())
                .sum::<usize>();

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

        if self.pending.len() >= MAX_PENDING_RECONSTRUCTIONS
            || self.retained_bytes() + retained_bytes > MAX_PENDING_RETAINED_BYTES
        {
            return Outcome::Fallback(hash);
        }
        let missing: Vec<u64> = filled
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.is_none())
            .map(|(index, _)| u64::try_from(index).unwrap_or(u64::MAX))
            .collect();
        if missing.is_empty() {
            return Outcome::Complete(Block {
                header,
                txs: filled.into_txs(),
            });
        }
        if missing.len() > MAX_REQUESTED_MISSING {
            return Outcome::Fallback(hash);
        }
        self.pending.insert(
            hash,
            Pending {
                header,
                filled,
                missing: missing.clone(),
                retained_bytes,
                deadline: now + PENDING_DEADLINE,
                fallback: false,
            },
        );
        Outcome::RequestMissing(GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash: wire_block_hash(hash),
                indexes: missing,
            },
        })
    }

    /// Receive-side entry for `blocktxn`.
    ///
    /// Places the announced transactions at the pending entry's missing
    /// indexes and completes the block, or falls back when the response does
    /// not match the outstanding request.
    pub fn receive_blocktxn(&mut self, txn: &BlockTxn, now: Instant) -> Outcome {
        self.prune(now);
        let hash = native_block_hash(txn.transactions.block_hash);
        {
            let Some(entry) = self.pending.get_mut(&hash) else {
                return Outcome::Idle;
            };
            if entry.fallback {
                return Outcome::Idle;
            }
            if txn.transactions.transactions.len() != entry.missing.len() {
                entry.fallback = true;
                return Outcome::Fallback(hash);
            }
            for (slot, tx) in entry.missing.iter().zip(&txn.transactions.transactions) {
                let Some(body) = native_tx(tx) else {
                    entry.fallback = true;
                    return Outcome::Fallback(hash);
                };
                let Some(slot) = usize::try_from(*slot)
                    .ok()
                    .filter(|slot| *slot < entry.filled.len())
                else {
                    entry.fallback = true;
                    return Outcome::Fallback(hash);
                };
                entry.filled[slot] = Some(body);
            }
            if entry.filled.iter().any(Option::is_none) {
                entry.fallback = true;
                return Outcome::Fallback(hash);
            }
        }
        let Some(entry) = self.pending.remove(&hash) else {
            return Outcome::Idle;
        };
        let txs = entry.filled.into_txs();
        Outcome::Complete(Block {
            header: entry.header,
            txs,
        })
    }

    /// Drops pending entries whose deadline passed.
    pub fn prune(&mut self, now: Instant) {
        self.pending.retain(|_, entry| now < entry.deadline);
    }

    fn retained_bytes(&self) -> usize {
        self.pending
            .values()
            .map(|entry| entry.retained_bytes)
            .sum()
    }
}

/// Matches the message's short IDs against the hint identities and fills
/// their slots. `short_ids` covers exactly the unfilled slots, in slot
/// order; a count mismatch means the message is malformed, and two distinct
/// hint identities claiming one short ID is an ambiguity — both fall back
/// rather than guess.
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
    if short_id_cursor != compact.short_ids.len() {
        return Err(());
    }
    let mut ambiguous = false;
    hints.for_each_identity(&mut |txid, wtxid| {
        if ambiguous {
            return;
        }
        let identity_bytes = if identity_is_wtxid {
            wtxid.as_bytes()
        } else {
            txid.as_bytes()
        };
        let short_id = ShortId::with_siphash_keys(identity_bytes, keys);
        let Some(&slot) = wanted.get(&short_id) else {
            return;
        };
        if filled[slot].is_some() {
            ambiguous = true;
            return;
        }
        let body = if identity_is_wtxid {
            hints.get_tx_by_wtxid(wtxid)
        } else {
            hints.get_tx_by_txid(txid)
        };
        let Some(body) = body else {
            return;
        };
        *retained_bytes += body.total_size();
        filled[slot] = Some(body);
    });
    if ambiguous { Err(()) } else { Ok(()) }
}

/// Places the differentially encoded prefills into the transaction slots,
/// or `None` when an index overflows or lies outside the block.
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

/// Consumes the slots into transaction bodies. Callers must have verified
/// completeness first (no `None` slots); the flatten is then lossless.
trait FilledSlots {
    fn into_txs(self) -> Vec<Tx>;
}

impl FilledSlots for Vec<Option<Tx>> {
    fn into_txs(self) -> Vec<Tx> {
        self.into_iter().flatten().collect()
    }
}

fn native_header(reg: &bitcoin::blockdata::block::Header) -> Option<Header> {
    deserialize(&bitcoin::consensus::encode::serialize(reg)).ok()
}

fn native_tx(reg: &bitcoin::Transaction) -> Option<Tx> {
    deserialize(&bitcoin::consensus::encode::serialize(reg)).ok()
}

/// Registry block hash → native block hash.
pub(crate) fn native_block_hash(hash: bitcoin::BlockHash) -> BlockHash {
    BlockHash::from(Hash256::from_le_bytes(hash.as_byte_array()))
}

fn wire_block_hash(hash: BlockHash) -> bitcoin::BlockHash {
    bitcoin::BlockHash::from_byte_array(*hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip152::BlockTransactions;
    use bitcoin::blockdata::block::Block as RegistryBlock;
    use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock};
    use bitcoin_rs_primitives::{
        Amount, LockTime, OutPoint, Sequence, TxIn, TxOut, Witness, consensus_bytes,
    };
    use std::time::Instant;

    /// Hints backed by a fixed transaction set, as the mempool would offer.
    struct SetHints {
        txs: Vec<Tx>,
    }

    impl CompactBlockHints for SetHints {
        fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
            for tx in &self.txs {
                f(tx.txid(), tx.wtxid());
            }
        }

        fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
            self.txs.iter().find(|tx| tx.txid() == txid).cloned()
        }

        fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
            self.txs.iter().find(|tx| tx.wtxid() == wtxid).cloned()
        }
    }

    fn test_tx(byte: u8) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from(Hash256::from_le_bytes(&[byte; 32])),
                    vout: 0,
                },
                script_sig: vec![byte].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![byte].into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    /// Native → registry transaction bridge for wire-level test fixtures.
    fn registry_tx(tx: &Tx) -> bitcoin::Transaction {
        bitcoin::consensus::encode::deserialize(&consensus_bytes(tx))
            .unwrap_or_else(|error| panic!("test tx must bridge: {error}"))
    }

    /// Builds a native block and the registry `cmpctblock` for it at
    /// `version`, proving the registry-encode / native-decode round trip.
    fn sample_cmpct(txs: Vec<Tx>, version: u64, nonce: u64) -> (Block, CmpctBlock) {
        let header = Header {
            version: 1,
            prev_blockhash: BlockHash::from(Hash256::from_le_bytes(&[0xab; 32])),
            merkle_root: Hash256::default(),
            time: 7,
            bits: bitcoin_rs_primitives::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 9,
        };
        let native = Block { header, txs };
        let registry =
            bitcoin::consensus::encode::deserialize::<RegistryBlock>(&consensus_bytes(&native))
                .unwrap_or_else(|error| panic!("sample block must decode: {error}"));
        let version =
            u32::try_from(version).unwrap_or_else(|error| panic!("version fits u32: {error}"));
        let compact = HeaderAndShortIds::from_block(&registry, nonce, version, &[])
            .unwrap_or_else(|error| panic!("sample compact block must build: {error}"));
        (
            native,
            CmpctBlock {
                compact_block: compact,
            },
        )
    }

    fn now() -> Instant {
        Instant::now()
    }

    /// v2 (wtxid identity): all transactions live in the hints, so the
    /// compact block reconstructs fully — the identity profile peers use
    /// toward us, round-tripped through the registry encoder.
    #[test]
    fn v2_compact_block_with_all_txs_hinted_reconstructs_completely() {
        let (native, cmpct) = sample_cmpct(vec![test_tx(1), test_tx(2), test_tx(3)], 2, 0x1234);
        let hints = SetHints {
            txs: native.txs.clone(),
        };
        let mut reconstruction = Reconstruction::new();

        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());

        let Outcome::Complete(block) = outcome else {
            panic!("expected complete reconstruction, got {outcome:?}");
        };
        assert_eq!(block.block_hash(), native.block_hash());
        assert_eq!(block.txs, native.txs);
    }

    /// v1 (txid identity, witness-stripped prefills): identities match by
    /// txid, so reconstruction still completes.
    #[test]
    fn v1_compact_block_matches_by_txid() {
        let (native, cmpct) = sample_cmpct(vec![test_tx(1), test_tx(2)], 1, 0x4321);
        let hints = SetHints {
            txs: native.txs.clone(),
        };
        let mut reconstruction = Reconstruction::new();

        let outcome = reconstruction.receive_cmpctblock(&cmpct, 1, &hints, now());

        let Outcome::Complete(block) = outcome else {
            panic!("expected complete reconstruction, got {outcome:?}");
        };
        assert_eq!(
            block.txs.iter().map(Tx::txid).collect::<Vec<_>>(),
            native.txs.iter().map(Tx::txid).collect::<Vec<_>>()
        );
    }

    /// A transaction missing from the mempool becomes a bounded
    /// `getblocktxn` request for its absolute index, and the late
    /// `blocktxn` completes the block.
    #[test]
    fn missing_tx_requests_getblocktxn_and_completes_on_blocktxn() {
        let (native, cmpct) = sample_cmpct(vec![test_tx(1), test_tx(2), test_tx(3)], 2, 0x99);
        let hints = SetHints {
            txs: vec![native.txs[0].clone(), native.txs[2].clone()],
        };
        let mut reconstruction = Reconstruction::new();

        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
        let Outcome::RequestMissing(request) = outcome else {
            panic!("expected getblocktxn request, got {outcome:?}");
        };
        assert_eq!(request.txs_request.indexes, vec![1]);
        assert_eq!(
            request.txs_request.block_hash,
            wire_block_hash(native.block_hash())
        );

        let txn = BlockTxn {
            transactions: BlockTransactions {
                block_hash: request.txs_request.block_hash,
                transactions: vec![registry_tx(&test_tx(2))],
            },
        };
        let outcome = reconstruction.receive_blocktxn(&txn, now());
        let Outcome::Complete(block) = outcome else {
            panic!("expected complete reconstruction, got {outcome:?}");
        };
        assert_eq!(block.txs, native.txs);
    }

    /// A `blocktxn` whose size does not match the outstanding request falls
    /// back to the full block instead of guessing.
    #[test]
    fn mismatched_blocktxn_falls_back() {
        let (native, cmpct) = sample_cmpct(vec![test_tx(1), test_tx(2)], 2, 0x77);
        let hints = SetHints {
            txs: vec![native.txs[0].clone()],
        };
        let mut reconstruction = Reconstruction::new();

        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
        let Outcome::RequestMissing(request) = outcome else {
            panic!("expected getblocktxn request, got {outcome:?}");
        };

        let wrong_size = BlockTxn {
            transactions: BlockTransactions {
                block_hash: request.txs_request.block_hash,
                transactions: vec![],
            },
        };
        let outcome = reconstruction.receive_blocktxn(&wrong_size, now());
        assert!(matches!(outcome, Outcome::Fallback(_)));
    }

    /// A `blocktxn` for an unknown (or expired) block does nothing, and the
    /// deadline release leaves nothing pending behind.
    #[test]
    fn stale_or_expired_blocktxn_is_idle_and_state_is_released() {
        let (native, cmpct) = sample_cmpct(vec![test_tx(1), test_tx(2)], 2, 0x55);
        let hints = SetHints {
            txs: vec![native.txs[0].clone()],
        };
        let mut reconstruction = Reconstruction::new();

        let sent_at = now();
        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, sent_at);
        assert!(matches!(outcome, Outcome::RequestMissing(_)));

        let unknown = BlockTxn {
            transactions: BlockTransactions {
                block_hash: wire_block_hash(BlockHash::from(Hash256::from_le_bytes(&[9; 32]))),
                transactions: vec![registry_tx(&test_tx(2))],
            },
        };
        assert!(matches!(
            reconstruction.receive_blocktxn(&unknown, sent_at),
            Outcome::Idle
        ));

        let expired_at = sent_at + PENDING_DEADLINE;
        let delayed = BlockTxn {
            transactions: BlockTransactions {
                block_hash: wire_block_hash(native.block_hash()),
                transactions: vec![registry_tx(&test_tx(2))],
            },
        };
        assert!(matches!(
            reconstruction.receive_blocktxn(&delayed, expired_at),
            Outcome::Idle
        ));
    }

    /// More than [`MAX_REQUESTED_MISSING`] missing transactions skips the
    /// `getblocktxn` round trip in favor of the full-block fallback; the
    /// bound itself is still worth one request.
    #[test]
    fn cmpctblock_missing_above_the_request_bound_falls_back() {
        let hints = SetHints { txs: Vec::new() };
        let mut reconstruction = Reconstruction::new();

        let (_, cmpct) = sample_cmpct((0_u8..130).map(test_tx).collect(), 2, 0x1234);
        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
        assert!(matches!(outcome, Outcome::Fallback(_)));

        let (_, cmpct) = sample_cmpct((0_u8..129).map(test_tx).collect(), 2, 0x1234);
        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
        let Outcome::RequestMissing(request) = outcome else {
            panic!("expected a missing-list request at the bound, got {outcome:?}");
        };
        assert_eq!(request.txs_request.indexes.len(), MAX_REQUESTED_MISSING);
    }
}

