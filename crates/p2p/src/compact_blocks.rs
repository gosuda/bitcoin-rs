//! BIP152 compact-block reconstruction.
//!
//! One [`Reconstruction`] lives per peer message loop: it owns the bounded
//! pending-reconstruction state for that connection and hands finished
//! blocks to the caller, which delivers them through the ordinary block
//! sink — the same validation and apply path as a `block` message, with no
//! bypass. Short IDs are hints only: any ambiguity, missing piece, or bound
//! miss degrades to a full-block `getdata` fallback on the same connection,
//! so a wrong guess costs round trips, never a wrong block; an entry whose
//! deadline passes is dropped silently — liveness then rests on the
//! connection's separate stall handling.
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
use bitcoin_rs_primitives::encode::double_sha256;
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
pub const PENDING_DEADLINE: Duration = Duration::from_mins(1);
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
    /// Number of short IDs the message declared for the non-prefilled slots;
    /// the accounting [`complete_block`] re-checks before delivery.
    short_id_count: usize,
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
            return match complete_block(header, filled, compact.short_ids.len()) {
                Ok(block) => Outcome::Complete(block),
                Err(()) => Outcome::Fallback(hash),
            };
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
                short_id_count: compact.short_ids.len(),
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
    /// not match the outstanding request. A completion that fails
    /// verification flags the entry first: a late `blocktxn` for the same
    /// block is then ignored, not re-guessed.
    pub fn receive_blocktxn(&mut self, txn: &BlockTxn, now: Instant) -> Outcome {
        self.prune(now);
        let hash = native_block_hash(txn.transactions.block_hash);
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
        let filled = std::mem::take(&mut entry.filled);
        let Ok(block) = complete_block(entry.header, filled, entry.short_id_count) else {
            entry.fallback = true;
            return Outcome::Fallback(hash);
        };
        self.pending.remove(&hash);
        Outcome::Complete(block)
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

/// PRE: `filled` holds the declared prefill plus one slot per declared short
/// ID for one reconstruction whose transaction request, if any, has been
/// answered.
/// POST: return a block only when every slot exists, no more slots than
/// `short_id_count` plus the prefills were declared, the transaction-ID
/// merkle root of the assembled body equals `header.merkle_root`, and the
/// transaction-ID tree is not mutated; otherwise return `Err`.
/// INVARIANT: no unverified compact reconstruction reaches
/// [`Outcome::Complete`]. The root check alone cannot detect the
/// duplicate-final-transaction collision (CVE-2012-2459): `[a, b, c]` and
/// `[a, b, c, c]` hash to the same root, so the reduction also rejects a
/// mutated tree and the caller answers with the same-peer full-block
/// fallback (Core 31.1 `READ_STATUS_FAILED` before delivery,
/// `blockencodings.cpp:207-219`).
fn complete_block(
    header: Header,
    filled: Vec<Option<Tx>>,
    short_id_count: usize,
) -> Result<Block, ()> {
    if filled.iter().any(Option::is_none) || filled.len() < short_id_count {
        return Err(());
    }
    let txs: Vec<Tx> = filled.into_iter().flatten().collect();
    let (root, mutated) = merkle_root_and_mutation(txs.iter().map(Tx::txid)).ok_or(())?;
    if mutated || root != Txid(header.merkle_root) {
        return Err(());
    }
    Ok(Block { header, txs })
}

/// Mutation-aware transaction-ID merkle reduction over borrowed leaves:
/// `(root, mutated)`, or `None` for an empty tree. Mirrors the consensus
/// walker (`bitcoin_rs_consensus` `merkle_root_spine`): two equal *real*
/// adjacent nodes at any level flag the tree as mutated, while the odd
/// leftover paired with its duplicate-last copy never does — the property
/// that makes `[a, b, c, c]` colliding with `[a, b, c]` a detected mutation
/// rather than a silent pass.
fn merkle_root_and_mutation(leaves: impl ExactSizeIterator<Item = Txid>) -> Option<(Txid, bool)> {
    if leaves.len() == 0 {
        return None;
    }
    let hash_pair = |left: Txid, right: Txid| {
        let mut pair = [0_u8; 64];
        pair[..32].copy_from_slice(left.as_bytes());
        pair[32..].copy_from_slice(right.as_bytes());
        Txid(double_sha256(&pair))
    };
    // One pending node per level; a block holds far fewer than 2^64 leaves.
    let mut spine: [Option<Txid>; 64] = [None; 64];
    let mut mutated = false;
    for leaf in leaves {
        let mut current = leaf;
        let mut height = 0;
        while let Some(left) = spine[height] {
            spine[height] = None;
            if left == current {
                mutated = true;
            }
            current = hash_pair(left, current);
            height += 1;
        }
        spine[height] = Some(current);
    }
    // Fold the right spine bottom-up: the carry rises to each pending height
    // through duplicate-last self-pairs (never a mutation), then joins that
    // pending node as its right sibling.
    let mut carry: Option<(Txid, usize)> = None;
    for (height, slot) in spine.iter().enumerate() {
        let Some(node) = *slot else { continue };
        carry = Some(match carry {
            None => (node, height),
            Some((accumulated, accumulated_height)) => {
                let mut right = accumulated;
                let mut right_height = accumulated_height;
                while right_height < height {
                    right = hash_pair(right, right);
                    right_height += 1;
                }
                if node == right {
                    mutated = true;
                }
                (hash_pair(node, right), height + 1)
            }
        });
    }
    carry.map(|(root, _height)| (root, mutated))
}

/// Matches the message's short IDs against the hint identities and fills
/// their slots. `short_ids` covers exactly the unfilled slots, in slot
/// order. Two structural faults mean the message cannot be trusted and the
/// reconstruction falls back rather than guess: fewer or more short IDs
/// than unfilled slots, and one short ID declared twice — a collapsed slot
/// map would silently misplace bodies. Two distinct hint identities that
/// collide on one short ID retire only that slot, which the `getblocktxn`
/// request then carries; a later candidate never refills it (Core 31.1
/// clears only the colliding slot, `blockencodings.cpp:116-166`).
///
/// PRE: `filled` holds one body per prefill and `None` per short-ID slot;
/// `retained_bytes` counts the short IDs and the prefilled bodies.
/// POST: every unambiguous slot holds its body and is counted once; a
/// retired slot, and one whose body the hints no longer offer, stay `None`
/// and uncounted.
/// INVARIANT: no body is looked up while the identity walk runs. The
/// mempool walk holds its pool read lock across the callback and a body
/// lookup takes that lock again, which deadlocks once a writer queues.
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
    // Identity scan: record one claim per slot, retire a slot the first time
    // a second identity claims it.
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
    // Body pass: outside the walk, fetch each surviving claim once.
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
        *retained_bytes += body.total_size();
        filled[slot] = Some(body);
    }
    Ok(())
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

/// Registry (rust-bitcoin) block header → primitives header.
pub(crate) fn native_header(reg: &bitcoin::blockdata::block::Header) -> Option<Header> {
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

    use bitcoin::bip152::{BlockTransactions, PrefilledTransaction};
    use bitcoin::blockdata::block::Block as RegistryBlock;
    use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock};
    use bitcoin_rs_primitives::{
        Amount, LockTime, OutPoint, Sequence, TxIn, TxOut, Witness, consensus_bytes,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Instant;

    /// Payload values ground offline for the fixed test header/nonce
    /// `(conforming_block([test_tx(1), test_tx(2), test_tx(3)]), 0x515)`:
    /// `colliding_tx_bytes(0x11, .0)` and `colliding_tx_bytes(0x22, .1)`
    /// produce distinct wtxids that hash to one short ID.
    const COLLIDING_PAYLOADS: (u32, u32) = (0x0055_7269, 0x0093_c777);

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

    /// Native → registry block bridge for wire-level test fixtures.
    fn registry_block(native: &Block) -> RegistryBlock {
        bitcoin::consensus::encode::deserialize(&consensus_bytes(native))
            .unwrap_or_else(|error| panic!("test block must bridge: {error}"))
    }

    /// Builds a native block over `txs` whose header commits to their
    /// transaction-ID merkle root, the property the reconstruction
    /// verifier enforces. The registry round trip pins the merkle byte
    /// order at the fixture level.
    fn conforming_block(txs: Vec<Tx>) -> Block {
        let mut native = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::from(Hash256::from_le_bytes(&[0xab; 32])),
                merkle_root: Hash256::default(),
                time: 7,
                bits: bitcoin_rs_primitives::CompactTarget::from_consensus(0x207f_ffff),
                nonce: 9,
            },
            txs,
        };
        let root = registry_block(&native)
            .compute_merkle_root()
            .unwrap_or_else(|| panic!("a non-empty block has a merkle root"));
        native.header.merkle_root = Hash256::from_le_bytes(&root.to_byte_array());
        assert_eq!(
            registry_block(&native).header.merkle_root,
            root,
            "merkle bytes must bridge losslessly"
        );
        native
    }

    /// Builds the registry `cmpctblock` for `native` at `version`, as the
    /// encoder produces it: the coinbase prefilled, every other slot a
    /// short ID.
    fn compact_of(native: &Block, version: u64, nonce: u64) -> CmpctBlock {
        let version =
            u32::try_from(version).unwrap_or_else(|error| panic!("version fits u32: {error}"));
        let compact = HeaderAndShortIds::from_block(&registry_block(native), nonce, version, &[])
            .unwrap_or_else(|error| panic!("sample compact block must build: {error}"));
        CmpctBlock {
            compact_block: compact,
        }
    }

    /// Builds a conforming native block and its registry `cmpctblock` at
    /// `version`, proving the registry-encode / native-decode round trip.
    fn sample_cmpct(txs: Vec<Tx>, version: u64, nonce: u64) -> (Block, CmpctBlock) {
        let native = conforming_block(txs);
        let cmpct = compact_of(&native, version, nonce);
        (native, cmpct)
    }

    /// Builds a `cmpctblock` over `native` with the coinbase prefilled at
    /// index zero and caller-supplied short IDs for the remaining slots.
    fn cmpct_with_slots(native: &Block, nonce: u64, short_ids: Vec<ShortId>) -> CmpctBlock {
        CmpctBlock {
            compact_block: HeaderAndShortIds {
                header: registry_block(native).header,
                nonce,
                short_ids,
                prefilled_txs: vec![PrefilledTransaction {
                    idx: 0,
                    tx: registry_tx(&native.txs[0]),
                }],
            },
        }
    }

    /// The wtxid short ID of `tx` under `native`'s header and `nonce`.
    fn wtxid_short_id(native: &Block, nonce: u64, tx: &Tx) -> ShortId {
        let keys = ShortId::calculate_siphash_keys(&registry_block(native).header, nonce);
        ShortId::with_siphash_keys(tx.wtxid().as_bytes(), keys)
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

    /// Two missing transactions become one ordered `getblocktxn`
    /// request for both absolute indexes, and the `blocktxn`
    /// completes the block.
    #[test]
    fn missing_txs_request_ordered_getblocktxn_and_complete_on_blocktxn() {
        let (native, cmpct) = sample_cmpct(vec![test_tx(1), test_tx(2), test_tx(3)], 2, 0x9a);
        let hints = SetHints {
            txs: vec![native.txs[0].clone()],
        };
        let mut reconstruction = Reconstruction::new();

        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
        let Outcome::RequestMissing(request) = outcome else {
            panic!("expected getblocktxn request, got {outcome:?}");
        };
        assert_eq!(request.txs_request.indexes, vec![1, 2]);

        let txn = BlockTxn {
            transactions: BlockTransactions {
                block_hash: request.txs_request.block_hash,
                transactions: vec![registry_tx(&test_tx(2)), registry_tx(&test_tx(3))],
            },
        };
        let outcome = reconstruction.receive_blocktxn(&txn, now());
        let Outcome::Complete(block) = outcome else {
            panic!("expected complete reconstruction, got {outcome:?}");
        };
        assert_eq!(block.txs, native.txs);
    }

    /// A `blocktxn` whose size does not match the outstanding request falls
    /// back to the full block instead of guessing. A late retry for the same
    /// block after fallback is ignored.
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

        let late = BlockTxn {
            transactions: BlockTransactions {
                block_hash: request.txs_request.block_hash,
                transactions: vec![],
            },
        };
        assert!(matches!(
            reconstruction.receive_blocktxn(&late, now()),
            Outcome::Idle
        ));
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
    ///
    /// CONTRACT: docs/policies/p2p-compatibility.md#5-message-surface (bounded
    /// missing list gates the getblocktxn round trip).
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

    // ---- Compact conformance fixtures and tests ----

    /// Rebuilds the precomputed colliding pair: two transactions whose
    /// distinct wtxids collide on one BIP152 short ID under `native`'s
    /// header and `nonce` — the fixture behind the per-slot collision path,
    /// which a hash collision makes unreachable by construction. The varying
    /// bytes sit in a trailing `OP_RETURN` payload; distinct outpoints separate
    /// the two inputs so the pair can coexist in one mempool. Setup asserts
    /// both hashes really do produce the same short ID: a fixture that
    /// silently stopped colliding would make the collision path unreachable
    /// and the test vacuous.
    fn colliding_hint_pair(native: &Block, nonce: u64) -> (Tx, Tx, ShortId) {
        let keys = ShortId::calculate_siphash_keys(&registry_block(native).header, nonce);
        let (first_payload, second_payload) = COLLIDING_PAYLOADS;
        let first_bytes = colliding_tx_bytes(0x11, first_payload);
        let second_bytes = colliding_tx_bytes(0x22, second_payload);
        let short_id = |bytes: &[u8]| {
            ShortId::with_siphash_keys(
                &bitcoin::hashes::sha256d::Hash::hash(bytes).to_byte_array(),
                keys,
            )
        };
        let sid = short_id(&first_bytes);
        assert_eq!(
            sid,
            short_id(&second_bytes),
            "precomputed fixture must actually collide"
        );
        let first = Tx::consensus_decode(&first_bytes)
            .unwrap_or_else(|error| panic!("fixture decodes: {error}"));
        let second = Tx::consensus_decode(&second_bytes)
            .unwrap_or_else(|error| panic!("fixture decodes: {error}"));
        (first, second, sid)
    }

    /// Two mempool identities colliding on one short ID retire only their
    /// own slot and request exactly that slot: the unrelated hinted slot
    /// stays filled, a later candidate for the collided slot does not refill
    /// it, and the correct `blocktxn` completes the block without a
    /// full-block fallback (Core 31.1 `blockencodings.cpp:116-166`).
    #[test]
    fn colliding_hint_requests_only_its_slot() {
        let native = conforming_block(vec![test_tx(1), test_tx(2), test_tx(3)]);
        let (first, second, collided) = colliding_hint_pair(&native, 0x515);
        let unrelated = wtxid_short_id(&native, 0x515, &native.txs[2]);
        // The last entry repeats `first`: after the collision retires the
        // slot, a later candidate for it must not refill it.
        let hints = SetHints {
            txs: vec![first.clone(), second, native.txs[2].clone(), first],
        };
        let mut reconstruction = Reconstruction::new();
        let cmpct = cmpct_with_slots(&native, 0x515, vec![collided, unrelated]);

        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());

        let Outcome::RequestMissing(request) = outcome else {
            panic!("expected a getblocktxn request for the collided slot, got {outcome:?}");
        };
        assert_eq!(request.txs_request.indexes, vec![1]);
        // Retained bytes: two short IDs, the prefilled coinbase, and the
        // unrelated hinted body; the collided candidate's body was returned
        // exactly once.
        assert_eq!(
            reconstruction.retained_bytes(),
            2 * 6 + native.txs[0].total_size() + native.txs[2].total_size()
        );

        let txn = BlockTxn {
            transactions: BlockTransactions {
                block_hash: request.txs_request.block_hash,
                transactions: vec![registry_tx(&native.txs[1])],
            },
        };
        let outcome = reconstruction.receive_blocktxn(&txn, now());
        let Outcome::Complete(block) = outcome else {
            panic!("expected the collided slot's blocktxn to complete, got {outcome:?}");
        };
        assert_eq!(block.txs, native.txs);
    }

    /// A `cmpctblock` declaring the same short ID twice is structurally
    /// malformed: the slot accounting cannot be trusted, so the message
    /// falls back immediately instead of reconstructing from a collapsed
    /// wanted map.
    #[test]
    fn duplicate_declared_short_ids_fall_back() {
        let native = conforming_block(vec![test_tx(1), test_tx(2), test_tx(3)]);
        let duplicated = wtxid_short_id(&native, 0x71, &native.txs[1]);
        let hints = SetHints {
            txs: native.txs.clone(),
        };
        let mut reconstruction = Reconstruction::new();
        let cmpct = cmpct_with_slots(&native, 0x71, vec![duplicated, duplicated]);

        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());

        assert!(
            matches!(outcome, Outcome::Fallback(_)),
            "duplicate declared short IDs must fall back, got {outcome:?}"
        );
    }

    /// Hints that notice a body lookup made while the identity walk is still
    /// running: [`SetHints`] behind a walk flag. The mempool holds its pool
    /// read lock across the walk callback and a body lookup takes that lock
    /// again, so a nested lookup deadlocks the moment a writer queues behind
    /// the reader.
    struct WalkGuardedHints {
        inner: SetHints,
        walking: AtomicBool,
        nested: AtomicUsize,
    }

    impl WalkGuardedHints {
        /// Counts one body lookup made during the walk.
        fn note_lookup(&self) {
            if !self.walking.load(Ordering::SeqCst) {
                return;
            }
            self.nested.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl CompactBlockHints for WalkGuardedHints {
        fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
            self.walking.store(true, Ordering::SeqCst);
            self.inner.for_each_identity(f);
            self.walking.store(false, Ordering::SeqCst);
        }

        fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
            self.note_lookup();
            self.inner.get_tx_by_txid(txid)
        }

        fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
            self.note_lookup();
            self.inner.get_tx_by_wtxid(wtxid)
        }
    }

    /// A fully hinted reconstruction fetches every body after the identity
    /// walk returns, never during it.
    #[test]
    fn hint_bodies_are_fetched_outside_the_identity_walk() {
        let (native, cmpct) = sample_cmpct(vec![test_tx(1), test_tx(2), test_tx(3)], 2, 0x77);
        let hints = WalkGuardedHints {
            inner: SetHints { txs: native.txs },
            walking: AtomicBool::new(false),
            nested: AtomicUsize::new(0),
        };
        let mut reconstruction = Reconstruction::new();

        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());

        assert!(
            matches!(outcome, Outcome::Complete(_)),
            "the reconstruction must still complete, got {outcome:?}"
        );
        assert_eq!(
            hints.nested.load(Ordering::SeqCst),
            0,
            "a body lookup inside the identity walk re-enters the pool read lock"
        );
    }

    /// A fully hinted reconstruction whose transaction set does not hash to
    /// the header's merkle root is never delivered as complete — the cheap
    /// reconstruction verdict runs before the block enters the sink.
    #[test]
    fn compact_completion_merkle_mismatch_falls_back() {
        let txs = vec![test_tx(1), test_tx(2)];
        let header = Header {
            version: 1,
            prev_blockhash: BlockHash::from(Hash256::from_le_bytes(&[0xab; 32])),
            merkle_root: Hash256::from_le_bytes(&[0; 32]),
            time: 7,
            bits: bitcoin_rs_primitives::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 9,
        };
        let bridged =
            bitcoin::consensus::encode::deserialize::<RegistryBlock>(&consensus_bytes(&Block {
                header,
                txs: txs.clone(),
            }))
            .unwrap_or_else(|error| panic!("sample block must decode: {error}"));
        let compact = HeaderAndShortIds::from_block(&bridged, 0x77, 2, &[])
            .unwrap_or_else(|error| panic!("sample compact block must build: {error}"));
        let hints = SetHints { txs };
        let mut reconstruction = Reconstruction::new();

        let outcome = reconstruction.receive_cmpctblock(
            &CmpctBlock {
                compact_block: compact,
            },
            COMPACT_BLOCK_VERSION,
            &hints,
            now(),
        );

        assert!(
            matches!(outcome, Outcome::Fallback(_)),
            "a merkle mismatch must never complete, got {outcome:?}"
        );
    }

    /// A completion whose transaction list ends in a duplicated final
    /// transaction hashes to the header's merkle root (CVE-2012-2459: the
    /// duplicate leaf pairs with itself exactly as the padded single leaf
    /// does), so the root check alone would deliver the mutated body; the
    /// mutation-aware completion rejects it with the same-peer full-block
    /// fallback (Core 31.1 `blockencodings.cpp:207-219`).
    #[test]
    fn duplicate_final_transaction_completion_falls_back() {
        let native = conforming_block(vec![test_tx(1), test_tx(2), test_tx(3)]);
        // Fixture validity: the mutated four-transaction set really does
        // commit to the honest header's root — the collision this test
        // exists to reject.
        let mut mutated = native.clone();
        mutated.txs.push(native.txs[2].clone());
        assert_eq!(
            registry_block(&mutated).compute_merkle_root(),
            registry_block(&native).compute_merkle_root(),
            "fixture must reproduce the duplicate-final-transaction collision"
        );

        let compact = HeaderAndShortIds {
            header: registry_block(&native).header,
            nonce: 0x77,
            // The two honest non-coinbase transactions as hinted short-ID
            // slots; the duplicated final transaction arrives as the
            // prefill at slot 3.
            short_ids: vec![
                wtxid_short_id(&native, 0x77, &native.txs[1]),
                wtxid_short_id(&native, 0x77, &native.txs[2]),
            ],
            prefilled_txs: vec![
                PrefilledTransaction {
                    idx: 0,
                    tx: registry_tx(&native.txs[0]),
                },
                PrefilledTransaction {
                    idx: 2,
                    tx: registry_tx(&native.txs[2]),
                },
            ],
        };
        let hints = SetHints {
            txs: vec![native.txs[1].clone(), native.txs[2].clone()],
        };
        let mut reconstruction = Reconstruction::new();

        let outcome = reconstruction.receive_cmpctblock(
            &CmpctBlock {
                compact_block: compact,
            },
            COMPACT_BLOCK_VERSION,
            &hints,
            now(),
        );

        assert!(
            matches!(outcome, Outcome::Fallback(_)),
            "a mutated completion must fall back, got {outcome:?}"
        );
    }

    /// A `blocktxn` response that fills the pending slots with the wrong
    /// bodies produces a transaction set that does not hash to the header's
    /// merkle root; the reconstruction falls back, the pending entry stays
    /// closed for late responses, and no wrong block is delivered.
    #[test]
    fn blocktxn_merkle_mismatch_falls_back() {
        let (native, cmpct) = sample_cmpct(vec![test_tx(1), test_tx(2)], 2, 0x78);
        let hints = SetHints {
            txs: vec![native.txs[0].clone()],
        };
        let mut reconstruction = Reconstruction::new();

        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
        let Outcome::RequestMissing(request) = outcome else {
            panic!("expected a getblocktxn request, got {outcome:?}");
        };

        let wrong_body = BlockTxn {
            transactions: BlockTransactions {
                block_hash: request.txs_request.block_hash,
                transactions: vec![registry_tx(&test_tx(9))],
            },
        };
        let outcome = reconstruction.receive_blocktxn(&wrong_body, now());
        assert!(
            matches!(outcome, Outcome::Fallback(_)),
            "a wrong-body completion must fall back, got {outcome:?}"
        );

        let late = BlockTxn {
            transactions: BlockTransactions {
                block_hash: request.txs_request.block_hash,
                transactions: vec![registry_tx(&test_tx(2))],
            },
        };
        assert!(matches!(
            reconstruction.receive_blocktxn(&late, now()),
            Outcome::Idle
        ));
    }

    /// Serializes the precomputed colliding fixture transaction; only the
    /// payload bytes separate the two inputs.
    fn colliding_tx_bytes(branch: u8, payload: u32) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&2_u32.to_le_bytes()); // version
        bytes.push(1); // one input
        let mut previous = [branch; 32];
        previous[0] = 0;
        bytes.extend_from_slice(&previous); // outpoint txid
        bytes.extend_from_slice(&0_u32.to_le_bytes()); // vout
        bytes.push(0); // empty script_sig
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // sequence
        bytes.push(1); // one output
        bytes.extend_from_slice(&1_000_u64.to_le_bytes()); // value
        bytes.push(6); // script len
        bytes.extend_from_slice(&[0x6a, 0x04]); // OP_RETURN, push 4
        bytes.extend_from_slice(&payload.to_le_bytes()); // varying payload
        bytes.extend_from_slice(&0_u32.to_le_bytes()); // lock time
        bytes
    }
}
