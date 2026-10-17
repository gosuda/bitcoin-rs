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
//! ([`compact_blocks::COMPACT_BLOCK_VERSION`], v2 = wtxid identity, witness-bearing
//! prefills). Conversely, we serve peers at the version they recorded with
//! us (`CompactBlockNegotiation::servable_version`, used by the chain
//! query). The two directions are independent; decoding incoming compact
//! blocks never reads their preference.
//!
//! State is released by completion, by the deadline, by a replacement, and
//! by dropping the owner at disconnect or session cancel — a chain change
//! cannot strand memory beyond the deadline.

use crate::inv::{native_block_hash, wire_block_hash};

use hashbrown::HashMap;
use std::time::{Duration, Instant};

use bitcoin::bip152::{BlockTransactionsRequest, HeaderAndShortIds, ShortId};
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn};
use bitcoin_rs_primitives::deserialize;
use bitcoin_rs_primitives::{Block, BlockHash, Header, Tx, Txid, Wtxid};

/// Compact-block protocol version this node advertises: the identity
/// profile peers use for the compact blocks they send us. Re-exported from
/// `peer` as the authority.
pub use crate::peer::COMPACT_BLOCK_VERSION;

/// Concurrent pending reconstructions per peer connection.
const MAX_PENDING_RECONSTRUCTIONS: usize = 4;
/// Approximate retained bytes across all pending entries before new
/// `cmpctblock` messages are refused in favor of the full-block fallback.
const MAX_PENDING_RETAINED_BYTES: usize = 8 * 1_024 * 1_024;
/// A pending entry older than this is dropped; a chain change cannot strand
/// memory longer than one deadline.
const PENDING_DEADLINE: Duration = Duration::from_mins(1);
/// Above this many missing transactions the `getblocktxn` round trip is
/// skipped: a full-block `getdata` is then the cheaper request.
const MAX_REQUESTED_MISSING: usize = 128;
/// Sanity bound on the transaction count a `cmpctblock` may declare.
const MAX_BLOCK_TX_COUNT: usize = 100_000;
/// Recently admitted hashes remembered per connection to avoid rescanning
/// the mempool for repeated compact announcements of one block. Sized to the
/// most block downloads one connection can own, so a peer cannot evict a
/// still-owned hash and replay it.
const MAX_RECENT_COMPACT_BLOCKS: usize = crate::download_window::PEER_INFLIGHT_BUDGET;

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
    /// At most one reconstruction attempt per hash within its deadline.
    recent: Vec<(BlockHash, Instant)>,
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
            recent: Vec::new(),
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
        // Re-sending one in-flight or already completed block must never
        // trigger another mempool-wide hint walk (or another fallback).
        if self.recent.iter().any(|(seen, _)| *seen == hash) {
            return Outcome::Idle;
        }
        if self.recent.len() == MAX_RECENT_COMPACT_BLOCKS {
            self.recent.remove(0);
        }
        self.recent.push((hash, now));
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

        // Enforce the cheap connection-level bounds before walking the
        // mempool. Keep the post-fill check as matched bodies add bytes.
        if self.pending.len() >= MAX_PENDING_RECONSTRUCTIONS
            || self.retained_bytes().saturating_add(retained_bytes) > MAX_PENDING_RETAINED_BYTES
        {
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
            return match complete_block(header, filled) {
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
        let Ok(block) = complete_block(entry.header, filled) else {
            // The taken bodies are dropped, so no byte stays retained: without
            // this reset the dead entry keeps its charge until the deadline
            // and later compact reconstructions can be refused for bytes that
            // no longer exist.
            entry.retained_bytes = 0;
            entry.fallback = true;
            return Outcome::Fallback(hash);
        };
        self.pending.remove(&hash);
        Outcome::Complete(block)
    }

    /// Drops pending entries whose deadline passed.
    pub fn prune(&mut self, now: Instant) {
        self.pending.retain(|_, entry| now < entry.deadline);
        self.recent
            .retain(|(_, received)| now.saturating_duration_since(*received) < PENDING_DEADLINE);
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
/// POST: return a block only when every slot holds a body, the
/// transaction-ID merkle root of the assembled body equals
/// `header.merkle_root`, the transaction-ID tree is not mutated, and the body
/// is not a coinbase-less body with a 64-byte transaction; otherwise return
/// `Err`. The slot count needs no re-check here: the vector
/// is sized from the declared short IDs and prefills, `place_prefills`
/// rejects a prefill outside the declared slots, and `fill_from_hints`
/// rejects a short-ID count that does not match the unfilled slots.
/// INVARIANT: no unverified compact reconstruction reaches
/// [`Outcome::Complete`]. The root check alone cannot detect the
/// duplicate-final-transaction collision (CVE-2012-2459): `[a, b, c]` and
/// `[a, b, c, c]` hash to the same root, so the reduction also rejects a
/// mutated tree and the caller answers with the same-peer full-block
/// fallback (Core 31.1 `READ_STATUS_FAILED` before delivery,
/// `blockencodings.cpp:207-219`). A 64-byte transaction in a body without a
/// coinbase can pose as an inner tree node and reach the header's root with
/// fabricated leaves (CVE-2017-12842), so that body takes the same fallback
/// (Core `IsBlockMutated`, `validation.cpp:4035-4061`).
fn complete_block(header: Header, filled: Vec<Option<Tx>>) -> Result<Block, ()> {
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
    Ok(block)
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

/// Registry block header → primitives header.
pub(crate) fn native_header(reg: &bitcoin::blockdata::block::Header) -> Option<Header> {
    deserialize(&bitcoin::consensus::encode::serialize(reg)).ok()
}

fn native_tx(reg: &bitcoin::Transaction) -> Option<Tx> {
    deserialize(&bitcoin::consensus::encode::serialize(reg)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::bip152::{BlockTransactions, PrefilledTransaction};
    use bitcoin::blockdata::block::Block as RegistryBlock;
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock};
    use bitcoin_rs_primitives::{
        Amount, Hash256, LockTime, OutPoint, Sequence, TxIn, TxOut, Witness, consensus_bytes,
        unix_time_secs,
    };
    use std::sync::Arc;
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

    struct CountingHints {
        inner: SetHints,
        scans: AtomicUsize,
    }

    impl CompactBlockHints for CountingHints {
        fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
            self.scans.fetch_add(1, Ordering::Relaxed);
            self.inner.for_each_identity(f);
        }

        fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
            self.inner.get_tx_by_txid(txid)
        }

        fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
            self.inner.get_tx_by_wtxid(wtxid)
        }
    }

    #[test]
    fn repeated_compact_block_does_not_repeat_mempool_scan() {
        let (_, cmpct) = sample_cmpct(vec![test_tx(1), test_tx(2)], 2, 0x51);
        let hints = CountingHints {
            inner: SetHints { txs: Vec::new() },
            scans: AtomicUsize::new(0),
        };
        let mut reconstruction = Reconstruction::new();
        let received_at = now();

        assert!(matches!(
            reconstruction.receive_cmpctblock(&cmpct, 2, &hints, received_at),
            Outcome::RequestMissing(_)
        ));
        assert!(matches!(
            reconstruction.receive_cmpctblock(&cmpct, 2, &hints, received_at),
            Outcome::Idle
        ));
        assert_eq!(hints.scans.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn saturated_pending_state_rejects_before_mempool_scan() {
        let hints = CountingHints {
            inner: SetHints { txs: Vec::new() },
            scans: AtomicUsize::new(0),
        };
        let mut reconstruction = Reconstruction::new();
        let received_at = now();

        for seed in 1_u8..=4 {
            let (_, cmpct) =
                sample_cmpct(vec![test_tx(seed), test_tx(seed + 10)], 2, u64::from(seed));
            assert!(matches!(
                reconstruction.receive_cmpctblock(&cmpct, 2, &hints, received_at),
                Outcome::RequestMissing(_)
            ));
        }
        let (_, extra) = sample_cmpct(vec![test_tx(5), test_tx(15)], 2, 5);
        assert!(matches!(
            reconstruction.receive_cmpctblock(&extra, 2, &hints, received_at),
            Outcome::Fallback(_)
        ));
        assert_eq!(
            hints.scans.load(Ordering::Relaxed),
            MAX_PENDING_RECONSTRUCTIONS,
            "no hint scan may run after the pending cap is reached"
        );
    }

    /// A hash stays remembered across more distinct blocks than one
    /// connection's 64 oldest, so a replay inside the deadline never rescans;
    /// past the deadline the hash is forgotten and may scan again.
    #[test]
    fn replay_dedup_spans_more_than_sixty_four_blocks_until_the_deadline() {
        let hints = CountingHints {
            inner: SetHints { txs: Vec::new() },
            scans: AtomicUsize::new(0),
        };
        let mut reconstruction = Reconstruction::new();
        let received_at = now();
        let (_, first) = sample_cmpct(vec![test_tx(0)], 2, 0);
        assert!(matches!(
            reconstruction.receive_cmpctblock(&first, 2, &hints, received_at),
            Outcome::Complete(_)
        ));
        for seed in 1_u8..=100 {
            let (_, cmpct) = sample_cmpct(vec![test_tx(seed)], 2, u64::from(seed));
            reconstruction.receive_cmpctblock(&cmpct, 2, &hints, received_at);
        }
        let scanned = hints.scans.load(Ordering::Relaxed);
        assert_eq!(scanned, 101);

        assert!(matches!(
            reconstruction.receive_cmpctblock(&first, 2, &hints, received_at),
            Outcome::Idle
        ));
        assert_eq!(hints.scans.load(Ordering::Relaxed), scanned);

        let expired = received_at + PENDING_DEADLINE + core::time::Duration::from_secs(1);
        reconstruction.receive_cmpctblock(&first, 2, &hints, expired);
        assert_eq!(hints.scans.load(Ordering::Relaxed), scanned + 1);
    }

    /// A non-coinbase transaction whose witness-stripped serialization is the
    /// 64 bytes of two Merkle child hashes: `test_tx` plus a 3-byte output
    /// script.
    fn sixty_four_byte_tx(byte: u8) -> Tx {
        let mut tx = test_tx(byte);
        tx.outputs[0].script_pubkey = vec![byte; 3].into();
        assert_eq!(tx.base_size(), 64, "fixture must be a Merkle node's size");
        tx
    }

    /// A coinbase of the same shape as `test_tx`.
    fn test_coinbase(byte: u8) -> Tx {
        let mut tx = test_tx(byte);
        tx.inputs[0].previous_output = OutPoint::null();
        assert!(tx.is_coinbase(), "fixture must be a coinbase");
        tx
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
    /// transaction-ID merkle root, the property the reconstruction verifier
    /// enforces.
    fn conforming_block(txs: Vec<Tx>) -> Block {
        let mut native = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::from(Hash256::from_le_bytes(&[0xab; 32])),
                merkle_root: Hash256::default(),
                time: 7,
                bits: bitcoin_rs_primitives::CompactTarget::from_consensus(
                    bitcoin_rs_chain::regtest_fixture::REGTEST_BITS,
                ),
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

    /// Rebuilds the precomputed colliding pair: two transactions whose distinct
    /// wtxids collide on one BIP152 short ID under `native`'s header and
    /// `nonce` — the fixture behind the per-slot collision path, which a hash
    /// collision makes unreachable by construction.
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
        let first = deserialize::<Tx>(&first_bytes)
            .unwrap_or_else(|error| panic!("fixture decodes: {error}"));
        let second = deserialize::<Tx>(&second_bytes)
            .unwrap_or_else(|error| panic!("fixture decodes: {error}"));
        (first, second, sid)
    }

    #[test]
    fn colliding_hint_requests_only_its_slot() {
        let native = conforming_block(vec![test_tx(1), test_tx(2), test_tx(3)]);
        let (first, second, collided) = colliding_hint_pair(&native, 0x515);
        let unrelated = wtxid_short_id(&native, 0x515, &native.txs[2]);
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
    /// running: [`SetHints`] behind a walk flag.
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

    #[test]
    fn duplicate_final_transaction_completion_falls_back() {
        let native = conforming_block(vec![test_tx(1), test_tx(2), test_tx(3)]);
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

    #[test]
    fn sixty_four_byte_transaction_without_coinbase_completion_falls_back() {
        let (native, cmpct) = sample_cmpct(vec![test_tx(1), sixty_four_byte_tx(2)], 2, 0x7a);
        assert!(
            !native.txs[0].is_coinbase(),
            "fixture body must have no coinbase"
        );
        let hints = SetHints { txs: native.txs };
        let mut reconstruction = Reconstruction::new();

        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());

        assert!(
            matches!(outcome, Outcome::Fallback(_)),
            "a coinbase-less body with a 64-byte transaction must fall back, got {outcome:?}"
        );
    }

    #[test]
    fn sixty_four_byte_transaction_completed_by_blocktxn_falls_back() {
        let (native, cmpct) = sample_cmpct(vec![test_tx(1), sixty_four_byte_tx(2)], 2, 0x7b);
        let hints = SetHints {
            txs: vec![native.txs[0].clone()],
        };
        let mut reconstruction = Reconstruction::new();

        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
        let Outcome::RequestMissing(request) = outcome else {
            panic!("expected a getblocktxn request, got {outcome:?}");
        };
        assert_eq!(request.txs_request.indexes, vec![1]);

        let txn = BlockTxn {
            transactions: BlockTransactions {
                block_hash: request.txs_request.block_hash,
                transactions: vec![registry_tx(&native.txs[1])],
            },
        };
        let outcome = reconstruction.receive_blocktxn(&txn, now());
        assert!(
            matches!(outcome, Outcome::Fallback(_)),
            "the blocktxn completion must take the same fallback, got {outcome:?}"
        );
    }

    #[test]
    fn sixty_four_byte_transaction_beside_a_coinbase_completes() {
        let (native, cmpct) = sample_cmpct(vec![test_coinbase(1), sixty_four_byte_tx(2)], 2, 0x7c);
        let hints = SetHints {
            txs: native.txs.clone(),
        };
        let mut reconstruction = Reconstruction::new();

        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());

        let Outcome::Complete(block) = outcome else {
            panic!("a body with a coinbase is not a mutation, got {outcome:?}");
        };
        assert_eq!(block.txs, native.txs);
    }

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

    #[test]
    fn failed_verification_releases_retained_bytes() {
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
        assert!(
            reconstruction.retained_bytes() > 0,
            "the pending entry must charge its bodies"
        );

        let wrong_body = BlockTxn {
            transactions: BlockTransactions {
                block_hash: request.txs_request.block_hash,
                transactions: vec![registry_tx(&test_tx(9))],
            },
        };
        assert!(matches!(
            reconstruction.receive_blocktxn(&wrong_body, now()),
            Outcome::Fallback(_)
        ));
        assert_eq!(
            reconstruction.retained_bytes(),
            0,
            "a failed verification keeps no body behind"
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

    #[test]
    fn failed_blocktxn_completion_releases_retained_byte_budget() {
        let mut first_prefill = test_tx(1);
        first_prefill.outputs[0].script_pubkey = vec![1; 4_300_000].into();
        let (first_block, first_cmpct) =
            sample_cmpct(vec![first_prefill, test_tx(2)], COMPACT_BLOCK_VERSION, 0x78);
        let hints = SetHints { txs: vec![] };
        let mut reconstruction = Reconstruction::new();

        let outcome =
            reconstruction.receive_cmpctblock(&first_cmpct, COMPACT_BLOCK_VERSION, &hints, now());
        let Outcome::RequestMissing(request) = outcome else {
            panic!("expected a getblocktxn request, got {outcome:?}");
        };
        let wrong_body = BlockTxn {
            transactions: BlockTransactions {
                block_hash: request.txs_request.block_hash,
                transactions: vec![registry_tx(&test_tx(9))],
            },
        };
        assert!(matches!(
            reconstruction.receive_blocktxn(&wrong_body, now()),
            Outcome::Fallback(_)
        ));
        drop(first_block);
        drop(first_cmpct);

        let mut second_prefill = test_tx(3);
        second_prefill.outputs[0].script_pubkey = vec![3; 4_300_000].into();
        let (_second_block, second_cmpct) = sample_cmpct(
            vec![second_prefill, test_tx(4)],
            COMPACT_BLOCK_VERSION,
            0x79,
        );
        let outcome =
            reconstruction.receive_cmpctblock(&second_cmpct, COMPACT_BLOCK_VERSION, &hints, now());
        assert!(
            matches!(outcome, Outcome::RequestMissing(_)),
            "a failed completion must release retained-byte capacity, got {outcome:?}"
        );
    }

    struct MissingCoins;
    impl bitcoin_rs_mempool::AdmissionChain for MissingCoins {
        fn snapshot(&self, _: &Tx) -> Option<bitcoin_rs_mempool::ChainAdmissionSnapshot> {
            Some(bitcoin_rs_mempool::ChainAdmissionSnapshot {
                prevouts: Vec::new(),
                height: 0,
                locktime_cutoff: 0,
                prevout_meta: hashbrown::HashMap::new(),
                csv_active: false,
                ..bitcoin_rs_mempool::ChainAdmissionSnapshot::default()
            })
        }
    }

    fn test_gateway() -> bitcoin_rs_mempool::MempoolGateway {
        bitcoin_rs_mempool::MempoolGateway::new(
            Arc::new(parking_lot::RwLock::new(bitcoin_rs_mempool::Mempool::new(
                bitcoin_rs_mempool::MempoolLimits::default(),
            ))),
            None,
            bitcoin_rs_consensus::ValidationEngine::Native,
            None,
        )
    }

    fn peer_source(connection_id: u64) -> bitcoin_rs_mempool::PeerToken {
        bitcoin_rs_mempool::PeerToken {
            addr: std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
            connection_id,
        }
    }

    /// Holdable peer spend: `OP_RETURN` output, one-push witness, missing
    /// outpoint (the `dispatch.rs` orphan shape; bare `test_tx` is not standard).
    fn orphan_tx(prev_byte: u8, witness_byte: u8) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from(Hash256::from_le_bytes(&[prev_byte; 32])),
                    vout: 0,
                },
                script_sig: Vec::<u8>::new().into(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![vec![witness_byte]]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x6a, 4, 1, 2, 3, 4].into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    /// 10_000-in/9_000-out parent/child values (gateway `parent_and_child`).
    fn p2p_parent() -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0xD0; 32])), 0),
                script_sig: Vec::<u8>::new().into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: vec![0x51].into(),
            }],
        }
    }

    fn p2p_child(parent_txid: Txid, marker: u8) -> Tx {
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&[marker; 20]);
        script.extend_from_slice(&[0x88, 0xac]);
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: Vec::<u8>::new().into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: script.into(),
            }],
        }
    }

    #[track_caller]
    fn hold_orphan(gateway: &bitcoin_rs_mempool::MempoolGateway, tx: &Arc<Tx>) {
        let outcome = gateway.submit_transaction(
            Arc::clone(tx),
            bitcoin_rs_mempool::AdmissionOrigin::Peer(peer_source(1)),
            None,
            0,
            &MissingCoins,
        );
        assert!(
            matches!(outcome, Ok(bitcoin_rs_mempool::SubmitOutcome::Held { .. })),
            "a peer tx with missing parents must be orphan-held, got {outcome:?}"
        );
    }

    /// Ring-only short ID completes; reconstruction never admits.
    #[test]
    fn extra_ring_orphan_only_hint_completes_reconstruction() {
        let gateway = test_gateway();
        let orphan = Arc::new(orphan_tx(0xA1, 0x01));
        hold_orphan(&gateway, &orphan);
        assert!(
            !gateway.read().contains_txid(&orphan.txid()),
            "an orphan-held tx must not be pool-resident"
        );
        assert_eq!(gateway.get_tx(orphan.txid()), None);

        let native = conforming_block(vec![test_tx(0xC0), (*orphan).clone()]);
        let cmpct = compact_of(&native, COMPACT_BLOCK_VERSION, 0x60);
        let mut reconstruction = Reconstruction::new();
        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &gateway, now());
        let Outcome::Complete(block) = outcome else {
            panic!("a ring-only hint must complete the block, got {outcome:?}");
        };
        assert_eq!(block.block_hash(), native.block_hash());
        assert_eq!(block.txs, native.txs);
        assert!(
            !gateway.read().contains_txid(&orphan.txid()),
            "reconstruction must never admit a hinted body"
        );
        assert_eq!(gateway.get_tx(orphan.txid()), None);
    }

    /// Pool+ring duplicate identity is one claim, not a collision.
    #[test]
    fn pool_and_ring_share_identity_without_false_collision() {
        let gateway = test_gateway();
        let parent = p2p_parent();
        let parent_txid = parent.txid();
        let child = Arc::new(p2p_child(parent_txid, 0x07));
        hold_orphan(&gateway, &child);
        let fresh_time = unix_time_secs();
        gateway
            .insert_entry(
                bitcoin_rs_mempool::AdmissionOrigin::Rpc,
                bitcoin_rs_mempool::MempoolEntry::new(
                    Arc::new(parent),
                    100,
                    1_000,
                    fresh_time,
                    1,
                    0,
                ),
            )
            .unwrap_or_else(|error| panic!("parent insertion failed: {error}"));
        let retried = gateway.retry_orphans(&MissingCoins, fresh_time);
        assert!(
            retried.iter().any(|retry| matches!(
                retry.result,
                Ok(bitcoin_rs_mempool::SubmitOutcome::Committed(_))
            )),
            "the orphan child must admit once its parent commits"
        );
        assert!(gateway.read().contains_txid(&child.txid()));

        let native = conforming_block(vec![test_tx(0xC1), (*child).clone()]);
        let cmpct = compact_of(&native, COMPACT_BLOCK_VERSION, 0x61);
        let mut reconstruction = Reconstruction::new();
        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &gateway, now());
        let Outcome::Complete(block) = outcome else {
            panic!("a pool+ring duplicate identity must complete, got {outcome:?}");
        };
        assert_eq!(block.txs, native.txs);
    }

    /// v2 resolves each witness variant from one shared gateway.
    #[test]
    fn v2_witness_variants_stay_distinct() {
        let gateway = test_gateway();
        let first = Arc::new(orphan_tx(0xA2, 0x01));
        let second = Arc::new(orphan_tx(0xA2, 0x02));
        assert_eq!(first.txid(), second.txid(), "variants must share a txid");
        assert_ne!(
            first.wtxid(),
            second.wtxid(),
            "variants must differ in wtxid"
        );
        hold_orphan(&gateway, &first);
        hold_orphan(&gateway, &second);

        let native_first = conforming_block(vec![test_tx(0xC2), (*first).clone()]);
        let cmpct_first = compact_of(&native_first, COMPACT_BLOCK_VERSION, 0x62);
        let mut reconstruction = Reconstruction::new();
        let outcome =
            reconstruction.receive_cmpctblock(&cmpct_first, COMPACT_BLOCK_VERSION, &gateway, now());
        let Outcome::Complete(block) = outcome else {
            panic!("v2 must resolve the first variant, got {outcome:?}");
        };
        assert_eq!(block.txs, native_first.txs);

        let native_second = conforming_block(vec![test_tx(0xC2), (*second).clone()]);
        let cmpct_second = compact_of(&native_second, COMPACT_BLOCK_VERSION, 0x66);
        let mut reconstruction = Reconstruction::new();
        let outcome = reconstruction.receive_cmpctblock(
            &cmpct_second,
            COMPACT_BLOCK_VERSION,
            &gateway,
            now(),
        );
        let Outcome::Complete(block) = outcome else {
            panic!("v2 must resolve the second variant, got {outcome:?}");
        };
        assert_eq!(block.txs, native_second.txs);
    }

    /// v1 retires the ambiguous txid slot; v2 resolves it.
    #[test]
    fn v1_shared_txid_ambiguity_requests_missing() {
        let gateway = test_gateway();
        let first = Arc::new(orphan_tx(0xA3, 0x01));
        let second = Arc::new(orphan_tx(0xA3, 0x02));
        assert_eq!(first.txid(), second.txid(), "variants must share a txid");
        assert_ne!(
            first.wtxid(),
            second.wtxid(),
            "variants must differ in wtxid"
        );
        hold_orphan(&gateway, &first);
        hold_orphan(&gateway, &second);

        let native = conforming_block(vec![test_tx(0xC3), (*first).clone()]);
        let cmpct_v1 = compact_of(&native, 1, 0x63);
        let mut reconstruction = Reconstruction::new();
        let outcome = reconstruction.receive_cmpctblock(&cmpct_v1, 1, &gateway, now());
        let Outcome::RequestMissing(request) = outcome else {
            panic!("v1 txid ambiguity must safely request the slot, got {outcome:?}");
        };
        assert_eq!(request.txs_request.indexes, vec![1]);
        assert_eq!(
            request.txs_request.block_hash,
            wire_block_hash(native.block_hash())
        );

        let cmpct_v2 = compact_of(&native, COMPACT_BLOCK_VERSION, 0x63);
        let mut reconstruction = Reconstruction::new();
        let outcome =
            reconstruction.receive_cmpctblock(&cmpct_v2, COMPACT_BLOCK_VERSION, &gateway, now());
        let Outcome::Complete(block) = outcome else {
            panic!("v2 must resolve the same variants, got {outcome:?}");
        };
        assert_eq!(block.txs, native.txs);
    }

    /// Forwards hint reads to the real gateway, then holds `evict` through
    /// the real submission path after the walk returns and before the body
    /// pass runs: scheduling control around the real store.
    struct EvictAfterWalk<'a> {
        hints: &'a dyn CompactBlockHints,
        gateway: &'a bitcoin_rs_mempool::MempoolGateway,
        evict: Vec<Tx>,
    }

    impl CompactBlockHints for EvictAfterWalk<'_> {
        fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
            self.hints.for_each_identity(f);
            for tx in &self.evict {
                hold_orphan(self.gateway, &Arc::new(tx.clone()));
            }
        }

        fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
            self.hints.get_tx_by_txid(txid)
        }

        fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
            self.hints.get_tx_by_wtxid(wtxid)
        }
    }

    /// The walk claims the victim, then the ring evicts it before the body
    /// fetch: the slot degrades to `getblocktxn`.
    #[test]
    fn eviction_between_walk_and_fetch_requests_missing() {
        let gateway = test_gateway();
        let victim = Arc::new(orphan_tx(0xB0, 0xB0));
        hold_orphan(&gateway, &victim);
        let native = conforming_block(vec![test_tx(0xC4), (*victim).clone()]);
        let cmpct = compact_of(&native, COMPACT_BLOCK_VERSION, 0x64);

        let mut baseline = Reconstruction::new();
        let outcome = baseline.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &gateway, now());
        let Outcome::Complete(block) = outcome else {
            panic!("the held victim must complete before eviction, got {outcome:?}");
        };
        assert_eq!(block.block_hash(), native.block_hash());
        assert_eq!(block.txs, native.txs);

        let evict: Vec<Tx> = (0..100_u8).map(|i| orphan_tx(0x10 + i, 0x20 + i)).collect();
        let racing = EvictAfterWalk {
            hints: &gateway,
            gateway: &gateway,
            evict,
        };
        let mut reconstruction = Reconstruction::new();
        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &racing, now());
        let Outcome::RequestMissing(request) = outcome else {
            panic!("a body evicted after the walk must be requested, got {outcome:?}");
        };
        assert_eq!(request.txs_request.indexes, vec![1]);
        assert_eq!(
            request.txs_request.block_hash,
            wire_block_hash(native.block_hash())
        );
    }

    /// Hints never rescue a merkle mismatch; the pool stays empty.
    #[test]
    fn gateway_hints_do_not_rescue_merkle_mismatch() {
        let gateway = test_gateway();
        let orphan = Arc::new(orphan_tx(0xA5, 0x05));
        hold_orphan(&gateway, &orphan);
        let txs = vec![test_tx(0xC5), (*orphan).clone()];
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
                txs,
            }))
            .unwrap_or_else(|error| panic!("sample block must decode: {error}"));
        let compact = HeaderAndShortIds::from_block(&bridged, 0x65, 2, &[])
            .unwrap_or_else(|error| panic!("sample compact block must build: {error}"));
        let mut reconstruction = Reconstruction::new();
        let outcome = reconstruction.receive_cmpctblock(
            &CmpctBlock {
                compact_block: compact,
            },
            COMPACT_BLOCK_VERSION,
            &gateway,
            now(),
        );
        assert!(
            matches!(outcome, Outcome::Fallback(_)),
            "ring hints must never rescue a merkle mismatch, got {outcome:?}"
        );
        assert!(gateway.read().is_empty(), "hints are read-only");
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
