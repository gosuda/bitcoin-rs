use super::*;

use crate::peer::COMPACT_BLOCK_VERSION;

use bitcoin::bip152::{BlockTransactions, PrefilledTransaction};
use bitcoin::blockdata::block::Block as RegistryBlock;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock};
use bitcoin_rs_consensus::primitives::{
    Amount, Hash256, LockTime, OutPoint, Sequence, TxIn, TxOut, Witness, consensus_bytes,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

const COLLIDING_PAYLOADS: (u32, u32) = (0x0055_7269, 0x0093_c777);

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
        let (_, cmpct) = sample_cmpct(vec![test_tx(seed), test_tx(seed + 10)], 2, u64::from(seed));
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

fn sixty_four_byte_tx(byte: u8) -> Tx {
    let mut tx = test_tx(byte);
    tx.outputs[0].script_pubkey = vec![byte; 3].into();
    assert_eq!(tx.base_size(), 64, "fixture must be a Merkle node's size");
    tx
}

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

fn registry_tx(tx: &Tx) -> bitcoin::Transaction {
    bitcoin::consensus::encode::deserialize(&consensus_bytes(tx))
        .unwrap_or_else(|error| panic!("test tx must bridge: {error}"))
}

fn registry_block(native: &Block) -> RegistryBlock {
    bitcoin::consensus::encode::deserialize(&consensus_bytes(native))
        .unwrap_or_else(|error| panic!("test block must bridge: {error}"))
}

fn conforming_block(txs: Vec<Tx>) -> Block {
    let mut native = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::from(Hash256::from_le_bytes(&[0xab; 32])),
            merkle_root: Hash256::default(),
            time: 7,
            bits: bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(0x207fffff),
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

fn compact_of(native: &Block, version: u64, nonce: u64) -> CmpctBlock {
    let version =
        u32::try_from(version).unwrap_or_else(|error| panic!("version fits u32: {error}"));
    let compact = HeaderAndShortIds::from_block(&registry_block(native), nonce, version, &[])
        .unwrap_or_else(|error| panic!("sample compact block must build: {error}"));
    CmpctBlock {
        compact_block: compact,
    }
}

fn sample_cmpct(txs: Vec<Tx>, version: u64, nonce: u64) -> (Block, CmpctBlock) {
    let native = conforming_block(txs);
    let cmpct = compact_of(&native, version, nonce);
    (native, cmpct)
}

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

    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());

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

    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
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

    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
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

    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
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
    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, sent_at);
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
    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
    assert!(matches!(outcome, Outcome::Fallback(_)));

    let (_, cmpct) = sample_cmpct((0_u8..129).map(test_tx).collect(), 2, 0x1234);
    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
    let Outcome::RequestMissing(request) = outcome else {
        panic!("expected a missing-list request at the bound, got {outcome:?}");
    };
    assert_eq!(request.txs_request.indexes.len(), MAX_REQUESTED_MISSING);
}

fn colliding_tx_bytes(branch: u8, payload: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    bytes.push(1);
    let mut previous = [branch; 32];
    previous[0] = 0;
    bytes.extend_from_slice(&previous);
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&1_000_u64.to_le_bytes());
    bytes.push(6);
    bytes.extend_from_slice(&[0x6a, 0x04]);
    bytes.extend_from_slice(&payload.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes
}

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
    let first =
        deserialize::<Tx>(&first_bytes).unwrap_or_else(|error| panic!("fixture decodes: {error}"));
    let second =
        deserialize::<Tx>(&second_bytes).unwrap_or_else(|error| panic!("fixture decodes: {error}"));
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

    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());

    let Outcome::RequestMissing(request) = outcome else {
        panic!("expected a getblocktxn request for the collided slot, got {outcome:?}");
    };
    assert_eq!(request.txs_request.indexes, vec![1]);
    assert_eq!(
        reconstruction.retained_bytes(),
        2 * 6
            + 3 * core::mem::size_of::<Option<Tx>>()
            + core::mem::size_of::<u64>()
            + [&native.txs[0], &native.txs[2]]
                .into_iter()
                .map(|tx| core::mem::size_of::<Tx>() + tx.retained_heap_bytes())
                .sum::<usize>()
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

    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());

    assert!(
        matches!(outcome, Outcome::Fallback(_)),
        "duplicate declared short IDs must fall back, got {outcome:?}"
    );
}

struct WalkGuardedHints {
    inner: SetHints,
    walking: AtomicBool,
    nested: AtomicUsize,
}

impl WalkGuardedHints {
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

    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());

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
        bits: bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(0x207f_ffff),
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

    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());

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

    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
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

    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());

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

    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
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

    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
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

#[test]
fn reconstruction_falls_back_on_oversized_block_tx_count_and_budget_overflow() {
    let mut reconstruction = Reconstruction::new();
    let hints = SetHints { txs: vec![] };
    let (first_block, first_cmpct) =
        sample_cmpct(vec![test_tx(1), test_tx(2)], COMPACT_BLOCK_VERSION, 0x11);
    let outcome =
        reconstruction.receive_cmpctblock(&first_cmpct, COMPACT_BLOCK_VERSION, &hints, now());
    assert!(matches!(outcome, Outcome::RequestMissing(_)));
    drop(first_block);

    let (_second_block, mut second_cmpct) =
        sample_cmpct(vec![test_tx(3), test_tx(4)], COMPACT_BLOCK_VERSION, 0x22);
    second_cmpct.compact_block.short_ids =
        vec![bitcoin::bip152::ShortId::from([1u8; 6]); MAX_BLOCK_TX_COUNT + 1];
    let outcome =
        reconstruction.receive_cmpctblock(&second_cmpct, COMPACT_BLOCK_VERSION, &hints, now());
    assert!(
        matches!(outcome, Outcome::Fallback(_)),
        "oversized block tx count must fall back, got {outcome:?}"
    );
}

#[test]
fn blocktxn_wrong_counts_and_failures_release_retained_budget() {
    for failure_case in 0..4 {
        let mut prefill = test_tx(1);
        prefill.outputs[0].script_pubkey = vec![1; 100_000].into();
        let (_block, cmpct) = sample_cmpct(
            vec![prefill, test_tx(2)],
            COMPACT_BLOCK_VERSION,
            0x30 + failure_case,
        );
        let hints = SetHints { txs: vec![] };
        let mut reconstruction = Reconstruction::new();

        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
        let Outcome::RequestMissing(request) = outcome else {
            panic!("expected request missing, got {outcome:?}");
        };
        assert!(reconstruction.retained_bytes() > 0);

        let txn = match failure_case {
            0 => BlockTxn {
                transactions: BlockTransactions {
                    block_hash: request.txs_request.block_hash,
                    transactions: vec![],
                },
            },
            1 => BlockTxn {
                transactions: BlockTransactions {
                    block_hash: request.txs_request.block_hash,
                    transactions: vec![registry_tx(&test_tx(2)), registry_tx(&test_tx(3))],
                },
            },
            2 => BlockTxn {
                transactions: BlockTransactions {
                    block_hash: request.txs_request.block_hash,
                    transactions: vec![registry_tx(&test_tx(99))],
                },
            },
            _ => BlockTxn {
                transactions: BlockTransactions {
                    block_hash: request.txs_request.block_hash,
                    transactions: vec![registry_tx(&sixty_four_byte_tx(2))],
                },
            },
        };

        let outcome = reconstruction.receive_blocktxn(&txn, now());
        assert!(
            matches!(outcome, Outcome::Fallback(_)),
            "case {failure_case} must fall back, got {outcome:?}"
        );
        assert_eq!(
            reconstruction.retained_bytes(),
            0,
            "case {failure_case} must release retained bytes"
        );
    }
}
