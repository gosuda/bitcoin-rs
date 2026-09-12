//! BIP152 reconstruction and fallback integration cases (overhaul plan
//! T26/T27). This file is the named gate target:
//! `cargo test -p bitcoin-rs-p2p --test overhaul_compact_blocks`
//! (`docs/benchmarks/p2p-loopback.md`).
//!
//! Plan-fidelity deviation, recorded per acceptance: the plan names
//! `src/compact_block.rs` (singular); the landed module is
//! `src/compact_blocks.rs` (plural), wired as `crate::compact_blocks`
//! across listener, dispatch, peer, and lib. Renaming six landed call sites
//! buys no behavior, so the deviation is recorded here instead of renamed.

use bitcoin::bip152::BlockTransactions;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock};
use bitcoin_rs_p2p::compact_blocks::{CompactBlockHints, Outcome, Reconstruction};
use bitcoin_rs_p2p::compact_blocks::COMPACT_BLOCK_VERSION;
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Sequence, Tx,
    TxIn, TxOut, Witness, consensus_bytes,
};
use std::time::Instant;

/// Hints backed by a fixed transaction set, as the mempool would offer.
struct SetHints {
    txs: Vec<Tx>,
}

impl CompactBlockHints for SetHints {
    fn for_each_identity(&self, f: &mut dyn FnMut(bitcoin_rs_primitives::Txid, bitcoin_rs_primitives::Wtxid)) {
        for tx in &self.txs {
            f(tx.txid(), tx.wtxid());
        }
    }

    fn get_tx_by_txid(&self, txid: bitcoin_rs_primitives::Txid) -> Option<Tx> {
        self.txs.iter().find(|tx| tx.txid() == txid).cloned()
    }

    fn get_tx_by_wtxid(&self, wtxid: bitcoin_rs_primitives::Wtxid) -> Option<Tx> {
        self.txs.iter().find(|tx| tx.wtxid() == wtxid).cloned()
    }
}

fn test_tx(byte: u8) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin_rs_primitives::Txid::from(Hash256::from_le_bytes(&[byte; 32])),
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

/// Builds a native block and the registry `cmpctblock` for it at `version`.
fn sample_cmpct(txs: Vec<Tx>, version: u64, nonce: u64) -> (Block, CmpctBlock) {
    let header = Header {
        version: 1,
        prev_blockhash: BlockHash::from(Hash256::from_le_bytes(&[0xab; 32])),
        merkle_root: Hash256::default(),
        time: 7,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 9,
    };
    let native = Block { header, txs };
    let registry = bitcoin::consensus::encode::deserialize::<bitcoin::blockdata::block::Block>(
        &consensus_bytes(&native),
    )
    .unwrap_or_else(|error| panic!("sample block must decode: {error}"));
    let version =
        u32::try_from(version).unwrap_or_else(|error| panic!("version fits u32: {error}"));
    let compact = bitcoin::bip152::HeaderAndShortIds::from_block(&registry, nonce, version, &[])
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

// CONTRACT: docs/policies/p2p-compatibility.md#5-message-surface (BIP152
// receive path): a cmpctblock whose every transaction is resident in the
// hints reconstructs completely and enters the ordinary pipeline as a block.
#[test]
fn cmpctblock_reconstructs_completely_from_hints() {
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

// CONTRACT: docs/policies/p2p-compatibility.md#5-message-surface (BIP152
// receive path): transactions absent from the hints become one bounded
// getblocktxn request naming their indexes.
#[test]
fn missing_transactions_request_getblocktxn() {
    let (native, cmpct) = sample_cmpct(vec![test_tx(1), test_tx(2), test_tx(3)], 2, 0x4321);
    let hints = SetHints {
        txs: vec![native.txs[0].clone()],
    };
    let mut reconstruction = Reconstruction::new();

    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());

    let Outcome::RequestMissing(request) = outcome else {
        panic!("expected getblocktxn request, got {outcome:?}");
    };
    assert_eq!(request.txs_request.indexes, vec![1, 2]);
    assert_eq!(request.txs_request.block_hash.to_byte_array(), *native.block_hash().as_bytes());
}

// CONTRACT: docs/policies/p2p-compatibility.md#5-message-surface (BIP152
// receive path): more missing transactions than the bounded missing list
// skips the getblocktxn round trip in favor of the full-block fallback; the
// bound itself is still worth one request.
#[test]
fn missing_above_the_request_bound_falls_back() {
    let hints = SetHints { txs: Vec::new() };
    let mut reconstruction = Reconstruction::new();

    // 130 txs minus the prefilled coinbase: 129 missing exceeds the bound.
    let (_, cmpct) = sample_cmpct((0_u8..130).map(test_tx).collect(), 2, 0x1234);
    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
    assert!(matches!(outcome, Outcome::Fallback(_)));

    // 129 txs: 128 missing is exactly the bound and still requests.
    let (_, cmpct) = sample_cmpct((0_u8..129).map(test_tx).collect(), 2, 0x1234);
    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, now());
    let Outcome::RequestMissing(request) = outcome else {
        panic!("expected a missing-list request at the bound, got {outcome:?}");
    };
    assert_eq!(request.txs_request.indexes.len(), 128);
}

// CONTRACT: docs/policies/p2p-compatibility.md#5-message-surface (BIP152
// receive path): a blocktxn that does not match the outstanding request
// falls back to the full block, and a late retry is ignored.
#[test]
fn mismatched_blocktxn_falls_back_and_late_retry_is_idle() {
    let (native, cmpct) = sample_cmpct(vec![test_tx(1), test_tx(2)], 2, 0x55);
    let hints = SetHints {
        txs: vec![native.txs[0].clone()],
    };
    let mut reconstruction = Reconstruction::new();

    let sent_at = now();
    let outcome = reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, sent_at);
    let Outcome::RequestMissing(request) = outcome else {
        panic!("expected getblocktxn request, got {outcome:?}");
    };

    let wrong_size = BlockTxn {
        transactions: BlockTransactions {
            block_hash: request.txs_request.block_hash,
            transactions: vec![],
        },
    };
    let outcome = reconstruction.receive_blocktxn(&wrong_size, sent_at);
    assert!(matches!(outcome, Outcome::Fallback(_)));

    let late = BlockTxn {
        transactions: BlockTransactions {
            block_hash: request.txs_request.block_hash,
            transactions: vec![],
        },
    };
    assert!(matches!(
        reconstruction.receive_blocktxn(&late, sent_at),
        Outcome::Idle
    ));
}
