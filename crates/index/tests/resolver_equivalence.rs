//! Equivalence tests for the index read-path refactor sets.
//!
//! Every optimized resolver is checked against its naive `_scan` reference over
//! the same fixture. Equality is over the **full** result — same elements, same
//! order, same values — not a spot check, because the resolvers' output order is
//! itself contractual: `combined_history` sorts by `(height, txid)` downstream,
//! and `ScriptIndex` clients hash the sequence to derive a status.
//!
//! These tests are deliberately backend-free so they run on a plain
//! `cargo test --workspace`.
// A resolver returning `Err` in an equivalence test is a test failure, and
// panicking reports it with the offending call site. `expect` is deliberate.
#![allow(clippy::expect_used)]

mod common;

use std::cell::Cell;
use std::sync::Arc;

use bitcoin::hashes::Hash as _;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness, absolute, block, transaction,
};
use bitcoin_rs_index::{BlockSource, Indexer, ScriptHash};
use bitcoin_rs_storage::{ColumnFamily, KvStore as _, WriteBatch as _};
use hashbrown::HashMap;
use proptest::prelude::*;

use common::MemoryStore;

const BASE_HEIGHT: u32 = 100;

/// Block source over decoded fixture blocks.
///
/// `sliceable` selects which read path the resolvers take. With it off,
/// `block_bytes_at_height` declines and every resolver falls back to a full
/// block scan — the behaviour of a storage backend that cannot serve ranges, and
/// of any un-reindexed database. With it on, the position path runs. Both must
/// produce identical results, so every equivalence assertion runs twice.
struct FixtureSource {
    blocks: HashMap<u32, Block>,
    sliceable: bool,
    /// Whole-block reads served. The position path must never need one.
    full_loads: Cell<usize>,
    /// Ranged reads served.
    range_loads: Cell<usize>,
}

impl FixtureSource {
    fn new(blocks: HashMap<u32, Block>, sliceable: bool) -> Self {
        Self {
            blocks,
            sliceable,
            full_loads: Cell::new(0),
            range_loads: Cell::new(0),
        }
    }
}

impl BlockSource for FixtureSource {
    fn block_at_height(&self, height: u32) -> Option<Block> {
        self.full_loads.set(self.full_loads.get() + 1);
        self.blocks.get(&height).cloned()
    }

    fn block_bytes_at_height(&self, height: u32, offset: u32, len: u32) -> Option<Vec<u8>> {
        if !self.sliceable {
            return None;
        }
        self.range_loads.set(self.range_loads.get() + 1);
        let bytes = bitcoin::consensus::encode::serialize(self.blocks.get(&height)?);
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        bytes.get(start..end).map(<[u8]>::to_vec)
    }
}

fn header() -> block::Header {
    block::Header {
        version: block::Version::ONE,
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: 0,
        bits: CompactTarget::from_consensus(0),
        nonce: 0,
    }
}

fn script(tag: u8, len: usize) -> ScriptBuf {
    ScriptBuf::from_bytes(core::iter::repeat_n(tag, len.max(1)).collect())
}

/// An `OP_RETURN` script, which ingest skips so no funding row is ever written.
fn op_return_script(tag: u8) -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x6a, tag])
}

fn tx_with_outputs(seed: u8, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([seed; 32]),
                vout: u32::from(seed),
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

fn out(script_pubkey: ScriptBuf, sats: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(sats),
        script_pubkey,
    }
}

/// Builds an indexer over `blocks` (height-ordered) plus a matching source.
fn index_blocks(blocks: Vec<(u32, Block)>) -> (Indexer<MemoryStore>, HashMap<u32, Block>) {
    let mut indexer = Indexer::new(Arc::new(MemoryStore::default()));
    let mut map = HashMap::new();
    for (height, block) in blocks {
        let bytes = bitcoin::consensus::encode::serialize(&block);
        indexer
            .ingest_block(&bytes, height)
            .expect("fixture block ingests");
        map.insert(height, block);
    }
    (indexer, map)
}

/// Asserts every optimized resolver matches its `_scan` reference exactly, on
/// both the position path and the scan-fallback path.
fn assert_resolvers_agree(
    indexer: &Indexer<MemoryStore>,
    blocks: &HashMap<u32, Block>,
    scripthash: ScriptHash,
) {
    for sliceable in [false, true] {
        let source = FixtureSource::new(blocks.clone(), sliceable);
        assert_resolvers_agree_on(indexer, &source, scripthash, sliceable);
    }
}

/// Asserts agreement against one source, whose `_scan` results are the oracle.
fn assert_resolvers_agree_on(
    indexer: &Indexer<MemoryStore>,
    source: &FixtureSource,
    scripthash: ScriptHash,
    sliceable: bool,
) {
    let path = if sliceable { "position" } else { "fallback" };

    assert_eq!(
        indexer
            .resolve_script_history(scripthash, source)
            .expect("fast resolver"),
        indexer
            .resolve_script_history_scan(scripthash, source)
            .expect("reference resolver"),
        "resolve_script_history diverged from its reference on the {path} path"
    );

    assert_eq!(
        indexer
            .resolve_unspent_outputs_with_height(scripthash, source)
            .expect("fast resolver"),
        indexer
            .resolve_unspent_outputs_with_height_scan(scripthash, source)
            .expect("reference resolver"),
        "resolve_unspent_outputs_with_height diverged from its reference on the {path} path"
    );

    assert_eq!(
        indexer
            .resolve_unspent_outputs(scripthash, source)
            .expect("fast resolver"),
        indexer
            .resolve_unspent_outputs_scan(scripthash, source)
            .expect("reference resolver"),
        "resolve_unspent_outputs diverged from its reference on the {path} path"
    );

    // Every transaction reachable from this scripthash must resolve by txid too.
    for entry in indexer
        .resolve_script_history_scan(scripthash, source)
        .expect("reference resolver")
    {
        assert_eq!(
            indexer
                .resolve_transaction(entry.txid, source)
                .expect("fast resolver"),
            indexer
                .resolve_transaction_scan(entry.txid, source)
                .expect("reference resolver"),
            "resolve_transaction diverged from its reference on the {path} path"
        );
    }
}

/// The equivalence assertions above cannot catch a resolver that quietly stops
/// using positions: deleting the fast path entirely leaves every one of them
/// green, because scanning is what they compare against. This is the test that
/// fails when that happens.
///
/// It asserts the read *shape*, not the result — on the position path a whole
/// block must never be loaded, and on the fallback path a range must never be
/// requested.
#[test]
fn the_position_path_reads_ranges_and_never_whole_blocks() {
    let target = script(0x5c, 22);
    let mut blocks = Vec::new();
    for offset in 0..4_u32 {
        let seed = u8::try_from(offset).unwrap_or(0);
        blocks.push((
            BASE_HEIGHT + offset,
            Block {
                header: header(),
                txdata: vec![
                    tx_with_outputs(0x40 + seed, vec![out(script(0x77, 22), 11)]),
                    tx_with_outputs(0x50 + seed, vec![out(target.clone(), 12)]),
                ],
            },
        ));
    }
    let (indexer, blocks) = index_blocks(blocks);
    let scripthash = ScriptHash::from_script_bytes(target.as_bytes());

    let positioned = FixtureSource::new(blocks.clone(), true);
    let history = indexer
        .resolve_script_history(scripthash, &positioned)
        .expect("fast resolver");
    assert_eq!(
        history.len(),
        4,
        "fixture must resolve one entry per height"
    );
    assert_eq!(
        positioned.full_loads.get(),
        0,
        "the position path loaded a whole block; the fast path is not being taken"
    );
    assert!(
        positioned.range_loads.get() > 0,
        "the position path served no ranged read"
    );

    let scanning = FixtureSource::new(blocks, false);
    assert_eq!(
        indexer
            .resolve_script_history(scripthash, &scanning)
            .expect("fallback resolver"),
        history,
        "the fallback must resolve what the position path resolved"
    );
    assert!(
        scanning.full_loads.get() > 0,
        "the fallback path served no whole-block read"
    );
    assert_eq!(
        scanning.range_loads.get(),
        0,
        "a source that declines ranges must never record one"
    );
}

#[test]
fn agrees_on_single_funding_output() {
    let target = script(0x11, 22);
    let block = Block {
        header: header(),
        txdata: vec![tx_with_outputs(1, vec![out(target.clone(), 5_000)])],
    };
    let (indexer, blocks) = index_blocks(vec![(BASE_HEIGHT, block)]);
    assert_resolvers_agree(
        &indexer,
        &blocks,
        ScriptHash::from_script_bytes(target.as_bytes()),
    );
}

#[test]
fn agrees_when_one_transaction_pays_the_target_twice() {
    // Two matching outputs in one transaction: the lazy txid must be computed
    // once and reused, and both entries must still carry it.
    let target = script(0x22, 22);
    let block = Block {
        header: header(),
        txdata: vec![tx_with_outputs(
            2,
            vec![
                out(target.clone(), 1),
                out(script(0x99, 22), 2),
                out(target.clone(), 3),
            ],
        )],
    };
    let (indexer, blocks) = index_blocks(vec![(BASE_HEIGHT, block)]);
    let scripthash = ScriptHash::from_script_bytes(target.as_bytes());
    assert_resolvers_agree(&indexer, &blocks, scripthash);

    let source = FixtureSource::new(blocks, true);
    let resolved = indexer
        .resolve_unspent_outputs_with_height(scripthash, &source)
        .expect("resolver");
    assert_eq!(resolved.len(), 2, "both matching outputs must be emitted");
    assert_eq!(
        resolved[0].0, resolved[1].0,
        "both entries must carry the same txid"
    );
}

#[test]
fn agrees_when_two_transactions_in_one_block_pay_the_target() {
    // Ingest collapses both into a single (prefix, height) row, so the resolver
    // sees one row and must still emit both transactions.
    let target = script(0x33, 22);
    let block = Block {
        header: header(),
        txdata: vec![
            tx_with_outputs(3, vec![out(target.clone(), 7)]),
            tx_with_outputs(4, vec![out(script(0x88, 22), 8)]),
            tx_with_outputs(5, vec![out(target.clone(), 9)]),
        ],
    };
    let (indexer, blocks) = index_blocks(vec![(BASE_HEIGHT, block)]);
    let scripthash = ScriptHash::from_script_bytes(target.as_bytes());
    assert_resolvers_agree(&indexer, &blocks, scripthash);
    let source = FixtureSource::new(blocks, true);
    assert_eq!(
        indexer
            .resolve_unspent_outputs_with_height(scripthash, &source)
            .expect("resolver")
            .len(),
        2
    );
}

#[test]
fn agrees_across_multiple_heights() {
    let target = script(0x44, 22);
    let blocks = (0..5_u32)
        .map(|offset| {
            let block = Block {
                header: header(),
                txdata: vec![
                    tx_with_outputs(
                        u8::try_from(offset).unwrap_or(0),
                        vec![out(script(0x77, 22), 1)],
                    ),
                    tx_with_outputs(
                        u8::try_from(offset + 100).unwrap_or(0),
                        vec![out(target.clone(), u64::from(offset) + 1)],
                    ),
                ],
            };
            (BASE_HEIGHT + offset, block)
        })
        .collect();
    let (indexer, blocks) = index_blocks(blocks);
    assert_resolvers_agree(
        &indexer,
        &blocks,
        ScriptHash::from_script_bytes(target.as_bytes()),
    );
}

#[test]
fn agrees_when_the_block_source_cannot_resolve_a_height() {
    // The resolver skips unresolvable heights rather than failing. Both arms
    // must skip identically.
    let target = script(0x55, 22);
    let block = Block {
        header: header(),
        txdata: vec![tx_with_outputs(6, vec![out(target.clone(), 4)])],
    };
    let mut indexer = Indexer::new(Arc::new(MemoryStore::default()));
    indexer
        .ingest_block(&bitcoin::consensus::encode::serialize(&block), BASE_HEIGHT)
        .expect("ingest");
    // Source deliberately holds no blocks at all.
    let blocks: HashMap<u32, Block> = HashMap::new();
    let scripthash = ScriptHash::from_script_bytes(target.as_bytes());
    assert_resolvers_agree(&indexer, &blocks, scripthash);
    let source = FixtureSource::new(blocks, true);
    assert!(
        indexer
            .resolve_unspent_outputs_with_height(scripthash, &source)
            .expect("resolver")
            .is_empty()
    );
}

#[test]
fn agrees_when_the_target_is_op_return() {
    // Ingest skips OP_RETURN outputs, so no funding row exists and both arms
    // must return empty rather than disagreeing about an unindexed script.
    let target = op_return_script(0x66);
    let block = Block {
        header: header(),
        txdata: vec![tx_with_outputs(7, vec![out(target.clone(), 0)])],
    };
    let (indexer, blocks) = index_blocks(vec![(BASE_HEIGHT, block)]);
    let scripthash = ScriptHash::from_script_bytes(target.as_bytes());
    assert_resolvers_agree(&indexer, &blocks, scripthash);
    let source = FixtureSource::new(blocks, true);
    assert!(
        indexer
            .resolve_unspent_outputs_with_height(scripthash, &source)
            .expect("resolver")
            .is_empty()
    );
}

#[test]
fn agrees_for_a_scripthash_that_was_never_indexed() {
    let block = Block {
        header: header(),
        txdata: vec![tx_with_outputs(8, vec![out(script(0xaa, 22), 1)])],
    };
    let (indexer, blocks) = index_blocks(vec![(BASE_HEIGHT, block)]);
    assert_resolvers_agree(
        &indexer,
        &blocks,
        ScriptHash::from_script_bytes(script(0xbb, 22).as_bytes()),
    );
}

/// A row whose positions describe a *different* block at the same height.
///
/// Funding keys carry no block identity, so a superseded block leaves rows
/// pointing into bytes that now belong to its replacement. This is the case the
/// all-or-scan rule exists for: the resolver must notice and scan, not report
/// whatever the stale offsets happen to decode to.
#[test]
fn stale_positions_from_a_superseded_block_fall_back_to_scanning() {
    let target = script(0x77, 22);

    // Block A: the target is funded by the second of three transactions.
    let block_a = Block {
        header: header(),
        txdata: vec![
            tx_with_outputs(10, vec![out(script(0xa1, 22), 1)]),
            tx_with_outputs(11, vec![out(target.clone(), 2)]),
            tx_with_outputs(12, vec![out(script(0xa2, 22), 3)]),
        ],
    };
    // Block B: same height, different transactions, and the target is funded
    // twice — at offsets that do not line up with A's.
    let block_b = Block {
        header: header(),
        txdata: vec![
            tx_with_outputs(20, vec![out(target.clone(), 4), out(script(0xb1, 22), 5)]),
            tx_with_outputs(21, vec![out(script(0xb2, 22), 6)]),
            tx_with_outputs(22, vec![out(target.clone(), 7)]),
        ],
    };

    // Index A, then serve B. The rows describe A; the source serves B.
    let mut indexer = Indexer::new(Arc::new(MemoryStore::default()));
    indexer
        .ingest_block(
            &bitcoin::consensus::encode::serialize(&block_a),
            BASE_HEIGHT,
        )
        .expect("ingest A");

    let mut served = HashMap::new();
    served.insert(BASE_HEIGHT, block_b);
    let source = FixtureSource::new(served, true);
    let scripthash = ScriptHash::from_script_bytes(target.as_bytes());

    let fast = indexer
        .resolve_script_history(scripthash, &source)
        .expect("fast resolver");
    let reference = indexer
        .resolve_script_history_scan(scripthash, &source)
        .expect("reference resolver");
    assert_eq!(
        fast, reference,
        "stale positions must fall back to scanning, not report a short result"
    );
    assert_eq!(
        fast.len(),
        2,
        "the served block funds the target twice; both must be reported"
    );
}

/// A stale position that decodes cleanly into a transaction which simply does
/// not match.
///
/// This is the case that pins the all-or-scan rule, and it is distinct from
/// `stale_positions_from_a_superseded_block_fall_back_to_scanning`: there the
/// stale offset produced undecodable bytes, so any implementation bails. Here
/// both blocks hold equally sized transactions, so the superseded block's offset
/// lands exactly on a transaction boundary in the replacement and yields a
/// perfectly valid transaction that funds something else.
///
/// A resolver that *skips* the non-matching position instead of scanning
/// returns an empty history while the block plainly funds the script. Verified
/// by mutation: turning the `return None` in `positioned_history` into a
/// `continue` leaves every other test in this file green and fails only this
/// one.
#[test]
fn a_stale_position_that_decodes_but_does_not_match_still_forces_a_scan() {
    let target = script(0x99, 22);
    let decoy_a = script(0xc1, 22);
    let decoy_b = script(0xc2, 22);

    // Every transaction here serializes to the same length: one input with a
    // 32-byte txid and a 4-byte vout, one output with a 22-byte script. So the
    // two blocks place their transactions at identical offsets.
    let block_a = Block {
        header: header(),
        txdata: vec![
            tx_with_outputs(40, vec![out(decoy_a.clone(), 1)]),
            tx_with_outputs(41, vec![out(target.clone(), 2)]),
            tx_with_outputs(42, vec![out(decoy_a, 3)]),
        ],
    };
    let block_b = Block {
        header: header(),
        txdata: vec![
            tx_with_outputs(50, vec![out(decoy_b.clone(), 4)]),
            // Same slot as A's target transaction, but funds a decoy.
            tx_with_outputs(51, vec![out(decoy_b, 5)]),
            // The replacement funds the target here instead.
            tx_with_outputs(52, vec![out(target.clone(), 6)]),
        ],
    };

    let a_bytes = bitcoin::consensus::encode::serialize(&block_a);
    let b_bytes = bitcoin::consensus::encode::serialize(&block_b);
    assert_eq!(
        a_bytes.len(),
        b_bytes.len(),
        "the fixture depends on both blocks laying transactions at the same offsets"
    );

    let mut indexer = Indexer::new(Arc::new(MemoryStore::default()));
    indexer
        .ingest_block(&a_bytes, BASE_HEIGHT)
        .expect("ingest A");

    let mut served = HashMap::new();
    served.insert(BASE_HEIGHT, block_b);
    let source = FixtureSource::new(served, true);
    let scripthash = ScriptHash::from_script_bytes(target.as_bytes());

    let history = indexer
        .resolve_script_history(scripthash, &source)
        .expect("resolver");
    assert_eq!(
        history,
        indexer
            .resolve_script_history_scan(scripthash, &source)
            .expect("reference resolver"),
        "a position that decodes but does not match must force a scan"
    );
    assert_eq!(
        history.len(),
        1,
        "the served block funds the target once and it must be reported"
    );

    let unspent = indexer
        .resolve_unspent_outputs_with_height(scripthash, &source)
        .expect("resolver");
    assert_eq!(
        unspent,
        indexer
            .resolve_unspent_outputs_with_height_scan(scripthash, &source)
            .expect("reference resolver"),
        "the same rule must hold for the unspent-output resolver"
    );
    assert_eq!(unspent.len(), 1);
}

/// A database written before row values carried positions.
///
/// Every row value is empty, which readers must treat as "no positions
/// available" rather than "no matching transactions".
#[test]
fn rows_without_positions_fall_back_to_scanning() {
    let target = script(0x88, 22);
    let block = Block {
        header: header(),
        txdata: vec![
            tx_with_outputs(30, vec![out(target.clone(), 1)]),
            tx_with_outputs(31, vec![out(target.clone(), 2)]),
        ],
    };
    let (indexer, blocks) = index_blocks(vec![(BASE_HEIGHT, block)]);

    // Blank every value, leaving the keys exactly as an old database would.
    let store = Arc::clone(indexer.store());
    for cf in [ColumnFamily::Funding, ColumnFamily::TxConfirmed] {
        let keys = store
            .iter_prefix(cf, &[])
            .expect("iterate")
            .map(|entry| entry.expect("row").0)
            .collect::<Vec<_>>();
        let mut batch = store.new_batch();
        for key in keys {
            batch.put(cf, &key, &[]);
        }
        store.write(batch).expect("blank values");
    }

    let scripthash = ScriptHash::from_script_bytes(target.as_bytes());
    assert_resolvers_agree(&indexer, &blocks, scripthash);

    let source = FixtureSource::new(blocks, true);
    assert_eq!(
        indexer
            .resolve_script_history(scripthash, &source)
            .expect("resolver")
            .len(),
        2,
        "an empty value means scan the block, not report nothing"
    );
}

proptest! {
    /// Random block shapes: varying transaction counts, output counts, script
    /// tags and values, with the target script planted at random positions.
    #[test]
    fn agrees_on_random_blocks(
        // blocks -> transactions -> outputs, each output a (script tag, value).
        plan in proptest::collection::vec(
            proptest::collection::vec(
                proptest::collection::vec((0_u8..4, 0_u64..1_000), 1..4),
                1..4,
            ),
            1..4,
        ),
    ) {
        // Tag 0 is the target; tags 1..3 are decoys. A tag-0 output makes the
        // transaction a match, and a transaction may match zero, one or many
        // times.
        let target = script(0x01, 22);
        let decoys = [script(0x02, 22), script(0x03, 22), script(0x04, 22)];

        let mut blocks = Vec::new();
        for (block_idx, txs) in plan.iter().enumerate() {
            let txdata = txs
                .iter()
                .enumerate()
                .map(|(tx_idx, outputs)| {
                    let outs = outputs
                        .iter()
                        .map(|(tag, sats)| {
                            let script_pubkey = if *tag == 0 {
                                target.clone()
                            } else {
                                decoys[usize::from(*tag) - 1].clone()
                            };
                            out(script_pubkey, *sats)
                        })
                        .collect();
                    let seed = u8::try_from((block_idx * 16 + tx_idx) % 256).unwrap_or(0);
                    tx_with_outputs(seed, outs)
                })
                .collect();
            let height = BASE_HEIGHT + u32::try_from(block_idx).unwrap_or(0);
            blocks.push((height, Block { header: header(), txdata }));
        }

        let (indexer, indexed) = index_blocks(blocks);
        assert_resolvers_agree(
            &indexer,
            &indexed,
            ScriptHash::from_script_bytes(target.as_bytes()),
        );
    }
}
