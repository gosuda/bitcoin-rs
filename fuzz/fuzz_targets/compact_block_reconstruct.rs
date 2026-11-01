#![no_main]

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use bitcoin::bip152::{BlockTransactions, HeaderAndShortIds, PrefilledTransaction};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock};
use bitcoin::merkle_tree::calculate_root;
use bitcoin_rs_p2p::compact_blocks::{CompactBlockHints, Outcome, Reconstruction};
use bitcoin_rs_primitives::{Tx, Txid, Wtxid, deserialize};
use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;

struct MemPoolHints {
    by_txid: HashMap<Txid, Tx>,
    by_wtxid: HashMap<Wtxid, Tx>,
}

impl CompactBlockHints for MemPoolHints {
    fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
        for (&txid, tx) in &self.by_txid {
            f(txid, tx.wtxid());
        }
    }
    fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
        self.by_txid.get(&txid).cloned()
    }
    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        self.by_wtxid.get(&wtxid).cloned()
    }
}

struct ForgetfulHints {
    identities: MemPoolHints,
}

impl CompactBlockHints for ForgetfulHints {
    fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
        self.identities.for_each_identity(f);
    }
    fn get_tx_by_txid(&self, _txid: Txid) -> Option<Tx> {
        None
    }
    fn get_tx_by_wtxid(&self, _wtxid: Wtxid) -> Option<Tx> {
        None
    }
}

fn native(tx: &bitcoin::Transaction) -> Option<Tx> {
    deserialize(&serialize(tx)).ok()
}

fn hints_for<'a>(txs: impl IntoIterator<Item = &'a bitcoin::Transaction>) -> Option<MemPoolHints> {
    let mut hints = MemPoolHints {
        by_txid: HashMap::new(),
        by_wtxid: HashMap::new(),
    };
    for tx in txs {
        let body = native(tx)?;
        hints.by_txid.insert(body.txid(), body.clone());
        hints.by_wtxid.insert(body.wtxid(), body);
    }
    Some(hints)
}

fn sixty_four_byte_tx() -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array([7u8; 32]),
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::from_bytes(vec![0u8; 4]),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    }
}

fn txid_bytes(txid: bitcoin::Txid) -> [u8; 32] {
    txid.to_byte_array()
}

fn assert_block_matches(block: &bitcoin_rs_primitives::Block, expected: &bitcoin::Block) {
    assert_eq!(
        block.header.compute_hash().as_bytes(),
        expected.header.block_hash().to_byte_array().as_slice()
    );
    let txids: Vec<[u8; 32]> = block.txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    let expected_txids: Vec<[u8; 32]> = expected
        .txdata
        .iter()
        .map(|tx| txid_bytes(tx.compute_txid()))
        .collect();
    assert_eq!(txids, expected_txids);
}

fn fork_tx(base: &bitcoin::Transaction, position: u64) -> bitcoin::Transaction {
    let mut tx = base.clone();
    tx.output[0].value = bitcoin::Amount::from_sat(position + 1);
    tx
}

fn fork_witness_tx(base: &bitcoin::Transaction, position: u64, marker: u8) -> bitcoin::Transaction {
    let mut tx = fork_tx(base, position);
    tx.input[0].witness.push([marker, 1, 2, 3]);
    tx
}

fn block_of(txs: Vec<bitcoin::Transaction>) -> Option<bitcoin::Block> {
    let merkle_root = calculate_root(txs.iter().map(bitcoin::Transaction::compute_txid))?;
    let mut header = genesis_block(bitcoin::Network::Regtest).header;
    header.merkle_root = merkle_root.into();
    Some(bitcoin::Block { header, txdata: txs })
}

fn finish(recon: &mut Reconstruction, now: Instant, start_budget: usize) {
    recon.prune(now + Duration::from_secs(120));
    assert_eq!(recon.pending_len(), 0, "pending reconstructions must expire");
    assert_eq!(
        recon.retained_bytes(),
        start_budget,
        "retained bytes must return to the baseline after expiry"
    );
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let start = Instant::now();
    let mut recon = Reconstruction::new();
    let start_budget = recon.retained_bytes();
    let coinbase = genesis_block(bitcoin::Network::Regtest).txdata[0].clone();

    let extra = usize::from(u.arbitrary::<u8>().unwrap_or_default() % 5);
    let mut txs = vec![coinbase.clone()];
    for position in 1..=extra {
        let position = u64::try_from(position).unwrap_or_default();
        let marker = u8::try_from(u.arbitrary::<u8>().unwrap_or_default()).unwrap_or_default();
        let tx = if u.arbitrary::<bool>().unwrap_or(false) {
            fork_witness_tx(&coinbase, position, marker)
        } else {
            fork_tx(&coinbase, position)
        };
        txs.push(tx);
    }
    let Some(block) = block_of(txs) else {
        return;
    };
    let version = if u.arbitrary::<bool>().unwrap_or(false) {
        2
    } else {
        1
    };
    let nonce = u.arbitrary::<u64>().unwrap_or_default();
    let prefill_selection: Vec<usize> = (1..block.txdata.len())
        .filter(|_| u.arbitrary::<bool>().unwrap_or(false))
        .collect();
    let Ok(compact) = HeaderAndShortIds::from_block(&block, nonce, version, &prefill_selection)
    else {
        return;
    };
    let cmpct = CmpctBlock {
        compact_block: compact.clone(),
    };

    let short_ids: HashSet<_> = cmpct.compact_block.short_ids.iter().copied().collect();
    let unique = short_ids.len() == cmpct.compact_block.short_ids.len();

    let missing_positions: Vec<usize> = (1..block.txdata.len())
        .filter(|index| !prefill_selection.contains(index))
        .filter(|_| u.arbitrary::<bool>().unwrap_or(false))
        .collect();
    let provided: Vec<bitcoin::Transaction> = block
        .txdata
        .iter()
        .enumerate()
        .filter(|(index, _)| *index == 0 || !missing_positions.contains(index))
        .map(|(_, tx)| tx.clone())
        .collect();
    let Some(hints) = hints_for(&provided) else {
        return;
    };

    match recon.receive_cmpctblock(&cmpct, u64::from(version), &hints, start) {
        Outcome::Complete(reconstructed) => {
            assert!(missing_positions.is_empty());
            assert_block_matches(&reconstructed, &block);
            assert_eq!(recon.pending_len(), 0);
        }
        Outcome::RequestMissing(request) => {
            assert!(!missing_positions.is_empty());
            if unique {
                let requested: Vec<u64> = request
                    .txs_request
                    .indexes
                    .iter()
                    .copied()
                    .collect();
                let expected: Vec<u64> = missing_positions
                    .iter()
                    .map(|index| u64::try_from(*index).unwrap_or(u64::MAX))
                    .collect();
                assert_eq!(requested, expected, "request must list every missing index");
            }
            let mut blocktxn = BlockTxn {
                transactions: BlockTransactions {
                    block_hash: request.txs_request.block_hash,
                    transactions: missing_positions
                        .iter()
                        .map(|index| block.txdata[*index].clone())
                        .collect(),
                },
            };
            if u.arbitrary::<bool>().unwrap_or(false) {
                blocktxn.transactions.transactions.clear();
                assert!(matches!(
                    recon.receive_blocktxn(&blocktxn, start),
                    Outcome::Fallback(_)
                ));
            } else {
                match recon.receive_blocktxn(&blocktxn, start) {
                    Outcome::Complete(reconstructed) => {
                        assert_block_matches(&reconstructed, &block);
                    }
                    other => panic!("completed blocktxn must reconstruct the block: {other:?}"),
                }
                assert!(
                    matches!(recon.receive_blocktxn(&blocktxn, start), Outcome::Idle),
                    "a repeated blocktxn must not complete twice"
                );
            }
        }
        Outcome::Fallback(_) => {
            assert!(
                !unique || !missing_positions.is_empty(),
                "a well-formed compact block with all transactions available must not fall back"
            );
        }
        Outcome::Idle => {}
    }
    finish(&mut recon, start, start_budget);

    let Some(mutated) = block_of(vec![
        coinbase.clone(),
        fork_tx(&coinbase, 1),
        fork_tx(&coinbase, 2),
        fork_tx(&coinbase, 2),
    ]) else {
        return;
    };
    let Some(mutated_hints) = hints_for(&mutated.txdata) else {
        return;
    };
    let mutated_nonce = u.arbitrary::<u64>().unwrap_or_default();
    let Ok(mutated_compact) =
        HeaderAndShortIds::from_block(&mutated, mutated_nonce, version, &[1, 2, 3])
    else {
        return;
    };
    let mutated_cmpct = CmpctBlock {
        compact_block: mutated_compact,
    };
    assert!(
        matches!(
            recon.receive_cmpctblock(&mutated_cmpct, u64::from(version), &mutated_hints, start),
            Outcome::Fallback(_)
        ),
        "a duplicate transaction subtree is a merkle mutation and must fall back"
    );
    finish(&mut recon, start, start_budget);

    let mut corrupt = HeaderAndShortIds::from_block(&block, nonce, version, &prefill_selection)
        .unwrap_or_else(|_| compact.clone());
    if !corrupt.prefilled_txs.is_empty() && u.arbitrary::<bool>().unwrap_or(false) {
        corrupt.prefilled_txs[0].idx = u16::MAX;
        let invalid = CmpctBlock {
            compact_block: corrupt,
        };
        let mut invalid_recon = Reconstruction::new();
        let invalid_budget = invalid_recon.retained_bytes();
        assert!(
            matches!(
                invalid_recon.receive_cmpctblock(&invalid, u64::from(version), &hints, start),
                Outcome::Fallback(_)
            ),
            "an out-of-range prefill index must fall back"
        );
        finish(&mut invalid_recon, start, invalid_budget);
    }

    if let Some(first) = cmpct.compact_block.prefilled_txs.first() {
        let mut duplicate = compact.clone();
        duplicate.short_ids = vec![
            bitcoin::bip152::ShortId::with_siphash_keys(
                &block.txdata[0].compute_txid(),
                bitcoin::bip152::ShortId::calculate_siphash_keys(&block.header, nonce),
            );
            u8::try_from(u.arbitrary::<u8>().unwrap_or_default() % 4)
                .map(usize::from)
                .unwrap_or_default()
                + 1
        ];
        duplicate.prefilled_txs = vec![PrefilledTransaction {
            idx: first.idx,
            tx: first.tx.clone(),
        }];
        let duplicated = CmpctBlock {
            compact_block: duplicate,
        };
        let mut duplicate_recon = Reconstruction::new();
        let duplicate_budget = duplicate_recon.retained_bytes();
        assert!(
            matches!(
                duplicate_recon.receive_cmpctblock(&duplicated, u64::from(version), &hints, start),
                Outcome::Fallback(_)
            ),
            "a repeated short id must fall back"
        );
        finish(&mut duplicate_recon, start, duplicate_budget);
    }

    let Some(coinbaseless) = block_of(vec![sixty_four_byte_tx(), coinbase.clone()]) else {
        return;
    };
    let Some(coinbaseless_hints) = hints_for(std::iter::empty::<&bitcoin::Transaction>()) else {
        return;
    };
    let coinbaseless_cmpct = CmpctBlock {
        compact_block: HeaderAndShortIds {
            header: coinbaseless.header,
            nonce,
            short_ids: Vec::new(),
            prefilled_txs: vec![
                PrefilledTransaction {
                    idx: 0,
                    tx: sixty_four_byte_tx(),
                },
                PrefilledTransaction {
                    idx: 0,
                    tx: coinbase.clone(),
                },
            ],
        },
    };
    assert!(
        matches!(
            recon.receive_cmpctblock(
                &coinbaseless_cmpct,
                u64::from(version),
                &coinbaseless_hints,
                start
            ),
            Outcome::Fallback(_)
        ),
        "a coinbaseless block with a 64-byte transaction must fall back"
    );
    finish(&mut recon, start, start_budget);

    let Some(requested) = block_of(vec![
        coinbase.clone(),
        fork_tx(&coinbase, 1),
        fork_tx(&coinbase, 2),
        fork_tx(&coinbase, 3),
    ]) else {
        return;
    };
    let Some(identities) = hints_for(&requested.txdata) else {
        return;
    };
    let Ok(requested_compact) = HeaderAndShortIds::from_block(&requested, nonce, version, &[])
    else {
        return;
    };
    let forgetful = ForgetfulHints { identities };
    assert!(
        matches!(
            recon.receive_cmpctblock(
                &CmpctBlock {
                    compact_block: requested_compact,
                },
                u64::from(version),
                &forgetful,
                start
            ),
            Outcome::RequestMissing(_)
        ),
        "identities without bodies must request the missing transactions"
    );
    finish(&mut recon, start, start_budget);
});
