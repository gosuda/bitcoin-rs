#![no_main]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bitcoin::bip152::{BlockTransactions, HeaderAndShortIds};
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock};
use bitcoin_rs_p2p::compact_blocks::{CompactBlockHints, Outcome, Reconstruction};
use bitcoin_rs_primitives::{Network, Tx, Txid, Wtxid};
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

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let mut recon = Reconstruction::new();
    let genesis = Network::Regtest.genesis_block();
    let mut hints = MemPoolHints {
        by_txid: HashMap::new(),
        by_wtxid: HashMap::new(),
    };
    for tx in genesis.txs {
        hints.by_txid.insert(tx.txid(), tx.clone());
        hints.by_wtxid.insert(tx.wtxid(), tx);
    }
    let mut now = Instant::now();
    let start_budget = recon.retained_bytes();

    while !u.is_empty() {
        let Ok(action_kind) = u.arbitrary::<u8>() else {
            break;
        };
        match action_kind % 3 {
            0 => {
                let Ok(nonce) = u.arbitrary::<u64>() else {
                    break;
                };
                let Ok(bits) = u.arbitrary::<u32>() else {
                    break;
                };
                let Ok(time) = u.arbitrary::<u32>() else {
                    break;
                };
                let Ok(header_nonce) = u.arbitrary::<u32>() else {
                    break;
                };
                let header = bitcoin::block::Header {
                    version: bitcoin::block::Version::ONE,
                    prev_blockhash: bitcoin::BlockHash::all_zeros(),
                    merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                    time,
                    bits: bitcoin::CompactTarget::from_consensus(bits),
                    nonce: header_nonce,
                };
                let cmpct = CmpctBlock {
                    compact_block: HeaderAndShortIds {
                        header,
                        nonce,
                        short_ids: vec![],
                        prefilled_txs: vec![],
                    },
                };
                let outcome = recon.receive_cmpctblock(&cmpct, 2, &hints, now);
                match outcome {
                    Outcome::Fallback(_) | Outcome::Complete(_) => {
                        if recon.pending_len() == 0 {
                            assert_eq!(recon.retained_bytes(), start_budget);
                        }
                    }
                    _ => {}
                }
            }
            1 => {
                let Ok(hash_bytes) = u.arbitrary::<[u8; 32]>() else {
                    break;
                };
                let block_hash = bitcoin::BlockHash::from_byte_array(hash_bytes);
                let txn = BlockTxn {
                    transactions: BlockTransactions {
                        block_hash,
                        transactions: vec![],
                    },
                };
                let outcome = recon.receive_blocktxn(&txn, now);
                match outcome {
                    Outcome::Complete(_) | Outcome::Fallback(_) => {
                        if recon.pending_len() == 0 {
                            assert_eq!(recon.retained_bytes(), start_budget);
                        }
                    }
                    _ => {}
                }
            }
            _ => {
                now += Duration::from_secs(65);
                recon.prune(now);
                assert_eq!(recon.pending_len(), 0);
                assert_eq!(recon.retained_bytes(), start_budget);
            }
        }
    }

    now += Duration::from_secs(120);
    recon.prune(now);
    assert_eq!(recon.pending_len(), 0);
    assert_eq!(recon.retained_bytes(), start_budget);
});
