use std::io::ErrorKind;
use std::path::Path;

use bitcoin::BlockHash;
use bitcoin::OutPoint as BitcoinOutPoint;
use bitcoin_rs_primitives::hex::{hex_decode, hex_encode};
use bitcoin_rs_utxo::stats::CoinStats;

use crate::chain::{Chain, ChainBlock};
use crate::convert;
use crate::error::Error;
use crate::hints::HintSet;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FoldCounters {
    pub blocks: u32,
    pub created: u64,
    pub spent: u64,
    pub body_bytes: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Fold {
    stats: CoinStats,
    hashes: Vec<BlockHash>,
    counters: FoldCounters,
}

#[derive(Clone, Debug)]
pub struct SyncOptions<'a> {
    pub checkpoint: Option<&'a Path>,
    pub checkpoint_every: u32,
    pub simulate_crash_after: Option<u32>,
}

impl Default for SyncOptions<'_> {
    fn default() -> Self {
        Self {
            checkpoint: None,
            checkpoint_every: 100,
            simulate_crash_after: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SyncReport {
    pub folded: u32,
    pub resumed_from: u32,
    pub created: u64,
    pub spent: u64,
    pub body_bytes: u64,
    pub hint_coins: u64,
    pub folded_muhash: bitcoin_rs_primitives::Hash256,
    pub aggregate_muhash: bitcoin_rs_primitives::Hash256,
}

impl Fold {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resume(
        stats: CoinStats,
        folded: u32,
        tip: BlockHash,
        chain: &Chain,
    ) -> Result<Self, Error> {
        if usize::try_from(folded).unwrap_or(usize::MAX) > chain.blocks.len() {
            return Err(Error::CheckpointBeyondChain {
                folded,
                length: chain.blocks.len(),
            });
        }
        let hashes: Vec<BlockHash> = chain
            .blocks
            .iter()
            .take(usize::try_from(folded).unwrap_or(0))
            .map(ChainBlock::hash)
            .collect();
        if let Some(last) = hashes.last() {
            if *last != tip {
                return Err(Error::CheckpointMismatch {
                    height: folded.saturating_sub(1),
                    expected: tip.to_string(),
                    found: last.to_string(),
                });
            }
        }
        Ok(Self {
            stats,
            hashes,
            counters: FoldCounters::default(),
        })
    }

    pub fn stats(&self) -> &CoinStats {
        &self.stats
    }

    pub fn folded(&self) -> u32 {
        u32::try_from(self.hashes.len()).unwrap_or(u32::MAX)
    }

    pub fn tip(&self) -> Option<BlockHash> {
        self.hashes.last().copied()
    }

    pub fn counters(&self) -> FoldCounters {
        self.counters
    }

    pub fn fold_block(&mut self, carried: &ChainBlock) -> Result<(), Error> {
        if carried.height != self.folded() {
            return Err(Error::ChainGap {
                expected: self.folded(),
                found: carried.height,
            });
        }
        if let Some(tip) = self.tip() {
            if carried.block.header.prev_blockhash != tip {
                return Err(Error::ReorgDetected {
                    height: carried.height,
                    parent: carried.block.header.prev_blockhash.to_string(),
                    tip: tip.to_string(),
                });
            }
        }
        if carried.height != 0 {
            for tx in &carried.block.txdata {
                let coinbase = tx.is_coinbase();
                let txid = tx.compute_txid();
                for (vout, txout) in tx.output.iter().enumerate() {
                    let Ok(vout) = u32::try_from(vout) else {
                        return Err(Error::InvalidBlock {
                            height: carried.height,
                            check: "output index",
                        });
                    };
                    let outpoint = BitcoinOutPoint { txid, vout };
                    self.stats.insert_utxo(
                        &convert::outpoint(&outpoint),
                        &convert::txout(txout),
                        carried.height,
                        coinbase,
                    );
                    self.counters.created = self.counters.created.saturating_add(1);
                }
            }
            for entry in &carried.undo {
                self.stats.remove_utxo(
                    &convert::outpoint(&entry.outpoint),
                    &convert::txout(&entry.coin.txout),
                    entry.coin.height,
                    entry.coin.coinbase,
                );
                self.counters.spent = self.counters.spent.saturating_add(1);
            }
        }
        self.hashes.push(carried.hash());
        self.counters.blocks = self.counters.blocks.saturating_add(1);
        self.counters.body_bytes = self
            .counters
            .body_bytes
            .saturating_add(u64::from(carried.wire_len));
        Ok(())
    }

    pub fn rewind_to(&mut self, target: u32, source: &Chain) -> Result<(), Error> {
        if target > self.folded() {
            return Err(Error::RewindForward {
                target,
                folded: self.folded(),
            });
        }
        for height in (target..self.folded()).rev() {
            let Some(carried) = source
                .blocks
                .get(usize::try_from(height).unwrap_or(usize::MAX))
            else {
                return Err(Error::UnknownPrevout {
                    height,
                    outpoint: "rewind source".to_owned(),
                });
            };
            if self
                .hashes
                .get(usize::try_from(height).unwrap_or(usize::MAX))
                != Some(&carried.hash())
            {
                return Err(Error::RewindSourceMismatch { height });
            }
            if height != 0 {
                for tx in &carried.block.txdata {
                    let coinbase = tx.is_coinbase();
                    let txid = tx.compute_txid();
                    for (vout, txout) in tx.output.iter().enumerate() {
                        let Ok(vout) = u32::try_from(vout) else {
                            return Err(Error::InvalidBlock {
                                height,
                                check: "output index",
                            });
                        };
                        let outpoint = BitcoinOutPoint { txid, vout };
                        self.stats.remove_utxo(
                            &convert::outpoint(&outpoint),
                            &convert::txout(txout),
                            height,
                            coinbase,
                        );
                    }
                }
                for entry in &carried.undo {
                    self.stats.insert_utxo(
                        &convert::outpoint(&entry.outpoint),
                        &convert::txout(&entry.coin.txout),
                        entry.coin.height,
                        entry.coin.coinbase,
                    );
                }
            }
            self.hashes.truncate(usize::try_from(height).unwrap_or(0));
        }
        Ok(())
    }

    pub fn finish(self, hints: &HintSet) -> Result<SyncReport, Error> {
        let folded = self.folded();
        if hints.height.saturating_add(1) != folded {
            return Err(Error::HintHeight {
                hint: hints.height,
                folded: folded.saturating_sub(1),
            });
        }
        let folded_muhash = self.stats.muhash.finalize_hash();
        let mut stats = self.stats;
        let mut hint_coins = 0_u64;
        for (outpoint, coin) in &hints.coins {
            stats.remove_utxo(
                &convert::outpoint(outpoint),
                &convert::txout(&coin.txout),
                coin.height,
                coin.coinbase,
            );
            hint_coins = hint_coins.saturating_add(1);
        }
        let identity = CoinStats::new();
        let identity_muhash = identity.muhash.finalize_hash();
        let aggregate_muhash = stats.muhash.finalize_hash();
        let zeroed = aggregate_muhash == identity_muhash
            && stats.utxo_count == 0
            && stats.total_amount == 0
            && stats.bogo_size == 0;
        if !zeroed {
            return Err(Error::AggregateNotZero {
                folded: folded.saturating_sub(1),
                hints: hint_coins,
                muhash: aggregate_muhash.to_string_be(),
                utxo_count: stats.utxo_count,
                total_amount: stats.total_amount,
            });
        }
        Ok(SyncReport {
            folded,
            resumed_from: 0,
            created: self.counters.created,
            spent: self.counters.spent,
            body_bytes: self.counters.body_bytes,
            hint_coins,
            folded_muhash,
            aggregate_muhash,
        })
    }
}

pub fn sync(
    chain: &Chain,
    hints: &HintSet,
    options: &SyncOptions<'_>,
) -> Result<SyncReport, Error> {
    let mut fold = Fold::new();
    let mut resumed_from = 0;
    if let Some(path) = options.checkpoint {
        if let Some(state) = read_checkpoint(path)? {
            fold = Fold::resume(state.stats, state.folded, state.tip, chain)?;
            resumed_from = state.folded;
        }
    }
    let start = usize::try_from(fold.folded()).unwrap_or(usize::MAX);
    for carried in chain.blocks.iter().skip(start) {
        fold.fold_block(carried)?;
        if options.simulate_crash_after == Some(fold.folded()) {
            return Err(Error::SimulatedCrash {
                folded: fold.folded(),
            });
        }
        if let Some(path) = options.checkpoint {
            if options.checkpoint_every != 0
                && fold.folded().is_multiple_of(options.checkpoint_every)
            {
                write_checkpoint(path, &fold)?;
            }
        }
    }
    let mut report = fold.finish(hints)?;
    report.resumed_from = resumed_from;
    if let Some(path) = options.checkpoint {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(source) => {
                return Err(Error::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }
    Ok(report)
}

#[derive(Debug)]
struct CheckpointState {
    folded: u32,
    tip: BlockHash,
    stats: CoinStats,
}

fn write_checkpoint(path: &Path, fold: &Fold) -> Result<(), Error> {
    let Some(tip) = fold.tip() else {
        return Ok(());
    };
    let text = format!(
        "swiftsync-checkpoint 1\nfolded {}\ntip {}\nstats {}\n",
        fold.folded(),
        tip,
        hex_encode(&fold.stats().to_bytes()),
    );
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, text).map_err(|source| Error::Io {
        path: temporary.clone(),
        source,
    })?;
    std::fs::rename(&temporary, path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn read_checkpoint(path: &Path) -> Result<Option<CheckpointState>, Error> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(Error::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let mut folded = None;
    let mut tip = None;
    let mut stats = None;
    for (index, line) in text.lines().enumerate() {
        let line_number = index.saturating_add(1);
        if index == 0 {
            if line != "swiftsync-checkpoint 1" {
                return Err(Error::CheckpointFormat {
                    line: line_number,
                    reason: "expected `swiftsync-checkpoint 1`".to_owned(),
                });
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("folded ") {
            folded = Some(rest.parse::<u32>().map_err(|_| Error::CheckpointFormat {
                line: line_number,
                reason: format!("cannot parse `{rest}`"),
            })?);
        } else if let Some(rest) = line.strip_prefix("tip ") {
            tip = Some(
                rest.parse::<BlockHash>()
                    .map_err(|_| Error::CheckpointFormat {
                        line: line_number,
                        reason: format!("cannot parse `{rest}`"),
                    })?,
            );
        } else if let Some(rest) = line.strip_prefix("stats ") {
            let bytes = hex_decode(rest).map_err(|error| Error::CheckpointFormat {
                line: line_number,
                reason: error.to_string(),
            })?;
            stats =
                Some(
                    CoinStats::from_bytes(&bytes).map_err(|error| Error::CheckpointFormat {
                        line: line_number,
                        reason: error.to_string(),
                    })?,
                );
        } else {
            return Err(Error::CheckpointFormat {
                line: line_number,
                reason: format!("unexpected line `{line}`"),
            });
        }
    }
    match (folded, tip, stats) {
        (Some(folded), Some(tip), Some(stats)) => Ok(Some(CheckpointState { folded, tip, stats })),
        _ => Err(Error::CheckpointFormat {
            line: 1,
            reason: "checkpoint needs folded, tip and stats lines".to_owned(),
        }),
    }
}
