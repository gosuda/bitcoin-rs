use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version as BlockVersion};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, Target,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_primitives::hex::{hex_decode, hex_encode};

use crate::error::Error;

pub const PINNED_SEED: u64 = 0x5eed_0fb1_7c01_d5a3;
pub const PINNED_BLOCKS: u32 = 2_000;
pub const COINBASE_MATURITY: u32 = 100;
pub const REGTEST_BITS: u32 = 0x207f_ffff;
pub const GENESIS_TIME: u32 = 1_700_000_000;
pub const BLOCK_INTERVAL: u32 = 600;
pub const SUBSIDY_HALVING_INTERVAL: u32 = 150;
pub const INITIAL_SUBSIDY: u64 = 50 * 100_000_000;
pub const MAX_BLOCK_TRANSACTIONS: u32 = 4;

pub fn subsidy(height: u32) -> u64 {
    INITIAL_SUBSIDY >> (height / SUBSIDY_HALVING_INTERVAL).min(63)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    pub txout: TxOut,
    pub height: u32,
    pub coinbase: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UndoEntry {
    pub outpoint: OutPoint,
    pub coin: Coin,
}

#[derive(Clone, Debug)]
pub struct ChainBlock {
    pub height: u32,
    pub block: Block,
    pub undo: Vec<UndoEntry>,
    pub wire_len: u32,
}

impl ChainBlock {
    pub fn hash(&self) -> BlockHash {
        self.block.block_hash()
    }
}

#[derive(Clone, Debug)]
pub struct Chain {
    pub blocks: Vec<ChainBlock>,
    pub final_set: BTreeMap<OutPoint, Coin>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainSpec {
    pub seed: u64,
    pub blocks: u32,
}

impl ChainSpec {
    pub const fn pinned() -> Self {
        Self {
            seed: PINNED_SEED,
            blocks: PINNED_BLOCKS,
        }
    }
}

pub fn build(spec: ChainSpec) -> Result<Chain, Error> {
    let mut builder = ChainBuilder::new(spec.seed);
    for _ in 0..spec.blocks {
        builder.append_random()?;
    }
    Ok(builder.finish())
}

#[derive(Clone, Debug)]
pub struct ChainBuilder {
    seed: u64,
    rng: SplitMix64,
    blocks: Vec<ChainBlock>,
    live: BTreeMap<OutPoint, Coin>,
    live_txids: BTreeMap<Txid, u32>,
    prev: BlockHash,
    next_height: u32,
}

impl ChainBuilder {
    pub fn new(seed: u64) -> Self {
        let genesis = genesis_block(Network::Regtest);
        let prev = genesis.block_hash();
        Self {
            seed,
            rng: SplitMix64::new(seed),
            blocks: vec![ChainBlock {
                height: 0,
                wire_len: u32::try_from(serialize(&genesis).len()).unwrap_or(u32::MAX),
                block: genesis,
                undo: Vec::new(),
            }],
            live: BTreeMap::new(),
            live_txids: BTreeMap::new(),
            prev,
            next_height: 1,
        }
    }

    pub fn height(&self) -> u32 {
        self.next_height.saturating_sub(1)
    }

    pub fn live(&self) -> &BTreeMap<OutPoint, Coin> {
        &self.live
    }

    pub fn append(&mut self, spends: Vec<Spend>) -> Result<u32, Error> {
        let script = coinbase_script(self.next_height, self.seed);
        self.append_with_coinbase(&script, spends)
    }

    pub fn append_with_coinbase(
        &mut self,
        coinbase_script_sig: &[u8],
        spends: Vec<Spend>,
    ) -> Result<u32, Error> {
        let height = self.next_height;
        let mut resolved = Vec::new();
        let mut fees = 0_u64;
        let mut txs: Vec<Transaction> = Vec::with_capacity(spends.len().saturating_add(1));
        for spend in spends {
            let mut in_sum = 0_u64;
            let mut inputs = Vec::with_capacity(spend.inputs.len());
            for (index, outpoint) in spend.inputs.iter().enumerate() {
                let coin = self
                    .live
                    .get(outpoint)
                    .ok_or_else(|| Error::UnknownPrevout {
                        height,
                        outpoint: outpoint.to_string(),
                    })?;
                in_sum = in_sum
                    .checked_add(coin.txout.value.to_sat())
                    .ok_or_else(|| Error::ValueImbalance {
                        height,
                        txid: "builder input total".to_owned(),
                    })?;
                resolved.push(UndoEntry {
                    outpoint: *outpoint,
                    coin: coin.clone(),
                });
                let witness = spend.witness.get(index).cloned().unwrap_or_default();
                inputs.push(TxIn {
                    previous_output: *outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness,
                });
            }
            let out_sum = spend
                .outputs
                .iter()
                .try_fold(0_u64, |acc, out| acc.checked_add(out.value.to_sat()))
                .ok_or_else(|| Error::ValueImbalance {
                    height,
                    txid: "builder output total".to_owned(),
                })?;
            let fee = in_sum
                .checked_sub(out_sum)
                .ok_or_else(|| Error::ValueImbalance {
                    height,
                    txid: "builder".to_owned(),
                })?;
            fees = fees.checked_add(fee).ok_or_else(|| Error::ValueImbalance {
                height,
                txid: "builder fee total".to_owned(),
            })?;
            txs.push(Transaction {
                version: TxVersion::TWO,
                lock_time: LockTime::ZERO,
                input: inputs,
                output: spend.outputs,
            });
        }
        let coinbase_value = subsidy(height).saturating_add(fees);
        txs.insert(0, coinbase_tx(coinbase_script_sig, coinbase_value));
        let block = mine(self.prev, height, txs)?;
        for entry in &resolved {
            self.live.remove(&entry.outpoint);
            self.decrement_txid(entry.outpoint.txid);
        }
        self.insert_created(height, &block);
        self.prev = block.block_hash();
        self.next_height = height.saturating_add(1);
        self.blocks.push(ChainBlock {
            height,
            wire_len: u32::try_from(serialize(&block).len()).unwrap_or(u32::MAX),
            block,
            undo: resolved,
        });
        Ok(height)
    }

    pub fn append_random(&mut self) -> Result<u32, Error> {
        let height = self.next_height;
        let mut spends = Vec::new();
        let mut selected: BTreeSet<OutPoint> = BTreeSet::new();
        let count = self.rng.below(MAX_BLOCK_TRANSACTIONS.saturating_add(1));
        for _ in 0..count {
            let candidates: Vec<OutPoint> = self
                .live
                .iter()
                .filter(|(outpoint, coin)| {
                    coin.height.saturating_add(COINBASE_MATURITY) <= height
                        && !selected.contains(outpoint)
                })
                .map(|(outpoint, _)| *outpoint)
                .collect();
            if candidates.len() < 2 {
                break;
            }
            let wanted = usize::try_from(1 + self.rng.below(2)).unwrap_or(1);
            let mut inputs = Vec::with_capacity(wanted);
            while inputs.len() < wanted {
                let pick = self
                    .rng
                    .below(u32::try_from(candidates.len()).unwrap_or(u32::MAX));
                let index = usize::try_from(pick).unwrap_or(0).min(candidates.len() - 1);
                let outpoint = candidates[index];
                if !inputs.contains(&outpoint) {
                    inputs.push(outpoint);
                }
            }
            let in_value = inputs.iter().try_fold(0_u64, |acc, outpoint| {
                self.live
                    .get(outpoint)
                    .map(|coin| acc.saturating_add(coin.txout.value.to_sat()))
            });
            let Some(in_value) = in_value else {
                break;
            };
            let outputs = self.random_outputs(in_value);
            let witness = inputs
                .iter()
                .map(|_| self.random_witness())
                .collect::<Vec<_>>();
            selected.extend(inputs.iter().copied());
            spends.push(Spend {
                inputs,
                outputs,
                witness,
            });
        }
        self.append(spends)
    }
    pub fn from_prefix(chain: &Chain, height: u32, seed: u64) -> Result<Self, Error> {
        let Some(last) = usize::try_from(height)
            .ok()
            .and_then(|index| chain.blocks.get(..=index))
        else {
            return Err(Error::InvalidBlock {
                height,
                check: "prefix height",
            });
        };
        let live = replay_final_set(last)?;
        let mut live_txids: BTreeMap<Txid, u32> = BTreeMap::new();
        for outpoint in live.keys() {
            *live_txids.entry(outpoint.txid).or_insert(0) += 1;
        }
        Ok(Self {
            seed,
            rng: SplitMix64::new(seed ^ u64::from(height.saturating_add(1))),
            blocks: last.to_vec(),
            live,
            live_txids,
            prev: last
                .last()
                .map_or_else(BlockHash::all_zeros, ChainBlock::hash),
            next_height: height.saturating_add(1),
        })
    }

    pub fn finish(self) -> Chain {
        Chain {
            blocks: self.blocks,
            final_set: self.live,
        }
    }

    fn random_outputs(&mut self, in_value: u64) -> Vec<TxOut> {
        let split = self.rng.below(2) == 1 && in_value > 10;
        if split {
            let first = in_value / 2;
            let second = in_value - first;
            vec![
                TxOut {
                    value: Amount::from_sat(first),
                    script_pubkey: self.random_script(),
                },
                TxOut {
                    value: Amount::from_sat(second),
                    script_pubkey: self.random_script(),
                },
            ]
        } else {
            vec![TxOut {
                value: Amount::from_sat(in_value),
                script_pubkey: self.random_script(),
            }]
        }
    }

    fn random_script(&mut self) -> ScriptBuf {
        let mut hash = self.rng.bytes::<20>();
        hash[0] = 0x00;
        let mut script = Vec::with_capacity(22);
        script.extend_from_slice(&[0x00, 0x14]);
        script.extend_from_slice(&hash);
        ScriptBuf::from_bytes(script)
    }

    fn random_witness(&mut self) -> Witness {
        let signature = self.rng.bytes::<71>();
        let pubkey = self.rng.bytes::<33>();
        Witness::from_slice(&[signature.as_slice(), pubkey.as_slice()])
    }

    fn insert_created(&mut self, height: u32, block: &Block) {
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            let coinbase = tx.is_coinbase();
            *self.live_txids.entry(txid).or_insert(0) += 1;
            for (vout, txout) in tx.output.iter().enumerate() {
                let Ok(vout) = u32::try_from(vout) else {
                    continue;
                };
                self.live.insert(
                    OutPoint { txid, vout },
                    Coin {
                        txout: txout.clone(),
                        height,
                        coinbase,
                    },
                );
            }
        }
    }

    fn decrement_txid(&mut self, txid: Txid) {
        let Some(count) = self.live_txids.get_mut(&txid) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            self.live_txids.remove(&txid);
        }
    }
}

#[derive(Clone, Debug)]
pub struct Spend {
    pub inputs: Vec<OutPoint>,
    pub outputs: Vec<TxOut>,
    pub witness: Vec<Witness>,
}

impl Spend {
    pub fn new(inputs: Vec<OutPoint>, outputs: Vec<TxOut>) -> Self {
        Self {
            inputs,
            outputs,
            witness: Vec::new(),
        }
    }
}

pub fn coinbase_script(height: u32, salt: u64) -> Vec<u8> {
    let mut script = Vec::with_capacity(13);
    script.push(0x04);
    script.extend_from_slice(&height.to_le_bytes());
    script.extend_from_slice(&salt.to_le_bytes());
    script
}

pub fn coinbase_tx(script_sig: &[u8], value: u64) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(script_sig.to_vec()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

pub fn mine(prev: BlockHash, height: u32, txs: Vec<Transaction>) -> Result<Block, Error> {
    let mut block = Block {
        header: Header {
            version: BlockVersion::from_consensus(0x2000_0000),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: GENESIS_TIME.saturating_add(height.saturating_mul(BLOCK_INTERVAL)),
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        },
        txdata: txs,
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or(Error::EmptyBlock { height })?;
    let target = Target::from_compact(block.header.bits);
    while block.header.validate_pow(target).is_err() {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    Ok(block)
}

impl Chain {
    pub fn height(&self) -> u32 {
        self.blocks.last().map_or(0, |block| block.height)
    }

    pub fn tip(&self) -> BlockHash {
        self.blocks
            .last()
            .map_or_else(BlockHash::all_zeros, ChainBlock::hash)
    }

    pub fn transaction_count(&self) -> u64 {
        self.blocks
            .iter()
            .map(|block| u64::try_from(block.block.txdata.len()).unwrap_or(u64::MAX))
            .sum()
    }

    pub fn validate(&self) -> Result<(), Error> {
        let mut state = ValidateState::default();
        for (index, carried) in self.blocks.iter().enumerate() {
            let height = u32::try_from(index).map_err(|_| Error::InvalidBlock {
                height: u32::MAX,
                check: "height order",
            })?;
            state.apply(carried, height)?;
        }
        Ok(())
    }

    pub fn write(&self, path: &Path) -> Result<(), Error> {
        let mut text = String::with_capacity(1 << 22);
        text.push_str("swiftsync-chain 1\n");
        text.push_str(&format!("seed {}\n", hex_u64(PINNED_SEED)));
        text.push_str(&format!("blocks {}\n", self.blocks.len()));
        for carried in &self.blocks {
            text.push_str(&format!(
                "block {} {} {}\n",
                carried.height,
                carried.hash(),
                hex_encode(&serialize(&carried.block)),
            ));
            text.push_str(&format!("undo {} {}\n", carried.height, carried.undo.len()));
            for entry in &carried.undo {
                text.push_str(&format!(
                    "{} {} {} {} {}\n",
                    entry.outpoint.txid,
                    entry.outpoint.vout,
                    entry.coin.height,
                    u8::from(entry.coin.coinbase),
                    hex_encode(&serialize(&entry.coin.txout)),
                ));
            }
        }
        std::fs::write(path, text).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn read(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut lines = text.lines().enumerate();
        let expect = |line: &str, want: &str, index: usize| {
            if line == want {
                Ok(())
            } else {
                Err(Error::ChainFormat {
                    line: index.saturating_add(1),
                    reason: format!("expected `{want}`"),
                })
            }
        };
        let Some((index, header)) = lines.next() else {
            return Err(Error::ChainFormat {
                line: 1,
                reason: "empty file".to_owned(),
            });
        };
        expect(header, "swiftsync-chain 1", index)?;
        let Some((index, seed_line)) = lines.next() else {
            return Err(Error::ChainFormat {
                line: 2,
                reason: "missing seed".to_owned(),
            });
        };
        if !seed_line.starts_with("seed ") {
            return Err(Error::ChainFormat {
                line: index.saturating_add(1),
                reason: "expected `seed <hex>`".to_owned(),
            });
        }
        let Some((index, count_line)) = lines.next() else {
            return Err(Error::ChainFormat {
                line: 3,
                reason: "missing block count".to_owned(),
            });
        };
        let count = parse_field::<usize>(count_line, "blocks", index.saturating_add(1))?;
        let mut blocks: Vec<ChainBlock> = Vec::with_capacity(count);
        while let Some((index, line)) = lines.next() {
            let line_number = index.saturating_add(1);
            let fields: Vec<&str> = line.split(' ').collect();
            if fields.len() != 4 || fields[0] != "block" {
                return Err(Error::ChainFormat {
                    line: line_number,
                    reason: "expected `block <height> <hash> <hex>`".to_owned(),
                });
            }
            let height = parse_str::<u32>(fields[1], line_number)?;
            let bytes = hex_decode(fields[3]).map_err(|error| Error::ChainFormat {
                line: line_number,
                reason: error.to_string(),
            })?;
            let block: Block = deserialize(&bytes).map_err(|error| Error::ChainFormat {
                line: line_number,
                reason: format!("block bytes: {error}"),
            })?;
            let Some((undo_index, undo_line)) = lines.next() else {
                return Err(Error::ChainFormat {
                    line: line_number,
                    reason: "missing undo section".to_owned(),
                });
            };
            let undo_line_number = undo_index.saturating_add(1);
            let undo_fields: Vec<&str> = undo_line.split(' ').collect();
            if undo_fields.len() != 3 || undo_fields[0] != "undo" {
                return Err(Error::ChainFormat {
                    line: undo_line_number,
                    reason: "expected `undo <height> <count>`".to_owned(),
                });
            }
            let undo_count = parse_str::<usize>(undo_fields[2], undo_line_number)?;
            let mut undo = Vec::with_capacity(undo_count);
            for _ in 0..undo_count {
                let Some((entry_index, entry_line)) = lines.next() else {
                    return Err(Error::ChainFormat {
                        line: undo_line_number,
                        reason: "truncated undo section".to_owned(),
                    });
                };
                let entry_line_number = entry_index.saturating_add(1);
                undo.push(parse_undo_entry(entry_line, entry_line_number)?);
            }
            blocks.push(ChainBlock {
                height,
                wire_len: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
                block,
                undo,
            });
        }
        if blocks.len() != count {
            return Err(Error::ChainFormat {
                line: 3,
                reason: format!("file declares {count} blocks but carries {}", blocks.len()),
            });
        }
        let final_set = replay_final_set(&blocks)?;
        Ok(Self { blocks, final_set })
    }
}

#[derive(Default)]
struct ValidateState {
    live: BTreeMap<OutPoint, Coin>,
    live_txids: BTreeMap<Txid, u32>,
    prev: Option<BlockHash>,
}

impl ValidateState {
    fn apply(&mut self, carried: &ChainBlock, height: u32) -> Result<(), Error> {
        if carried.height != height {
            return Err(Error::InvalidBlock {
                height,
                check: "height order",
            });
        }
        self.check_header(carried, height)?;
        if height == 0 {
            self.prev = Some(carried.hash());
            return Ok(());
        }
        let resolved = self.resolve_spends(carried, height)?;
        Self::check_undo(carried, height, &resolved)?;
        self.mutate(carried, height, &resolved)
    }

    fn check_header(&self, carried: &ChainBlock, height: u32) -> Result<(), Error> {
        let block = &carried.block;
        if block.header.bits.to_consensus() != REGTEST_BITS {
            return Err(Error::InvalidBlock {
                height,
                check: "difficulty bits",
            });
        }
        let target = Target::from_compact(CompactTarget::from_consensus(REGTEST_BITS));
        if block.header.validate_pow(target).is_err() {
            return Err(Error::InvalidBlock {
                height,
                check: "proof of work",
            });
        }
        if !block.check_merkle_root() {
            return Err(Error::InvalidBlock {
                height,
                check: "merkle root",
            });
        }
        if let Some(expected) = self.prev {
            if block.header.prev_blockhash != expected {
                return Err(Error::InvalidBlock {
                    height,
                    check: "previous block hash",
                });
            }
        }
        if height == 0 && block.block_hash() != genesis_block(Network::Regtest).block_hash() {
            return Err(Error::InvalidBlock {
                height,
                check: "regtest genesis",
            });
        }
        Ok(())
    }

    fn resolve_spends(
        &self,
        carried: &ChainBlock,
        height: u32,
    ) -> Result<Vec<(OutPoint, Coin)>, Error> {
        let coinbase = coinbase_transaction(&carried.block, height)?;
        let mut resolved = Vec::new();
        let mut spent: BTreeSet<OutPoint> = BTreeSet::new();
        let mut created_here: BTreeSet<OutPoint> = BTreeSet::new();
        let mut fees = 0_u64;
        for tx in carried.block.txdata.iter().skip(1) {
            let fee =
                self.resolve_transaction(tx, height, &mut spent, &mut created_here, &mut resolved)?;
            fees = fees.checked_add(fee).ok_or_else(|| Error::ValueImbalance {
                height,
                txid: tx.compute_txid().to_string(),
            })?;
        }
        check_coinbase_value(coinbase, height, fees)?;
        Ok(resolved)
    }

    fn resolve_transaction(
        &self,
        tx: &Transaction,
        height: u32,
        spent: &mut BTreeSet<OutPoint>,
        created_here: &mut BTreeSet<OutPoint>,
        resolved: &mut Vec<(OutPoint, Coin)>,
    ) -> Result<u64, Error> {
        let txid = tx.compute_txid();
        let mut in_sum = 0_u64;
        for input in &tx.input {
            let outpoint = input.previous_output;
            if created_here.contains(&outpoint) {
                return Err(Error::InvalidBlock {
                    height,
                    check: "same-block spend",
                });
            }
            if !spent.insert(outpoint) {
                return Err(Error::InvalidBlock {
                    height,
                    check: "duplicate input",
                });
            }
            let coin = self
                .live
                .get(&outpoint)
                .ok_or_else(|| Error::UnknownPrevout {
                    height,
                    outpoint: outpoint.to_string(),
                })?;
            if coin.coinbase && coin.height.saturating_add(COINBASE_MATURITY) > height {
                return Err(Error::InvalidBlock {
                    height,
                    check: "coinbase maturity",
                });
            }
            in_sum = in_sum
                .checked_add(coin.txout.value.to_sat())
                .ok_or_else(|| Error::ValueImbalance {
                    height,
                    txid: txid.to_string(),
                })?;
            resolved.push((outpoint, coin.clone()));
        }
        let out_sum = sum_outputs(tx).ok_or_else(|| Error::ValueImbalance {
            height,
            txid: txid.to_string(),
        })?;
        let fee = in_sum
            .checked_sub(out_sum)
            .ok_or_else(|| Error::ValueImbalance {
                height,
                txid: txid.to_string(),
            })?;
        for (vout, _) in tx.output.iter().enumerate() {
            let Ok(vout) = u32::try_from(vout) else {
                return Err(Error::InvalidBlock {
                    height,
                    check: "output index",
                });
            };
            created_here.insert(OutPoint { txid, vout });
        }
        Ok(fee)
    }

    fn check_undo(
        carried: &ChainBlock,
        height: u32,
        resolved: &[(OutPoint, Coin)],
    ) -> Result<(), Error> {
        if carried.undo.len() != resolved.len() {
            return Err(Error::UndoLength {
                height,
                carried: carried.undo.len(),
                resolved: resolved.len(),
            });
        }
        for (index, (entry, (outpoint, coin))) in carried.undo.iter().zip(resolved).enumerate() {
            if entry.outpoint == *outpoint
                && entry.coin.txout == coin.txout
                && entry.coin.height == coin.height
                && entry.coin.coinbase == coin.coinbase
            {
                continue;
            }
            return Err(Error::UndoMismatch {
                height,
                index,
                found: format!("{} {}", entry.outpoint, entry.coin.height),
                expected: format!("{outpoint} {}", coin.height),
            });
        }
        Ok(())
    }

    fn mutate(
        &mut self,
        carried: &ChainBlock,
        height: u32,
        resolved: &[(OutPoint, Coin)],
    ) -> Result<(), Error> {
        for (outpoint, _) in resolved {
            self.live.remove(outpoint);
            let Some(count) = self.live_txids.get_mut(&outpoint.txid) else {
                continue;
            };
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.live_txids.remove(&outpoint.txid);
            }
        }
        for tx in &carried.block.txdata {
            let txid = tx.compute_txid();
            if self.live_txids.get(&txid).is_some_and(|count| *count > 0) {
                return Err(Error::InvalidBlock {
                    height,
                    check: "duplicate txid",
                });
            }
            let coinbase = tx.is_coinbase();
            *self.live_txids.entry(txid).or_insert(0) += 1;
            for (vout, txout) in tx.output.iter().enumerate() {
                let Ok(vout) = u32::try_from(vout) else {
                    return Err(Error::InvalidBlock {
                        height,
                        check: "output index",
                    });
                };
                self.live.insert(
                    OutPoint { txid, vout },
                    Coin {
                        txout: txout.clone(),
                        height,
                        coinbase,
                    },
                );
            }
        }
        self.prev = Some(carried.hash());
        Ok(())
    }
}
fn coinbase_transaction(block: &Block, height: u32) -> Result<&Transaction, Error> {
    let Some(coinbase) = block.txdata.first() else {
        return Err(Error::EmptyBlock { height });
    };
    if !coinbase.is_coinbase() {
        return Err(Error::InvalidBlock {
            height,
            check: "coinbase position",
        });
    }
    if block.txdata.iter().filter(|tx| tx.is_coinbase()).count() != 1 {
        return Err(Error::InvalidBlock {
            height,
            check: "coinbase count",
        });
    }
    Ok(coinbase)
}

fn sum_outputs(tx: &Transaction) -> Option<u64> {
    tx.output
        .iter()
        .try_fold(0_u64, |acc, out| acc.checked_add(out.value.to_sat()))
}

fn check_coinbase_value(coinbase: &Transaction, height: u32, fees: u64) -> Result<(), Error> {
    let coinbase_out = sum_outputs(coinbase).ok_or(Error::InvalidBlock {
        height,
        check: "coinbase value",
    })?;
    if coinbase_out > subsidy(height).saturating_add(fees) {
        return Err(Error::InvalidBlock {
            height,
            check: "coinbase value",
        });
    }
    Ok(())
}
pub fn replay_final_set(blocks: &[ChainBlock]) -> Result<BTreeMap<OutPoint, Coin>, Error> {
    let mut live: BTreeMap<OutPoint, Coin> = BTreeMap::new();
    for carried in blocks {
        if carried.height == 0 {
            continue;
        }
        for tx in &carried.block.txdata {
            if tx.is_coinbase() {
                continue;
            }
            for input in &tx.input {
                let outpoint = input.previous_output;
                if live.remove(&outpoint).is_none() {
                    return Err(Error::UnknownPrevout {
                        height: carried.height,
                        outpoint: outpoint.to_string(),
                    });
                }
            }
        }
        for tx in &carried.block.txdata {
            let txid = tx.compute_txid();
            let coinbase = tx.is_coinbase();
            for (vout, txout) in tx.output.iter().enumerate() {
                let Ok(vout) = u32::try_from(vout) else {
                    return Err(Error::UnknownPrevout {
                        height: carried.height,
                        outpoint: format!("{txid}:{vout}"),
                    });
                };
                live.insert(
                    OutPoint { txid, vout },
                    Coin {
                        txout: txout.clone(),
                        height: carried.height,
                        coinbase,
                    },
                );
            }
        }
    }
    Ok(live)
}

fn parse_undo_entry(line: &str, line_number: usize) -> Result<UndoEntry, Error> {
    let fields: Vec<&str> = line.split(' ').collect();
    if fields.len() != 5 {
        return Err(Error::ChainFormat {
            line: line_number,
            reason: "expected `<txid> <vout> <height> <0|1> <txout>`".to_owned(),
        });
    }
    let txid = parse_str::<Txid>(fields[0], line_number)?;
    let vout = parse_str::<u32>(fields[1], line_number)?;
    let height = parse_str::<u32>(fields[2], line_number)?;
    let coinbase = match parse_str::<u8>(fields[3], line_number)? {
        0 => false,
        1 => true,
        other => {
            return Err(Error::ChainFormat {
                line: line_number,
                reason: format!("coinbase flag {other}"),
            });
        }
    };
    let bytes = hex_decode(fields[4]).map_err(|error| Error::ChainFormat {
        line: line_number,
        reason: error.to_string(),
    })?;
    let txout: TxOut = deserialize(&bytes).map_err(|error| Error::ChainFormat {
        line: line_number,
        reason: format!("txout bytes: {error}"),
    })?;
    Ok(UndoEntry {
        outpoint: OutPoint { txid, vout },
        coin: Coin {
            txout,
            height,
            coinbase,
        },
    })
}

fn parse_field<T: std::str::FromStr>(
    line: &str,
    name: &str,
    line_number: usize,
) -> Result<T, Error> {
    let rest = line
        .strip_prefix(name)
        .and_then(|tail| tail.strip_prefix(' '))
        .ok_or_else(|| Error::ChainFormat {
            line: line_number,
            reason: format!("expected `{name} <value>`"),
        })?;
    parse_str::<T>(rest, line_number)
}

fn parse_str<T: std::str::FromStr>(text: &str, line_number: usize) -> Result<T, Error> {
    text.parse::<T>().map_err(|_| Error::ChainFormat {
        line: line_number,
        reason: format!("cannot parse `{text}`"),
    })
}

pub fn hex_u64(value: u64) -> String {
    format!("{value:016x}")
}

#[derive(Clone, Debug)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u32) -> u32 {
        let [b0, b1, b2, b3, _, _, _, _] = self.next_u64().to_le_bytes();
        u32::from_le_bytes([b0, b1, b2, b3]) % bound.max(1)
    }

    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0_u8; N];
        for chunk in out.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        out
    }
}
