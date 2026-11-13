#![no_main]

use std::collections::HashMap;

use bitcoin_rs_execution::chain::ChainTxCount;
use bitcoin_rs_execution::chain::regtest_fixture::{
    genesis_time, mined_block_with_prev_hash, mined_regtest_child_at_time, script_num_push,
};
use bitcoin_rs_execution::fuzzing::{FuzzChain, FuzzCheckpoint};
use bitcoin_rs_consensus::{MAX_SCRIPT_SIZE, block_subsidy};
use bitcoin_rs_consensus::primitives::{
    Amount, Block, BlockHash, Hash256, Header, LockTime, Network, OutPoint, Script, Sequence, Tx,
    TxIn, TxOut, Witness,
};
use libfuzzer_sys::fuzz_target;

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn next(&mut self) -> Option<u8> {
        let byte = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    fn byte_or(&mut self, fallback: u8) -> u8 {
        self.next().unwrap_or(fallback)
    }

    fn take_upto(&mut self, len: usize) -> &'a [u8] {
        let end = self.bytes.len().min(self.pos.saturating_add(len));
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        slice
    }
}

struct Model {
    genesis: Header,
    tip: Header,
    height: u32,
    coins: HashMap<OutPoint, TxOut>,
    tx_count: u64,
    blocks: Vec<Block>,
}

impl Model {
    fn new(genesis: &Block) -> Self {
        Self {
            genesis: genesis.header,
            tip: genesis.header,
            height: 0,
            coins: HashMap::new(),
            tx_count: u64::try_from(genesis.txs.len()).expect("genesis size"),
            blocks: Vec::new(),
        }
    }

    fn tip_hash(&self) -> Hash256 {
        Hash256::from(self.tip.compute_hash())
    }

    fn connect(&mut self, block: &Block) {
        assert_eq!(
            block.txs.len(),
            1,
            "the reorg model only connects single-transaction blocks"
        );
        let tx = &block.txs[0];
        let txid = tx.txid();
        for (vout, output) in tx.outputs.iter().enumerate() {
            if !stored_output(output) {
                continue;
            }
            let vout = u32::try_from(vout).expect("output index fits");
            self.coins
                .insert(OutPoint::new(txid, vout), output.clone());
        }
        self.tx_count = self
            .tx_count
            .checked_add(u64::try_from(block.txs.len()).expect("tx count"))
            .expect("tx count does not overflow");
        self.height = self.height.checked_add(1).expect("height does not overflow");
        self.tip = block.header;
        self.blocks.push(block.clone());
    }

    fn disconnect(&mut self, block: &Block) {
        let tx = &block.txs[0];
        let txid = tx.txid();
        for (vout, output) in tx.outputs.iter().enumerate() {
            if !stored_output(output) {
                continue;
            }
            let vout = u32::try_from(vout).expect("output index fits");
            self.coins.remove(&OutPoint::new(txid, vout));
        }
        self.tx_count = self
            .tx_count
            .checked_sub(u64::try_from(block.txs.len()).expect("tx count"))
            .expect("tx count does not underflow");
        self.height = self.height.checked_sub(1).expect("height does not underflow");
        self.blocks.pop();
        self.tip = self
            .blocks
            .last()
            .map_or(self.genesis, |previous| previous.header);
    }
}

/// Outputs whose script is provably unspendable never enter the UTXO set.
fn stored_output(output: &TxOut) -> bool {
    output.script_pubkey.as_bytes().first() != Some(&0x6a)
        && output.script_pubkey.len() <= MAX_SCRIPT_SIZE
}

fn assert_state(chain: &FuzzChain, model: &Model) {
    let tip = chain.applied_tip().expect("an applied tip must be published");
    assert_eq!(tip.height, model.height, "applied height must track the model");
    assert_eq!(tip.hash, model.tip_hash(), "applied tip must track the model");
    assert_eq!(
        tip.chain_tx_count,
        ChainTxCount::established(model.tx_count),
        "chain transaction count must track the model"
    );
    let utxo = chain.utxo();
    assert_eq!(
        utxo.with_stable_view(|view| view.len())
            .expect("the model's committed coin state must be readable"),
        model.coins.len(),
        "utxo output count must track the model"
    );
    for (outpoint, output) in &model.coins {
        match utxo.get(outpoint) {
            Ok(Some(found)) => assert_eq!(
                &found, output,
                "utxo entry {outpoint:?} must track the model"
            ),
            other => panic!("utxo entry {outpoint:?} must track the model: got {other:?}"),
        }
    }
}

fn coinbase(height: u32, extra: &[u8], outputs: Vec<TxOut>) -> Tx {
    let mut script_sig = script_num_push(i64::from(height));
    script_sig.extend_from_slice(extra);
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(script_sig),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs,
    }
}

fn valid_block(model: &Model, cursor: &mut Cursor<'_>) -> Block {
    let height = model.height + 1;
    let output_count = 1 + usize::from(cursor.byte_or(0) % 3);
    let subsidy = block_subsidy(
        height,
        Network::Regtest.subsidy_halving_interval(),
    );
    let share = subsidy / u64::try_from(output_count).expect("output count");
    let mut outputs = Vec::with_capacity(output_count);
    for index in 0..output_count {
        let script_len = usize::from(cursor.byte_or(0) % 8);
        let script_pubkey = Script::from_bytes(cursor.take_upto(script_len).to_vec());
        let value = if index + 1 == output_count {
            subsidy - share * u64::try_from(output_count - 1).expect("output count")
        } else {
            share
        };
        outputs.push(TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        });
    }
    let extra_len = usize::from(cursor.byte_or(0) % 16);
    let extra = cursor.take_upto(extra_len).to_vec();
    let parent = BlockHash(model.tip_hash());
    mined_block_with_prev_hash(parent, height, vec![coinbase(height, &extra, outputs)])
        .expect("regtest fixture must mine")
}

fn connect(chain: &FuzzChain, model: &mut Model, block: &Block) {
    if chain.apply(block).is_ok() {
        model.connect(block);
    }
}

fuzz_target!(|data: &[u8]| {
    let network = Network::Regtest;
    let genesis = network.genesis_block();
    let mut chain = FuzzChain::new(network).expect("in-memory chainstate must open");
    let mut model = Model::new(&genesis);
    assert_state(&chain, &model);

    let mut cursor = Cursor::new(data);
    let mut checkpoint: Option<FuzzCheckpoint> = None;
    let mut can_reopen = false;
    while let Some(op) = cursor.next() {
        match op % 6 {
            0 | 1 => {
                let block = valid_block(&model, &mut cursor);
                connect(&chain, &mut model, &block);
            }
            2 => {
                if let Some(block) = model.blocks.last().cloned()
                    && chain.disconnect(&block).is_ok()
                {
                    model.disconnect(&block);
                    can_reopen = false;
                }
            }
            3 => {
                let flushed = chain.flush().expect("a quiescent chain must flush its durable head");
                assert_eq!(flushed.tip().height, model.height, "flush tip height");
                assert_eq!(flushed.tip().hash, model.tip_hash(), "flush tip hash");
                assert_eq!(
                    flushed.coin_count(),
                    model.coins.len(),
                    "flush coin count"
                );
                checkpoint = Some(flushed);
                can_reopen = true;
            }
            4 => {
                if can_reopen && let Some(flushed) = checkpoint.take() {
                    chain = chain.reopen(&flushed).expect("reopen must restore the durable head");
                }
            }
            _ => {
                let height = model.height + 1;
                let stale = mined_regtest_child_at_time(
                    BlockHash(model.tip_hash()),
                    genesis_time(),
                    height,
                )
                .expect("regtest fixture must mine");
                connect(&chain, &mut model, &stale);
            }
        }
        assert_state(&chain, &model);
    }
});
