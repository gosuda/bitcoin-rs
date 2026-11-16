#![no_main]

use bitcoin_rs_consensus::compute_merkle_root;
use bitcoin_rs_consensus::primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness, consensus_bytes, deserialize,
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

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let slice = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn take_upto(&mut self, len: usize) -> &'a [u8] {
        let end = self.bytes.len().min(self.pos.saturating_add(len));
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        slice
    }

    fn array<const N: usize>(&mut self, fallback: [u8; N]) -> [u8; N] {
        match self.take(N) {
            Some(slice) => {
                let mut out = [0_u8; N];
                out.copy_from_slice(slice);
                out
            }
            None => fallback,
        }
    }

    fn u32_or(&mut self, fallback: u32) -> u32 {
        u32::from_le_bytes(self.array(fallback.to_le_bytes()))
    }

    fn u64_or(&mut self, fallback: u64) -> u64 {
        u64::from_le_bytes(self.array(fallback.to_le_bytes()))
    }
}

fn generate_tx(cursor: &mut Cursor<'_>, index: usize) -> Tx {
    let version = u32::from(cursor.byte_or(2) & 1) + 1;
    let lock_time = LockTime::from_consensus(cursor.u32_or(0));
    let input_count = if index == 0 {
        1
    } else {
        1 + usize::from(cursor.byte_or(0) % 4)
    };
    let mut inputs = Vec::with_capacity(input_count);
    for input_index in 0..input_count {
        let previous_output = if index == 0 && input_index == 0 {
            OutPoint::null()
        } else {
            let txid = Hash256::from_le_bytes(&cursor.array([0_u8; 32]));
            OutPoint::new(Txid(txid), cursor.u32_or(0))
        };
        let script_len = usize::from(cursor.byte_or(0) % 24);
        let script_sig = Script::from_bytes(cursor.take_upto(script_len).to_vec());
        let sequence = Sequence::from_consensus(cursor.u32_or(u32::MAX));
        let item_count = usize::from(cursor.byte_or(0) % 4);
        let mut stack = Vec::with_capacity(item_count);
        for _ in 0..item_count {
            let item_len = usize::from(cursor.byte_or(0) % 16);
            stack.push(cursor.take_upto(item_len).to_vec());
        }
        inputs.push(TxIn {
            previous_output,
            script_sig,
            sequence,
            witness: Witness::from_stack(stack),
        });
    }
    let output_count = usize::from(cursor.byte_or(1) % 4);
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let value = Amount::from_sat(cursor.u64_or(0));
        let script_len = usize::from(cursor.byte_or(0) % 32);
        let script_pubkey = Script::from_bytes(cursor.take_upto(script_len).to_vec());
        outputs.push(TxOut {
            value,
            script_pubkey,
        });
    }
    Tx {
        version,
        inputs,
        outputs,
        lock_time,
    }
}

fn generate_block(cursor: &mut Cursor<'_>) -> Block {
    let mut header = Header {
        version: i32::from_le_bytes(cursor.array([4_u8, 0, 0, 0])),
        prev_blockhash: BlockHash(Hash256::from_le_bytes(&cursor.array([0_u8; 32]))),
        merkle_root: Hash256::default(),
        time: cursor.u32_or(0),
        bits: CompactTarget::from_consensus(cursor.u32_or(0x207f_ffff)),
        nonce: cursor.u32_or(0),
    };
    let tx_count = usize::from(cursor.byte_or(0) % 8);
    let mut txs = Vec::with_capacity(tx_count);
    for index in 0..tx_count {
        txs.push(generate_tx(cursor, index));
    }
    let mut leaves: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    if let Some(root) = compute_merkle_root(&mut leaves) {
        header.merkle_root = Hash256::from_le_bytes(&root);
    }
    Block { header, txs }
}

fn mutate(cursor: &mut Cursor<'_>, mut wire: Vec<u8>) -> Vec<u8> {
    for _ in 0..32 {
        let Some(op) = cursor.next() else {
            break;
        };
        if wire.is_empty() {
            break;
        }
        let len = wire.len();
        let position = |cursor: &mut Cursor<'_>| -> usize {
            usize::from(cursor.byte_or(0)) % len
        };
        match op % 4 {
            0 => {
                let index = position(cursor);
                let bit = cursor.byte_or(0) % 8;
                wire[index] ^= 1 << bit;
            }
            1 => {
                let index = position(cursor);
                wire[index] = cursor.byte_or(0);
            }
            2 => {
                let index = position(cursor);
                wire.truncate(index);
            }
            _ => {
                let first = position(cursor);
                let second = usize::from(cursor.byte_or(0)) % len;
                wire.swap(first, second);
            }
        }
    }
    wire
}

fn check_decoded(wire: &[u8]) {
    let Ok(block) = deserialize::<Block>(wire) else {
        return;
    };
    let canonical = consensus_bytes(&block);
    assert_eq!(canonical, wire, "accepted block must re-encode canonically");
    let re_decoded = deserialize::<Block>(&canonical).expect("canonical bytes must decode");
    assert_eq!(re_decoded, block, "canonical decode must be stable");
    assert_eq!(
        consensus_bytes(&re_decoded),
        canonical,
        "canonical re-encode must be idempotent"
    );
    assert!(
        block.retained_heap_bytes() <= 64 * wire.len(),
        "decoded block retains more than 64x its wire length"
    );
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let block = generate_block(&mut cursor);
    let encoded = consensus_bytes(&block);
    let decoded = deserialize::<Block>(&encoded).expect("generated block must decode");
    assert_eq!(decoded, block, "decode(encode(x)) must equal x");
    assert_eq!(
        consensus_bytes(&decoded),
        encoded,
        "generated block must re-encode canonically"
    );
    let mutated = mutate(&mut cursor, encoded);
    check_decoded(&mutated);
});
