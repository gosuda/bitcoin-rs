//! Undo coverage for deterministic block disconnects.
use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{BlockChanges, UndoBatch, UtxoAdd, UtxoSet, aggregate_hash};

fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(9).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0xd6e8_feb8_6659_fd93).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0xfeed_face_cafe_beef).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txout(seed: u64) -> TxOut {
    let mut script = Vec::with_capacity(10);
    script.extend_from_slice(&[0x00, 0x08]);
    script.extend_from_slice(&seed.to_le_bytes());
    TxOut {
        value: Amount::from_sat(50_000 + seed),
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

fn build_blocks() -> Result<Vec<(BlockChanges, UndoBatch)>, Box<dyn std::error::Error>> {
    let mut live: Vec<UtxoAdd> = Vec::new();
    let mut blocks = Vec::with_capacity(10);

    for height in 1_u32..=10 {
        let mut changes = BlockChanges::default();
        let mut undo = UndoBatch::default();

        let remove_count = live.len().min(50);
        for _ in 0..remove_count {
            let add = live.remove(0);
            changes.remove(add.outpoint);
            undo.restore(add);
        }

        for n in 0_u64..100 {
            let seed = u64::from(height) * 1_000 + n;
            let outpoint = OutPoint::new(txid(seed), u32::try_from(n % 3)?);
            let txout = txout(seed);
            let add = UtxoAdd::new(outpoint, txout, height == 1, height);
            live.push(add.clone());
            changes.add(add);
            undo.remove(outpoint);
        }

        blocks.push((changes, undo));
    }

    Ok(blocks)
}

#[test]
fn undoing_last_five_blocks_matches_first_five_only_state() -> Result<(), Box<dyn std::error::Error>>
{
    let blocks = build_blocks()?;
    let full = UtxoSet::new();

    for (height, (changes, _undo)) in (1_u64..=10).zip(&blocks) {
        full.commit_block(changes, &txid(height))?;
    }
    for (_changes, undo) in blocks.iter().rev().take(5) {
        full.undo_block(undo)?;
    }

    let first_five = UtxoSet::new();
    for (height, (changes, _undo)) in (1_u64..=5).zip(&blocks) {
        first_five.commit_block(changes, &txid(height))?;
    }

    assert_eq!(aggregate_hash(&full)?, aggregate_hash(&first_five)?);
    assert_eq!(full.len(), first_five.len());

    Ok(())
}
