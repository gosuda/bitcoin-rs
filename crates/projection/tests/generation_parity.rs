use bitcoin_rs_projection::segment::bulk_builder::BulkSegmentBuilder;
use bitcoin_rs_projection::segment::{TailWriterState, append_tail_block, seal_tail_generation};
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, SpentPrevout, TxFacts};
use bitcoin_rs_storage::{Bytes, ColumnFamily, KvStore, RocksDbStore};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use crate::support::TestError;
fn create_synthetic_blocks(count: u32) -> Vec<CommittedBlock> {
    let Ok(capacity) = usize::try_from(count) else {
        return Vec::new();
    };
    let mut blocks = Vec::with_capacity(capacity);
    for h in 1..=count {
        let mut hash = [0u8; 32];
        hash[..4].copy_from_slice(&h.to_be_bytes());
        hash[31] = 0xAA;

        let mut txs = Vec::new();
        for t in 0..5u32 {
            let mut txid = [0u8; 32];
            txid[..4].copy_from_slice(&h.to_be_bytes());
            txid[4..8].copy_from_slice(&t.to_be_bytes());

            let mut inputs = Vec::new();
            if t > 0 {
                let mut prev_txid = [0u8; 32];
                prev_txid[..4].copy_from_slice(&h.to_be_bytes());
                prev_txid[4..8].copy_from_slice(&(t.saturating_sub(1)).to_be_bytes());
                inputs.push(SpentPrevout {
                    txid: prev_txid,
                    vout: 0,
                    value: 50_000,
                    script: Bytes::copy_from_slice(b"\x76\xa9\x14synthetic_prev_script\x88\xac"),
                    height: 0,
                    coinbase: false,
                });
            }

            let outputs = vec![
                CreatedOutput {
                    vout: 0,
                    value: 50_000,
                    script: Bytes::copy_from_slice(b"\x76\xa9\x14synthetic_output_script\x88\xac"),
                },
                CreatedOutput {
                    vout: 1,
                    value: 25_000,
                    script: Bytes::copy_from_slice(b"\x00\x14synthetic_witness_script"),
                },
            ];

            txs.push(TxFacts {
                txid,
                offset: t.saturating_mul(100),
                len: 90,
                inputs,
                outputs,
            });
        }

        blocks.push(CommittedBlock {
            height: h,
            hash,
            parent_hash: [0u8; 32],
            header: [0u8; 80],
            txs,
        });
    }
    blocks
}

fn hash_cf_entry(hasher: &mut Sha256, k: &[u8], v: &[u8]) {
    let Ok(k_len) = u32::try_from(k.len()) else {
        return;
    };
    let Ok(v_len) = u32::try_from(v.len()) else {
        return;
    };
    hasher.update(k_len.to_le_bytes());
    hasher.update(k);
    hasher.update(v_len.to_le_bytes());
    hasher.update(v);
}

fn compute_family_digest<S: KvStore>(store: &S, cf: ColumnFamily, gen_id: u64) -> [u8; 32] {
    let start = gen_id.to_be_bytes();
    let end = gen_id.saturating_add(1).to_be_bytes();
    let mut hasher = Sha256::new();
    let Ok(snapshot) = store.snapshot() else {
        return hasher.finalize().into();
    };
    let Ok(iter) = snapshot.iter_prefix(cf, &start) else {
        return hasher.finalize().into();
    };
    for item in iter {
        let Ok((k, v)) = item else {
            continue;
        };
        if k.as_slice() >= end.as_slice() {
            break;
        }
        hash_cf_entry(&mut hasher, &k, &v);
    }
    hasher.finalize().into()
}

// PRJ-09
#[test]
fn bulk_and_live_generations_are_byte_identical() -> Result<(), TestError> {
    let blocks = create_synthetic_blocks(50);
    let gen_id = 1u64;
    let dir_b = tempdir()?;
    let scratch_b = tempdir()?;
    let store_b = RocksDbStore::open(dir_b.path())?;
    let builder_b = BulkSegmentBuilder::new(64 * 1024 * 1024, scratch_b.path().to_path_buf());
    let coverage = builder_b
        .build_and_ingest(&store_b, gen_id, &blocks)
        .map_err(|e| e.to_string())?;

    let dir_a = tempdir()?;
    let scratch_a = tempdir()?;
    let store_a = RocksDbStore::open(dir_a.path())?;

    let mut tail_state = TailWriterState::new();
    for block in &blocks {
        let mut batch = store_a.new_batch();
        append_tail_block(&mut batch, block, &mut tail_state);
        store_a.write_durable(batch)?;
    }

    seal_tail_generation(&store_a, gen_id, coverage, scratch_a.path())?;

    let indexed_cfs = [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
    ];

    for &cf in &indexed_cfs {
        let digest_a = compute_family_digest(&store_a, cf, gen_id);
        let digest_b = compute_family_digest(&store_b, cf, gen_id);
        assert_eq!(digest_a, digest_b, "mismatch on {:?}", cf);
    }
    Ok(())
}
