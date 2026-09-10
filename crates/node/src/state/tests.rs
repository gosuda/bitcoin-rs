mod checkpoint;
mod construction;
mod events;
mod index;
mod prune;
mod recovery;

use anyhow::Result;

use bitcoin_rs_chain::TipSnapshot;

use bitcoin_rs_primitives::{Block, Hash256, Tx, Txid, chain_constants::CORE_REORG_SAFETY_MARGIN};

use bitcoin_rs_rpc::context::{BlockLog, PruneService, PruneServiceError};

use bitcoin_rs_storage::FlatFileBlockStore;

use core::mem::size_of;

use hashbrown::HashMap;

use parking_lot::RwLock;

use super::{events::*, index::*, prune::load_pruneheight, restore::*};

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};

use super::*;

use bitcoin_rs_index::IndexCapabilities;

use bitcoin_rs_primitives::BlockHash;

use bitcoin_rs_primitives::Header;

use bitcoin_rs_primitives::OutPoint;

use bitcoin_rs_primitives::TxIn;

use bitcoin_rs_primitives::TxOut;

use bitcoin_rs_primitives::consensus_bytes;

use bitcoin_rs_primitives::encode::double_sha256;

use bitcoin_rs_rpc::context::BlockRecord;

fn publish_applied_tip_height(state: &NodeState, height: u32) {
    let mut hash = [0_u8; 32];
    hash[..size_of::<u32>()].copy_from_slice(&height.to_le_bytes());
    state.applied_tip.store(Some(Arc::new(TipSnapshot {
        tip_id: bitcoin_rs_chain::node::NodeId::new(height),
        height,
        chainwork: bitcoin_rs_chain::node::ChainWork::ZERO,
        hash: bitcoin_rs_primitives::Hash256::from_le_bytes(&hash),
    })));
}

#[test]
fn process_epoch_allocation_is_unique_across_processes() -> anyhow::Result<()> {
    const CHILD_DIR_ENV: &str = "BITCOIN_RS_TEST_EPOCH_CHILD_DIR";
    const CHILDREN: usize = 8;
    // Subprocess mode: this same test binary was re-exec'd by the parent
    // below. Park on the start barrier, then allocate one epoch.
    if let Ok(data_dir) = std::env::var(CHILD_DIR_ENV) {
        let data_dir = std::path::PathBuf::from(data_dir);
        let dir = cap_std::fs::Dir::open_ambient_dir(&data_dir, cap_std::ambient_authority())?;
        std::fs::write(data_dir.join(format!("ready-{}", std::process::id())), b"")?;
        let go = data_dir.join("go");
        let deadline = std::time::Instant::now() + std::time::Duration::from_mins(1);
        while !go.exists() {
            if std::time::Instant::now() >= deadline {
                anyhow::bail!("epoch child never saw the start barrier");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let epoch = super::events::allocate_process_epoch(&dir)?;
        std::fs::write(
            data_dir.join(format!("epoch-{}", std::process::id())),
            format!("{epoch}\n"),
        )?;
        std::process::exit(0);
    }

    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    std::fs::create_dir_all(&data_dir)?;

    // Harness test names are crate-relative; `module_path!()` is not.
    let test_name = concat!(
        module_path!(),
        "::process_epoch_allocation_is_unique_across_processes"
    )
    .split("::")
    .skip(1)
    .collect::<Vec<_>>()
    .join("::");
    let exe = std::env::current_exe()?;
    let mut children = Vec::new();
    for _ in 0..CHILDREN {
        children.push(
            std::process::Command::new(&exe)
                .args(["--exact", &test_name])
                .env(CHILD_DIR_ENV, &data_dir)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?,
        );
    }

    // Every child must be alive and parked before any allocates, so all
    // eight genuinely contend for the same lock file on one data dir.
    let deadline = std::time::Instant::now() + std::time::Duration::from_mins(1);
    loop {
        let ready = std::fs::read_dir(&data_dir)?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("ready-"))
            .count();
        if ready == CHILDREN {
            break;
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("epoch children never became ready: {ready}/{CHILDREN}");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    std::fs::write(data_dir.join("go"), b"")?;

    let mut epochs = Vec::new();
    for child in children {
        let output = child.wait_with_output()?;
        anyhow::ensure!(
            output.status.success(),
            "epoch child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for entry in std::fs::read_dir(&data_dir)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with("epoch-") {
            let text = std::fs::read_to_string(entry.path())?;
            epochs.push(text.trim().parse::<u64>()?);
        }
    }
    epochs.sort_unstable();
    assert_eq!(
        epochs.len(),
        CHILDREN,
        "each child reports exactly one epoch"
    );
    for (index, epoch) in epochs.iter().enumerate() {
        assert_eq!(
            *epoch,
            u64::try_from(index)? + 1,
            "concurrent children must each own one distinct epoch: {epochs:?}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(data_dir.join("process-epoch"))?,
        format!("{}\n", epochs[CHILDREN - 1]),
        "the persisted file must name the highest allocated epoch"
    );
    Ok(())
}

fn mined_regtest_child(prev_blockhash: BlockHash) -> anyhow::Result<Block> {
    mined_regtest_child_at(prev_blockhash, 1_296_688_603, 1)
}

fn mined_regtest_child_at(
    prev_blockhash: BlockHash,
    time: u32,
    height: u32,
) -> anyhow::Result<Block> {
    let mut script_sig = vec![8];
    script_sig.extend_from_slice(&height.to_le_bytes());
    script_sig.extend_from_slice(&time.to_le_bytes());
    let coinbase = Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig,
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 1,
            script_pubkey: Vec::new(),
        }],
    };
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        txs: vec![coinbase],
    };
    block.header.merkle_root = merkle_root(&block.txs)
        .ok_or_else(|| std::io::Error::other("test block has no merkle root"))?;
    while !pow_met(block.header.bits, block.block_hash().0) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("test nonce exhausted"))?;
    }
    Ok(block)
}

/// Pairwise double-SHA256 fold over little-endian txid bytes, duplicating
/// the last leaf on odd levels (the native stand-in for
/// `compute_merkle_root`).
fn merkle_root(txs: &[Tx]) -> Option<Hash256> {
    let mut leaves: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    if leaves.is_empty() {
        return None;
    }
    while leaves.len() > 1 {
        let original_len = leaves.len();
        let mut next = Vec::with_capacity(original_len.div_ceil(2));
        for pos in 0..original_len.div_ceil(2) {
            let left = leaves[2 * pos];
            let right = leaves[(2 * pos + 1).min(original_len - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(double_sha256(&pair).to_le_bytes());
        }
        leaves = next;
    }
    Some(Hash256::from_le_bytes(&leaves[0]))
}

/// Regtest-easy compact-target `PoW` check over the hash as a 256-bit
/// little-endian integer (mirrors `chain::pow::compact_is_met_by` for the
/// >3-exponent, 3-byte-mantissa forms these fixtures mine).
fn pow_met(bits: u32, hash: Hash256) -> bool {
    let exponent = u8::try_from(bits >> 24).unwrap_or(0);
    let mantissa = bits & 0x007f_ffff;
    if exponent <= 3 || exponent > 32 || mantissa > 0x00ff_ffff {
        return false;
    }
    let bytes = hash.as_byte_array();
    let low = usize::from(exponent - 3);
    let window =
        u32::from(bytes[low]) | u32::from(bytes[low + 1]) << 8 | u32::from(bytes[low + 2]) << 16;
    window <= mantissa && bytes[usize::from(exponent)..].iter().all(|&byte| byte == 0)
}
