//! Checkpoint codec and immutable-publication regressions.

use super::headers;

use std::fs;
use std::io::Cursor;
use std::path::Path;

use bitcoin_rs_chain::{BlockTree, NodeId, TipSnapshot, accept_headers, compact_is_met_by};
use bitcoin_rs_primitives::{
    Amount, BlockHash, CompactTarget, Hash256, Header, Network, OutPoint, Script, TxOut, Txid,
    deserialize,
};
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener, scan_coin_stats};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};

use super::{
    CHECKPOINT_ROOT, COINSTATS_FILE, CURRENT_FILE, CheckpointCorruption, CheckpointFailpoint,
    CheckpointLoad, CheckpointLoadError, CheckpointManifestV1, CheckpointWrite, CurrentV1,
    HEADERS_FILE, MANIFEST_FILE, UTXO_FILE, load_checkpoint, write_checkpoint_with_failpoint,
};

const NETWORK: Network = Network::Regtest;

fn mutate_authenticated_artifact(
    data_dir: &Path,
    artifact: &str,
    mutate: impl FnOnce(&mut Vec<u8>),
) -> Result<(), Box<dyn std::error::Error>> {
    let root = data_dir.join(CHECKPOINT_ROOT);
    let current_path = root.join(CURRENT_FILE);
    let mut current: CurrentV1 = serde_json::from_slice(&fs::read(&current_path)?)?;

    let generation = root.join(&current.directory);
    let manifest_path = generation.join(MANIFEST_FILE);
    let mut manifest: CheckpointManifestV1 = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let artifact_path = generation.join(artifact);
    let mut bytes = fs::read(&artifact_path)?;
    mutate(&mut bytes);
    fs::write(&artifact_path, &bytes)?;
    let digest = super::hex_encode(&Sha256::digest(&bytes));
    let length = u64::try_from(bytes.len())?;
    match artifact {
        HEADERS_FILE => {
            manifest.headers.bytes = length;
            manifest.headers.sha256 = digest;
        }
        UTXO_FILE => {
            manifest.utxo.bytes = length;
            manifest.utxo.sha256 = digest;
        }
        COINSTATS_FILE => {
            manifest.coinstats.bytes = length;
            manifest.coinstats.sha256 = digest;
        }
        _ => return Err("unknown checkpoint artifact".into()),
    }
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    fs::write(&manifest_path, &manifest_bytes)?;
    current.manifest_sha256 = super::hex_encode(&Sha256::digest(&manifest_bytes));
    fs::write(current_path, serde_json::to_vec(&current)?)?;
    Ok(())
}
fn mutate_authenticated_manifest(
    data_dir: &Path,
    mutate: impl FnOnce(&mut CheckpointManifestV1),
) -> Result<(), Box<dyn std::error::Error>> {
    let root = data_dir.join(CHECKPOINT_ROOT);
    let current_path = root.join(CURRENT_FILE);
    let mut current: CurrentV1 = serde_json::from_slice(&fs::read(&current_path)?)?;
    let manifest_path = root.join(&current.directory).join(MANIFEST_FILE);
    let mut manifest: CheckpointManifestV1 = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    mutate(&mut manifest);
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    fs::write(&manifest_path, &manifest_bytes)?;
    current.manifest_sha256 = super::hex_encode(&Sha256::digest(&manifest_bytes));
    fs::write(current_path, serde_json::to_vec(&current)?)?;
    Ok(())
}

fn tip_snapshot(
    tree: &BlockTree,
    point: headers::HeaderCheckpointPoint,
) -> Result<TipSnapshot, headers::HeaderCheckpointError> {
    let id = tree
        .lookup(point.hash)
        .ok_or(headers::HeaderCheckpointError::AppliedTipNotBestPrefix)?;
    let node = tree.node(id)?;
    Ok(TipSnapshot {
        tip_id: id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
    })
}

fn config() -> headers::HeaderCheckpointConfig {
    headers::HeaderCheckpointConfig {
        network: NETWORK,
        genesis: NETWORK.genesis_block_hash(),
    }
}

fn write_checkpoint(
    tree: &BlockTree,
    best_tip_id: NodeId,
    applied: headers::HeaderCheckpointPoint,
) -> Result<(Vec<u8>, headers::HeaderCheckpointWrite), headers::HeaderCheckpointError> {
    let mut bytes = Vec::new();
    let written = headers::write_headers(&mut bytes, tree, config(), best_tip_id, applied)?;
    assert_eq!(u64::try_from(bytes.len()).ok(), Some(written.bytes_written));
    Ok((bytes, written))
}

fn chain_with_applied_height(
    best_height: u32,
    applied_height: u32,
) -> Result<(BlockTree, NodeId, headers::HeaderCheckpointPoint), headers::HeaderCheckpointError> {
    let genesis = NETWORK.genesis_block().header;
    let mut tree = BlockTree::new();
    let mut current = accept_headers(
        &mut tree,
        core::slice::from_ref(&genesis),
        NETWORK,
        bitcoin_rs_chain::current_unix_seconds(),
    )?[0];
    for height in 1..=best_height {
        let prev = BlockHash(tree.node(current)?.hash);
        let mut header = next_header(prev, height);
        mine_header_to_declared_target(&mut header)?;
        current = accept_headers(
            &mut tree,
            core::slice::from_ref(&header),
            NETWORK,
            bitcoin_rs_chain::current_unix_seconds(),
        )?[0];
    }
    let applied_id = tree
        .node_at_height_from(current, applied_height)
        .ok_or(headers::HeaderCheckpointError::AppliedTipNotBestPrefix)?;
    let applied = tree.node(applied_id)?;
    let height = applied.height;
    let hash = applied.hash;
    Ok((
        tree,
        current,
        headers::HeaderCheckpointPoint { height, hash },
    ))
}

fn next_header(prev_blockhash: BlockHash, height: u32) -> Header {
    Header {
        version: 1,
        prev_blockhash,
        merkle_root: Hash256::default(),
        time: 1_296_688_602_u32.saturating_add(height),
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    }
}

fn mine_header_to_declared_target(
    header: &mut Header,
) -> Result<(), headers::HeaderCheckpointError> {
    while !compact_is_met_by(header.bits, header.compute_hash().0) {
        header.nonce = header.nonce.checked_add(1).ok_or_else(|| {
            headers::HeaderCheckpointError::Codec("exhausted test nonce".to_owned())
        })?;
    }
    Ok(())
}

fn header_from_row(row: &[u8]) -> Result<Header, headers::HeaderCheckpointError> {
    deserialize(row).map_err(|error| headers::HeaderCheckpointError::Codec(error.to_string()))
}

fn populated_utxo() -> Result<UtxoSet, bitcoin_rs_utxo::UtxoError> {
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(Txid(Hash256::from_le_bytes(&[7_u8; 32])), 3),
        TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::from_bytes(vec![0x51, 0x21]),
        },
        true,
        0,
    ));
    let utxo = UtxoSet::new();
    utxo.commit_block(&changes, &Hash256::default())?;
    Ok(utxo)
}

#[cfg(test)]
mod behavior_1;

#[cfg(test)]
mod behavior_2;

#[cfg(test)]
mod persistence_1;

#[cfg(test)]
mod validation_1;

#[cfg(test)]
mod transitions_1;
