//! Startup crash-recovery: detect partial commits and replay the gap.
//!
//! The node persists `(height, last_committed_height, tip_hash)` in a small
//! JSON sidecar file inside the data directory.  The production apply path
//! writes the sidecar after every successful block apply, so the sidecar
//! records the tip the node reached.  On boot, if the sidecar's `height`
//! exceeds the restored checkpoint height, the gap is replayed from stored
//! block bodies: the tip hash lets the recovery walk backward through
//! `prev_blockhash` fields to identify the missing blocks, then apply them
//! forward as locally validated replay without re-executing scripts.
//!
//! When the sidecar lacks a tip hash (legacy test metadata) or stored bodies
//! are unavailable, recovery falls back to recording the gap in memory via
//! [`NodeState::push_replayed`] so the sync layer can re-download the blocks.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::state::NodeState;

/// Filename of the recovery sidecar inside the data directory.
pub const META_FILENAME: &str = "recovery_meta.json";

/// Recovery sidecar contents.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    /// Tip height the node reached before the crash.
    pub height: u32,
    /// Last height whose state was fully persisted.
    ///
    /// On the production apply path this is advanced to `height` after every
    /// successful block apply, because the block body — the durable artifact
    /// needed to reconstruct the UTXO state at that height — is on disk.
    pub last_committed_height: u32,
    /// Big-endian hex of the tip block hash at `height`.
    ///
    /// Present on every meta written by the production apply path.  Absent
    /// in legacy test metadata that predates the field; recovery falls back
    /// to in-memory replay when it is missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip_hash_hex: Option<String>,
}

fn meta_path(state: &NodeState) -> PathBuf {
    state.data_dir().join(META_FILENAME)
}

/// Reads the recovery sidecar, returning `None` if no file exists yet.
pub fn read_meta(state: &NodeState) -> Result<Option<Meta>> {
    let path = meta_path(state);
    read_meta_from_path(&path)
}

/// Reads the recovery sidecar from `path`, returning `None` if no file exists.
fn read_meta_from_path(path: &Path) -> Result<Option<Meta>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes =
        std::fs::read(path).with_context(|| format!("read recovery meta {}", path.display()))?;
    let meta: Meta = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse recovery meta {}", path.display()))?;
    Ok(Some(meta))
}

/// Overwrites the recovery sidecar with `meta`.
pub fn write_meta(state: &NodeState, meta: &Meta) -> Result<()> {
    write_meta_to_path(&meta_path(state), meta)
}

/// Writes the recovery sidecar at `path` using atomic rename + fsync.
pub fn write_meta_to_path(path: &Path, meta: &Meta) -> Result<()> {
    use std::io::Write as _;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(meta)
        .with_context(|| format!("encode recovery meta {}", path.display()))?;

    {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .with_context(|| format!("open tmp recovery meta {}", tmp.display()))?;
        file.write_all(&json)
            .with_context(|| format!("write tmp recovery meta {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("fsync tmp recovery meta {}", tmp.display()))?;
    }

    std::fs::rename(&tmp, path)
        .with_context(|| format!("atomic rename recovery meta {}", path.display()))?;
    // Best-effort directory fsync. POSIX allows the rename to be re-ordered until
    // the parent directory's inode is synced. Failing the fsync (e.g. on filesystems
    // that don't support it) is non-fatal — the rename already happened.
    if let Ok(dir_handle) = std::fs::File::open(dir) {
        let _ = dir_handle.sync_all();
    }

    Ok(())
}

/// Test helper: rewinds `last_committed_height` to simulate a partial commit.
pub fn set_last_committed_height(state: &NodeState, height: u32) -> Result<()> {
    let mut meta = read_meta(state)?.unwrap_or_default();
    meta.last_committed_height = height;
    write_meta(state, &meta)
}

/// Detects a gap between the restored checkpoint and the last applied tip,
/// and replays it from stored block bodies.
///
/// When the sidecar has a tip hash and stored bodies are available, the gap
/// is replayed by walking backward from the tip through `prev_blockhash`
/// fields, retaining only block identities, and applying bodies forward as
/// locally validated replay. The walk must land on the restored base tip.
/// When the tip hash is absent (legacy test metadata) or a body cannot be
/// loaded, recovery falls back to recording the gap in memory via
/// [`NodeState::push_replayed`].
pub fn recover_if_needed(state: &NodeState) -> Result<()> {
    let Some(meta) = read_meta(state)? else {
        tracing::debug!("no recovery metadata; fresh node");
        return Ok(());
    };

    // Determine the gap base.  Production metadata (with `tip_hash_hex`)
    // uses the restored checkpoint height, because `last_committed_height`
    // is always written equal to `height` on the production apply path.
    // Legacy/test metadata (without `tip_hash_hex`) uses
    // `last_committed_height`, which tests rewind to simulate a partial
    // commit.
    let restored_height = state.applied_tip().load().as_ref().map(|tip| tip.height);

    let gap_base = if meta.tip_hash_hex.is_some() {
        restored_height
    } else {
        Some(meta.last_committed_height)
    };
    let gap_start = gap_base.map_or(0, |base| base.saturating_add(1));

    if gap_base.is_some_and(|base| meta.height <= base) {
        tracing::debug!(height = meta.height, ?gap_base, "no gap; recovery skipped");
        return Ok(());
    }

    tracing::warn!(
        height = meta.height,
        ?gap_base,
        "crash-recovery gap detected: base at {:?} but tip was at {}",
        gap_base,
        meta.height
    );

    // Try full replay from stored bodies when we have a tip hash.
    if let Some(tip_hex) = &meta.tip_hash_hex
        && let Some(tip_hash) = parse_hash_hex(tip_hex)
    {
        match replay_from_bodies(state, meta.height, tip_hash) {
            Ok(replayed) => {
                for height in &replayed {
                    state.push_replayed(*height);
                }
                let new_meta = Meta {
                    height: meta.height,
                    last_committed_height: meta.height,
                    tip_hash_hex: meta.tip_hash_hex,
                };
                write_meta(state, &new_meta)?;
                tracing::info!(
                    replayed = replayed.len(),
                    from = gap_start,
                    to = meta.height,
                    "crash recovery replayed from stored bodies"
                );
                return Ok(());
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "full replay from stored bodies failed; falling back to in-memory gap record"
                );
            }
        }
    }

    // Fallback: record the gap in memory for the sync layer.
    for replay in gap_start..=meta.height {
        state.push_replayed(replay);
    }
    let new_meta = Meta {
        height: meta.height,
        last_committed_height: meta.height,
        tip_hash_hex: meta.tip_hash_hex,
    };
    write_meta(state, &new_meta)?;
    Ok(())
}

/// Walks backward from `(tip_height, tip_hash)` to the restored tip, or
/// through genesis when nothing is restored, retaining only block identities
/// while reading headers. It then loads and replays one complete body at a
/// time as locally validated input. The walk must land on the restored base
/// tip before any body is replayed.
fn replay_from_bodies(
    state: &NodeState,
    tip_height: u32,
    tip_hash: bitcoin_rs_primitives::Hash256,
) -> Result<Vec<u32>> {
    let handles = state.apply_handles();
    let body_store = handles
        .block_body_store
        .as_ref()
        .context("no block body store available for crash recovery replay")?;

    let base = state
        .applied_tip()
        .load()
        .as_deref()
        .map(|tip| (tip.height, tip.hash));
    let genesis_hash = handles.network.genesis_block_hash();

    // Walk backward from the tip, retaining only identities. A ranged header
    // read keeps the walk bounded by the largest body when the store supports
    // slicing; stores without that capability fall back to one full body.
    let mut identities: Vec<(u32, bitcoin_rs_primitives::Hash256)> = Vec::new();
    let mut current_hash = tip_hash;
    let mut current_height = tip_height;

    loop {
        if base.is_some_and(|(base_height, _)| current_height <= base_height) {
            break;
        }

        let header_bytes = match body_store
            .load_block_body_range(current_height, current_hash, 0, 80)
            .with_context(|| format!("load block header for replay at height {current_height}"))?
        {
            Some(bytes) => bytes,
            None => body_store
                .load_block_body(current_height, current_hash)
                .with_context(|| format!("load block body for replay at height {current_height}"))?
                .with_context(|| {
                    format!(
                        "block body missing for replay at height {current_height}; \
                         it may have been pruned or not yet flushed to disk"
                    )
                })?,
        };

        let header_prefix = header_bytes
            .get(..80)
            .context("stored block body is shorter than its header")?;
        let header: bitcoin_rs_primitives::Header =
            bitcoin_rs_primitives::encode::deserialize(header_prefix)
                .with_context(|| format!("deserialize block header at height {current_height}"))?;

        identities.push((current_height, current_hash));
        if current_height == 0 {
            anyhow::ensure!(
                current_hash == genesis_hash,
                "crash-recovery walk reached height 0 at {} but genesis is {}",
                current_hash.to_string_be(),
                genesis_hash.to_string_be()
            );
            break;
        }
        current_hash = header.prev_blockhash.0;
        current_height -= 1;
    }

    if let Some((base_height, base_hash)) = base {
        anyhow::ensure!(
            current_hash == base_hash,
            "crash-recovery walk landed on {} at restored height {}, expected {}",
            current_hash.to_string_be(),
            base_height,
            base_hash.to_string_be()
        );
    }

    // Reverse to apply in forward order, loading one body at a time.
    identities.reverse();

    let mut replayed = Vec::with_capacity(identities.len());
    for (height, hash) in identities {
        let body_bytes = body_store
            .load_block_body(height, hash)
            .with_context(|| format!("load block body for replay at height {height}"))?
            .with_context(|| {
                format!(
                    "block body missing for replay at height {height}; \
                     it may have been pruned or not yet flushed to disk"
                )
            })?;
        let block: bitcoin_rs_primitives::Block =
            bitcoin_rs_primitives::encode::deserialize(&body_bytes)
                .with_context(|| format!("deserialize block body at height {height}"))?;
        let tip =
            crate::apply::replay_local_block(&handles, &block, bytes::Bytes::from(body_bytes))
                .map_err(|error| {
                    anyhow::anyhow!("replay apply failed at height {height}: {error}")
                })?;
        tracing::debug!(
            height,
            hash = %tip.hash.to_string_be(),
            "replayed block through apply path"
        );
        replayed.push(height);
    }

    Ok(replayed)
}

/// Parses a big-endian hex string into a `Hash256`.
fn parse_hash_hex(hex: &str) -> Option<bitcoin_rs_primitives::Hash256> {
    bitcoin_rs_primitives::Hash256::from_str_be(hex).ok()
}
