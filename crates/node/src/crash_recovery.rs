//! Startup crash-recovery: detect partial commits and replay the gap.
//!
//! The node persists `(height, last_committed_height)` in a small JSON
//! sidecar file inside the data directory. On boot, if
//! `last_committed_height < height`, the block range `(last + 1 ..= tip)`
//! is replayed and `last_committed_height` is advanced to match `height`.
//!
//! V1 records the replay only in-memory via [`NodeState::push_replayed`]
//! so tests can observe the recovery path. Real replay (re-applying block
//! bodies to UTXO + filter index + coinstats) is wired by the binary as
//! it constructs the full subsystem stack.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::state::NodeState;

const META_FILENAME: &str = "recovery_meta.json";

/// Recovery sidecar contents.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    /// Tip height the node believes is canonical.
    pub height: u32,
    /// Last height whose state was fully persisted.
    pub last_committed_height: u32,
}

fn meta_path(state: &NodeState) -> PathBuf {
    state.data_dir().join(META_FILENAME)
}

/// Reads the recovery sidecar, returning `None` if no file exists yet.
pub fn read_meta(state: &NodeState) -> Result<Option<Meta>> {
    let path = meta_path(state);
    if !path.exists() {
        return Ok(None);
    }
    let bytes =
        std::fs::read(&path).with_context(|| format!("read recovery meta {}", path.display()))?;
    let meta: Meta = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse recovery meta {}", path.display()))?;
    Ok(Some(meta))
}

/// Overwrites the recovery sidecar with `meta`.
pub fn write_meta(state: &NodeState, meta: &Meta) -> Result<()> {
    let path = meta_path(state);
    let json = serde_json::to_vec_pretty(meta)
        .with_context(|| format!("encode recovery meta {}", path.display()))?;
    std::fs::write(&path, json)
        .with_context(|| format!("write recovery meta {}", path.display()))?;
    Ok(())
}

/// Test helper: rewinds `last_committed_height` to simulate a partial commit.
pub fn set_last_committed_height(state: &NodeState, height: u32) -> Result<()> {
    let mut meta = read_meta(state)?.unwrap_or_default();
    meta.last_committed_height = height;
    write_meta(state, &meta)
}

/// Detects a partial commit and replays the gap.
///
/// Replay is recorded in [`NodeState::replayed_heights`]; the actual chain
/// re-application is the binary's responsibility once the subsystem stack
/// is bound.
pub fn recover_if_needed(state: &NodeState) -> Result<()> {
    let Some(mut meta) = read_meta(state)? else {
        tracing::debug!("no recovery metadata; fresh node");
        return Ok(());
    };
    if meta.last_committed_height >= meta.height {
        tracing::debug!(
            height = meta.height,
            last_committed = meta.last_committed_height,
            "no gap; recovery skipped"
        );
        return Ok(());
    }
    tracing::warn!(
        height = meta.height,
        last_committed = meta.last_committed_height,
        "partial commit detected; replaying"
    );
    for replay in (meta.last_committed_height + 1)..=meta.height {
        state.push_replayed(replay);
    }
    meta.last_committed_height = meta.height;
    write_meta(state, &meta)?;
    Ok(())
}
