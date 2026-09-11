//! Logical ledger collection and exact durable watermark observations.

use super::IndexWatermarkEvidence;
use super::LogicalScan;
use super::TxIndexScan;
use super::WatermarkEvidence;
use anyhow::Result;
use bitcoin_rs_index::IndexWatermark;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::DataDirAnchor;
use bitcoin_rs_storage::FootprintError;
use bitcoin_rs_storage::LogicalLedger;
use bitcoin_rs_storage::LogicalOwner;
use bitcoin_rs_storage::StorageBackend;
use bitcoin_rs_storage::dir_has_entries;
use bitcoin_rs_storage::opened_fd_path;
use std::os::fd::AsFd;
use std::path::Path;

pub(super) fn collect_logical(
    anchor: &DataDirAnchor,
    backend: StorageBackend,
) -> Result<(LogicalLedger, IndexWatermarkEvidence)> {
    let mut logical = LogicalLedger::default();
    logical.push(
        anchor
            .logical_flat_block_files()
            .map_err(|error| io_from_footprint(&error))?,
    );

    if let Some(chainstate) = anchor
        .open_child_dir("chainstate")
        .map_err(|error| io_from_footprint(&error))?
    {
        if dir_has_entries(chainstate.as_fd()).map_err(|error| io_from_footprint(&error))? {
            let path = opened_fd_path(chainstate.as_fd());
            // Hold `chainstate` until the backend has opened `/proc/self/fd/N`.
            let owners = scan_store(backend, &path, "chainstate")?;
            drop(chainstate);
            for owner in owners {
                logical.push(owner);
            }
        }
    }

    let mut watermarks = IndexWatermarkEvidence {
        tx_lookup: None,
        script_history: None,
        script_live: None,
    };
    if let Some(txindex) = anchor
        .open_child_dir("txindex")
        .map_err(|error| io_from_footprint(&error))?
    {
        if dir_has_entries(txindex.as_fd()).map_err(|error| io_from_footprint(&error))? {
            let path = opened_fd_path(txindex.as_fd());
            // Hold `txindex` until the backend has opened `/proc/self/fd/N`.
            let (owners, found) = scan_store_with_watermarks(backend, &path)?;
            drop(txindex);
            for owner in owners {
                logical.push(owner);
            }
            if let Some(found) = found {
                watermarks = found;
            }
        }
    }
    Ok((logical, watermarks))
}

pub(super) fn io_from_footprint(error: &FootprintError) -> anyhow::Error {
    anyhow::Error::msg(error.to_string())
}

pub(super) fn scan_store(
    backend: StorageBackend,
    path: &Path,
    namespace: &str,
) -> Result<Vec<LogicalOwner>> {
    crate::storage_backend::open_store_inspection(backend, path, LogicalScan { namespace })
}

pub(super) fn scan_store_with_watermarks(
    backend: StorageBackend,
    path: &Path,
) -> Result<(Vec<LogicalOwner>, Option<IndexWatermarkEvidence>)> {
    crate::storage_backend::open_store_inspection(backend, path, TxIndexScan)
}

pub(super) fn watermark_evidence(
    watermarks: bitcoin_rs_index::IndexWatermarks,
) -> IndexWatermarkEvidence {
    IndexWatermarkEvidence {
        tx_lookup: watermarks.tx_lookup.map(watermark_json),
        script_history: watermarks.script_history.map(watermark_json),
        script_live: watermarks.script_live.map(watermark_json),
    }
}

pub(super) fn watermark_json(watermark: IndexWatermark) -> WatermarkEvidence {
    WatermarkEvidence {
        height: watermark.height,
        hash: Hash256::from_le_bytes(&watermark.hash).to_string_be(),
    }
}
