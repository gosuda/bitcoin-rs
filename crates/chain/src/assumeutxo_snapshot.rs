//! Immutable snapshot input selected only by the authoritative durable head.

use bitcoin_rs_consensus::primitives::{AssumeUtxoData, Hash256, Network};
use bitcoin_rs_storage::utxo::UtxoRecord;
use bitcoin_rs_storage::utxo::stats::CoinStats;
use bitcoin_rs_storage::{Bytes, COIN_KEY_LEN, CoinKey, CoinStore, StorageError, WindowDelta};

use crate::AssumeUtxoDiskStatus;

#[derive(Debug, thiserror::Error)]
pub enum SnapshotAnchorError {
    #[error(
        "AssumeUTXO validation previously failed; preserve this datadir and resync into a separate directory"
    )]
    PreviouslyFailed,
    #[error("unrecognized durable snapshot base")]
    UnrecognizedBase,
    #[error("durable snapshot identity differs from the network trust anchor")]
    TrustAnchorIdentity,
    #[error("durable snapshot transaction count differs from the network trust anchor")]
    TrustAnchorTxCount,
}

pub(crate) fn trusted_anchor(
    network: Network,
    status: &AssumeUtxoDiskStatus,
) -> Result<Option<&'static AssumeUtxoData>, SnapshotAnchorError> {
    let (height, hash, commitment) = match status {
        AssumeUtxoDiskStatus::Uninitialized => return Ok(None),
        AssumeUtxoDiskStatus::Failed { .. } => return Err(SnapshotAnchorError::PreviouslyFailed),
        AssumeUtxoDiskStatus::Validating {
            base_height,
            base_hash,
            expected_hash_serialized,
            ..
        } => (base_height, base_hash, expected_hash_serialized),
        AssumeUtxoDiskStatus::Finalized {
            base_height,
            base_hash,
            validated_hash_serialized,
        } => (base_height, base_hash, validated_hash_serialized),
    };
    let pinned = network
        .assume_utxo_for_height(*height)
        .ok_or(SnapshotAnchorError::UnrecognizedBase)?;
    if pinned.block_hash != *hash || pinned.hash_serialized != *commitment {
        return Err(SnapshotAnchorError::TrustAnchorIdentity);
    }
    if let AssumeUtxoDiskStatus::Validating { chain_tx_count, .. } = status
        && *chain_tx_count != pinned.chain_tx_count
    {
        return Err(SnapshotAnchorError::TrustAnchorTxCount);
    }
    Ok(Some(pinned))
}

pub(super) struct StagedCoins {
    delta: WindowDelta,
    bytes: usize,
    limit: usize,
}

impl StagedCoins {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            delta: WindowDelta::default(),
            bytes: 0,
            limit,
        }
    }

    fn stage(&mut self, txid: Hash256, record: &UtxoRecord) {
        let encoded = Bytes::copy_from_slice(record.bytes());
        self.bytes += COIN_KEY_LEN + encoded.len();
        self.delta
            .push_final(CoinKey(txid.to_le_bytes()), Some(encoded));
    }

    fn flush(&mut self, coins: &CoinStore) -> Result<(), StorageError> {
        coins.ingest_chunk(&self.delta)?;
        self.delta = WindowDelta::default();
        self.bytes = 0;
        Ok(())
    }
}

pub(super) fn stage_record(
    staged: &mut StagedCoins,
    coins: &CoinStore,
    txid: Hash256,
    record: &UtxoRecord,
) -> Result<(), StorageError> {
    staged.stage(txid, record);
    if staged.bytes >= staged.limit {
        staged.flush(coins)?;
    }
    Ok(())
}

pub(super) fn finish_stage(
    staged: &mut StagedCoins,
    coins: &CoinStore,
) -> Result<(), StorageError> {
    if staged.bytes > 0 {
        staged.flush(coins)?;
    }
    Ok(())
}

pub(super) struct StreamedCoins {
    pub(super) coin_stats: CoinStats,
}
