//! Capability selection and the exact durable watermark representation.

use super::error::IndexError;
use crate::{
    reconcile::SelectedWatermark, reconcile::selected_watermark as reconcile_selected_watermark,
};
use bitcoin_rs_storage::{ColumnFamily, KvSnapshot, WriteBatch};

pub(super) const TX_LOOKUP_WATERMARK_KEY: &[u8] = &[0x00, b'T'];

pub(super) const SCRIPT_HISTORY_WATERMARK_KEY: &[u8] = &[0x00, b'S'];

pub(super) const SCRIPT_LIVE_WATERMARK_KEY: &[u8] = &[0x00, b'L'];

pub(super) const WATERMARK_LEN: usize = crate::types::HEIGHT_SIZE + 32;

pub(super) const fn watermark_key(capability: IndexCapability) -> &'static [u8] {
    match capability {
        IndexCapability::TxLookup => TX_LOOKUP_WATERMARK_KEY,
        IndexCapability::ScriptHistory => SCRIPT_HISTORY_WATERMARK_KEY,
        IndexCapability::ScriptLive => SCRIPT_LIVE_WATERMARK_KEY,
    }
}

/// Exact durable point represented by all committed `TxIndex` rows.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IndexWatermark {
    /// Indexed active-chain height.
    pub height: u32,
    /// Full block identity at `height`.
    pub hash: [u8; 32],
}

/// One independently tracked family of derived index rows.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IndexCapability {
    /// Core-compatible transaction lookup rows.
    TxLookup,
    /// `ScriptIndex` scripthash funding and spending rows.
    ScriptHistory,
    /// `ScriptIndex` live-output rows: one row per currently unspent outpoint,
    /// filed under its script (#225). Rebuildable from the authoritative UTXO
    /// set alone, unlike history.
    ScriptLive,
}

/// Capabilities included in one prepared index transition.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexCapabilities {
    /// Build transaction lookup rows.
    pub tx_lookup: bool,
    /// Build `ScriptIndex` funding and spending rows.
    pub script_history: bool,
    /// Build `ScriptIndex` live-output rows.
    pub script_live: bool,
}

impl IndexCapabilities {
    /// No derived rows.
    pub const NONE: Self = Self {
        tx_lookup: false,
        script_history: false,
        script_live: false,
    };
    /// Transaction lookup only.
    pub const TX_LOOKUP: Self = Self {
        tx_lookup: true,
        script_history: false,
        script_live: false,
    };
    /// `ScriptIndex` history only.
    pub const SCRIPT_HISTORY: Self = Self {
        tx_lookup: false,
        script_history: true,
        script_live: false,
    };
    /// `ScriptIndex` live outputs only.
    pub const SCRIPT_LIVE: Self = Self {
        tx_lookup: false,
        script_history: false,
        script_live: true,
    };
    /// Every index capability, including the compact live view.
    pub const ALL: Self = Self {
        tx_lookup: true,
        script_history: true,
        script_live: true,
    };
    /// Every capability derivable from a block body alone.
    ///
    /// Anchorless paths use this, because `ScriptLive` cannot be prepared
    /// without a spent-coin script source.
    pub const HISTORICAL: Self = Self {
        tx_lookup: true,
        script_history: true,
        script_live: false,
    };

    /// Returns whether `capability` is selected.
    pub const fn contains(self, capability: IndexCapability) -> bool {
        match capability {
            IndexCapability::TxLookup => self.tx_lookup,
            IndexCapability::ScriptHistory => self.script_history,
            IndexCapability::ScriptLive => self.script_live,
        }
    }

    /// Returns whether no capability is selected.
    pub const fn is_empty(self) -> bool {
        !self.tx_lookup && !self.script_history && !self.script_live
    }

    /// Persisted cursors this selection no longer maintains.
    ///
    /// Mode demotion (`full` → `utxo`) and an explicit-`txindex` independence
    /// change leave durable rows behind. Those leftover families are reset
    /// and rebuilt or discarded; they are never served as if still configured.
    #[must_use]
    pub const fn leftover(self, watermarks: IndexWatermarks) -> Self {
        Self {
            tx_lookup: !self.tx_lookup && watermarks.tx_lookup.is_some(),
            script_history: !self.script_history && watermarks.script_history.is_some(),
            script_live: !self.script_live && watermarks.script_live.is_some(),
        }
    }

    pub(super) fn to_mask(self) -> u8 {
        u8::from(self.tx_lookup)
            | (u8::from(self.script_history) << 1)
            | (u8::from(self.script_live) << 2)
    }

    pub(super) fn from_mask(mask: u8) -> Result<Self, IndexError> {
        // A pre-#225 marker never carries bit 2, and reading one with the bit
        // absent is exactly right: the store had no live rows to reset.
        if mask == 0 || mask & !0b111 != 0 {
            return Err(IndexError::InvalidResetMarker);
        }
        Ok(Self {
            tx_lookup: mask & 0b001 != 0,
            script_history: mask & 0b010 != 0,
            script_live: mask & 0b100 != 0,
        })
    }
}

/// Durable cursors for the independently ready index capabilities.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexWatermarks {
    /// Transaction lookup cursor.
    pub tx_lookup: Option<IndexWatermark>,
    /// `ScriptIndex` history cursor.
    pub script_history: Option<IndexWatermark>,
    /// `ScriptIndex` live-output cursor. Independent of history by design:
    /// a ready live view stays queryable while history backfills (#225).
    pub script_live: Option<IndexWatermark>,
}

impl IndexWatermarks {
    /// Returns one capability's durable cursor.
    pub const fn get(self, capability: IndexCapability) -> Option<IndexWatermark> {
        match capability {
            IndexCapability::TxLookup => self.tx_lookup,
            IndexCapability::ScriptHistory => self.script_history,
            IndexCapability::ScriptLive => self.script_live,
        }
    }
}

impl IndexWatermark {
    /// Encodes the durable representation as `height (4 LE) || hash (32)`.
    pub fn to_bytes(&self) -> [u8; WATERMARK_LEN] {
        let mut bytes = [0_u8; WATERMARK_LEN];
        bytes[..crate::types::HEIGHT_SIZE].copy_from_slice(&self.height.to_le_bytes());
        bytes[crate::types::HEIGHT_SIZE..].copy_from_slice(&self.hash);
        bytes
    }

    /// Decodes the durable representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IndexError> {
        if bytes.len() != WATERMARK_LEN {
            return Err(IndexError::InvalidWatermark);
        }
        let mut height = [0_u8; crate::types::HEIGHT_SIZE];
        height.copy_from_slice(&bytes[..crate::types::HEIGHT_SIZE]);
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&bytes[crate::types::HEIGHT_SIZE..]);
        Ok(Self {
            height: u32::from_le_bytes(height),
            hash,
        })
    }

    /// Reads the durable watermark from a snapshot without requiring a writer handle.
    pub fn read_from_snapshot(
        snapshot: &dyn KvSnapshot,
        capability: IndexCapability,
    ) -> Result<Option<Self>, IndexError> {
        let key = watermark_key(capability);
        snapshot
            .get(ColumnFamily::UtxoMeta, key)?
            .as_deref()
            .map(Self::from_bytes)
            .transpose()
    }
}

pub(super) fn put_selected_watermarks<B: WriteBatch>(
    batch: &mut B,
    capabilities: IndexCapabilities,
    watermark: Option<IndexWatermark>,
) {
    for capability in [
        IndexCapability::TxLookup,
        IndexCapability::ScriptHistory,
        IndexCapability::ScriptLive,
    ] {
        if !capabilities.contains(capability) {
            continue;
        }
        let key = watermark_key(capability);
        if let Some(watermark) = watermark {
            batch.put(ColumnFamily::UtxoMeta, key, &watermark.to_bytes());
        } else {
            batch.delete(ColumnFamily::UtxoMeta, key);
        }
    }
}

pub(super) fn selected_watermark(
    watermarks: IndexWatermarks,
    capabilities: IndexCapabilities,
) -> Result<Option<IndexWatermark>, IndexError> {
    match reconcile_selected_watermark(watermarks, capabilities) {
        SelectedWatermark::Valid(watermark) => Ok(watermark),
        SelectedWatermark::Invalid => Err(IndexError::NonContiguousPrepared { watermark: None }),
    }
}
