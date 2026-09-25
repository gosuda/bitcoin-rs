//! Capability selection and the exact durable watermark representation.

use super::error::IndexError;
use crate::{
    reconcile::SelectedWatermark, reconcile::selected_watermark as reconcile_selected_watermark,
};
use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily, KvSnapshot};

pub(super) const TX_LOOKUP_WATERMARK_KEY: &[u8] = &[0x00, b'T'];

pub(super) const SCRIPT_HISTORY_WATERMARK_KEY: &[u8] = &[0x00, b'S'];

pub(super) const SCRIPT_LIVE_WATERMARK_KEY: &[u8] = &[0x00, b'L'];

pub(super) const WATERMARK_LEN: usize = crate::types::HEIGHT_SIZE + 32;

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

impl IndexCapability {
    /// Every capability in mask-bit and report order.
    ///
    /// PRE: none.
    /// POST: distinct entries, ordered `TxLookup`, `ScriptHistory`, `ScriptLive`.
    /// INVARIANT: this order is load-bearing; the query-refusal text and the
    /// index-ahead capability label follow it.
    pub const ALL: [Self; 3] = [Self::TxLookup, Self::ScriptHistory, Self::ScriptLive];

    /// PRE: none.
    /// POST: the single mask bit this capability owns, matching the persisted
    /// reset-marker mask (`TxLookup` 0b001, `ScriptHistory` 0b010, `ScriptLive` 0b100).
    pub(super) const fn bit(self) -> u8 {
        match self {
            Self::TxLookup => 0b001,
            Self::ScriptHistory => 0b010,
            Self::ScriptLive => 0b100,
        }
    }

    /// PRE: none.
    /// POST: the position of this capability in [`Self::ALL`], 0 to 2.
    pub const fn index(self) -> usize {
        match self {
            Self::TxLookup => 0,
            Self::ScriptHistory => 1,
            Self::ScriptLive => 2,
        }
    }

    /// PRE: none.
    /// POST: the persisted watermark key, byte-identical to the constants
    /// this method replaces (the `T`, `S`, `L` keys under `0x00`).
    pub(super) const fn watermark_key(self) -> &'static [u8] {
        match self {
            Self::TxLookup => TX_LOOKUP_WATERMARK_KEY,
            Self::ScriptHistory => SCRIPT_HISTORY_WATERMARK_KEY,
            Self::ScriptLive => SCRIPT_LIVE_WATERMARK_KEY,
        }
    }

    /// PRE: none.
    /// POST: the column families this capability occupies
    /// (`TxLookup`: `TxConfirmed`; `ScriptHistory`: Funding, Spending;
    /// `ScriptLive`: `ScriptLive`).
    pub(super) const fn column_families(self) -> &'static [ColumnFamily] {
        match self {
            Self::TxLookup => &[ColumnFamily::TxConfirmed],
            Self::ScriptHistory => &[ColumnFamily::Funding, ColumnFamily::Spending],
            Self::ScriptLive => &[ColumnFamily::ScriptLive],
        }
    }

    /// PRE: none.
    /// POST: the display name (`tx_lookup`, `script_history`, `script_live`).
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::TxLookup => "tx_lookup",
            Self::ScriptHistory => "script_history",
            Self::ScriptLive => "script_live",
        }
    }

    /// PRE: none.
    /// POST: the query-refusal text for this capability, byte-identical to
    /// the inline literals this method replaces.
    pub(crate) const fn disabled_message(self) -> &'static str {
        match self {
            Self::TxLookup => "txindex is disabled",
            Self::ScriptHistory => "script history is disabled",
            Self::ScriptLive => "script live is disabled",
        }
    }
}

/// Named subset of [`IndexCapability`]: one prepared transition, an
/// enabled configuration, or one query requirement.
///
/// PRE: build only from the named constants, [`Self::insert`], or
/// `FromIterator`.
/// POST: [`Self::contains`], [`Self::iter`], and [`Self::leftover`] answer
/// over the selected capabilities.
/// INVARIANT: bit `capability.index()` is set iff `capability` is selected;
/// `to_mask` persists exactly this byte, so the on-disk reset-marker
/// encoding is unchanged.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexCapabilities(u8);

impl IndexCapabilities {
    /// No derived rows.
    pub const NONE: Self = Self(0);
    /// Transaction lookup only.
    pub const TX_LOOKUP: Self = Self(IndexCapability::TxLookup.bit());
    /// `ScriptIndex` history only.
    pub const SCRIPT_HISTORY: Self = Self(IndexCapability::ScriptHistory.bit());
    /// `ScriptIndex` live outputs only.
    pub const SCRIPT_LIVE: Self = Self(IndexCapability::ScriptLive.bit());
    /// Node `--txindex` plus `--scriptindex=utxo`; previously an ad-hoc
    /// struct literal at its sole construction site.
    pub const TX_LOOKUP_SCRIPT_LIVE: Self =
        Self(IndexCapability::TxLookup.bit() | IndexCapability::ScriptLive.bit());
    /// Every index capability, including the compact live view.
    pub const ALL: Self = Self(0b111);
    /// Every capability derivable from a block body alone.
    ///
    /// Anchorless paths use this, because `ScriptLive` cannot be prepared
    /// without a spent-coin script source.
    pub const HISTORICAL: Self =
        Self(IndexCapability::TxLookup.bit() | IndexCapability::ScriptHistory.bit());

    /// PRE: none.
    /// POST: whether `capability` is selected.
    #[must_use]
    pub const fn contains(self, capability: IndexCapability) -> bool {
        self.0 & capability.bit() != 0
    }

    /// PRE: none.
    /// POST: whether no capability is selected.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// PRE: none.
    /// POST: `capability` is selected in the result; every other selection
    /// bit is unchanged.
    #[must_use]
    pub const fn insert(self, capability: IndexCapability) -> Self {
        Self(self.0 | capability.bit())
    }

    /// PRE: none.
    /// POST: the selected capabilities in [`IndexCapability::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = IndexCapability> {
        IndexCapability::ALL
            .into_iter()
            .filter(move |&capability| self.contains(capability))
    }

    /// Persisted cursors this selection no longer maintains.
    ///
    /// Mode demotion (`full` → `utxo`) and an explicit-`txindex` independence
    /// change leave durable rows behind. Those leftover families are reset
    /// and rebuilt or discarded; they are never served as if still configured.
    #[must_use]
    pub fn leftover(self, watermarks: IndexWatermarks) -> Self {
        IndexCapability::ALL
            .into_iter()
            .filter(|&capability| {
                !self.contains(capability) && watermarks.get(capability).is_some()
            })
            .collect()
    }

    pub(super) const fn to_mask(self) -> u8 {
        self.0
    }

    /// PRE: none.
    /// POST: the set the mask encodes, or
    /// [`IndexError::InvalidResetMarker`] when `mask` is 0 or any bit above
    /// bit 2 is set.
    pub(super) fn from_mask(mask: u8) -> Result<Self, IndexError> {
        // A pre-#225 marker never carries bit 2, and reading one with the bit
        // absent is exactly right: the store had no live rows to reset.
        if mask == 0 || mask & !0b111 != 0 {
            return Err(IndexError::InvalidResetMarker);
        }
        Ok(Self(mask))
    }
}

impl FromIterator<IndexCapability> for IndexCapabilities {
    fn from_iter<I: IntoIterator<Item = IndexCapability>>(iter: I) -> Self {
        iter.into_iter().fold(Self::NONE, Self::insert)
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
    ///
    /// Watermarks are decoded numerically, never ordered as KV row keys, so
    /// they stay little-endian while row heights are big-endian (format 5).
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
        let key = capability.watermark_key();
        snapshot
            .get(ColumnFamily::UtxoMeta, key)?
            .as_deref()
            .map(Self::from_bytes)
            .transpose()
    }
}

pub(super) fn put_selected_watermarks(
    batch: &mut BufferedWriteBatch,
    capabilities: IndexCapabilities,
    watermark: Option<IndexWatermark>,
) {
    for capability in capabilities.iter() {
        let key = capability.watermark_key();
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Each fact method must equal the literal it replaces: a swapped arm
    /// would silently change persisted bytes, column families, or refusal
    /// text.
    #[test]
    fn per_capability_facts_match_the_literals_they_replace() {
        for (capability, bit, index, key, families, name, message) in [
            (
                IndexCapability::TxLookup,
                0b001_u8,
                0_usize,
                TX_LOOKUP_WATERMARK_KEY,
                &[ColumnFamily::TxConfirmed][..],
                "tx_lookup",
                "txindex is disabled",
            ),
            (
                IndexCapability::ScriptHistory,
                0b010,
                1,
                SCRIPT_HISTORY_WATERMARK_KEY,
                &[ColumnFamily::Funding, ColumnFamily::Spending][..],
                "script_history",
                "script history is disabled",
            ),
            (
                IndexCapability::ScriptLive,
                0b100,
                2,
                SCRIPT_LIVE_WATERMARK_KEY,
                &[ColumnFamily::ScriptLive][..],
                "script_live",
                "script live is disabled",
            ),
        ] {
            assert_eq!(capability.bit(), bit);
            assert_eq!(capability.index(), index);
            assert_eq!(capability.watermark_key(), key);
            assert_eq!(capability.column_families(), families);
            assert_eq!(capability.name(), name);
            assert_eq!(capability.disabled_message(), message);
        }
    }

    #[test]
    fn all_lists_every_capability_in_mask_bit_order() {
        assert_eq!(
            IndexCapability::ALL,
            [
                IndexCapability::TxLookup,
                IndexCapability::ScriptHistory,
                IndexCapability::ScriptLive,
            ]
        );
        for (position, capability) in IndexCapability::ALL.into_iter().enumerate() {
            assert_eq!(capability.index(), position);
            assert_eq!(capability.bit(), 1 << position);
        }
    }

    /// The reset marker round-trips byte-identically and refuses an empty
    /// mask and any bit above bit 2 (the pre-#225 marker rule).
    #[test]
    fn reset_marker_mask_round_trips_and_refuses_invalid_masks() {
        for selection in [
            IndexCapabilities::TX_LOOKUP,
            IndexCapabilities::SCRIPT_HISTORY,
            IndexCapabilities::SCRIPT_LIVE,
            IndexCapabilities::HISTORICAL,
            IndexCapabilities::ALL,
        ] {
            assert!(
                matches!(
                    IndexCapabilities::from_mask(selection.to_mask()),
                    Ok(selected) if selected == selection
                ),
                "mask round trip must hold for {selection:?}"
            );
        }
        assert!(matches!(
            IndexCapabilities::from_mask(0),
            Err(IndexError::InvalidResetMarker)
        ));
        for mask in [0b1000_u8, 0b0001_0000, 0b1001, 0b1111] {
            assert!(
                IndexCapabilities::from_mask(mask).is_err(),
                "mask {mask:#b} must be refused"
            );
        }
    }
}
