//! Capability selection and the exact durable watermark representation.

use super::error::IndexError;
use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily, KvSnapshot};

pub(super) const TX_LOOKUP_WATERMARK_KEY: &[u8] = &[0x00, b'T'];

pub(super) const SCRIPT_HISTORY_WATERMARK_KEY: &[u8] = &[0x00, b'S'];

pub(super) const COMPACT_FILTERS_WATERMARK_KEY: &[u8] = &[0x00, b'F'];

pub(super) const SCRIPT_LIVE_WATERMARK_KEY: &[u8] = &[0x00, b'L'];

/// `TxLookup` coverage floor: first height with derived rows.
pub(super) const TX_LOOKUP_FLOOR_KEY: &[u8] = &[0x00, b't'];

/// `ScriptHistory` coverage floor: first height with derived rows.
pub(super) const SCRIPT_HISTORY_FLOOR_KEY: &[u8] = &[0x00, b's'];

pub(super) const WATERMARK_LEN: usize = crate::types::HEIGHT_SIZE + 32;

/// `ScriptLive` reseeds from an immutable artifact or retained history and can never hold a
/// pruned-prefix floor, so it has no key.
pub(super) const fn floor_key(capability: IndexCapability) -> Option<&'static [u8]> {
    match capability {
        IndexCapability::TxLookup => Some(TX_LOOKUP_FLOOR_KEY),
        IndexCapability::ScriptHistory => Some(SCRIPT_HISTORY_FLOOR_KEY),
        IndexCapability::ScriptLive | IndexCapability::CompactFilters => None,
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IndexWatermark {
    pub height: u32,
    pub hash: [u8; 32],
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IndexCapability {
    TxLookup,
    ScriptHistory,
    ScriptLive,
    /// BIP158 basic filters and their BIP157 header chain.
    CompactFilters,
}

impl IndexCapability {
    /// INVARIANT: this order is load-bearing; the query-refusal text and the
    /// index-ahead capability label follow it.
    pub(crate) const ALL: [Self; 4] = [
        Self::TxLookup,
        Self::ScriptHistory,
        Self::ScriptLive,
        Self::CompactFilters,
    ];

    /// reset-marker mask (`TxLookup` 0b001, `ScriptHistory` 0b010, `ScriptLive` 0b100, `CompactFilters` 0b1000).
    pub(super) const fn bit(self) -> u8 {
        match self {
            Self::TxLookup => 0b001,
            Self::ScriptHistory => 0b010,
            Self::ScriptLive => 0b100,
            Self::CompactFilters => 0b1000,
        }
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::TxLookup => 0,
            Self::ScriptHistory => 1,
            Self::ScriptLive => 2,
            Self::CompactFilters => 3,
        }
    }

    pub(super) const fn watermark_key(self) -> &'static [u8] {
        match self {
            Self::TxLookup => TX_LOOKUP_WATERMARK_KEY,
            Self::ScriptHistory => SCRIPT_HISTORY_WATERMARK_KEY,
            Self::ScriptLive => SCRIPT_LIVE_WATERMARK_KEY,
            Self::CompactFilters => COMPACT_FILTERS_WATERMARK_KEY,
        }
    }

    pub(super) const fn column_families(self) -> &'static [ColumnFamily] {
        match self {
            Self::TxLookup => &[ColumnFamily::TxConfirmed],
            Self::ScriptHistory => &[ColumnFamily::Funding, ColumnFamily::Spending],
            Self::ScriptLive => &[ColumnFamily::ScriptLive],
            Self::CompactFilters => &[],
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::TxLookup => "tx_lookup",
            Self::ScriptHistory => "script_history",
            Self::ScriptLive => "script_live",
            Self::CompactFilters => "compact_filters",
        }
    }

    pub(crate) const fn disabled_message(self) -> &'static str {
        match self {
            Self::TxLookup => "txindex is disabled",
            Self::ScriptHistory => "script history is disabled",
            Self::ScriptLive => "script live is disabled",
            Self::CompactFilters => "blockfilterindex is disabled",
        }
    }
}

/// INVARIANT: bit `capability.index()` is set iff `capability` is selected;
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexCapabilities(u8);

impl IndexCapabilities {
    pub const NONE: Self = Self(0);
    pub const TX_LOOKUP: Self = Self(IndexCapability::TxLookup.bit());
    pub const SCRIPT_HISTORY: Self = Self(IndexCapability::ScriptHistory.bit());
    pub const SCRIPT_LIVE: Self = Self(IndexCapability::ScriptLive.bit());
    pub const TX_LOOKUP_SCRIPT_LIVE: Self =
        Self(IndexCapability::TxLookup.bit() | IndexCapability::ScriptLive.bit());
    pub const ALL: Self = Self(0b1111);
    pub const TX_AND_SCRIPTS: Self = Self(0b111);
    /// BIP158 basic filter index only.
    pub const COMPACT_FILTERS: Self = Self(0b1000);

    #[must_use]
    pub const fn with_compact_filters(self, enabled: bool) -> Self {
        if enabled {
            self.insert(IndexCapability::CompactFilters)
        } else {
            self
        }
    }
    pub const HISTORICAL: Self =
        Self(IndexCapability::TxLookup.bit() | IndexCapability::ScriptHistory.bit());

    #[must_use]
    pub(crate) const fn contains(self, capability: IndexCapability) -> bool {
        self.0 & capability.bit() != 0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub(crate) const fn insert(self, capability: IndexCapability) -> Self {
        Self(self.0 | capability.bit())
    }

    #[must_use]
    pub(crate) const fn without(self, capability: IndexCapability) -> Self {
        Self(self.0 & !capability.bit())
    }

    pub(crate) fn iter(self) -> impl Iterator<Item = IndexCapability> {
        IndexCapability::ALL
            .into_iter()
            .filter(move |&capability| self.contains(capability))
    }

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

    pub(super) fn from_mask(mask: u8) -> Result<Self, IndexError> {
        if mask == 0 || mask & !0b1111 != 0 {
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

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexWatermarks {
    pub tx_lookup: Option<IndexWatermark>,
    pub script_history: Option<IndexWatermark>,
    pub script_live: Option<IndexWatermark>,
    pub compact_filters: Option<IndexWatermark>,
}

impl IndexWatermarks {
    pub(crate) const fn get(self, capability: IndexCapability) -> Option<IndexWatermark> {
        match capability {
            IndexCapability::TxLookup => self.tx_lookup,
            IndexCapability::ScriptHistory => self.script_history,
            IndexCapability::ScriptLive => self.script_live,
            IndexCapability::CompactFilters => self.compact_filters,
        }
    }

    pub(crate) const fn set(
        &mut self,
        capability: IndexCapability,
        cursor: Option<IndexWatermark>,
    ) {
        match capability {
            IndexCapability::TxLookup => self.tx_lookup = cursor,
            IndexCapability::ScriptHistory => self.script_history = cursor,
            IndexCapability::ScriptLive => self.script_live = cursor,
            IndexCapability::CompactFilters => self.compact_filters = cursor,
        }
    }

    pub(crate) fn selected(
        self,
        capabilities: IndexCapabilities,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        let mut selected = IndexCapability::ALL
            .into_iter()
            .filter(|&capability| capabilities.contains(capability))
            .map(|capability| self.get(capability));
        let Some(first) = selected.next() else {
            return Err(IndexError::NonContiguousPrepared { watermark: None });
        };
        if selected.all(|watermark| watermark == first) {
            Ok(first)
        } else {
            Err(IndexError::NonContiguousPrepared { watermark: None })
        }
    }

    pub(crate) fn is_aligned(
        self,
        capabilities: IndexCapabilities,
        target: Option<IndexWatermark>,
    ) -> bool {
        capabilities
            .iter()
            .all(|capability| self.get(capability) == target)
    }
}

impl IndexWatermark {
    /// they stay little-endian while row heights are big-endian (format 5).
    pub fn to_bytes(&self) -> [u8; WATERMARK_LEN] {
        let mut bytes = [0_u8; WATERMARK_LEN];
        bytes[..crate::types::HEIGHT_SIZE].copy_from_slice(&self.height.to_le_bytes());
        bytes[crate::types::HEIGHT_SIZE..].copy_from_slice(&self.hash);
        bytes
    }

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

    pub(crate) fn read_from_snapshot(
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

/// Reads one capability's coverage floor: the first height its committed rows
/// cover. Missing keys mean complete coverage from genesis.
pub(super) fn read_coverage_floor(
    snapshot: &dyn KvSnapshot,
    capability: IndexCapability,
) -> Result<u32, IndexError> {
    let Some(key) = floor_key(capability) else {
        return Ok(0);
    };
    let Some(raw) = snapshot.get(ColumnFamily::UtxoMeta, key)? else {
        return Ok(0);
    };
    let bytes: [u8; crate::types::HEIGHT_SIZE] = raw.as_slice().try_into().map_err(|_| {
        IndexError::Storage(bitcoin_rs_storage::StorageError::IncompatibleData(
            "coverage floor is not a height".into(),
        ))
    })?;
    Ok(u32::from_le_bytes(bytes))
}

pub(super) fn put_selected_floors(
    batch: &mut BufferedWriteBatch,
    capabilities: IndexCapabilities,
    floor: u32,
) {
    for capability in [IndexCapability::TxLookup, IndexCapability::ScriptHistory] {
        if !capabilities.contains(capability) {
            continue;
        }
        if let Some(key) = floor_key(capability) {
            batch.put(ColumnFamily::UtxoMeta, key, &floor.to_le_bytes());
        }
    }
}

/// rebuilds from genesis, which covers everything.
pub(super) fn delete_selected_floors(
    batch: &mut BufferedWriteBatch,
    capabilities: IndexCapabilities,
) {
    for capability in [IndexCapability::TxLookup, IndexCapability::ScriptHistory] {
        if !capabilities.contains(capability) {
            continue;
        }
        if let Some(key) = floor_key(capability) {
            batch.delete(ColumnFamily::UtxoMeta, key);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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
            (
                IndexCapability::CompactFilters,
                0b1000,
                3,
                &[0, b'F'][..],
                &[][..],
                "compact_filters",
                "blockfilterindex is disabled",
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
                IndexCapability::CompactFilters,
            ]
        );
        for (position, capability) in IndexCapability::ALL.into_iter().enumerate() {
            assert_eq!(capability.index(), position);
            assert_eq!(capability.bit(), 1 << position);
        }
    }

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
        for mask in [0b10000_u8, 0b0010_0000, 0b10001, 0b11111] {
            assert!(
                IndexCapabilities::from_mask(mask).is_err(),
                "mask {mask:#b} must be refused"
            );
        }
    }

    #[test]
    fn watermarks_selected_and_aligned() {
        let mark_a = IndexWatermark {
            height: 10,
            hash: [1; 32],
        };
        let mark_b = IndexWatermark {
            height: 11,
            hash: [2; 32],
        };
        let mut watermarks = IndexWatermarks::default();

        assert!(matches!(
            watermarks.selected(IndexCapabilities::NONE),
            Err(IndexError::NonContiguousPrepared { watermark: None })
        ));

        assert!(matches!(
            watermarks.selected(IndexCapabilities::HISTORICAL),
            Ok(None)
        ));
        assert!(watermarks.is_aligned(IndexCapabilities::HISTORICAL, None));

        watermarks.tx_lookup = Some(mark_a);
        assert!(matches!(
            watermarks.selected(IndexCapabilities::HISTORICAL),
            Err(IndexError::NonContiguousPrepared { watermark: None })
        ));
        assert!(!watermarks.is_aligned(IndexCapabilities::HISTORICAL, Some(mark_a)));

        watermarks.script_history = Some(mark_a);
        assert!(matches!(
            watermarks.selected(IndexCapabilities::HISTORICAL),
            Ok(Some(mark)) if mark == mark_a
        ));
        assert!(watermarks.is_aligned(IndexCapabilities::HISTORICAL, Some(mark_a)));
        assert!(!watermarks.is_aligned(IndexCapabilities::HISTORICAL, Some(mark_b)));
    }
}
