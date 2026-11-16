use super::{
    capability::IndexCapability, capability::IndexWatermark, error::IndexError, reader::Indexer,
    write::IndexWriter,
};
use crate::types::{HashPrefixRow, ScriptHash};
use bitcoin_rs_consensus::primitives::{OutPoint, Txid};
use bitcoin_rs_storage::{KvStore, PrefixScanLimit};

#[derive(Debug)]
pub struct TxIndexScanRow {
    pub row: HashPrefixRow,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub struct TxIndexScan {
    pub rows: Vec<TxIndexScanRow>,
    pub encoded_bytes: usize,
    pub complete: bool,
}

#[derive(Debug)]
pub struct TxIndexPage {
    pub rows: Vec<TxIndexScanRow>,
    pub complete: bool,
}

#[derive(Debug)]
pub struct ScriptLiveScan {
    pub rows: Vec<crate::ScriptLiveRow>,
    pub coins: Vec<crate::ScriptLiveCoin>,
    pub encoded_bytes: usize,
    pub complete: bool,
}

pub trait TxIndexSnapshot: Send + Sync {
    fn compact_filter(
        &self,
        _height: u32,
        _hash: &[u8; 32],
    ) -> Result<Option<super::BasicFilter>, IndexError> {
        Ok(None)
    }
    /// Whether the capability has a published descriptor in this view. Fixtures
    /// without a descriptor store answer `true`.
    fn capability_published(&self, _capability: IndexCapability) -> Result<bool, IndexError> {
        Ok(true)
    }
    fn capability_watermark(
        &self,
        capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError>;
    fn tx_lookup_page(
        &self,
        start_after: Option<&[u8]>,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexPage, IndexError>;
    fn capability_floor(&self, capability: IndexCapability) -> Result<u32, IndexError> {
        let _ = capability;
        Ok(0)
    }
    fn transaction_rows(
        &self,
        txid: &Txid,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError>;
    fn funding_rows(
        &self,
        scripthash: ScriptHash,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError>;
    fn funding_rows_from(
        &self,
        scripthash: ScriptHash,
        start_height: u32,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError>;
    fn spending_rows(
        &self,
        outpoint: &OutPoint,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError>;
    fn live_rows(
        &self,
        scripthash: ScriptHash,
        limit: PrefixScanLimit,
    ) -> Result<ScriptLiveScan, IndexError>;
}

pub trait IndexReader: Send + Sync {
    fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError>;
}

impl<S: KvStore> IndexReader for Indexer<S> {
    fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
        Ok(Box::new(crate::segment::SegmentSnapshot::open(
            self.store.snapshot()?,
        )?))
    }
}

impl<S: KvStore> IndexReader for IndexWriter<S> {
    fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
        Ok(Box::new(crate::segment::SegmentSnapshot::open(
            self.indexer.store.snapshot()?,
        )?))
    }
}

impl<S: KvStore> IndexWriter<S> {
    pub(crate) fn segment_snapshot(
        &self,
    ) -> Result<crate::segment::SegmentSnapshot<'_>, IndexError> {
        crate::segment::SegmentSnapshot::open(self.indexer.store.snapshot()?)
    }
}
