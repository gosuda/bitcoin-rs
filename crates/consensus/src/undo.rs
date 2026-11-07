use thiserror::Error;

use crate::UtxoCoin;
use crate::primitives::{Block, Hash256};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Error)]
pub enum HistoryUnavailable {
    #[error("history below height {below} is pruned")]
    Pruned { below: u32 },
    #[error("history below height {below} is reserved by an in-flight prune pass")]
    Reserved { below: u32 },
    #[error("retained history is temporarily unavailable")]
    Missing,
    #[error("history is unavailable while the node shuts down")]
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum BoundedReadError {
    #[error("bounded value reads are unavailable for this store")]
    Unsupported,
    #[error("stored value has {size} bytes, exceeding the {limit}-byte read limit")]
    Limit { size: usize, limit: usize },
    #[error("storage: {0}")]
    Storage(String),
}

impl From<std::io::Error> for BoundedReadError {
    fn from(error: std::io::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

#[derive(Debug)]
pub struct BlockSpends {
    pub block: Block,
    pub spent: Result<Vec<Vec<UtxoCoin>>, HistoryUnavailable>,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum UndoReadError {
    #[error("missing undo record for block {block} at height {height}")]
    Missing { block: Hash256, height: u32 },
    #[error("undo record for block {block} is unreadable")]
    Unreadable { block: Hash256 },
    #[error("undo store read: {0}")]
    Store(String),
}

#[derive(Debug, Error)]
pub enum BlockSpendsError {
    #[error("Block not found")]
    UnknownBlock,
    #[error(transparent)]
    History(#[from] HistoryUnavailable),
    #[error(transparent)]
    Undo(#[from] UndoReadError),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("block body read: {0}")]
    BodyRead(#[source] BoundedReadError),
    #[error(transparent)]
    BoundedRead(#[from] BoundedReadError),
    #[error("inconsistent retained block/undo: {0}")]
    Corrupt(&'static str),
    #[error("chain history changed during the query; retry")]
    Retry,
    #[error("chain history is unavailable while the node is closed for recovery")]
    Closed,
    #[error("block undo query exceeds its read budget")]
    ResourceLimit,
}

pub trait BlockUndoSource: Send + Sync {
    fn block_spends(
        &self,
        hash: Hash256,
        expected_applied_hash: Hash256,
    ) -> Result<BlockSpends, BlockSpendsError>;
}
