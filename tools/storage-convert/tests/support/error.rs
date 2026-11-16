use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum TestError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("storage error: {0}")]
    Storage(#[from] bitcoin_rs_storage::StorageError),

    #[error("index error: {0}")]
    Index(#[from] bitcoin_rs_projection::IndexError),

    #[error("fjall error: {0}")]
    Fjall(#[from] fjall::Error),

    #[error("redb database error: {0}")]
    RedbDatabase(#[from] redb::DatabaseError),

    #[error("redb transaction error: {0}")]
    RedbTransaction(#[from] redb::TransactionError),

    #[error("redb table error: {0}")]
    RedbTable(#[from] redb::TableError),

    #[error("redb commit error: {0}")]
    RedbCommit(#[from] redb::CommitError),

    #[error("redb storage error: {0}")]
    RedbStorage(#[from] redb::StorageError),

    #[error("json format error: {0}")]
    Json(#[from] sonic_rs::Error),

    #[error("utf-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("assertion failed: {0}")]
    Assertion(String),

    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
}

pub(crate) type TestResult<T = ()> = Result<T, TestError>;
