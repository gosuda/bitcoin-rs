//! Native mining pool jobs, protocols, and durable accounting.
#![forbid(unsafe_code)]

mod core;
mod job;
pub mod ledger;
pub mod stratum;

pub use core::{
    BlockOutcome, LedgerUnavailable, PoolCore, RecordOutcome, RefreshError, Refreshed, ShareLedger,
    WorkerIdentity,
};
pub use job::{
    AcceptedShare, BIP320_VERSION_MASK, BlockReceipt, BlockStatus, Extranonce, ExtranonceLayout,
    FoundBlock, Installed, Job, JobBook, JobBookConfig, JobError, JobId,
    MAX_COINBASE_SCRIPT_SIG_LEN, MAX_NTIME_FORWARD_SECS, Session, SessionId, ShareClass,
    ShareError, ShareOutcome, ShareSubmission, ShareTarget, ShareWork, StaleReason, fetch_template,
};
