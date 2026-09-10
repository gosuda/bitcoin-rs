//! Optional checkpoint-based chainstate journal.
//!
//! `record` owns ordered redo bytes; `head` owns the framed head representation
//! and its size-checked reader; `segment` owns the filename grammar. `writer`
//! alone appends, truncates, syncs, and publishes the durable frontier. `replay`
//! authenticates the committed range against the checkpoint before restore.
//! These are current checkpoint/journal mechanisms, not the planned durable-root
//! authority described in the recovery contract.

// Wire-format surface lands in Task 1 and is consumed by the writer (Task 2),
// apply-path emission (Task 4), and boot replay (Task 5). Until those callers
// exist the codec is deliberately unreferenced from the production path.
#![allow(dead_code)]
// The re-export is the module's public surface; writers/replayers arrive in Task 2+.

mod delta;

mod emit;

mod record;

mod replay;

mod error;
pub(crate) mod head;
mod segment;
mod writer;

pub(crate) use error::JournalWriterError;

#[allow(unused_imports)]
// writer surface; apply-path emission (Task 4) and boot replay (Task 5) consume these
pub(crate) use delta::{BlockDeltaInputs, journal_record_for_block};
#[allow(unused_imports)]
// emit surface; Task 5 (boot wiring) installs the SharedJournalWriter
pub(crate) use emit::{JournalEmit, SharedJournalWriter, shared_journal_writer};
#[allow(unused_imports)]
// module surface; consumers arrive in Task 2 (writer), 4 (emit), 5 (replay)
pub(crate) use record::{
    BlockMeta, Coin, JournalRecord, JournalRecordError, Mutation, decode_record, encode_record,
};
pub(crate) use replay::{ReplayOutcome, replay_from_journal};
#[allow(unused_imports)]
// writer surface; Task 5 (boot fast path) consumes HeadMarker + failpoints
pub(crate) use writer::{
    FULL_REVALIDATION_MARKER, JOURNAL_DIR_NAME, JournalWriter, JournalWriterFailpoint,
    clear_full_revalidation_marker_at,
};
