//! Durable chainstate journal records, append policy, and committed-range replay.
mod emit;
mod record;
mod replay;
mod writer;

pub use emit::{JournalEmit, SharedJournalWriter, shared_journal_writer};
pub(crate) use record::crc32c;
pub use record::{Coin, JournalRecord, Mutation};
pub use replay::{JournalReplayBase, JournalReplayError, ReplayedHead, replay_committed_range};
pub use writer::{
    FULL_REVALIDATION_MARKER, JOURNAL_DIR_NAME, JournalPolicy, JournalWriter, JournalWriterError,
    clear_full_revalidation_marker_at,
};
