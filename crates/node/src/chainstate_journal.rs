//! Chainstate journal record codec.
//!
//! This module is the single owner of the on-wire journal record format.  It
//! does not define a commit point: records are bytes only, while `head.json`
//! (owned by the journal writer in a later task) is the commit point.
//! Encoding is pure and infallible; decoding classifies malformed or
//! corrupted bytes so callers can fail closed.  Coin fields mirror the
//! per-coin tuple used by `utxo::undo_codec` (outpoint, `TxOut`, height, and
//! coinbase), but this codec owns the ordered journal mutation shape.  Each
//! record also carries the block's full 80-byte consensus header: boot replay
//! rebuilds the checkpoint→head header chain in the `BlockTree` from these, so
//! the post-replay `TipSnapshot` (`NodeId` + `chainwork`) is reconstructible.
//! Records are semantic UTXO deltas (net effects in commit order), not
//! physical shard-commit order.

// Wire-format surface lands in Task 1 and is consumed by the writer (Task 2),
// apply-path emission (Task 4), and boot replay (Task 5). Until those callers
// exist the codec is deliberately unreferenced from the production path.
#![allow(dead_code)]
// The re-export is the module's public surface; writers/replayers arrive in Task 2+.

mod delta;

mod emit;

mod record;

mod replay;

mod writer;

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
#[allow(unused_imports)]
// writer surface; Task 5 (boot fast path) consumes HeadMarker + failpoints
pub(crate) use writer::{HeadMarker, JournalWriter, JournalWriterError, JournalWriterFailpoint};
