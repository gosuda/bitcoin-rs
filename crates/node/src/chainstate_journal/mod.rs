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
//! rebuilds the checkpoint→head header chain in the BlockTree from these, so
//! the post-replay `TipSnapshot` (NodeId + chainwork) is reconstructible.
//! Records are semantic UTXO deltas (net effects in commit order), not
//! physical shard-commit order.

mod record;

pub(crate) use record::{
    BlockMeta, Coin, JournalRecord, JournalRecordError, Mutation, decode_record, encode_record,
};
