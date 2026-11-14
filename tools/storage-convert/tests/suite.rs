#![expect(clippy::expect_used, reason = "test assertions")]

mod support;

mod assumeutxo_archive;
mod conversion;
mod empty_namespaces;
#[cfg(any(feature = "mdbx", feature = "surrealkv"))]
mod engine_copy;
mod engine_rejection;
mod epoch3_to_4;
mod epoch4_to_5;
mod epoch5_copy;
mod full_revalidation;
mod historical_checkpoint;
mod large_row;
mod pool_ledger;
mod rebuild_index;
mod scoped_peers;
mod suffix_checkpoint;
mod validation;
