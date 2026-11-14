#![expect(clippy::expect_used, reason = "test assertions")]

mod support;

mod assumeutxo_archive;
mod conversion;
mod empty_namespaces;
#[cfg(any(feature = "mdbx", feature = "surrealkv"))]
mod engine_copy;
mod engine_rejection;
mod epoch3_copy;
mod epoch3_to_4;
mod full_revalidation;
mod historical_checkpoint;
mod large_row;
mod pool_ledger;
mod scoped_peers;
mod suffix_checkpoint;
mod validation;
