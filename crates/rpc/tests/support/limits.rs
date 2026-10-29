//! Fixed ceilings for the Core parity corpus and its replay transport.

use core::time::Duration;

/// Production JSON-RPC body ceiling (`crates/rpc/src/server.rs`); the replay
/// decoder refuses a declared `Content-Length` above it before allocating.
pub(crate) const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1_024 * 1_024;

/// Largest single checked-in fixture, checked from directory metadata before
/// the file is read.
pub(crate) const MAX_FIXTURE_BYTES: u64 = 64 * 1_024;

pub(crate) const MAX_FIXTURE_COUNT: usize = 64;

pub(crate) const MAX_CORPUS_BYTES: u64 = 1_024 * 1_024;

/// Deepest object/array nesting a fixture may carry, measured on the raw
/// bytes before the strict parser sees them.
pub(crate) const MAX_JSON_DEPTH: usize = 32;

pub(crate) const MAX_RESPONSE_HEADERS: usize = 64;

pub(crate) const MAX_HEADER_LINE_BYTES: u64 = 8 * 1_024;

pub(crate) const MAX_STATUS_LINE_BYTES: u64 = 1_024;

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) const SERVER_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) const SERVER_MAX_CONNECTIONS: usize = 8;

pub(crate) const SEED_CHAIN_BLOCKS: u32 = 2;
