use core::time::Duration;

/// Production JSON-RPC body ceiling (`crates/rpc/src/server.rs`); the replay
/// decoder refuses a declared `Content-Length` above it before allocating.
pub(crate) const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1_024 * 1_024;

/// Largest single checked-in fixture, checked from directory metadata before
/// the file is read.
pub(crate) const MAX_FIXTURE_BYTES: u64 = 64 * 1_024;

/// Largest number of fixtures the corpus may hold.
pub(crate) const MAX_FIXTURE_COUNT: usize = 64;

/// Largest total size of the checked-in corpus.
pub(crate) const MAX_CORPUS_BYTES: u64 = 1_024 * 1_024;

/// Deepest object/array nesting a fixture may carry, measured on the raw
/// bytes before the strict parser sees them.
pub(crate) const MAX_JSON_DEPTH: usize = 32;

/// Largest number of response header lines the decoder accepts.
pub(crate) const MAX_RESPONSE_HEADERS: usize = 64;

/// Largest single response header line, in bytes.
pub(crate) const MAX_HEADER_LINE_BYTES: u64 = 8 * 1_024;

/// Largest response status line, in bytes.
pub(crate) const MAX_STATUS_LINE_BYTES: u64 = 1_024;

/// Connect deadline for a replay connection.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Read and write deadline for a replay connection; a stalled response fails
/// here instead of hanging the gate.
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(20);

/// Idle timeout configured on the replay server.
pub(crate) const SERVER_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// Concurrent connections the replay server accepts.
pub(crate) const SERVER_MAX_CONNECTIONS: usize = 8;

/// Blocks mined over regtest genesis before the corpus is replayed.
pub(crate) const SEED_CHAIN_BLOCKS: u32 = 2;
