//! Native Stratum V1 pool adapter.
//!
//! Two layers:
//!
//! * this module: the SV1 wire. Bounded line framing ([`LineBuffer`]), JSON-RPC
//!   decode ([`decode_line`], [`ClientRequest`]), exact response and
//!   notification encoders, the prevhash word swap, BIP310 parameter parsing,
//!   decimal difficulty ([`Difficulty`]), explicit account resolution
//!   ([`AccountResolver`]) and the accounting boundary ([`ShareLedger`]);
//! * [`session`]: the per-connection state machine, the shared [`PoolCore`]
//!   over [`crate::JobBook`], and the bounded TCP [`Server`].
//!
//! Division of ownership. The parent crate owns job projection, the coinbase
//! split, extranonce allocation, the share predicate, stale and duplicate state,
//! and block assembly. This adapter never hashes a header, never builds a
//! coinbase, never compares a hash with a target. It owns what only SV1 has:
//! framing, dialect, handshake order, BIP310 negotiation, per-session
//! difficulty policy, deadlines, and connection bounds. It holds no keys, no
//! wallet, no signer, and no money: payouts are the ledger's business.
//!
//! JSON goes through `sonic-rs`. Untrusted frames are bounded three ways before
//! any value exists: line length ([`LineBuffer`]), nesting depth
//! ([`MAX_JSON_DEPTH`]), and parameter count ([`MAX_PARAMS`]).
#![forbid(unsafe_code)]

mod session;

use std::collections::HashMap;
use std::fmt;

use crate::{AcceptedShare, BlockReceipt, FoundBlock, Job, JobError, JobId, ShareTarget};
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_primitives::Hash256;
use sonic_rs::{Array, JsonContainerTrait, JsonValueTrait, Value};

pub use session::{
    BlockOutcome, ConfigError, ConnectionLimiter, ConnectionPermit, Observer, PoolCore,
    RefreshError, Refreshed, RefusalReason, Server, ServerConfig, ServerDeps, ServerEvent,
    SessionEnd, ShutdownReport,
};

/// Longest accepted JSON-RPC request id string.
pub const MAX_ID_LEN: usize = 128;
/// Longest accepted method name.
pub const MAX_METHOD_LEN: usize = 64;
/// Most parameters any SV1 request carries (`mining.submit` has six).
pub const MAX_PARAMS: usize = 8;
/// Longest accepted worker login.
pub const MAX_LOGIN_LEN: usize = 128;
/// Longest accepted worker password.
pub const MAX_PASSWORD_LEN: usize = 128;
/// Longest user agent kept from `mining.subscribe`; longer ones are truncated.
pub const MAX_USER_AGENT_LEN: usize = 128;
/// Longest `job_id` string a `mining.submit` may carry.
pub const MAX_JOB_ID_LEN: usize = 64;
/// Most `extranonce2` bytes a `mining.submit` may carry.
pub const MAX_EXTRANONCE2_BYTES: usize = 32;
/// Most extensions one `mining.configure` may name.
pub const MAX_CONFIGURE_EXTENSIONS: usize = 16;
/// Longest extension name in `mining.configure`.
pub const MAX_EXTENSION_NAME_LEN: usize = 64;
/// Deepest array/object nesting a frame may have. SV1 needs 3.
pub const MAX_JSON_DEPTH: usize = 8;
/// Most characters a difficulty may be written with.
pub const MAX_DIFFICULTY_TEXT_LEN: usize = 20;

// ---------------------------------------------------------------------------
// Hex and byte order
// ---------------------------------------------------------------------------

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Appends the lowercase hex of `bytes` to `out`.
pub fn push_hex(out: &mut String, bytes: &[u8]) {
    out.reserve(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
}

/// Lowercase hex of `bytes`.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    push_hex(&mut out, bytes);
    out
}

/// Decodes an even-length hex string of either case; `None` on any other byte.
#[must_use]
pub fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let (pairs, odd_tail) = text.as_bytes().as_chunks::<2>();
    if !odd_tail.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|&[high, low]| Some((nibble(high)? << 4) | nibble(low)?))
        .collect()
}

/// Parses `min_digits..=8` hex digits as one `u32`. No sign, no prefix.
#[must_use]
pub fn parse_u32_hex(text: &str, min_digits: usize) -> Option<u32> {
    if text.len() < min_digits.max(1) || text.len() > 8 {
        return None;
    }
    text.bytes().try_fold(0_u32, |value, byte| {
        Some((value << 4) | u32::from(nibble(byte)?))
    })
}

/// Reverses the four bytes of each 32-bit word of a 32-byte hash. The swap is
/// its own inverse.
#[must_use]
pub fn swap_words(hash: &[u8; 32]) -> [u8; 32] {
    let mut out = *hash;
    for word in out.as_chunks_mut::<4>().0 {
        word.reverse();
    }
    out
}

/// SV1 `prevhash` text for a parent hash in internal (header) byte order.
#[must_use]
pub fn prevhash_to_wire(internal: &[u8; 32]) -> String {
    encode_hex(&swap_words(internal))
}

/// Parent hash in internal byte order from SV1 `prevhash` text.
#[must_use]
pub fn prevhash_from_wire(text: &str) -> Option<[u8; 32]> {
    let bytes: [u8; 32] = decode_hex(text)?.try_into().ok()?;
    Some(swap_words(&bytes))
}

/// SV1 `job_id` text of a native job id: eight lowercase hex digits.
#[must_use]
pub fn wire_job_id(id: JobId) -> String {
    format!("{:08x}", id.get())
}

/// Native job id of SV1 `job_id` text; `None` unless it is exactly the text
/// [`wire_job_id`] writes (so no job this adapter did not issue can parse).
#[must_use]
pub fn parse_wire_job_id(text: &str) -> Option<JobId> {
    if text.len() != 8
        || !text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    parse_u32_hex(text, 8).map(JobId::new)
}

// ---------------------------------------------------------------------------
// Wire errors
// ---------------------------------------------------------------------------

/// One SV1 error triple `[code, message, null]`. Messages are fixed text:
/// nothing internal reaches a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireError {
    /// Numeric code.
    pub code: i32,
    /// Fixed message.
    pub message: &'static str,
}

impl WireError {
    /// Builds an error.
    #[must_use]
    pub const fn new(code: i32, message: &'static str) -> Self {
        Self { code, message }
    }

    /// The `[code, "message", null]` array.
    #[must_use]
    pub fn to_json(&self) -> String {
        format!("[{},{},null]", self.code, json_string(self.message))
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.code, self.message)
    }
}

/// The SV1 error vocabulary this adapter speaks.
pub mod errors {
    use super::WireError;

    /// Slush draft 20: other or unknown.
    pub const OTHER: i32 = 20;
    /// Slush draft 21: job not found (stale).
    pub const JOB_NOT_FOUND: i32 = 21;
    /// Slush draft 22: duplicate share.
    pub const DUPLICATE_SHARE: i32 = 22;
    /// Slush draft 23: low difficulty share.
    pub const LOW_DIFFICULTY: i32 = 23;
    /// Slush draft 24: unauthorized worker.
    pub const UNAUTHORIZED_WORKER: i32 = 24;
    /// Slush draft 25: not subscribed.
    pub const NOT_SUBSCRIBED: i32 = 25;

    /// Frame is not JSON.
    pub const PARSE_ERROR: WireError = WireError::new(-32700, "Parse error");
    /// Frame is JSON but not a request.
    pub const INVALID_REQUEST: WireError = WireError::new(-32600, "Invalid request");
    /// Unknown method.
    pub const METHOD_NOT_FOUND: WireError = WireError::new(-32601, "Method not found");
    /// Parameters of the wrong shape.
    pub const INVALID_PARAMS: WireError = WireError::new(-32602, "Invalid params");
    /// `extranonce2` is not hex of a bounded length.
    pub const INVALID_EXTRANONCE2: WireError = WireError::new(-32602, "Invalid extranonce2");
    /// `extranonce2` length differs from the one announced at subscribe.
    pub const INVALID_EXTRANONCE2_LENGTH: WireError =
        WireError::new(-32602, "Invalid extranonce2 length");
    /// `ntime` is not eight hex digits.
    pub const INVALID_NTIME_FORMAT: WireError = WireError::new(-32602, "Invalid ntime");
    /// `nonce` is not eight hex digits.
    pub const INVALID_NONCE_FORMAT: WireError = WireError::new(-32602, "Invalid nonce");
    /// `version_bits` is not eight hex digits.
    pub const INVALID_VERSION_BITS_FORMAT: WireError =
        WireError::new(-32602, "Invalid version bits");
    /// `version_bits` sent without a negotiated version-rolling mask.
    pub const UNEXPECTED_VERSION_BITS: WireError =
        WireError::new(-32602, "Unexpected version bits");
    /// `version-rolling.mask` is not hex.
    pub const INVALID_VERSION_MASK: WireError =
        WireError::new(-32602, "Invalid version-rolling.mask");
    /// Difficulty is not a plain positive decimal.
    pub const INVALID_DIFFICULTY: WireError = WireError::new(-32602, "Invalid difficulty");

    /// Submit before `mining.subscribe`.
    pub const NOT_SUBSCRIBED_ERROR: WireError = WireError::new(NOT_SUBSCRIBED, "Not subscribed");
    /// Submit or authorize outcome for an unknown or denied worker.
    pub const UNAUTHORIZED_WORKER_ERROR: WireError =
        WireError::new(UNAUTHORIZED_WORKER, "Unauthorized worker");
    /// `mining.subscribe` twice.
    pub const ALREADY_SUBSCRIBED: WireError = WireError::new(OTHER, "Already subscribed");
    /// `mining.configure` after work was sent.
    pub const CONFIGURE_TOO_LATE: WireError = WireError::new(OTHER, "Configure after work started");
    /// More workers than one session may authorize.
    pub const TOO_MANY_WORKERS: WireError = WireError::new(OTHER, "Too many workers");
    /// The pool has no free session slot.
    pub const POOL_AT_CAPACITY: WireError = WireError::new(OTHER, "Pool at capacity");
    /// Extranonce rotation is not offered.
    pub const EXTRANONCE_SUBSCRIPTION_UNSUPPORTED: WireError =
        WireError::new(OTHER, "Extranonce subscription not supported");
    /// Difficulty suggestion outside the pool's range.
    pub const DIFFICULTY_OUT_OF_RANGE: WireError = WireError::new(OTHER, "Difficulty out of range");
    /// `version_bits` outside the negotiated mask.
    pub const VERSION_BITS_OUTSIDE_MASK: WireError =
        WireError::new(OTHER, "Version bits outside mask");
    /// `ntime` outside the job window.
    pub const INVALID_NTIME: WireError = WireError::new(OTHER, "Invalid ntime");
    /// The job holds its maximum number of shares.
    pub const JOB_SHARE_CAPACITY: WireError = WireError::new(OTHER, "Job share capacity reached");
    /// The ledger refused the accepted share.
    pub const ACCOUNTING_UNAVAILABLE: WireError =
        WireError::new(OTHER, "Share accounting unavailable");
    /// Share verdict that cannot occur on an open session.
    pub const INTERNAL: WireError = WireError::new(OTHER, "Internal error");
    /// Job id never issued or already retired.
    pub const JOB_NOT_FOUND_ERROR: WireError = WireError::new(JOB_NOT_FOUND, "Job not found");
    /// Job superseded.
    pub const STALE_SHARE: WireError = WireError::new(JOB_NOT_FOUND, "Stale share");
    /// Already accepted.
    pub const DUPLICATE_SHARE_ERROR: WireError = WireError::new(DUPLICATE_SHARE, "Duplicate share");
    /// Hash misses the session target.
    pub const LOW_DIFFICULTY_SHARE: WireError =
        WireError::new(LOW_DIFFICULTY, "Low difficulty share");
}

// ---------------------------------------------------------------------------
// Bounded line framing
// ---------------------------------------------------------------------------

/// Framing failure; the connection must be closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// A line (or an unterminated tail) exceeds the limit.
    LineTooLong,
}

/// Extra bytes one [`LineBuffer::push`] may add beyond the line limit.
const PUSH_SLACK: usize = 64 * 1024;

/// Newline-delimited frame splitter with a hard memory bound.
///
/// Memory never exceeds `max_line + PUSH_SLACK` bytes plus the caller's push
/// size: an unterminated tail longer than `max_line` is an error, so a client
/// that streams without a `\n` cannot grow the buffer.
#[derive(Debug)]
pub struct LineBuffer {
    buf: Vec<u8>,
    start: usize,
    scanned: usize,
    max_line: usize,
    poisoned: bool,
}

impl LineBuffer {
    /// A buffer that rejects lines longer than `max_line` bytes (terminator
    /// excluded).
    #[must_use]
    pub fn new(max_line: usize) -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            scanned: 0,
            max_line,
            poisoned: false,
        }
    }

    /// Appends received bytes. Drain [`Self::next_frame`] to `None` between
    /// pushes.
    pub fn push(&mut self, data: &[u8]) -> Result<(), FrameError> {
        if self.poisoned {
            return Err(FrameError::LineTooLong);
        }
        if self.pending_len().saturating_add(data.len()) > self.max_line.saturating_add(PUSH_SLACK)
        {
            self.poisoned = true;
            return Err(FrameError::LineTooLong);
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// Bytes received and not yet returned as frames.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.buf.len() - self.start
    }

    /// Whether an unterminated tail is buffered.
    #[must_use]
    pub fn has_partial(&self) -> bool {
        self.pending_len() > 0
    }

    /// The next non-empty line without its `\n` or `\r\n`; `None` when only a
    /// partial line remains. Empty lines are skipped.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        if self.poisoned {
            return Err(FrameError::LineTooLong);
        }
        loop {
            let unread = self.buf.len() - self.start;
            let found = self.buf[self.start + self.scanned..]
                .iter()
                .position(|&byte| byte == b'\n');
            let Some(offset) = found else {
                // Allow up to max_line + 1 bytes in unread in case a trailing \r is waiting for \n
                if unread > self.max_line + 1 {
                    self.poisoned = true;
                    return Err(FrameError::LineTooLong);
                }
                self.scanned = unread;
                self.compact();
                return Ok(None);
            };
            let end = self.scanned + offset;
            let mut line = &self.buf[self.start..self.start + end];
            if let Some((&b'\r', head)) = line.split_last() {
                line = head;
            }
            if line.len() > self.max_line {
                self.poisoned = true;
                return Err(FrameError::LineTooLong);
            }
            let frame = line.to_vec();
            self.start += end + 1;
            self.scanned = 0;
            if frame.is_empty() {
                continue;
            }
            self.compact();
            return Ok(Some(frame));
        }
    }

    fn compact(&mut self) {
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        } else if self.start >= 4096 && self.start * 2 >= self.buf.len() {
            self.buf.drain(..self.start);
            self.start = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC decode
// ---------------------------------------------------------------------------

/// JSON text of a string value.
#[must_use]
pub fn json_string(text: &str) -> String {
    sonic_rs::to_string(text).unwrap_or_else(|_| String::from("\"\""))
}

/// A request id, kept as the exact JSON text to echo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestId(String);

impl RequestId {
    /// The JSON `null` id.
    #[must_use]
    pub fn null() -> Self {
        Self(String::from("null"))
    }

    /// JSON text of the id.
    #[must_use]
    pub fn as_json(&self) -> &str {
        &self.0
    }
}

fn request_id(value: Option<&Value>) -> Option<RequestId> {
    let Some(value) = value else {
        return Some(RequestId::null());
    };
    if value.is_null() {
        return Some(RequestId::null());
    }
    if let Some(text) = value.as_str() {
        return (text.len() <= MAX_ID_LEN).then(|| RequestId(json_string(text)));
    }
    if let Some(number) = value.as_u64() {
        return Some(RequestId(number.to_string()));
    }
    value.as_i64().map(|number| RequestId(number.to_string()))
}

/// One decoded client request. Parameters stay inside the parsed document;
/// [`Request::params`] borrows them.
pub struct Request {
    /// Id to echo in the response.
    pub id: RequestId,
    /// Method name, at most [`MAX_METHOD_LEN`] bytes.
    pub method: String,
    document: Value,
}

impl Request {
    /// Positional parameters, at most [`MAX_PARAMS`].
    #[must_use]
    pub fn params(&self) -> &[Value] {
        self.document
            .as_object()
            .and_then(|object| object.get(&"params"))
            .and_then(|params| params.as_array())
            .map_or(&[][..], Array::as_slice)
    }
}

/// Deliberately omits parameters: they can carry a password.
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("id", &self.id)
            .field("method", &self.method)
            .field("params", &self.params().len())
            .finish_non_exhaustive()
    }
}

/// A decoded frame.
#[derive(Debug)]
pub enum Incoming {
    /// A request or notification from the miner.
    Request(Request),
    /// A response to a server request. This adapter sends none, so it is dropped.
    Response,
}

/// A frame that could not be decoded, with the id to answer under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeFailure {
    /// Id to echo; `null` when the frame had no usable id.
    pub id: RequestId,
    /// Error to send.
    pub error: WireError,
}

impl DecodeFailure {
    fn new(id: RequestId, error: WireError) -> Self {
        Self { id, error }
    }
}

fn nesting_exceeds(line: &[u8], limit: usize) -> bool {
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in line {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > limit {
                    return true;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// Decodes one frame (no terminator).
pub fn decode_line(line: &[u8]) -> Result<Incoming, DecodeFailure> {
    if nesting_exceeds(line, MAX_JSON_DEPTH) {
        return Err(DecodeFailure::new(RequestId::null(), errors::PARSE_ERROR));
    }
    let document: Value = sonic_rs::from_slice(line)
        .map_err(|_| DecodeFailure::new(RequestId::null(), errors::PARSE_ERROR))?;
    let (id, method, shape) = {
        let Some(object) = document.as_object() else {
            return Err(DecodeFailure::new(
                RequestId::null(),
                errors::INVALID_REQUEST,
            ));
        };
        let Some(id) = request_id(object.get(&"id")) else {
            return Err(DecodeFailure::new(
                RequestId::null(),
                errors::INVALID_REQUEST,
            ));
        };
        match object.get(&"method") {
            Some(method) => {
                let name = method
                    .as_str()
                    .filter(|name| !name.is_empty() && name.len() <= MAX_METHOD_LEN);
                let Some(name) = name else {
                    return Err(DecodeFailure::new(id, errors::INVALID_REQUEST));
                };
                let params_ok = match object.get(&"params") {
                    None => true,
                    Some(params) if params.is_null() => true,
                    Some(params) => params
                        .as_array()
                        .is_some_and(|array| array.len() <= MAX_PARAMS),
                };
                if !params_ok {
                    return Err(DecodeFailure::new(id, errors::INVALID_PARAMS));
                }
                (id, name.to_owned(), true)
            }
            None => {
                if object.get(&"result").is_some() || object.get(&"error").is_some() {
                    (id, String::new(), false)
                } else {
                    return Err(DecodeFailure::new(id, errors::INVALID_REQUEST));
                }
            }
        }
    };
    if shape {
        Ok(Incoming::Request(Request {
            id,
            method,
            document,
        }))
    } else {
        Ok(Incoming::Response)
    }
}

// ---------------------------------------------------------------------------
// Secrets, accounts, difficulty
// ---------------------------------------------------------------------------

/// A worker password. Not `Clone`, not `Display`; `Debug` prints nothing of it.
pub struct Password(String);

impl Password {
    /// Wraps password text.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// The password text. Callers must not log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

/// Who a share is credited to: the pool account and the rig under it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorkerIdentity {
    /// Account that is paid.
    pub account: String,
    /// Rig name under the account.
    pub worker: String,
}

/// Authentication failed. Carries no reason, so unknown account and wrong
/// password are indistinguishable to the miner and to logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthDenied;

/// Maps a `mining.authorize` login and password to an identity. There is no
/// always-accepting implementation in this crate.
pub trait AccountResolver: Send + Sync {
    /// Resolves the credentials or denies them.
    fn resolve(&self, login: &str, password: &Password) -> Result<WorkerIdentity, AuthDenied>;
}

/// `account` or `account.rig` is not a valid login.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidAccount;

/// Fixed in-memory account table: login is `account` or `account.rig`.
#[derive(Default)]
pub struct StaticAccountResolver {
    accounts: HashMap<String, Password>,
}

fn valid_account(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn valid_rig(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(a ^ b);
    }
    difference == 0
}

impl StaticAccountResolver {
    /// An empty table; every login is denied until accounts are added.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `account` with `password`.
    pub fn with_account(mut self, account: &str, password: &str) -> Result<Self, InvalidAccount> {
        if !valid_account(account) || password.len() > MAX_PASSWORD_LEN {
            return Err(InvalidAccount);
        }
        self.accounts
            .insert(account.to_owned(), Password::new(password));
        Ok(self)
    }
}

impl fmt::Debug for StaticAccountResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticAccountResolver")
            .field("accounts", &self.accounts.len())
            .finish()
    }
}

impl AccountResolver for StaticAccountResolver {
    fn resolve(&self, login: &str, password: &Password) -> Result<WorkerIdentity, AuthDenied> {
        let (account, worker) = match login.split_once('.') {
            Some((account, worker)) => (account, worker),
            None => (login, "default"),
        };
        if !valid_account(account) || !valid_rig(worker) {
            return Err(AuthDenied);
        }
        let stored = self.accounts.get(account);
        let expected = stored.map_or(&[][..], |stored| stored.expose().as_bytes());
        let matches = constant_time_eq(expected, password.expose().as_bytes());
        if matches && stored.is_some() {
            Ok(WorkerIdentity {
                account: account.to_owned(),
                worker: worker.to_owned(),
            })
        } else {
            Err(AuthDenied)
        }
    }
}

/// Why a difficulty text was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DifficultyError {
    /// Not a plain decimal: sign, exponent, empty part, leading zero, or too long.
    Malformed,
    /// Zero names no work.
    Zero,
    /// Bounds are not `min <= initial <= max`.
    OutOfOrder,
}

/// A pool difficulty as plain decimal text plus the share target it names.
///
/// The target comes from `ShareTarget::from_pool_difficulty_decimal`, the
/// common owner of difficulty-to-target arithmetic; no float is involved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Difficulty {
    text: String,
    target: ShareTarget,
}

impl Difficulty {
    /// Parses `"16384"` or `"0.001"`: ASCII digits, an optional `.` with at
    /// least one digit after it, no leading zero before the point, at most
    /// [`MAX_DIFFICULTY_TEXT_LEN`] characters. The text is also valid JSON.
    pub fn parse(text: &str) -> Result<Self, DifficultyError> {
        if text.len() > MAX_DIFFICULTY_TEXT_LEN {
            return Err(DifficultyError::Malformed);
        }
        let (whole, fraction) = match text.split_once('.') {
            Some((whole, fraction)) => (whole, Some(fraction)),
            None => (text, None),
        };
        let canonical = !whole.is_empty()
            && (whole == "0" || !whole.starts_with('0'))
            && fraction.is_none_or(|fraction| !fraction.is_empty());
        if !canonical {
            return Err(DifficultyError::Malformed);
        }
        let target =
            ShareTarget::from_pool_difficulty_decimal(text).map_err(|error| match error {
                JobError::ZeroTarget => DifficultyError::Zero,
                _ => DifficultyError::Malformed,
            })?;
        Ok(Self {
            text: text.to_owned(),
            target,
        })
    }

    /// The decimal text, exactly as sent in `mining.set_difficulty`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The share target this difficulty names.
    #[must_use]
    pub fn target(&self) -> ShareTarget {
        self.target
    }
}

/// Session difficulty bounds: the starting value and the range a miner's
/// `mining.suggest_difficulty` may move it within.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DifficultyPolicy {
    initial: Difficulty,
    min: Difficulty,
    max: Difficulty,
}

impl DifficultyPolicy {
    /// Builds a policy; requires `min <= initial <= max` as difficulties.
    pub fn new(initial: &str, min: &str, max: &str) -> Result<Self, DifficultyError> {
        let policy = Self {
            initial: Difficulty::parse(initial)?,
            min: Difficulty::parse(min)?,
            max: Difficulty::parse(max)?,
        };
        if !policy.contains(&policy.initial) || policy.max.target > policy.min.target {
            return Err(DifficultyError::OutOfOrder);
        }
        Ok(policy)
    }

    /// Difficulty a session starts at.
    #[must_use]
    pub fn initial(&self) -> &Difficulty {
        &self.initial
    }

    /// Whether `difficulty` lies inside `[min, max]`. A larger difficulty is a
    /// smaller target.
    #[must_use]
    pub fn contains(&self, difficulty: &Difficulty) -> bool {
        difficulty.target <= self.min.target && difficulty.target >= self.max.target
    }
}

// ---------------------------------------------------------------------------
// Accounting boundary
// ---------------------------------------------------------------------------

/// The ledger could not take the record right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerUnavailable;

/// Whether a share row was new.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordOutcome {
    /// New row written.
    Recorded,
    /// A row with this header hash already exists; nothing changed.
    AlreadyRecorded,
}

/// Pool accounting, separate from this adapter.
///
/// Implementations must be idempotent on `share.hash`: the adapter retries a
/// failed call, and the common owner's duplicate set makes every first delivery
/// unique.
pub trait ShareLedger: Send + Sync {
    /// Records one accepted share (`share.class` may be `Block`) credited to
    /// `worker`. `share.hash` is the unique key; `share.work` is the work.
    fn record_share(
        &self,
        worker: &WorkerIdentity,
        share: &AcceptedShare,
    ) -> Result<RecordOutcome, LedgerUnavailable>;

    /// Records what the node answered when `block` was submitted. `Err` or an
    /// `Undetermined` receipt means the chain outcome is unknown: keep the
    /// block pending and reconcile from chain observation.
    fn record_block(
        &self,
        worker: &WorkerIdentity,
        block: &FoundBlock,
        submission: &Result<BlockReceipt, MiningControlError>,
    ) -> Result<(), LedgerUnavailable>;
}

// ---------------------------------------------------------------------------
// Typed client requests
// ---------------------------------------------------------------------------

/// Parsed `mining.subscribe`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscribe {
    /// Miner software, truncated to [`MAX_USER_AGENT_LEN`].
    pub user_agent: Option<String>,
}

/// Parsed `mining.authorize`.
#[derive(Debug)]
pub struct Authorize {
    /// Worker login as sent.
    pub login: String,
    /// Worker password; empty when absent.
    pub password: Password,
}

/// Parsed `mining.submit`; lexical checks only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submit {
    /// Worker login as sent.
    pub login: String,
    /// Job id text.
    pub job_id: String,
    /// Miner-chosen extranonce bytes.
    pub extranonce2: Vec<u8>,
    /// Header time.
    pub ntime: u32,
    /// Header nonce.
    pub nonce: u32,
    /// BIP310 rolled bits, when the sixth parameter is present.
    pub version_bits: Option<u32>,
}

/// Parsed `mining.configure`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Configure {
    /// Requested extension names, in request order.
    pub extensions: Vec<String>,
    /// `version-rolling.mask`, present when `version-rolling` was requested.
    pub version_rolling_mask: Option<u32>,
    /// `version-rolling.min-bit-count`, 0 when absent.
    pub version_rolling_min_bits: u32,
}

/// A method this adapter understands, or [`ClientRequest::Unknown`].
#[derive(Debug)]
pub enum ClientRequest {
    /// BIP310 feature negotiation.
    Configure(Configure),
    /// Session start.
    Subscribe(Subscribe),
    /// Worker login.
    Authorize(Authorize),
    /// Share submission.
    Submit(Submit),
    /// NiceHash-dialect extranonce subscription.
    ExtranonceSubscribe,
    /// Miner's preferred difficulty.
    SuggestDifficulty(Difficulty),
    /// Any other method.
    Unknown,
}

fn text_at(params: &[Value], index: usize, max: usize) -> Result<Option<&str>, WireError> {
    match params.get(index) {
        None => Ok(None),
        Some(value) if value.is_null() => Ok(None),
        Some(value) => match value.as_str() {
            Some(text) if text.len() <= max => Ok(Some(text)),
            _ => Err(errors::INVALID_PARAMS),
        },
    }
}

fn required_text_at(params: &[Value], index: usize, max: usize) -> Result<&str, WireError> {
    match text_at(params, index, max)? {
        Some(text) if !text.is_empty() => Ok(text),
        _ => Err(errors::INVALID_PARAMS),
    }
}

fn truncate_utf8(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn parse_subscribe(params: &[Value]) -> Result<Subscribe, WireError> {
    if params.len() > 2 {
        return Err(errors::INVALID_PARAMS);
    }
    // Session-resumption id: validated for shape, never honoured.
    text_at(params, 1, MAX_USER_AGENT_LEN)?;
    let user_agent = match params.first() {
        None => None,
        Some(value) if value.is_null() => None,
        Some(value) => Some(truncate_utf8(
            value.as_str().ok_or(errors::INVALID_PARAMS)?,
            MAX_USER_AGENT_LEN,
        )),
    };
    Ok(Subscribe { user_agent })
}

fn parse_authorize(params: &[Value]) -> Result<Authorize, WireError> {
    if params.is_empty() || params.len() > 2 {
        return Err(errors::INVALID_PARAMS);
    }
    let login = required_text_at(params, 0, MAX_LOGIN_LEN)?.to_owned();
    let password = text_at(params, 1, MAX_PASSWORD_LEN)?.unwrap_or("");
    Ok(Authorize {
        login,
        password: Password::new(password),
    })
}

fn parse_submit(params: &[Value]) -> Result<Submit, WireError> {
    if params.len() != 5 && params.len() != 6 {
        return Err(errors::INVALID_PARAMS);
    }
    let login = required_text_at(params, 0, MAX_LOGIN_LEN)?.to_owned();
    let job_id = required_text_at(params, 1, MAX_JOB_ID_LEN)?.to_owned();
    let extranonce2_text = required_text_at(params, 2, MAX_EXTRANONCE2_BYTES * 2)
        .map_err(|_| errors::INVALID_EXTRANONCE2)?;
    let extranonce2 = decode_hex(extranonce2_text).ok_or(errors::INVALID_EXTRANONCE2)?;
    let ntime =
        parse_u32_hex(required_text_at(params, 3, 8)?, 8).ok_or(errors::INVALID_NTIME_FORMAT)?;
    let nonce =
        parse_u32_hex(required_text_at(params, 4, 8)?, 8).ok_or(errors::INVALID_NONCE_FORMAT)?;
    let version_bits = match text_at(params, 5, 8)? {
        None => None,
        Some(text) => Some(parse_u32_hex(text, 8).ok_or(errors::INVALID_VERSION_BITS_FORMAT)?),
    };
    Ok(Submit {
        login,
        job_id,
        extranonce2,
        ntime,
        nonce,
        version_bits,
    })
}

fn parse_configure(params: &[Value]) -> Result<Configure, WireError> {
    if params.is_empty() || params.len() > 2 {
        return Err(errors::INVALID_PARAMS);
    }
    let names = params[0].as_array().ok_or(errors::INVALID_PARAMS)?;
    if names.len() > MAX_CONFIGURE_EXTENSIONS {
        return Err(errors::INVALID_PARAMS);
    }
    let mut extensions = Vec::with_capacity(names.len());
    for name in names.as_slice() {
        let name = name
            .as_str()
            .filter(|name| !name.is_empty() && name.len() <= MAX_EXTENSION_NAME_LEN)
            .ok_or(errors::INVALID_PARAMS)?;
        extensions.push(name.to_owned());
    }
    let options = match params.get(1) {
        None => None,
        Some(value) if value.is_null() => None,
        Some(value) => Some(value.as_object().ok_or(errors::INVALID_PARAMS)?),
    };
    let mut version_rolling_mask = None;
    let mut version_rolling_min_bits = 0_u32;
    if extensions.iter().any(|name| name == "version-rolling") {
        let options = options.ok_or(errors::INVALID_PARAMS)?;
        let mask_text = options
            .get(&"version-rolling.mask")
            .and_then(|value| value.as_str())
            .ok_or(errors::INVALID_VERSION_MASK)?;
        version_rolling_mask =
            Some(parse_u32_hex(mask_text, 1).ok_or(errors::INVALID_VERSION_MASK)?);
        if let Some(value) = options.get(&"version-rolling.min-bit-count") {
            let bits = value
                .as_u64()
                .filter(|bits| *bits <= 32)
                .ok_or(errors::INVALID_PARAMS)?;
            version_rolling_min_bits = u32::try_from(bits).map_err(|_| errors::INVALID_PARAMS)?;
        }
    }
    Ok(Configure {
        extensions,
        version_rolling_mask,
        version_rolling_min_bits,
    })
}

/// The decimal text of a JSON number: integers verbatim, fractions through
/// Rust's shortest round-trip `Display` (never an exponent). No arithmetic.
fn number_text(value: &Value) -> Option<String> {
    if !value.is_number() {
        return None;
    }
    if let Some(whole) = value.as_u64() {
        return Some(whole.to_string());
    }
    let float = value.as_f64()?;
    (float.is_finite() && float > 0.0).then(|| format!("{float}"))
}

fn parse_suggest(params: &[Value]) -> Result<Difficulty, WireError> {
    let [value] = params else {
        return Err(errors::INVALID_PARAMS);
    };
    let text = number_text(value).ok_or(errors::INVALID_DIFFICULTY)?;
    Difficulty::parse(&text).map_err(|_| errors::INVALID_DIFFICULTY)
}

impl ClientRequest {
    /// Types a decoded request, or says which parameter is wrong.
    pub fn parse(request: &Request) -> Result<Self, WireError> {
        let params = request.params();
        match request.method.as_str() {
            "mining.configure" => parse_configure(params).map(Self::Configure),
            "mining.subscribe" => parse_subscribe(params).map(Self::Subscribe),
            "mining.authorize" => parse_authorize(params).map(Self::Authorize),
            "mining.submit" => parse_submit(params).map(Self::Submit),
            "mining.extranonce.subscribe" => {
                if params.is_empty() {
                    Ok(Self::ExtranonceSubscribe)
                } else {
                    Err(errors::INVALID_PARAMS)
                }
            }
            "mining.suggest_difficulty" => parse_suggest(params).map(Self::SuggestDifficulty),
            _ => Ok(Self::Unknown),
        }
    }
}

// ---------------------------------------------------------------------------
// Encoders
// ---------------------------------------------------------------------------

/// `{"id":ID,"result":RESULT,"error":null}\n`
#[must_use]
pub fn encode_result(id: &RequestId, result_json: &str) -> String {
    format!(
        "{{\"id\":{},\"result\":{},\"error\":null}}\n",
        id.as_json(),
        result_json
    )
}

/// `{"id":ID,"result":null,"error":[code,"message",null]}\n`
#[must_use]
pub fn encode_error(id: &RequestId, error: &WireError) -> String {
    format!(
        "{{\"id\":{},\"result\":null,\"error\":{}}}\n",
        id.as_json(),
        error.to_json()
    )
}

/// `{"id":ID,"result":false,"error":[code,"message",null]}\n`: a refused
/// authorize or share.
#[must_use]
pub fn encode_reject(id: &RequestId, error: &WireError) -> String {
    format!(
        "{{\"id\":{},\"result\":false,\"error\":{}}}\n",
        id.as_json(),
        error.to_json()
    )
}

/// `mining.set_difficulty` notification.
#[must_use]
pub fn encode_set_difficulty(difficulty: &Difficulty) -> String {
    format!(
        "{{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[{}]}}\n",
        difficulty.as_str()
    )
}

/// `mining.notify` notification for `job`.
///
/// The parent hash is word-swapped; `coinb1`, `coinb2` and the merkle branch are
/// the common owner's bytes verbatim; version, nbits and ntime are eight hex
/// digits of the integer.
#[must_use]
pub fn encode_notify(job: &Job, clean_jobs: bool) -> String {
    let parent = Hash256::from(job.previous_block_hash()).to_le_bytes();
    let mut line = String::with_capacity(
        384 + 2 * (job.coinbase_prefix().len() + job.coinbase_suffix().len())
            + 68 * job.merkle_branch().len(),
    );
    line.push_str("{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"");
    line.push_str(&wire_job_id(job.id()));
    line.push_str("\",\"");
    push_hex(&mut line, &swap_words(&parent));
    line.push_str("\",\"");
    push_hex(&mut line, job.coinbase_prefix());
    line.push_str("\",\"");
    push_hex(&mut line, job.coinbase_suffix());
    line.push_str("\",[");
    for (index, sibling) in job.merkle_branch().iter().enumerate() {
        if index > 0 {
            line.push(',');
        }
        line.push('"');
        push_hex(&mut line, &sibling.to_le_bytes());
        line.push('"');
    }
    line.push_str("],\"");
    line.push_str(&format!("{:08x}", job.version()));
    line.push_str("\",\"");
    line.push_str(&format!("{:08x}", job.bits().to_consensus()));
    line.push_str("\",\"");
    line.push_str(&format!("{:08x}", job.ntime()));
    line.push_str("\",");
    line.push_str(if clean_jobs { "true" } else { "false" });
    line.push_str("]}\n");
    line
}
