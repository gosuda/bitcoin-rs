//! Native Stratum V1 pool adapter.
#![forbid(unsafe_code)]

mod session;

use std::collections::HashMap;
use std::fmt;

use crate::pool::{Job, JobError, JobId, ShareTarget, WorkerIdentity};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::encode::hex_encode as primitives_hex_encode;
use sonic_rs::{Array, JsonContainerTrait, JsonValueTrait, Value};

pub use crate::pool::{BlockOutcome, PoolCore, RefreshError, Refreshed};
pub use session::{
    ConfigError, ConnectionLimiter, ConnectionPermit, Observer, RefusalReason, Server,
    ServerConfig, ServerDeps, ServerEvent, SessionEnd, ShutdownReport,
};

pub const MAX_ID_LEN: usize = 128;
pub const MAX_METHOD_LEN: usize = 64;
pub const MAX_PARAMS: usize = 8;
pub const MAX_LOGIN_LEN: usize = 128;
pub const MAX_PASSWORD_LEN: usize = 128;
pub const MAX_USER_AGENT_LEN: usize = 128;
pub const MAX_JOB_ID_LEN: usize = 64;
pub const MAX_EXTRANONCE2_BYTES: usize = 32;
pub const MAX_CONFIGURE_EXTENSIONS: usize = 16;
pub const MAX_EXTENSION_NAME_LEN: usize = 64;
pub const MAX_JSON_DEPTH: usize = 8;
pub const MAX_DIFFICULTY_TEXT_LEN: usize = 20;

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn push_hex(out: &mut String, bytes: &[u8]) {
    out.push_str(&primitives_hex_encode(bytes));
}

#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    primitives_hex_encode(bytes)
}

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

/// One SV1 error triple `[code, message, null]`. Messages are fixed text:
/// nothing internal reaches a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireError {
    pub code: i32,
    pub message: &'static str,
}

impl WireError {
    #[must_use]
    pub const fn new(code: i32, message: &'static str) -> Self {
        Self { code, message }
    }

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

    pub const OTHER: i32 = 20;
    /// Slush draft 21: job not found (stale).
    pub const JOB_NOT_FOUND: i32 = 21;
    /// Slush draft 22: duplicate share.
    pub const DUPLICATE_SHARE: i32 = 22;
    /// Slush draft 23: low difficulty share.
    pub const LOW_DIFFICULTY: i32 = 23;
    pub const UNAUTHORIZED_WORKER: i32 = 24;
    pub const NOT_SUBSCRIBED: i32 = 25;

    pub const PARSE_ERROR: WireError = WireError::new(-32700, "Parse error");
    pub const INVALID_REQUEST: WireError = WireError::new(-32600, "Invalid request");
    pub const METHOD_NOT_FOUND: WireError = WireError::new(-32601, "Method not found");
    pub const INVALID_PARAMS: WireError = WireError::new(-32602, "Invalid params");
    pub const INVALID_EXTRANONCE2: WireError = WireError::new(-32602, "Invalid extranonce2");
    pub const INVALID_EXTRANONCE2_LENGTH: WireError =
        WireError::new(-32602, "Invalid extranonce2 length");
    pub const INVALID_NTIME_FORMAT: WireError = WireError::new(-32602, "Invalid ntime");
    pub const INVALID_NONCE_FORMAT: WireError = WireError::new(-32602, "Invalid nonce");
    pub const INVALID_VERSION_BITS_FORMAT: WireError =
        WireError::new(-32602, "Invalid version bits");
    pub const UNEXPECTED_VERSION_BITS: WireError =
        WireError::new(-32602, "Unexpected version bits");
    pub const INVALID_VERSION_MASK: WireError =
        WireError::new(-32602, "Invalid version-rolling.mask");
    pub const INVALID_DIFFICULTY: WireError = WireError::new(-32602, "Invalid difficulty");

    pub const NOT_SUBSCRIBED_ERROR: WireError = WireError::new(NOT_SUBSCRIBED, "Not subscribed");
    pub const UNAUTHORIZED_WORKER_ERROR: WireError =
        WireError::new(UNAUTHORIZED_WORKER, "Unauthorized worker");
    pub const ALREADY_SUBSCRIBED: WireError = WireError::new(OTHER, "Already subscribed");
    pub const CONFIGURE_TOO_LATE: WireError = WireError::new(OTHER, "Configure after work started");
    pub const TOO_MANY_WORKERS: WireError = WireError::new(OTHER, "Too many workers");
    pub const POOL_AT_CAPACITY: WireError = WireError::new(OTHER, "Pool at capacity");
    pub const EXTRANONCE_SUBSCRIPTION_UNSUPPORTED: WireError =
        WireError::new(OTHER, "Extranonce subscription not supported");
    pub const DIFFICULTY_OUT_OF_RANGE: WireError = WireError::new(OTHER, "Difficulty out of range");
    pub const VERSION_BITS_OUTSIDE_MASK: WireError =
        WireError::new(OTHER, "Version bits outside mask");
    pub const INVALID_NTIME: WireError = WireError::new(OTHER, "Invalid ntime");
    pub const JOB_SHARE_CAPACITY: WireError = WireError::new(OTHER, "Job share capacity reached");
    pub const ACCOUNTING_UNAVAILABLE: WireError =
        WireError::new(OTHER, "Share accounting unavailable");
    pub const INTERNAL: WireError = WireError::new(OTHER, "Internal error");
    pub const JOB_NOT_FOUND_ERROR: WireError = WireError::new(JOB_NOT_FOUND, "Job not found");
    pub const STALE_SHARE: WireError = WireError::new(JOB_NOT_FOUND, "Stale share");
    pub const DUPLICATE_SHARE_ERROR: WireError = WireError::new(DUPLICATE_SHARE, "Duplicate share");
    pub const LOW_DIFFICULTY_SHARE: WireError =
        WireError::new(LOW_DIFFICULTY, "Low difficulty share");
}

/// Framing failure; the connection must be closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    LineTooLong,
}

const PUSH_SLACK: usize = 64 * 1024;

/// Newline-delimited frame splitter with a hard memory bound.
#[derive(Debug)]
pub struct LineBuffer {
    buf: Vec<u8>,
    start: usize,
    scanned: usize,
    max_line: usize,
    poisoned: bool,
}

impl LineBuffer {
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

    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.buf.len() - self.start
    }

    #[must_use]
    pub fn has_partial(&self) -> bool {
        self.pending_len() > 0
    }

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

#[must_use]
pub fn json_string(text: &str) -> String {
    sonic_rs::to_string(text).unwrap_or_else(|_| String::from("\"\""))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestId(String);

impl RequestId {
    #[must_use]
    pub fn null() -> Self {
        Self(String::from("null"))
    }

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

pub struct Request {
    pub id: RequestId,
    pub has_id: bool,
    pub method: String,
    document: Value,
}

impl Request {
    #[must_use]
    pub fn params(&self) -> &[Value] {
        self.document
            .as_object()
            .and_then(|object| object.get(&"params"))
            .and_then(|params| params.as_array())
            .map_or(&[][..], Array::as_slice)
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("id", &self.id)
            .field("method", &self.method)
            .field("params", &self.params().len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum Incoming {
    Request(Request),
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeFailure {
    pub id: RequestId,
    pub error: WireError,
    pub has_id: bool,
}

impl DecodeFailure {
    fn new(id: RequestId, error: WireError) -> Self {
        Self {
            id,
            error,
            has_id: true,
        }
    }

    fn notification(id: RequestId, error: WireError) -> Self {
        Self {
            id,
            error,
            has_id: false,
        }
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

pub fn decode_line(line: &[u8]) -> Result<Incoming, DecodeFailure> {
    if nesting_exceeds(line, MAX_JSON_DEPTH) {
        return Err(DecodeFailure::new(RequestId::null(), errors::PARSE_ERROR));
    }
    let document: Value = sonic_rs::from_slice(line)
        .map_err(|_| DecodeFailure::new(RequestId::null(), errors::PARSE_ERROR))?;
    let (id, has_id, method, shape) = {
        let Some(object) = document.as_object() else {
            return Err(DecodeFailure::new(
                RequestId::null(),
                errors::INVALID_REQUEST,
            ));
        };
        let has_id = object.get(&"id").is_some();
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
                    if has_id {
                        return Err(DecodeFailure::new(id, errors::INVALID_REQUEST));
                    }
                    return Err(DecodeFailure::notification(id, errors::INVALID_REQUEST));
                };
                let params_ok = match object.get(&"params") {
                    None => true,
                    Some(params) if params.is_null() => true,
                    Some(params) => params
                        .as_array()
                        .is_some_and(|array| array.len() <= MAX_PARAMS),
                };
                if !params_ok {
                    if has_id {
                        return Err(DecodeFailure::new(id, errors::INVALID_PARAMS));
                    }
                    return Err(DecodeFailure::notification(id, errors::INVALID_PARAMS));
                }
                (id, has_id, name.to_owned(), true)
            }
            None => {
                if object.get(&"result").is_some() || object.get(&"error").is_some() {
                    (id, has_id, String::new(), false)
                } else if has_id {
                    return Err(DecodeFailure::new(id, errors::INVALID_REQUEST));
                } else {
                    return Err(DecodeFailure::notification(id, errors::INVALID_REQUEST));
                }
            }
        }
    };
    if shape {
        Ok(Incoming::Request(Request {
            id,
            has_id,
            method,
            document,
        }))
    } else {
        Ok(Incoming::Response)
    }
}

pub struct Password(String);

impl Password {
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthDenied;

pub trait AccountResolver: Send + Sync {
    fn resolve(&self, login: &str, password: &Password) -> Result<WorkerIdentity, AuthDenied>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidAccount;

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
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DifficultyError {
    Malformed,
    Zero,
    OutOfOrder,
}

/// A pool difficulty as plain decimal text plus the share target it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Difficulty {
    text: String,
    target: ShareTarget,
}

impl Difficulty {
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

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

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

    #[must_use]
    pub fn initial(&self) -> &Difficulty {
        &self.initial
    }

    #[must_use]
    pub fn contains(&self, difficulty: &Difficulty) -> bool {
        difficulty.target <= self.min.target && difficulty.target >= self.max.target
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscribe {
    pub user_agent: Option<String>,
}

#[derive(Debug)]
pub struct Authorize {
    pub login: String,
    pub password: Password,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submit {
    pub login: String,
    pub job_id: String,
    pub extranonce2: Vec<u8>,
    pub ntime: u32,
    pub nonce: u32,
    pub version_bits: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Configure {
    pub extensions: Vec<String>,
    pub version_rolling_mask: Option<u32>,
    pub version_rolling_min_bits: u32,
}

#[derive(Debug)]
pub enum ClientRequest {
    Configure(Configure),
    Subscribe(Subscribe),
    Authorize(Authorize),
    Submit(Submit),
    ExtranonceSubscribe,
    SuggestDifficulty(Difficulty),
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

#[must_use]
fn encode_envelope(id: &RequestId, result_fragment: &str, error_fragment: &str) -> String {
    format!(
        "{{\"id\":{},\"result\":{},\"error\":{}}}\n",
        id.as_json(),
        result_fragment,
        error_fragment
    )
}

/// `{"id":ID,"result":RESULT,"error":null}\n`
#[must_use]
pub fn encode_result(id: &RequestId, result_json: &str) -> String {
    encode_envelope(id, result_json, "null")
}

#[must_use]
pub fn encode_error(id: &RequestId, error: &WireError) -> String {
    encode_envelope(id, "null", &error.to_json())
}

#[must_use]
pub fn encode_reject(id: &RequestId, error: &WireError) -> String {
    encode_envelope(id, "false", &error.to_json())
}

#[must_use]
pub fn encode_set_difficulty(difficulty: &Difficulty) -> String {
    format!(
        "{{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[{}]}}\n",
        difficulty.as_str()
    )
}

/// `mining.notify` notification for `job`.
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

#[cfg(test)]
mod notification_tests {
    use super::{DecodeFailure, Incoming, decode_line, errors};

    fn has_id_of(line: &[u8]) -> Option<bool> {
        match decode_line(line) {
            Ok(Incoming::Request(request)) => Some(request.has_id),
            Ok(Incoming::Response) => None,
            Err(DecodeFailure { has_id, .. }) => Some(has_id),
        }
    }

    #[test]
    fn calls_carry_has_id_and_notifications_do_not() {
        let call = br#"{"id":7,"method":"mining.subscribe","params":[]}"#;
        let decoded = decode_line(call)
            .unwrap_or_else(|error| panic!("a call with an id decodes: {error:?}"));
        match decoded {
            Incoming::Request(request) => {
                assert!(request.has_id);
                assert_eq!(request.id.as_json(), "7");
            }
            Incoming::Response => panic!("a method frame is not a response"),
        }

        let notification = br#"{"method":"mining.subscribe","params":[]}"#;
        let decoded = decode_line(notification)
            .unwrap_or_else(|error| panic!("a notification decodes: {error:?}"));
        match decoded {
            Incoming::Request(request) => {
                assert!(!request.has_id);
                assert_eq!(request.id.as_json(), "null");
            }
            Incoming::Response => panic!("a method frame is not a response"),
        }
    }

    #[test]
    fn explicit_null_id_is_a_call_not_a_notification() {
        let line = br#"{"id":null,"method":"mining.subscribe","params":[]}"#;
        assert_eq!(has_id_of(line), Some(true));
    }

    #[test]
    fn only_notifications_suppress_their_failure_reply() {
        let bad_call = br#"{"id":3,"method":"","params":[]}"#;
        match decode_line(bad_call) {
            Err(failure) => {
                assert!(failure.has_id);
                assert_eq!(failure.error, errors::INVALID_REQUEST);
            }
            Ok(_) => panic!("an empty method is invalid"),
        }

        let bad_notification = br#"{"method":"","params":[]}"#;
        match decode_line(bad_notification) {
            Err(failure) => {
                assert!(!failure.has_id);
                assert_eq!(failure.error, errors::INVALID_REQUEST);
            }
            Ok(_) => panic!("an empty method is invalid"),
        }
    }
}
