//! I2P SAM v3 client (pinned IVNP bridge) for typed I2P transports.
//!
//! One persistent `SESSION CREATE STYLE=STREAM` root is held per session;
//! every dial opens a fresh SAM bridge connection with `STREAM CONNECT`,
//! and inbound streams arrive through fresh `STREAM ACCEPT` bridges.
//! Names resolve only through `NAMING LOOKUP` on the bridge — never
//! through the system resolver — and no failure falls back to direct TCP.
//! Private destination material is never logged.
//!
//! Each installed root carries a generation. A stream request is issued
//! against the root that was live when the caller started, so a stale
//! `INVALID_ID` retires only that root and never one recovered meanwhile.
//! The generation rises only when a root is installed.
//!
//! # Root readiness
//!
//! The pinned bridge answers `SESSION CREATE` only once its destination is
//! ready, which can take its whole readiness wait ([`READINESS_WAIT`]).
//! A root under construction is therefore one resumable [`PendingRoot`]
//! owned by the `recovery` state: its socket, one absolute readiness
//! deadline fixed once per root, before its socket connects, so the budget
//! covers the TCP connect, `HELLO`, the readiness wait, and `NAMING LOOKUP`
//! together, an explicit [`RootPhase`], the count of command bytes the socket
//! already accepted, and the bounded partial reply line. A connect or accept
//! caller advances it only while it holds `recovery`, bounded by the earlier
//! of its own deadline and the root's deadline. A caller deadline pauses the
//! exchange and reports `TimedOut`; the next caller resumes the same
//! exchange, so each command reaches the bridge exactly once. Only a hard
//! protocol or I/O failure, the root deadline, or [`SamSession::close`]
//! discards it. A TCP connect that cannot finish inside a caller's deadline
//! is abandoned: nothing was sent, so nothing can be duplicated. The
//! readiness budget is separate from the per-stream [`EXCHANGE_BUDGET`].
//!
//! [`SamSession::close`] wakes a connected root at once. Before the socket
//! exists there is nothing to wake, so `close` waits for at most the one
//! connect attempt in flight (at most [`EXCHANGE_BUDGET`]) and never for the
//! root's budget.
//!
//! # Lock order
//!
//! `recovery` then `control`, never the reverse. `wake` is a leaf: no other
//! lock is taken while it is held, and `close` releases it before taking
//! `recovery`.

use parking_lot::{Mutex, MutexGuard};
use std::cell::Cell;
use std::fmt::Write as _;
use std::fs::OpenOptions;
#[cfg(test)]
use std::io::BufReader;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bitcoin::secp256k1::rand::{Rng, RngCore, thread_rng};
use bitcoin_rs_primitives::endpoint::base32_encode;
use sha2::{Digest, Sha256};

/// How long the pinned IVNP bridge may take to answer `SESSION CREATE`: its
/// default SAM readiness wait (`operating.go:471-473`). Readiness needs an
/// inbound tunnel, an outbound tunnel, and a confirmed publication.
const READINESS_WAIT: Duration = Duration::from_secs(120);

/// Budget of one bounded exchange: a stream request, a key step, and each
/// of the connect, `HELLO`, and `NAMING LOOKUP` steps that bracket the
/// readiness wait. It is never widened to cover the readiness wait.
pub(crate) const EXCHANGE_BUDGET: Duration = Duration::from_secs(5);

/// Owner budget for one root: the readiness wait plus three bounded steps
/// (connect, `HELLO`, `NAMING LOOKUP`).
pub(crate) const ROOT_READINESS_BUDGET: Duration =
    READINESS_WAIT.saturating_add(Duration::from_secs(3 * EXCHANGE_BUDGET.as_secs()));

/// How long startup keeps retrying a bridge that has never accepted a
/// connection (a refused or black-holed `--i2psam` address): the overall
/// startup limit this node had before the readiness budget existed. It
/// bounds the TCP connect waits as well as the retries: no connect attempt
/// waits past it while the bridge has never accepted. Only a bridge that
/// connects is given [`ROOT_READINESS_BUDGET`], and once one has connected
/// the window no longer applies.
const UNREACHABLE_WINDOW: Duration = Duration::from_secs(20);

/// Longest wait before a blocked root read or write notices cancellation. It
/// only slices waits; every slice is clipped to the remaining deadline. A TCP
/// connect is not sliced this finely: a handshake needs one full round trip
/// inside its timeout, so each attempt gets up to [`EXCHANGE_BUDGET`].
const CANCEL_POLL: Duration = Duration::from_millis(100);

/// Retry pause growth per failed startup step, in milliseconds.
const PAUSE_STEP_MS: u64 = 250;

/// Failed startup steps after which the retry pause stops growing.
const PAUSE_STEPS_MAX: u64 = 10;

/// Longest single pause between startup steps: the grown base plus full jitter.
pub(crate) const MAX_RETRY_PAUSE: Duration =
    Duration::from_millis(PAUSE_STEP_MS * PAUSE_STEPS_MAX + PAUSE_STEP_MS);

/// Remaining budget before `deadline`.
///
/// An exhausted deadline is reported as `TimedOut` rather than handed to
/// the socket layer, which rejects a zero timeout as `InvalidInput`.
fn remaining_timeout(deadline: Instant) -> io::Result<Duration> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(rem) if !rem.is_zero() => Ok(rem),
        _ => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "sam exchange deadline expired",
        )),
    }
}

/// Acquire `mutex` without waiting past `deadline`.
///
/// Every blocking step on the recovery path is charged to the caller's
/// absolute deadline, so a wider budget held by another caller can never
/// extend this exchange. An expired budget is reported here rather than
/// handed to the lock, which would wait without one.
fn lock_within<T>(mutex: &Mutex<T>, deadline: Instant) -> io::Result<MutexGuard<'_, T>> {
    let remaining = remaining_timeout(deadline)?;
    mutex.try_lock_for(remaining).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "sam recovery deadline expired waiting for the session lock",
        )
    })
}

const MAX_SAM_LINE: usize = 16_384;

/// Derive the SAM session id for one node instance from its private
/// destination, so two nodes sharing one SAM bridge never collide on
/// `SESSION CREATE`. Stable for the life of one destination key; falls
/// back to a process-random suffix when the destination cannot decode.
#[must_use]
fn session_id_for(private_destination: &str) -> String {
    let mut out = String::from("btcrs-");
    if let Some(bytes) = i2p_base64_decode(private_destination) {
        let hash = Sha256::digest(&bytes);
        for b in &hash[..6] {
            let _ = write!(out, "{b:02x}");
        }
    } else {
        let mut bytes = [0u8; 6];
        thread_rng().fill_bytes(&mut bytes);
        for b in bytes {
            let _ = write!(out, "{b:02x}");
        }
    }
    out
}

/// Strict canonical I2P base64 decode (SAM alphabet: `-`/`~` replace
/// `+`/`/`; the standard alphabet is also accepted).
///
/// Canonicality is load-bearing: destinations decoded here are hashed
/// into peer endpoints and accepted as key material, so malformed
/// encodings must not silently decode. Rejects: invalid alphabet bytes
/// (including whitespace/control bytes), padding anywhere except one or
/// two trailing `=` completing a quartet, any data after padding,
/// non-zero padding bits, and truncated quartets (a lone trailing
/// character or padding that does not complete a group of four).
#[must_use]
pub(crate) fn i2p_base64_decode(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() {
        return None;
    }
    let bytes = text.as_bytes();
    let padding = bytes.iter().rev().take_while(|b| **b == b'=').count();
    if padding > 2 {
        return None;
    }
    let core = &bytes[..bytes.len() - padding];
    if core.contains(&b'=') {
        return None; // padding embedded in the body, or data after padding
    }
    if padding > 0 && !(core.len() + padding).is_multiple_of(4) {
        return None; // padding does not complete a quartet
    }
    if core.len() % 4 == 1 {
        return None; // truncated quartet
    }
    let mut values = Vec::with_capacity(core.len());
    for byte in core {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'~' => 63,
            _ => return None,
        };
        values.push(value);
    }
    // Non-zero padding bits make the encoding non-canonical: a final
    // pair carries 4 spare bits, a final triple carries 2.
    match values.len() % 4 {
        2 if values.last().is_some_and(|v| v & 0x0f != 0) => return None,
        3 if values.last().is_some_and(|v| v & 0x03 != 0) => return None,
        _ => {}
    }
    let mut out = Vec::with_capacity(values.len() * 3 / 4);
    for chunk in values.chunks(4) {
        let mut acc: u32 = 0;
        for (index, value) in chunk.iter().enumerate() {
            acc |= u32::from(*value) << (18 - 6 * index);
        }
        match chunk.len() {
            4 => out.extend_from_slice(&acc.to_be_bytes()[1..]),
            3 => out.extend_from_slice(&acc.to_be_bytes()[1..3]),
            2 => out.push(acc.to_be_bytes()[1]),
            _ => return None,
        }
    }
    Some(out)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// The one failure a closed session reports from every entry point.
fn session_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "sam session is closed")
}

struct SamConn {
    reader: TcpStream,
    writer: TcpStream,
}

impl SamConn {
    fn connect_with_deadline(sam: SocketAddr, deadline: Instant) -> io::Result<Self> {
        let rem = remaining_timeout(deadline)?;
        let stream = TcpStream::connect_timeout(&sam, rem)?;
        stream.set_read_timeout(Some(rem))?;
        stream.set_write_timeout(Some(rem))?;
        Self::from_stream(stream)
    }

    /// Wrap a connected bridge socket as a reader and a writer half.
    fn from_stream(stream: TcpStream) -> io::Result<Self> {
        let _ = stream.set_nodelay(true);
        let writer = stream.try_clone()?;
        Ok(Self {
            reader: stream,
            writer,
        })
    }

    /// Read one reply line byte at a time. This is deliberately
    /// unbuffered: after `STREAM STATUS RESULT=OK` the same socket
    /// carries bridged peer payload, and a buffered reader could
    /// prefetch and drop those bytes when the stream is handed off.
    ///
    /// The deadline is absolute: the remaining budget is recomputed
    /// before every byte, so a bridge that trickles one byte inside each
    /// socket timeout cannot stretch the exchange past the deadline.
    ///
    /// EOF before `\n` is always a truncated exchange, never a reply, even
    /// when the bytes read so far are syntactically complete.
    fn read_line(&mut self, deadline: Instant) -> io::Result<String> {
        let mut line = Vec::new();
        loop {
            let rem = remaining_timeout(deadline)?;
            self.reader.set_read_timeout(Some(rem))?;
            let mut byte = [0u8; 1];
            let read = match self.reader.read(&mut byte) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sam bridge closed the connection before the reply line ended",
                ));
            }
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
            if line.len() >= MAX_SAM_LINE {
                return Err(invalid("sam reply line exceeds the bound"));
            }
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        String::from_utf8(line).map_err(|_| invalid("sam reply line is not utf-8"))
    }

    /// Write every byte of `buf` inside `deadline`, recomputing the
    /// socket timeout before each partial write.
    fn write_all_deadline(&mut self, mut buf: &[u8], deadline: Instant) -> io::Result<()> {
        while !buf.is_empty() {
            let rem = remaining_timeout(deadline)?;
            self.writer.set_write_timeout(Some(rem))?;
            match self.writer.write(buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "sam bridge stopped accepting commands",
                    ));
                }
                Ok(written) => buf = &buf[written..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn command(&mut self, command: &str, deadline: Instant) -> io::Result<String> {
        self.write_all_deadline(command.as_bytes(), deadline)?;
        self.write_all_deadline(b"\n", deadline)?;
        self.read_line(deadline)
    }

    /// SAM handshake: requires the bridge to negotiate exactly 3.3.
    fn hello(&mut self, deadline: Instant) -> io::Result<()> {
        let reply = self.command("HELLO VERSION MIN=3.1 MAX=3.3", deadline)?;
        check_hello(&reply)
    }

    /// Whether the bridge still holds this session's control connection.
    ///
    /// The probe must not spend the caller's exchange budget, so the
    /// socket is switched to non-blocking for one `MSG_PEEK`: a healthy
    /// idle root reports `WouldBlock`. Only an orderly close or a hard
    /// connection error counts as dead; an unrecognized error leaves a
    /// possibly-live root alone, because replacing a live root would
    /// race the bridge into `DUPLICATED_ID`.
    fn is_alive(&mut self) -> bool {
        if self.reader.set_nonblocking(true).is_err() {
            return false;
        }
        let mut buf = [0u8; 1];
        let alive = match self.reader.peek(&mut buf) {
            Ok(read) => read > 0,
            Err(error) => {
                error.kind() == io::ErrorKind::Interrupted
                    || !matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::NotConnected
                    )
            }
        };
        // Restoring the blocking mode is best effort: the root is only
        // ever peeked, never read for payload, so a failed restore cannot
        // corrupt the session and must not declare a live root dead.
        let _ = self.reader.set_nonblocking(false);
        alive
    }

    fn into_stream(self) -> TcpStream {
        // Reads were unbuffered, so no bridged bytes can be stranded.
        let _ = self.writer.set_read_timeout(None);
        let _ = self.writer.set_write_timeout(None);
        let _ = self.reader.set_read_timeout(None);
        let _ = self.reader.set_write_timeout(None);
        self.writer
    }
}

/// Require a `HELLO REPLY` that negotiated exactly version 3.3.
fn check_hello(reply: &str) -> io::Result<()> {
    let fields = parse_fields(reply, "HELLO REPLY")?;
    if field(&fields, "RESULT") != Some("OK") || field(&fields, "VERSION") != Some("3.3") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sam bridge did not negotiate version 3.3",
        ));
    }
    Ok(())
}

/// Parse `VERB SUBVERB KEY=VALUE ...` SAM replies with quote awareness,
/// exact verb boundary, and duplicate key rejection.
fn parse_fields(reply: &str, prefix: &str) -> io::Result<Vec<(String, String)>> {
    let rest = if reply == prefix {
        ""
    } else if let Some(stripped) = reply.strip_prefix(prefix) {
        if !stripped.starts_with(' ') && !stripped.starts_with('\t') {
            return Err(invalid("unexpected sam reply verb boundary"));
        }
        stripped.trim_start()
    } else {
        return Err(invalid("unexpected sam reply prefix"));
    };

    let mut fields: Vec<(String, String)> = Vec::new();
    let chars: Vec<char> = rest.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        if fields.len() >= 64 {
            return Err(invalid("too many fields in sam reply"));
        }
        let key_start = i;
        while i < chars.len() && chars[i] != '=' && chars[i] != ' ' && chars[i] != '\t' {
            i += 1;
        }
        if i >= chars.len() || chars[i] != '=' {
            return Err(invalid("malformed sam field: token missing '='"));
        }
        let key: String = chars[key_start..i].iter().collect();
        if key.is_empty() {
            return Err(invalid("malformed sam field: empty key"));
        }
        i += 1; // skip '='

        if i < chars.len() && chars[i] == '"' {
            i += 1; // skip opening quote
            let val_start = i;
            while i < chars.len() && chars[i] != '"' {
                i += 1;
            }
            if i >= chars.len() {
                return Err(invalid("malformed sam field: unterminated quoted value"));
            }
            let value: String = chars[val_start..i].iter().collect();
            i += 1; // skip closing quote
            if i < chars.len() && chars[i] != ' ' && chars[i] != '\t' {
                return Err(invalid(
                    "malformed sam field: trailing characters after quote",
                ));
            }
            if fields.iter().any(|(k, _)| k == &key) {
                return Err(invalid("duplicate field in sam reply"));
            }
            fields.push((key, value));
        } else {
            let val_start = i;
            while i < chars.len() && chars[i] != ' ' && chars[i] != '\t' {
                i += 1;
            }
            let value: String = chars[val_start..i].iter().collect();
            if value.is_empty() {
                return Err(invalid("malformed sam field: empty value"));
            }
            if fields.iter().any(|(k, _)| k == &key) {
                return Err(invalid("duplicate field in sam reply"));
            }
            fields.push((key, value));
        }
    }
    Ok(fields)
}

fn field<'a>(fields: &'a [(String, String)], key: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn sanitize_sam_result(result: &str) -> &'static str {
    match result {
        "OK" => "OK",
        "CANT_REACH_PEER" => "CANT_REACH_PEER",
        "KEY_NOT_FOUND" => "KEY_NOT_FOUND",
        "PEER_NOT_FOUND" => "PEER_NOT_FOUND",
        "TIMEOUT" => "TIMEOUT",
        "I2P_ERROR" => "I2P_ERROR",
        "INVALID_KEY" => "INVALID_KEY",
        "INVALID_ID" => "INVALID_ID",
        "ALREADY_ACCEPTING" => "ALREADY_ACCEPTING",
        "DUPLICATED_ID" => "DUPLICATED_ID",
        "DUPLICATED_DEST" => "DUPLICATED_DEST",
        _ => "UNKNOWN",
    }
}

fn require_ok(reply: &str, prefix: &str) -> io::Result<Vec<(String, String)>> {
    let fields = parse_fields(reply, prefix)?;
    if field(&fields, "RESULT") != Some("OK") {
        let raw = field(&fields, "RESULT").unwrap_or("");
        let sanitized = sanitize_sam_result(raw);
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("sam request failed: {prefix} RESULT={sanitized}"),
        ));
    }
    Ok(fields)
}

/// Length of the I2P `KeysAndCert` identity when `bytes` opens with a
/// structurally valid destination: 384 key bytes plus a certificate
/// (3-byte header + payload) at offset 384. For `CertificateKey` (5)
/// the payload must be exactly `4 + signing excess + crypto excess`
/// for recognized key types, mirroring the pinned bridge's
/// `ParseIdentity`. Other certificate types follow its payload rules.
/// Returns the identity's total length, or `None` when malformed.
#[must_use]
fn destination_identity_len(bytes: &[u8]) -> Option<usize> {
    const BASE: usize = 384;
    if bytes.len() < BASE + 3 {
        return None;
    }
    let cert_type = bytes[BASE];
    let payload_len = usize::from(u16::from_be_bytes([bytes[BASE + 1], bytes[BASE + 2]]));
    let total = BASE + 3 + payload_len;
    if bytes.len() < total {
        return None;
    }
    let payload = &bytes[BASE + 3..total];
    let valid = match cert_type {
        0 | 2 => payload_len == 0,                   // Null, Hidden
        1 | 4 => true,                               // HashCash, Multiple
        3 => payload_len == 40 || payload_len == 72, // Signed
        5 => {
            // Key: signing type (2) || crypto type (2) || excess keys.
            if payload_len < 4 {
                return None;
            }
            let signing = u16::from_be_bytes([payload[0], payload[1]]);
            let crypto = u16::from_be_bytes([payload[2], payload[3]]);
            let signing_len: usize = match signing {
                0 | 10 => 128,
                1 | 9 => 64,
                2 => 96,
                3 => 132,
                4 => 256,
                5 => 384,
                6 => 512,
                7 | 8 | 11 => 32,
                _ => return None,
            };
            let crypto_len: usize = match crypto {
                0 => 256,
                1 => 64,
                2 => 96,
                3 => 132,
                4 | 6 | 7 => 32,
                _ => return None,
            };
            payload_len == 4 + signing_len.saturating_sub(128) + crypto_len.saturating_sub(256)
        }
        _ => false,
    };
    valid.then_some(total)
}

/// Whether `bytes` is exactly one structurally valid I2P destination
/// (`KeysAndCert` wire form, no trailing data; 387 bytes for Null Certificate,
/// ~391 bytes for `CertificateKey`).
#[must_use]
fn valid_destination(bytes: &[u8]) -> bool {
    destination_identity_len(bytes) == Some(bytes.len()) && bytes.len() >= 387
}

/// The hash identifying an I2P destination (SHA-256 of the destination).
#[must_use]
pub(crate) fn destination_hash(destination: &[u8]) -> [u8; 32] {
    Sha256::digest(destination).into()
}

/// The session root together with the generation that identifies it.
///
/// One root, one generation: the count rises on every install and is never
/// reused, so evidence gathered against an older root can never be mistaken
/// for evidence about a newer one. Both fields live under the same exclusion
/// so comparing a generation and retiring the root are one atomic step.
struct ControlState {
    /// The installed root, if any. Only the recovery owner installs one.
    conn: Option<SamConn>,
    /// Generation of the root in `conn`, or of the most recently installed
    /// root once `conn` is empty.
    generation: u64,
}

/// Phase of the one root exchange. Each variant names the command that is
/// next written or whose reply is awaited; a phase ends only when its reply
/// line has been consumed, so a command is never written twice.
enum RootPhase {
    /// `HELLO VERSION`: the bridge must negotiate exactly 3.3.
    Hello,
    /// `SESSION CREATE`: the reply may take the whole readiness wait.
    Create,
    /// `NAMING LOOKUP NAME=ME`: the bridge reports our public destination.
    Lookup,
    /// Every reply has arrived. Only installation remains; the structurally
    /// valid public destination the bridge reported is kept for it.
    Ready(String),
}

impl RootPhase {
    /// The command line (newline included) this phase writes.
    fn command(&self, id: &str, private_destination: &str) -> String {
        match self {
            Self::Hello => "HELLO VERSION MIN=3.1 MAX=3.3\n".to_owned(),
            Self::Create => {
                format!("SESSION CREATE STYLE=STREAM ID={id} DESTINATION={private_destination}\n")
            }
            Self::Lookup => "NAMING LOOKUP NAME=ME\n".to_owned(),
            Self::Ready(_) => String::new(),
        }
    }

    /// The phase that follows once `reply` answered this one.
    fn on_reply(&self, reply: &str) -> io::Result<Self> {
        match self {
            Self::Hello => check_hello(reply).map(|()| Self::Create),
            Self::Create => require_ok(reply, "SESSION STATUS").map(|_| Self::Lookup),
            Self::Lookup => {
                let fields = require_ok(reply, "NAMING REPLY")?;
                let destination = field(&fields, "VALUE")
                    .ok_or_else(|| invalid("sam naming reply carries no public destination"))?;
                if i2p_base64_decode(destination).is_none_or(|bytes| !valid_destination(&bytes)) {
                    return Err(invalid("sam public destination is not a valid destination"));
                }
                Ok(Self::Ready(destination.to_owned()))
            }
            Self::Ready(_) => Err(invalid("sam root exchange is already complete")),
        }
    }
}

/// Why one resumable root step ended without finishing.
enum Stop {
    /// The caller's own deadline passed. The exchange is intact and resumable.
    Paused,
    /// The root's readiness deadline passed. The exchange is spent.
    Expired,
    /// The cancellation predicate fired: the session closed, or the startup
    /// owner cancelled.
    Cancelled,
    /// A hard I/O or protocol failure. The exchange is spent.
    Failed(io::Error),
}

impl Stop {
    /// The error a caller reports; `cancelled` builds the owner's own error.
    fn into_io(self, cancelled: fn() -> io::Error) -> io::Error {
        match self {
            Self::Paused => io::Error::new(
                io::ErrorKind::TimedOut,
                "sam root is not ready before this caller's deadline",
            ),
            Self::Expired => {
                io::Error::new(io::ErrorKind::TimedOut, "sam root readiness budget expired")
            }
            Self::Cancelled => cancelled(),
            Self::Failed(error) => error,
        }
    }
}

/// The failure a cancelled startup reports.
fn startup_cancelled() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "i2p session startup was cancelled",
    )
}

/// Whether a socket call ended because its slice timeout elapsed.
fn slice_ended(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// The wait for the next blocking step: at most `cap`, clipped to the
/// earlier of the caller's and the root's deadline, after the checks that
/// decide whether the step may start at all. The root deadline wins a tie,
/// so a spent root is never merely paused.
fn poll_slice(
    call_deadline: Instant,
    root_deadline: Instant,
    cap: Duration,
    cancelled: &dyn Fn() -> bool,
) -> Result<Duration, Stop> {
    if cancelled() {
        return Err(Stop::Cancelled);
    }
    let now = Instant::now();
    if now >= root_deadline {
        return Err(Stop::Expired);
    }
    call_deadline
        .min(root_deadline)
        .checked_duration_since(now)
        .filter(|left| !left.is_zero())
        .map(|left| left.min(cap))
        .ok_or(Stop::Paused)
}

/// One root exchange in progress: the socket, the phase, and exactly what
/// the bridge has been sent and has answered. It is advanced only by a
/// caller holding `recovery`, and it is the only owner of its socket until
/// it is installed or discarded.
struct PendingRoot {
    conn: SamConn,
    /// Absolute readiness deadline, fixed once per root before its socket
    /// connects, so the budget includes the TCP connect. No caller and no
    /// phase moves it.
    deadline: Instant,
    phase: RootPhase,
    /// Bytes of the current phase's command the socket already accepted.
    sent: usize,
    /// Reply bytes received for the current phase, without the newline.
    line: Vec<u8>,
}

impl PendingRoot {
    /// Connect the root socket. Each attempt waits at most
    /// [`EXCHANGE_BUDGET`], so cancellation is observed between attempts and
    /// a bridge further than one poll slice away can still connect; an
    /// attempt already in flight is not interrupted. A connect that cannot
    /// finish by `connect_deadline` is abandoned: nothing was sent, so no
    /// state is kept and no command can be duplicated. `root_deadline` is
    /// the root's own readiness deadline and wins a tie.
    fn connect(
        sam: SocketAddr,
        connect_deadline: Instant,
        root_deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, Stop> {
        loop {
            let slice = poll_slice(connect_deadline, root_deadline, EXCHANGE_BUDGET, cancelled)?;
            match TcpStream::connect_timeout(&sam, slice) {
                Ok(stream) => {
                    return Ok(Self {
                        conn: SamConn::from_stream(stream).map_err(Stop::Failed)?,
                        deadline: root_deadline,
                        phase: RootPhase::Hello,
                        sent: 0,
                        line: Vec::new(),
                    });
                }
                Err(error) if slice_ended(&error) => {}
                Err(error) => return Err(Stop::Failed(error)),
            }
        }
    }

    /// Write what remains of `command` for at most `slice`. The offset is
    /// recorded as soon as the socket accepts bytes, so a pause that follows
    /// resumes mid-command instead of repeating or skipping bytes.
    fn write_step(&mut self, command: &[u8], slice: Duration) -> io::Result<()> {
        self.conn.writer.set_write_timeout(Some(slice))?;
        match self.conn.writer.write(&command[self.sent..]) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "sam bridge stopped accepting commands",
            )),
            Ok(written) => {
                self.sent += written;
                Ok(())
            }
            Err(error) if slice_ended(&error) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Read at most one reply byte within `slice`. A complete line is
    /// returned and consumed; end of stream before the newline is a dead
    /// bridge, never a reply.
    fn read_step(&mut self, slice: Duration) -> io::Result<Option<String>> {
        self.conn.reader.set_read_timeout(Some(slice))?;
        let mut byte = [0u8; 1];
        match self.conn.reader.read(&mut byte) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "sam bridge closed the connection before the reply line ended",
            )),
            Ok(_) if byte[0] == b'\n' => {
                if self.line.last() == Some(&b'\r') {
                    self.line.pop();
                }
                String::from_utf8(std::mem::take(&mut self.line))
                    .map(Some)
                    .map_err(|_| invalid("sam reply line is not utf-8"))
            }
            Ok(_) => {
                self.line.push(byte[0]);
                if self.line.len() >= MAX_SAM_LINE {
                    return Err(invalid("sam reply line exceeds the bound"));
                }
                Ok(None)
            }
            Err(error) if slice_ended(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Drive the exchange until it is [`RootPhase::Ready`], or until a
    /// deadline, cancellation, or hard failure stops it. Every blocking step
    /// is bounded by the earlier of `call_deadline` and the root deadline.
    /// A reply is consumed and the next phase entered with no deadline check
    /// in between, so a pause can only fall inside a phase, never between a
    /// reply and its successor.
    fn advance(
        &mut self,
        id: &str,
        private_destination: &str,
        call_deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), Stop> {
        while !matches!(self.phase, RootPhase::Ready(_)) {
            let command = self.phase.command(id, private_destination);
            let reply = loop {
                let slice = poll_slice(call_deadline, self.deadline, CANCEL_POLL, cancelled)?;
                let step = if self.sent < command.len() {
                    self.write_step(command.as_bytes(), slice).map(|()| None)
                } else {
                    self.read_step(slice)
                };
                if let Some(reply) = step.map_err(Stop::Failed)? {
                    break reply;
                }
            };
            self.sent = 0;
            self.phase = self.phase.on_reply(&reply).map_err(Stop::Failed)?;
        }
        Ok(())
    }
}

/// Recovery ownership: the one root exchange that may be in progress.
struct Recovery {
    pending: Option<PendingRoot>,
}

/// One persistent SAM STREAM session root.
pub struct SamSession {
    sam: SocketAddr,
    id: String,
    /// Our public destination (base64), reported for diagnostics only.
    destination: String,
    /// Private destination material, stored for session re-establishment.
    /// Never exposed via Debug or public accessors.
    private_destination: String,
    /// Installed root and its generation. Never read for payload; held so
    /// the bridge keeps the session alive.
    control: Mutex<ControlState>,
    /// Serializes root installation against retirement and close, and owns
    /// the one root exchange in progress. The order is always `recovery`
    /// then `control`.
    recovery: Mutex<Recovery>,
    /// Leaf lock: a clone of the socket `recovery`'s holder is blocked on,
    /// so `close` can wake it without waiting for `recovery`. It is empty
    /// while the holder is still in its TCP connect, when `close` waits for
    /// that one attempt (at most [`EXCHANGE_BUDGET`]) instead. The holder
    /// checks `closed` and stores the clone under this lock, and `close`
    /// stores `closed` before it takes this lock, so a close either finds
    /// the socket here or the holder finds `closed`. No lock is taken while
    /// it is held.
    wake: Mutex<Option<TcpStream>>,
    closed: AtomicBool,
    /// Budget of one stream exchange (`connect`, `accept`'s recovery step).
    timeout: Duration,
    /// Readiness budget of a root recovered after the first one.
    root_budget: Duration,
}

impl std::fmt::Debug for SamSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print destination private material; the session was
        // created from it and holds no copy worth repeating.
        f.debug_struct("SamSession")
            .field("sam", &self.sam)
            .field("id", &self.id)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SamSession {
    /// Establish the persistent session with `DESTINATION=<private>` on a
    /// fresh control connection. The session id is derived from the
    /// destination (see [`session_id_for`]) and stays stable for this session's life.
    /// `timeout` bounds this establishment and is the budget of each later
    /// stream exchange; a root recovered later gets [`ROOT_READINESS_BUDGET`].
    pub fn establish(
        sam: SocketAddr,
        private_destination: &str,
        timeout: Duration,
    ) -> io::Result<Self> {
        let deadline = Instant::now() + timeout;
        Self::establish_within(
            sam,
            private_destination,
            timeout,
            deadline,
            deadline,
            &|| false,
            &Cell::new(false),
        )
    }

    /// Establish the session under two absolute deadlines and a cancellation
    /// predicate.
    ///
    /// `root_deadline` bounds the whole exchange. The owner fixes it before
    /// this call connects, so it covers the TCP connect, `HELLO`, the
    /// readiness wait, and `NAMING LOOKUP` together. `connect_deadline`
    /// bounds only the TCP connect: a connect that cannot finish by it fails
    /// `TimedOut` with nothing sent, and `root_deadline` wins a tie. Once the
    /// bridge has accepted the connection only `root_deadline` applies.
    ///
    /// `cancelled` is polled at least every [`CANCEL_POLL`] while reading or
    /// writing, between connect attempts, and once more together with
    /// `root_deadline` before the session is returned, so a cancelled
    /// establishment, or one whose root deadline passed after the final
    /// reply, never publishes a session: the first reports `Interrupted`, the
    /// second `TimedOut`. A connect attempt already in flight is not
    /// interrupted; it ends within [`EXCHANGE_BUDGET`].
    /// `timeout` is the per-stream budget the session keeps. `reached` is set
    /// once the bridge accepted the connection and this call never clears it,
    /// so a caller can tell a bridge that is unreachable from one that is
    /// merely slow to become ready, and a bridge that has connected before
    /// from one that never has.
    pub(crate) fn establish_within(
        sam: SocketAddr,
        private_destination: &str,
        timeout: Duration,
        connect_deadline: Instant,
        root_deadline: Instant,
        cancelled: &dyn Fn() -> bool,
        reached: &Cell<bool>,
    ) -> io::Result<Self> {
        validate_private_destination(private_destination)?;
        let id = session_id_for(private_destination);
        let mut root = PendingRoot::connect(sam, connect_deadline, root_deadline, cancelled)
            .map_err(|stop| match stop {
                Stop::Paused => io::Error::new(
                    io::ErrorKind::TimedOut,
                    "sam bridge accepted no connection before the connect deadline",
                ),
                stop => stop.into_io(startup_cancelled),
            })?;
        reached.set(true);
        // The SESSION STATUS reply carries the *private* destination on
        // this bridge; the exchange never stores it. The public destination
        // comes from NAMING LOOKUP NAME=ME on the session root.
        let advanced = root.advance(&id, private_destination, root_deadline, cancelled);
        let PendingRoot { conn, phase, .. } = root;
        // Publication is the last step the root deadline bounds. The same
        // check that gates every step before it runs once more, after the
        // final reply: cancellation is reported as such, and a deadline that
        // passed meanwhile is the root's `TimedOut`, never a cancellation.
        let verdict = match (advanced, phase) {
            (Ok(()), RootPhase::Ready(destination)) => {
                poll_slice(root_deadline, root_deadline, CANCEL_POLL, cancelled)
                    .map(|_left| destination)
            }
            (Err(stop), _) => Err(stop),
            (Ok(()), _) => Err(Stop::Failed(invalid(
                "sam root exchange ended without a public destination",
            ))),
        };
        let destination = match verdict {
            Ok(destination) => destination,
            Err(stop) => {
                let _ = conn.writer.shutdown(std::net::Shutdown::Both);
                return Err(stop.into_io(startup_cancelled));
            }
        };
        Ok(Self {
            sam,
            id,
            destination,
            private_destination: private_destination.to_owned(),
            control: Mutex::new(ControlState {
                conn: Some(conn),
                generation: 1,
            }),
            recovery: Mutex::new(Recovery { pending: None }),
            wake: Mutex::new(None),
            closed: AtomicBool::new(false),
            timeout,
            root_budget: ROOT_READINESS_BUDGET,
        })
    }

    /// Establish the session for node startup under one absolute owner
    /// `deadline` and a `cancelled` predicate.
    ///
    /// The identity is loaded or generated once and reused by every session
    /// attempt, so a retry never creates a second key or a second session id.
    /// Each network step is clipped to the remaining owner deadline, a
    /// session attempt gets at most [`ROOT_READINESS_BUDGET`] (connect
    /// included), and the pause between attempts is cut by cancellation and
    /// by the deadline. A corrupt key, a malformed bridge reply, and a bridge
    /// that does not speak 3.3 fail at once (`InvalidData`, `Unsupported`);
    /// every other failure retries until the deadline. Cancellation is
    /// reported as `Interrupted` and leaves no session behind; it is seen
    /// between connect attempts, so a connect attempt in flight delays it by
    /// at most [`EXCHANGE_BUDGET`]. A bridge that has never accepted a
    /// connection is given up on after [`UNREACHABLE_WINDOW`], which also
    /// clips its connect waits, instead of the whole owner deadline.
    pub(crate) fn establish_startup(
        sam: SocketAddr,
        key_path: Option<&Path>,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<Self> {
        let unreachable_after = Instant::now() + UNREACHABLE_WINDOW;
        // A key step answers at once; it never needs the readiness budget.
        let private = retry_until(
            deadline.min(unreachable_after),
            cancelled,
            || false,
            |left| match key_path {
                Some(path) => {
                    load_or_create_private_destination(sam, path, left.min(EXCHANGE_BUDGET))
                }
                None => generate_destination(sam, left.min(EXCHANGE_BUDGET))
                    .map(|(_public, private)| private),
            },
        )?;
        Self::retry_establish(
            sam,
            &private,
            deadline,
            unreachable_after,
            cancelled,
            &Cell::new(false),
        )
    }

    /// Retry root establishment until a session is up, a failure is final,
    /// `cancelled` fires, or the owner `deadline` passes.
    ///
    /// Each attempt fixes its root deadline once, before it connects:
    /// [`ROOT_READINESS_BUDGET`] clipped to `deadline`. While `reached` is
    /// false no bridge has ever accepted a connection, so an attempt's connect
    /// waits no longer than `unreachable_after`, and the retry ends, reporting
    /// its last failure, at the first failure or the end of the pause after a
    /// failure that falls at or past it. A connect cut off by the window
    /// reports `TimedOut`; a refusal that preceded the window is reported as
    /// itself. The first accepted connection sets `reached` for good; nothing
    /// here clears it, so later attempts connect, and fail, under their root
    /// deadline alone.
    fn retry_establish(
        sam: SocketAddr,
        private: &str,
        deadline: Instant,
        unreachable_after: Instant,
        cancelled: &dyn Fn() -> bool,
        reached: &Cell<bool>,
    ) -> io::Result<Self> {
        retry_until(
            deadline,
            cancelled,
            || !reached.get() && Instant::now() >= unreachable_after,
            |_left| {
                let root_deadline = (Instant::now() + ROOT_READINESS_BUDGET).min(deadline);
                let connect_deadline = if reached.get() {
                    root_deadline
                } else {
                    root_deadline.min(unreachable_after)
                };
                Self::establish_within(
                    sam,
                    private,
                    EXCHANGE_BUDGET,
                    connect_deadline,
                    root_deadline,
                    cancelled,
                    reached,
                )
            },
        )
    }

    /// Ensure one live root and report the generation that owns it.
    ///
    /// The generation identifies the root this caller's request is issued
    /// against, so later evidence about that root can be retired without
    /// touching a root recovered in the meantime. The recovery lock, the
    /// control lock, and the bridge exchange are all charged to
    /// `deadline`; another caller's budget never extends this call.
    fn ensure_control(&self, deadline: Instant) -> io::Result<u64> {
        if self.closed.load(Ordering::Acquire) {
            return Err(session_closed());
        }
        // Healthy fast path: a live root costs no budget, no recovery
        // lock, and no state change.
        if let Some(generation) = self.live_control_generation(deadline)? {
            return Ok(generation);
        }

        // Recovery is serialized on `recovery`, then `control` — the same
        // order `retire_root` and `close` take. The dead root is shut down
        // while those locks are held so the bridge cannot still own the old
        // session when the replacement `SESSION CREATE` for the same id
        // arrives. The wait for `recovery` is charged to `deadline`, so
        // queueing behind another caller never extends this one.
        let mut recovery = lock_within(&self.recovery, deadline)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(session_closed());
        }
        if let Some(generation) = self.live_control_generation(deadline)? {
            return Ok(generation);
        }
        {
            let mut state = lock_within(&self.control, deadline)?;
            if let Some(dead) = state.conn.take() {
                let _ = dead.writer.shutdown(std::net::Shutdown::Both);
            }
        }
        self.recover_root(&mut recovery, deadline)
    }

    /// Advance the pending root, or start one, then install it when ready.
    ///
    /// `recovery` is held by the caller. The pending root is taken out of it
    /// for the exchange and goes back only when the exchange paused at this
    /// caller's deadline; every other exit either installs it or shuts its
    /// socket down, so no discarded root keeps a bridge session alive.
    fn recover_root(&self, recovery: &mut Recovery, call_deadline: Instant) -> io::Result<u64> {
        let cancelled = || self.closed.load(Ordering::Acquire);
        let mut root = match recovery.pending.take() {
            Some(root) => root,
            // The readiness deadline is fixed here, once per root; resuming
            // never moves it.
            None => PendingRoot::connect(
                self.sam,
                call_deadline,
                Instant::now() + self.root_budget,
                &cancelled,
            )
            .map_err(|stop| stop.into_io(session_closed))?,
        };
        // Register a close-reachable clone of the socket. The `closed`
        // check and the store share the `wake` lock that `close` takes after
        // it stores `closed`, so this root is never left unwakeable.
        let armed = root.conn.reader.try_clone().and_then(|clone| {
            let mut slot = self.wake.lock();
            if self.closed.load(Ordering::Acquire) {
                return Err(session_closed());
            }
            *slot = Some(clone);
            Ok(())
        });
        let outcome = match armed {
            Ok(()) => root.advance(
                &self.id,
                &self.private_destination,
                call_deadline,
                &cancelled,
            ),
            Err(error) => Err(Stop::Failed(error)),
        };
        drop(self.wake.lock().take());
        match outcome {
            Ok(()) => self.install_root(recovery, root, call_deadline),
            Err(Stop::Paused) => {
                recovery.pending = Some(root);
                Err(Stop::Paused.into_io(session_closed))
            }
            Err(stop) => {
                let _ = root.conn.writer.shutdown(std::net::Shutdown::Both);
                // A wake-induced failure is the close, not a bridge fault.
                Err(if self.closed.load(Ordering::Acquire) {
                    session_closed()
                } else {
                    stop.into_io(session_closed)
                })
            }
        }
    }

    /// Publish a root whose exchange completed.
    ///
    /// The generation rises only here, and only when nothing refuses the
    /// root: `close`, the root's own deadline, a public destination that is
    /// not ours, or an exhausted counter each discard it with the generation
    /// untouched. `recovery` stays held, so `close` cannot drain between
    /// these checks and the install; a close that already stored `closed`
    /// waits for `recovery` and then removes the root installed here. If this
    /// caller's deadline passes while waiting for `control`, the complete
    /// root stays pending for the next caller instead of being repeated.
    fn install_root(
        &self,
        recovery: &mut Recovery,
        root: PendingRoot,
        call_deadline: Instant,
    ) -> io::Result<u64> {
        let mut state = match lock_within(&self.control, call_deadline) {
            Ok(state) => state,
            Err(error) => {
                recovery.pending = Some(root);
                return Err(error);
            }
        };
        let verdict = if self.closed.load(Ordering::Acquire) {
            Err(session_closed())
        } else if Instant::now() >= root.deadline {
            Err(Stop::Expired.into_io(session_closed))
        } else if !matches!(&root.phase, RootPhase::Ready(reported) if *reported == self.destination)
        {
            Err(invalid(
                "sam re-established session public destination mismatch",
            ))
        } else {
            state
                .generation
                .checked_add(1)
                .ok_or_else(|| io::Error::other("sam root generation exhausted"))
        };
        match verdict {
            Ok(generation) => {
                state.generation = generation;
                state.conn = Some(root.conn);
                Ok(generation)
            }
            Err(error) => {
                let _ = root.conn.writer.shutdown(std::net::Shutdown::Both);
                Err(error)
            }
        }
    }

    /// Generation of the installed root while the bridge still holds it.
    ///
    /// The probe costs one non-blocking peek under `control` only. Its
    /// answer describes the root at this instant, so retirement re-checks
    /// the generation under the same exclusion instead of trusting it.
    fn live_control_generation(&self, deadline: Instant) -> io::Result<Option<u64>> {
        let mut state = lock_within(&self.control, deadline)?;
        let alive = state.conn.as_mut().is_some_and(SamConn::is_alive);
        Ok(alive.then_some(state.generation))
    }

    /// Retire the installed root when it is still generation `observed`.
    ///
    /// `observed` names the root a request was issued against. Evidence
    /// from that request — `STREAM STATUS RESULT=INVALID_ID` — is evidence
    /// about that root alone, so a root installed while the evidence was in
    /// flight has a newer generation and survives. The comparison and the
    /// removal happen under `control` while `recovery` is held, so no
    /// install can slip between them, and the wait is charged to `deadline`.
    fn retire_root(&self, observed: u64, deadline: Instant) -> io::Result<()> {
        let _recovery = lock_within(&self.recovery, deadline)?;
        let mut state = lock_within(&self.control, deadline)?;
        if state.generation != observed {
            return Ok(());
        }
        if let Some(conn) = state.conn.take() {
            let _ = conn.writer.shutdown(std::net::Shutdown::Both);
        }
        Ok(())
    }

    /// Our public destination in SAM base64 form.
    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// The per-instance SAM session id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The `.b32.i2p` name of our own destination.
    #[must_use]
    pub fn b32_name(&self) -> Option<String> {
        let bytes = i2p_base64_decode(&self.destination)?;
        Some(format!(
            "{}.b32.i2p",
            base32_encode(&destination_hash(&bytes))
        ))
    }

    /// Parse and validate our local public destination as a typed
    /// [`PeerEndpoint::I2p`] at `port`. Fails closed if the destination
    /// is structurally invalid or corrupt.
    pub fn local_endpoint(&self, port: u16) -> io::Result<crate::PeerEndpoint> {
        let bytes = i2p_base64_decode(&self.destination)
            .filter(|b| valid_destination(b))
            .ok_or_else(|| invalid("sam local destination is not a valid destination"))?;
        Ok(crate::PeerEndpoint::I2p {
            hash: destination_hash(&bytes),
            port,
        })
    }

    fn naming_lookup_with_deadline(
        &self,
        name: &str,
        deadline: Instant,
    ) -> io::Result<(String, [u8; 32])> {
        let mut conn = SamConn::connect_with_deadline(self.sam, deadline)?;
        conn.hello(deadline)?;
        let reply = conn.command(&format!("NAMING LOOKUP NAME={name}"), deadline)?;
        let fields = require_ok(&reply, "NAMING REPLY")?;
        let value = field(&fields, "VALUE")
            .map(str::to_owned)
            .ok_or_else(|| invalid("sam naming reply carries no value"))?;
        let bytes = i2p_base64_decode(&value)
            .filter(|bytes| valid_destination(bytes))
            .ok_or_else(|| invalid("sam naming value is not a valid destination"))?;
        let hash = destination_hash(&bytes);
        Ok((value, hash))
    }

    /// Dial the peer identified by `hash` at `port` over a fresh bridge.
    ///
    /// Local bridge failures (connect, hello, lookup, protocol) are
    /// [`DialFailure::Transport`]; only a bridge-reported
    /// `CANT_REACH_PEER` or `TIMEOUT` is [`DialFailure::PeerUnreachable`].
    pub fn connect(
        &self,
        hash: [u8; 32],
        port: u16,
    ) -> Result<TcpStream, crate::endpoint::DialFailure> {
        use crate::endpoint::DialFailure;
        if self.closed.load(Ordering::Acquire) {
            return Err(DialFailure::Transport(io::Error::new(
                io::ErrorKind::NotConnected,
                "sam session is closed",
            )));
        }
        let deadline = Instant::now() + self.timeout;
        let root = self
            .ensure_control(deadline)
            .map_err(DialFailure::Transport)?;
        let name = format!("{}.b32.i2p", base32_encode(&hash));
        let (destination, resolved_hash) = self
            .naming_lookup_with_deadline(&name, deadline)
            .map_err(DialFailure::Transport)?;
        if resolved_hash != hash {
            return Err(DialFailure::Transport(io::Error::new(
                io::ErrorKind::InvalidData,
                "sam naming destination does not match requested hash",
            )));
        }
        let mut conn =
            SamConn::connect_with_deadline(self.sam, deadline).map_err(DialFailure::Transport)?;
        conn.hello(deadline).map_err(DialFailure::Transport)?;
        let reply = conn
            .command(
                &format!(
                    "STREAM CONNECT ID={} DESTINATION={destination} TO_PORT={port}",
                    self.id
                ),
                deadline,
            )
            .map_err(DialFailure::Transport)?;
        let fields = parse_fields(&reply, "STREAM STATUS").map_err(DialFailure::Transport)?;
        match field(&fields, "RESULT") {
            Some("OK") => Ok(conn.into_stream()),
            Some(result @ ("CANT_REACH_PEER" | "TIMEOUT")) => {
                Err(DialFailure::PeerUnreachable(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("sam peer unreachable: STREAM STATUS RESULT={result}"),
                )))
            }
            Some("INVALID_ID") => {
                // The reply describes the root this request was issued
                // against. Retiring it is bounded by the same deadline, and
                // a root recovered meanwhile keeps a newer generation.
                self.retire_root(root, deadline)
                    .map_err(DialFailure::Transport)?;
                if self.ensure_control(deadline).is_ok() {
                    if let Ok(mut retry_conn) = SamConn::connect_with_deadline(self.sam, deadline) {
                        if retry_conn.hello(deadline).is_ok() {
                            if let Ok(retry_reply) = retry_conn.command(
                                &format!(
                                    "STREAM CONNECT ID={} DESTINATION={destination} TO_PORT={port}",
                                    self.id
                                ),
                                deadline,
                            ) {
                                if let Ok(retry_fields) =
                                    parse_fields(&retry_reply, "STREAM STATUS")
                                {
                                    if field(&retry_fields, "RESULT") == Some("OK") {
                                        return Ok(retry_conn.into_stream());
                                    }
                                }
                            }
                        }
                    }
                }
                Err(DialFailure::Transport(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "sam stream request failed: STREAM STATUS RESULT=INVALID_ID",
                )))
            }
            Some(result) => Err(DialFailure::Transport(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!(
                    "sam stream request failed: STREAM STATUS RESULT={}",
                    sanitize_sam_result(result)
                ),
            ))),
            None => Err(DialFailure::Transport(invalid(
                "sam stream reply carries no result",
            ))),
        }
    }

    /// Accept one inbound stream, waiting at most `wait`. Returns the
    /// bridged stream and the remote endpoint (destination hash + the
    /// `TO_PORT` the peer dialed). An absent `TO_PORT`, or I2CP port `0`
    /// (any or unspecified service), yields the application `fallback_port`;
    /// a nonzero port is returned as reported.
    pub fn accept(
        &self,
        wait: Duration,
        fallback_port: u16,
    ) -> io::Result<(TcpStream, [u8; 32], u16)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "sam session is closed",
            ));
        }
        let deadline = Instant::now() + wait;
        let root = self.ensure_control(deadline)?;
        let mut conn = SamConn::connect_with_deadline(self.sam, deadline)?;
        conn.hello(deadline)?;
        let reply = conn.command(&format!("STREAM ACCEPT ID={}", self.id), deadline)?;
        let fields = parse_fields(&reply, "STREAM STATUS")?;
        if field(&fields, "RESULT") == Some("INVALID_ID") {
            let _ = self.retire_root(root, deadline);
            let _ = self.ensure_control(deadline);
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "sam stream accept failed: STREAM STATUS RESULT=INVALID_ID",
            ));
        }
        if field(&fields, "RESULT") != Some("OK") {
            let res = sanitize_sam_result(field(&fields, "RESULT").unwrap_or(""));
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("sam request failed: STREAM STATUS RESULT={res}"),
            ));
        }
        let line = conn.read_line(deadline)?;
        let mut parts = line.split_whitespace();
        let destination = parts
            .next()
            .ok_or_else(|| invalid("sam accepted stream carries no destination"))?;
        // `Some(0)` is retained through the loop so a zero followed by
        // another `TO_PORT` is still a duplicate.
        let mut port: Option<u16> = None;
        for part in parts {
            if let Some(value) = part.strip_prefix("TO_PORT=") {
                if port.is_some() {
                    return Err(invalid("duplicate TO_PORT in sam accepted stream"));
                }
                let parsed: u16 = value
                    .parse()
                    .map_err(|_| invalid("malformed TO_PORT in sam accepted stream"))?;
                port = Some(parsed);
            }
        }
        let port = port.filter(|&p| p != 0).unwrap_or(fallback_port);
        let bytes = i2p_base64_decode(destination)
            .filter(|bytes| valid_destination(bytes))
            .ok_or_else(|| invalid("sam accepted destination is not a valid destination"))?;
        Ok((conn.into_stream(), destination_hash(&bytes), port))
    }

    /// Close the session root; later dials fail closed.
    ///
    /// Order: store `closed`; wake root I/O in progress through `wake`
    /// (released before anything else is taken); then take `recovery` and
    /// drain the pending root and, under `control`, the installed one. No
    /// root can be installed after the drain: every install holds `recovery`
    /// and re-checks `closed`.
    ///
    /// Waiting for `recovery` ends in one of two ways. Once the holder's root
    /// socket exists, the wake interrupts its read or write at once and the
    /// holder reports the close. Before the socket exists there is nothing to
    /// wake: the holder is inside a TCP connect attempt, which cannot be
    /// interrupted, so `close` waits for that one attempt, at most
    /// [`EXCHANGE_BUDGET`], after which the holder sees `closed` before it
    /// starts another. Either way `close` never waits out a readiness budget.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        {
            let wake = self.wake.lock();
            if let Some(socket) = wake.as_ref() {
                let _ = socket.shutdown(std::net::Shutdown::Both);
            }
        }
        let mut recovery = self.recovery.lock();
        if let Some(pending) = recovery.pending.take() {
            let _ = pending.conn.writer.shutdown(std::net::Shutdown::Both);
        }
        let conn = self.control.lock().conn.take();
        if let Some(conn) = conn {
            let _ = conn.writer.shutdown(std::net::Shutdown::Both);
            drop(conn);
        }
    }
}

/// Run `attempt` until it succeeds, fails for good, is cancelled, or the
/// owner `deadline` passes. `attempt` receives the time left and must clip
/// its own network steps to it. `InvalidData` (a corrupt key or a malformed
/// bridge reply) and `Unsupported` (a bridge that does not speak 3.3) are
/// final, because retrying cannot change them; so is any failure after which
/// `give_up` reports true. `give_up` is consulted again once the pause that
/// follows a failure ends, so a limit that expired during the pause reports
/// that failure instead of spending a doomed attempt. Any other failure
/// pauses and retries. When the deadline ends the loop, the last failure is
/// reported.
fn retry_until<T>(
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
    give_up: impl Fn() -> bool,
    mut attempt: impl FnMut(Duration) -> io::Result<T>,
) -> io::Result<T> {
    let mut last: Option<io::Error> = None;
    let mut failures = 0u64;
    loop {
        if cancelled() {
            return Err(startup_cancelled());
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(last.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "i2p session startup budget expired",
                )
            }));
        }
        match attempt(left) {
            Ok(value) => return Ok(value),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::InvalidData | io::ErrorKind::Unsupported
                ) =>
            {
                return Err(error);
            }
            Err(error) => {
                if give_up() {
                    return Err(error);
                }
                failures += 1;
                startup_pause(failures, deadline, cancelled)?;
                if give_up() {
                    return Err(error);
                }
                last = Some(error);
            }
        }
    }
}

/// The jittered, growing pause between startup attempts. It is clipped to
/// `deadline`, so it can never extend the owner deadline, and it polls
/// `cancelled` every [`CANCEL_POLL`], so shutdown never waits out a pause.
/// Reaching the deadline is not an error here: the caller's next deadline
/// check reports it with the last failure.
fn startup_pause(failures: u64, deadline: Instant, cancelled: &dyn Fn() -> bool) -> io::Result<()> {
    let base = Duration::from_millis(failures.min(PAUSE_STEPS_MAX) * PAUSE_STEP_MS);
    let jitter = Duration::from_millis(thread_rng().gen_range(0..=PAUSE_STEP_MS));
    let until = (Instant::now() + base + jitter).min(deadline);
    loop {
        if cancelled() {
            return Err(startup_cancelled());
        }
        let Some(left) = until
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
        else {
            return Ok(());
        };
        std::thread::sleep(left.min(CANCEL_POLL));
    }
}

/// Generate a fresh Ed25519 destination through the bridge.
/// Returns `(public, private)` SAM base64 strings.
///
/// The request is `DEST GENERATE SIGNATURE_TYPE=7`: SAM defaults an omitted
/// type to DSA-SHA1 (the pinned IVNP bridge defaults to 7), so the client
/// selects Ed25519 explicitly and relies on no bridge default. A successful
/// `DEST REPLY` is `DEST REPLY PUB=<pub> PRIV=<priv>` and carries no `RESULT`,
/// unlike every other reply here, which `require_ok` accepts only with
/// `RESULT=OK`. An explicit `RESULT=OK` is not a failure and is tolerated;
/// the key pair is authoritative and still passes full validation. Any other
/// `RESULT` is a failure status, refused before a key field is read even
/// beside keys; only the sanitized result name reaches the error.
pub(crate) fn generate_destination(
    sam: SocketAddr,
    timeout: Duration,
) -> io::Result<(String, String)> {
    let deadline = Instant::now() + timeout;
    let mut conn = SamConn::connect_with_deadline(sam, deadline)?;
    conn.hello(deadline)?;
    let reply = conn.command("DEST GENERATE SIGNATURE_TYPE=7", deadline)?;
    let fields = parse_fields(&reply, "DEST REPLY")?;
    match field(&fields, "RESULT") {
        None | Some("OK") => {}
        Some(result) => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!(
                    "sam request failed: DEST REPLY RESULT={}",
                    sanitize_sam_result(result)
                ),
            ));
        }
    }
    let public = field(&fields, "PUB")
        .ok_or_else(|| invalid("dest reply carries no public destination"))?
        .to_owned();
    let private = field(&fields, "PRIV")
        .ok_or_else(|| invalid("dest reply carries no private destination"))?
        .to_owned();
    if i2p_base64_decode(&public).is_none_or(|b| !valid_destination(&b)) {
        return Err(invalid(
            "generated public destination is not a valid destination",
        ));
    }
    validate_private_destination(&private)?;
    Ok((public, private))
}

/// Open a persisted key file; the returned handle owns every later step.
///
/// Unix: the path is resolved exactly once, with `O_RDONLY | O_CLOEXEC |
/// O_NOFOLLOW | O_NONBLOCK`. `O_NOFOLLOW` refuses a final-component
/// symbolic link (a dangling one included, so it never reads as absent),
/// and `O_NONBLOCK` keeps opening a FIFO from waiting for a writer before
/// the type check below can refuse it. Only that handle is used after
/// the open: its type is checked first, a non-regular file is refused
/// before any permission change, a mode other than `0600` is repaired
/// through the handle (`fchmod`), and the caller reads the same handle, so
/// the object checked, repaired, and read cannot differ. Failure to
/// tighten fails closed rather than running with exposed key material.
/// Symbolic links in parent directories are still followed.
///
/// Elsewhere: a plain read-only open with no permission or link policy.
#[cfg(unix)]
fn open_key_file(path: &Path) -> io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::PermissionsExt;

    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let file = std::fs::File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(invalid("persisted key path is not a regular file"));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Open a persisted key file (non-unix): no link or mode policy applies.
#[cfg(not(unix))]
fn open_key_file(path: &Path) -> io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// Load the persisted I2P private destination, generating and persisting
/// it (mode `0600`, create-only) when the file is absent.
///
/// Fails closed on unreadable or corrupt content; never replaces an
/// existing file and never logs the material. A reused file's mode is
/// repaired to `0600` before its content is read. A symbolic link at
/// `key_path` (unix), dangling or not, or any non-regular file is an
/// error and never selects generation: only an absent path does.
pub(crate) fn load_or_create_private_destination(
    sam: SocketAddr,
    key_path: &Path,
    timeout: Duration,
) -> io::Result<String> {
    match read_key_file(key_path) {
        Ok(text) => validate_private_destination(text.trim()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let (_public, private) = generate_destination(sam, timeout)?;
            write_key_file(key_path, &private)?;
            Ok(private)
        }
        Err(error) => Err(error),
    }
}

fn destination_identity_and_types(bytes: &[u8]) -> Option<(usize, u16, u16)> {
    const BASE: usize = 384;
    let total = destination_identity_len(bytes)?;
    let cert_type = bytes[BASE];
    let (signing, crypto) = if cert_type == 5 {
        let payload = &bytes[BASE + 3..total];
        if payload.len() < 4 {
            return None;
        }
        (
            u16::from_be_bytes([payload[0], payload[1]]),
            u16::from_be_bytes([payload[2], payload[3]]),
        )
    } else {
        (0, 0)
    };
    Some((total, signing, crypto))
}

fn signing_public_key_len(signing: u16) -> Option<usize> {
    match signing {
        0 | 10 => Some(128),
        1 | 9 => Some(64),
        2 => Some(96),
        3 => Some(132),
        4 => Some(256),
        5 => Some(384),
        6 => Some(512),
        7 | 8 | 11 => Some(32),
        _ => None,
    }
}

fn signing_signature_len(signing: u16) -> Option<usize> {
    match signing {
        0 => Some(40),
        1 | 7 | 8 | 9 | 11 => Some(64),
        2 => Some(96),
        3 => Some(132),
        4 => Some(256),
        5 => Some(384),
        6 => Some(512),
        10 => Some(128),
        _ => None,
    }
}

fn validate_private_destination(text: &str) -> io::Result<String> {
    const SIGNING_LENGTH: usize = 32;
    let wire = i2p_base64_decode(text)
        .ok_or_else(|| invalid("persisted i2p destination key is corrupt base64"))?;
    let (consumed, signing_type, crypto_type) = destination_identity_and_types(&wire)
        .ok_or_else(|| invalid("persisted i2p destination key has invalid identity"))?;

    let encryption_len = match crypto_type {
        4 => 32,
        0 => 256,
        _ => return Err(invalid("unsupported i2p private crypto key type")),
    };

    match signing_type {
        7 => {}
        11 if crypto_type == 4 => {}
        _ => return Err(invalid("unsupported i2p private signing key type")),
    }

    if wire.len() < consumed + encryption_len + SIGNING_LENGTH {
        return Err(invalid(
            "persisted i2p private destination key is truncated",
        ));
    }

    let signing = &wire[consumed + encryption_len..consumed + encryption_len + SIGNING_LENGTH];
    let offline_section = &wire[consumed + encryption_len + SIGNING_LENGTH..];

    if signing.iter().all(|&b| b == 0) {
        if offline_section.len() < 6 {
            return Err(invalid("malformed offline i2p key section"));
        }
        let offline_key_type = u16::from_be_bytes([offline_section[4], offline_section[5]]);
        let pub_len = signing_public_key_len(offline_key_type)
            .ok_or_else(|| invalid("unknown offline key type"))?;
        let sig_len = signing_signature_len(signing_type)
            .ok_or_else(|| invalid("unknown signing signature length"))?;
        if offline_section.len() != 6 + pub_len + sig_len + 32 {
            return Err(invalid("invalid offline i2p key section length"));
        }
    } else if !offline_section.is_empty() {
        return Err(invalid(
            "persisted i2p destination key has unexpected trailing bytes",
        ));
    }

    Ok(text.to_owned())
}

struct TempCleanup<'a>(&'a Path);

impl Drop for TempCleanup<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0);
    }
}

/// Write `contents` as a new mode-`0600` file; refuse to replace.
pub(crate) fn write_key_file(path: &Path, contents: &str) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut nonce = [0u8; 8];
    thread_rng().fill_bytes(&mut nonce);
    let temp_name = format!(
        ".{}.tmp.{:016x}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("key"),
        u64::from_ne_bytes(nonce)
    );
    let temp_path = parent.join(temp_name);
    let cleanup = TempCleanup(&temp_path);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        let mut file = options.open(&temp_path)?;
        file.write_all(contents.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }

    // Atomic publication without replacing an existing file.
    // std::fs::hard_link fails with AlreadyExists if path already exists.
    std::fs::hard_link(&temp_path, path)?;

    // Temp file can be removed now; drop guard will harmlessly find it gone.
    let _ = std::fs::remove_file(&temp_path);
    drop(cleanup);

    // Sync parent directory to ensure directory entry is durable.
    let dir = std::fs::File::open(parent)?;
    dir.sync_all()?;

    Ok(())
}

/// Read a persisted key file, failing closed on corrupt content. On unix
/// the file is opened once without following a final symbolic link, must
/// be a regular file, has its mode repaired to `0600` through that handle,
/// and is read through the same handle (see `open_key_file`). Callers treat
/// only `NotFound` as an absent key; every other error is refused.
pub(crate) fn read_key_file(path: &Path) -> io::Result<String> {
    let mut file = open_key_file(path)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return Err(invalid("persisted key file is corrupt"));
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead as _;
    use std::net::TcpListener;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::mpsc;

    struct FakeSam {
        addr: SocketAddr,
        commands: mpsc::Receiver<String>,
        /// Fires once the bridge has closed the root connection it was
        /// told to lose, or has seen the client hang up on a root whose
        /// reply it was holding, so a recovery test never races the peer's FIN.
        root_closed: mpsc::Receiver<()>,
        stop: std::sync::Arc<AtomicBool>,
        listener_handle: Option<std::thread::JoinHandle<io::Result<()>>>,
        workers: std::sync::Arc<parking_lot::Mutex<Vec<std::thread::JoinHandle<io::Result<()>>>>>,
    }

    impl FakeSam {
        fn finish(&mut self) -> io::Result<()> {
            self.stop.store(true, Ordering::Release);
            let _ = std::net::TcpStream::connect(self.addr);
            let mut first_error: Option<io::Error> = None;
            if let Some(handle) = self.listener_handle.take() {
                match handle.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        if first_error.is_none() {
                            first_error = Some(err);
                        }
                    }
                    Err(payload) => std::panic::resume_unwind(payload),
                }
            }
            let workers = std::mem::take(&mut *self.workers.lock());
            for worker in workers {
                match worker.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        if first_error.is_none() {
                            first_error = Some(err);
                        }
                    }
                    Err(payload) => std::panic::resume_unwind(payload),
                }
            }
            if let Some(err) = first_error {
                return Err(err);
            }
            Ok(())
        }
    }

    impl Drop for FakeSam {
        fn drop(&mut self) {
            let _ = self.finish();
        }
    }

    /// Scripted bridge behaviour that is not a command-to-reply row.
    #[derive(Clone, Default)]
    struct FakeSamOptions {
        /// Verbatim remote-destination line written after
        /// `STREAM ACCEPT RESULT=OK`.
        accept_line: Option<String>,
        /// Drop the root connection once, immediately after the first
        /// `NAMING LOOKUP NAME=ME` reply, simulating bridge-side root loss.
        lose_root_after_first_me: bool,
        /// Stall this long before answering `STREAM CONNECT`.
        stall_stream_connect: Option<Duration>,
        /// Send the `STREAM CONNECT` reply without its terminating newline,
        /// then close the bridge connection.
        truncate_stream_reply: bool,
        /// Hold every stream request starting with this verb until the gate
        /// opens, then answer `STREAM STATUS RESULT=INVALID_ID`. A test opens
        /// the gate only after a newer root is installed, so the reply is
        /// delayed evidence about the root the request was issued against.
        gate_invalid_stream: Option<(&'static str, GateHandle)>,
        /// Drop the root connection on request: the first root worker that
        /// sees this flag set clears it and closes its connection, so only
        /// one root is lost per request.
        kill_root: Option<std::sync::Arc<AtomicBool>>,
        /// Hold one scripted reply behind a gate.
        held_reply: Option<HeldReply>,
        /// Answer the first this-many `SESSION CREATE` commands with
        /// `SESSION STATUS RESULT=I2P_ERROR`.
        fail_creates: usize,
        /// `SESSION CREATE` commands seen, shared by every worker.
        creates: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    /// One scripted reply withheld behind a gate.
    #[derive(Clone)]
    struct HeldReply {
        /// Command prefix whose reply is held.
        prefix: &'static str,
        /// Zero-based ordinal of the matching command that is held; every
        /// other matching command is answered normally.
        nth: usize,
        /// Reply bytes written before the hold, so a test can split a reply.
        head: usize,
        gate: GateHandle,
        /// Matching commands seen so far, shared by every worker.
        seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl HeldReply {
        fn new(prefix: &'static str, nth: usize, head: usize, gate: &GateHandle) -> Self {
            Self {
                prefix,
                nth,
                head,
                gate: std::sync::Arc::clone(gate),
                seen: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }
    }

    /// How a worker's wait for a held reply ended.
    enum GateWait {
        Opened,
        Stopped,
        /// The client closed its side while the reply was held.
        HungUp,
    }

    /// Whether the client closed its end of `socket`. A peek leaves any
    /// pipelined bytes in place, so an open client is never disturbed.
    fn client_hung_up(socket: &TcpStream) -> bool {
        if socket.set_nonblocking(true).is_err() {
            return false;
        }
        let mut byte = [0u8; 1];
        let hung_up = match socket.peek(&mut byte) {
            Ok(read) => read == 0,
            Err(error) => matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
            ),
        };
        let _ = socket.set_nonblocking(false);
        hung_up
    }

    /// Wait for `gate` to open, noticing a stop request or a client hang-up.
    fn wait_for_gate(gate: &GateHandle, stop: &AtomicBool, socket: &TcpStream) -> GateWait {
        let (open, condvar) = &**gate;
        let mut opened = open.lock();
        while !*opened {
            if stop.load(Ordering::Acquire) {
                return GateWait::Stopped;
            }
            if client_hung_up(socket) {
                return GateWait::HungUp;
            }
            let _ = condvar.wait_for(&mut opened, Duration::from_millis(50));
        }
        GateWait::Opened
    }

    /// Open/closed state a fixture worker waits on.
    type GateHandle = std::sync::Arc<(Mutex<bool>, parking_lot::Condvar)>;

    fn new_gate() -> GateHandle {
        std::sync::Arc::new((Mutex::new(false), parking_lot::Condvar::new()))
    }

    fn open_gate(gate: &GateHandle) {
        let (open, condvar) = &**gate;
        *open.lock() = true;
        condvar.notify_all();
    }

    /// Opens its gate when dropped, so a worker blocked on the gate is
    /// released on every exit path, including a failed assertion, before
    /// anything joins it.
    struct ReleaseOnDrop(GateHandle);

    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            open_gate(&self.0);
        }
    }

    /// Answer a gated stream request with `INVALID_ID` once its gate opens.
    /// Returns `true` when the request belonged to the gate.
    fn answer_gated_invalid_id(
        options: &FakeSamOptions,
        line: &str,
        writer: &mut TcpStream,
        stop: &AtomicBool,
    ) -> io::Result<bool> {
        let Some((prefix, gate)) = &options.gate_invalid_stream else {
            return Ok(false);
        };
        if !line.starts_with(*prefix) {
            return Ok(false);
        }
        let (open, condvar) = &**gate;
        let mut opened = open.lock();
        while !*opened {
            if stop.load(Ordering::Acquire) {
                return Ok(true);
            }
            let _ = condvar.wait_for(&mut opened, Duration::from_millis(50));
        }
        drop(opened);
        match writer.write_all(b"STREAM STATUS RESULT=INVALID_ID\n") {
            Err(error) if !stop.load(Ordering::Acquire) => Err(error),
            _ => Ok(true),
        }
    }

    /// Consume one pending root-loss request, if any.
    fn root_kill_requested(options: &FakeSamOptions) -> bool {
        options
            .kill_root
            .as_ref()
            .is_some_and(|kill| kill.swap(false, Ordering::SeqCst))
    }

    /// Bridge-side root loss: close both halves and only then signal, so the
    /// FIN is queued before the test thread probes.
    fn close_root(writer: TcpStream, reader: BufReader<TcpStream>, closed_tx: &mpsc::Sender<()>) {
        let _ = writer.shutdown(std::net::Shutdown::Both);
        drop(writer);
        drop(reader);
        let _ = closed_tx.send(());
    }

    /// Name the fixture operation whose socket I/O failed, keeping the kind.
    ///
    /// Workers tolerate a failure only once `stop` is set; every other
    /// error, `ConnectionReset` included, still fails the test through
    /// `FakeSam::finish`. This only adds the missing location to it.
    fn worker_failure(site: &str, error: &io::Error) -> io::Error {
        io::Error::new(error.kind(), format!("fake SAM worker {site}: {error}"))
    }

    /// Scripted SAM bridge: records every command line, replies from the
    /// script keyed by command prefix.
    fn fake_sam(script: Vec<(String, String)>) -> io::Result<FakeSam> {
        fake_sam_with(script, FakeSamOptions::default())
    }

    fn handle_stream_command(
        line: &str,
        writer: &mut TcpStream,
        reader: &mut BufReader<TcpStream>,
        script: &[(String, String)],
        options: &FakeSamOptions,
        stop: &AtomicBool,
    ) -> io::Result<()> {
        let (_, reply) = script
            .iter()
            .find(|(p, _)| line.starts_with(p))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "scripted stream reply missing")
            })?;
        if let Some(stall) = options.stall_stream_connect {
            let until = Instant::now() + stall;
            while Instant::now() < until && !stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(10));
            }
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
        }
        if answer_gated_invalid_id(options, line, writer, stop)? {
            return Ok(());
        }
        if options.truncate_stream_reply && line.starts_with("STREAM CONNECT") {
            let unterminated = reply.trim_end_matches(['\r', '\n']);
            writer.write_all(unterminated.as_bytes())?;
            writer.shutdown(std::net::Shutdown::Both)?;
            return Ok(());
        }
        if let Err(error) = writer.write_all(reply.as_bytes()) {
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            return Err(worker_failure(
                &format!("writing the reply to `{line}`"),
                &error,
            ));
        }
        if line.starts_with("STREAM ACCEPT") {
            let accept_line = options
                .accept_line
                .clone()
                .unwrap_or_else(|| format!("{} FROM_PORT=1 TO_PORT=8333\n", dest_b64()));
            if let Err(error) = writer.write_all(accept_line.as_bytes()) {
                if stop.load(Ordering::Acquire) {
                    return Ok(());
                }
                return Err(worker_failure(
                    &format!("writing the accept line for `{line}`"),
                    &error,
                ));
            }
        }
        let mut byte = [0u8; 1];
        if !stop.load(Ordering::Acquire) {
            match reader.read_exact(&mut byte) {
                Ok(()) => {
                    if let Err(error) = writer.write_all(&byte) {
                        if stop.load(Ordering::Acquire) {
                            return Ok(());
                        }
                        return Err(worker_failure(
                            &format!("echoing the bridged byte for `{line}`"),
                            &error,
                        ));
                    }
                }
                Err(err)
                    if stop.load(Ordering::Acquire)
                        || matches!(
                            err.kind(),
                            io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe
                        ) => {}
                Err(err) => {
                    return Err(worker_failure(
                        &format!("reading the bridged byte for `{line}`"),
                        &err,
                    ));
                }
            }
        }
        Ok(())
    }

    /// Write the scripted reply to `line`, applying the fixture's refusal
    /// and hold options. Returns `true` when the worker must end: it was
    /// stopped, or the client hung up while the reply was held.
    fn write_scripted_reply(
        line: &str,
        script: &[(String, String)],
        options: &FakeSamOptions,
        writer: &mut TcpStream,
        closed_tx: &mpsc::Sender<()>,
        stop: &AtomicBool,
    ) -> io::Result<bool> {
        let scripted = script
            .iter()
            .find(|(p, _)| line.starts_with(p))
            .map_or("SESSION STATUS RESULT=I2P_ERROR\n", |(_, r)| r.as_str());
        let refused = line.starts_with("SESSION CREATE")
            && options.creates.fetch_add(1, Ordering::SeqCst) < options.fail_creates;
        let reply = if refused {
            "SESSION STATUS RESULT=I2P_ERROR\n"
        } else {
            scripted
        };
        let held = options.held_reply.as_ref().filter(|held| {
            line.starts_with(held.prefix) && held.seen.fetch_add(1, Ordering::SeqCst) == held.nth
        });
        let (head, tail) = reply
            .as_bytes()
            .split_at(held.map_or(reply.len(), |held| held.head.min(reply.len())));
        if let Err(error) = writer.write_all(head) {
            if stop.load(Ordering::Acquire) {
                return Ok(true);
            }
            return Err(worker_failure(
                &format!("writing the reply to `{line}`"),
                &error,
            ));
        }
        let Some(held) = held else {
            return Ok(false);
        };
        match wait_for_gate(&held.gate, stop, writer) {
            GateWait::Opened => {}
            GateWait::Stopped => return Ok(true),
            GateWait::HungUp => {
                let _ = closed_tx.send(());
                return Ok(true);
            }
        }
        match writer.write_all(tail) {
            Ok(()) => Ok(false),
            Err(_) if stop.load(Ordering::Acquire) => Ok(true),
            Err(error) => Err(worker_failure(
                &format!("writing the held reply to `{line}`"),
                &error,
            )),
        }
    }

    fn handle_fake_sam_stream(
        stream: TcpStream,
        tx: &mpsc::Sender<String>,
        closed_tx: &mpsc::Sender<()>,
        script: &[(String, String)],
        options: &FakeSamOptions,
        root_lost: &AtomicBool,
        stop: &AtomicBool,
    ) -> io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_millis(200)))?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = stream;
        let mut pending: Vec<u8> = Vec::new();
        let mut is_root = false;
        loop {
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            if is_root && root_kill_requested(options) {
                close_root(writer, reader, closed_tx);
                return Ok(());
            }
            match reader.read_until(b'\n', &mut pending) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    if stop.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    continue;
                }
                Err(error) => {
                    if stop.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    let site = if is_root {
                        "reading a command on the root connection"
                    } else {
                        "reading a command on a bridge connection"
                    };
                    return Err(worker_failure(site, &error));
                }
            }
            if pending.last() != Some(&b'\n') {
                continue;
            }
            let line = String::from_utf8_lossy(&pending).trim_end().to_owned();
            pending.clear();
            let _ = tx.send(line.clone());
            is_root |= line.starts_with("SESSION CREATE");
            if line.starts_with("STREAM CONNECT") || line.starts_with("STREAM ACCEPT") {
                return handle_stream_command(
                    &line,
                    &mut writer,
                    &mut reader,
                    script,
                    options,
                    stop,
                );
            }
            if write_scripted_reply(&line, script, options, &mut writer, closed_tx, stop)? {
                return Ok(());
            }
            if options.lose_root_after_first_me
                && line.starts_with("NAMING LOOKUP NAME=ME")
                && !root_lost.swap(true, Ordering::SeqCst)
            {
                // Bridge-side root loss: shut down and drop the
                // socket before signaling so the FIN is queued on
                // the wire before the test thread probes.
                let _ = writer.shutdown(std::net::Shutdown::Both);
                drop(writer);
                drop(reader);
                let _ = closed_tx.send(());
                return Ok(());
            }
        }
    }

    fn fake_sam_with(
        script: Vec<(String, String)>,
        options: FakeSamOptions,
    ) -> io::Result<FakeSam> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (tx, rx) = mpsc::channel();
        let (closed_tx, closed_rx) = mpsc::channel();
        let options = std::sync::Arc::new(options);
        let root_lost = std::sync::Arc::new(AtomicBool::new(false));
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stop_listener = std::sync::Arc::clone(&stop);
        let stop_worker = std::sync::Arc::clone(&stop);
        let workers = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let workers_listener = std::sync::Arc::clone(&workers);
        let listener_handle = std::thread::spawn(move || -> io::Result<()> {
            for stream in listener.incoming() {
                if stop_listener.load(Ordering::Acquire) {
                    break;
                }
                let stream = match stream {
                    Ok(s) => s,
                    Err(err) => {
                        if stop_listener.load(Ordering::Acquire) {
                            break;
                        }
                        return Err(err);
                    }
                };
                if stop_listener.load(Ordering::Acquire) {
                    break;
                }
                let tx = tx.clone();
                let closed_tx = closed_tx.clone();
                let script = script.clone();
                let options = std::sync::Arc::clone(&options);
                let root_lost = std::sync::Arc::clone(&root_lost);
                let stop = std::sync::Arc::clone(&stop_worker);
                let handle = std::thread::spawn(move || {
                    handle_fake_sam_stream(
                        stream, &tx, &closed_tx, &script, &options, &root_lost, &stop,
                    )
                });
                workers_listener.lock().push(handle);
            }
            Ok(())
        });

        Ok(FakeSam {
            addr,
            commands: rx,
            root_closed: closed_rx,
            stop,
            listener_handle: Some(listener_handle),
            workers,
        })
    }

    const HELLO_OK: &str = "HELLO REPLY RESULT=OK VERSION=3.3\n";

    /// Standard-alphabet base64 encoding for fixture construction.
    fn b64_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let acc =
                chunk.iter().fold(0u32, |a, b| (a << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
            let chars = [acc >> 18, acc >> 12, acc >> 6, acc].map(|v| {
                let idx = usize::try_from(v & 63).unwrap_or_default();
                char::from(ALPHABET[idx])
            });
            out.extend(chars.iter().take(chunk.len() + 1));
            out.extend(std::iter::repeat_n('=', 3 - chunk.len()));
        }
        out
    }

    /// One structurally valid destination: 384 zero key bytes plus a
    /// key certificate (Ed25519 signing, X25519 crypto).
    fn dest_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; 384];
        bytes.extend_from_slice(&[5, 0, 4, 0, 7, 0, 4]);
        bytes
    }

    fn dest_b64() -> String {
        b64_encode(&dest_bytes())
    }

    /// Private fixture: the destination plus private key bytes.
    fn priv_b64() -> String {
        let mut bytes = dest_bytes();
        bytes.extend_from_slice(&[2u8; 64]);
        b64_encode(&bytes)
    }

    fn session_script() -> Vec<(String, String)> {
        let dest = dest_b64();
        vec![
            ("HELLO".to_owned(), HELLO_OK.to_owned()),
            (
                "SESSION CREATE".to_owned(),
                format!("SESSION STATUS RESULT=OK DESTINATION={dest}\n"),
            ),
            (
                "NAMING LOOKUP".to_owned(),
                format!("NAMING REPLY RESULT=OK NAME=ME VALUE={dest}\n"),
            ),
            (
                "STREAM CONNECT".to_owned(),
                "STREAM STATUS RESULT=OK\n".to_owned(),
            ),
            (
                "STREAM ACCEPT".to_owned(),
                "STREAM STATUS RESULT=OK\n".to_owned(),
            ),
            (
                "DEST GENERATE SIGNATURE_TYPE=7".to_owned(),
                format!("DEST REPLY PUB={dest} PRIV={}\n", priv_b64()),
            ),
        ]
    }

    #[test]
    fn base64_strict_canonicality() -> Result<(), Box<dyn std::error::Error>> {
        // Trailing data after padding.
        assert_eq!(i2p_base64_decode("AA=garbage"), None);
        // Non-zero padding bits.
        assert_eq!(i2p_base64_decode("AB"), None);
        assert_eq!(i2p_base64_decode("AAB="), None);
        // Padding embedded in the body.
        assert_eq!(i2p_base64_decode("AA==AA"), None);
        assert_eq!(i2p_base64_decode("AA=A"), None);
        // Invalid alphabet characters and embedded whitespace.
        assert_eq!(i2p_base64_decode("A!AA"), None);
        assert_eq!(i2p_base64_decode("AA AA"), None);
        assert_eq!(i2p_base64_decode("AA\nAA"), None);
        // Truncated quartets and padding that completes nothing.
        assert_eq!(i2p_base64_decode("A"), None);
        assert_eq!(i2p_base64_decode("AAA=="), None);
        assert_eq!(i2p_base64_decode(""), None);
        // Valid forms round-trip to exact bytes.
        assert_eq!(i2p_base64_decode("AQID"), Some(vec![1, 2, 3]));
        assert_eq!(i2p_base64_decode("AQIDBA=="), Some(vec![1, 2, 3, 4]));
        assert_eq!(i2p_base64_decode("AQI="), Some(vec![1, 2]));
        assert_eq!(i2p_base64_decode("AQ=="), Some(vec![1]));
        // The hash of a destination is over its exact decoded bytes.
        let expected: [u8; 32] = Sha256::digest([1u8, 2, 3]).into();
        let decoded = i2p_base64_decode("AQID")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "valid destination"))?;
        assert_eq!(destination_hash(&decoded), expected);
        // Destination structure: the 391-byte `KeysAndCert` form is valid;
        // truncated, trailing-data, and bad-certificate forms are not.
        assert!(valid_destination(&dest_bytes()));
        assert!(!valid_destination(&dest_bytes()[..390]));
        let mut trailing = dest_bytes();
        trailing.push(0);
        assert!(!valid_destination(&trailing));
        let mut bad_cert = dest_bytes();
        bad_cert[384] = 9;
        assert!(!valid_destination(&bad_cert));
        assert!(!valid_destination(&[0u8; 32]));
        Ok(())
    }

    #[test]
    fn session_id_is_derived_per_destination() {
        // Two destinations on one shared bridge must not collide.
        assert_ne!(session_id_for(&dest_b64()), session_id_for(&priv_b64()));
        assert!(session_id_for(&dest_b64()).starts_with("btcrs-"));
        assert_eq!(session_id_for(&dest_b64()), session_id_for(&dest_b64()));
    }

    #[test]
    fn session_negotiates_33_and_stream_connect_uses_fresh_bridge()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fake = fake_sam(session_script())?;
        let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
        // Public destination comes from NAMING LOOKUP NAME=ME, never from
        // the SESSION STATUS reply (which carries private material).
        assert_eq!(session.destination(), dest_b64());
        let mut stream = session
            .connect(destination_hash(&dest_bytes()), 8333)
            .map_err(crate::endpoint::DialFailure::into_io)?;
        stream.write_all(b"x")?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)?;
        assert_eq!(byte, *b"x");
        let commands: Vec<String> = fake.commands.try_iter().collect();
        assert_eq!(commands[0], "HELLO VERSION MIN=3.1 MAX=3.3");
        assert!(commands[1].starts_with(&format!(
            "SESSION CREATE STYLE=STREAM ID={} DESTINATION=",
            session.id()
        )));
        assert!(session.id().starts_with("btcrs-"));
        assert_eq!(commands[2], "NAMING LOOKUP NAME=ME");
        assert!(
            commands
                .iter()
                .any(|c| c.starts_with("NAMING LOOKUP NAME=") && c.ends_with(".b32.i2p"))
        );
        assert!(commands.iter().any(|c| c.starts_with(&format!(
            "STREAM CONNECT ID={} DESTINATION=",
            session.id()
        ))));
        assert_eq!(
            commands
                .iter()
                .filter(|c| c.starts_with("SESSION CREATE"))
                .count(),
            1,
            "a healthy root is never replaced: only the stream uses a fresh bridge"
        );
        fake.finish()?;
        Ok(())
    }

    #[test]
    fn hello_requiring_below_33_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut fake = fake_sam(vec![(
            "HELLO".to_owned(),
            "HELLO REPLY RESULT=OK VERSION=3.1\n".to_owned(),
        )])?;
        let Err(error) = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))
        else {
            panic!("3.1 must not satisfy the 3.3 requirement");
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        fake.finish()?;
        Ok(())
    }

    #[test]
    fn accept_hashes_remote_destination() -> Result<(), Box<dyn std::error::Error>> {
        // Construct a valid destination whose key bytes differ from our own,
        // proving accept() hashes the remote destination line rather than
        // repeating self.destination.
        let mut remote_bytes = dest_bytes();
        remote_bytes[0] = 0x42;
        let remote_dest = b64_encode(&remote_bytes);
        let mut fake = fake_sam_with(
            session_script(),
            FakeSamOptions {
                accept_line: Some(format!("{remote_dest} FROM_PORT=1 TO_PORT=8333\n")),
                ..FakeSamOptions::default()
            },
        )?;
        let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
        let (_stream, hash, port) = session.accept(Duration::from_secs(5), 9999)?;
        assert_eq!(hash, destination_hash(&remote_bytes));
        assert_ne!(
            hash,
            destination_hash(&dest_bytes()),
            "remote hash must differ from our own"
        );
        assert_eq!(port, 8333);
        fake.finish()?;
        Ok(())
    }

    #[test]
    fn key_file_create_reuse_and_corrupt_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("sam-key-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("i2p_private_key");
        let mut fake = fake_sam(session_script())?;
        let first = load_or_create_private_destination(fake.addr, &path, Duration::from_secs(5))?;
        assert_eq!(first, priv_b64());
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&path)?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Reuse: no DEST GENERATE is needed and content is identical.
        let second = load_or_create_private_destination(fake.addr, &path, Duration::from_secs(5))?;
        assert_eq!(first, second);
        // A loosened reused file is repaired to 0600 on load.
        #[cfg(unix)]
        {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
            let third =
                load_or_create_private_destination(fake.addr, &path, Duration::from_secs(5))?;
            assert_eq!(first, third);
            let mode = std::fs::metadata(&path)?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "reused key file mode is repaired");
        }
        std::fs::write(&path, "not a destination!!")?;
        let Err(error) =
            load_or_create_private_destination(fake.addr, &path, Duration::from_secs(5))
        else {
            panic!("corrupt key must fail closed");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(&path)?, b"not a destination!!");
        let _ = std::fs::remove_dir_all(&dir);
        fake.finish()?;
        Ok(())
    }

    #[test]
    fn generate_destination_requests_ed25519_and_accepts_the_standard_reply()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fake = fake_sam(session_script())?;
        let (public, private) = generate_destination(fake.addr, Duration::from_secs(5))?;
        assert_eq!(public, dest_b64());
        assert_eq!(private, priv_b64());
        // SAM defaults an omitted signature type to DSA-SHA1. The peer only
        // answers a request opening `DEST GENERATE SIGNATURE_TYPE=7`, and
        // the recorded lines pin the exact request on the wire.
        let commands: Vec<String> = fake.commands.try_iter().collect();
        assert_eq!(
            commands,
            [
                "HELLO VERSION MIN=3.1 MAX=3.3",
                "DEST GENERATE SIGNATURE_TYPE=7"
            ]
        );
        fake.finish()?;

        // An explicit `RESULT=OK` is not a failure: the same validated key
        // pair is accepted.
        let mut script = session_script();
        script.retain(|(prefix, _)| !prefix.starts_with("DEST GENERATE"));
        script.push((
            "DEST GENERATE SIGNATURE_TYPE=7".to_owned(),
            format!(
                "DEST REPLY RESULT=OK PUB={} PRIV={}\n",
                dest_b64(),
                priv_b64()
            ),
        ));
        let mut fake = fake_sam(script)?;
        let (public, private) = generate_destination(fake.addr, Duration::from_secs(5))?;
        assert_eq!(public, dest_b64());
        assert_eq!(private, priv_b64());
        fake.finish()?;
        Ok(())
    }

    /// A `DEST REPLY` the client must refuse, and the error it must raise.
    struct BadDestReply {
        label: &'static str,
        reply: String,
        kind: io::ErrorKind,
        fragment: &'static str,
    }

    /// Replies carrying a failure `RESULT`, alone or beside keys.
    fn result_bearing_dest_replies() -> Vec<BadDestReply> {
        let dest = dest_b64();
        let key = priv_b64();
        let case = |label, reply: String, fragment| BadDestReply {
            label,
            reply,
            kind: io::ErrorKind::ConnectionAborted,
            fragment,
        };
        vec![
            case(
                "explicit error",
                "DEST REPLY RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_SIGNATURE_TYPE\n".to_owned(),
                "DEST REPLY RESULT=I2P_ERROR",
            ),
            case(
                "error contradicting its keys",
                format!("DEST REPLY RESULT=I2P_ERROR PUB={dest} PRIV={key}\n"),
                "DEST REPLY RESULT=I2P_ERROR",
            ),
            case(
                "private key in the result field",
                format!("DEST REPLY RESULT={key}\n"),
                "DEST REPLY RESULT=UNKNOWN",
            ),
        ]
    }

    /// Replies without a failure `RESULT` whose keys are unusable.
    fn malformed_dest_replies() -> Vec<BadDestReply> {
        let dest = dest_b64();
        let key = priv_b64();
        let case = |label, reply: String, fragment| BadDestReply {
            label,
            reply,
            kind: io::ErrorKind::InvalidData,
            fragment,
        };
        vec![
            case(
                "missing public destination",
                format!("DEST REPLY PRIV={key}\n"),
                "no public destination",
            ),
            case(
                "missing private destination",
                format!("DEST REPLY PUB={dest}\n"),
                "no private destination",
            ),
            case(
                "public key is not a destination",
                format!("DEST REPLY PUB=AAAA PRIV={key}\n"),
                "generated public destination is not a valid destination",
            ),
            case(
                "private key is not base64",
                format!("DEST REPLY PUB={dest} PRIV={key}!\n"),
                "corrupt base64",
            ),
            case(
                "private key lacks its secret bytes",
                format!("DEST REPLY PUB={dest} PRIV={dest}\n"),
                "truncated",
            ),
            case(
                "ok status does not rescue an unusable key",
                format!("DEST REPLY RESULT=OK PUB={dest} PRIV={dest}\n"),
                "truncated",
            ),
        ]
    }

    #[test]
    fn bad_dest_replies_persist_no_key_and_reflect_no_key_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let dest = dest_b64();
        let key = priv_b64();
        let cases = result_bearing_dest_replies()
            .into_iter()
            .chain(malformed_dest_replies());
        for BadDestReply {
            label,
            reply,
            kind,
            fragment,
        } in cases
        {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("i2p_private_key");
            let mut fake = fake_sam(vec![
                ("HELLO".to_owned(), HELLO_OK.to_owned()),
                ("DEST GENERATE SIGNATURE_TYPE=7".to_owned(), reply),
            ])?;
            let Err(error) =
                load_or_create_private_destination(fake.addr, &path, Duration::from_secs(5))
            else {
                panic!("{label}: a refused DEST REPLY must not yield a key");
            };
            let text = error.to_string();
            assert_eq!(error.kind(), kind, "{label}: {text}");
            assert!(text.contains(fragment), "{label}: {text}");
            for secret in [&key, &dest] {
                assert!(
                    !text.contains(secret.as_str()),
                    "{label}: the error reflects reply material"
                );
            }
            assert!(!path.exists(), "{label}: no key file may be created");
            assert_eq!(
                std::fs::read_dir(dir.path())?.count(),
                0,
                "{label}: no temporary key file may remain"
            );
            let commands: Vec<String> = fake.commands.try_iter().collect();
            assert_eq!(
                commands,
                [
                    "HELLO VERSION MIN=3.1 MAX=3.3",
                    "DEST GENERATE SIGNATURE_TYPE=7"
                ],
                "{label}"
            );
            fake.finish()?;
        }
        Ok(())
    }

    #[test]
    fn missing_result_is_success_only_for_dest_reply() -> Result<(), Box<dyn std::error::Error>> {
        for (reply, prefix) in [
            ("SESSION STATUS DESTINATION=x", "SESSION STATUS"),
            ("NAMING REPLY NAME=ME VALUE=x", "NAMING REPLY"),
            ("STREAM STATUS", "STREAM STATUS"),
        ] {
            let Err(error) = require_ok(reply, prefix) else {
                panic!("`{prefix}` without RESULT must not succeed");
            };
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        }
        // The `DEST REPLY` rule does not reach the handshake: a `HELLO REPLY`
        // without `RESULT=OK` stops generation before `DEST GENERATE`.
        let mut fake = fake_sam(vec![(
            "HELLO".to_owned(),
            "HELLO REPLY VERSION=3.3\n".to_owned(),
        )])?;
        let Err(error) = generate_destination(fake.addr, Duration::from_secs(5)) else {
            panic!("a HELLO reply without RESULT must not succeed");
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        fake.finish()?;
        let commands: Vec<String> = fake.commands.try_iter().collect();
        assert_eq!(commands, ["HELLO VERSION MIN=3.1 MAX=3.3"]);
        Ok(())
    }

    /// A well-formed key token: a reader that followed a link or ignored
    /// the file type would hand it back as `Ok`.
    #[cfg(unix)]
    const KEY_FIXTURE: &str = "unrelated-owned-fixture-token\n";

    #[cfg(unix)]
    #[test]
    fn key_reader_refuses_a_symlink_and_leaves_its_target_untouched()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("unrelated");
        std::fs::write(&target, KEY_FIXTURE)?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))?;
        let link = dir.path().join("i2p_private_key");
        std::os::unix::fs::symlink(&target, &link)?;

        let Err(error) = read_key_file(&link) else {
            panic!("a symlinked key path must be refused");
        };
        assert_ne!(
            error.kind(),
            io::ErrorKind::NotFound,
            "a link is never an absent key"
        );

        assert_eq!(std::fs::read(&target)?, KEY_FIXTURE.as_bytes());
        assert_eq!(
            std::fs::metadata(&target)?.permissions().mode() & 0o777,
            0o644,
            "the link target's mode must not be repaired"
        );
        assert!(std::fs::symlink_metadata(&link)?.file_type().is_symlink());
        assert_eq!(std::fs::read_link(&link)?, target);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn dangling_key_symlink_is_refused_and_never_selects_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let missing = dir.path().join("missing-target");
        let link = dir.path().join("i2p_private_key");
        std::os::unix::fs::symlink(&missing, &link)?;
        let mut fake = fake_sam(session_script())?;

        let Err(error) =
            load_or_create_private_destination(fake.addr, &link, Duration::from_secs(5))
        else {
            panic!("a dangling key symlink must be refused");
        };
        assert_ne!(
            error.kind(),
            io::ErrorKind::NotFound,
            "a dangling link is not an absent key"
        );
        fake.finish()?;
        assert!(
            fake.commands.try_recv().is_err(),
            "a refused key path must not reach the SAM bridge"
        );
        assert!(!missing.exists(), "the link target must not be created");
        assert_eq!(std::fs::read_link(&link)?, missing);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn key_reader_refuses_a_directory_without_changing_its_mode()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("onion_v3_private_key");
        std::fs::create_dir(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;

        let Err(error) = read_key_file(&path) else {
            panic!("a directory key path must be refused");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o755,
            "a refused directory must not be chmodded"
        );
        Ok(())
    }

    // `rustix::fs::mkfifoat` is absent on exactly these targets (rustix 1.1.5
    // `src/fs/at.rs`), so the fixture is gated on the same set.
    #[cfg(all(
        unix,
        not(any(
            target_vendor = "apple",
            target_os = "espidf",
            target_os = "horizon",
            target_os = "vita",
            target_os = "wasi",
            target_os = "redox",
        ))
    ))]
    #[test]
    fn key_reader_refuses_a_fifo_without_blocking_or_chmod()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("i2p_private_key");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &path,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(io::Error::from)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?;

        // A blocking open would wait for a writer that never comes; the
        // bounded wait turns that regression into a failure, not a hang.
        // The reader thread is owned by this test and joined on every path:
        // a reader stuck in `open` is released by a nonblocking read-write
        // open of the same FIFO, which counts as the missing partner.
        let (done_tx, done_rx) = mpsc::channel();
        let reader_path = path.clone();
        let reader = std::thread::spawn(move || {
            let _ = done_tx.send(read_key_file(&reader_path));
        });
        let outcome = done_rx.recv_timeout(Duration::from_secs(5));
        if outcome.is_err() {
            let _ = rustix::fs::open(
                &path,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            );
        }
        reader
            .join()
            .map_err(|_| "the FIFO key reader thread panicked")?;
        let result = outcome.map_err(|_| "reading a FIFO key path blocked")?;

        let Err(error) = result else {
            panic!("a FIFO key path must be refused");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o640,
            "a refused FIFO must not be chmodded"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn key_reader_follows_a_symlinked_parent_and_repairs_the_mode_in_place()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let real = dir.path().join("real");
        std::fs::create_dir(&real)?;
        let key = real.join("onion_v3_private_key");
        std::fs::write(&key, KEY_FIXTURE)?;
        let linked = dir.path().join("datadir");
        std::os::unix::fs::symlink(&real, &linked)?;

        // Only the final component is refused; a linked data directory works.
        for loose in [0o644, 0o400] {
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(loose))?;
            let text = read_key_file(&linked.join("onion_v3_private_key"))?;
            assert_eq!(text, KEY_FIXTURE.trim());
            assert_eq!(
                std::fs::metadata(&key)?.permissions().mode() & 0o777,
                0o600,
                "mode {loose:o} is repaired through the opened handle"
            );
        }
        assert_eq!(std::fs::read(&key)?, KEY_FIXTURE.as_bytes());
        Ok(())
    }

    #[test]
    fn cant_reach_peer_and_timeout_are_peer_unreachable() -> Result<(), Box<dyn std::error::Error>>
    {
        for result in ["CANT_REACH_PEER", "TIMEOUT"] {
            let reply = format!("STREAM STATUS RESULT={result}\n");
            let dest = dest_b64();
            let script: Vec<(String, String)> = vec![
                ("HELLO".to_owned(), HELLO_OK.to_owned()),
                (
                    "SESSION CREATE".to_owned(),
                    format!("SESSION STATUS RESULT=OK DESTINATION={dest}\n"),
                ),
                (
                    "NAMING LOOKUP".to_owned(),
                    format!("NAMING REPLY RESULT=OK NAME=ME VALUE={dest}\n"),
                ),
                ("STREAM CONNECT".to_owned(), reply),
            ];
            let mut fake = fake_sam(script)?;
            let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
            let Err(error) = session.connect(destination_hash(&dest_bytes()), 8333) else {
                panic!("peer unreachable must fail the dial");
            };
            assert!(
                matches!(&error, crate::endpoint::DialFailure::PeerUnreachable(_)),
                "{result} must be peer-unreachable, got {error:?}"
            );
            assert!(error.counts_as_peer_failure());
            // Exactly one stream request: a peer-unreachable reply is never
            // retried as an invalid session id.
            let commands: Vec<String> = fake.commands.try_iter().collect();
            assert_eq!(
                commands
                    .iter()
                    .filter(|c| c.starts_with("STREAM CONNECT"))
                    .count(),
                1,
                "peer-unreachable is final, not a session fault: {commands:?}"
            );
            fake.finish()?;
        }
        Ok(())
    }

    #[test]
    fn local_sam_protocol_failure_is_transport() -> Result<(), Box<dyn std::error::Error>> {
        let dest = dest_b64();
        let script: Vec<(String, String)> = vec![
            ("HELLO".to_owned(), HELLO_OK.to_owned()),
            (
                "SESSION CREATE".to_owned(),
                format!("SESSION STATUS RESULT=OK DESTINATION={dest}\n"),
            ),
            (
                "NAMING LOOKUP NAME=ME".to_owned(),
                format!("NAMING REPLY RESULT=OK NAME=ME VALUE={dest}\n"),
            ),
            (
                "NAMING LOOKUP".to_owned(),
                "NAMING REPLY RESULT=KEY_NOT_FOUND NAME=x\n".to_owned(),
            ),
        ];
        let mut fake = fake_sam(script)?;
        let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
        // NAMING for ME succeeds in establish; the peer lookup fails as a
        // local naming/protocol matter, not peer evidence.
        let Err(error) = session.connect([9u8; 32], 8333) else {
            panic!("failed lookup must fail the dial");
        };
        assert!(
            matches!(&error, crate::endpoint::DialFailure::Transport(_)),
            "got {error:?}"
        );
        assert!(!error.counts_as_peer_failure());
        fake.finish()?;
        Ok(())
    }

    #[test]
    fn dead_sam_is_a_transport_error() -> Result<(), Box<dyn std::error::Error>> {
        let addr = "127.0.0.1:1".parse()?;
        let Err(error) = SamSession::establish(addr, &priv_b64(), Duration::from_secs(2)) else {
            panic!("dead sam must fail");
        };
        assert_ne!(error.kind(), io::ErrorKind::Unsupported);
        Ok(())
    }

    #[test]
    fn naming_destination_hash_mismatch_is_transport_and_forbids_stream_connect()
    -> Result<(), Box<dyn std::error::Error>> {
        let dest = dest_b64();
        let script: Vec<(String, String)> = vec![
            ("HELLO".to_owned(), HELLO_OK.to_owned()),
            (
                "SESSION CREATE".to_owned(),
                format!("SESSION STATUS RESULT=OK DESTINATION={dest}\n"),
            ),
            (
                "NAMING LOOKUP NAME=ME".to_owned(),
                format!("NAMING REPLY RESULT=OK NAME=ME VALUE={dest}\n"),
            ),
            (
                "NAMING LOOKUP".to_owned(),
                format!("NAMING REPLY RESULT=OK NAME=peer VALUE={dest}\n"),
            ),
            (
                "STREAM CONNECT".to_owned(),
                "STREAM STATUS RESULT=OK\n".to_owned(),
            ),
        ];
        let mut fake = fake_sam(script)?;
        let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;

        // Request a hash different from dest's hash.
        let requested_hash = [9u8; 32];
        assert_ne!(requested_hash, destination_hash(&dest_bytes()));

        let Err(error) = session.connect(requested_hash, 8333) else {
            panic!("substituted destination identity must fail the dial");
        };

        assert!(
            matches!(&error, crate::endpoint::DialFailure::Transport(_)),
            "mismatch must be DialFailure::Transport, got {error:?}"
        );
        assert!(
            !error.counts_as_peer_failure(),
            "transport mismatch must not count as peer failure"
        );

        // Verify fake SAM did NOT receive STREAM CONNECT command
        let commands: Vec<String> = fake.commands.try_iter().collect();
        assert!(
            commands.iter().all(|c| !c.starts_with("STREAM CONNECT")),
            "STREAM CONNECT must not be sent on identity mismatch: {commands:?}"
        );
        fake.finish()?;
        Ok(())
    }

    #[test]
    fn secret_result_is_never_reflected_in_errors() -> Result<(), Box<dyn std::error::Error>> {
        let secret = priv_b64();
        // An unrecognized RESULT classifies to the fixed UNKNOWN token; the
        // raw bridge value never reaches an error string.
        assert_eq!(sanitize_sam_result(&secret), "UNKNOWN");
        // 1. require_ok with secret in RESULT
        let reply = format!("SESSION STATUS RESULT={secret}\n");
        let Err(err) = require_ok(&reply, "SESSION STATUS") else {
            panic!("must fail");
        };
        let err_str = err.to_string();
        assert!(
            !err_str.contains(&secret),
            "require_ok reflected private key material in error: {err_str}"
        );
        assert_eq!(
            err.kind(),
            io::ErrorKind::ConnectionAborted,
            "a refused SAM request is a local protocol refusal: {err_str}"
        );
        assert!(
            err_str.contains("SESSION STATUS"),
            "the refusal must name the refused verb, not the bridge value: {err_str}"
        );

        // 2. SamSession::connect with secret in STREAM STATUS RESULT
        let dest = dest_b64();
        let script: Vec<(String, String)> = vec![
            ("HELLO".to_owned(), HELLO_OK.to_owned()),
            (
                "SESSION CREATE".to_owned(),
                format!("SESSION STATUS RESULT=OK DESTINATION={dest}\n"),
            ),
            (
                "NAMING LOOKUP NAME=ME".to_owned(),
                format!("NAMING REPLY RESULT=OK NAME=ME VALUE={dest}\n"),
            ),
            (
                "NAMING LOOKUP".to_owned(),
                format!("NAMING REPLY RESULT=OK NAME=peer VALUE={dest}\n"),
            ),
            (
                "STREAM CONNECT".to_owned(),
                format!("STREAM STATUS RESULT={secret}\n"),
            ),
        ];
        let mut fake = fake_sam(script)?;
        let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
        let Err(error) = session.connect(destination_hash(&dest_bytes()), 8333) else {
            panic!("connect must fail");
        };
        let error_str = error.to_string();
        assert!(
            !error_str.contains(&secret),
            "connect reflected private key material in error: {error_str}"
        );
        assert!(
            matches!(&error, crate::endpoint::DialFailure::Transport(_)),
            "an unrecognized bridge result is a local transport failure: {error:?}"
        );
        assert!(
            !error.counts_as_peer_failure(),
            "an unrecognized bridge result is never peer evidence"
        );
        fake.finish()?;
        Ok(())
    }

    #[test]
    fn parse_fields_handles_quotes_and_rejects_malformed_grammar()
    -> Result<(), Box<dyn std::error::Error>> {
        // Valid quoted value with spaces
        let fields = parse_fields(
            r#"SESSION STATUS RESULT=I2P_ERROR MESSAGE="tunnel build failed: no peers""#,
            "SESSION STATUS",
        )?;
        assert_eq!(field(&fields, "RESULT"), Some("I2P_ERROR"));
        assert_eq!(
            field(&fields, "MESSAGE"),
            Some("tunnel build failed: no peers")
        );

        // Malformed: token missing '='
        assert!(parse_fields("HELLO REPLY RESULT=OK GARBAGE VERSION=3.3", "HELLO REPLY").is_err());

        // Malformed: duplicate singleton key
        assert!(parse_fields("SESSION STATUS RESULT=OK RESULT=OK", "SESSION STATUS").is_err());

        // Malformed: verb boundary violation
        assert!(parse_fields("HELLO REPLYEVIL RESULT=OK", "HELLO REPLY").is_err());

        // Malformed: unterminated quote
        assert!(
            parse_fields(
                r#"SESSION STATUS RESULT=OK MESSAGE="unterminated"#,
                "SESSION STATUS"
            )
            .is_err()
        );

        // Malformed: characters immediately following closing quote without space
        assert!(
            parse_fields(
                r#"SESSION STATUS RESULT=OK MESSAGE="msg"extra"#,
                "SESSION STATUS"
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn valid_destination_accepts_387_byte_null_certificate() {
        // Base 384 bytes + 3-byte CertificateNull (type 0, length 0) = 387 bytes.
        let mut null_cert = vec![0u8; 384];
        null_cert.extend_from_slice(&[0, 0, 0]); // cert_type 0, payload_len 0
        assert_eq!(null_cert.len(), 387);
        assert_eq!(destination_identity_len(&null_cert), Some(387));
        assert!(
            valid_destination(&null_cert),
            "valid_destination must accept 387-byte null certificate"
        );
    }

    #[test]
    fn validate_private_destination_strict_ivnp_rules() {
        let valid_key = priv_b64();
        assert!(validate_private_destination(&valid_key).is_ok());

        // Corrupt: trailing bytes on an online key
        let mut bytes = dest_bytes();
        bytes.extend_from_slice(&[2u8; 64]);
        bytes.extend_from_slice(&[9u8; 4]); // extra trailing bytes!
        let with_trailing = b64_encode(&bytes);
        assert!(
            validate_private_destination(&with_trailing).is_err(),
            "trailing bytes must fail validation"
        );

        // Corrupt: truncated private key bytes
        let mut truncated = dest_bytes();
        truncated.extend_from_slice(&[2u8; 32]); // only 32 bytes instead of 64
        assert!(validate_private_destination(&b64_encode(&truncated)).is_err());
    }

    #[test]
    fn stream_accept_refuses_bad_ports_and_uses_fallback_for_absent_or_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        let dest = dest_b64();
        let session_with = |accept_line: Option<String>| -> Result<(FakeSam, SamSession), Box<dyn std::error::Error>> {
            let fake = fake_sam_with(
                session_script(),
                FakeSamOptions {
                    accept_line,
                    ..FakeSamOptions::default()
                },
            )?;
            let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
            Ok((fake, session))
        };

        // 1. Absent TO_PORT keeps the caller's fallback port.
        let (mut fake, session) = session_with(Some(format!("{dest} FROM_PORT=1\n")))?;
        let (_stream, hash, port) = session.accept(Duration::from_secs(5), 7777)?;
        assert_eq!(port, 7777, "an absent TO_PORT uses the fallback port");
        assert_eq!(hash, destination_hash(&dest_bytes()));
        fake.finish()?;

        // 2. A present, well-formed TO_PORT is used as reported.
        let (mut fake, session) = session_with(Some(format!("{dest} TO_PORT=9999\n")))?;
        let (_stream, _hash, port) = session.accept(Duration::from_secs(5), 7777)?;
        assert_eq!(port, 9999);
        fake.finish()?;

        // 3. I2CP port 0 means any or unspecified service: it is the
        //    application fallback, not malformed input.
        let (mut fake, session) = session_with(Some(format!("{dest} TO_PORT=0\n")))?;
        let (_stream, hash, port) = session.accept(Duration::from_secs(5), 7777)?;
        assert_eq!(port, 7777, "TO_PORT=0 uses the fallback port");
        assert_eq!(hash, destination_hash(&dest_bytes()));
        fake.finish()?;

        // 4. Malformed and out-of-range ports are refused outright rather
        //    than silently replaced by the fallback.
        for bad in ["TO_PORT=not-a-port", "TO_PORT=65536"] {
            let (mut fake, session) = session_with(Some(format!("{dest} {bad}\n")))?;
            let Err(error) = session.accept(Duration::from_secs(5), 7777) else {
                panic!("a malformed present port must fail the accept");
            };
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "{bad} must be refused as malformed, got {error}"
            );
            fake.finish()?;
        }

        // 5. A repeated TO_PORT is ambiguous and refused, not last-wins. A
        //    zero is a present field, so it counts in either position.
        for duplicate in [
            "TO_PORT=9999 TO_PORT=9999",
            "TO_PORT=0 TO_PORT=0",
            "TO_PORT=0 TO_PORT=9999",
            "TO_PORT=9999 TO_PORT=0",
        ] {
            let (mut fake, session) = session_with(Some(format!("{dest} {duplicate}\n")))?;
            let Err(error) = session.accept(Duration::from_secs(5), 7777) else {
                panic!("a duplicate TO_PORT must fail the accept");
            };
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "`{duplicate}` must be refused, got {error}"
            );
            fake.finish()?;
        }
        Ok(())
    }

    #[test]
    fn write_key_file_atomic_and_no_replace() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("sam-atomic-key-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("test_key");

        // Write first time: succeeds
        write_key_file(&path, "initial_key_data")?;
        assert_eq!(std::fs::read_to_string(&path)?, "initial_key_data\n");

        // Write second time to same path: must refuse to replace!
        let Err(err) = write_key_file(&path, "new_key_data") else {
            panic!("must not replace");
        };
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

        // Content of existing file remains untouched
        assert_eq!(std::fs::read_to_string(&path)?, "initial_key_data\n");

        // Public destination (391 bytes) rejected as private destination in establish
        let addr: SocketAddr = "127.0.0.1:7656".parse()?;
        let Err(err) = SamSession::establish(addr, &dest_b64(), Duration::from_secs(5)) else {
            panic!("public destination must be rejected as private");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Corrupt private destination with invalid trailing bytes rejected in validate_private_destination
        let mut corrupt = dest_bytes();
        corrupt.extend_from_slice(&[2u8; 64]);
        corrupt.extend_from_slice(&[9u8; 4]); // trailing bytes!
        let corrupt_b64 = b64_encode(&corrupt);
        let Err(err) = SamSession::establish(addr, &corrupt_b64, Duration::from_secs(5)) else {
            panic!("corrupt private key must be rejected");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // No temp files left behind in directory
        let temp_files: Vec<_> = std::fs::read_dir(&dir)?
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
            .collect();
        assert!(temp_files.is_empty(), "temporary files must be cleaned up");

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn sam_root_session_loss_lifecycle_and_recovery() -> Result<(), Box<dyn std::error::Error>> {
        let dest = dest_b64();
        let priv_key = priv_b64();
        let mut fake = fake_sam(session_script())?;
        let session = SamSession::establish(fake.addr, &priv_key, Duration::from_secs(5))?;

        // Simulate root session drop through the production retirement path.
        let deadline = Instant::now() + Duration::from_secs(5);
        let root = session.ensure_control(deadline)?;
        session.retire_root(root, deadline)?;

        // Calling connect or accept automatically recovers the root session
        let mut stream = session
            .connect(destination_hash(&dest_bytes()), 8333)
            .map_err(crate::endpoint::DialFailure::into_io)?;
        stream.write_all(b"x")?;
        assert_eq!(session.destination(), dest);
        fake.finish()?;
        Ok(())
    }

    #[test]
    fn bridge_side_root_loss_recovers_the_same_identity_once()
    -> Result<(), Box<dyn std::error::Error>> {
        // The bridge drops the root control connection right after
        // establishment. The next dial must re-create the *same* session
        // id and destination, then keep using that recovered root.
        let mut fake = fake_sam_with(
            session_script(),
            FakeSamOptions {
                lose_root_after_first_me: true,
                ..FakeSamOptions::default()
            },
        )?;
        let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
        fake.root_closed
            .recv_timeout(Duration::from_secs(5))
            .map_err(|e| io::Error::new(io::ErrorKind::TimedOut, e))?;

        for _ in 0..2 {
            let mut stream = session
                .connect(destination_hash(&dest_bytes()), 8333)
                .map_err(crate::endpoint::DialFailure::into_io)?;
            stream.write_all(b"x")?;
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte)?;
            assert_eq!(byte, *b"x");
        }

        let commands: Vec<String> = fake.commands.try_iter().collect();
        let creates: Vec<&String> = commands
            .iter()
            .filter(|c| c.starts_with("SESSION CREATE"))
            .collect();
        assert_eq!(
            creates.len(),
            2,
            "the lost root is re-created exactly once: {commands:?}"
        );
        assert_eq!(
            creates[0], creates[1],
            "recovery must reuse the same session id and destination key"
        );
        assert_eq!(session.destination(), dest_b64());
        assert!(
            commands
                .iter()
                .filter(|c| c.starts_with("STREAM CONNECT"))
                .count()
                >= 2,
            "every dial still opens its own fresh bridge: {commands:?}"
        );
        fake.finish()?;
        Ok(())
    }

    #[test]
    fn close_forbids_session_resurrection() -> Result<(), Box<dyn std::error::Error>> {
        let mut fake = fake_sam(session_script())?;
        let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
        session.close();

        let Err(error) = session.connect(destination_hash(&dest_bytes()), 8333) else {
            panic!("a closed session must never dial");
        };
        assert!(matches!(&error, crate::endpoint::DialFailure::Transport(_)));
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert!(!error.counts_as_peer_failure());

        let Err(accept_error) = session.accept(Duration::from_secs(1), 8333) else {
            panic!("a closed session must never accept");
        };
        assert_eq!(accept_error.kind(), io::ErrorKind::NotConnected);

        // No root re-creation and no stream request may follow the close.
        let commands: Vec<String> = fake.commands.try_iter().collect();
        assert_eq!(
            commands
                .iter()
                .filter(|c| c.starts_with("SESSION CREATE"))
                .count(),
            1,
            "close forbids a second session root: {commands:?}"
        );
        assert!(
            commands.iter().all(|c| !c.starts_with("STREAM")),
            "no stream request may follow a close: {commands:?}"
        );
        fake.finish()?;
        Ok(())
    }

    /// Upper bound for waits that only guard liveness; no assertion
    /// measures against it.
    const LIVENESS: Duration = Duration::from_secs(10);

    /// Budget given to a caller that is expected to be refused by the lock.
    const HELD_BUDGET: Duration = Duration::from_millis(600);

    /// The two public stream verbs, so one scenario drives both callers.
    #[derive(Clone, Copy)]
    enum Verb {
        Connect,
        Accept,
    }

    impl Verb {
        fn request_prefix(self) -> &'static str {
            match self {
                Self::Connect => "STREAM CONNECT",
                Self::Accept => "STREAM ACCEPT",
            }
        }

        fn other(self) -> Self {
            match self {
                Self::Connect => Self::Accept,
                Self::Accept => Self::Connect,
            }
        }

        /// Issue the public call. `budget` is `accept`'s wait; `connect` is
        /// bounded by the session timeout fixed at `establish`.
        fn call(self, session: &SamSession, budget: Duration) -> io::Result<TcpStream> {
            match self {
                Self::Connect => session
                    .connect(destination_hash(&dest_bytes()), 8333)
                    .map_err(crate::endpoint::DialFailure::into_io),
                Self::Accept => session
                    .accept(budget, 8333)
                    .map(|(stream, _hash, _port)| stream),
            }
        }
    }

    /// Drain bridge commands into `seen` until one starts with `prefix`.
    fn wait_for_command(
        commands: &mpsc::Receiver<String>,
        seen: &mut Vec<String>,
        prefix: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            let line = commands.recv_timeout(Duration::from_secs(5))?;
            let hit = line.starts_with(prefix);
            seen.push(line);
            if hit {
                return Ok(());
            }
        }
    }

    /// Wait until the production liveness probe reports the lost root dead.
    ///
    /// The fixture signals after it closes the root, but delivery of the
    /// close to the client socket is asynchronous, so a caller must not be
    /// started on the strength of that signal alone.
    fn wait_until_root_is_dead(session: &SamSession) -> io::Result<()> {
        let give_up = Instant::now() + Duration::from_secs(5);
        // The probe reports `TimedOut` once `give_up` passes, which ends the
        // wait if the root never reads dead.
        while session.live_control_generation(give_up)?.is_some() {
            std::thread::yield_now();
        }
        Ok(())
    }

    /// Complete one bridged exchange, then close the client side.
    ///
    /// The fixture's bridge worker answers a stream request and then waits
    /// for one client byte to echo. Writing and reading one byte before the
    /// client closes lets that worker finish on a normal close instead of
    /// racing the client's teardown. This removes one way for a worker to
    /// see an abrupt close; it does not establish that such a close was the
    /// only source of a reset, which `step` and `worker_failure` locate.
    ///
    /// `into_stream` clears the socket timeouts so bridged payload is never
    /// bounded by a handshake budget, so this exchange sets its own: a
    /// bridge that never echoes fails here instead of hanging the test.
    fn finish_stream_exchange(stream: &mut TcpStream) -> io::Result<()> {
        stream.set_write_timeout(Some(LIVENESS))?;
        stream.set_read_timeout(Some(LIVENESS))?;
        stream.write_all(b"x")?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)?;
        if byte != *b"x" {
            return Err(invalid("bridge echoed a different byte"));
        }
        Ok(())
    }

    /// Name the step whose I/O failed, keeping the original error kind.
    ///
    /// A bare `ConnectionReset` from a test that opens several bridge
    /// connections does not say which exchange produced it.
    fn step<T>(label: &str, result: io::Result<T>) -> Result<T, Box<dyn std::error::Error>> {
        result.map_err(|error| -> Box<dyn std::error::Error> {
            io::Error::new(error.kind(), format!("{label}: {error}")).into()
        })
    }

    /// Tear the fixture down, naming the step that led here.
    ///
    /// `finish` joins every bridge worker and returns the first worker
    /// error, which would otherwise surface as a bare socket error with no
    /// indication of which exchange left a worker mid-read.
    fn finish_bridge_after(
        fake: &mut FakeSam,
        step: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        fake.finish()
            .map_err(|error| -> Box<dyn std::error::Error> {
                io::Error::new(
                    error.kind(),
                    format!("bridge teardown after {step}: {error}"),
                )
                .into()
            })
    }

    fn session_creates(commands: &[String]) -> usize {
        commands
            .iter()
            .filter(|command| command.starts_with("SESSION CREATE"))
            .count()
    }

    #[test]
    fn recovery_wait_is_charged_to_each_callers_own_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        // Another owner holds the session lock with an unrelated budget.
        // Each public caller must still report by its own absolute
        // deadline, without reaching the bridge, and the lock is released
        // only after the caller has reported.
        for verb in [Verb::Connect, Verb::Accept] {
            let mut fake = fake_sam_with(
                session_script(),
                FakeSamOptions {
                    lose_root_after_first_me: true,
                    ..FakeSamOptions::default()
                },
            )?;
            // Establish with a generous budget, then shorten the budget
            // `connect` reads per call, so setup cannot flake on a loaded
            // machine while the refused caller still has a short deadline.
            let mut session = step(
                "held-lock establish",
                SamSession::establish(fake.addr, &priv_b64(), LIVENESS),
            )?;
            session.timeout = HELD_BUDGET;
            // The root is gone, so the caller must take the recovery path.
            fake.root_closed.recv_timeout(Duration::from_secs(5))?;
            step(
                "held-lock wait for the lost root",
                wait_until_root_is_dead(&session),
            )?;

            let outcome = std::thread::scope(
                |scope| -> Result<io::Result<()>, Box<dyn std::error::Error>> {
                    let session = &session;
                    let (reported_tx, reported_rx) = mpsc::channel();
                    // Dropped on every path out of this closure, before the
                    // scope joins the caller.
                    let held = session.recovery.lock();
                    scope.spawn(move || {
                        let _ = reported_tx.send(verb.call(session, HELD_BUDGET).map(|_stream| ()));
                    });
                    let outcome = reported_rx.recv_timeout(LIVENESS)?;
                    drop(held);
                    Ok(outcome)
                },
            )?;

            let Err(error) = outcome else {
                return Err("a caller blocked behind recovery must fail at its deadline".into());
            };
            assert_eq!(
                error.kind(),
                io::ErrorKind::TimedOut,
                "the caller must report its own deadline, got {error:?}"
            );
            let mut commands: Vec<String> = fake.commands.try_iter().collect();
            assert_eq!(
                session_creates(&commands),
                1,
                "the refused caller must not touch recovery: {commands:?}"
            );
            assert!(
                commands.iter().all(|c| !c.starts_with("STREAM")),
                "the refused caller must not reach the bridge: {commands:?}"
            );

            // With the lock free, the same public call recovers the same
            // identity once.
            session.timeout = LIVENESS;
            let mut stream = step("held-lock recovered call", verb.call(&session, LIVENESS))?;
            step(
                "held-lock echo on the recovered stream",
                finish_stream_exchange(&mut stream),
            )?;
            drop(stream);
            commands.extend(fake.commands.try_iter());
            assert_eq!(
                session_creates(&commands),
                2,
                "recovery runs once after release: {commands:?}"
            );
            assert_eq!(session.destination(), dest_b64());
            finish_bridge_after(&mut fake, "held-lock recovery")?;
        }
        Ok(())
    }

    fn delayed_invalid_id_spares_the_recovered_root(
        gated: Verb,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let gate = new_gate();
        let kill = std::sync::Arc::new(AtomicBool::new(false));
        let mut fake = fake_sam_with(
            session_script(),
            FakeSamOptions {
                gate_invalid_stream: Some((gated.request_prefix(), std::sync::Arc::clone(&gate))),
                kill_root: Some(std::sync::Arc::clone(&kill)),
                ..FakeSamOptions::default()
            },
        )?;
        let session = step(
            "delayed INVALID_ID establish",
            SamSession::establish(fake.addr, &priv_b64(), LIVENESS),
        )?;
        let mut seen: Vec<String> = Vec::new();

        let outcome = std::thread::scope(
            |scope| -> Result<io::Result<()>, Box<dyn std::error::Error>> {
                // Opens the gate on every path out of this closure, before
                // the scope joins the held request.
                let _release = ReleaseOnDrop(std::sync::Arc::clone(&gate));
                let session = &session;
                let (reported_tx, reported_rx) = mpsc::channel();
                scope.spawn(move || {
                    let _ = reported_tx.send(gated.call(session, LIVENESS).map(|_stream| ()));
                });
                // 1. The old request is in flight against the first root.
                wait_for_command(&fake.commands, &mut seen, gated.request_prefix())?;
                // 2. The bridge loses that root; the other public verb
                //    recovers a newer one.
                kill.store(true, Ordering::SeqCst);
                fake.root_closed.recv_timeout(Duration::from_secs(5))?;
                step(
                    "delayed INVALID_ID wait for the lost root",
                    wait_until_root_is_dead(session),
                )?;
                let mut recovered = step(
                    "delayed INVALID_ID recovering call",
                    gated.other().call(session, LIVENESS),
                )?;
                step(
                    "delayed INVALID_ID echo on the recovering stream",
                    finish_stream_exchange(&mut recovered),
                )?;
                drop(recovered);
                // 3. Only now does the old root's INVALID_ID arrive.
                open_gate(&gate);
                Ok(reported_rx.recv_timeout(LIVENESS)?)
            },
        )?;

        let Err(error) = outcome else {
            return Err("the delayed INVALID_ID must still fail the old request".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::NotConnected, "got {error:?}");

        // The recovered root still serves the other verb with no further
        // SESSION CREATE.
        let mut stream = step(
            "delayed INVALID_ID follow-up call",
            gated.other().call(&session, LIVENESS),
        )?;
        step(
            "delayed INVALID_ID echo on the follow-up stream",
            finish_stream_exchange(&mut stream),
        )?;
        drop(stream);
        seen.extend(fake.commands.try_iter());
        assert_eq!(
            session_creates(&seen),
            2,
            "stale evidence about the first root must not retire the recovered one: {seen:?}"
        );
        assert_eq!(session.destination(), dest_b64());
        finish_bridge_after(&mut fake, "delayed INVALID_ID")?;
        Ok(())
    }

    #[test]
    fn delayed_invalid_id_never_retires_a_recovered_root() -> Result<(), Box<dyn std::error::Error>>
    {
        for gated in [Verb::Connect, Verb::Accept] {
            delayed_invalid_id_spares_the_recovered_root(gated)?;
        }
        Ok(())
    }

    /// A session whose root is lost, with the reply to the recovery's
    /// `prefix` command held behind `gate`, and the commands seen so far.
    fn session_with_held_recovery(
        prefix: &'static str,
        gate: &GateHandle,
    ) -> Result<(FakeSam, SamSession, Vec<String>), Box<dyn std::error::Error>> {
        let fake = fake_sam_with(
            session_script(),
            FakeSamOptions {
                lose_root_after_first_me: true,
                held_reply: Some(HeldReply::new(prefix, 1, 0, gate)),
                ..FakeSamOptions::default()
            },
        )?;
        let session = step(
            "held recovery establish",
            SamSession::establish(fake.addr, &priv_b64(), LIVENESS),
        )?;
        fake.root_closed.recv_timeout(Duration::from_secs(5))?;
        step(
            "held recovery wait for the lost root",
            wait_until_root_is_dead(&session),
        )?;
        let seen = fake.commands.try_iter().collect();
        Ok((fake, session, seen))
    }

    /// The phase of the pending root, if one is held.
    fn pending_phase_is(session: &SamSession, expected: &RootPhase) -> bool {
        session
            .recovery
            .lock()
            .pending
            .as_ref()
            .is_some_and(|pending| {
                std::mem::discriminant(&pending.phase) == std::mem::discriminant(expected)
            })
    }

    fn pending_root_resumes_across_short_callers(
        verb: Verb,
        held_prefix: &'static str,
        paused_in: &RootPhase,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let gate = new_gate();
        let (mut fake, mut session, mut seen) = session_with_held_recovery(held_prefix, &gate)?;
        session.timeout = HELD_BUDGET;
        for _ in 0..2 {
            let Err(error) = verb.call(&session, HELD_BUDGET) else {
                return Err("a caller behind a held reply must time out".into());
            };
            assert_eq!(error.kind(), io::ErrorKind::TimedOut, "got {error:?}");
        }
        seen.extend(fake.commands.try_iter());
        assert!(
            pending_phase_is(&session, paused_in),
            "the paused exchange stays pending in its own phase"
        );
        assert_eq!(
            session_creates(&seen),
            if matches!(paused_in, RootPhase::Hello) {
                1
            } else {
                2
            },
            "short callers resume the pending root; they never restart it: {seen:?}"
        );
        assert_eq!(
            session.control.lock().generation,
            1,
            "a pending root never moves the generation"
        );
        // Delayed evidence about the old root spares the pending one.
        step(
            "pending delayed retire",
            session.retire_root(1, Instant::now() + LIVENESS),
        )?;
        assert!(pending_phase_is(&session, paused_in));

        open_gate(&gate);
        session.timeout = LIVENESS;
        let mut stream = step("pending resumed call", verb.call(&session, LIVENESS))?;
        step("pending echo", finish_stream_exchange(&mut stream))?;
        drop(stream);
        seen.extend(fake.commands.try_iter());
        assert_eq!(session_creates(&seen), 2, "installed once: {seen:?}");
        assert_eq!(session.control.lock().generation, 2);
        assert!(session.recovery.lock().pending.is_none());
        assert_eq!(session.destination(), dest_b64());
        finish_bridge_after(&mut fake, "pending root resumed")?;
        Ok(())
    }

    #[test]
    fn pending_root_outlives_short_callers_and_installs_once()
    -> Result<(), Box<dyn std::error::Error>> {
        for verb in [Verb::Connect, Verb::Accept] {
            pending_root_resumes_across_short_callers(verb, "SESSION CREATE", &RootPhase::Create)?;
        }
        Ok(())
    }

    #[test]
    fn caller_deadline_during_hello_keeps_the_connected_exchange()
    -> Result<(), Box<dyn std::error::Error>> {
        for verb in [Verb::Connect, Verb::Accept] {
            pending_root_resumes_across_short_callers(verb, "HELLO", &RootPhase::Hello)?;
        }
        Ok(())
    }

    fn spent_root_is_discarded_and_the_next_caller_starts_fresh(
        verb: Verb,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let gate = new_gate();
        let (mut fake, mut session, mut seen) =
            session_with_held_recovery("SESSION CREATE", &gate)?;
        session.timeout = HELD_BUDGET;
        let Err(paused) = verb.call(&session, HELD_BUDGET) else {
            return Err("a caller behind a held reply must time out".into());
        };
        assert!(
            paused.to_string().contains("before this caller's deadline"),
            "the caller's own deadline paused it: {paused}"
        );
        // The owner's readiness deadline passes while no caller is inside.
        {
            let mut recovery = session.recovery.lock();
            let Some(pending) = recovery.pending.as_mut() else {
                return Err("the paused root must still be pending".into());
            };
            pending.deadline = Instant::now();
        }
        session.timeout = LIVENESS;
        let Err(spent) = verb.call(&session, LIVENESS) else {
            return Err("a spent root must not install".into());
        };
        assert_eq!(spent.kind(), io::ErrorKind::TimedOut, "got {spent:?}");
        assert!(
            spent.to_string().contains("readiness budget expired"),
            "the root deadline, not the caller's, ended it: {spent}"
        );
        assert!(session.recovery.lock().pending.is_none());
        assert_eq!(session.control.lock().generation, 1);
        // The bridge saw the spent root's socket close before any new
        // `SESSION CREATE` could be sent for the same id.
        fake.root_closed.recv_timeout(LIVENESS)?;
        seen.extend(fake.commands.try_iter());
        assert_eq!(session_creates(&seen), 2, "{seen:?}");

        let mut stream = step("spent root fresh call", verb.call(&session, LIVENESS))?;
        step("spent root echo", finish_stream_exchange(&mut stream))?;
        drop(stream);
        seen.extend(fake.commands.try_iter());
        assert_eq!(session_creates(&seen), 3, "{seen:?}");
        assert_eq!(session.control.lock().generation, 2);
        finish_bridge_after(&mut fake, "spent root")?;
        Ok(())
    }

    #[test]
    fn root_deadline_discards_the_pending_root_without_extending_any_caller()
    -> Result<(), Box<dyn std::error::Error>> {
        for verb in [Verb::Connect, Verb::Accept] {
            spent_root_is_discarded_and_the_next_caller_starts_fresh(verb)?;
        }
        Ok(())
    }

    fn close_wakes_a_caller_blocked_on_a_held_root_reply(
        verb: Verb,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let gate = new_gate();
        let (mut fake, session, mut seen) = session_with_held_recovery("SESSION CREATE", &gate)?;
        let outcome = std::thread::scope(
            |scope| -> Result<io::Result<()>, Box<dyn std::error::Error>> {
                let session = &session;
                let (reported_tx, reported_rx) = mpsc::channel();
                scope.spawn(move || {
                    let _ = reported_tx.send(verb.call(session, LIVENESS).map(|_stream| ()));
                });
                // The caller is inside the recovery, blocked on the held reply.
                wait_for_command(&fake.commands, &mut seen, "SESSION CREATE")?;
                let (closed_tx, closed_rx) = mpsc::channel();
                scope.spawn(move || {
                    session.close();
                    let _ = closed_tx.send(());
                });
                closed_rx.recv_timeout(LIVENESS)?;
                Ok(reported_rx.recv_timeout(LIVENESS)?)
            },
        )?;
        let Err(error) = outcome else {
            return Err("close must fail the caller blocked on the held reply".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::NotConnected, "got {error:?}");
        // The bridge saw the root socket close, so it no longer owns the id.
        fake.root_closed.recv_timeout(LIVENESS)?;
        assert!(session.recovery.lock().pending.is_none());
        assert!(session.control.lock().conn.is_none());
        assert_eq!(
            session.control.lock().generation,
            1,
            "nothing is installed after close"
        );
        let Err(refused) = verb.call(&session, LIVENESS) else {
            return Err("a closed session must never dial".into());
        };
        assert_eq!(refused.kind(), io::ErrorKind::NotConnected);
        seen.extend(fake.commands.try_iter());
        assert_eq!(session_creates(&seen), 2, "{seen:?}");
        assert!(
            seen.iter().all(|command| !command.starts_with("STREAM")),
            "no stream request may follow the close: {seen:?}"
        );
        finish_bridge_after(&mut fake, "close during a held root reply")?;
        Ok(())
    }

    #[test]
    fn close_during_a_held_root_reply_wakes_the_caller_and_installs_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        for verb in [Verb::Connect, Verb::Accept] {
            close_wakes_a_caller_blocked_on_a_held_root_reply(verb)?;
        }
        Ok(())
    }

    #[test]
    fn close_drains_a_paused_pending_root() -> Result<(), Box<dyn std::error::Error>> {
        let gate = new_gate();
        let (mut fake, mut session, _seen) = session_with_held_recovery("SESSION CREATE", &gate)?;
        session.timeout = HELD_BUDGET;
        let Err(error) = Verb::Accept.call(&session, HELD_BUDGET) else {
            return Err("a caller behind a held reply must time out".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "got {error:?}");
        assert!(pending_phase_is(&session, &RootPhase::Create));
        session.close();
        assert!(session.recovery.lock().pending.is_none());
        fake.root_closed.recv_timeout(LIVENESS)?;
        let Err(refused) = Verb::Connect.call(&session, LIVENESS) else {
            return Err("a closed session must never dial".into());
        };
        assert_eq!(refused.kind(), io::ErrorKind::NotConnected);
        finish_bridge_after(&mut fake, "close of a paused root")?;
        Ok(())
    }

    /// RAII gate holding `session.wake` mutex to order recovery connect before
    /// wake registration. Drops the guard and closes the session on failure
    /// before any scoped thread joins.
    struct WakeGate<'a> {
        guard: Option<MutexGuard<'a, Option<TcpStream>>>,
        session: &'a SamSession,
        bridge_addr: SocketAddr,
    }

    impl<'a> WakeGate<'a> {
        fn new(session: &'a SamSession, bridge_addr: SocketAddr) -> Self {
            Self {
                guard: Some(session.wake.lock()),
                session,
                bridge_addr,
            }
        }

        fn release(&mut self) {
            drop(self.guard.take());
        }
    }

    impl Drop for WakeGate<'_> {
        fn drop(&mut self) {
            self.release();
            if !self.session.closed.load(Ordering::Acquire) {
                self.session.close();
            }
            let _ = TcpStream::connect_timeout(&self.bridge_addr, Duration::from_millis(100));
        }
    }

    /// Local recovery bridge listener and its loopback address.
    struct RecoveryBridge {
        listener: TcpListener,
        addr: SocketAddr,
    }

    impl RecoveryBridge {
        fn bind() -> io::Result<Self> {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let addr = listener.local_addr()?;
            Ok(Self { listener, addr })
        }

        fn assert_clean_eof(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
            stream.set_read_timeout(Some(Duration::from_millis(500)))?;
            let mut received = Vec::new();
            let bytes_read = stream.read_to_end(&mut received)?;
            assert_eq!(
                bytes_read, 0,
                "expected EOF with no HELLO, got {bytes_read} bytes: {received:?}"
            );
            assert!(
                received.is_empty(),
                "expected no HELLO payload, got: {received:?}"
            );
            Ok(())
        }
    }

    /// Fixture session established with an initial root that is retired before recovery.
    struct RetiredRootSession {
        fake: FakeSam,
        session: SamSession,
    }

    impl RetiredRootSession {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let fake = fake_sam(session_script())?;
            let session = step(
                "close before wake establish",
                SamSession::establish(fake.addr, &priv_b64(), LIVENESS),
            )?;
            step(
                "close before wake retire root",
                session.retire_root(1, Instant::now() + LIVENESS),
            )?;
            assert!(
                session.control.lock().conn.is_none(),
                "root connection must be retired"
            );
            assert_eq!(session.control.lock().generation, 1);
            Ok(Self { fake, session })
        }

        fn assert_quiescent(&self) {
            assert!(
                self.session.recovery.lock().pending.is_none(),
                "no pending root may remain"
            );
            assert!(
                self.session.control.lock().conn.is_none(),
                "no installed root may remain"
            );
            assert_eq!(
                self.session.control.lock().generation,
                1,
                "root generation must not advance"
            );
            assert!(
                self.session.wake.lock().is_none(),
                "no wake socket may remain registered"
            );
            assert!(
                self.session.closed.load(Ordering::Acquire),
                "session must remain closed"
            );
        }

        fn finish(mut self, step_name: &str) -> Result<(), Box<dyn std::error::Error>> {
            finish_bridge_after(&mut self.fake, step_name)
        }
    }

    fn orchestrate_close_before_wake(
        session: &SamSession,
        bridge: &RecoveryBridge,
        verb: Verb,
    ) -> Result<(io::Result<()>, TcpStream), Box<dyn std::error::Error>> {
        std::thread::scope(
            |scope| -> Result<(io::Result<()>, TcpStream), Box<dyn std::error::Error>> {
                let (accepted_tx, accepted_rx) = mpsc::channel();
                scope.spawn(move || {
                    let _ = accepted_tx.send(bridge.listener.accept().map(|(stream, _)| stream));
                });

                let (reported_tx, reported_rx) = mpsc::channel();
                let (closed_tx, closed_rx) = mpsc::channel();

                let (rep, stream) = {
                    let mut gate = WakeGate::new(session, bridge.addr);

                    scope.spawn(move || {
                        let res = verb.call(session, LIVENESS).map(|_stream| ());
                        let _ = reported_tx.send(res);
                    });

                    let accepted = match accepted_rx.recv_timeout(LIVENESS) {
                        Ok(Ok(stream)) => Ok(stream),
                        Ok(Err(err)) => Err(io::Error::new(
                            err.kind(),
                            format!("recovery listener accept failed: {err}"),
                        )),
                        Err(err) => Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("recovery connect not accepted: {err}"),
                        )),
                    };

                    let closed_published = if accepted.is_ok() {
                        scope.spawn(move || {
                            session.close();
                            let _ = closed_tx.send(());
                        });

                        let give_up = Instant::now() + LIVENESS;
                        let mut published = false;
                        while Instant::now() < give_up {
                            if session.closed.load(Ordering::Acquire) {
                                published = true;
                                break;
                            }
                            std::thread::yield_now();
                        }
                        published
                    } else {
                        false
                    };

                    gate.release();

                    let stream = accepted?;
                    if !closed_published {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "terminal closed was not published before timeout",
                        )
                        .into());
                    }

                    let rep = reported_rx.recv_timeout(LIVENESS).map_err(|err| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("caller thread did not exit: {err}"),
                        )
                    })?;
                    closed_rx.recv_timeout(LIVENESS).map_err(|err| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("close thread did not exit: {err}"),
                        )
                    })?;

                    (rep, stream)
                };

                Ok((rep, stream))
            },
        )
    }

    fn close_between_root_connect_and_wake_registration(
        verb: Verb,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = RetiredRootSession::new()?;
        let bridge = RecoveryBridge::bind()?;
        fixture.session.sam = bridge.addr;

        let (reported, accepted_stream) =
            orchestrate_close_before_wake(&fixture.session, &bridge, verb)?;

        let Err(error) = reported else {
            return Err("recovery caller must fail when session is closed".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::NotConnected, "got {error:?}");

        RecoveryBridge::assert_clean_eof(accepted_stream)?;
        fixture.assert_quiescent();
        fixture.finish("close before wake registration")?;
        Ok(())
    }

    #[test]
    fn close_between_root_connect_and_wake_registration_installs_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        for verb in [Verb::Connect, Verb::Accept] {
            close_between_root_connect_and_wake_registration(verb)?;
        }
        Ok(())
    }

    /// A bridge that answers `HELLO` in two pieces and then serves the root
    /// exchange, recording each command line it receives.
    fn split_hello_bridge(
        listener: TcpListener,
        head: &'static str,
        release: mpsc::Receiver<()>,
        lines: mpsc::Sender<String>,
    ) -> std::thread::JoinHandle<io::Result<()>> {
        let replies = [
            "SESSION STATUS RESULT=OK\n".to_owned(),
            format!("NAMING REPLY RESULT=OK NAME=ME VALUE={}\n", dest_b64()),
        ];
        std::thread::spawn(move || {
            let (stream, _) = listener.accept()?;
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut writer = stream;
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let _ = lines.send(line.trim_end().to_owned());
            writer.write_all(head.as_bytes())?;
            release.recv_timeout(LIVENESS).map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "the reply tail was never released")
            })?;
            writer.write_all(b"SION=3.3\n")?;
            for reply in replies {
                line.clear();
                reader.read_line(&mut line)?;
                let _ = lines.send(line.trim_end().to_owned());
                writer.write_all(reply.as_bytes())?;
            }
            Ok(())
        })
    }

    #[test]
    fn paused_exchange_keeps_the_partial_reply_and_resumes_the_same_command()
    -> Result<(), Box<dyn std::error::Error>> {
        const HEAD: &str = "HELLO REPLY RESULT=OK VER";
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (release_tx, release_rx) = mpsc::channel();
        let (lines_tx, lines_rx) = mpsc::channel();
        let bridge = split_hello_bridge(listener, HEAD, release_rx, lines_tx);
        let private = priv_b64();
        let id = session_id_for(&private);
        let root_deadline = Instant::now() + LIVENESS;
        let mut root = PendingRoot::connect(addr, root_deadline, root_deadline, &|| false)
            .map_err(|stop| stop.into_io(startup_cancelled))?;
        // Short callers pause the exchange until the head of the reply is in.
        let give_up = Instant::now() + LIVENESS;
        while root.line.len() < HEAD.len() {
            match root.advance(
                &id,
                &private,
                Instant::now() + Duration::from_millis(50),
                &|| false,
            ) {
                Err(Stop::Paused) => {}
                Err(stop) => return Err(stop.into_io(startup_cancelled).into()),
                Ok(()) => return Err("the exchange finished before its tail arrived".into()),
            }
            if Instant::now() >= give_up {
                return Err("the reply head was never consumed".into());
            }
        }
        assert_eq!(root.line, HEAD.as_bytes());
        assert!(matches!(root.phase, RootPhase::Hello));
        assert_eq!(
            root.sent,
            "HELLO VERSION MIN=3.1 MAX=3.3\n".len(),
            "the whole command was accepted once"
        );
        release_tx.send(())?;
        root.advance(&id, &private, Instant::now() + LIVENESS, &|| false)
            .map_err(|stop| stop.into_io(startup_cancelled))?;
        assert!(matches!(
            &root.phase,
            RootPhase::Ready(destination) if *destination == dest_b64()
        ));
        match bridge.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err.into()),
            Err(payload) => std::panic::resume_unwind(payload),
        }
        let lines: Vec<String> = lines_rx.try_iter().collect();
        assert_eq!(lines.len(), 3, "one line per command: {lines:?}");
        assert_eq!(lines[0], "HELLO VERSION MIN=3.1 MAX=3.3");
        assert!(lines[1].starts_with(&format!("SESSION CREATE STYLE=STREAM ID={id} DESTINATION=")));
        assert_eq!(lines[2], "NAMING LOOKUP NAME=ME");
        Ok(())
    }

    #[test]
    fn a_recorded_write_offset_resumes_the_same_command_mid_line()
    -> Result<(), Box<dyn std::error::Error>> {
        const COMMAND: &str = "HELLO VERSION MIN=3.1 MAX=3.3\n";
        const ACCEPTED: usize = 10;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (received_tx, received_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let bridge = std::thread::spawn(move || -> io::Result<()> {
            let (stream, _) = listener.accept()?;
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut writer = stream;
            let mut received = Vec::new();
            reader.read_until(b'\n', &mut received)?;
            let _ = received_tx.send(received);
            writer.write_all(HELLO_OK.as_bytes())?;
            let _ = release_rx.recv_timeout(LIVENESS);
            Ok(())
        });
        let private = priv_b64();
        let id = session_id_for(&private);
        let root_deadline = Instant::now() + LIVENESS;
        let mut root = PendingRoot::connect(addr, root_deadline, root_deadline, &|| false)
            .map_err(|stop| stop.into_io(startup_cancelled))?;
        // An earlier caller's pause left the first ten bytes accepted.
        root.sent = ACCEPTED;
        let give_up = Instant::now() + LIVENESS;
        while !matches!(root.phase, RootPhase::Create) {
            match root.advance(
                &id,
                &private,
                Instant::now() + Duration::from_millis(50),
                &|| false,
            ) {
                Err(Stop::Paused) => {}
                Err(stop) => return Err(stop.into_io(startup_cancelled).into()),
                Ok(()) => return Err("the exchange cannot finish without a bridge".into()),
            }
            if Instant::now() >= give_up {
                return Err("the HELLO reply was never consumed".into());
            }
        }
        let received = received_rx.recv_timeout(LIVENESS)?;
        assert_eq!(
            received,
            COMMAND.as_bytes()[ACCEPTED..].to_vec(),
            "the resumed write sends only what was not yet accepted"
        );
        release_tx.send(())?;
        match bridge.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err.into()),
            Err(payload) => std::panic::resume_unwind(payload),
        }
        Ok(())
    }

    #[test]
    fn startup_generates_an_ephemeral_key_once_across_session_retries()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fake = fake_sam_with(
            session_script(),
            FakeSamOptions {
                fail_creates: 1,
                ..FakeSamOptions::default()
            },
        )?;
        let session = step(
            "startup retry",
            SamSession::establish_startup(fake.addr, None, Instant::now() + LIVENESS, &|| false),
        )?;
        let commands: Vec<String> = fake.commands.try_iter().collect();
        assert_eq!(
            commands
                .iter()
                .filter(|command| command.starts_with("DEST GENERATE"))
                .count(),
            1,
            "one identity for every attempt: {commands:?}"
        );
        let creates: Vec<&String> = commands
            .iter()
            .filter(|command| command.starts_with("SESSION CREATE"))
            .collect();
        assert_eq!(creates.len(), 2, "{commands:?}");
        assert_eq!(creates[0], creates[1], "a retry reuses the identity");
        assert_eq!(session.id(), session_id_for(&priv_b64()));
        assert_eq!(session.destination(), dest_b64());
        finish_bridge_after(&mut fake, "startup retry")?;
        Ok(())
    }

    #[test]
    fn startup_cancellation_during_root_readiness_publishes_no_session()
    -> Result<(), Box<dyn std::error::Error>> {
        let gate = new_gate();
        let mut fake = fake_sam_with(
            session_script(),
            FakeSamOptions {
                held_reply: Some(HeldReply::new("SESSION CREATE", 0, 0, &gate)),
                ..FakeSamOptions::default()
            },
        )?;
        let cancelled = AtomicBool::new(false);
        let mut seen: Vec<String> = Vec::new();
        let outcome = std::thread::scope(
            |scope| -> Result<io::Result<SamSession>, Box<dyn std::error::Error>> {
                let (reported_tx, reported_rx) = mpsc::channel();
                let (addr, flag) = (fake.addr, &cancelled);
                let deadline = Instant::now() + LIVENESS;
                scope.spawn(move || {
                    let _ = reported_tx.send(SamSession::establish_startup(
                        addr,
                        None,
                        deadline,
                        &|| flag.load(Ordering::Acquire),
                    ));
                });
                wait_for_command(&fake.commands, &mut seen, "SESSION CREATE")?;
                cancelled.store(true, Ordering::Release);
                Ok(reported_rx.recv_timeout(LIVENESS)?)
            },
        )?;
        let Err(error) = outcome else {
            return Err("a cancelled startup must not return a session".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::Interrupted, "got {error:?}");
        // The bridge saw the cancelled root's socket close.
        fake.root_closed.recv_timeout(LIVENESS)?;
        seen.extend(fake.commands.try_iter());
        assert_eq!(session_creates(&seen), 1, "no retry after cancel: {seen:?}");
        finish_bridge_after(&mut fake, "cancelled startup")?;
        Ok(())
    }

    #[test]
    fn startup_cancellation_after_the_final_reply_publishes_no_session()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fake = fake_sam(session_script())?;
        // Cancellation that first becomes true once the bridge has been sent
        // the last command: the establishment must still publish nothing.
        let lookup_seen = std::cell::Cell::new(false);
        let creates = std::cell::Cell::new(0usize);
        let cancelled = || {
            while let Ok(line) = fake.commands.try_recv() {
                creates.set(creates.get() + usize::from(line.starts_with("SESSION CREATE")));
                if line.starts_with("NAMING LOOKUP NAME=ME") {
                    lookup_seen.set(true);
                }
            }
            lookup_seen.get()
        };
        let Err(error) =
            SamSession::establish_startup(fake.addr, None, Instant::now() + LIVENESS, &cancelled)
        else {
            return Err("a cancelled startup must not return a session".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::Interrupted, "got {error:?}");
        assert!(lookup_seen.get());
        assert_eq!(creates.get(), 1, "no retry after cancel");
        finish_bridge_after(&mut fake, "startup cancelled at publication")?;
        Ok(())
    }

    #[test]
    fn startup_owner_deadline_bounds_a_root_that_never_becomes_ready()
    -> Result<(), Box<dyn std::error::Error>> {
        let gate = new_gate();
        let mut fake = fake_sam_with(
            session_script(),
            FakeSamOptions {
                held_reply: Some(HeldReply::new("SESSION CREATE", 0, 0, &gate)),
                ..FakeSamOptions::default()
            },
        )?;
        let deadline = Instant::now() + Duration::from_millis(1500);
        let Err(error) = SamSession::establish_startup(fake.addr, None, deadline, &|| false) else {
            return Err("a root that never becomes ready must not establish".into());
        };
        let returned = Instant::now();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "got {error:?}");
        assert!(
            error.to_string().contains("readiness budget expired"),
            "{error}"
        );
        assert!(returned >= deadline, "the owner deadline was waited out");
        assert!(
            returned < deadline + LIVENESS,
            "nothing extended the owner deadline"
        );
        fake.root_closed.recv_timeout(LIVENESS)?;
        let commands: Vec<String> = fake.commands.try_iter().collect();
        assert_eq!(session_creates(&commands), 1, "{commands:?}");
        finish_bridge_after(&mut fake, "owner deadline")?;
        Ok(())
    }

    #[test]
    fn the_reached_flag_tells_an_unreachable_bridge_from_a_slow_one()
    -> Result<(), Box<dyn std::error::Error>> {
        // Nothing listens on port 1: the bridge never accepts a connection.
        let refused: SocketAddr = "127.0.0.1:1".parse()?;
        let reached = Cell::new(false);
        let deadline = Instant::now() + LIVENESS;
        let Err(_error) = SamSession::establish_within(
            refused,
            &priv_b64(),
            EXCHANGE_BUDGET,
            deadline,
            deadline,
            &|| false,
            &reached,
        ) else {
            return Err("a refused bridge must not establish".into());
        };
        assert!(!reached.get(), "a refused connect never reached the bridge");

        let mut fake = fake_sam(session_script())?;
        let session = SamSession::establish_within(
            fake.addr,
            &priv_b64(),
            EXCHANGE_BUDGET,
            deadline,
            deadline,
            &|| false,
            &reached,
        )?;
        assert!(reached.get(), "a connected bridge is reached");
        drop(session);
        finish_bridge_after(&mut fake, "reached flag")?;
        Ok(())
    }

    #[test]
    fn startup_connect_is_clipped_to_the_unreachable_window_until_the_bridge_connects()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fake = fake_sam(session_script())?;
        let deadline = Instant::now() + LIVENESS;
        // The window has already passed when the first attempt starts, while
        // a live bridge listens and the owner deadline is far away.
        let unreachable_after = Instant::now();
        let reached = Cell::new(false);

        // A bridge that never accepted a connection gets no connect past the
        // window: the attempt ends `TimedOut` before touching the listener.
        let Err(error) = SamSession::retry_establish(
            fake.addr,
            &priv_b64(),
            deadline,
            unreachable_after,
            &|| false,
            &reached,
        ) else {
            return Err("a connect past the unreachable window must not establish".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "got {error:?}");
        assert!(error.to_string().contains("connect deadline"), "{error}");
        assert!(!reached.get(), "no connection was accepted");
        let commands: Vec<String> = fake.commands.try_iter().collect();
        assert!(
            commands.is_empty(),
            "the bridge was never contacted: {commands:?}"
        );

        // After one accepted connection the same expired window no longer
        // applies: the connect and the whole root keep the owner's budget.
        reached.set(true);
        let session = SamSession::retry_establish(
            fake.addr,
            &priv_b64(),
            deadline,
            unreachable_after,
            &|| false,
            &reached,
        )?;
        let commands: Vec<String> = fake.commands.try_iter().collect();
        assert_eq!(session_creates(&commands), 1, "{commands:?}");
        drop(session);
        finish_bridge_after(&mut fake, "unreachable window connect")?;
        Ok(())
    }

    #[test]
    fn a_bridge_that_never_accepted_is_abandoned_at_the_window_with_its_refusal()
    -> Result<(), Box<dyn std::error::Error>> {
        // Nothing listens on port 1: every connect is refused at once. The
        // pause after the first refusal (at least `PAUSE_STEP_MS`) outlasts
        // the 100 ms window, so the limit is checked again as the pause ends
        // and the refusal itself is reported, without a second connect.
        let refused: SocketAddr = "127.0.0.1:1".parse()?;
        let started = Instant::now();
        let unreachable_after = started + Duration::from_millis(100);
        let deadline = started + LIVENESS;
        let reached = Cell::new(false);
        let Err(error) = SamSession::retry_establish(
            refused,
            &priv_b64(),
            deadline,
            unreachable_after,
            &|| false,
            &reached,
        ) else {
            return Err("a refused bridge must not establish".into());
        };
        let returned = Instant::now();
        assert_eq!(
            error.kind(),
            io::ErrorKind::ConnectionRefused,
            "got {error:?}"
        );
        assert!(!reached.get(), "a refused connect never reached the bridge");
        assert!(
            returned >= unreachable_after,
            "given up before the window ended"
        );
        assert!(returned < deadline, "the owner deadline was waited out");
        Ok(())
    }

    #[test]
    fn a_bridge_that_connected_is_not_abandoned_when_a_later_connect_is_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        // The bridge accepts the first connection, answers `HELLO`, then
        // closes its listener *before* it answers `SESSION CREATE` with the
        // retryable `I2P_ERROR`. The refusal therefore precedes the retry by
        // construction: the client only learns of the failure after the port
        // stopped accepting.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (create_tx, create_rx) = mpsc::channel();
        let bridge = std::thread::spawn(move || -> io::Result<()> {
            let (stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(LIVENESS))?;
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut writer = stream;
            let mut line = String::new();
            reader.read_line(&mut line)?;
            writer.write_all(HELLO_OK.as_bytes())?;
            line.clear();
            reader.read_line(&mut line)?;
            let _ = create_tx.send(line.trim_end().to_owned());
            drop(listener);
            writer.write_all(b"SESSION STATUS RESULT=I2P_ERROR\n")?;
            Ok(())
        });
        // The window ends 100 ms in; the first retry pause (at least 250 ms)
        // ends after it, and every later connect is refused.
        let started = Instant::now();
        let unreachable_after = started + Duration::from_millis(100);
        let deadline = started + Duration::from_millis(1000);
        let reached = Cell::new(false);
        let outcome = SamSession::retry_establish(
            addr,
            &priv_b64(),
            deadline,
            unreachable_after,
            &|| false,
            &reached,
        );
        let returned = Instant::now();
        match bridge.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err.into()),
            Err(payload) => std::panic::resume_unwind(payload),
        }
        let create = create_rx.try_recv()?;
        assert!(create.starts_with("SESSION CREATE"), "{create}");
        assert!(outcome.is_err(), "a closed bridge must not establish");
        assert!(reached.get(), "the first attempt reached the bridge");
        assert!(
            returned >= deadline,
            "a bridge that connected once was given up on as unreachable"
        );
        Ok(())
    }

    #[test]
    fn retry_gives_up_on_the_first_failure_only_when_told_to()
    -> Result<(), Box<dyn std::error::Error>> {
        let refused = || io::Error::from(io::ErrorKind::ConnectionRefused);
        let attempts = Cell::new(0u32);
        let far = Instant::now() + LIVENESS;

        // A give-up verdict ends the loop at the first failure, unpaused.
        let Err(error) = retry_until(
            far,
            &|| false,
            || true,
            |_left| {
                attempts.set(attempts.get() + 1);
                Err::<(), _>(refused())
            },
        ) else {
            return Err("a give-up verdict must end the retry".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(attempts.get(), 1);

        // Without it, a transient failure retries and the next attempt wins.
        attempts.set(0);
        let value = retry_until(
            far,
            &|| false,
            || false,
            |_left| {
                attempts.set(attempts.get() + 1);
                if attempts.get() < 2 {
                    Err(refused())
                } else {
                    Ok(7u8)
                }
            },
        )?;
        assert_eq!((value, attempts.get()), (7, 2));
        Ok(())
    }

    #[test]
    fn startup_pause_is_cut_by_cancellation_and_clipped_to_the_owner_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        // Cancellation is polled while pausing: the third poll fires, long
        // before the grown pause (at least 2.5 s) could end by itself.
        let polls = std::cell::Cell::new(0u32);
        let cancelled = || {
            polls.set(polls.get() + 1);
            polls.get() >= 3
        };
        let Err(error) = startup_pause(PAUSE_STEPS_MAX, Instant::now() + LIVENESS, &cancelled)
        else {
            return Err("a cancelled pause must report the cancellation".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(polls.get(), 3);

        // The pause is clipped to the owner deadline instead of outlasting it.
        let started = Instant::now();
        let deadline = started + Duration::from_millis(150);
        startup_pause(PAUSE_STEPS_MAX, deadline, &|| false)?;
        assert!(Instant::now() >= deadline);
        assert!(
            started.elapsed() < Duration::from_millis(PAUSE_STEP_MS * PAUSE_STEPS_MAX),
            "the full grown pause would have outlasted the deadline"
        );
        Ok(())
    }

    #[test]
    fn stream_deadline_bounds_the_whole_exchange_and_yields_no_stream()
    -> Result<(), Box<dyn std::error::Error>> {
        // The bridge is healthy for establishment, then stalls past the
        // session timeout on `STREAM CONNECT`. The dial must fail inside the
        // absolute deadline and must never hand back a stream.
        let mut fake = fake_sam_with(
            session_script(),
            FakeSamOptions {
                stall_stream_connect: Some(Duration::from_millis(600)),
                ..FakeSamOptions::default()
            },
        )?;
        let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_millis(200))?;
        let started = Instant::now();
        let Err(error) = session.connect(destination_hash(&dest_bytes()), 8333) else {
            panic!("a stalled STREAM CONNECT must fail inside the deadline");
        };
        let elapsed = started.elapsed();
        assert!(
            matches!(&error, crate::endpoint::DialFailure::Transport(_)),
            "a local bridge stall is transport evidence, never peer-unreachable: {error:?}"
        );
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ),
            "the stall must end on the exchange deadline, got {error:?}"
        );
        assert!(
            !error.counts_as_peer_failure(),
            "a local bridge stall is never peer evidence"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "the whole exchange must stay under the 200ms deadline, took {elapsed:?}"
        );
        fake.finish()?;
        Ok(())
    }

    #[test]
    fn crlf_reply_is_parsed_without_the_carriage_return() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let bridge = std::thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).is_ok_and(|read| read == 1) {
                if byte[0] == b'\n' {
                    break;
                }
            }
            stream.write_all(b"STREAM STATUS RESULT=OK\r\n")?;
            let _ = stream.shutdown(std::net::Shutdown::Both);
            Ok(())
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut conn = SamConn::connect_with_deadline(addr, deadline)?;
        let reply = conn.command(
            "STREAM CONNECT ID=btcrs-deadbeef DESTINATION=x TO_PORT=8333",
            deadline,
        )?;
        match bridge.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err.into()),
            Err(payload) => std::panic::resume_unwind(payload),
        }
        assert_eq!(reply, "STREAM STATUS RESULT=OK");
        assert!(
            !reply.contains('\r'),
            "the carriage return is not part of the reply: {reply:?}"
        );
        Ok(())
    }

    #[test]
    fn unterminated_status_line_is_never_accepted_as_a_reply()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let bridge = std::thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).is_ok_and(|read| read == 1) {
                if byte[0] == b'\n' {
                    break;
                }
            }
            stream.write_all(b"STREAM STATUS RESULT=OK")?;
            let _ = stream.shutdown(std::net::Shutdown::Both);
            Ok(())
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut conn = SamConn::connect_with_deadline(addr, deadline)?;
        let Err(error) = conn.command(
            "STREAM CONNECT ID=btcrs-deadbeef DESTINATION=x TO_PORT=8333",
            deadline,
        ) else {
            panic!("an unterminated reply must not decode");
        };
        match bridge.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err.into()),
            Err(payload) => std::panic::resume_unwind(payload),
        }
        assert_eq!(
            error.kind(),
            io::ErrorKind::UnexpectedEof,
            "EOF before the newline is truncation, not a reply: {error:?}"
        );
        Ok(())
    }

    #[test]
    fn unterminated_stream_connect_reply_fails_the_dial_without_promoting_a_stream()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fake = fake_sam_with(
            session_script(),
            FakeSamOptions {
                truncate_stream_reply: true,
                ..FakeSamOptions::default()
            },
        )?;
        let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
        let Err(error) = session.connect(destination_hash(&dest_bytes()), 8333) else {
            panic!("an unterminated STREAM STATUS must fail the dial");
        };
        assert!(
            matches!(&error, crate::endpoint::DialFailure::Transport(_)),
            "truncation is a local transport failure: {error:?}"
        );
        assert_eq!(
            error.kind(),
            io::ErrorKind::UnexpectedEof,
            "a closed, unterminated status line is EOF: {error:?}"
        );
        assert!(
            !error.counts_as_peer_failure(),
            "a truncated bridge exchange is never peer evidence"
        );
        fake.finish()?;
        Ok(())
    }

    #[test]
    fn slow_trickle_handshake_exceeds_absolute_deadline() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let bridge = std::thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut byte = [0u8; 1];
            while stream.read_exact(&mut byte).is_ok() {
                if byte[0] == b'\n' {
                    break;
                }
            }
            // Trickle the reply one byte at a time, each gap well inside the
            // 100ms exchange budget. A per-line timeout would let the whole
            // reply through; only a per-byte absolute deadline bounds it.
            let trickle = HELLO_OK.as_bytes();
            for byte in trickle {
                std::thread::sleep(Duration::from_millis(30));
                if stream.write_all(&[*byte]).is_err() {
                    return Ok(());
                }
            }
            Ok(())
        });
        let started = Instant::now();
        let Err(error) = SamSession::establish(addr, &priv_b64(), Duration::from_millis(100))
        else {
            panic!("a trickling bridge must not outlive the deadline");
        };
        let elapsed = started.elapsed();
        match bridge.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err.into()),
            Err(payload) => std::panic::resume_unwind(payload),
        }
        // Socket timeout expiry reports WouldBlock on Unix and TimedOut on
        // platforms that synthesize it; both are the bounded-exchange
        // outcome. Anything else would be a different failure.
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ),
            "trickling exchange must end on its deadline, got {error:?}"
        );
        assert!(
            elapsed < Duration::from_millis(900),
            "whole exchange must stay bounded by the 100ms deadline, took {elapsed:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(50),
            "the deadline must actually be waited out, took {elapsed:?}"
        );
        Ok(())
    }
}
