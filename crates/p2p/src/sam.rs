//! I2P SAM v3 client (pinned IVNP bridge) for typed I2P transports.

use parking_lot::{Mutex, MutexGuard};
use std::cell::Cell;
use std::fmt::Write as _;
#[cfg(test)]
use std::fs::OpenOptions;
#[cfg(test)]
use std::io::BufReader;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
#[cfg(test)]
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(test)]
use bitcoin::secp256k1::rand::Rng;
use bitcoin::secp256k1::rand::{RngCore, thread_rng};
use bitcoin_rs_primitives::endpoint::base32_encode;
use sha2::{Digest, Sha256};

const READINESS_WAIT: Duration = Duration::from_secs(120);

pub(crate) const EXCHANGE_BUDGET: Duration = Duration::from_secs(5);

pub(crate) const ROOT_READINESS_BUDGET: Duration =
    READINESS_WAIT.saturating_add(Duration::from_secs(3 * EXCHANGE_BUDGET.as_secs()));

#[cfg(test)]
const UNREACHABLE_WINDOW: Duration = Duration::from_secs(20);

const CANCEL_POLL: Duration = Duration::from_millis(100);

#[cfg(test)]
const PAUSE_STEP_MS: u64 = 250;

#[cfg(test)]
const PAUSE_STEPS_MAX: u64 = 10;

fn remaining_timeout(deadline: Instant) -> io::Result<Duration> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(rem) if !rem.is_zero() => Ok(rem),
        _ => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "sam exchange deadline expired",
        )),
    }
}

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
        return None;
    }
    if padding > 0 && !(core.len() + padding).is_multiple_of(4) {
        return None;
    }
    if core.len() % 4 == 1 {
        return None;
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

fn session_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "sam session is closed")
}

#[cfg(test)]
static SESSION_SOCKETS: std::sync::Mutex<Vec<(SocketAddr, SocketAddr)>> =
    std::sync::Mutex::new(Vec::new());

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

    fn from_stream(stream: TcpStream) -> io::Result<Self> {
        #[cfg(test)]
        if let (Ok(local), Ok(bridge)) = (stream.local_addr(), stream.peer_addr()) {
            SESSION_SOCKETS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((local, bridge));
        }
        let _ = stream.set_nodelay(true);
        let writer = stream.try_clone()?;
        Ok(Self {
            reader: stream,
            writer,
        })
    }

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

    fn hello(&mut self, deadline: Instant) -> io::Result<()> {
        let reply = self.command("HELLO VERSION MIN=3.1 MAX=3.3", deadline)?;
        check_hello(&reply)
    }

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
        let _ = self.reader.set_nonblocking(false);
        alive
    }

    fn into_stream(self) -> TcpStream {
        let _ = self.writer.set_read_timeout(None);
        let _ = self.writer.set_write_timeout(None);
        let _ = self.reader.set_read_timeout(None);
        let _ = self.reader.set_write_timeout(None);
        self.writer
    }
}

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
        i += 1;

        if i < chars.len() && chars[i] == '"' {
            i += 1;
            let val_start = i;
            while i < chars.len() && chars[i] != '"' {
                i += 1;
            }
            if i >= chars.len() {
                return Err(invalid("malformed sam field: unterminated quoted value"));
            }
            let value: String = chars[val_start..i].iter().collect();
            i += 1;
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
        0 | 2 => payload_len == 0,
        1 | 4 => true,
        3 => payload_len == 40 || payload_len == 72,
        5 => {
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

#[must_use]
fn valid_destination(bytes: &[u8]) -> bool {
    destination_identity_len(bytes) == Some(bytes.len()) && bytes.len() >= 387
}

#[must_use]
pub(crate) fn destination_hash(destination: &[u8]) -> [u8; 32] {
    Sha256::digest(destination).into()
}

struct ControlState {
    conn: Option<SamConn>,
    generation: u64,
}

enum RootPhase {
    Hello,
    Create,
    Lookup,
    Ready(String),
}

impl RootPhase {
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

enum Stop {
    Paused,
    Expired,
    Cancelled,
    Failed(io::Error),
}

impl Stop {
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

fn startup_cancelled() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "i2p session startup was cancelled",
    )
}

fn slice_ended(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

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

struct PendingRoot {
    conn: SamConn,
    deadline: Instant,
    phase: RootPhase,
    sent: usize,
    line: Vec<u8>,
}

impl PendingRoot {
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

struct Recovery {
    pending: Option<PendingRoot>,
}

pub struct SamSession {
    sam: SocketAddr,
    id: String,
    destination: String,
    private_destination: String,
    control: Mutex<ControlState>,
    recovery: Mutex<Recovery>,
    wake: Mutex<Option<TcpStream>>,
    closed: AtomicBool,
    timeout: Duration,
    root_budget: Duration,
}

impl std::fmt::Debug for SamSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SamSession")
            .field("sam", &self.sam)
            .field("id", &self.id)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SamSession {
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
        let advanced = root.advance(&id, private_destination, root_deadline, cancelled);
        let PendingRoot { conn, phase, .. } = root;
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

    #[cfg(test)]
    pub(crate) fn establish_startup(
        sam: SocketAddr,
        key_path: Option<&Path>,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<Self> {
        let unreachable_after = Instant::now() + UNREACHABLE_WINDOW;
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

    #[cfg(test)]
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

    fn ensure_control(&self, deadline: Instant) -> io::Result<u64> {
        if self.closed.load(Ordering::Acquire) {
            return Err(session_closed());
        }
        if let Some(generation) = self.live_control_generation(deadline)? {
            return Ok(generation);
        }

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

    fn recover_root(&self, recovery: &mut Recovery, call_deadline: Instant) -> io::Result<u64> {
        let cancelled = || self.closed.load(Ordering::Acquire);
        let mut root = match recovery.pending.take() {
            Some(root) => root,
            None => PendingRoot::connect(
                self.sam,
                call_deadline,
                Instant::now() + self.root_budget,
                &cancelled,
            )
            .map_err(|stop| stop.into_io(session_closed))?,
        };
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
                Err(if self.closed.load(Ordering::Acquire) {
                    session_closed()
                } else {
                    stop.into_io(session_closed)
                })
            }
        }
    }

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

    fn live_control_generation(&self, deadline: Instant) -> io::Result<Option<u64>> {
        let mut state = lock_within(&self.control, deadline)?;
        let alive = state.conn.as_mut().is_some_and(SamConn::is_alive);
        Ok(alive.then_some(state.generation))
    }

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

    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn b32_name(&self) -> Option<String> {
        let bytes = i2p_base64_decode(&self.destination)?;
        Some(format!(
            "{}.b32.i2p",
            base32_encode(&destination_hash(&bytes))
        ))
    }

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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(all(test, unix))]
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

#[cfg(all(test, not(unix)))]
fn open_key_file(path: &Path) -> io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(test)]
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

#[cfg(test)]
struct TempCleanup<'a>(&'a Path);

#[cfg(test)]
impl Drop for TempCleanup<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0);
    }
}

#[cfg(test)]
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

    std::fs::hard_link(&temp_path, path)?;

    let _ = std::fs::remove_file(&temp_path);
    drop(cleanup);

    let dir = std::fs::File::open(parent)?;
    dir.sync_all()?;

    Ok(())
}

#[cfg(test)]
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
mod tests;
