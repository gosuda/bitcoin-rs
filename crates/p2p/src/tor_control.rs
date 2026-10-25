//! External Tor control-port client: SAFECOOKIE (or password)
//! authentication, `ADD_ONION`/`DEL_ONION` for one v3 hidden service.
//!
//! The onion private key blob is operator state: it is persisted by the
//! caller (mode `0600`, create-only) and never logged or printed here.
//! Control failures are transport errors; they never mark a peer.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use bitcoin::hashes::{Hash as _, HashEngine, hmac, sha256};
use bitcoin::secp256k1::rand::{RngCore, thread_rng};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REPLY_LINE: usize = 16_384;
const MAX_REPLY_LINES: usize = 1_024;
const MAX_REPLY_BYTES: usize = 256 * 1024;
/// Pause between retries while a non-blocking unix-socket connect reports a
/// full listener backlog. Every retry still charges the single caller
/// deadline.
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(5);
/// Smallest timeout handed to the OS. Sub-millisecond remainders round to an
/// invalid `timeval`, so the last fraction of a budget is spent as 1 ms.
const MIN_IO_TIMEOUT: Duration = Duration::from_millis(1);

/// Where the Tor control interface listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TorControlTarget {
    /// TCP control port (`host:port`).
    Tcp(SocketAddr),
    /// Unix control socket path.
    #[cfg(unix)]
    Unix(PathBuf),
}

impl TorControlTarget {
    /// Parse `--torcontrol`: a socket address, or a filesystem path for a
    /// unix control socket.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if let Ok(addr) = text.parse::<SocketAddr>() {
            return Some(Self::Tcp(addr));
        }
        #[cfg(unix)]
        {
            Some(Self::Unix(PathBuf::from(text)))
        }
        #[cfg(not(unix))]
        {
            None
        }
    }
}

enum ControlStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl ControlStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_read_timeout(timeout),
            #[cfg(unix)]
            Self::Unix(stream) => stream.set_read_timeout(timeout),
        }
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_write_timeout(timeout),
            #[cfg(unix)]
            Self::Unix(stream) => stream.set_write_timeout(timeout),
        }
    }
}

impl Read for ControlStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(buf),
        }
    }
}

impl Write for ControlStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush(),
        }
    }
}

fn deadline_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "tor control exchange deadline expired",
    )
}

fn remaining_timeout(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(deadline_error)
}

fn socket_timeout(deadline: Instant) -> io::Result<Duration> {
    Ok(remaining_timeout(deadline)?.max(MIN_IO_TIMEOUT))
}

#[cfg(unix)]
fn connect_unix(
    path: &std::path::Path,
    deadline: Instant,
) -> io::Result<std::os::unix::net::UnixStream> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketType};

    let address = SocketAddrUnix::new(path).map_err(io::Error::from)?;
    let fd = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)
        .map_err(io::Error::from)?;
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC).map_err(io::Error::from)?;
    rustix::io::ioctl_fionbio(&fd, true).map_err(io::Error::from)?;

    loop {
        remaining_timeout(deadline)?;
        match rustix::net::connect(&fd, &address) {
            Ok(()) => break,
            Err(errno) if errno == rustix::io::Errno::ISCONN => break,
            Err(errno)
                if errno == rustix::io::Errno::AGAIN
                    || errno == rustix::io::Errno::WOULDBLOCK
                    || errno == rustix::io::Errno::INPROGRESS
                    || errno == rustix::io::Errno::ALREADY =>
            {
                let rem = remaining_timeout(deadline)?;
                std::thread::sleep(rem.min(CONNECT_RETRY_INTERVAL));
            }
            Err(errno) if errno == rustix::io::Errno::INTR => continue,
            Err(errno) => return Err(io::Error::from(errno)),
        }
    }
    rustix::io::ioctl_fionbio(&fd, false).map_err(io::Error::from)?;
    Ok(std::os::unix::net::UnixStream::from(fd))
}

fn write_all_with_deadline(
    writer: &mut ControlStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let rem = socket_timeout(deadline)?;
        writer.set_write_timeout(Some(rem))?;
        match writer.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "tor control write accepted zero bytes",
                ));
            }
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                let _ = remaining_timeout(deadline);
                return Err(deadline_error());
            }
            Err(e) => return Err(e),
        }
    }
    let rem = socket_timeout(deadline)?;
    writer.set_write_timeout(Some(rem))?;
    writer.flush()
}

fn read_reply_line(
    reader: &mut BufReader<ControlStream>,
    deadline: Instant,
    total_bytes: &mut usize,
) -> io::Result<String> {
    let mut line_bytes = Vec::new();
    loop {
        let rem = socket_timeout(deadline)?;
        reader.get_mut().set_read_timeout(Some(rem))?;
        let (consumed, done) = {
            let available = match reader.fill_buf() {
                Ok(buf) => buf,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    let _ = remaining_timeout(deadline);
                    return Err(deadline_error());
                }
                Err(e) => return Err(e),
            };
            if available.is_empty() {
                if line_bytes.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "tor control connection closed",
                    ));
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tor control reply line truncated without terminator",
                ));
            }
            if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                let chunk = &available[..pos];
                if line_bytes.len().saturating_add(chunk.len()) > MAX_REPLY_LINE {
                    return Err(invalid("tor control reply line exceeds maximum length"));
                }
                line_bytes.extend_from_slice(chunk);
                (pos + 1, true)
            } else {
                if line_bytes.len().saturating_add(available.len()) > MAX_REPLY_LINE {
                    return Err(invalid("tor control reply line exceeds maximum length"));
                }
                line_bytes.extend_from_slice(available);
                (available.len(), false)
            }
        };
        reader.consume(consumed);
        *total_bytes = total_bytes.saturating_add(consumed);
        if *total_bytes > MAX_REPLY_BYTES {
            return Err(invalid("tor control reply exceeds maximum total bytes"));
        }
        if done {
            break;
        }
    }
    if line_bytes.last() == Some(&b'\r') {
        line_bytes.pop();
    }
    String::from_utf8(line_bytes).map_err(|_| invalid("tor control reply line is not valid UTF-8"))
}

fn read_reply(reader: &mut BufReader<ControlStream>, deadline: Instant) -> io::Result<Vec<String>> {
    let mut lines = Vec::new();
    let mut total_bytes = 0usize;
    let mut first_code = None;
    loop {
        if lines.len() >= MAX_REPLY_LINES {
            return Err(invalid("tor control reply exceeds maximum line count"));
        }
        let line = read_reply_line(reader, deadline, &mut total_bytes)?;
        if line.len() < 3 || !line.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
            return Err(invalid("tor control reply has no status code"));
        }
        let code: u32 = line[..3]
            .parse()
            .map_err(|_| invalid("tor control reply has no status code"))?;
        if !(200..300).contains(&code) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("tor control command refused with status {code}"),
            ));
        }
        if let Some(first) = first_code {
            if first != code {
                return Err(invalid("tor control multiline reply status code mismatch"));
            }
        } else {
            first_code = Some(code);
        }
        let separator = line.as_bytes().get(3).copied().unwrap_or(b' ');
        if separator == b'+' {
            return Err(invalid(
                "tor control multiline data reply framing (+) is unsupported",
            ));
        }
        lines.push(line);
        if separator == b' ' {
            return Ok(lines);
        }
        if separator != b'-' {
            return Err(invalid("tor control reply has a bad separator"));
        }
    }
}

/// One authenticated Tor control connection and its hidden service.
pub(crate) struct TorController {
    reader: BufReader<ControlStream>,
    writer: ControlStream,
    service_id: Option<String>,
    deadline: Option<Instant>,
    command_timeout: Duration,
}

impl std::fmt::Debug for TorController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorController")
            .field("service_id", &self.service_id)
            .finish_non_exhaustive()
    }
}

/// A live onion service registration.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OnionService {
    /// Service id (`<56 base32 chars>`, no `.onion` suffix).
    pub service_id: String,
    /// Private key blob, present only when Tor generated a fresh key.
    /// Sensitive: persist it, never log it.
    pub private_key: Option<String>,
}

impl std::fmt::Debug for OnionService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionService")
            .field("service_id", &self.service_id)
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn validate_password(password: &str) -> io::Result<()> {
    if password
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == 0 || b.is_ascii_control())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tor password must not contain CR, LF, NUL, or control characters",
        ));
    }
    Ok(())
}

impl TorController {
    /// Connect and authenticate. `password` selects password auth;
    /// otherwise SAFECOOKIE is used (cookie path from `PROTOCOLINFO`).
    pub(crate) fn connect(target: &TorControlTarget, password: Option<&str>) -> io::Result<Self> {
        Self::connect_bounded(target, password, CONTROL_TIMEOUT, CONTROL_TIMEOUT)
    }

    #[cfg(test)]
    fn connect_with_budget(
        target: &TorControlTarget,
        password: Option<&str>,
        connect_budget: Duration,
        command_budget: Duration,
    ) -> io::Result<Self> {
        Self::connect_bounded(target, password, connect_budget, command_budget)
    }

    fn connect_bounded(
        target: &TorControlTarget,
        password: Option<&str>,
        connect_timeout: Duration,
        command_timeout: Duration,
    ) -> io::Result<Self> {
        if let Some(password) = password {
            validate_password(password)?;
        }
        let deadline = Instant::now().checked_add(connect_timeout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "tor control connect timeout overflow",
            )
        })?;
        let rem = socket_timeout(deadline)?;
        let stream = match target {
            TorControlTarget::Tcp(addr) => {
                let stream = TcpStream::connect_timeout(addr, rem)?;
                stream.set_read_timeout(Some(rem))?;
                stream.set_write_timeout(Some(rem))?;
                ControlStream::Tcp(stream)
            }
            #[cfg(unix)]
            TorControlTarget::Unix(path) => {
                let stream = connect_unix(path, deadline)?;
                stream.set_read_timeout(Some(rem))?;
                stream.set_write_timeout(Some(rem))?;
                ControlStream::Unix(stream)
            }
        };
        let writer = match &stream {
            ControlStream::Tcp(stream) => ControlStream::Tcp(stream.try_clone()?),
            #[cfg(unix)]
            ControlStream::Unix(stream) => ControlStream::Unix(stream.try_clone()?),
        };
        let mut controller = Self {
            reader: BufReader::new(stream),
            writer,
            service_id: None,
            deadline: Some(deadline),
            command_timeout,
        };
        controller.authenticate(password)?;
        controller.deadline = None;
        let _ = controller
            .reader
            .get_mut()
            .set_read_timeout(Some(command_timeout));
        let _ = controller.writer.set_write_timeout(Some(command_timeout));
        Ok(controller)
    }

    fn command(&mut self, command: &str) -> io::Result<Vec<String>> {
        let deadline = match self.deadline {
            Some(deadline) => {
                remaining_timeout(deadline)?;
                deadline
            }
            None => Instant::now()
                .checked_add(self.command_timeout)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "tor control command timeout overflow",
                    )
                })?,
        };
        let res = (|| {
            write_all_with_deadline(&mut self.writer, command.as_bytes(), deadline)?;
            write_all_with_deadline(&mut self.writer, b"\r\n", deadline)?;
            read_reply(&mut self.reader, deadline)
        })();
        let _ = self
            .reader
            .get_mut()
            .set_read_timeout(Some(self.command_timeout));
        let _ = self.writer.set_write_timeout(Some(self.command_timeout));
        res
    }

    fn authenticate(&mut self, password: Option<&str>) -> io::Result<()> {
        if let Some(password) = password {
            validate_password(password)?;
            let escaped = password.replace('\\', "\\\\").replace('"', "\\\"");
            self.command(&format!("AUTHENTICATE \"{escaped}\""))?;
            return Ok(());
        }
        let info = self.command("PROTOCOLINFO 1")?;
        let cookie_file = info
            .iter()
            .find_map(|line| quoted_value(line, "COOKIEFILE="))
            .ok_or_else(|| invalid("tor PROTOCOLINFO carries no cookie file"))?;
        let cookie = std::fs::read(&cookie_file)?;
        let mut client_nonce = [0u8; 32];
        thread_rng().fill_bytes(&mut client_nonce);
        let reply = self.command(&format!(
            "AUTHCHALLENGE SAFECOOKIE {}",
            hex_encode(&client_nonce)
        ))?;
        let line = reply
            .first()
            .ok_or_else(|| invalid("tor AUTHCHALLENGE reply is empty"))?;
        let server_hash = unquoted_value(line, "SERVERHASH=")
            .and_then(|text| hex_decode(&text))
            .ok_or_else(|| invalid("tor AUTHCHALLENGE reply has no server hash"))?;
        let server_nonce = unquoted_value(line, "SERVERNONCE=")
            .and_then(|text| hex_decode(&text))
            .ok_or_else(|| invalid("tor AUTHCHALLENGE reply has no server nonce"))?;
        let expected = safecookie_hash(
            b"Tor safe cookie authentication server-to-controller hash",
            &cookie,
            &client_nonce,
            &server_nonce,
        );
        if expected.as_slice() != server_hash.as_slice() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tor SAFECOOKIE server hash mismatch",
            ));
        }
        let client_hash = safecookie_hash(
            b"Tor safe cookie authentication controller-to-server hash",
            &cookie,
            &client_nonce,
            &server_nonce,
        );
        self.command(&format!("AUTHENTICATE {}", hex_encode(&client_hash)))?;
        Ok(())
    }

    /// Register the hidden service. With `key_blob` the persisted key is
    /// reused; without it Tor generates a fresh key whose blob is
    /// returned for persistence. Response bodies are never logged.
    pub(crate) fn add_onion(
        &mut self,
        key_blob: Option<&str>,
        virtual_port: u16,
        target: SocketAddr,
    ) -> io::Result<OnionService> {
        if let Some(blob) = key_blob {
            if !valid_key_blob(blob) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "provided key blob is not a valid ED25519-V3 key blob",
                ));
            }
        }
        let key = match key_blob {
            Some(blob) => format!("ED25519-V3:{blob}"),
            None => "NEW:ED25519-V3".to_owned(),
        };
        let lines = self.command(&format!(
            "ADD_ONION {key} Port={virtual_port},127.0.0.1:{}",
            target.port()
        ))?;
        let mut service_id = None;
        let mut private_key = None;
        for line in &lines {
            if let Some(value) = unquoted_value(line, "ServiceID=") {
                let id = value.strip_suffix(".onion").unwrap_or(&value);
                service_id = Some(id.to_owned());
            }
            if let Some(value) = unquoted_value(line, "PrivateKey=ED25519-V3:") {
                private_key = Some(value);
            }
        }
        let service_id =
            service_id.ok_or_else(|| invalid("tor ADD_ONION reply has no service id"))?;
        if !valid_service_id(&service_id) {
            return Err(invalid("tor ADD_ONION reply carries invalid service id"));
        }
        if let Some(pk) = &private_key {
            if !valid_key_blob(pk) {
                return Err(invalid(
                    "tor ADD_ONION reply carries invalid private key blob",
                ));
            }
        }
        self.service_id = Some(service_id.clone());
        Ok(OnionService {
            service_id,
            private_key,
        })
    }

    /// Remove the hidden service registered on this connection.
    pub(crate) fn del_onion(&mut self) -> io::Result<()> {
        let Some(service_id) = self.service_id.take() else {
            return Ok(());
        };
        self.command(&format!("DEL_ONION {service_id}"))?;
        Ok(())
    }

    /// Probe control-connection liveness (`GETINFO version`).
    pub(crate) fn poll_alive(&mut self) -> io::Result<()> {
        self.command("GETINFO version")?;
        Ok(())
    }
}

fn safecookie_hash(key: &[u8], cookie: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> Vec<u8> {
    let mut engine = hmac::HmacEngine::<sha256::Hash>::new(key);
    engine.input(cookie);
    engine.input(client_nonce);
    engine.input(server_nonce);
    hmac::Hmac::<sha256::Hash>::from_engine(engine)
        .to_byte_array()
        .to_vec()
}

fn quoted_value(line: &str, key: &str) -> Option<String> {
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    let inner = rest.strip_prefix('"')?;
    let end = inner.find('"')?;
    Some(inner[..end].replace("\\\"", "\"").replace("\\\\", "\\"))
}

fn unquoted_value(line: &str, key: &str) -> Option<String> {
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    Some(
        rest.split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches('"')
            .to_owned(),
    )
}

/// Hex encoding for control-protocol nonces and hashes.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let hi = usize::from(b >> 4);
        let lo = usize::from(b & 0x0f);
        out.push(char::from(HEX[hi]));
        out.push(char::from(HEX[lo]));
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn rfc4648_base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut values = Vec::with_capacity(text.len());
    let mut padding = 0;
    for &byte in text.as_bytes() {
        if padding > 0 {
            if byte == b'=' && padding < 2 {
                padding += 1;
                continue;
            }
            return None;
        }
        match byte {
            b'A'..=b'Z' => values.push(byte - b'A'),
            b'a'..=b'z' => values.push(byte - b'a' + 26),
            b'0'..=b'9' => values.push(byte - b'0' + 52),
            b'+' => values.push(62),
            b'/' => values.push(63),
            b'=' if values.len() >= 2 => padding = 1,
            _ => return None,
        }
    }
    match (values.len() + padding) % 4 {
        0 => {}
        _ => return None,
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

/// Validate a persisted ED25519-V3 key blob: RFC 4648 base64 decoding to 64 bytes
/// (32-byte Ed25519 secret scalar + 32-byte Ed25519 PRF secret).
#[must_use]
pub(crate) fn valid_key_blob(text: &str) -> bool {
    rfc4648_base64_decode(text).is_some_and(|bytes| bytes.len() == 64)
}

/// Validate a Tor v3 onion service ID: 56-character base32 payload containing
/// 32-byte Ed25519 public key, 2-byte SHA3 checksum, and version byte 0x03.
#[must_use]
fn valid_service_id(text: &str) -> bool {
    let clean = text.strip_suffix(".onion").unwrap_or(text);
    if clean.len() != 56 {
        return false;
    }
    let Some(payload) = bitcoin_rs_primitives::endpoint::base32_decode(clean) else {
        return false;
    };
    bitcoin_rs_primitives::endpoint::tor_v3_key_from_payload(&payload).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// Scripted Tor control server using password auth, recording every
    /// command (key material redacted by the test script itself: the
    /// scripted `PrivateKey` line is a fixture, never a real key).
    fn fake_tor() -> io::Result<(SocketAddr, mpsc::Receiver<String>, tempfile::TempDir)> {
        let dir = tempfile::tempdir()?;
        let cookie = dir.path().join("control_auth_cookie");
        std::fs::write(&cookie, [7u8; 32])?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (tx, rx) = mpsc::channel();
        let cookie_text = cookie.to_string_lossy().into_owned();
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            if stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .is_err()
            {
                return;
            }
            let Ok(stream_clone) = stream.try_clone() else {
                return;
            };
            let mut reader = BufReader::new(stream_clone);
            let mut writer = stream;
            loop {
                let mut line = String::new();
                let Ok(read) = reader.read_line(&mut line) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                let line = line.trim_end().to_owned();
                let _ = tx.send(line.clone());
                let reply: String = if line.starts_with("PROTOCOLINFO") {
                    format!(
                        "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=SAFECOOKIE COOKIEFILE=\"{cookie_text}\"\r\n250 OK\r\n"
                    )
                } else if line.starts_with("AUTHCHALLENGE") {
                    // Server nonce of zeros; server hash computed with
                    // the documented key over cookie||client||server.
                    let Some(client) = line.split_whitespace().nth(2).and_then(hex_decode) else {
                        return;
                    };
                    let server_nonce = [0u8; 32];
                    let hash = safecookie_hash(
                        b"Tor safe cookie authentication server-to-controller hash",
                        &[7u8; 32],
                        &client,
                        &server_nonce,
                    );
                    format!(
                        "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                        hex_encode(&hash),
                        hex_encode(&server_nonce)
                    )
                } else if line.starts_with("AUTHENTICATE") {
                    "250 OK\r\n".to_owned()
                } else if line.starts_with("ADD_ONION NEW") {
                    let blob = "A".repeat(86) + "==";
                    format!(
                        "250-ServiceID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion\r\n250-PrivateKey=ED25519-V3:{blob}\r\n250 OK\r\n",
                    )
                } else if line.starts_with("ADD_ONION ED25519-V3:") {
                    "250-ServiceID=aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaea37ead.onion\r\n250 OK\r\n".to_owned()
                } else if line.starts_with("DEL_ONION") {
                    "250 OK\r\n".to_owned()
                } else {
                    "510 Unrecognized command\r\n".to_owned()
                };
                if writer.write_all(reply.as_bytes()).is_err() {
                    return;
                }
            }
        });
        Ok((addr, rx, dir))
    }

    #[test]
    fn safecookie_auth_and_onion_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
        let (addr, rx, _dir) = fake_tor()?;
        let mut controller = TorController::connect(&TorControlTarget::Tcp(addr), None)?;
        let service = controller.add_onion(None, 8333, "127.0.0.1:19000".parse()?)?;
        assert_eq!(
            service.service_id,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd"
        );
        assert!(service.private_key.as_deref().is_some_and(valid_key_blob));
        controller.del_onion()?;
        drop(controller);
        let commands: Vec<String> = rx.try_iter().collect();
        assert_eq!(commands[0], "PROTOCOLINFO 1");
        assert!(commands[1].starts_with("AUTHCHALLENGE SAFECOOKIE "));
        assert!(commands[2].starts_with("AUTHENTICATE "));
        assert_eq!(
            commands[3],
            "ADD_ONION NEW:ED25519-V3 Port=8333,127.0.0.1:19000"
        );
        assert_eq!(
            commands[4],
            "DEL_ONION aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd"
        );
        Ok(())
    }

    #[test]
    fn persisted_key_blob_reuse_sends_no_new() -> Result<(), Box<dyn std::error::Error>> {
        let (addr, rx, _dir) = fake_tor()?;
        let mut controller = TorController::connect(&TorControlTarget::Tcp(addr), Some("pw"))?;
        let blob = "A".repeat(86) + "==";
        let service = controller.add_onion(Some(&blob), 8333, "127.0.0.1:19000".parse()?)?;
        assert_eq!(
            service.service_id,
            "aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaea37ead"
        );
        assert_eq!(service.private_key, None);
        drop(controller);
        let commands: Vec<String> = rx.try_iter().collect();
        assert!(
            commands
                .iter()
                .any(|c| c.starts_with("ADD_ONION ED25519-V3:") && c.contains("Port=8333"))
        );
        Ok(())
    }

    #[test]
    fn corrupt_key_blob_is_rejected_by_validation() {
        assert!(!valid_key_blob("not base64!!"));
        assert!(!valid_key_blob("AAAA"));
        assert!(!valid_key_blob(&("A".repeat(43) + "="))); // 32-byte public key is not 64-byte private key blob
        assert!(!valid_key_blob(&("-".repeat(86) + "=="))); // I2P base64 chars rejected
        assert!(!valid_key_blob(&("~".repeat(86) + "==")));
        assert!(valid_key_blob(&("A".repeat(86) + "==")));
    }

    #[test]
    fn onion_service_debug_redacts_private_key() {
        let service = OnionService {
            service_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd".to_owned(),
            private_key: Some("super_secret_private_key_blob_123456789".to_owned()),
        };
        let formatted = format!("{service:?}");
        assert!(
            !formatted.contains("super_secret_private_key_blob_123456789"),
            "OnionService Debug leaked private_key"
        );
        assert!(
            formatted.contains("<redacted>"),
            "OnionService Debug did not contain <redacted>"
        );
    }

    #[test]
    fn tor_password_crlf_and_control_chars_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let bad_passwords = [
            "pass\r\nSIGNAL NEWNYM\r\n",
            "pass\nSIGNAL NEWNYM",
            "pass\rSIGNAL NEWNYM",
            "pass\0word",
            "pass\x07word",
        ];
        for bad in bad_passwords {
            let Err(error) = TorController::connect(&TorControlTarget::Tcp(addr), Some(bad)) else {
                panic!("control chars in password must be rejected");
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
        let Err(accept_err) = listener.accept() else {
            panic!("no connection should have been established");
        };
        assert_eq!(accept_err.kind(), io::ErrorKind::WouldBlock);

        let unroutable_target = TorControlTarget::Tcp("127.0.0.1:1".parse()?);
        let Err(error) = TorController::connect(&unroutable_target, Some("bad\npassword")) else {
            panic!("must reject without connecting");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        Ok(())
    }

    #[test]
    fn valid_service_id_verification() {
        assert!(valid_service_id(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd"
        ));
        assert!(valid_service_id(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion"
        ));
        assert!(valid_service_id(
            "aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaea37ead"
        ));
        assert!(valid_service_id(
            "aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaea37ead.onion"
        ));
        assert!(!valid_service_id(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafp4ad"
        ));
        assert!(!valid_service_id(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafp4ad.onion"
        ));
        assert!(!valid_service_id(
            "aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaea73dyd"
        ));
        assert!(!valid_service_id(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )); // bad checksum
        assert!(!valid_service_id("tooshort"));
        assert!(!valid_service_id("badcharacters!!notbase32"));
    }

    #[test]
    fn key_blob_distinguishes_expanded_private_from_public_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let (addr, rx, _dir) = fake_tor()?;
        let mut controller = TorController::connect(&TorControlTarget::Tcp(addr), Some("pw"))?;
        let pubkey_blob = "A".repeat(43) + "=";
        let target = "127.0.0.1:19000".parse()?;
        let Err(err) = controller.add_onion(Some(&pubkey_blob), 8333, target) else {
            panic!("32-byte public key must be rejected as private key blob");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let commands: Vec<String> = rx.try_iter().collect();
        assert!(
            commands.iter().all(|c| !c.starts_with("ADD_ONION")),
            "ADD_ONION must not be sent when key blob is invalid"
        );
        Ok(())
    }

    #[test]
    fn add_onion_rejects_corrupted_service_id_from_tor() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let Ok(stream_clone) = stream.try_clone() else {
                return;
            };
            let mut reader = BufReader::new(stream_clone);
            let mut writer = stream;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let line = line.trim_end();
                let reply = if line.starts_with("AUTHENTICATE") {
                    "250 OK\r\n".to_owned()
                } else if line.starts_with("ADD_ONION") {
                    "250-ServiceID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafp4ad.onion\r\n250 OK\r\n".to_owned()
                } else {
                    "250 OK\r\n".to_owned()
                };
                if writer.write_all(reply.as_bytes()).is_err() {
                    return;
                }
            }
        });
        let mut controller = TorController::connect(&TorControlTarget::Tcp(addr), Some("pw"))?;
        let target = "127.0.0.1:19000".parse()?;
        let Err(err) = controller.add_onion(None, 8333, target) else {
            panic!("add_onion must reject invalid service id returned by Tor");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        Ok(())
    }

    #[test]
    fn safecookie_auth_fails_on_server_hash_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let cookie = dir.path().join("control_auth_cookie");
        std::fs::write(&cookie, [7u8; 32])?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let cookie_text = cookie.to_string_lossy().into_owned();
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let Ok(stream_clone) = stream.try_clone() else {
                return;
            };
            let mut reader = BufReader::new(stream_clone);
            let mut writer = stream;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let line = line.trim_end();
                let reply = if line.starts_with("PROTOCOLINFO") {
                    format!(
                        "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=SAFECOOKIE COOKIEFILE=\"{cookie_text}\"\r\n250 OK\r\n"
                    )
                } else if line.starts_with("AUTHCHALLENGE") {
                    let server_nonce = [0u8; 32];
                    let corrupt_server_hash = [0xffu8; 32];
                    format!(
                        "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                        hex_encode(&corrupt_server_hash),
                        hex_encode(&server_nonce)
                    )
                } else {
                    "250 OK\r\n".to_owned()
                };
                if writer.write_all(reply.as_bytes()).is_err() {
                    return;
                }
            }
        });
        let Err(err) = TorController::connect(&TorControlTarget::Tcp(addr), None) else {
            panic!("mismatched server hash must fail authentication");
        };
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        Ok(())
    }

    #[test]
    fn tcp_slow_trickle_auth_deadline_expires() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Ok(stream_clone) = stream.try_clone() else {
                return;
            };
            let mut reader = BufReader::new(stream_clone);
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            // Trickle bytes with delays so each read would succeed if timeout were re-armed
            // per read, but total exchange must hit the single monotonic deadline.
            for _ in 0..200 {
                if stream.write_all(b"2").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });

        let start = Instant::now();
        let Err(err) = TorController::connect_with_budget(
            &TorControlTarget::Tcp(addr),
            Some("pw"),
            Duration::from_millis(150),
            Duration::from_millis(150),
        ) else {
            panic!("slow trickle must hit deadline");
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(3));
        let Ok(()) = server.join() else {
            panic!("scripted server must not panic");
        };
        Ok(())
    }

    #[test]
    fn tcp_post_auth_command_deadline_expires() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Ok(stream_clone) = stream.try_clone() else {
                return;
            };
            let mut reader = BufReader::new(stream_clone);
            let mut line = String::new();
            // 1. Read AUTHENTICATE
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            if stream.write_all(b"250 OK\r\n").is_err() {
                return;
            }
            // 2. Read GETINFO version
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            // 3. Stalls / trickles GETINFO reply so post-auth command deadline is exercised
            for _ in 0..200 {
                if stream.write_all(b"2").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });

        let mut controller = TorController::connect_with_budget(
            &TorControlTarget::Tcp(addr),
            Some("pw"),
            Duration::from_secs(5),
            Duration::from_millis(150),
        )?;

        let start = Instant::now();
        let Err(err) = controller.poll_alive() else {
            panic!("post-auth stalled command must hit its own deadline");
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(3));
        drop(controller);
        let Ok(()) = server.join() else {
            panic!("scripted server must not panic");
        };
        Ok(())
    }

    #[test]
    fn tcp_multiline_reply_exceeding_line_cap_is_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Ok(stream_clone) = stream.try_clone() else {
                return;
            };
            let mut reader = BufReader::new(stream_clone);
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            // Send more lines than MAX_REPLY_LINES (1024)
            for _ in 0..1200 {
                if stream.write_all(b"250-line\r\n").is_err() {
                    return;
                }
            }
            let _ = stream.write_all(b"250 OK\r\n");
        });

        let Err(err) = TorController::connect(&TorControlTarget::Tcp(addr), Some("pw")) else {
            panic!("reply exceeding line limit must be rejected");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let Ok(()) = server.join() else {
            panic!("scripted server must not panic");
        };
        Ok(())
    }

    #[test]
    fn tcp_truncated_reply_without_terminator_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Ok(stream_clone) = stream.try_clone() else {
                return;
            };
            let mut reader = BufReader::new(stream_clone);
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            // Write reply without newline then close stream
            let _ = stream.write_all(b"250 OK");
        });

        let Err(err) = TorController::connect(&TorControlTarget::Tcp(addr), Some("pw")) else {
            panic!("truncated reply without terminator must fail");
        };
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        let Ok(()) = server.join() else {
            panic!("scripted server must not panic");
        };
        Ok(())
    }

    #[test]
    fn tcp_reply_line_exceeding_max_len_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Ok(stream_clone) = stream.try_clone() else {
                return;
            };
            let mut reader = BufReader::new(stream_clone);
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let mut long_line = Vec::with_capacity(20000);
            long_line.extend_from_slice(b"250-");
            long_line.resize(20000, b'A');
            long_line.extend_from_slice(b"\r\n");
            let _ = stream.write_all(&long_line);
            let _ = stream.write_all(b"250 OK\r\n");
        });

        let Err(err) = TorController::connect(&TorControlTarget::Tcp(addr), Some("pw")) else {
            panic!("line exceeding MAX_REPLY_LINE must be rejected");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let Ok(()) = server.join() else {
            panic!("scripted server must not panic");
        };
        Ok(())
    }

    #[test]
    fn tcp_unsupported_data_framing_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Ok(stream_clone) = stream.try_clone() else {
                return;
            };
            let mut reader = BufReader::new(stream_clone);
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let _ = stream.write_all(b"250+key=value\r\n.\r\n250 OK\r\n");
        });

        let Err(err) = TorController::connect(&TorControlTarget::Tcp(addr), Some("pw")) else {
            panic!("unsupported '+' data framing must be rejected");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let Ok(()) = server.join() else {
            panic!("scripted server must not panic");
        };
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unix_absent_path_fails_fast() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("absent-socket.sock");
        let start = Instant::now();
        let Err(err) = TorController::connect_with_budget(
            &TorControlTarget::Unix(path),
            Some("pw"),
            Duration::from_secs(5),
            Duration::from_secs(5),
        ) else {
            panic!("absent path must fail fast");
        };
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(start.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unix_full_backlog_deadline_expires() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("backlog.sock");
        let address = rustix::net::SocketAddrUnix::new(&path)?;
        let listener = rustix::net::socket(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            None,
        )?;
        rustix::net::bind(&listener, &address)?;
        rustix::net::listen(&listener, 0)?;

        // Fill accept queue using non-blocking connects so the filler itself cannot hang.
        let mut held = Vec::new();
        for _ in 0..16 {
            let client = rustix::net::socket(
                rustix::net::AddressFamily::UNIX,
                rustix::net::SocketType::STREAM,
                None,
            )?;
            let _ = rustix::io::ioctl_fionbio(&client, true);
            match rustix::net::connect(&client, &address) {
                Ok(()) => held.push(client),
                Err(e) if e == rustix::io::Errno::AGAIN || e == rustix::io::Errno::WOULDBLOCK => {
                    break;
                }
                Err(e) => panic!("unexpected fill error: {e:?}"),
            }
        }

        let start = Instant::now();
        let Err(err) = TorController::connect_with_budget(
            &TorControlTarget::Unix(path),
            Some("pw"),
            Duration::from_millis(150),
            Duration::from_millis(150),
        ) else {
            panic!("connect to full backlog must timeout");
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(3));
        drop(held);
        Ok(())
    }

    /// Upper bound on every scripted-server wait on a unix socket. A client
    /// that never speaks fails the fixture instead of parking the harness.
    #[cfg(unix)]
    const SERVER_STEP_TIMEOUT: Duration = Duration::from_secs(5);

    #[cfg(unix)]
    #[test]
    fn unix_silent_server_hits_auth_deadline_and_server_is_joined()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("silent.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        // The server reads the AUTHENTICATE line and withholds every reply.
        // Only the client's own deadline can end the exchange: its failed
        // connect drops both descriptors, which is the EOF this server then
        // reads. The server never waits on anything the test joins before.
        let server = std::thread::spawn(move || -> io::Result<String> {
            let (stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(SERVER_STEP_TIMEOUT))?;
            let mut reader = BufReader::new(stream);
            let mut command = String::new();
            reader.read_line(&mut command)?;
            let mut tail = String::new();
            if reader.read_line(&mut tail)? != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "client sent more than the single AUTHENTICATE command",
                ));
            }
            Ok(command)
        });

        let start = Instant::now();
        let Err(err) = TorController::connect_with_budget(
            &TorControlTarget::Unix(path),
            Some("pw"),
            Duration::from_millis(150),
            Duration::from_millis(150),
        ) else {
            panic!("a silent unix server must hit the auth deadline");
        };
        let elapsed = start.elapsed();
        let Ok(served) = server.join() else {
            panic!("scripted server must not panic");
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            elapsed < Duration::from_secs(3),
            "deadline took {elapsed:?}"
        );
        let Ok(served_cmd) = served else {
            panic!("scripted server must see the client close");
        };
        assert_eq!(served_cmd, "AUTHENTICATE \"pw\"\r\n");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unix_control_connection_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("control.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        // The server owns exactly two request/reply exchanges (password
        // AUTHENTICATE, then the GETINFO liveness probe) and returns. Its
        // completion never depends on the client closing the connection,
        // so joining it while the controller is still alive cannot form a
        // wait cycle: the server exits as soon as its second reply is sent.
        let server = std::thread::spawn(move || -> io::Result<Vec<String>> {
            let (stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(SERVER_STEP_TIMEOUT))?;
            stream.set_write_timeout(Some(SERVER_STEP_TIMEOUT))?;
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut writer = stream;
            let mut commands = Vec::with_capacity(2);
            for reply in ["250 OK\r\n", "250-version=0.4.9.14\r\n250 OK\r\n"] {
                let mut line = String::new();
                if reader.read_line(&mut line)? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "client closed before completing the scripted exchange",
                    ));
                }
                commands.push(line);
                writer.write_all(reply.as_bytes())?;
            }
            Ok(commands)
        });

        // Assert client progress before joining: a client-side failure panics
        // here, unwinding the test thread and failing fast without entering join.
        let mut controller = TorController::connect(&TorControlTarget::Unix(path), Some("secret"))?;
        controller.poll_alive()?;
        // Server exits once its second reply is sent; join succeeds while controller lives.
        let Ok(commands) = server.join() else {
            panic!("scripted server must not panic");
        };
        drop(controller);
        let Ok(commands) = commands else {
            panic!("scripted server must finish its exchanges");
        };
        assert_eq!(
            commands,
            ["AUTHENTICATE \"secret\"\r\n", "GETINFO version\r\n"],
            "unix control transport must carry canonical CRLF-framed commands"
        );
        Ok(())
    }
}
