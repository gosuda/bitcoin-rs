//! Bounded HTTP/1.1 replay client for the Core parity gate.
//!
//! Response framing comes only from an exact `HTTP/1.1` status line with
//! CRLF line endings, a 3-digit status, the status-defined empty body for
//! 204 or a strict ASCII-decimal `Content-Length`, and explicit refusal of
//! `Transfer-Encoding` and conflicting framing — never from end of stream.
//! Every read is byte-bounded before it happens, and the absolute
//! per-connection deadline is recomputed and re-armed before *every* syscall (a
//! multi-syscall `write_all` or buffered read can never outlive the window
//! set once), the read buffer is retained across responses so pipelined or
//! trailing bytes survive to the next framed response instead of being
//! dropped with a temporary reader, and one outstanding request
//! legitimizes exactly one decoded response.

use core::time::Duration;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Instant;

use super::limits::{
    CONNECT_TIMEOUT, IO_TIMEOUT, MAX_HEADER_LINE_BYTES, MAX_RESPONSE_BODY_BYTES,
    MAX_RESPONSE_HEADERS, MAX_STATUS_LINE_BYTES,
};

/// Size of the retained read buffer. Small enough to exercise the refill
/// path on every fixture body.
const READ_BUFFER_CAPACITY: usize = 8 * 1024;

/// One decoded HTTP/1.1 response: complete tuple, body carried to its
/// declared length, never truncated at end of stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawResponse {
    /// HTTP version as asserted by the decoder; only `HTTP/1.1` passes.
    pub(crate) version: String,
    /// Numeric status code (`200`, `204`, `401`, `500`, ...).
    pub(crate) status: u16,
    /// Reason phrase as sent (`OK`, `No Content`, ...).
    pub(crate) reason: String,
    /// Header lines in wire order, names lower-cased.
    pub(crate) headers: Vec<(String, String)>,
    /// Body bytes read to the declared or status-defined length.
    pub(crate) body: Vec<u8>,
}

/// Replay error: every failure names the bound it hit.
#[derive(Debug)]
pub(crate) enum HttpError {
    /// Socket setup, deadline, or write failure.
    Io(std::io::Error),
    /// The peer broke the framing contract this decoder enforces.
    Framing(&'static str),
    /// The absolute connection deadline passed before the exchange finished.
    DeadlineExceeded,
}

impl From<std::io::Error> for HttpError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl core::fmt::Display for HttpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "io error: {error}"),
            Self::Framing(why) => write!(f, "framing violation: {why}"),
            Self::DeadlineExceeded => write!(f, "absolute connection deadline exceeded"),
        }
    }
}

impl std::error::Error for HttpError {}

/// A composed replay request.
pub(crate) struct RawRequest {
    /// Request target path (`/` for JSON-RPC POSTs).
    pub(crate) path: &'static str,
    /// Base64 `user:password` credentials, when the case sends auth.
    pub(crate) authorization: Option<String>,
    /// JSON-RPC body as raw text (already exact fixture bytes).
    pub(crate) body: String,
    /// `keep-alive` (default) or `close`.
    pub(crate) keep_alive: bool,
}

impl RawRequest {
    /// Builds the exact wire bytes for this request, including the
    /// `Content-Length` header derived from the body bytes.
    #[must_use]
    pub(crate) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let connection = if self.keep_alive {
            "keep-alive"
        } else {
            "close"
        };
        let auth_line = self
            .authorization
            .as_deref()
            .map(|token| format!("Authorization: Basic {token}\r\n"))
            .unwrap_or_default();
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: localhost\r\n{auth_line}Content-Type: \
             application/json\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
            self.path,
            self.body.len()
        );
        out.extend_from_slice(head.as_bytes());
        out.extend_from_slice(self.body.as_bytes());
        out
    }
}

/// Minimal standard base64 encoder for the replay credentials; the binary
/// `crates/rpc/tests/auth.rs` uses the same `user:password` shape.
#[must_use]
pub(crate) fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).map_or(0, |b| u32::from(*b));
        let b2 = chunk.get(2).map_or(0, |b| u32::from(*b));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        // A masked 6-bit value always fits `usize`.
        let index = |bits: u32| usize::try_from(bits).unwrap_or_default();
        out.push(char::from(ALPHABET[index((triple >> 18) & 0x3f)]));
        out.push(char::from(ALPHABET[index((triple >> 12) & 0x3f)]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[index((triple >> 6) & 0x3f)])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[index(triple & 0x3f)])
        } else {
            '='
        });
    }
    out
}

/// One persistent connection to the replay server with one absolute
/// deadline for the whole exchange, a retained read buffer across
/// responses, and one-outstanding-request-per-response accounting.
pub(crate) struct Connection {
    stream: TcpStream,
    /// Retained across responses: bytes read past one response's declared
    /// length stay here for the next one instead of being dropped.
    buffer: Box<[u8; READ_BUFFER_CAPACITY]>,
    buffered_start: usize,
    buffered_end: usize,
    deadline: Instant,
    /// How many requests have been sent whose responses are not yet
    /// decoded: one outstanding request legitimizes exactly one response.
    /// Reads beyond that are refused, so retained or unsolicited bytes can
    /// never be mistaken for a response.
    outstanding_requests: u32,
}

impl Connection {
    /// Connects to the replay server under [`CONNECT_TIMEOUT`] and starts
    /// the default absolute [`IO_TIMEOUT`] deadline.
    ///
    /// # Errors
    /// Propagates socket setup failures.
    pub(crate) fn connect(address: SocketAddr) -> Result<Self, HttpError> {
        Self::connect_with_deadline(address, IO_TIMEOUT)
    }

    /// Connects with an injected absolute deadline; the negative tests use
    /// a short one so the deadline property is provable in milliseconds.
    ///
    /// # Errors
    /// Propagates socket setup failures.
    pub(crate) fn connect_with_deadline(
        address: SocketAddr,
        deadline: Duration,
    ) -> Result<Self, HttpError> {
        let stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)?;
        stream.set_read_timeout(Some(deadline))?;
        stream.set_write_timeout(Some(deadline))?;
        Ok(Self {
            stream,
            buffer: Box::new([0_u8; READ_BUFFER_CAPACITY]),
            buffered_start: 0,
            buffered_end: 0,
            deadline: Instant::now() + deadline,
            outstanding_requests: 0_u32,
        })
    }

    fn remaining(&self) -> Result<Duration, HttpError> {
        self.deadline
            .checked_duration_since(Instant::now())
            .ok_or(HttpError::DeadlineExceeded)
    }

    /// Re-arms the write timeout to the remaining deadline. Called before
    /// every single write syscall.
    fn rearm_write(&self) -> Result<(), HttpError> {
        self.stream
            .set_write_timeout(Some(self.remaining()?))
            .map_err(HttpError::Io)
    }

    /// Re-arms the read timeout to the remaining deadline. Called before
    /// every single read syscall.
    fn rearm_read(&self) -> Result<(), HttpError> {
        self.stream
            .set_read_timeout(Some(self.remaining()?))
            .map_err(HttpError::Io)
    }

    /// One underlying read syscall into the retained buffer, with the read
    /// timeout re-armed immediately before it.
    fn fill(&mut self) -> Result<(), HttpError> {
        self.rearm_read()?;
        let chunk = self.stream.read(self.buffer.as_mut_slice());
        match chunk {
            Ok(0) => Err(HttpError::Framing(
                "connection closed before the response was fully framed",
            )),
            Ok(n) => {
                self.buffered_start = 0;
                self.buffered_end = n;
                Ok(())
            }
            // The timeout was just re-armed to the remaining deadline, so a
            // timeout here means the absolute deadline passed mid-read.
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                Err(HttpError::DeadlineExceeded)
            }
            Err(error) => Err(HttpError::Io(error)),
        }
    }

    /// Consumes buffered bytes; refills with one deadline-guarded syscall
    /// when the buffer is empty.
    fn take_buffered(&mut self, target: &mut [u8]) -> Result<usize, HttpError> {
        if self.buffered_start == self.buffered_end {
            self.fill()?;
        }
        let available = self.buffered_end - self.buffered_start;
        let taken = available.min(target.len());
        target[..taken]
            .copy_from_slice(&self.buffer[self.buffered_start..self.buffered_start + taken]);
        self.buffered_start += taken;
        Ok(taken)
    }

    /// Reads exactly `target.len()` bytes through the retained buffer, re-
    /// arming the deadline before every underlying read syscall.
    fn read_exact_deadlined(&mut self, target: &mut [u8]) -> Result<(), HttpError> {
        let mut filled = 0;
        while filled < target.len() {
            let taken = self.take_buffered(&mut target[filled..])?;
            filled += taken;
        }
        Ok(())
    }

    /// Reads one byte through the retained buffer.
    fn read_byte(&mut self) -> Result<u8, HttpError> {
        let mut one = [0_u8; 1];
        self.read_exact_deadlined(&mut one)?;
        Ok(one[0])
    }

    /// Writes `bytes` in explicit per-syscall loops, re-arming the write
    /// timeout immediately before every syscall; `write_all`'s internal
    /// retries can therefore never run past the deadline set once.
    fn write_all_deadlined(&mut self, bytes: &[u8]) -> Result<(), HttpError> {
        let mut rest = bytes;
        while !rest.is_empty() {
            self.rearm_write()?;
            let written = self.stream.write(rest).map_err(|error| {
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
                    HttpError::DeadlineExceeded
                } else {
                    HttpError::Io(error)
                }
            })?;
            if written == 0 {
                return Err(HttpError::Framing("write made no progress"));
            }
            rest = &rest[written..];
        }
        self.rearm_write()?;
        self.stream.flush()?;
        Ok(())
    }

    /// Sends one complete request and decodes exactly one response.
    ///
    /// # Errors
    /// [`HttpError::Framing`] when the response violates a ceiling or omits
    /// the framing this decoder requires; [`HttpError::Io`] on transport
    /// failure; [`HttpError::DeadlineExceeded`] once the absolute deadline
    /// has passed.
    pub(crate) fn round_trip(&mut self, request: &RawRequest) -> Result<RawResponse, HttpError> {
        let bytes = request.bytes();
        self.send_request_fragmented(&bytes, None)?;
        self.read_response()
    }

    /// Writes `bytes`, optionally split at `split_at` into two fragments
    /// with a flush between them, proving the server answers mid-request
    /// writes.
    ///
    /// # Errors
    /// Propagates transport failures and deadline expiry.
    pub(crate) fn send_fragmented(
        &mut self,
        bytes: &[u8],
        split_at: Option<usize>,
    ) -> Result<(), HttpError> {
        match split_at {
            Some(split) if split > 0 && split < bytes.len() => {
                self.write_all_deadlined(&bytes[..split])?;
                self.write_all_deadlined(&bytes[split..])?;
            }
            _ => self.write_all_deadlined(bytes)?,
        }
        Ok(())
    }

    /// Sends one request (optionally fragmented) and accounts it as one
    /// outstanding request, so [`Self::read_response`] accepts exactly one
    /// framed reply for it.
    ///
    /// # Errors
    /// Propagates transport failures and deadline expiry.
    pub(crate) fn send_request_fragmented(
        &mut self,
        bytes: &[u8],
        split_at: Option<usize>,
    ) -> Result<(), HttpError> {
        self.send_fragmented(bytes, split_at)?;
        self.outstanding_requests = self.outstanding_requests.saturating_add(1);
        Ok(())
    }

    /// Decodes one response from the retained buffer, framed by an exact
    /// `HTTP/1.1` status line, CRLF-terminated headers, and either the
    /// status-defined empty 204 body or a declared `Content-Length`.
    /// Refuses to read without an outstanding request: retained pipelined or
    /// trailing bytes may never be mistaken for an unsolicited response — a
    /// request must actually have been sent for every response this decoder
    /// produces.
    ///
    /// # Errors
    /// [`HttpError::Framing`] on any ceiling or framing violation;
    /// [`HttpError::DeadlineExceeded`] once the absolute deadline passes.
    pub(crate) fn read_response(&mut self) -> Result<RawResponse, HttpError> {
        if self.outstanding_requests == 0 {
            return Err(HttpError::Framing(
                "no request is outstanding on this connection",
            ));
        }
        // Status line.
        let status_line = self.read_bounded_line(MAX_STATUS_LINE_BYTES)?;
        let (version, status, reason) = parse_status_line(&status_line)?;
        // Header block.
        let mut headers = Vec::new();
        loop {
            if headers.len() >= MAX_RESPONSE_HEADERS {
                return Err(HttpError::Framing("too many response headers"));
            }
            let line = self.read_bounded_line(MAX_HEADER_LINE_BYTES)?;
            if line.is_empty() {
                break;
            }
            let Some((name, value)) = line.split_once(':') else {
                return Err(HttpError::Framing("malformed header line"));
            };
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
        // Conflicting or chunked framing is refused outright.
        if headers.iter().any(|(name, _)| name == "transfer-encoding") {
            return Err(HttpError::Framing(
                "transfer-encoding is refused; only Content-Length framing is accepted",
            ));
        }
        let content_length = parse_content_length(&headers, status)?;
        let mut body = vec![0_u8; content_length];
        self.read_exact_deadlined(&mut body)?;
        self.outstanding_requests -= 1;
        Ok(RawResponse {
            version: version.to_owned(),
            status,
            reason,
            headers,
            body,
        })
    }

    /// Reads one CRLF-terminated line bounded by `ceiling` actual bytes,
    /// through the retained buffer. A bare-LF line (no carriage return) is
    /// a framing violation.
    fn read_bounded_line(&mut self, ceiling: u64) -> Result<String, HttpError> {
        let mut line = Vec::new();
        loop {
            let byte = self.read_byte()?;
            if byte == b'\n' {
                if line.last() != Some(&b'\r') {
                    return Err(HttpError::Framing("lines must end with CRLF"));
                }
                line.pop();
                return String::from_utf8(line)
                    .map_err(|_| HttpError::Framing("header block is not valid utf-8"));
            }
            if u64::try_from(line.len()).unwrap_or(u64::MAX) >= ceiling {
                return Err(HttpError::Framing(
                    "line exceeded the declared byte ceiling",
                ));
            }
            line.push(byte);
        }
    }
}

/// Parses one exact `HTTP/1.1` status line: version, exactly three ASCII
/// digits, one space, and the reason phrase.
fn parse_status_line(line: &str) -> Result<(&'static str, u16, String), HttpError> {
    const VERSION: &str = "HTTP/1.1";
    let Some(rest) = line.strip_prefix(VERSION) else {
        return Err(HttpError::Framing("only HTTP/1.1 responses are accepted"));
    };
    let Some(rest) = rest.strip_prefix(' ') else {
        return Err(HttpError::Framing("malformed status line separator"));
    };
    let (code, reason) = rest
        .split_once(' ')
        .ok_or(HttpError::Framing("malformed status line"))?;
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HttpError::Framing("status code must be three ASCII digits"));
    }
    let status = code
        .parse::<u16>()
        .map_err(|_| HttpError::Framing("status code must be three ASCII digits"))?;
    Ok((VERSION, status, reason.to_owned()))
}

/// Resolves the body length strictly: 204 omits `Content-Length` and has zero
/// bytes; other responses require one ASCII-decimal value. Duplicate, invalid,
/// or oversized declarations are refused before any allocation.
fn parse_content_length(headers: &[(String, String)], status: u16) -> Result<usize, HttpError> {
    let declared: Vec<&str> = headers
        .iter()
        .filter(|(name, _)| name == "content-length")
        .map(|(_, value)| value.as_str())
        .collect();
    if status == 204 {
        return if declared.is_empty() {
            Ok(0)
        } else {
            Err(HttpError::Framing(
                "204 response must not carry Content-Length",
            ))
        };
    }
    match declared.as_slice() {
        [] => Err(HttpError::Framing(
            "response without a Content-Length header",
        )),
        [single] => {
            if single.is_empty() || !single.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(HttpError::Framing(
                    "Content-Length must be ASCII digits only",
                ));
            }
            let length: usize = single
                .parse()
                .map_err(|_| HttpError::Framing("Content-Length above addressable size"))?;
            if length > MAX_RESPONSE_BODY_BYTES {
                return Err(HttpError::Framing(
                    "Content-Length above the production body ceiling",
                ));
            }
            Ok(length)
        }
        [..] => Err(HttpError::Framing("duplicate Content-Length headers")),
    }
}

/// Waits for the replay server port to accept connections before the gate
/// issues its first request; bounded by [`CONNECT_TIMEOUT`].
///
/// # Errors
/// Propagates the last connect failure once the deadline passes.
pub(crate) fn wait_for_server(address: SocketAddr) -> Result<(), HttpError> {
    let deadline = std::time::Instant::now() + CONNECT_TIMEOUT;
    loop {
        match TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(HttpError::Io(error)),
        }
    }
}

#[cfg(test)]
mod negative_probes {
    //! Negative framing probes: a stub listener serves canned responses and
    //! the decoder must refuse exactly the violated rule. Helpers return
    //! results instead of panicking; an assertion failure surfaces through
    //! the returned error or a `panic!` with the divergent verdict.

    use super::*;
    use std::net::TcpListener;

    /// Serves `response` once on a fresh loopback port and returns it.
    fn stub(response: &str) -> Result<SocketAddr, HttpError> {
        let response = response.to_owned();
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut stream = stream;
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });
        Ok(address)
    }

    /// Serves nothing at all: the absolute-deadline probe.
    fn silent_stub() -> Result<SocketAddr, HttpError> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut stream = stream;
            // One header byte every four seconds: every individual read is
            // well inside any inactivity window, so only the absolute
            // deadline can end the exchange.
            for byte in b"HTTP/1.1 200 OK\r\n" {
                let _ = stream.write_all(std::slice::from_ref(byte));
                let _ = stream.flush();
                std::thread::sleep(Duration::from_secs(4));
            }
        });
        Ok(address)
    }

    /// Drains two pipelined requests and only then writes both responses
    /// plus trailing garbage in one go: the server coalesces its replies
    /// after the client has actually issued the second request.
    fn pipelined_stub(first: &str, second: &str, trailing: &str) -> Result<SocketAddr, HttpError> {
        let canned = format!("{first}{second}{trailing}");
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        std::thread::spawn(move || {
            use std::io::BufRead;
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let Ok(mut reader) = stream.try_clone().map(std::io::BufReader::new) else {
                return;
            };
            let mut stream = stream;
            for _ in 0..2 {
                // Drain one request: headers, then exactly its declared
                // body length. A read error or EOF aborts the stub; the
                // blank line only ends the header block.
                let mut content_length = 0_usize;
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line
                        .to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                    {
                        if let Ok(parsed) = value.parse() {
                            content_length = parsed;
                        }
                    }
                }
                if content_length > 0 {
                    let mut body = vec![0_u8; content_length];
                    if reader.read_exact(&mut body).is_err() {
                        return;
                    }
                }
            }
            // Both requests are fully drained: only now are the coalesced
            // responses written. The stub then drains the client side until
            // EOF, so the connection never closes while a decode is in
            // flight — no fixed sleep, no race.
            let _ = stream.write_all(canned.as_bytes());
            let _ = stream.flush();
            let mut sink = [0_u8; 512];
            while let Ok(n @ 1..) = reader.read(&mut sink) {
                let _ = n;
            }
        });
        Ok(address)
    }

    /// A minimal well-formed request: the stubs only need the connection to
    /// have an outstanding request before the decoder will read.
    fn probe_request() -> Vec<u8> {
        RawRequest {
            path: "/",
            authorization: None,
            body: "{}".to_owned(),
            keep_alive: true,
        }
        .bytes()
    }

    fn decode(address: SocketAddr) -> Result<RawResponse, HttpError> {
        let mut connection = Connection::connect(address)?;
        connection.send_request_fragmented(&probe_request(), None)?;
        connection.read_response()
    }

    #[test]
    fn http_1_0_is_refused() -> Result<(), HttpError> {
        let response = "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        match decode(stub(response)?) {
            Err(HttpError::Framing(why)) => {
                assert!(why.contains("HTTP/1.1"), "{why}");
                Ok(())
            }
            other => panic!("expected framing refusal, got {other:?}"),
        }
    }

    #[test]
    fn transfer_encoding_is_refused() -> Result<(), HttpError> {
        let response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n";
        match decode(stub(response)?) {
            Err(HttpError::Framing(why)) => {
                assert!(why.contains("transfer-encoding"), "{why}");
                Ok(())
            }
            other => panic!("expected framing refusal, got {other:?}"),
        }
    }

    #[test]
    fn bare_lf_line_terminators_are_refused() -> Result<(), HttpError> {
        let response = "HTTP/1.1 200 OK\nContent-Length: 2\r\n\r\n{}";
        match decode(stub(response)?) {
            Err(HttpError::Framing(why)) => {
                assert!(why.contains("CRLF"), "{why}");
                Ok(())
            }
            other => panic!("expected framing refusal, got {other:?}"),
        }
    }

    #[test]
    fn non_digit_content_length_is_refused() -> Result<(), HttpError> {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\n{}";
        match decode(stub(response)?) {
            Err(HttpError::Framing(why)) => {
                assert!(why.contains("ASCII digits"), "{why}");
                Ok(())
            }
            other => panic!("expected framing refusal, got {other:?}"),
        }
    }

    #[test]
    fn content_length_on_no_content_is_refused() -> Result<(), HttpError> {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
        match decode(stub(response)?) {
            Err(HttpError::Framing(why)) => {
                assert!(why.contains("204 response"), "{why}");
                Ok(())
            }
            other => panic!("expected 204 framing refusal, got {other:?}"),
        }
    }

    #[test]
    fn malformed_status_digits_are_refused() -> Result<(), HttpError> {
        let response = "HTTP/1.1 2000 OK\r\nContent-Length: 0\r\n\r\n";
        match decode(stub(response)?) {
            Err(HttpError::Framing(why)) => {
                assert!(why.contains("three ASCII digits"), "{why}");
                Ok(())
            }
            other => panic!("expected framing refusal, got {other:?}"),
        }
    }

    /// Reading without an outstanding request is refused: retained
    /// pipelined or trailing bytes can never be mistaken for a response.
    #[test]
    fn read_without_outstanding_request_is_refused() -> Result<(), HttpError> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        std::thread::spawn(move || {
            let Ok((_stream, _)) = listener.accept() else {
                return;
            };
        });
        let mut connection = Connection::connect(address)?;
        match connection.read_response() {
            Err(HttpError::Framing(why)) => {
                assert!(why.contains("no request is outstanding"), "{why}");
                Ok(())
            }
            other => panic!("expected outstanding-request refusal, got {other:?}"),
        }
    }

    /// The client issues TWO requests back-to-back; only then does the
    /// server coalesce both responses plus trailing garbage into one write.
    /// The first decode consumes its status-defined empty body, the second
    /// consumes its declared bytes from the retained buffer, and the leftover
    /// garbage is refused once no further request is outstanding.
    #[test]
    fn retained_buffer_carries_pipelined_response_and_rejects_trailing_bytes()
    -> Result<(), HttpError> {
        let first = "HTTP/1.1 204 No Content\r\n\r\n";
        let second = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        let trailing = "TRAILING";
        let address = pipelined_stub(first, second, trailing)?;
        let mut connection = Connection::connect(address)?;
        // Both requests are issued before any response is read: the server
        // may legitimately coalesce its replies from here on.
        connection.send_request_fragmented(&probe_request(), None)?;
        connection.send_request_fragmented(&probe_request(), None)?;
        let decoded_first = connection.read_response()?;
        assert_eq!(decoded_first.status, 204);
        // The second response decodes purely from bytes retained in the
        // connection buffer, paid for by the second request.
        let decoded_second = connection.read_response()?;
        assert_eq!(decoded_second.status, 200);
        assert_eq!(decoded_second.body, b"{}");
        // Both outstanding requests are now settled: the trailing garbage
        // must be refused, never served as a response.
        match connection.read_response() {
            Err(HttpError::Framing(why)) => {
                assert!(why.contains("no request is outstanding"), "{why}");
                Ok(())
            }
            other => panic!("expected trailing-byte refusal, got {other:?}"),
        }
    }

    /// The slow-drip peer: every single read stays inside the inactivity
    /// window, so only the absolute per-connection deadline can end it. The
    /// injected short deadline proves the property in well under a second
    /// and asserts an upper bound, not merely that time passed.
    #[test]
    fn slow_drip_peer_hits_the_absolute_deadline() -> Result<(), HttpError> {
        let address = silent_stub()?;
        let injected = Duration::from_millis(700);
        let upper_bound = Duration::from_secs(5);
        let started = Instant::now();
        let mut connection = Connection::connect_with_deadline(address, injected)?;
        connection.send_request_fragmented(&probe_request(), None)?;
        match connection.read_response() {
            Err(HttpError::DeadlineExceeded) => {
                let elapsed = started.elapsed();
                assert!(
                    elapsed >= injected,
                    "deadline fired at {elapsed:?}, before the injected {injected:?}"
                );
                assert!(
                    elapsed < upper_bound,
                    "deadline took {elapsed:?}, above the {upper_bound:?} bound: the \
                     deadline is not absolute"
                );
                Ok(())
            }
            other => panic!("expected deadline expiry, got {other:?}"),
        }
    }
}
