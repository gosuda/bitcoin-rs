//! One HTTP/1.1 transport for every harness request to a node listener.
//!
//! PRE: the address given to [`Connection::new`] is the RPC/REST/Esplora
//! loopback endpoint a spawned node bound.
//! POST: every returned value was parsed from one complete HTTP/1.1 reply
//! with a valid status line and a body whose length matches its
//! `Content-Length`.
//! INVARIANT: a request that reached the peer's dispatch is never resent.
//! Only a socket provably closed or broken before any request byte could
//! have been processed is retried, and at most once per call.
//!
//! This module owns the keep-alive connection, the strict reply parser, the
//! request wire builder, and the Basic-authorization encoder. Callers supply
//! method, path, body bytes, and credentials; nothing else in the workspace
//! builds an HTTP request by hand.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::error::{Error, Result};
use crate::node::HttpResponse;

/// Bound on a request or response body the transport reads or writes.
const MAX_BODY: usize = 64 * 1024 * 1024;

/// Transport outcome for the cached socket. `Stale` means the request
/// provably never reached the server, so one resend on a fresh socket is
/// safe; anything else is surfaced as the original harness error.
enum ConnFail {
    Stale,
    Error(Error),
}

/// A persistent HTTP/1.1 connection to one node listener.
///
/// PRE: the node is listening on `addr` (readiness already observed, or the
/// caller accepts a connect failure).
/// POST: the kept-alive socket holds no unread reply bytes.
/// INVARIANT: a socket whose peer closed it is dropped before any request
/// byte leaves the client, so a retry always runs on a fresh connection.
#[derive(Debug)]
pub struct Connection {
    addr: SocketAddr,
    conn: Option<BufReader<TcpStream>>,
}

impl Connection {
    /// Opens no socket: the first request connects lazily and every later
    /// request reuses the keep-alive connection until it closes.
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr, conn: None }
    }

    /// POST one pre-built JSON-RPC envelope to `/` and return the parsed
    /// envelope. Error conversion into [`Error::Rpc`] is the caller's policy.
    ///
    /// PRE: `request` is a complete JSON-RPC envelope.
    /// POST: the reply parsed as a JSON value, or the call failed.
    pub fn rpc(&mut self, request: &Value, auth: (&str, &str), deadline: Instant) -> Result<Value> {
        let wire = request_wire(self.addr, request, Some(auth))?;
        let response = self.round_trip(&wire, deadline)?;
        response.json()
    }

    /// Send one HTTP request and return the parsed reply.
    ///
    /// PRE: `path` begins with `/`; `body` fits [`MAX_BODY`].
    /// POST: the reply carries a validated status line, lower-cased headers,
    /// and exactly `Content-Length` body bytes.
    /// INVARIANT: non-2xx replies are returned, not converted to errors;
    /// only protocol and transport violations fail the call.
    pub fn http(
        &mut self,
        method: &str,
        path: &str,
        body: &[u8],
        auth: Option<(&str, &str)>,
        deadline: Instant,
    ) -> Result<HttpResponse> {
        let wire = http_wire(self.addr, method, path, body, auth)?;
        self.round_trip(&wire, deadline)
    }

    /// One round trip on the cached connection, reconnecting once when the
    /// socket is stale (idle close) or the exchange never reached dispatch.
    /// A request that reached the server is never resent: admission calls
    /// are not idempotent from the caller's view.
    fn round_trip(&mut self, wire: &[u8], deadline: Instant) -> Result<HttpResponse> {
        match self.try_round_trip(wire, deadline) {
            Ok(response) => Ok(response),
            Err(ConnFail::Stale) => {
                self.conn = None;
                self.try_round_trip(wire, deadline)
                    .map_err(|fail| match fail {
                        ConnFail::Stale => Error::Protocol("RPC socket failed twice".into()),
                        ConnFail::Error(error) => error,
                    })
            }
            Err(ConnFail::Error(error)) => {
                // A hard failure may leave an in-flight request on the
                // socket: drop it so a later call cannot be pipelined or
                // answered with the wrong response.
                self.conn = None;
                Err(error)
            }
        }
    }

    /// Ensures `conn` holds a socket the peer has not already closed:
    /// connects when absent, probes a reused socket for an idle close before
    /// any request bytes leave the client (`Stale` means safe to reconnect).
    fn live_conn(&mut self, deadline: Instant) -> std::result::Result<(), ConnFail> {
        let fresh = if self.conn.is_none() {
            let stream = TcpStream::connect_timeout(
                &self.addr,
                remaining_time(deadline, Instant::now(), "RPC deadline reached")
                    .map_err(ConnFail::Error)?
                    .min(Duration::from_secs(1)),
            )
            .map_err(|_| ConnFail::Stale)?;
            self.conn = Some(BufReader::new(stream));
            true
        } else {
            false
        };
        if !fresh && idle_closed(self.conn.as_ref().ok_or(ConnFail::Stale)?.get_ref()) {
            return Err(ConnFail::Stale);
        }
        Ok(())
    }

    /// One request/response exchange on the cached socket. `Stale` marks a
    /// socket that closed or broke before the request could have been
    /// dispatched (idle close, dead peer), so re-sending once is safe.
    fn try_round_trip(
        &mut self,
        wire: &[u8],
        deadline: Instant,
    ) -> std::result::Result<HttpResponse, ConnFail> {
        let remaining = || remaining_time(deadline, Instant::now(), "RPC deadline reached");
        self.live_conn(deadline)?;
        let conn = self.conn.as_mut().ok_or(ConnFail::Stale)?;
        conn.get_ref()
            .set_write_timeout(Some(remaining().map_err(ConnFail::Error)?))
            .map_err(|_| ConnFail::Stale)?;
        // A failed write() transferred zero bytes, so resending is safe.
        // Any partial send is not: the peer may hold a request prefix.
        let sent = conn.get_mut().write(wire).map_err(|_| ConnFail::Stale)?;
        if sent == 0 {
            return Err(ConnFail::Stale);
        }
        conn.get_mut()
            .write_all(&wire[sent..])
            .map_err(Error::Io)
            .map_err(ConnFail::Error)?;
        let mut head = Vec::new();
        loop {
            let mut line = Vec::new();
            conn.get_ref()
                .set_read_timeout(Some(remaining().map_err(ConnFail::Error)?))
                .map_err(Error::Io)
                .map_err(ConnFail::Error)?;
            let count = conn.read_until(b'\n', &mut line).map_err(|error| {
                if head.is_empty() && socket_closed(&error) {
                    ConnFail::Stale
                } else {
                    ConnFail::Error(Error::Io(error))
                }
            })?;
            if count == 0 {
                // serve_connection writes a response before every close it
                // initiates, so zero response bytes prove this request never
                // reached dispatch: re-sending once is safe (a dead daemon
                // fails the reconnect instead). Mid-headers EOF is
                // ambiguous and is never retried.
                return Err(if head.is_empty() {
                    ConnFail::Stale
                } else {
                    ConnFail::Error(Error::Protocol("connection closed mid-headers".into()))
                });
            }
            head.extend_from_slice(&line);
            if head.len() > MAX_BODY {
                return Err(ConnFail::Error(Error::Protocol(
                    "RPC response bound exceeded".into(),
                )));
            }
            if line == b"\r\n" {
                break;
            }
        }
        let (status, headers, content_length, peer_close) =
            parse_reply_head(&head).map_err(ConnFail::Error)?;
        let content_length = match content_length {
            // The head bound covers header bytes only; a corrupt peer could
            // advertise an arbitrary length and drive an unbounded
            // allocation, so bound it before the buffer exists.
            Some(length) if length > MAX_BODY => {
                return Err(ConnFail::Error(Error::Protocol(
                    "RPC body length exceeds the response bound".into(),
                )));
            }
            Some(length) => length,
            // A 1xx, 204, or 304 reply carries no body and may omit
            // Content-Length; any other framing-less reply is a protocol
            // violation on a keep-alive connection.
            None if matches!(status, 100..=199 | 204 | 304) => 0,
            None => {
                return Err(ConnFail::Error(Error::Protocol(
                    "missing HTTP content length".into(),
                )));
            }
        };
        let mut body = vec![0_u8; content_length];
        conn.get_ref()
            .set_read_timeout(Some(remaining().map_err(ConnFail::Error)?))
            .map_err(Error::Io)
            .map_err(ConnFail::Error)?;
        conn.read_exact(&mut body)
            .map_err(Error::Io)
            .map_err(ConnFail::Error)?;
        if peer_close {
            self.conn = None;
        }
        remaining().map_err(ConnFail::Error)?;
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// One-shot JSON-RPC exchange: connect, send, read to EOF, close.
///
/// PRE: `addr` accepts a TCP connection before `deadline`.
/// POST: the returned value is the parsed reply body.
/// INVARIANT: the total deadline bounds connect, every write, and every
/// read; a peer that dribbles bytes cannot renew it.
pub fn exchange(addr: SocketAddr, request: &Value, deadline: Instant) -> Result<Value> {
    let wire = request_wire(addr, request, Some(("parity", "parity")))?;
    let remaining = || remaining_time(deadline, Instant::now(), "RPC deadline reached");
    let mut stream = TcpStream::connect_timeout(&addr, remaining()?.min(Duration::from_secs(2)))?;
    let mut pending = wire.as_slice();
    while !pending.is_empty() {
        stream.set_write_timeout(Some(remaining()?))?;
        let written = stream.write(pending)?;
        if written == 0 {
            return Err(Error::Protocol("closed HTTP writer".into()));
        }
        pending = pending
            .get(written..)
            .ok_or_else(|| Error::Protocol("invalid write size".into()))?;
    }
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        stream.set_read_timeout(Some(remaining()?))?;
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        if bytes.len().saturating_add(count) > MAX_BODY {
            return Err(Error::Protocol("RPC response bound exceeded".into()));
        }
        bytes.extend_from_slice(
            chunk
                .get(..count)
                .ok_or_else(|| Error::Protocol("invalid read size".into()))?,
        );
    }
    let response = parse_reply(&bytes)?;
    remaining()?;
    response.json()
}

/// Time left before `deadline`, or a protocol failure naming `message`.
pub(crate) fn remaining_time(
    deadline: Instant,
    now: Instant,
    message: &'static str,
) -> Result<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|time| *time >= Duration::from_micros(1))
        .ok_or_else(|| Error::Protocol(message.to_owned()))
}

/// Builds the wire bytes for one JSON-RPC POST to `/`.
fn request_wire(addr: SocketAddr, request: &Value, auth: Option<(&str, &str)>) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(request)?;
    http_wire(addr, "POST", "/", &body, auth)
}

/// Builds one HTTP/1.1 keep-alive request. `keep-alive` asks the peer to
/// hold the socket so the harness can reuse it across calls instead of
/// paying a fresh accept-poll per request.
fn http_wire(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
    auth: Option<(&str, &str)>,
) -> Result<Vec<u8>> {
    let mut wire = Vec::new();
    write!(wire, "{method} {path} HTTP/1.1\r\nHost: {addr}\r\n")?;
    if let Some((user, password)) = auth {
        let token = base64(format!("{user}:{password}").as_bytes());
        write!(wire, "Authorization: Basic {token}\r\n")?;
    }
    if !body.is_empty() {
        write!(wire, "Content-Type: application/json\r\n")?;
    }
    write!(
        wire,
        "Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    )?;
    wire.extend_from_slice(body);
    if wire.len() > MAX_BODY {
        return Err(Error::Protocol("HTTP request byte limit".into()));
    }
    Ok(wire)
}

/// Validates the head of a complete reply and splits its parts.
///
/// INVARIANT: duplicate `Content-Length`, any `Transfer-Encoding`, a
/// non-HTTP/1.x version, and a status code outside 100..=599 are protocol
/// failures; header names come back lower-cased.
/// The parts of a reply head: status code, lower-cased headers, declared
/// body length, and whether the peer announced a close.
type ReplyHeadParts = (u16, Vec<(String, String)>, Option<usize>, bool);

fn parse_reply_head(head: &[u8]) -> Result<ReplyHeadParts> {
    let text = std::str::from_utf8(head)
        .map_err(|error| Error::Protocol(format!("invalid HTTP headers: {error}")))?;
    let mut lines = text.split("\r\n");
    let mut status_line = lines.next().unwrap_or_default().split_whitespace();
    let version = status_line.next();
    let code = status_line.next();
    if !matches!(version, Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(Error::Protocol("invalid HTTP status line".into()));
    }
    let status = code
        .filter(|code| code.len() == 3)
        .and_then(|code| code.parse::<u16>().ok())
        .filter(|code| (100..=599).contains(code))
        .ok_or_else(|| Error::Protocol("invalid HTTP status line".into()))?;
    let mut headers = Vec::new();
    let mut content_length = None;
    let mut peer_close = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| Error::Protocol("invalid HTTP header".into()))?;
        let name = name.trim().to_lowercase();
        let value = value.trim().to_owned();
        if name == "content-length" {
            let length = value
                .parse::<usize>()
                .map_err(|_| Error::Protocol("invalid HTTP content length".into()))?;
            if content_length.replace(length).is_some() {
                return Err(Error::Protocol("duplicate HTTP content length".into()));
            }
        }
        if name == "transfer-encoding" {
            return Err(Error::Protocol("unsupported HTTP transfer encoding".into()));
        }
        if name == "connection" && value.eq_ignore_ascii_case("close") {
            peer_close = true;
        }
        headers.push((name, value));
    }
    Ok((status, headers, content_length, peer_close))
}

/// Parses a complete reply (head plus body bytes) into an HTTP response.
fn parse_reply(bytes: &[u8]) -> Result<HttpResponse> {
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| Error::Protocol("missing HTTP header terminator".into()))?;
    let head = bytes
        .get(..split)
        .ok_or_else(|| Error::Protocol("invalid header split".into()))?;
    let (status, headers, content_length, _) = parse_reply_head(head)?;
    let payload = bytes
        .get(split.saturating_add(4)..)
        .ok_or_else(|| Error::Protocol("missing HTTP body".into()))?;
    if content_length.is_some_and(|length| length != payload.len()) {
        return Err(Error::Protocol(
            "HTTP content length differs from body".into(),
        ));
    }
    Ok(HttpResponse {
        status,
        headers,
        body: payload.to_vec(),
    })
}

/// Reports whether a kept-alive socket was already closed (or desynced) on
/// the peer side. A non-blocking peek sees the close before any request
/// bytes are sent, which makes reconnecting unambiguously safe.
fn idle_closed(stream: &TcpStream) -> bool {
    if stream.set_nonblocking(true).is_err() {
        return true;
    }
    let stale = !matches!(
        stream.peek(&mut [0_u8; 1]),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    );
    if stream.set_nonblocking(false).is_err() {
        return true;
    }
    stale
}

/// Socket-close errors proving the peer tore the connection down.
/// WouldBlock/TimedOut are absent: an alive-but-slow peer means the request
/// may still be in flight server-side, so those stay non-retryable.
fn socket_closed(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::NotConnected
    )
}

/// Standard base64: the Basic authorization encoder for every harness
/// credential. The wire never carries a hardcoded credential literal.
fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = usize::from(chunk[0]);
        let b1 = usize::from(*chunk.get(1).unwrap_or(&0));
        let b2 = usize::from(*chunk.get(2).unwrap_or(&0));
        out.push(char::from(TABLE[b0 >> 2]));
        out.push(char::from(TABLE[((b0 & 3) << 4) | (b1 >> 4)]));
        out.push(if chunk.len() > 1 {
            char::from(TABLE[((b1 & 15) << 2) | (b2 >> 6)])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(TABLE[b2 & 63])
        } else {
            '='
        });
    }
    out
}
