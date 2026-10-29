//! One HTTP/1.1 transport for every harness request to a node listener: the

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use sonic_rs::Value;

use crate::error::{Error, Result};
use crate::node::HttpResponse;

const MAX_BODY: usize = 64 * 1024 * 1024;

enum ConnFail {
    Stale,
    Error(Error),
}

#[derive(Debug)]
pub struct Connection {
    addr: SocketAddr,
    conn: Option<BufReader<TcpStream>>,
}

impl Connection {
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr, conn: None }
    }

    pub fn rpc(&mut self, request: &Value, auth: (&str, &str), deadline: Instant) -> Result<Value> {
        let wire = request_wire(self.addr, request, Some(auth))?;
        let response = self.round_trip(&wire, deadline)?;
        response.json()
    }

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
                self.conn = None;
                Err(error)
            }
        }
    }

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
            Some(length) if length > MAX_BODY => {
                return Err(ConnFail::Error(Error::Protocol(
                    "RPC body length exceeds the response bound".into(),
                )));
            }
            Some(length) => length,
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

pub fn exchange(addr: SocketAddr, request: &Value, deadline: Instant) -> Result<Value> {
    let wire = request_wire(addr, request, Some(("parity", "parity")))?;
    let remaining = || remaining_time(deadline, Instant::now(), "RPC deadline reached");
    let mut stream = TcpStream::connect_timeout(&addr, remaining()?.min(Duration::from_secs(2)))?;
    stream.set_nonblocking(true).map_err(Error::Io)?;
    let mut pending = wire.as_slice();
    while !pending.is_empty() {
        remaining()?;
        match stream.write(pending) {
            Ok(0) => return Err(Error::Protocol("closed HTTP writer".into())),
            Ok(written) => {
                pending = pending
                    .get(written..)
                    .ok_or_else(|| Error::Protocol("invalid write size".into()))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        remaining()?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                if bytes.len().saturating_add(count) > MAX_BODY {
                    return Err(Error::Protocol("RPC response bound exceeded".into()));
                }
                bytes.extend_from_slice(
                    chunk
                        .get(..count)
                        .ok_or_else(|| Error::Protocol("invalid read size".into()))?,
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
    let response = parse_reply(&bytes)?;
    remaining()?;
    response.json()
}

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

fn request_wire(addr: SocketAddr, request: &Value, auth: Option<(&str, &str)>) -> Result<Vec<u8>> {
    let body = sonic_rs::to_vec(request)?;
    http_wire(addr, "POST", "/", &body, auth)
}

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
