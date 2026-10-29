//! Minimal SOCKS5 client (RFC 1928, username/password auth per RFC 1929).

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use bitcoin::secp256k1::rand::{RngCore, thread_rng};

use crate::endpoint::DialFailure;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SocksTarget {
    Ip(SocketAddr),
    Domain(String, u16),
}

fn remaining_timeout(deadline: Instant) -> io::Result<Duration> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(rem) if !rem.is_zero() => Ok(rem),
        _ => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "socks exchange deadline expired",
        )),
    }
}

fn write_all_deadline(stream: &mut TcpStream, mut buf: &[u8], deadline: Instant) -> io::Result<()> {
    while !buf.is_empty() {
        let rem = remaining_timeout(deadline)?;
        stream.set_write_timeout(Some(rem))?;
        match stream.write(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write whole buffer to socks proxy",
                ));
            }
            Ok(n) => {
                buf = &buf[n..];
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn read_exact_deadline(
    stream: &mut TcpStream,
    mut buf: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !buf.is_empty() {
        let rem = remaining_timeout(deadline)?;
        stream.set_read_timeout(Some(rem))?;
        match stream.read(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "socks proxy closed the connection during handshake",
                ));
            }
            Ok(n) => {
                let tmp = buf;
                buf = &mut tmp[n..];
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

const CREDENTIAL_LEN: u8 = 16;
const AUTH_LEN: usize = 3 + 16 * 2;

fn random_credentials() -> ([u8; 16], [u8; 16]) {
    const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = [0u8; 32];
    thread_rng().fill_bytes(&mut bytes);
    let mut user = [0u8; 16];
    let mut password = [0u8; 16];
    for (i, b) in bytes[..16].iter().enumerate() {
        user[i] = BASE32[usize::from(b & 31)];
    }
    for (i, b) in bytes[16..].iter().enumerate() {
        password[i] = BASE32[usize::from(b & 31)];
    }
    (user, password)
}

fn authenticate_isolated(stream: &mut TcpStream, deadline: Instant) -> Result<(), DialFailure> {
    write_all_deadline(stream, &[0x05, 0x01, 0x02], deadline)?;
    let mut selection = [0u8; 2];
    read_exact_deadline(stream, &mut selection, deadline)?;
    if selection[0] != 0x05 {
        return Err(DialFailure::Transport(invalid(
            "socks greeting reply has wrong version",
        )));
    }
    match selection[1] {
        0x00 => Err(DialFailure::Transport(invalid(
            "socks proxy selected no-authentication for an isolation-required dial",
        ))),
        0x02 => {
            let (user, password) = random_credentials();
            let mut auth = [0u8; AUTH_LEN];
            auth[0] = 0x01;
            auth[1] = CREDENTIAL_LEN;
            auth[2..18].copy_from_slice(&user);
            auth[18] = CREDENTIAL_LEN;
            auth[19..35].copy_from_slice(&password);
            write_all_deadline(stream, &auth, deadline)?;
            let mut reply = [0u8; 2];
            read_exact_deadline(stream, &mut reply, deadline)?;
            if reply != [0x01, 0x00] {
                return Err(DialFailure::Transport(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "socks username/password authentication failed",
                )));
            }
            Ok(())
        }
        _ => Err(DialFailure::Transport(invalid(
            "socks proxy selected an unsupported authentication method",
        ))),
    }
}

fn authenticate_no_auth(stream: &mut TcpStream, deadline: Instant) -> Result<(), DialFailure> {
    write_all_deadline(stream, &[0x05, 0x01, 0x00], deadline)?;
    let mut selection = [0u8; 2];
    read_exact_deadline(stream, &mut selection, deadline)?;
    if selection != [0x05, 0x00] {
        return Err(DialFailure::Transport(invalid(
            "socks proxy refused no-authentication",
        )));
    }
    Ok(())
}

fn read_connect_reply(stream: &mut TcpStream, deadline: Instant) -> Result<(), DialFailure> {
    let mut head = [0u8; 4];
    read_exact_deadline(stream, &mut head, deadline)?;
    if head[0] != 0x05 {
        return Err(DialFailure::Transport(invalid(
            "socks connect reply has wrong version",
        )));
    }
    if head[2] != 0x00 {
        return Err(DialFailure::Transport(invalid(
            "socks connect reply has nonzero reserved byte",
        )));
    }
    if head[1] != 0x00 {
        let error = io::Error::new(
            reply_kind(head[1]),
            format!("socks connect failed with reply code {}", head[1]),
        );
        return Err(match head[1] {
            0x05 => DialFailure::PeerUnreachable(error),
            _ => DialFailure::Transport(error),
        });
    }
    let bound_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            read_exact_deadline(stream, &mut len, deadline)?;
            usize::from(len[0])
        }
        _ => {
            return Err(DialFailure::Transport(invalid(
                "socks connect reply has unknown address type",
            )));
        }
    };
    let mut bound = vec![0u8; bound_len + 2];
    read_exact_deadline(stream, &mut bound, deadline)?;
    Ok(())
}

pub(crate) fn socks_connect(
    proxy: SocketAddr,
    target: &SocksTarget,
    isolate: bool,
    timeout: Duration,
) -> Result<TcpStream, DialFailure> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| DialFailure::Transport(invalid("socks exchange timeout overflow")))?;
    let connect_timeout = remaining_timeout(deadline).map_err(DialFailure::Transport)?;
    let mut stream =
        TcpStream::connect_timeout(&proxy, connect_timeout).map_err(DialFailure::Transport)?;
    let _ = stream.set_nodelay(true);

    if isolate {
        authenticate_isolated(&mut stream, deadline)?;
    } else {
        authenticate_no_auth(&mut stream, deadline)?;
    }

    let mut request = vec![0x05, 0x01, 0x00];
    match target {
        SocksTarget::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
        },
        SocksTarget::Domain(host, _) => {
            let bytes = host.as_bytes();
            let len = u8::try_from(bytes.len()).map_err(|_| {
                DialFailure::Transport(invalid("socks domain name exceeds 255 bytes"))
            })?;
            request.push(0x03);
            request.push(len);
            request.extend_from_slice(bytes);
        }
    }
    let port = match target {
        SocksTarget::Ip(addr) => addr.port(),
        SocksTarget::Domain(_, port) => *port,
    };
    request.extend_from_slice(&port.to_be_bytes());
    write_all_deadline(&mut stream, &request, deadline)?;

    read_connect_reply(&mut stream, deadline)?;

    stream
        .set_read_timeout(None)
        .map_err(DialFailure::Transport)?;
    stream
        .set_write_timeout(None)
        .map_err(DialFailure::Transport)?;
    Ok(stream)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn reply_kind(code: u8) -> io::ErrorKind {
    match code {
        0x02 => io::ErrorKind::PermissionDenied,
        0x03 | 0x04 => io::ErrorKind::NetworkUnreachable,
        0x05 => io::ErrorKind::ConnectionRefused,
        0x06 => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::ConnectionAborted,
    }
}

#[cfg(test)]
mod tests;
