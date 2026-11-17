#![cfg_attr(not(feature = "fuzzing"), allow(unreachable_pub))]

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

pub fn parse_isolated_greeting(selection: [u8; 2]) -> Result<u8, DialFailure> {
    if selection[0] != 0x05 {
        return Err(DialFailure::Transport(invalid(
            "socks greeting reply has wrong version",
        )));
    }
    match selection[1] {
        0x00 => Err(DialFailure::Transport(invalid(
            "socks proxy selected no-authentication for an isolation-required dial",
        ))),
        0x02 => Ok(selection[1]),
        _ => Err(DialFailure::Transport(invalid(
            "socks proxy selected an unsupported authentication method",
        ))),
    }
}

pub fn parse_no_auth_greeting(selection: [u8; 2]) -> Result<u8, DialFailure> {
    if selection[0] != 0x05 {
        return Err(DialFailure::Transport(invalid(
            "socks greeting reply has wrong version",
        )));
    }
    if selection != [0x05, 0x00] {
        return Err(DialFailure::Transport(invalid(
            "socks proxy refused no-authentication",
        )));
    }
    Ok(selection[1])
}

pub fn parse_auth_reply(reply: [u8; 2]) -> Result<(), DialFailure> {
    if reply != [0x01, 0x00] {
        return Err(DialFailure::Transport(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks username/password authentication failed",
        )));
    }
    Ok(())
}

#[cfg_attr(not(feature = "fuzzing"), allow(dead_code))]
pub fn parse_connect_reply<R: Read>(reader: &mut R) -> Result<(), DialFailure> {
    let mut head = [0u8; 4];
    reader
        .read_exact(&mut head)
        .map_err(DialFailure::Transport)?;
    let bound_len = validate_connect_head(head)?;
    let bound_len = if let Some(len) = bound_len {
        len
    } else {
        let mut len = [0u8; 1];
        reader
            .read_exact(&mut len)
            .map_err(DialFailure::Transport)?;
        usize::from(len[0])
    };
    let mut bound = vec![0u8; bound_len + 2];
    reader
        .read_exact(&mut bound)
        .map_err(DialFailure::Transport)?;
    Ok(())
}

fn validate_connect_head(head: [u8; 4]) -> Result<Option<usize>, DialFailure> {
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
    match head[3] {
        0x01 => Ok(Some(4)),
        0x04 => Ok(Some(16)),
        0x03 => Ok(None),
        _ => Err(DialFailure::Transport(invalid(
            "socks connect reply has unknown address type",
        ))),
    }
}

fn authenticate_isolated(stream: &mut TcpStream, deadline: Instant) -> Result<(), DialFailure> {
    write_all_deadline(stream, &[0x05, 0x01, 0x02], deadline)?;
    let mut selection = [0u8; 2];
    read_exact_deadline(stream, &mut selection, deadline)?;
    parse_isolated_greeting(selection)?;
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
    parse_auth_reply(reply)?;
    Ok(())
}

fn authenticate_no_auth(stream: &mut TcpStream, deadline: Instant) -> Result<(), DialFailure> {
    write_all_deadline(stream, &[0x05, 0x01, 0x00], deadline)?;
    let mut selection = [0u8; 2];
    read_exact_deadline(stream, &mut selection, deadline)?;
    parse_no_auth_greeting(selection)?;
    Ok(())
}

fn read_connect_reply(stream: &mut TcpStream, deadline: Instant) -> Result<(), DialFailure> {
    let mut head = [0u8; 4];
    read_exact_deadline(stream, &mut head, deadline)?;
    let bound_len = if let Some(len) = validate_connect_head(head)? {
        len
    } else {
        let mut len = [0u8; 1];
        read_exact_deadline(stream, &mut len, deadline)?;
        usize::from(len[0])
    };
    let mut bound = vec![0u8; bound_len + 2];
    read_exact_deadline(stream, &mut bound, deadline)?;
    Ok(())
}

pub(crate) fn socks_connect(
    proxy: SocketAddr,
    target: &SocksTarget,
    timeout: Duration,
) -> Result<TcpStream, DialFailure> {
    socks_connect_with(
        proxy,
        target,
        SocksDial {
            isolate: false,
            timeout,
            set_nodelay: &|stream| stream.set_nodelay(true),
        },
    )
}

pub(crate) fn socks_connect_isolated(
    proxy: SocketAddr,
    target: &SocksTarget,
    timeout: Duration,
) -> Result<TcpStream, DialFailure> {
    socks_connect_with(
        proxy,
        target,
        SocksDial {
            isolate: true,
            timeout,
            set_nodelay: &|stream| stream.set_nodelay(true),
        },
    )
}

struct SocksDial<'a> {
    isolate: bool,
    timeout: Duration,
    set_nodelay: &'a dyn Fn(&TcpStream) -> io::Result<()>,
}

fn socks_connect_with(
    proxy: SocketAddr,
    target: &SocksTarget,
    dial: SocksDial<'_>,
) -> Result<TcpStream, DialFailure> {
    let deadline = Instant::now()
        .checked_add(dial.timeout)
        .ok_or_else(|| DialFailure::Transport(invalid("socks exchange timeout overflow")))?;
    let connect_timeout = remaining_timeout(deadline).map_err(DialFailure::Transport)?;
    let mut stream =
        TcpStream::connect_timeout(&proxy, connect_timeout).map_err(DialFailure::Transport)?;
    let _ = (dial.set_nodelay)(&stream);

    if dial.isolate {
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
            if bytes.is_empty() {
                return Err(DialFailure::Transport(invalid(
                    "socks domain name cannot be empty",
                )));
            }
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
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn fake_socks_auth(connect_reply: u8) -> io::Result<(SocketAddr, mpsc::Receiver<Vec<u8>>)> {
        fake_socks(true, connect_reply)
    }

    fn fake_socks_no_auth(connect_reply: u8) -> io::Result<(SocketAddr, mpsc::Receiver<Vec<u8>>)> {
        fake_socks(false, connect_reply)
    }

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        AddrParse(#[from] std::net::AddrParseError),
        #[error(transparent)]
        Recv(#[from] std::sync::mpsc::RecvError),
        #[error(transparent)]
        Dial(#[from] crate::endpoint::DialFailure),
        #[error("missing: {0}")]
        Missing(&'static str),
    }

    type TestResult = Result<(), TestError>;

    fn fake_socks(
        auth_required: bool,
        connect_reply: u8,
    ) -> io::Result<(SocketAddr, mpsc::Receiver<Vec<u8>>)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut greeting = [0u8; 2];
            stream.read_exact(&mut greeting)?;
            assert_eq!(greeting[0], 0x05);
            let methods = usize::from(greeting[1]);
            let mut method_bytes = vec![0u8; methods];
            stream.read_exact(&mut method_bytes)?;
            if auth_required {
                assert!(method_bytes.contains(&0x02), "client must offer auth");
                stream.write_all(&[0x05, 0x02])?;
                let mut auth_head = [0u8; 2];
                stream.read_exact(&mut auth_head)?;
                assert_eq!(auth_head[0], 0x01);
                let mut user = vec![0u8; usize::from(auth_head[1])];
                stream.read_exact(&mut user)?;
                let mut plen = [0u8; 1];
                stream.read_exact(&mut plen)?;
                let mut pass = vec![0u8; usize::from(plen[0])];
                stream.read_exact(&mut pass)?;
                assert!(!user.is_empty() && !pass.is_empty());
                stream.write_all(&[0x01, 0x00])?;
            } else {
                stream.write_all(&[0x05, 0x00])?;
            }
            let mut head = [0u8; 4];
            stream.read_exact(&mut head)?;
            let mut rest = Vec::new();
            match head[3] {
                0x01 => {
                    let mut b = [0u8; 6];
                    stream.read_exact(&mut b)?;
                    rest.extend_from_slice(&b);
                }
                0x03 => {
                    let mut len = [0u8; 1];
                    stream.read_exact(&mut len)?;
                    rest.push(len[0]);
                    let mut b = vec![0u8; usize::from(len[0]) + 2];
                    stream.read_exact(&mut b)?;
                    rest.extend_from_slice(&b);
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected atyp {other}"),
                    ));
                }
            }
            let mut full = head.to_vec();
            full.extend_from_slice(&rest);
            let _ = tx.send(full);
            if connect_reply == 0x00 {
                stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x20, 0x8d])?;
                std::thread::sleep(Duration::from_millis(200));
            } else {
                let mut reply = vec![0x05, connect_reply, 0x00, 0x01];
                reply.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
                stream.write_all(&reply)?;
            }
            Ok(())
        });
        Ok((addr, rx))
    }

    #[test]
    fn tor_dial_uses_exact_domain_transcript() -> TestResult {
        let (proxy, rx) = fake_socks_auth(0x00)?;
        let onion = format!("{}.onion", "a".repeat(56));
        assert_eq!(onion.len(), 62);
        let stream = socks_connect_isolated(
            proxy,
            &SocksTarget::Domain(onion.clone(), 8333),
            Duration::from_secs(5),
        )?;
        assert_eq!(stream.read_timeout()?, None);
        assert_eq!(stream.write_timeout()?, None);
        drop(stream);
        let request = rx.recv()?;
        let mut expected = vec![0x05, 0x01, 0x00, 0x03, 0x3e];
        expected.extend_from_slice(onion.as_bytes());
        expected.extend_from_slice(&8333u16.to_be_bytes());
        assert_eq!(request, expected);
        Ok(())
    }

    #[test]
    fn isolation_dial_refuses_no_auth_selection_and_sends_no_connect() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let proxy = listener.local_addr()?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut greeting = [0u8; 2];
            stream.read_exact(&mut greeting)?;
            let mut methods = vec![0u8; usize::from(greeting[1])];
            stream.read_exact(&mut methods)?;
            assert_eq!(methods, vec![0x02], "isolation dial must offer only 0x02");
            stream.write_all(&[0x05, 0x00])?;
            let mut byte = [0u8; 1];
            let extra = stream.read(&mut byte).unwrap_or(0);
            let _ = tx.send(extra);
            Ok(())
        });
        let onion = format!("{}.onion", "a".repeat(56));
        let Err(error) = socks_connect_isolated(
            proxy,
            &SocksTarget::Domain(onion, 8333),
            Duration::from_secs(5),
        ) else {
            return Err(TestError::Missing(
                "no-auth selection must fail an isolation dial",
            ));
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(rx.recv()?, 0, "no CONNECT may be sent");
        Ok(())
    }

    #[test]
    fn ip_dial_uses_literal_address_without_auth() -> TestResult {
        let (proxy, rx) = fake_socks_no_auth(0x00)?;
        let target: SocketAddr = "203.0.113.7:8333".parse()?;
        let stream = socks_connect(proxy, &SocksTarget::Ip(target), Duration::from_secs(5))?;
        drop(stream);
        let request = rx.recv()?;
        assert_eq!(
            request,
            vec![0x05, 0x01, 0x00, 0x01, 203, 0, 113, 7, 0x20, 0x8d]
        );
        Ok(())
    }

    #[test]
    fn a_failed_nodelay_does_not_fail_the_dial() -> TestResult {
        let (proxy, rx) = fake_socks_no_auth(0x00)?;
        let target: SocketAddr = "203.0.113.7:8333".parse()?;
        let stream = socks_connect_with(
            proxy,
            &SocksTarget::Ip(target),
            SocksDial {
                isolate: false,
                timeout: Duration::from_secs(5),
                set_nodelay: &|_| Err(io::Error::other("test-injected nodelay failure")),
            },
        )?;
        drop(stream);
        let request = rx.recv()?;
        assert_eq!(
            request,
            vec![0x05, 0x01, 0x00, 0x01, 203, 0, 113, 7, 0x20, 0x8d],
            "the SOCKS exchange must complete when only the optional socket option fails"
        );
        Ok(())
    }

    #[test]
    fn dead_proxy_is_a_transport_error() -> TestResult {
        let target: SocketAddr = "203.0.113.7:8333".parse()?;
        let Err(error) = socks_connect(
            "127.0.0.1:1".parse()?,
            &SocksTarget::Ip(target),
            Duration::from_secs(2),
        ) else {
            return Err(TestError::Missing("dead proxy must fail"));
        };
        assert_ne!(error.kind(), io::ErrorKind::Unsupported);
        Ok(())
    }

    #[test]
    fn refused_connect_is_a_transport_error() -> TestResult {
        let (proxy, _rx) = fake_socks_no_auth(0x05)?;
        let target: SocketAddr = "203.0.113.7:8333".parse()?;
        let Err(error) = socks_connect(proxy, &SocksTarget::Ip(target), Duration::from_secs(5))
        else {
            return Err(TestError::Missing("refused connect must fail"));
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        Ok(())
    }

    #[test]
    fn unresolvable_onion_never_falls_back_to_direct_tcp() -> TestResult {
        let (proxy, _rx) = fake_socks_auth(0x05)?;
        let onion = format!("{}.onion", "z".repeat(56));
        let Err(error) = socks_connect_isolated(
            proxy,
            &SocksTarget::Domain(onion, 8333),
            Duration::from_secs(5),
        ) else {
            return Err(TestError::Missing("must fail"));
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert!(error.counts_as_peer_failure());
        Ok(())
    }

    #[test]
    fn nonzero_rsv_is_rejected_as_invalid_data() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let proxy = listener.local_addr()?;
        std::thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting)?;
            stream.write_all(&[0x05, 0x00])?;
            let mut head = [0u8; 4];
            stream.read_exact(&mut head)?;
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest)?;
            stream.write_all(&[0x05, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0x20, 0x8d])?;
            Ok(())
        });
        let target: SocketAddr = "127.0.0.1:8333".parse()?;
        let Err(error) = socks_connect(proxy, &SocksTarget::Ip(target), Duration::from_secs(5))
        else {
            return Err(TestError::Missing("nonzero RSV must fail"));
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!error.counts_as_peer_failure());
        Ok(())
    }

    #[test]
    fn network_unreachable_and_ttl_expired_are_transport_not_peer_unreachable() -> TestResult {
        for reply_code in [0x03, 0x04, 0x06] {
            let (proxy, _rx) = fake_socks_no_auth(reply_code)?;
            let target: SocketAddr = "203.0.113.7:8333".parse()?;
            let Err(error) = socks_connect(proxy, &SocksTarget::Ip(target), Duration::from_secs(5))
            else {
                return Err(TestError::Missing("must fail"));
            };
            assert!(
                !error.counts_as_peer_failure(),
                "reply code {reply_code:#x} must be transport error, not peer failure"
            );
        }
        Ok(())
    }

    #[test]
    fn slow_trickle_handshake_exceeds_absolute_deadline() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let proxy = listener.local_addr()?;
        std::thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut greeting = [0u8; 3];
            let _ = stream.read_exact(&mut greeting);
            std::thread::sleep(Duration::from_millis(800));
            let _ = stream.write_all(&[0x05, 0x00]);
            let mut head = [0u8; 4];
            let _ = stream.read_exact(&mut head);
            let mut rest = [0u8; 6];
            let _ = stream.read_exact(&mut rest);
            std::thread::sleep(Duration::from_millis(800));
            let _ = stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x20, 0x8d]);
            Ok(())
        });
        let target: SocketAddr = "127.0.0.1:8333".parse()?;
        let started = Instant::now();
        let Err(error) = socks_connect(proxy, &SocksTarget::Ip(target), Duration::from_millis(200))
        else {
            return Err(TestError::Missing("slow trickle must exceed deadline"));
        };
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(150),
            "must not return before deadline: took {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(700),
            "must fail at deadline, not wait for server delay: took {elapsed:?}"
        );
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ),
            "expected platform timeout error category (TimedOut or WouldBlock), got {:?}",
            error.kind()
        );
        assert!(!error.counts_as_peer_failure());
        Ok(())
    }

    #[test]
    fn partial_byte_trickle_does_not_extend_deadline() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let proxy = listener.local_addr()?;
        std::thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut greeting = [0u8; 3];
            let _ = stream.read_exact(&mut greeting);
            let _ = stream.write_all(&[0x05, 0x00]);
            let mut head = [0u8; 4];
            let _ = stream.read_exact(&mut head);
            let mut rest = [0u8; 6];
            let _ = stream.read_exact(&mut rest);
            for byte in [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x20, 0x8d] {
                std::thread::sleep(Duration::from_millis(80));
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
            }
            Ok(())
        });
        let target: SocketAddr = "127.0.0.1:8333".parse()?;
        let started = Instant::now();
        let Err(error) = socks_connect(proxy, &SocksTarget::Ip(target), Duration::from_millis(200))
        else {
            return Err(TestError::Missing(
                "partial byte trickle must not extend absolute deadline",
            ));
        };
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(150),
            "must not return before deadline: took {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(700),
            "must fail at deadline, not allow trickle to run: took {elapsed:?}"
        );
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ),
            "expected platform timeout error category (TimedOut or WouldBlock), got {:?}",
            error.kind()
        );
        assert!(!error.counts_as_peer_failure());
        Ok(())
    }

    #[test]
    fn empty_domain_name_is_rejected() -> TestResult {
        let (proxy, _rx) = fake_socks_no_auth(0x00)?;
        let Err(error) = socks_connect(
            proxy,
            &SocksTarget::Domain(String::new(), 8333),
            Duration::from_secs(5),
        ) else {
            return Err(TestError::Missing("empty domain must fail"));
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        Ok(())
    }

    #[test]
    fn oversize_domain_name_is_rejected() -> TestResult {
        let (proxy, _rx) = fake_socks_no_auth(0x00)?;
        let over_domain = "a".repeat(256);
        let Err(error) = socks_connect(
            proxy,
            &SocksTarget::Domain(over_domain, 8333),
            Duration::from_secs(5),
        ) else {
            return Err(TestError::Missing("oversize domain must fail"));
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        Ok(())
    }

    #[test]
    fn truncated_socks_handshakes_fail_with_unexpected_eof() -> TestResult {
        for stage in 0..4 {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let proxy = listener.local_addr()?;
            let server = std::thread::spawn(move || -> io::Result<()> {
                let (mut stream, _) = listener.accept()?;
                let mut greeting = [0u8; 3];
                let _ = stream.read_exact(&mut greeting);
                if stage == 0 {
                    return Ok(());
                }
                let _ = stream.write_all(&[0x05, 0x00]);
                let mut head = [0u8; 4];
                let _ = stream.read_exact(&mut head);
                let mut rest = [0u8; 6];
                let _ = stream.read_exact(&mut rest);
                if stage == 1 {
                    return Ok(());
                }
                if stage == 2 {
                    let _ = stream.write_all(&[0x05, 0x00]);
                    return Ok(());
                }
                let _ = stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127]);
                Ok(())
            });

            let target: SocketAddr = "127.0.0.1:8333".parse()?;
            let Err(error) = socks_connect(proxy, &SocksTarget::Ip(target), Duration::from_secs(2))
            else {
                return Err(TestError::Missing("truncated handshake must fail"));
            };
            assert_eq!(
                error.kind(),
                io::ErrorKind::UnexpectedEof,
                "stage {stage} must fail with unexpected eof"
            );
            let _server_res = server
                .join()
                .map_err(|_| TestError::Missing("server panicked"))?;
        }
        Ok(())
    }

    #[test]
    fn malformed_connect_replies_fail() -> TestResult {
        for (atyp, rsv, ver) in [(0x02, 0x00, 0x05), (0x01, 0x01, 0x05), (0x01, 0x00, 0x04)] {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let proxy = listener.local_addr()?;
            let server = std::thread::spawn(move || -> io::Result<()> {
                let (mut stream, _) = listener.accept()?;
                let mut greeting = [0u8; 3];
                let _ = stream.read_exact(&mut greeting);
                let _ = stream.write_all(&[0x05, 0x00]);
                let mut head = [0u8; 4];
                let _ = stream.read_exact(&mut head);
                let mut rest = [0u8; 6];
                let _ = stream.read_exact(&mut rest);
                let _ = stream.write_all(&[ver, 0x00, rsv, atyp, 127, 0, 0, 1, 0x20, 0x8d]);
                Ok(())
            });

            let target: SocketAddr = "127.0.0.1:8333".parse()?;
            let Err(error) = socks_connect(proxy, &SocksTarget::Ip(target), Duration::from_secs(2))
            else {
                return Err(TestError::Missing("malformed connect reply must fail"));
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            let _server_res = server
                .join()
                .map_err(|_| TestError::Missing("server panicked"))?;
        }
        Ok(())
    }
}
