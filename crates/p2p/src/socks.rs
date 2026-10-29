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
    fn tor_dial_uses_exact_domain_transcript() -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, rx) = fake_socks_auth(0x00)?;
        let onion = format!("{}.onion", "a".repeat(56));
        assert_eq!(onion.len(), 62);
        let stream = socks_connect(
            proxy,
            &SocksTarget::Domain(onion.clone(), 8333),
            true,
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
    fn isolation_dial_refuses_no_auth_selection_and_sends_no_connect()
    -> Result<(), Box<dyn std::error::Error>> {
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
        let Err(error) = socks_connect(
            proxy,
            &SocksTarget::Domain(onion, 8333),
            true,
            Duration::from_secs(5),
        ) else {
            return Err("no-auth selection must fail an isolation dial".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(rx.recv()?, 0, "no CONNECT may be sent");
        Ok(())
    }

    #[test]
    fn ip_dial_uses_literal_address_without_auth() -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, rx) = fake_socks_no_auth(0x00)?;
        let target: SocketAddr = "203.0.113.7:8333".parse()?;
        let stream = socks_connect(
            proxy,
            &SocksTarget::Ip(target),
            false,
            Duration::from_secs(5),
        )?;
        drop(stream);
        let request = rx.recv()?;
        assert_eq!(
            request,
            vec![0x05, 0x01, 0x00, 0x01, 203, 0, 113, 7, 0x20, 0x8d]
        );
        Ok(())
    }

    #[test]
    fn dead_proxy_is_a_transport_error() -> Result<(), Box<dyn std::error::Error>> {
        let target: SocketAddr = "203.0.113.7:8333".parse()?;
        let Err(error) = socks_connect(
            "127.0.0.1:1".parse()?,
            &SocksTarget::Ip(target),
            false,
            Duration::from_secs(2),
        ) else {
            return Err("dead proxy must fail".into());
        };
        assert_ne!(error.kind(), io::ErrorKind::Unsupported);
        Ok(())
    }

    #[test]
    fn refused_connect_is_a_transport_error() -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, _rx) = fake_socks_no_auth(0x05)?;
        let target: SocketAddr = "203.0.113.7:8333".parse()?;
        let Err(error) = socks_connect(
            proxy,
            &SocksTarget::Ip(target),
            false,
            Duration::from_secs(5),
        ) else {
            return Err("refused connect must fail".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        Ok(())
    }

    #[test]
    fn unresolvable_onion_never_falls_back_to_direct_tcp() -> Result<(), Box<dyn std::error::Error>>
    {
        let (proxy, _rx) = fake_socks_auth(0x05)?;
        let onion = format!("{}.onion", "z".repeat(56));
        let Err(error) = socks_connect(
            proxy,
            &SocksTarget::Domain(onion, 8333),
            true,
            Duration::from_secs(5),
        ) else {
            return Err("must fail".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert!(error.counts_as_peer_failure());
        Ok(())
    }

    #[test]
    fn nonzero_rsv_is_rejected_as_invalid_data() -> Result<(), Box<dyn std::error::Error>> {
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
        let Err(error) = socks_connect(
            proxy,
            &SocksTarget::Ip(target),
            false,
            Duration::from_secs(5),
        ) else {
            return Err("nonzero RSV must fail".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!error.counts_as_peer_failure());
        Ok(())
    }

    #[test]
    fn network_unreachable_and_ttl_expired_are_transport_not_peer_unreachable()
    -> Result<(), Box<dyn std::error::Error>> {
        for reply_code in [0x03, 0x04, 0x06] {
            let (proxy, _rx) = fake_socks_no_auth(reply_code)?;
            let target: SocketAddr = "203.0.113.7:8333".parse()?;
            let Err(error) = socks_connect(
                proxy,
                &SocksTarget::Ip(target),
                false,
                Duration::from_secs(5),
            ) else {
                return Err("must fail".into());
            };
            assert!(
                !error.counts_as_peer_failure(),
                "reply code {reply_code:#x} must be transport error, not peer failure"
            );
        }
        Ok(())
    }

    #[test]
    fn slow_trickle_handshake_exceeds_absolute_deadline() -> Result<(), Box<dyn std::error::Error>>
    {
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
        let Err(error) = socks_connect(
            proxy,
            &SocksTarget::Ip(target),
            false,
            Duration::from_millis(200),
        ) else {
            return Err("slow trickle must exceed deadline".into());
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
    fn partial_byte_trickle_does_not_extend_deadline() -> Result<(), Box<dyn std::error::Error>> {
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
        let Err(error) = socks_connect(
            proxy,
            &SocksTarget::Ip(target),
            false,
            Duration::from_millis(200),
        ) else {
            return Err("partial byte trickle must not extend absolute deadline".into());
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
}
