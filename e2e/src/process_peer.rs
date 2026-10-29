//! Bounded, recorded v1 wire peer for the public-process lane.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::Transaction;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hex::DisplayHex as _;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use sonic_rs::json;

use crate::error::{Error, Result};
use crate::node::ProcessNode;
use crate::rpc::remaining_time;

const HEADER_BYTES: usize = 24;
const MAX_PAYLOAD_BYTES: usize = 4_000_000;
const MAX_TRANSCRIPT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MESSAGES: usize = 128;
const TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct ProcessPeer {
    stream: TcpStream,
    journal: File,
    journal_bytes: u64,
    started: Instant,
    pending: FrameBuffer,
}

impl ProcessPeer {
    pub fn connect(node: &ProcessNode) -> Result<Self> {
        let deadline = Instant::now() + TIMEOUT;
        let stream = connect_loopback(node.p2p_addr, deadline)?;
        stream.set_nodelay(true)?;
        let journal = File::options()
            .write(true)
            .create_new(true)
            .open(node.evidence.join("p2p.jsonl"))?;
        let mut peer = Self {
            stream,
            journal,
            journal_bytes: 0,
            started: node.evidence_clock(),
            pending: FrameBuffer::default(),
        };
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let mut version = VersionMessage::new(
            services,
            i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|error| Error::Protocol(error.to_string()))?
                    .as_secs(),
            )
            .map_err(|error| Error::Protocol(error.to_string()))?,
            Address::new(&node.p2p_addr, ServiceFlags::NONE),
            Address::new(&peer.stream.local_addr()?, services),
            0,
            "/public-process-test:0.1/".to_owned(),
            0,
        );
        version.version = 70016;
        peer.send(NetworkMessage::Version(version), deadline)?;
        let mut received_version = false;
        for _ in 0..MAX_MESSAGES {
            match peer.receive(deadline)? {
                NetworkMessage::Version(_) if !received_version => {
                    received_version = true;
                    peer.send(NetworkMessage::WtxidRelay, deadline)?;
                    peer.send(NetworkMessage::Verack, deadline)?;
                }
                NetworkMessage::Verack if received_version => return Ok(peer),
                NetworkMessage::Verack | NetworkMessage::Version(_) => {
                    return peer.record_result(Err(Error::Protocol(
                        "out-of-order P2P handshake".to_owned(),
                    )));
                }
                NetworkMessage::Ping(nonce) => peer.send(NetworkMessage::Pong(nonce), deadline)?,
                _ => {}
            }
        }
        peer.record_result(Err(Error::Protocol(
            "P2P handshake message limit".to_owned(),
        )))
    }

    pub fn send_transaction(&mut self, tx: &Transaction) -> Result<()> {
        let deadline = Instant::now() + TIMEOUT;
        self.send(NetworkMessage::Tx(tx.clone()), deadline)?;
        let nonce = 626;
        self.send(NetworkMessage::Ping(nonce), deadline)?;
        self.wait_for_pong(nonce, deadline)
    }

    pub fn wait_for_pong(&mut self, nonce: u64, deadline: Instant) -> Result<()> {
        for _ in 0..MAX_MESSAGES {
            match self.receive(deadline)? {
                NetworkMessage::Pong(reply) if reply == nonce => return Ok(()),
                NetworkMessage::Ping(reply) => self.send(NetworkMessage::Pong(reply), deadline)?,
                _ => {}
            }
        }
        self.record_result(Err(Error::Protocol("P2P pong message limit".to_owned())))
    }

    fn send(&mut self, message: NetworkMessage, deadline: Instant) -> Result<()> {
        let result = (|| {
            let frame = serialize(&RawNetworkMessage::new(Magic::REGTEST, message));
            let decoded = decode_frame(&frame)?;
            self.record("sending", Some(&decoded), &frame)?;
            let mut pending = frame.as_slice();
            while !pending.is_empty() {
                self.stream.set_write_timeout(Some(remaining(deadline)?))?;
                let written = self.stream.write(pending)?;
                if written == 0 {
                    return Err(Error::Protocol("closed P2P writer".to_owned()));
                }
                pending = pending
                    .get(written..)
                    .ok_or_else(|| Error::Protocol("invalid write length".to_owned()))?;
            }
            self.record("sent", Some(&decoded), &[])?;
            remaining(deadline)?;
            Ok(())
        })();
        self.record_result(result)
    }

    fn receive(&mut self, deadline: Instant) -> Result<NetworkMessage> {
        let result = (|| {
            let frame = read_frame(&mut self.stream, deadline, &mut self.pending)?;
            let decoded = decode_frame(&frame);
            let record = self.record("received", decoded.as_ref().ok(), &frame);
            let message = decoded?;
            record?;
            remaining(deadline)?;
            Ok(message)
        })();
        self.record_result(result)
    }

    fn record_result<T>(&mut self, result: std::result::Result<T, Error>) -> Result<T> {
        result.inspect_err(|error| {
            if let Err(record_error) = self.record_failure(error) {
                eprintln!("Cannot record the P2P failure: {record_error}");
            }
        })
    }

    fn record_failure(&mut self, error: &Error) -> Result<()> {
        self.append(json!({"direction": "failure", "error": error.to_string()}))
    }

    fn record(
        &mut self,
        direction: &str,
        message: Option<&NetworkMessage>,
        bytes: &[u8],
    ) -> Result<()> {
        self.append(json!({
            "direction": direction,
            "command": message.map(NetworkMessage::cmd),
            "wire_hex": bytes.to_lower_hex_string(),
        }))
    }

    fn append(&mut self, mut event: sonic_rs::Value) -> Result<()> {
        event["at_micros"] = json!(self.started.elapsed().as_micros());
        let mut bytes = sonic_rs::to_vec(&event)?;
        bytes.push(b'\n');
        let next = self
            .journal_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if next > MAX_TRANSCRIPT_BYTES {
            return Err(Error::Protocol("P2P transcript byte limit".to_owned()));
        }
        self.journal.write_all(&bytes)?;
        self.journal.flush()?;
        self.journal_bytes = next;
        Ok(())
    }
}

pub fn connect_loopback(addr: SocketAddr, deadline: Instant) -> Result<TcpStream> {
    if !addr.ip().is_loopback() {
        return Err(Error::Protocol(
            "P2P fixture address is not loopback".to_owned(),
        ));
    }
    loop {
        match TcpStream::connect_timeout(
            &addr,
            remaining(deadline)?.min(Duration::from_millis(100)),
        ) {
            Ok(stream) => {
                remaining(deadline)?;
                return Ok(stream);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ) =>
            {
                std::thread::sleep(remaining(deadline)?.min(Duration::from_millis(10)));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn remaining(deadline: Instant) -> Result<Duration> {
    remaining_time(deadline, Instant::now(), "P2P operation deadline")
}

pub fn is_soft_recv_error(error: &Error) -> bool {
    match error {
        Error::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        Error::Protocol(detail) => detail.contains("deadline"),
        _ => false,
    }
}

#[derive(Debug, Default)]
pub struct FrameBuffer {
    bytes: Vec<u8>,
    want: usize,
}

fn payload_length(header: &[u8]) -> Result<usize> {
    let length = header
        .get(16..20)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .ok_or_else(|| Error::Protocol("truncated P2P header".to_owned()))?;
    let length = usize::try_from(u32::from_le_bytes(length))
        .map_err(|error| Error::Protocol(error.to_string()))?;
    if length > MAX_PAYLOAD_BYTES {
        return Err(Error::Protocol("P2P payload byte limit".to_owned()));
    }
    Ok(length)
}

pub fn read_frame(
    stream: &mut TcpStream,
    deadline: Instant,
    pending: &mut FrameBuffer,
) -> Result<Vec<u8>> {
    if pending.want == 0 {
        pending.want = HEADER_BYTES;
    }
    while pending.bytes.len() < pending.want {
        let wait = remaining(deadline).unwrap_or(Duration::from_millis(1));
        stream.set_read_timeout(Some(wait))?;
        let want = (pending.want - pending.bytes.len()).min(64 * 1024);
        let base = pending.bytes.len();
        pending.bytes.resize(base + want, 0);
        match stream.read(&mut pending.bytes[base..]) {
            Ok(0) => {
                pending.bytes.clear();
                pending.want = 0;
                return Err(Error::Protocol("truncated P2P frame".to_owned()));
            }
            Ok(count) => {
                pending.bytes.truncate(base + count);
                if pending.want == HEADER_BYTES && pending.bytes.len() == HEADER_BYTES {
                    pending.want = HEADER_BYTES
                        + payload_length(&pending.bytes).inspect_err(|_| {
                            pending.bytes.clear();
                            pending.want = 0;
                        })?;
                }
                if pending.bytes.len() < pending.want && remaining(deadline).is_err() {
                    return Err(Error::Protocol(
                        "P2P frame paused at the read deadline".to_owned(),
                    ));
                }
            }
            Err(error) => {
                pending.bytes.truncate(base);
                return Err(error.into());
            }
        }
    }
    let frame = std::mem::take(&mut pending.bytes);
    pending.want = 0;
    Ok(frame)
}

pub fn decode_frame(frame: &[u8]) -> Result<NetworkMessage> {
    let length = payload_length(frame)?;
    if frame.len() != HEADER_BYTES + length {
        return Err(Error::Protocol("P2P frame length mismatch".to_owned()));
    }
    let envelope: RawNetworkMessage = deserialize(frame)
        .map_err(|error| Error::Protocol(format!("invalid P2P envelope: {error}")))?;
    if *envelope.magic() != Magic::REGTEST {
        return Err(Error::Protocol("P2P network mismatch".to_owned()));
    }
    Ok(envelope.into_payload())
}
