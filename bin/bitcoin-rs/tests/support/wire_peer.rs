//! Handshaken, journaled loopback peer for the binary's wire scenarios.

use std::fs::File;
use std::io::Write as _;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::consensus::serialize;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin_rs_e2e::Error;
use bitcoin_rs_e2e::node::workspace;
use bitcoin_rs_e2e::process_peer::{
    FrameBuffer, connect_loopback, decode_frame, is_soft_recv_error, read_frame,
};

fn remaining(deadline: Instant) -> Result<Option<Duration>, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| *time >= Duration::from_micros(1))
        .map(Some)
        .ok_or_else(|| Error::Protocol("write deadline reached ran past the deadline".to_owned()))
}

fn evidence_dir(name: &str) -> std::path::PathBuf {
    let dir = workspace().join("target").join(name);
    std::fs::create_dir_all(&dir).expect("evidence dir");
    dir
}

pub(crate) struct Peer {
    stream: TcpStream,
    journal: File,
    pending: FrameBuffer,
    t0: Instant,
    /// The peer socket died: the node disconnected, or the transport failed.
    pub(crate) dropped: bool,
}

impl Peer {
    pub(crate) fn connect(
        addr: SocketAddr,
        evidence: &str,
        name: &str,
        start_height: i32,
        deadline: Instant,
    ) -> Result<Self, Error> {
        let stream = connect_loopback(addr, deadline)?;
        stream.set_nodelay(true)?;
        let journal = File::create(evidence_dir(evidence).join(format!("{name}-peer.jsonl")))?;
        let mut peer = Self {
            stream,
            journal,
            pending: FrameBuffer::default(),
            t0: Instant::now(),
            dropped: false,
        };
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| Error::Protocol(error.to_string()))?
                .as_secs(),
        )
        .map_err(|error| Error::Protocol(error.to_string()))?;
        let local = peer.stream.local_addr().map_err(Error::Io)?;
        let mut version = VersionMessage::new(
            services,
            now,
            Address::new(&addr, ServiceFlags::NONE),
            Address::new(&local, services),
            0,
            format!("/{evidence}:0.1/"),
            start_height,
        );
        version.version = 70016;
        version.relay = true;
        peer.send(NetworkMessage::Version(version), deadline)?;
        let mut saw_version = false;
        for _ in 0..64 {
            match peer.recv(deadline)? {
                NetworkMessage::Version(_) if !saw_version => {
                    saw_version = true;
                    peer.send(NetworkMessage::WtxidRelay, deadline)?;
                    peer.send(NetworkMessage::Verack, deadline)?;
                }
                NetworkMessage::Verack if saw_version => return Ok(peer),
                NetworkMessage::Verack | NetworkMessage::Version(_) => {
                    return Err(Error::Protocol("out-of-order P2P handshake".to_owned()));
                }
                NetworkMessage::Ping(nonce) => peer.send(NetworkMessage::Pong(nonce), deadline)?,
                _ => {}
            }
        }
        Err(Error::Protocol("P2P handshake message limit".to_owned()))
    }

    pub(crate) fn send(&mut self, message: NetworkMessage, deadline: Instant) -> Result<(), Error> {
        let cmd = message.cmd().to_owned();
        let frame = serialize(&RawNetworkMessage::new(Magic::REGTEST, message));
        self.stream
            .set_write_timeout(remaining(deadline)?)
            .map_err(Error::Io)?;
        self.stream.write_all(&frame).map_err(Error::Io)?;
        self.log("send", &cmd);
        Ok(())
    }

    pub(crate) fn recv(&mut self, deadline: Instant) -> Result<NetworkMessage, Error> {
        match read_frame(&mut self.stream, deadline, &mut self.pending) {
            Ok(frame) => {
                let message = decode_frame(&frame)?;
                self.log("recv", message.cmd());
                Ok(message)
            }
            Err(error) => {
                if !is_soft_recv_error(&error) {
                    self.dropped = true;
                    self.log("dropped", &error.to_string());
                }
                Err(error)
            }
        }
    }

    pub(crate) fn log(&mut self, direction: &str, detail: &str) {
        let at_ms = u64::try_from(self.t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        let line = serde_json::json!({"at_ms": at_ms, "dir": direction, "detail": detail});
        let _ = writeln!(self.journal, "{line}");
        let _ = self.journal.flush();
        eprintln!("[E2E {at_ms:>6}ms {direction}] {detail}");
    }
}
