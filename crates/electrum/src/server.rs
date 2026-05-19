use alloc::sync::Arc;
use core::time::Duration;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

use crossbeam_channel::{Receiver, Sender, bounded};
use rustls::{ServerConnection, StreamOwned};
use tracing::{debug, warn};

use crate::methods::{ElectrumError, IndexHandle, MempoolHandle};
use crate::session::Session;

const DEFAULT_MAX_SESSIONS: usize = 256;
const READ_TIMEOUT: Duration = Duration::from_secs(1);

/// Electrum TCP server configuration.
#[derive(Clone)]
pub struct ServerConfig {
    /// Optional TLS configuration for accepted sockets.
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// Maximum concurrent sessions.
    pub max_sessions: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            tls: None,
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }
}

/// Synchronous Electrum TCP/TLS server.
pub struct ElectrumServer {
    /// Bound TCP listener.
    pub listener: TcpListener,
    index: IndexHandle,
    mempool: MempoolHandle,
    tls: Option<Arc<rustls::ServerConfig>>,
    permits: Receiver<()>,
    permit_returns: Sender<()>,
}

impl ElectrumServer {
    /// Binds a server to `addr`.
    pub fn bind(
        addr: SocketAddr,
        index: IndexHandle,
        mempool: MempoolHandle,
        config: ServerConfig,
    ) -> Result<Self, ElectrumError> {
        let listener = TcpListener::bind(addr)?;
        Self::from_listener(listener, index, mempool, config)
    }

    /// Creates a server from an existing listener.
    pub fn from_listener(
        listener: TcpListener,
        index: IndexHandle,
        mempool: MempoolHandle,
        config: ServerConfig,
    ) -> Result<Self, ElectrumError> {
        let max_sessions = config.max_sessions.max(1);
        let (permit_returns, permits) = bounded(max_sessions);
        for _ in 0..max_sessions {
            permit_returns
                .send(())
                .map_err(|_| ElectrumError::InvalidParams("session permit channel closed"))?;
        }
        Ok(Self {
            listener,
            index,
            mempool,
            tls: config.tls,
            permits,
            permit_returns,
        })
    }

    /// Returns the local address of the listener.
    pub fn local_addr(&self) -> Result<SocketAddr, ElectrumError> {
        Ok(self.listener.local_addr()?)
    }

    /// Runs the accept loop, spawning one operating-system thread per accepted session.
    pub fn run(self) -> Result<(), ElectrumError> {
        for accepted in self.listener.incoming() {
            let stream = accepted?;
            stream.set_read_timeout(Some(READ_TIMEOUT))?;
            if self.permits.try_recv().is_err() {
                warn!(peer = ?stream.peer_addr().ok(), "rejecting electrum session: capacity reached");
                continue;
            }
            let index = self.index.clone();
            let mempool = self.mempool.clone();
            let tls = self.tls.clone();
            let permit_returns = self.permit_returns.clone();
            thread::spawn(move || {
                let result = serve_stream(stream, tls, index, mempool);
                if permit_returns.send(()).is_err() {
                    warn!("electrum session permit return channel closed");
                }
                if let Err(error) = result {
                    debug!(error = %error, "electrum session ended with error");
                }
            });
        }
        Ok(())
    }
}

fn serve_stream(
    stream: TcpStream,
    tls: Option<Arc<rustls::ServerConfig>>,
    index: IndexHandle,
    mempool: MempoolHandle,
) -> Result<(), ElectrumError> {
    match tls {
        Some(config) => {
            let connection = ServerConnection::new(config)?;
            Session::new(
                MaybeTlsStream::Tls(Box::new(StreamOwned::new(connection, stream))),
                index,
                mempool,
            )
            .serve()
        }
        None => Session::new(MaybeTlsStream::Tcp(stream), index, mempool).serve(),
    }
}

enum MaybeTlsStream {
    Tcp(TcpStream),
    Tls(Box<StreamOwned<ServerConnection, TcpStream>>),
}

impl Read for MaybeTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for MaybeTlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}
