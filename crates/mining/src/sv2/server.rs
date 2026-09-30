//! SV2 Template Distribution Protocol server.
//!
//! Accepts pool connections over TCP and distributes block templates
//! via the Template Distribution Protocol. The Noise encryption layer
//! is handled by `network_helpers`; this module implements the TDP
//! message exchange on top.
//!
//! Architecture:
//! ```text
//! SRI pool ←→ [Noise (network_helpers)] ←→ [TDP (this module)] ←→ MiningSource
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use super::template::TemplateHub;

/// SV2 template-distribution server.
pub struct Sv2TpServer {
    listen: SocketAddr,
    hub: Arc<Mutex<TemplateHub>>,
}

impl Sv2TpServer {
    /// Creates a new server.
    pub fn new(listen: SocketAddr, hub: TemplateHub) -> Self {
        Self {
            listen,
            hub: Arc::new(Mutex::new(hub)),
        }
    }

    /// Runs the server, accepting connections and distributing templates.
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(self.listen).await?;
        tracing::info!(addr = %self.listen, "SV2 TDP server listening");

        loop {
            let (stream, peer) = listener.accept().await?;
            tracing::info!(%peer, "new pool connection");
            let hub = Arc::clone(&self.hub);
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, hub).await {
                    tracing::error!(%peer, error = %e, "connection error");
                }
            });
        }
    }
}

/// Handles one pool connection: TDP message loop.
///
/// The Noise encryption layer will be added in a follow-up using
/// `network_helpers`. For now, this handles raw TDP messages.
async fn handle_connection(
    mut stream: TcpStream,
    hub: Arc<Mutex<TemplateHub>>,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("TDP connection established");

    let mut last_template_id = 0u64;
    let mut buf = [0u8; 4096];

    loop {
        // Check for template updates and push to pool
        let update = {
            let mut h = hub.lock();
            h.check_for_update()
        };

        if let Ok(Some(update)) = update {
            if update.template_id != last_template_id {
                last_template_id = update.template_id;
                tracing::info!(
                    template_id = last_template_id,
                    height = update.height,
                    "sending template to pool"
                );

                // Send SetNewPrevHash
                stream.write_all(&update.set_new_prev_hash).await?;
                // Send NewTemplate
                stream.write_all(&update.new_template).await?;
                stream.flush().await?;
            }
        }

        // Read incoming TDP messages (non-blocking poll)
        match stream.try_read(&mut buf) {
            Ok(0) => {
                tracing::info!("pool disconnected");
                return Ok(());
            }
            Ok(n) => {
                process_tdp_message(&buf[..n], &hub).await?;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available; sleep briefly before polling again
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Processes an incoming TDP message.
async fn process_tdp_message(
    data: &[u8],
    _hub: &Arc<Mutex<TemplateHub>>,
) -> Result<(), Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Ok(());
    }

    let msg_type = data[0];
    match msg_type {
        // SetupConnection
        0x00 => {
            tracing::info!("SetupConnection received");
        }
        // SubmitSolution
        0x76 => {
            if data.len() >= 21 {
                let template_id = u64::from_le_bytes(data[1..9].try_into()?);
                tracing::info!(template_id, "SubmitSolution received");
                // TODO: decode solution and submit via MiningSource
            }
        }
        // RequestTransactionData
        0x73 => {
            if data.len() >= 9 {
                let template_id = u64::from_le_bytes(data[1..9].try_into()?);
                tracing::info!(template_id, "RequestTransactionData received");
                // TODO: respond with transaction data
            }
        }
        // CoinbaseOutputConstraints
        0x70 => {
            tracing::info!("CoinbaseOutputConstraints received");
        }
        other => {
            tracing::debug!(msg_type = other, "unhandled TDP message");
        }
    }
    Ok(())
}
