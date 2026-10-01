//! SV2 Template Distribution Protocol server.
//!
//! Accepts pool connections over Noise-encrypted TCP and distributes
//! block templates via TDP. The Noise handshake is performed using
//! the `noise_sv2` crate directly; messages are encrypted with the
//! resulting cipher after the handshake completes.
//!
//! Architecture:
//! ```text
//! SRI pool ←→ [Noise handshake] ←→ [TDP message loop] ←→ MiningSource
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use noise_sv2::{ELLSWIFT_ENCODING_SIZE, ENCRYPTED_SIGNATURE_NOISE_MESSAGE_SIZE, Responder};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::template::TemplateHub;

/// SV2 template-distribution server.
pub struct Sv2TpServer {
    listen: SocketAddr,
    hub: Arc<Mutex<TemplateHub>>,
    /// Authority keypair for Noise handshake.
    authority_secret: [u8; 32],
}

impl Sv2TpServer {
    /// Creates a new server.
    pub fn new(listen: SocketAddr, hub: TemplateHub) -> Self {
        // Example authority key — in production this should be configurable.
        let authority_secret = [0x42u8; 32];
        Self {
            listen,
            hub: Arc::new(Mutex::new(hub)),
            authority_secret,
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
            let authority_secret = self.authority_secret;
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, hub, authority_secret).await {
                    tracing::error!(%peer, error = %e, "connection error");
                }
            });
        }
    }
}

/// Handles one pool connection: Noise handshake + TDP message loop.
async fn handle_connection(
    mut stream: TcpStream,
    hub: Arc<Mutex<TemplateHub>>,
    authority_secret: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    // ── Noise handshake ──────────────────────────────────────────
    let secret_key = secp256k1_sv2::SecretKey::from_slice(&authority_secret)
        .map_err(|e| format!("invalid authority key: {e}"))?;
    let secp = secp256k1_sv2::Secp256k1::new();
    let keypair = secp256k1_sv2::Keypair::from_secret_key(&secp, &secret_key);
    let mut responder = Responder::new(keypair, 3600);

    // Read initiator's ephemeral key (64 bytes ElligatorSwift)
    let mut ephemeral_buf = [0u8; ELLSWIFT_ENCODING_SIZE];
    stream.read_exact(&mut ephemeral_buf).await?;

    // Process handshake step 1: get reply + cipher
    let (reply, mut noise) = responder
        .step_1(ephemeral_buf)
        .map_err(|e| format!("handshake step_1 failed: {e:?}"))?;

    // Send responder's handshake message
    stream.write_all(&reply).await?;
    stream.flush().await?;

    // Read initiator's encrypted signature (74 bytes + 16 byte MAC)
    let mut sig_buf = [0u8; ENCRYPTED_SIGNATURE_NOISE_MESSAGE_SIZE];
    stream.read_exact(&mut sig_buf).await?;

    // Decrypt to verify (optional — full auth verification is a follow-up)
    let mut sig_vec = sig_buf.to_vec();
    let _ = noise.decrypt(&mut sig_vec);

    tracing::info!("Noise handshake completed");

    // ── TDP message loop ─────────────────────────────────────────
    let mut last_template_id = 0u64;
    let mut read_buf = [0u8; 4096];

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

                // Encrypt and send SetNewPrevHash
                let mut prev_hash_msg = update.set_new_prev_hash.clone();
                noise
                    .encrypt(&mut prev_hash_msg)
                    .map_err(|e| format!("encrypt failed: {e:?}"))?;
                let len = u16::try_from(prev_hash_msg.len()).map_err(|_| "message too large")?;
                stream.write_all(&len.to_be_bytes()).await?;
                stream.write_all(&prev_hash_msg).await?;

                // Encrypt and send NewTemplate
                let mut new_template_msg = update.new_template.clone();
                noise
                    .encrypt(&mut new_template_msg)
                    .map_err(|e| format!("encrypt failed: {e:?}"))?;
                let len = u16::try_from(new_template_msg.len()).map_err(|_| "message too large")?;
                stream.write_all(&len.to_be_bytes()).await?;
                stream.write_all(&new_template_msg).await?;

                stream.flush().await?;
            }
        }

        // Read incoming messages (with Noise decryption)
        match stream.try_read(&mut read_buf) {
            Ok(0) => {
                tracing::info!("pool disconnected");
                return Ok(());
            }
            Ok(n) => {
                // Try to decrypt (messages are Noise-encrypted after handshake)
                let mut data = read_buf[..n].to_vec();
                if noise.decrypt(&mut data).is_ok() {
                    process_tdp_message(&data, &hub)?;
                } else {
                    // Not a valid Noise message — try raw parse
                    process_tdp_message(&read_buf[..n], &hub)?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Processes an incoming TDP message.
fn process_tdp_message(
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
            // TODO: respond with SetupConnectionSuccess
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
