//! SV2 Template Distribution Protocol server.
//!
//! Accepts pool connections over Noise-encrypted TCP and distributes
//! block templates via TDP. Implements the full TDP session:
//! `SetupConnection` → `NewTemplate` → `SetNewPrevHash` → mining → `SubmitSolution`.
//!
//! Architecture:
//! ```text
//! SRI pool ←→ [Noise handshake] ←→ [TDP message loop] ←→ `MiningSource`
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use noise_sv2::{ELLSWIFT_ENCODING_SIZE, ENCRYPTED_SIGNATURE_NOISE_MESSAGE_SIZE, Responder};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::template::TemplateHub;

/// SV2 TDP message types.
const MSG_SETUP_CONNECTION: u8 = 0x00;
const MSG_SETUP_CONNECTION_SUCCESS: u8 = 0x01;
const MSG_COINBASE_OUTPUT_CONSTRAINTS: u8 = 0x70;
const MSG_NEW_TEMPLATE: u8 = 0x71;
const MSG_SET_NEW_PREV_HASH: u8 = 0x72;
const MSG_REQUEST_TRANSACTION_DATA: u8 = 0x73;
const MSG_REQUEST_TRANSACTION_DATA_SUCCESS: u8 = 0x74;
const MSG_SUBMIT_SOLUTION: u8 = 0x76;

/// SV2 template-distribution server.
pub struct Sv2TpServer {
    listen: SocketAddr,
    hub: Arc<Mutex<TemplateHub>>,
    authority_secret: [u8; 32],
}

impl Sv2TpServer {
    /// Creates a new server.
    pub fn new(listen: SocketAddr, hub: TemplateHub) -> Self {
        let authority_secret = [0x42u8; 32];
        Self {
            listen,
            hub: Arc::new(Mutex::new(hub)),
            authority_secret,
        }
    }

    /// Runs the server, accepting connections and distributing templates.
    ///
    /// Returns after binding. Bind errors are returned to the caller
    /// so node startup can fail fast.
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

/// Encodes an SV2 TDP frame: 6-byte header + payload.
///
/// Header layout per SV2 spec:
/// - `extension_type`: u16 LE (2 bytes)
/// - `msg_type`: u8 (1 byte)
/// - `msg_length`: U24 LE (3 bytes)
#[allow(clippy::as_conversions)]
fn encode_frame(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.extend_from_slice(&0u16.to_le_bytes()); // extension_type = 0 (TDP)
    frame.push(msg_type);
    // U24 length: 3 bytes LE
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    frame.push((len & 0xff) as u8);
    frame.push(((len >> 8) & 0xff) as u8);
    frame.push(((len >> 16) & 0xff) as u8);
    frame.extend_from_slice(payload);
    frame
}

/// Builds `SetupConnectionSuccess` payload.
///
/// Contains: `used_version` (2 LE) + `flags` (4 LE).
fn build_setup_connection_success() -> Vec<u8> {
    let mut payload = Vec::with_capacity(6);
    payload.extend_from_slice(&0u16.to_le_bytes()); // used_version = 0
    payload.extend_from_slice(&0u32.to_le_bytes()); // flags = 0
    payload
}

/// Builds `RequestTransactionDataSuccess` payload.
///
/// Contains: `template_id` (8 LE) + `transaction_count` (4 LE) + transactions
/// (each: 4 LE length + serialized tx bytes).
fn build_request_transaction_data_success(template_id: u64, transactions: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(128);
    payload.extend_from_slice(&template_id.to_le_bytes());
    payload.extend_from_slice(&u32::try_from(transactions.len()).unwrap_or(0).to_le_bytes());
    for tx in transactions {
        payload.extend_from_slice(&u32::try_from(tx.len()).unwrap_or(0).to_le_bytes());
        payload.extend_from_slice(tx);
    }
    payload
}

/// Handles one pool connection: Noise handshake + TDP message loop.
#[allow(clippy::too_many_lines)]
async fn handle_connection(
    mut stream: TcpStream,
    hub: Arc<Mutex<TemplateHub>>,
    authority_secret: [u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ── Noise handshake ──────────────────────────────────────────
    let secret_key = secp256k1_sv2::SecretKey::from_slice(&authority_secret)
        .map_err(|e| format!("invalid authority key: {e}"))?;
    let secp = secp256k1_sv2::Secp256k1::new();
    let keypair = secp256k1_sv2::Keypair::from_secret_key(&secp, &secret_key);
    let mut responder = Responder::new(keypair, 3600);

    let mut ephemeral_buf = [0u8; ELLSWIFT_ENCODING_SIZE];
    stream.read_exact(&mut ephemeral_buf).await?;

    let (reply, mut noise) = responder
        .step_1(ephemeral_buf)
        .map_err(|e| format!("handshake step_1 failed: {e:?}"))?;

    stream.write_all(&reply).await?;
    stream.flush().await?;

    let mut sig_buf = [0u8; ENCRYPTED_SIGNATURE_NOISE_MESSAGE_SIZE];
    stream.read_exact(&mut sig_buf).await?;
    let mut sig_vec = sig_buf.to_vec();
    let _ = noise.decrypt(&mut sig_vec);

    tracing::info!("Noise handshake completed");

    // ── TDP session ──────────────────────────────────────────────
    let mut last_template_id = 0u64;
    let mut read_buf = [0u8; 8192];
    let mut read_pos = 0usize;

    loop {
        // Push template updates to pool (NewTemplate first, then SetNewPrevHash)
        let update = {
            let mut h = hub.lock();
            h.check_for_update()
        };

        if let Ok(Some(update)) = update {
            if update.template_id != last_template_id {
                last_template_id = update.template_id;

                // Send NewTemplate FIRST (per TDP: it advertises a future template)
                let frame = encode_frame(MSG_NEW_TEMPLATE, &update.new_template);
                let mut enc = frame;
                noise
                    .encrypt(&mut enc)
                    .map_err(|e| format!("encrypt: {e:?}"))?;
                let len = u16::try_from(enc.len()).map_err(|_| "too large")?;
                stream.write_all(&len.to_be_bytes()).await?;
                stream.write_all(&enc).await?;

                // Send SetNewPrevHash SECOND (activates the future template)
                let frame = encode_frame(MSG_SET_NEW_PREV_HASH, &update.set_new_prev_hash);
                let mut enc = frame;
                noise
                    .encrypt(&mut enc)
                    .map_err(|e| format!("encrypt: {e:?}"))?;
                let len = u16::try_from(enc.len()).map_err(|_| "too large")?;
                stream.write_all(&len.to_be_bytes()).await?;
                stream.write_all(&enc).await?;

                stream.flush().await?;
                tracing::info!(
                    template_id = last_template_id,
                    height = update.height,
                    "sent template to pool"
                );
            }
        }

        // Read incoming TDP messages with proper buffering
        match stream.try_read(&mut read_buf[read_pos..]) {
            Ok(0) => {
                tracing::info!("pool disconnected");
                return Ok(());
            }
            Ok(n) => {
                read_pos += n;
                // Process complete messages from the buffer
                while read_pos >= 2 {
                    let msg_len = usize::from(u16::from_le_bytes([read_buf[0], read_buf[1]]));
                    if read_pos < 2 + msg_len {
                        break; // Need more data
                    }
                    let mut msg_data = read_buf[2..2 + msg_len].to_vec();
                    read_buf.copy_within(2 + msg_len.., 0);
                    read_pos -= 2 + msg_len;

                    // Decrypt the message
                    if noise.decrypt(&mut msg_data).is_ok() {
                        // Decrypted: 6-byte SV2 header + payload
                        if msg_data.len() >= 6 {
                            let msg_type = msg_data[2];
                            let payload = &msg_data[6..];
                            match msg_type {
                                MSG_SETUP_CONNECTION => {
                                    tracing::info!("SetupConnection received");
                                    let success = encode_frame(
                                        MSG_SETUP_CONNECTION_SUCCESS,
                                        &build_setup_connection_success(),
                                    );
                                    let mut enc = success;
                                    noise
                                        .encrypt(&mut enc)
                                        .map_err(|e| format!("encrypt: {e:?}"))?;
                                    let len = u16::try_from(enc.len()).map_err(|_| "too large")?;
                                    stream.write_all(&len.to_be_bytes()).await?;
                                    stream.write_all(&enc).await?;
                                    stream.flush().await?;
                                    tracing::info!("SetupConnectionSuccess sent");
                                }
                                MSG_COINBASE_OUTPUT_CONSTRAINTS => {
                                    tracing::info!("CoinbaseOutputConstraints received");
                                }
                                MSG_REQUEST_TRANSACTION_DATA => {
                                    if payload.len() >= 8 {
                                        let template_id =
                                            u64::from_le_bytes(payload[0..8].try_into()?);
                                        tracing::info!(template_id, "RequestTransactionData");
                                        let transactions = {
                                            let h = hub.lock();
                                            h.get_template(template_id)
                                                .map(|t| t.transactions.clone())
                                                .unwrap_or_default()
                                        };
                                        let success = build_request_transaction_data_success(
                                            template_id,
                                            &transactions,
                                        );
                                        let frame = encode_frame(
                                            MSG_REQUEST_TRANSACTION_DATA_SUCCESS,
                                            &success,
                                        );
                                        let mut enc = frame;
                                        noise
                                            .encrypt(&mut enc)
                                            .map_err(|e| format!("encrypt: {e:?}"))?;
                                        let len =
                                            u16::try_from(enc.len()).map_err(|_| "too large")?;
                                        stream.write_all(&len.to_be_bytes()).await?;
                                        stream.write_all(&enc).await?;
                                        stream.flush().await?;
                                    }
                                }
                                MSG_SUBMIT_SOLUTION => {
                                    if payload.len() >= 20 {
                                        let template_id =
                                            u64::from_le_bytes(payload[0..8].try_into()?);
                                        let version =
                                            u32::from_le_bytes(payload[8..12].try_into()?);
                                        let header_timestamp =
                                            u32::from_le_bytes(payload[12..16].try_into()?);
                                        let nonce = u32::from_le_bytes(payload[16..20].try_into()?);
                                        let coinbase_tx = &payload[20..];
                                        tracing::info!(
                                            template_id,
                                            version,
                                            header_timestamp,
                                            nonce,
                                            coinbase_len = coinbase_tx.len(),
                                            "SubmitSolution received"
                                        );

                                        // Reconstruct and submit the block
                                        let result = {
                                            let h = hub.lock();
                                            h.reconstruct_block(
                                                template_id,
                                                version,
                                                header_timestamp,
                                                nonce,
                                                coinbase_tx,
                                            )
                                        };

                                        match result {
                                            Ok(block) => {
                                                let h = hub.lock();
                                                match h.submit_block(block) {
                                                    Ok(validation) => {
                                                        tracing::info!(
                                                            template_id,
                                                            ?validation,
                                                            "block submitted successfully"
                                                        );
                                                    }
                                                    Err(e) => {
                                                        tracing::error!(
                                                            template_id,
                                                            error = %e,
                                                            "block submission failed"
                                                        );
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::error!(
                                                    template_id,
                                                    error = %e,
                                                    "block reconstruction failed"
                                                );
                                            }
                                        }
                                    }
                                }
                                other => {
                                    tracing::debug!(msg_type = other, "unhandled TDP message");
                                }
                            }
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
}
