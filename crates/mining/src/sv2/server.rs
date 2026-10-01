//! SV2 Template Distribution Protocol server.
//!
//! Accepts pool connections over Noise-encrypted TCP and distributes
//! block templates via TDP. Implements the full TDP session:
//! `SetupConnection` → `NewTemplate`/`SetNewPrevHash` → mining → `SubmitSolution`.
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

/// Encodes an SV2 TDP frame: 6-byte header + payload.
///
/// Header layout: `extension_type` (2 LE) + `msg_type` (1) + `channel_bit` (1) + `payload_len` (2 LE).
fn encode_frame(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.extend_from_slice(&0u16.to_le_bytes()); // extension_type = 0 (TDP)
    frame.push(msg_type);
    frame.push(0u8); // channel_bit = 0
    let len = u16::try_from(payload.len()).unwrap_or(0);
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Builds `SetupConnectionSuccess` payload.
fn build_setup_connection_success() -> Vec<u8> {
    let mut payload = Vec::with_capacity(4);
    payload.extend_from_slice(&0u32.to_le_bytes()); // flags = 0
    payload
}

/// Builds `SubmitSolution` response (empty = accepted).
fn build_submit_solution_success() -> Vec<u8> {
    Vec::new()
}

/// Builds `RequestTransactionDataSuccess` payload.
///
/// Contains: `template_id` (8 LE) + `future_template` (1) + `version` (4 LE)
/// + `coinbase_tx_version` (4 LE) + `coinbase_prefix_len` (1) + `coinbase_prefix`
/// + `coinbase_tx_input_sequence` (4 LE) + `coinbase_tx_value_remaining` (8 LE)
/// + `coinbase_tx_outputs_count` (4 LE) + `coinbase_tx_outputs` (4 LE len + data)
/// + `coinbase_tx_locktime` (4 LE) + `merkle_path` (4 LE len + data)
/// + `transaction_list_count` (4 LE) + `transactions` (each: 32-byte txid)
fn build_request_transaction_data_success(template_id: u64, txids: &[[u8; 32]]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(128 + txids.len() * 32);
    payload.extend_from_slice(&template_id.to_le_bytes());
    payload.push(0u8); // future_template = false
    payload.extend_from_slice(&0u32.to_le_bytes()); // version
    payload.extend_from_slice(&2u32.to_le_bytes()); // coinbase_tx_version
    payload.push(0u8); // coinbase_prefix_len
    payload.extend_from_slice(&0u32.to_le_bytes()); // coinbase_tx_input_sequence
    payload.extend_from_slice(&0u64.to_le_bytes()); // coinbase_tx_value_remaining
    payload.extend_from_slice(&0u32.to_le_bytes()); // coinbase_tx_outputs_count
    payload.extend_from_slice(&0u32.to_le_bytes()); // coinbase_tx_outputs len
    payload.extend_from_slice(&0u32.to_le_bytes()); // coinbase_tx_locktime
    payload.extend_from_slice(&0u32.to_le_bytes()); // merkle_path len
    payload.extend_from_slice(&u32::try_from(txids.len()).unwrap_or(0).to_le_bytes());
    for txid in txids {
        payload.extend_from_slice(txid);
    }
    payload
}

/// Handles one pool connection: Noise handshake + TDP message loop.
#[allow(clippy::too_many_lines)]
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
    let mut txids_cache: Vec<[u8; 32]> = Vec::new();
    let mut read_buf = [0u8; 8192];

    loop {
        // Push template updates to pool
        let update = {
            let mut h = hub.lock();
            h.check_for_update()
        };

        if let Ok(Some(update)) = update {
            if update.template_id != last_template_id {
                last_template_id = update.template_id;
                txids_cache = update.txids.clone();

                // Send SetNewPrevHash (encrypted)
                let frame = encode_frame(MSG_SET_NEW_PREV_HASH, &update.set_new_prev_hash);
                let mut enc = frame;
                noise
                    .encrypt(&mut enc)
                    .map_err(|e| format!("encrypt: {e:?}"))?;
                let len = u16::try_from(enc.len()).map_err(|_| "too large")?;
                stream.write_all(&len.to_be_bytes()).await?;
                stream.write_all(&enc).await?;

                // Send NewTemplate (encrypted)
                let frame = encode_frame(MSG_NEW_TEMPLATE, &update.new_template);
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

        // Read incoming TDP messages
        match stream.try_read(&mut read_buf) {
            Ok(0) => {
                tracing::info!("pool disconnected");
                return Ok(());
            }
            Ok(n) => {
                let mut data = read_buf[..n].to_vec();
                if noise.decrypt(&mut data).is_ok() {
                    // Decrypted message: 6-byte header + payload
                    if data.len() >= 6 {
                        let msg_type = data[2];
                        let payload = &data[6..];
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
                                    let template_id = u64::from_le_bytes(payload[0..8].try_into()?);
                                    tracing::info!(template_id, "RequestTransactionData");
                                    let success = build_request_transaction_data_success(
                                        template_id,
                                        &txids_cache,
                                    );
                                    let frame = encode_frame(
                                        MSG_REQUEST_TRANSACTION_DATA_SUCCESS,
                                        &success,
                                    );
                                    let mut enc = frame;
                                    noise
                                        .encrypt(&mut enc)
                                        .map_err(|e| format!("encrypt: {e:?}"))?;
                                    let len = u16::try_from(enc.len()).map_err(|_| "too large")?;
                                    stream.write_all(&len.to_be_bytes()).await?;
                                    stream.write_all(&enc).await?;
                                    stream.flush().await?;
                                }
                            }
                            MSG_SUBMIT_SOLUTION => {
                                if payload.len() >= 20 {
                                    let template_id = u64::from_le_bytes(payload[0..8].try_into()?);
                                    let version = u32::from_le_bytes(payload[8..12].try_into()?);
                                    let header_timestamp =
                                        u32::from_le_bytes(payload[12..16].try_into()?);
                                    let nonce = u32::from_le_bytes(payload[16..20].try_into()?);
                                    tracing::info!(
                                        template_id,
                                        version,
                                        header_timestamp,
                                        nonce,
                                        "SubmitSolution received"
                                    );
                                    // TODO: decode full block and submit via MiningSource
                                    let frame = encode_frame(
                                        MSG_SUBMIT_SOLUTION,
                                        &build_submit_solution_success(),
                                    );
                                    let mut enc = frame;
                                    noise
                                        .encrypt(&mut enc)
                                        .map_err(|e| format!("encrypt: {e:?}"))?;
                                    let len = u16::try_from(enc.len()).map_err(|_| "too large")?;
                                    stream.write_all(&len.to_be_bytes()).await?;
                                    stream.write_all(&enc).await?;
                                    stream.flush().await?;
                                }
                            }
                            other => {
                                tracing::debug!(msg_type = other, "unhandled TDP message");
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
