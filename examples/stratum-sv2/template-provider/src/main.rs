//! bitcoin-rs SV2 Template Distribution bridge.
//!
//! Translates bitcoin-rs's authoritative mining surface (getblocktemplate with
//! long-poll + submitblock) into the Stratum V2 Template Distribution
//! protocol, so an external SRI pool can mine against bitcoin-rs without
//! bitcoin-rs gaining any Stratum dependency. Example for issue #1289.

mod rpc;
mod server;
mod template;

use std::net::SocketAddr;

use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use tokio::sync::watch;
use tracing::{error, info};

use crate::rpc::RpcClient;
use crate::template::TemplateState;

/// Example-only noise keypair material. Regtest example; never reuse anywhere
/// real. Override with `TP_PRIVATE_KEY_HEX` (64 hex chars).
const EXAMPLE_PRIVATE_KEY_HEX: &str =
    "626974636f696e2d727320737632207470206578616d706c65206b6579203031";

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_pass: String,
    pub cert_validity: u64,
    pub secret_key: Secp256k1SecretKey,
}

impl Config {
    /// Reads environment overrides with regtest defaults, rejecting invalid
    /// listener addresses, certificate lifetimes, and Noise private keys.
    fn from_env() -> Result<Self, String> {
        let listen = env_or("TP_LISTEN", "0.0.0.0:8442")
            .parse()
            .map_err(|e| format!("TP_LISTEN: {e}"))?;
        let rpc_url = env_or("BITCOINRS_RPC_URL", "http://127.0.0.1:18443");
        let rpc_user = env_or("BITCOINRS_RPC_USER", "bitcoin-rs");
        let rpc_pass = env_or("BITCOINRS_RPC_PASS", "bitcoin-rs");
        let cert_validity = env_or("TP_CERT_VALIDITY_SECS", "3600")
            .parse()
            .map_err(|e| format!("TP_CERT_VALIDITY_SECS: {e}"))?;
        let secret_hex = std::env::var("TP_PRIVATE_KEY_HEX")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| EXAMPLE_PRIVATE_KEY_HEX.to_string());
        let secret_bytes =
            hex::decode(secret_hex.trim()).map_err(|e| format!("TP_PRIVATE_KEY_HEX: {e}"))?;
        if secret_bytes.len() != 32 {
            return Err(format!(
                "TP_PRIVATE_KEY_HEX must be 32 bytes, got {}",
                secret_bytes.len()
            ));
        }
        let secret_key = Secp256k1SecretKey(
            secp256k1::SecretKey::from_slice(&secret_bytes)
                .map_err(|e| format!("TP_PRIVATE_KEY_HEX: {e}"))?,
        );
        Ok(Self {
            listen,
            rpc_url,
            rpc_user,
            rpc_pass,
            cert_validity,
            secret_key,
        })
    }
}

/// Returns the environment value unchanged, or the default if absent,
/// non-Unicode, or blank after trimming.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Shared template hub. The long-poll loop publishes; every pool connection
/// subscribes and pushes `NewTemplate` + `SetNewPrevHash` on change. Recently
/// issued templates stay addressable by id: a miner working a superseded
/// template still gets its `SubmitSolution` / `RequestTransactionData`
/// resolved instead of dropped as unknown.
#[derive(Clone)]
pub struct Hub {
    tx: watch::Sender<Option<std::sync::Arc<TemplateState>>>,
    next_id: std::sync::Arc<std::sync::atomic::AtomicU64>,
    issued: std::sync::Arc<
        parking_lot::Mutex<std::collections::BTreeMap<u64, std::sync::Arc<TemplateState>>>,
    >,
}

/// How many issued templates stay resolvable by id. A mempool refresh issues
/// a new template while miners keep working the previous one, so one slot is
/// not enough.
const RETAINED_TEMPLATES: usize = 16;

impl Hub {
    /// Creates an empty template slot with the first template ID set to one.
    fn new() -> Self {
        let (tx, _) = watch::channel(None);
        Self {
            tx,
            next_id: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
            issued: std::sync::Arc::new(parking_lot::Mutex::new(std::collections::BTreeMap::new())),
        }
    }

    /// Subscribes to the latest template and subsequent replacements.
    fn subscribe(&self) -> watch::Receiver<Option<std::sync::Arc<TemplateState>>> {
        self.tx.subscribe()
    }

    /// Allocates the next template ID from the counter shared by hub clones.
    fn next_id(&self) -> u64 {
        self.next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Resolves an issued template by id, including superseded ones still
    /// within the retention window.
    pub fn lookup(&self, template_id: u64) -> Option<std::sync::Arc<TemplateState>> {
        self.issued.lock().get(&template_id).cloned()
    }

    /// Replaces the latest template, notifies subscribers, and returns its
    /// shared handle; the slot retains it even without subscribers.
    fn publish(&self, state: TemplateState) -> std::sync::Arc<TemplateState> {
        let state = std::sync::Arc::new(state);
        {
            let mut issued = self.issued.lock();
            issued.insert(state.id, state.clone());
            while issued.len() > RETAINED_TEMPLATES {
                issued.pop_first();
            }
        }
        self.tx.send_replace(Some(state.clone()));
        state
    }
}

/// Starts the template polling loop and pool listener, then aborts both tasks
/// when Ctrl-C is received. Invalid configuration exits with status two.
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "invalid configuration");
            std::process::exit(2);
        }
    };

    let public_key = Secp256k1PublicKey::from(config.secret_key);
    info!(
        listen = %config.listen,
        rpc = %config.rpc_url,
        "bitcoin-rs SV2 template provider starting — paste this public key into the pool config under [template_provider_type.Sv2Tp] public_key = \"{}\"",
        public_key
    );

    let rpc = RpcClient::new(
        config.rpc_url.clone(),
        config.rpc_user.clone(),
        config.rpc_pass.clone(),
    );
    let hub = Hub::new();

    let gbt_hub = hub.clone();
    let rpc = std::sync::Arc::new(rpc);
    let gbt_task = tokio::spawn(async move {
        if let Err(e) = run_template_loop(rpc, gbt_hub).await {
            error!(error = ?e, "template loop terminated");
            std::process::exit(1);
        }
    });

    let listener_task = tokio::spawn(server::run(config, hub));

    tokio::signal::ctrl_c().await.ok();
    info!("shutdown signal received");
    gbt_task.abort();
    listener_task.abort();
}

/// Blocks on bitcoin-rs getblocktemplate: first template immediately (with
/// bootstrap retry while the regtest node finishes genesis), then one
/// long-poll per template so every tip/mempool change issues a new template.
async fn run_template_loop(rpc: std::sync::Arc<RpcClient>, hub: Hub) -> Result<(), rpc::RpcError> {
    let mut long_poll_id: Option<String> = None;
    loop {
        match rpc.get_block_template(long_poll_id.as_deref()).await {
            Ok(gbt) => {
                long_poll_id = Some(gbt.long_poll_id.clone());
                let id = hub.next_id();
                match TemplateState::from_gbt(id, &gbt.raw) {
                    Ok(state) => {
                        info!(
                            template_id = state.id,
                            height = state.height,
                            txs = state.txs.len(),
                            value_remaining = state.value_remaining,
                            longpoll = %gbt.long_poll_id,
                            "issued template"
                        );
                        hub.publish(state);
                    }
                    Err(e) => {
                        error!(template_id = id, error = %e, "failed to convert getblocktemplate response");
                        long_poll_id = None;
                        // The next fetch has no long-poll id and returns at
                        // once; without a delay a persistent bad response
                        // spins the loop and floods the RPC.
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
            Err(e) => {
                info!(error = %e, "getblocktemplate not ready yet, retrying");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}
