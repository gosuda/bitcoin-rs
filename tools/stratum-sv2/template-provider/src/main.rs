//! bitcoin-rs SV2 Template Distribution bridge.
//!
//! Translates bitcoin-rs's authoritative mining surface (`getblocktemplate`
//! long-poll + `submitblock`) into the Stratum V2 Template Distribution
//! protocol, so an external SRI pool mines against bitcoin-rs without
//! bitcoin-rs gaining any Stratum dependency. Example for issue #1289.
//!
//! Everything is configured through the environment; see `config_from_env`
//! for the full escape-hatch list.

mod rpc;
mod server;
mod template;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
// Direct dep pinned at 0.28: the secp256k1 the noise layer's key types wrap.
// (`stratum_core::bitcoin::secp256k1` is 0.29 — a different crate version.)
use secp256k1::SecretKey;
use tokio::sync::watch;
use tracing::{error, info};

use crate::rpc::RpcClient;
use crate::template::TemplateState;

/// Example-only Noise keypair material (32 bytes, ASCII
/// `bitcoin-rs sv2 tp example key 01`). Never reuse anywhere real; override
/// with `TP_PRIVATE_KEY_HEX` (64 hex chars). The matching public key is
/// printed at startup so it can be pinned into the pool config.
const EXAMPLE_PRIVATE_KEY_HEX: &str =
    "626974636f696e2d727320737632207470206578616d706c65206b6579203031";

/// How many issued templates stay resolvable by id. Mempool refreshes
/// supersede a template while miners keep working it, so one slot is not
/// enough; the window just has to outlive in-flight shares.
const RETAINED_TEMPLATES: usize = 16;

/// Retry delay for template-loop failures (RPC errors and unconvertible
/// responses both wait instead of spinning against the node).
const RETRY_DELAY: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_pass: String,
    pub cert_validity_secs: u64,
    pub secret_key: Secp256k1SecretKey,
}

/// Env var with a fallback: blank or unset values take the default.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn config_from_env() -> Result<Config, String> {
    let listen = env_or("TP_LISTEN", "0.0.0.0:8442")
        .parse()
        .map_err(|e| format!("TP_LISTEN: {e}"))?;
    let cert_validity_secs = env_or("TP_CERT_VALIDITY_SECS", "3600")
        .parse()
        .map_err(|e| format!("TP_CERT_VALIDITY_SECS: {e}"))?;

    let key_hex = env_or("TP_PRIVATE_KEY_HEX", EXAMPLE_PRIVATE_KEY_HEX);
    let key_bytes = hex::decode(key_hex.trim()).map_err(|e| format!("TP_PRIVATE_KEY_HEX: {e}"))?;
    let secret_key = SecretKey::from_slice(&key_bytes)
        .map(Secp256k1SecretKey)
        .map_err(|e| format!("TP_PRIVATE_KEY_HEX: {e}"))?;

    Ok(Config {
        listen,
        rpc_url: env_or("BITCOINRS_RPC_URL", "http://127.0.0.1:18443"),
        rpc_user: env_or("BITCOINRS_RPC_USER", "bitcoin-rs"),
        rpc_pass: env_or("BITCOINRS_RPC_PASS", "bitcoin-rs"),
        cert_validity_secs,
        secret_key,
    })
}

/// Latest-template fan-out plus id-keyed retention. The long-poll loop
/// publishes; each pool connection subscribes for `NewTemplate` +
/// `SetNewPrevHash` pushes, while `SubmitSolution` /
/// `RequestTransactionData` resolve superseded-but-recent templates by id.
#[derive(Clone)]
pub struct Hub {
    latest: watch::Sender<Option<Arc<TemplateState>>>,
    issued: Arc<Mutex<BTreeMap<u64, Arc<TemplateState>>>>,
    next_id: Arc<AtomicU64>,
}

impl Hub {
    fn new() -> Self {
        Self {
            latest: watch::channel(None).0,
            issued: Arc::new(Mutex::new(BTreeMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    fn subscribe(&self) -> watch::Receiver<Option<Arc<TemplateState>>> {
        self.latest.subscribe()
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Resolves an issued template by id, including superseded ones still
    /// within the retention window.
    pub fn lookup(&self, template_id: u64) -> Option<Arc<TemplateState>> {
        self.issued
            .lock()
            .expect("issued map poisoned")
            .get(&template_id)
            .cloned()
    }

    /// Replaces the latest template and notifies subscribers. The issued map
    /// retains it (bounded to `RETAINED_TEMPLATES` most recent) so in-flight
    /// work on superseded templates still resolves.
    fn publish(&self, state: TemplateState) {
        let state = Arc::new(state);
        {
            let mut issued = self.issued.lock().expect("issued map poisoned");
            issued.insert(state.id, Arc::clone(&state));
            while issued.len() > RETAINED_TEMPLATES {
                issued.pop_first();
            }
        }
        // `send` silently drops the value while the channel has zero
        // receivers (e.g. every publish before the first pool connects);
        // `send_replace` stores it unconditionally and still notifies.
        self.latest.send_replace(Some(state));
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = match config_from_env() {
        Ok(config) => config,
        Err(e) => {
            error!(error = %e, "invalid configuration");
            std::process::exit(2);
        }
    };

    info!(
        listen = %config.listen,
        rpc = %config.rpc_url,
        pubkey = %Secp256k1PublicKey::from(config.secret_key),
        "bitcoin-rs SV2 template provider starting — pin this pubkey under \
         [template_provider_type.Sv2Tp] in the pool config"
    );

    let rpc = Arc::new(RpcClient::new(
        &config.rpc_url,
        &config.rpc_user,
        &config.rpc_pass,
    ));
    let hub = Hub::new();

    let gbt_task = {
        let rpc = Arc::clone(&rpc);
        let hub = hub.clone();
        tokio::spawn(async move {
            if let Err(e) = template_loop(rpc, hub).await {
                error!(error = %e, "template loop terminated");
                std::process::exit(1);
            }
        })
    };

    let listener_task = tokio::spawn(server::run(config, hub));

    tokio::signal::ctrl_c().await.ok();
    info!("shutdown signal received");
    gbt_task.abort();
    listener_task.abort();
}

/// Blocks on `getblocktemplate`: the first call returns immediately (with a
/// retry loop while the regtest node finishes booting), then each call
/// long-polls so every tip or mempool change issues a fresh template.
/// Only an unrecoverable client error terminates the loop.
async fn template_loop(rpc: Arc<RpcClient>, hub: Hub) -> Result<(), String> {
    let mut long_poll_id: Option<String> = None;
    loop {
        match rpc.get_block_template(long_poll_id.as_deref()).await {
            Ok(gbt) => {
                long_poll_id = Some(gbt.long_poll_id);
                match TemplateState::from_gbt(hub.next_id(), &gbt.raw) {
                    Ok(state) => {
                        info!(
                            template_id = state.id,
                            height = state.height,
                            txs = state.txs.len(),
                            value_remaining = state.value_remaining,
                            "issued template"
                        );
                        hub.publish(state);
                    }
                    Err(e) => {
                        error!(error = %e, "failed to convert getblocktemplate response");
                        // Re-poll without a long-poll id; the sleep keeps a
                        // persistent bad response from spinning the loop.
                        long_poll_id = None;
                        tokio::time::sleep(RETRY_DELAY).await;
                    }
                }
            }
            Err(e) => {
                info!(error = %e, "getblocktemplate not ready yet, retrying");
                tokio::time::sleep(RETRY_DELAY).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn gbt() -> serde_json::Value {
        json!({
            "version": 0x20000000u32,
            "bits": "207fffff",
            "curtime": 1_700_000_000u64,
            "previousblockhash": "00".repeat(32),
            "height": 1u64,
            "coinbasevalue": 5_000_000_000u64,
            "default_witness_commitment": null,
            "transactions": [],
        })
    }

    /// `watch::Sender::send` discards the value while rx_count == 0, so a
    /// publish before any pool subscribes must still reach the subscriber.
    #[test]
    fn publish_before_subscribe_is_visible() {
        let hub = Hub::new();
        hub.publish(TemplateState::from_gbt(1, &gbt()).unwrap());
        let mut rx = hub.subscribe();
        assert_eq!(
            rx.borrow_and_update().as_ref().map(|s| s.id),
            Some(1),
            "template published with zero receivers must be stored"
        );
    }
}
