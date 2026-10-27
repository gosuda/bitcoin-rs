//! Regtest-only embedded Node -> SV2 Template Distribution adapter.
mod server;
mod template;

use bitcoin_rs_mining::{
    BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult, Candidate, MiningControlError,
    TemplateId,
};
use bitcoin_rs_node::{Network, Node, NodeConfig, RuntimeInputs};
use futures_executor::block_on;
use secp256k1::SecretKey;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use template::TemplateState;
use tokio::sync::watch;
use tracing::{info, warn};

const EXAMPLE_PRIVATE_KEY_HEX: &str =
    "626974636f696e2d727320737632207470206578616d706c65206b6579203031";
const RETAINED_TEMPLATES: usize = 16;
const TEMPLATE_RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub cert_validity_secs: u64,
    pub secret_key: Secp256k1SecretKey,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn config_from_env() -> Result<(Config, NodeConfig), String> {
    let mut node = NodeConfig::default_for_network(Network::Regtest);
    node.data_dir = env_or("BITCOINRS_DATA_DIR", ".bitcoin-rs-sv2").into();
    node.rpc.bind = env_or("BITCOINRS_RPC_BIND", "127.0.0.1:0")
        .parse()
        .map_err(|e| format!("RPC bind: {e}"))?;
    node.p2p.listen = vec![
        env_or("BITCOINRS_P2P_LISTEN", "127.0.0.1:0")
            .parse()
            .map_err(|e| format!("P2P listen: {e}"))?,
    ];
    node.p2p.dns_seeds_enabled = false;
    node.storage.dbcache_mb = 32;
    node.validate().map_err(|e| e.to_string())?;
    let key = hex::decode(env_or("TP_PRIVATE_KEY_HEX", EXAMPLE_PRIVATE_KEY_HEX))
        .map_err(|e| e.to_string())?;
    Ok((
        Config {
            listen: env_or("TP_LISTEN", "0.0.0.0:8442")
                .parse()
                .map_err(|e| format!("TP_LISTEN: {e}"))?,
            cert_validity_secs: env_or("TP_CERT_VALIDITY_SECS", "3600")
                .parse()
                .map_err(|e| format!("TP_CERT_VALIDITY_SECS: {e}"))?,
            secret_key: Secp256k1SecretKey(SecretKey::from_slice(&key).map_err(|e| e.to_string())?),
        },
        node,
    ))
}

/// Shared by every session: a generation counter that wakes them, and the
/// bounded history of jobs they issued. A session pins its own current job, so
/// this history only has to answer for superseded ones.
#[derive(Clone)]
pub struct Hub {
    generation: watch::Sender<u64>,
    issued: Arc<Mutex<BTreeMap<u64, Arc<TemplateState>>>>,
    next_id: Arc<AtomicU64>,
}

impl Hub {
    fn new() -> Self {
        Self {
            generation: watch::channel(0).0,
            issued: Arc::new(Mutex::new(BTreeMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }
    fn subscribe(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }
    /// Tells every session the mining owner's generation moved. It carries no
    /// candidate: each session asks the owner for one fitting its own budget.
    fn wake(&self) {
        self.generation.send_modify(|count| *count += 1);
    }
    pub fn lookup(&self, id: u64) -> Option<Arc<TemplateState>> {
        self.issued.lock().unwrap().get(&id).cloned()
    }
    /// Returns the retained job for `candidate`'s owner identity, or retains a
    /// new one. Sessions given equal identities share one id and one state.
    fn issue(&self, candidate: Arc<Candidate>) -> Arc<TemplateState> {
        if let Some(state) = retained(&self.issued.lock().unwrap(), &candidate.template_id) {
            return state;
        }
        // Built before taking the lock again: hashing the merkle branch is
        // linear in the transaction count.
        let state = Arc::new(TemplateState::new(
            self.next_id.fetch_add(1, Ordering::Relaxed),
            candidate,
        ));
        let mut issued = self.issued.lock().unwrap();
        if let Some(raced) = retained(&issued, &state.candidate.template_id) {
            return raced;
        }
        issued.insert(state.id, Arc::clone(&state));
        while issued.len() > RETAINED_TEMPLATES {
            issued.pop_first();
        }
        state
    }
}

fn retained(
    issued: &BTreeMap<u64, Arc<TemplateState>>,
    identity: &TemplateId,
) -> Option<Arc<TemplateState>> {
    issued
        .values()
        .find(|state| state.candidate.template_id == *identity)
        .map(Arc::clone)
}

// A dedicated OS worker owns the synchronous long poll. It holds no Node lock
// between calls, and the injected normal shutdown signal cancels the wait. Its
// unconstrained template is never sent to a pool: it only wakes the sessions.
fn template_loop(
    mut get_template: impl FnMut(
        BlockTemplateRequest,
    ) -> Result<BlockTemplateResult, MiningControlError>,
    hub: Hub,
) -> Result<(), String> {
    let mut long_poll_id = None;
    loop {
        let request = BlockTemplateRequest {
            mode: BlockTemplateMode::Template,
            capabilities: vec![],
            rules: vec![],
            long_poll_id: long_poll_id.clone(),
            coinbase_budget: None,
        };
        let result = match get_template(request) {
            Ok(result) => result,
            Err(error) if error.is_template_generation_race() => {
                warn!(%error, "template generation raced; retrying");
                // The next acquisition rechecks the node shutdown latch;
                // this delay bounds both retry load and added shutdown latency.
                std::thread::sleep(TEMPLATE_RETRY_DELAY);
                continue;
            }
            Err(error) => return Err(error.to_string()),
        };
        let BlockTemplateResult::Template(template) = result else {
            return Err("unexpected proposal response".into());
        };
        long_poll_id = Some(template.candidate.template_id.as_str().into());
        hub.wake();
        info!(
            height = template.candidate.height,
            "generation changed; waking sessions"
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let (config, node_config) = config_from_env()?;
    info!(listen = %config.listen, pubkey = %Secp256k1PublicKey::from(config.secret_key), "embedded regtest template provider starting");
    let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
    let node = Arc::new(
        tokio::task::spawn_blocking(move || {
            block_on(Node::start(
                node_config,
                RuntimeInputs::default().with_shutdown(shutdown_rx),
            ))
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?,
    );
    let hub = Hub::new();
    let (ended_tx, mut ended_rx) = tokio::sync::oneshot::channel();
    let worker_node = Arc::clone(&node);
    let worker_hub = hub.clone();
    let worker = std::thread::spawn(move || {
        let result = worker_node
            .mining_control()
            .map_err(|e| e.to_string())
            .and_then(|mining| {
                template_loop(|request| mining.get_block_template(request), worker_hub)
            });
        let _ = ended_tx.send(result);
    });
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut listener = tokio::spawn(server::run(config, hub, Arc::clone(&node), stop_rx));
    let (outcome, listener_joined) = tokio::select! {
        result = tokio::signal::ctrl_c() => (result.map_err(|e| e.to_string()), false),
        result = &mut listener => (result.map_err(|e| e.to_string()).and_then(|r| r), true),
        result = &mut ended_rx => (result.map_err(|e| e.to_string()).and_then(|r| r), false),
    };
    stop_tx.send_replace(true);
    // Drain sessions and their blocking submission calls before stopping Node.
    let listener_outcome = if listener_joined {
        Ok(())
    } else {
        listener.await.map_err(|e| e.to_string()).and_then(|r| r)
    };
    let _ = shutdown_tx.try_send(());
    let worker_outcome = tokio::task::spawn_blocking(move || worker.join())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|_| "template worker panicked".to_owned());
    let node = Arc::try_unwrap(node).map_err(|_| "node still borrowed after workers joined")?;
    tokio::task::spawn_blocking(move || block_on(node.shutdown()))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    outcome.and(listener_outcome).and(worker_outcome)
}

#[cfg(test)]
mod tests;
