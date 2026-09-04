//! RAII harness: a real regtest `NodeState`, the real authenticated
//! `RpcServer` on loopback, and the replay client that exercises them.
//!
//! Every handle the RPC context consumes comes from the live `NodeState`
//! exactly the way the daemon wires them (`crates/node/src/run.rs`); nothing
//! here constructs a fake or empty context. The server thread and the
//! shutdown flag are joined and released by `Drop`, and the temporary data
//! directory is deleted after the node state closes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use bitcoin_rs_mempool::MempoolGateway;
use bitcoin_rs_node::state::NodeState;
use bitcoin_rs_rpc::context::{
    ChainHandles, Context, ContextHandles, IndexHandles, MempoolHandles, NetworkHandles,
};
use bitcoin_rs_rpc::{Auth, Handler, RpcServer};
use tempfile::TempDir;

use super::chain::{SeedChain, apply_genesis, current_tip, regtest_config, seed_chain};
use super::compare::LiveChain;
use super::fixture::RequestAuth;
use super::http::{Connection, RawRequest, RawResponse, base64, wait_for_server};
use super::limits::{SERVER_IDLE_TIMEOUT, SERVER_MAX_CONNECTIONS};
use super::{GateResult, fail};

/// The replay credentials, matching the `user:password` Basic shape the
/// authentication layer expects.
pub(crate) const REPLAY_USER: &str = "parity";
pub(crate) const REPLAY_PASSWORD: &str = "parity-secret";

/// A real regtest node over a temporary data directory.
///
/// Field order is load-bearing: `state` closes its storage handles before
/// `_datadir` deletes the directory.
pub(crate) struct NodeHarness {
    /// Live node state, dropped before the directory.
    pub state: NodeState,
    _datadir: TempDir,
}

impl NodeHarness {
    /// Opens a fresh regtest node and applies genesis.
    ///
    /// # Errors
    /// Propagates node open or genesis failures.
    pub(crate) fn open() -> GateResult<Self> {
        let datadir = tempfile::tempdir()?;
        let config = regtest_config(&datadir.path().join("node"));
        let state = NodeState::open(config, None).map_err(fail)?;
        apply_genesis(&state)?;
        Ok(Self {
            state,
            _datadir: datadir,
        })
    }

    /// Mines the deterministic seed chain.
    ///
    /// # Errors
    /// Propagates validation failures.
    pub(crate) fn seed(&self, blocks: u32) -> GateResult<SeedChain> {
        seed_chain(&self.state, blocks)
    }

    /// Reads the chain identity used for chain-bound key comparison. Both
    /// values come from the node state directly, never from an RPC answer.
    ///
    /// # Errors
    /// Fails when the applied tip is missing.
    pub(crate) fn live_chain(&self) -> GateResult<LiveChain> {
        let applied = current_tip(&self.state)?;
        let headers = self
            .state
            .chain_tip()
            .load_full()
            .map_or(applied.height, |header| header.height);
        Ok(LiveChain {
            blocks: u64::from(applied.height),
            headers: u64::from(headers),
            best_block_hash: applied.hash.to_string_be(),
        })
    }
}

/// The real `RpcServer` on `127.0.0.1:0`, driven from one worker thread and
/// shut down by `Drop`.
pub(crate) struct ServerHarness {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl ServerHarness {
    /// Wires the production RPC context over `node` and starts the server.
    ///
    /// Mining is deliberately unattached: this gate measures the chain and
    /// transport surfaces, not the template coordinator.
    ///
    /// # Errors
    /// Propagates bind failures.
    pub(crate) fn start(node: &NodeHarness) -> GateResult<Self> {
        let state = &node.state;
        let ctx = Context::from_handles(ContextHandles {
            chain: ChainHandles {
                chain_tip: state.chain_tip(),
                applied_tip: state.applied_tip(),
                blocks: state.blocks(),
                transactions: state.transactions(),
                utxo: state.utxo(),
                coin_stats: state.coin_stats(),
                block_tree: state.block_tree(),
                chain_network: state.config().network,
            },
            mempool: MempoolHandles {
                mempool: MempoolGateway::shared(state.mempool()),
            },
            indexes: IndexHandles {
                tx_index: state.tx_index_query(),
                script_index: state.script_index_query(),
            },
            network: NetworkHandles {
                network: state.network(),
                network_active: state.network_active(),
                peer_table: state.peer_table(),
                p2p_outbound_sender: Some(state.p2p_outbound_sender()),
                banned: state.banned_subnets(),
                added_nodes: Arc::new(parking_lot::RwLock::new(Vec::new())),
            },
            mining: bitcoin_rs_rpc::context::MiningHandles {
                mining_control: None,
            },
            capabilities: Some(state.capability_provider()),
        });
        let handler = Arc::new(Handler::new(Arc::new(ctx)));
        let auth = Arc::new(Auth::basic(REPLAY_USER, REPLAY_PASSWORD));
        let server = RpcServer::bind(
            "127.0.0.1:0",
            auth,
            handler,
            SERVER_MAX_CONNECTIONS,
            SERVER_IDLE_TIMEOUT,
            false,
        )?;
        let address = server.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);
        let join = std::thread::spawn(move || {
            // Shutdown errors at teardown are expected and ignored.
            let _ignored = server.serve_with_shutdown(flag);
        });
        wait_for_server(address)?;
        Ok(Self {
            address,
            shutdown,
            join: Some(join),
        })
    }

    /// Bound loopback address.
    #[must_use]
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// Base64 token of the correct `user:password` credentials.
    #[must_use]
    pub(crate) fn basic_token() -> String {
        base64(format!("{REPLAY_USER}:{REPLAY_PASSWORD}").as_bytes())
    }

    /// Base64 token of deliberately wrong credentials.
    #[must_use]
    pub(crate) fn wrong_token() -> String {
        base64(b"parity:not-the-password")
    }

    /// Replays one request and decodes exactly one framed response.
    ///
    /// `fragment_at`, when present, splits the wire bytes into two writes
    /// with a flush between them.
    ///
    /// # Errors
    /// Propagates transport or framing failures.
    pub(crate) fn replay(
        &self,
        auth: RequestAuth,
        body: &str,
        fragment_at: Option<usize>,
    ) -> GateResult<RawResponse> {
        let authorization = match auth {
            RequestAuth::Valid => Some(Self::basic_token()),
            RequestAuth::Invalid => Some(Self::wrong_token()),
            RequestAuth::Absent => None,
        };
        let request = RawRequest {
            path: "/",
            authorization,
            body: body.to_owned(),
            keep_alive: true,
        };
        let bytes = request.bytes();
        let mut connection = Connection::connect(self.address)?;
        connection.send_request_fragmented(&bytes, fragment_at)?;
        Ok(connection.read_response()?)
    }
}

impl Drop for ServerHarness {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            // A join failure at teardown must not panic inside Drop.
            let _ignored = join.join();
        }
    }
}
