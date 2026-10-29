//! RAII harness: a real regtest `NodeState`, the real authenticated
//! `RpcServer` on loopback, and the replay client that exercises them.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

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

pub(crate) const REPLAY_USER: &str = "parity";
pub(crate) const REPLAY_PASSWORD: &str = "parity-secret";

/// Field order is load-bearing: `state` closes its storage handles before
/// `_datadir` deletes the directory.
pub(crate) struct NodeHarness {
    pub state: NodeState,
    _datadir: TempDir,
}

impl NodeHarness {
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

    pub(crate) fn seed(&self, blocks: u32) -> GateResult<SeedChain> {
        seed_chain(&self.state, blocks)
    }

    pub(crate) fn live_chain(&self) -> GateResult<LiveChain> {
        let applied = current_tip(&self.state)?;
        let headers = self
            .state
            .chainstate()
            .header_tip()
            .map_or(applied.height, |header| header.height);
        Ok(LiveChain {
            blocks: u64::from(applied.height),
            headers: u64::from(headers),
            best_block_hash: applied.hash.to_string_be(),
        })
    }
}

pub(crate) struct ServerHarness {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    transition: bitcoin_rs_chain::StableRead,
}

impl ServerHarness {
    pub(crate) fn start(node: &NodeHarness) -> GateResult<Self> {
        let state = &node.state;
        let chainstate = state.chainstate();
        let transition = state.stable_read();
        let ctx = Context::from_handles(ContextHandles {
            chain: ChainHandles {
                chain_tip: chainstate.header_tip_reader(),
                applied_tip: chainstate.applied_tip_reader(),
                active_tip_wait: Some(chainstate.clone()),
                progress: chainstate.chain_progress_reader(),
                blocks: state.block_log_reader(),
                utxo: chainstate.utxo_reader(),
                coin_stats: chainstate.coin_stats_handle(),
                block_tree: chainstate.block_tree_reader(),
                chain_network: state.config().network,
                closed_for_recovery: chainstate.closed_for_recovery_reader(),
                chain_transition: transition.clone(),
                ..ChainHandles::default()
            },
            mempool: MempoolHandles {
                gateway: state.mempool_gateway(),
            },
            indexes: IndexHandles {
                derived_index: state.derived_index_query(),
                script_index: state.script_index_query(),
                compact_filters: state.compact_filter_query(),
                esplora_tx_index: None,
                derived_index_status: Some(state.derived_index_status()),
            },
            network: NetworkHandles {
                overlay: bitcoin_rs_p2p::overlay::OverlayConfig::default(),
                peer_table: state.peer_table(),
                p2p: state.p2p(),
                local_services: state.p2p().local_services().to_u64(),
            },
            mining: bitcoin_rs_rpc::context::MiningHandles {
                mining_control: None,
            },
            ..ContextHandles::default()
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
            let _ignored = server.serve_with_shutdown(flag);
        });
        wait_for_server(address)?;
        Ok(Self {
            address,
            shutdown,
            join: Some(join),
            transition,
        })
    }

    #[must_use]
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    #[must_use]
    pub(crate) fn chain_transition(&self) -> bitcoin_rs_chain::StableRead {
        self.transition.clone()
    }

    #[must_use]
    pub(crate) fn basic_token() -> String {
        base64(format!("{REPLAY_USER}:{REPLAY_PASSWORD}").as_bytes())
    }

    #[must_use]
    pub(crate) fn wrong_token() -> String {
        base64(b"parity:not-the-password")
    }

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
            let _ignored = join.join();
        }
    }
}
