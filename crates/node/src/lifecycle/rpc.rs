//! RPC composition over the node's authoritative and derived handles.

use anyhow::Result;

use bitcoin_rs_chain::BlockBodySource;

use bitcoin_rs_mining::MiningControl;

use bitcoin_rs_rpc::{
    RpcServer,
    context::{
        ChainControl, ChainControlError, ChainHandles, Context, ContextHandles, IndexHandles,
        MempoolHandles, MiningHandles, NetworkHandles,
    },
};

use crate::state::NodeState;

use std::{sync::Arc, time::Duration};

const RPC_MAX_CONNECTIONS: usize = 128;
const RPC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct RpcChainControl {
    handles: crate::apply::Chainstate,
    followers: crate::chain_effects::ChainFollowers,
}

impl ChainControl for RpcChainControl {
    fn invalidate_block(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> core::result::Result<(), ChainControlError> {
        crate::reorg::invalidate_block(&self.handles, &self.followers, hash).map_err(|error| {
            match error {
                crate::reorg::ReorgError::UnknownBlock(_) => ChainControlError::UnknownBlock,
                crate::reorg::ReorgError::CannotInvalidateGenesis => ChainControlError::Genesis,
                other => ChainControlError::Failed(other.to_string()),
            }
        })
    }
}

/// Binds the RPC listener without spawning a worker. Startup records the
/// worker immediately after spawning, so a later failure cannot detach it.
pub(super) fn bind_rpc(
    state: &NodeState,
    mining_control: &Arc<dyn MiningControl>,
    block_body_source: Arc<dyn BlockBodySource>,
) -> Result<(Arc<Context>, RpcServer)> {
    let rpc_auth = Arc::new(state.config().rpc.auth.to_rpc_auth()?);
    let mut context = Context::from_handles(ContextHandles {
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
            mempool: state.mempool_gateway(),
        },
        indexes: IndexHandles {
            derived_index: state.derived_index_query(),
            script_index: state.script_index_query(),
        },
        network: NetworkHandles {
            network: state.network(),
            network_active: state.network_active(),
            peer_table: state.peer_table(),
            p2p_outbound_sender: Some(state.p2p_outbound_sender()),
            banned: state.banned_subnets(),
            added_nodes: state.added_nodes(),
        },
        mining: MiningHandles {
            mining_control: Some(Arc::clone(mining_control)),
        },
        derived_index_status: Some(state.derived_index_status()),
    })
    .with_esplora_derived_index(state.esplora_derived_index_query())
    .with_block_body_source(block_body_source)
    .with_chain_transition(Arc::clone(&state.chainstate().chain_transition));
    if let Some(prune_service) = state.prune_service() {
        context = context.with_prune_service(prune_service);
    }
    context = context
        .with_chain_control(Arc::new(RpcChainControl {
            handles: state.chainstate(),
            followers: state.chain_followers(),
        }))
        .with_zmq_publisher(state.zmq_publisher())
        .with_debug_log_path(state.data_dir().join("debug.log"))
        .with_rollback_warnings(state.warning_store());
    let context = Arc::new(context);
    let handler = Arc::new(bitcoin_rs_rpc::Handler::new(Arc::clone(&context)));
    let server = RpcServer::bind(
        state.config().rpc.bind,
        rpc_auth,
        handler,
        RPC_MAX_CONNECTIONS,
        RPC_IDLE_TIMEOUT,
        state.config().rpc.rest,
    )?;
    Ok((context, server))
}
