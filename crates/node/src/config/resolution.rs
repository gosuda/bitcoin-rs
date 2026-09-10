//! Ordered source-layer application and final-network-dependent decoding.

use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::Result;
use bitcoin_rs_primitives::Network;

use super::network::{DRYNET4_CONNECT, DRYNET4_P2P_MAGIC};
use super::{Auth, NetworkSelection, NodeConfig, UserConfig};

/// Resolves layers from lowest to highest precedence.
pub fn resolve(layers: &[&UserConfig]) -> Result<NodeConfig> {
    let mut config = NodeConfig::default_for_network(Network::Mainnet);
    for layer in layers {
        config.apply_layer(layer);
    }
    // Decode only after all network selections have been applied. Inspecting
    // the final set address avoids cloning an intermediate mining layer.
    if let Some(address) = layers
        .iter()
        .rev()
        .find_map(|layer| layer.mining.payout_address.as_deref())
    {
        config.mining.payout_script = decode_payout_script(config.network, address)?;
    }
    config.validate()?;
    Ok(config)
}

impl NodeConfig {
    fn apply_layer(&mut self, layer: &UserConfig) {
        if let Some(network) = layer.network {
            self.apply_network_selection(network);
        }
        if let Some(magic) = layer.p2p.magic {
            self.p2p.magic = magic;
        }
        if let Some(data_dir) = &layer.data_dir {
            self.data_dir.clone_from(data_dir);
        }
        if let Some(backend) = layer.storage.backend {
            self.storage.backend = backend;
        }
        if let Some(value) = layer.storage.dbcache_mb {
            self.storage.dbcache_mb = value;
        }
        if let Some(value) = layer.storage.prune_target_mb {
            self.storage.prune_target_mb = value;
        }
        if let Some(bind) = layer.rpc.bind {
            self.rpc.bind = bind;
        }
        if let Some(rest) = layer.rpc.rest {
            self.rpc.rest = rest;
        }
        if let Some(path) = &layer.rpc.cookie {
            self.rpc.auth = Auth::Cookie { path: path.clone() };
        } else if layer.rpc.user.is_some() || layer.rpc.password.is_some() {
            let (old_user, old_password) = self.rpc.auth.basic_parts();
            self.rpc.auth = Auth::basic(
                layer.rpc.user.clone().unwrap_or(old_user),
                layer.rpc.password.clone().unwrap_or(old_password),
            );
        }
        if let Some(value) = layer.indexes.txindex {
            self.indexes.txindex = value;
        }
        if let Some(value) = layer.indexes.script_index {
            self.indexes.script_index = value;
        }
        if let Some(value) = &layer.observability.log_level {
            self.observability.log_level.clone_from(value);
        }
        if let Some(value) = layer.observability.metrics_bind {
            self.observability.metrics_bind = Some(value);
        }
        if let Some(value) = &layer.p2p.listen {
            self.p2p.listen.clone_from(value);
        }
        if let Some(value) = layer.p2p.dns_seeds {
            self.p2p.dns_seeds_enabled = value;
        }
        if let Some(value) = &layer.p2p.connect {
            self.p2p.connect.clone_from(value);
        }
        if let Some(notifications) = &layer.notifications {
            self.notifications.clone_from(notifications);
        }
        if let Some(journal) = layer.chainstate_journal {
            journal.apply_to(&mut self.chainstate_journal);
        }
        if let Some(value) = layer.validation.assume_valid_height {
            self.validation.assume_valid_height = value;
        }
    }

    pub(super) fn apply_network_selection(&mut self, selection: NetworkSelection) {
        let network = selection.consensus_network();
        self.network = network;
        self.p2p.magic = network.magic();
        self.rpc.bind = SocketAddr::from(([127, 0, 0, 1], network.default_rpc_port()));
        self.p2p.listen = vec![SocketAddr::from(([0, 0, 0, 0], network.default_p2p_port()))];
        self.p2p.dns_seeds_enabled = true;
        self.p2p.connect.clear();
        self.validation.assume_valid_height = network
            .assume_valid_anchor()
            .map_or(0, |(height, _)| height);
        if selection == NetworkSelection::Drynet4 {
            self.p2p.magic = DRYNET4_P2P_MAGIC;
            self.p2p.dns_seeds_enabled = false;
            self.p2p.connect = vec![DRYNET4_CONNECT.to_owned()];
        }
    }
}

fn bitcoin_network(network: Network) -> bitcoin::Network {
    match network {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Testnet3 => bitcoin::Network::Testnet,
        Network::Testnet4 => bitcoin::Network::Testnet4,
        Network::Signet => bitcoin::Network::Signet,
        Network::Regtest => bitcoin::Network::Regtest,
    }
}

fn decode_payout_script(network: Network, address: &str) -> Result<Vec<u8>> {
    let parsed = bitcoin::Address::from_str(address)
        .map_err(|err| anyhow::anyhow!("invalid mining payout address: {err}"))?;
    let checked = parsed
        .require_network(bitcoin_network(network))
        .map_err(|err| {
            anyhow::anyhow!(
                "mining payout address is not valid for {}: {err}",
                network.identity_name()
            )
        })?;
    Ok(checked.script_pubkey().as_bytes().to_vec())
}
