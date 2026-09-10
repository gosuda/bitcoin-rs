use anyhow::Result;
use bitcoin_rs_primitives::Network;

use super::resolved::NodeConfig;
use super::user::{MiningOverrides, UserConfig};

/// Resolves layers from lowest to highest precedence.
pub fn resolve(layers: &[&UserConfig]) -> Result<NodeConfig> {
    let mut config = NodeConfig::default_for_network(Network::Mainnet);
    for layer in layers {
        config.apply_layer(layer);
    }
    let mut mining = MiningOverrides::default();
    for layer in layers {
        mining.overlay(&layer.mining);
    }
    if let Some(address) = mining.payout_address.as_deref() {
        config.mining.payout_script = decode_payout_script(config.network, address)?;
    }
    config.validate()?;
    Ok(config)
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
    use std::str::FromStr as _;

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
