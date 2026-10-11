//! Deployment reporting is a projection of native consensus activation.

use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin_rs_chain::{DeploymentStatus, VersionBitsStatus, deployment_statuses};
use bitcoin_rs_consensus::{DeploymentState, SoftforkState};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_script::VerifyFlags;
use corepc_types::v31;
use sonic_rs::{JsonValueTrait as _, Value};

use crate::compat::convert::typed_to_sonic_omitting_nulls;
use crate::context::Context;
use crate::error::RpcError;

pub(crate) fn getdeploymentinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let params = super::bind_named_params(params, &["blockhash"])?;
    super::ensure_at_most_params(&params, 1)?;
    let value = super::params_array(&params)?.first();
    let hash = match value.filter(|value| !value.is_null()) {
        None => ctx.chain.applied_view().hash(ctx.chain.chain_network),
        Some(value) => {
            let text = value
                .as_str()
                .ok_or_else(|| super::wrong_type(1, "blockhash", value, "string"))?;
            if text.len() != 64 {
                return Err(RpcError::InvalidParameter(format!(
                    "blockhash must be of length 64 (not {}, for '{}')",
                    text.len(),
                    text
                )));
            }
            Hash256::from_str(text).map_err(|_| {
                RpcError::InvalidParameter(format!(
                    "blockhash must be hexadecimal string (not '{text}')"
                ))
            })?
        }
    };
    at_hash(ctx, hash)
}

/// One projection shared by RPC and REST; named headers need no block body.
/// The caller selects its hash from one applied publication or an explicit query.
pub(crate) fn at_hash(ctx: &Context, hash: Hash256) -> Result<Value, RpcError> {
    let network = ctx.chain.chain_network;
    let tree = ctx.chain.block_tree.read();
    let block = tree.lookup(hash);
    let height = match block {
        Some(id) => {
            let node = tree
                .node(id)
                .map_err(|error| RpcError::Internal(error.to_string()))?;
            node.height
        }
        None if hash == network.genesis_block_hash() => 0,
        None => return Err(RpcError::InvalidAddressOrKey("Block not found".to_owned())),
    };
    let statuses = deployment_statuses(&tree, network, block).map_err(|error| match error {
        bitcoin_rs_chain::DeploymentQueryError::Budget { .. } => RpcError::Misc(error.to_string()),
        _ => RpcError::Internal(error.to_string()),
    })?;
    // The same captured deployment states supply CSV/Segwit flags. Do not
    // independently traverse a cold side branch a second time for flags.
    let softforks = SoftforkState {
        csv_active: statuses
            .iter()
            .any(|status| status.name == "csv" && status.active_at_block),
        segwit_active: statuses
            .iter()
            .any(|status| status.name == "segwit" && status.active_at_block),
    };
    let flags = bitcoin_rs_consensus::verify_flags(network, height, hash, softforks);
    let deployments = statuses
        .into_iter()
        .map(|status| (status.name.to_owned(), deployment(&status)))
        .collect();
    // All flags validation can emit, in Core's lexical ordering. This maps
    // flags to wire names; their activation remains owned by verify_flags.
    let script_flags = [
        ("CHECKLOCKTIMEVERIFY", VerifyFlags::CHECKLOCKTIMEVERIFY),
        ("CHECKSEQUENCEVERIFY", VerifyFlags::CHECKSEQUENCEVERIFY),
        ("DERSIG", VerifyFlags::DERSIG),
        ("NULLDUMMY", VerifyFlags::NULLDUMMY),
        ("P2SH", VerifyFlags::P2SH),
        ("TAPROOT", VerifyFlags::TAPROOT),
        ("WITNESS", VerifyFlags::WITNESS),
    ]
    .into_iter()
    .filter(|(_, flag)| flags.contains(*flag))
    .map(|(name, _)| name.to_owned())
    .collect();
    drop(tree);
    typed_to_sonic_omitting_nulls(&v31::GetDeploymentInfo {
        hash: hash.to_string_be(),
        height,
        script_flags,
        deployments,
    })
}

fn deployment(status: &DeploymentStatus) -> v31::DeploymentInfo {
    v31::DeploymentInfo {
        deployment_type: if status.bip9.is_some() {
            "bip9"
        } else {
            "buried"
        }
        .to_owned(),
        height: status.height,
        active: status.active,
        bip9: status.bip9.as_ref().map(versionbits),
    }
}

fn versionbits(status: &VersionBitsStatus) -> v31::Bip9Info {
    let signalling = status.signalling.as_ref().map(|signals| {
        signals
            .iter()
            .map(|signal| if *signal { '#' } else { '-' })
            .collect()
    });
    let statistics = status.signalling.as_ref().map(|signals| {
        let elapsed = u32::try_from(signals.len()).unwrap_or(u32::MAX);
        let count =
            u32::try_from(signals.iter().filter(|signal| **signal).count()).unwrap_or(u32::MAX);
        let started = status.state == DeploymentState::Started;
        v31::Bip9Statistics {
            period: status.params.period,
            threshold: started.then_some(status.params.threshold),
            elapsed,
            count,
            possible: started
                .then_some(status.params.period - elapsed + count >= status.params.threshold),
        }
    });
    v31::Bip9Info {
        bit: statistics.as_ref().map(|_| status.params.bit),
        start_time: i64::from(status.params.start_time),
        timeout: i64::from(status.params.timeout),
        min_activation_height: 0,
        status: state_name(status.state).to_owned(),
        since: status.since,
        status_next: state_name(status.next).to_owned(),
        statistics,
        signalling,
    }
}

const fn state_name(state: DeploymentState) -> &'static str {
    match state {
        DeploymentState::Defined => "defined",
        DeploymentState::Started => "started",
        DeploymentState::LockedIn => "locked_in",
        DeploymentState::Active => "active",
        DeploymentState::Failed => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::getdeploymentinfo;
    use crate::{Handler, context::Context};
    use bitcoin_rs_primitives::Network;
    use sonic_rs::json;
    use std::sync::Arc;

    #[test]
    fn native_deployments_share_the_pinned_schema_without_inventing_versionbits()
    -> anyhow::Result<()> {
        let mut context = Context::new();
        context.chain.chain_network = Network::Regtest;
        let context = Arc::new(context);
        let handler = Handler::new(Arc::clone(&context));
        let value = handler.dispatch("getdeploymentinfo", &json!([]))?;
        let typed: corepc_types::v31::GetDeploymentInfo =
            serde_json::from_str(&sonic_rs::to_string(&value)?)?;
        assert_eq!(
            typed.hash,
            Network::Regtest.genesis_block_hash().to_string_be()
        );
        assert_eq!(typed.deployments.len(), 6);
        assert_eq!(typed.deployments["bip34"].height, Some(500));
        assert_eq!(typed.deployments["csv"].height, Some(432));
        assert!(!typed.deployments["csv"].active);
        assert_eq!(typed.deployments["taproot"].deployment_type, "buried");
        assert!(typed.deployments["taproot"].active);
        assert_eq!(
            typed.script_flags,
            ["NULLDUMMY", "P2SH", "TAPROOT", "WITNESS"]
        );
        assert!(!sonic_rs::to_string(&value)?.contains("null"));
        assert_eq!(
            value,
            getdeploymentinfo(&context, &json!({"blockhash": typed.hash}))?
        );
        assert_eq!(value, getdeploymentinfo(&context, &json!([null]))?);
        let rest = crate::rest::route(&context, "/rest/deploymentinfo.json", "", true);
        assert_eq!(rest.status, 200);
        assert_eq!(value, sonic_rs::from_slice::<sonic_rs::Value>(&rest.body)?);
        for (params, code) in [
            (json!(["short"]), -8),
            (json!([7]), -3),
            (json!(["00".repeat(32)]), -5),
            (json!({"unknown": 0}), -8),
        ] {
            assert_eq!(
                handler
                    .dispatch("getdeploymentinfo", &params)
                    .err()
                    .map(|e| e.code()),
                Some(code)
            );
        }
        Ok(())
    }
}
