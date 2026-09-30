//! TDP server: accepts the SRI pool's Noise connection, completes the
//! SetupConnection handshake, pushes templates from the [`Hub`], answers
//! `RequestTransactionData`, and forwards `SubmitSolution` to bitcoin-rs
//! `submitblock` (the normal production submission path).

use std::sync::Arc;

use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use stratum_apps::network_helpers::accept_noise_connection;
use stratum_apps::network_helpers::noise_stream::NoiseTcpWriteHalf;
use stratum_apps::stratum_core::bitcoin;
use stratum_apps::stratum_core::common_messages_sv2::{
    Protocol, SetupConnectionErrorOwned, SetupConnectionSuccessOwned,
    MESSAGE_TYPE_SETUP_CONNECTION_ERROR, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
};
use stratum_apps::stratum_core::parsers_sv2::{
    AnyMessageOwned, CommonMessagesOwned, TemplateDistribution, TemplateDistributionOwned,
};
use stratum_apps::utils::types::OutboundFrame;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::rpc::RpcClient;
use crate::template::{TemplateError, TemplateState};
use crate::{Config, Hub};

pub async fn run(config: Config, hub: Hub) {
    let rpc = Arc::new(RpcClient::new(
        config.rpc_url.clone(),
        config.rpc_user.clone(),
        config.rpc_pass.clone(),
    ));
    let keys = (
        Secp256k1PublicKey::from(config.secret_key),
        config.secret_key,
    );
    let cert_validity = config.cert_validity;

    let listener = match TcpListener::bind(config.listen).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, listen = %config.listen, "failed to bind TDP listener");
            std::process::exit(1);
        }
    };
    info!(listen = %config.listen, "TDP server listening");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                debug!(%peer, "pool TCP connection accepted");
                let hub = hub.clone();
                let rpc = rpc.clone();
                let (public_key, secret_key) = keys;
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_connection(stream, hub, rpc, public_key, secret_key, cert_validity)
                            .await
                    {
                        warn!(%peer, error = %e, "pool connection ended");
                    }
                });
            }
            Err(e) => warn!(error = %e, "listener accept error"),
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    hub: Hub,
    rpc: Arc<RpcClient>,
    public_key: Secp256k1PublicKey,
    secret_key: Secp256k1SecretKey,
    cert_validity: u64,
) -> Result<(), String> {
    let noise = accept_noise_connection(stream, public_key, secret_key, cert_validity)
        .await
        .map_err(|e| format!("noise handshake: {e}"))?;
    info!("pool noise handshake completed");
    let (mut reader, mut writer) = noise.into_split();

    // Handshake: pool (initiator) opens with SetupConnection.
    let mut frame = reader
        .read_frame()
        .await
        .map_err(|e| format!("read during setup: {e}"))?;
    let setup = parse_common(&mut frame).ok_or("expected SetupConnection as first message")?;
    match setup {
        CommonMessagesOwned::SetupConnection(setup) => {
            let (protocol, min_version, max_version) =
                (setup.protocol, setup.min_version, setup.max_version);
            if protocol != Protocol::TemplateDistributionProtocol {
                let error = SetupConnectionErrorOwned {
                    flags: 0,
                    error_code: "unsupported-protocol".try_into().expect("ascii fits"),
                };
                send(
                    &mut writer,
                    AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionError(error)),
                )
                .await?;
                return Err(format!("pool requested unsupported protocol {protocol:?}"));
            }
            if min_version > 2 || max_version < 2 {
                let error = SetupConnectionErrorOwned {
                    flags: 0,
                    error_code: "protocol-version-mismatch".try_into().expect("ascii fits"),
                };
                send(
                    &mut writer,
                    AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionError(error)),
                )
                .await?;
                return Err(format!(
                    "pool versions {min_version}..{max_version} exclude 2"
                ));
            }
        }
        other => return Err(format!("expected SetupConnection, got {other:?}")),
    }
    send(
        &mut writer,
        AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionSuccess(
            SetupConnectionSuccessOwned {
                used_version: 2,
                flags: 0,
            },
        )),
    )
    .await?;
    info!("pool setup connection completed");

    // Push the current template, then every refresh.
    let mut templates = hub.subscribe();
    let current = templates.borrow_and_update().clone();
    if let Some(state) = current {
        push_template(&mut writer, &state).await?;
    }

    loop {
        tokio::select! {
            changed = templates.changed() => {
                if changed.is_err() {
                    return Err("template hub closed".into());
                }
                let latest = templates.borrow().clone();
                if let Some(state) = latest {
                    push_template(&mut writer, &state).await?;
                }
            }
            frame = reader.read_frame() => {
                let mut frame = frame.map_err(|e| format!("read: {e}"))?;
                let msg_type = frame.header().msg_type();
                match msg_type {
                    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS | MESSAGE_TYPE_SETUP_CONNECTION_ERROR => {
                        return Err("unexpected common message mid-session".into());
                    }
                    _ => {
                        let message = TemplateDistribution::try_from((msg_type, frame.payload()))
                            .map_err(|e| format!("undecodable TDP message type {msg_type}: {e}"))?
                            .into_owned();
                        handle_tdp(message, &state_snapshot(&templates), &rpc, &mut writer).await?;
                    }
                }
            }
        }
    }
}

fn state_snapshot(
    templates: &watch::Receiver<Option<Arc<TemplateState>>>,
) -> Option<Arc<TemplateState>> {
    templates.borrow().clone()
}

async fn push_template(
    writer: &mut NoiseTcpWriteHalf,
    state: &TemplateState,
) -> Result<(), String> {
    send(
        writer,
        AnyMessageOwned::TemplateDistribution(TemplateDistributionOwned::NewTemplate(
            state.new_template_msg(),
        )),
    )
    .await?;
    send(
        writer,
        AnyMessageOwned::TemplateDistribution(TemplateDistributionOwned::SetNewPrevHash(
            state.set_new_prev_hash_msg(),
        )),
    )
    .await?;
    debug!(template_id = state.id, "pushed template to pool");
    Ok(())
}

async fn handle_tdp(
    message: TemplateDistributionOwned,
    state: &Option<Arc<TemplateState>>,
    rpc: &Arc<RpcClient>,
    writer: &mut NoiseTcpWriteHalf,
) -> Result<(), String> {
    match message {
        TemplateDistributionOwned::RequestTransactionData(request) => {
            let template_id = request.template_id;
            match state.as_deref().filter(|s| s.id == template_id) {
                Some(template) => {
                    send(
                        writer,
                        AnyMessageOwned::TemplateDistribution(
                            TemplateDistributionOwned::RequestTransactionDataSuccess(
                                stratum_apps::stratum_core::template_distribution_sv2::RequestTransactionDataSuccessOwned {
                                    template_id,
                                    excess_data: Vec::new().try_into().expect("empty fits B064K"),
                                    transaction_list: template.transaction_data(),
                                },
                            ),
                        ),
                    )
                    .await?;
                    debug!(template_id, "served RequestTransactionData");
                }
                None => {
                    warn!(template_id, "unknown template requested");
                    send(
                        writer,
                        AnyMessageOwned::TemplateDistribution(
                            TemplateDistributionOwned::RequestTransactionDataError(
                                stratum_apps::stratum_core::template_distribution_sv2::RequestTransactionDataErrorOwned {
                                    template_id,
                                    error_code: "template-not-found"
                                        .try_into()
                                        .expect("ascii fits"),
                                },
                            ),
                        ),
                    )
                    .await?;
                }
            }
            Ok(())
        }
        TemplateDistributionOwned::SubmitSolution(solution) => {
            let template_id = solution.template_id;
            let template = match state.as_deref().filter(|s| s.id == template_id) {
                Some(template) => template,
                None => {
                    warn!(template_id, "solution for unknown template; dropped");
                    return Ok(());
                }
            };
            let version = solution.version;
            let timestamp = solution.header_timestamp;
            let nonce = solution.header_nonce;
            let block = match template.assemble_block(&solution) {
                Ok(block) => block,
                Err(TemplateError::Solution(reason)) => {
                    warn!(template_id, %reason, "invalid solution; dropped");
                    return Ok(());
                }
                Err(e) => return Err(format!("solution assembly: {e}")),
            };
            if !TemplateState::header_meets_target(&block.header) {
                warn!(template_id, "solution header misses target; dropped");
                return Ok(());
            }
            let block_hex = hex::encode(bitcoin::consensus::serialize(&block));
            debug!(
                template_id,
                block_hex = %block_hex,
                "submitting assembled block to bitcoin-rs"
            );
            match rpc.submit_block(&block_hex).await {
                Ok(None) => {
                    info!(
                        template_id,
                        block_hash = %block.header.block_hash(),
                        version,
                        timestamp,
                        nonce,
                        "block accepted by bitcoin-rs via submitblock"
                    );
                    let tip_rpc = rpc.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        match tip_rpc.block_count().await {
                            Ok(count) => {
                                info!(tip_height = count, "tip advanced after accepted block")
                            }
                            Err(e) => {
                                warn!(error = %e, "could not read tip height after submission")
                            }
                        }
                    });
                }
                Ok(Some(reason)) => {
                    warn!(template_id, %reason, "bitcoin-rs rejected submitted block");
                }
                Err(e) => error!(template_id, error = %e, "submitblock rpc failed"),
            }
            Ok(())
        }
        TemplateDistributionOwned::CoinbaseOutputConstraints(constraints) => {
            debug!(
                max_additional_size = constraints.coinbase_output_max_additional_size,
                max_additional_sigops = constraints.coinbase_output_max_additional_sigops,
                "pool sent coinbase output constraints"
            );
            Ok(())
        }
        other => {
            debug!(?other, "ignoring TDP message");
            Ok(())
        }
    }
}

fn parse_common(
    frame: &mut stratum_apps::utils::types::InboundFrame,
) -> Option<CommonMessagesOwned> {
    let msg_type = frame.header().msg_type();
    let message = stratum_apps::stratum_core::parsers_sv2::CommonMessages::try_from((
        msg_type,
        frame.payload(),
    ))
    .ok()?
    .into_owned();
    Some(message)
}

async fn send(writer: &mut NoiseTcpWriteHalf, message: AnyMessageOwned) -> Result<(), String> {
    let frame = OutboundFrame::from_message(message).map_err(|e| format!("frame encode: {e}"))?;
    writer
        .write_frame(frame)
        .await
        .map_err(|e| format!("write: {e}"))
}
