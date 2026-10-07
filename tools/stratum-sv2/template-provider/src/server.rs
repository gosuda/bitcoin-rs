//! TDP server: accepts the SRI pool's Noise connection, completes the
//! `SetupConnection` handshake, pushes templates from the [`Hub`], answers
//! `RequestTransactionData`, and forwards `SubmitSolution` to bitcoin-rs
//! `submitblock` — the normal production submission path.

use std::sync::Arc;

use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use stratum_apps::network_helpers::accept_noise_connection;
use stratum_apps::network_helpers::noise_stream::NoiseTcpWriteHalf;
use stratum_apps::stratum_core::bitcoin;
use stratum_apps::stratum_core::common_messages_sv2::{
    MESSAGE_TYPE_SETUP_CONNECTION_ERROR, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, Protocol,
    SetupConnectionErrorOwned, SetupConnectionSuccessOwned,
};
use stratum_apps::stratum_core::parsers_sv2::{
    AnyMessageOwned, CommonMessagesOwned, TemplateDistribution, TemplateDistributionOwned,
};
use stratum_apps::stratum_core::template_distribution_sv2::{
    RequestTransactionDataErrorOwned, RequestTransactionDataSuccessOwned,
};
use stratum_apps::utils::types::{InboundFrame, OutboundFrame};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::rpc::RpcClient;
use crate::template::TemplateState;
use crate::{Config, Hub};

/// Binds the TDP listener and spawns a handler per pool connection. A bind
/// failure exits the process (the example is useless without its listener).
pub async fn run(config: Config, hub: Hub) {
    let rpc = Arc::new(RpcClient::new(
        &config.rpc_url,
        &config.rpc_user,
        &config.rpc_pass,
    ));
    let keys = (
        Secp256k1PublicKey::from(config.secret_key),
        config.secret_key,
    );

    let listener = match TcpListener::bind(config.listen).await {
        Ok(listener) => listener,
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
                let session = Session {
                    hub: hub.clone(),
                    rpc: Arc::clone(&rpc),
                    keys,
                    cert_validity_secs: config.cert_validity_secs,
                };
                tokio::spawn(async move {
                    if let Err(e) = session.serve(stream).await {
                        warn!(%peer, error = %e, "pool connection ended");
                    }
                });
            }
            Err(e) => warn!(error = %e, "listener accept error"),
        }
    }
}

struct Session {
    hub: Hub,
    rpc: Arc<RpcClient>,
    keys: (Secp256k1PublicKey, Secp256k1SecretKey),
    cert_validity_secs: u64,
}

impl Session {
    /// Completes Noise and TDP version-2 setup, then streams template
    /// updates and answers pool messages until a transport or protocol
    /// error occurs.
    async fn serve(self, stream: TcpStream) -> Result<(), String> {
        let (public_key, secret_key) = self.keys;
        let noise =
            accept_noise_connection(stream, public_key, secret_key, self.cert_validity_secs)
                .await
                .map_err(|e| format!("noise handshake: {e}"))?;
        info!("pool noise handshake completed");
        let (mut reader, mut writer) = noise.into_split();

        // Handshake: the pool (initiator) opens with SetupConnection.
        let mut frame = reader
            .read_frame()
            .await
            .map_err(|e| format!("read during setup: {e}"))?;
        match parse_common(&mut frame) {
            Some(CommonMessagesOwned::SetupConnection(setup))
                if setup.protocol == Protocol::TemplateDistributionProtocol
                    && setup.min_version <= 2
                    && setup.max_version >= 2 => {}
            Some(CommonMessagesOwned::SetupConnection(setup)) => {
                send_error(
                    &mut writer,
                    if setup.protocol == Protocol::TemplateDistributionProtocol {
                        "protocol-version-mismatch"
                    } else {
                        "unsupported-protocol"
                    },
                )
                .await?;
                return Err(format!(
                    "unsupported setup {:?}",
                    (setup.protocol, setup.min_version, setup.max_version)
                ));
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
        let mut templates = self.hub.subscribe();
        let state = templates.borrow_and_update().clone();
        if let Some(state) = state {
            push_template(&mut writer, &state).await?;
            info!(template_id = state.id, "pushed template to pool");
        }
        loop {
            // NoiseTcpStream's read_frame/write_frame are not
            // cancellation-safe, so the select races only the cancel-safe
            // inputs (the watch flag and the read); every write runs after
            // the select resolves. A canceled write_frame could emit a
            // partial AEAD record and corrupt the whole stream.
            enum Event {
                Refresh,
                Tdp(TemplateDistributionOwned),
            }
            let event = tokio::select! {
                changed = templates.changed() => {
                    if changed.is_err() {
                        return Err("template hub closed".into());
                    }
                    Event::Refresh
                }
                frame = reader.read_frame() => {
                    let mut frame = frame.map_err(|e| format!("read: {e}"))?;
                    let msg_type = frame.header().msg_type();
                    match msg_type {
                        MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS
                        | MESSAGE_TYPE_SETUP_CONNECTION_ERROR => {
                            return Err("unexpected common message mid-session".into());
                        }
                        _ => {
                            let message = TemplateDistribution::try_from((
                                msg_type,
                                frame.payload(),
                            ))
                            .map_err(|e| format!("undecodable TDP message type {msg_type}: {e}"))?
                            .into_owned();
                            Event::Tdp(message)
                        }
                    }
                }
            };
            match event {
                Event::Refresh => {
                    // borrow_and_update marks the value seen — plain borrow()
                    // would leave changed() resolved and re-push forever.
                    // (Also: the watch Ref is !Send, so it must drop before
                    // the await — bind, don't inline in the scrutinee.)
                    let state = templates.borrow_and_update().clone();
                    if let Some(state) = state {
                        push_template(&mut writer, &state).await?;
                        info!(template_id = state.id, "pushed template to pool");
                    }
                }
                Event::Tdp(message) => self.handle_tdp(message, &mut writer).await?,
            }
        }
    }

    /// Serves transaction requests and submits solutions for issued
    /// templates after assembly and a header PoW check. Unknown templates
    /// and invalid solutions are logged and dropped.
    async fn handle_tdp(
        &self,
        message: TemplateDistributionOwned,
        writer: &mut NoiseTcpWriteHalf,
    ) -> Result<(), String> {
        match message {
            TemplateDistributionOwned::RequestTransactionData(request) => {
                let template_id = request.template_id;
                match self.hub.lookup(template_id) {
                    Some(template) => {
                        send(
                            writer,
                            AnyMessageOwned::TemplateDistribution(
                                TemplateDistributionOwned::RequestTransactionDataSuccess(
                                    RequestTransactionDataSuccessOwned {
                                        template_id,
                                        excess_data: Vec::new()
                                            .try_into()
                                            .expect("empty fits B064K"),
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
                        send_error_tdp(writer, template_id, "template-not-found").await?;
                    }
                }
            }
            TemplateDistributionOwned::SubmitSolution(solution) => {
                let template_id = solution.template_id;
                let Some(template) = self.hub.lookup(template_id) else {
                    warn!(template_id, "solution for unknown template; dropped");
                    return Ok(());
                };
                let block = match template.assemble_block(&solution) {
                    Ok(block) => block,
                    Err(e) => {
                        warn!(template_id, error = %e, "invalid solution; dropped");
                        return Ok(());
                    }
                };
                if !TemplateState::header_meets_target(&block.header) {
                    warn!(template_id, "solution header misses target; dropped");
                    return Ok(());
                }
                match self
                    .rpc
                    .submit_block(&hex::encode(bitcoin::consensus::serialize(&block)))
                    .await
                {
                    Ok(None) => {
                        info!(
                            template_id,
                            block_hash = %block.header.block_hash(),
                            "block accepted by bitcoin-rs via submitblock"
                        );
                        let rpc = Arc::clone(&self.rpc);
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            match rpc.block_count().await {
                                Ok(count) => info!(tip_height = count, "tip advanced"),
                                Err(e) => warn!(error = %e, "tip height unreadable"),
                            }
                        });
                    }
                    Ok(Some(reason)) => {
                        warn!(template_id, %reason, "bitcoin-rs rejected submitted block");
                    }
                    Err(e) => error!(template_id, error = %e, "submitblock rpc failed"),
                }
            }
            TemplateDistributionOwned::CoinbaseOutputConstraints(constraints) => {
                // The pool declares how much coinbase space/sigops it needs
                // for its own outputs; informational for this example.
                debug!(
                    max_additional_size = constraints.coinbase_output_max_additional_size,
                    max_additional_sigops = constraints.coinbase_output_max_additional_sigops,
                    "pool sent coinbase output constraints"
                );
            }
            other => debug!(?other, "ignoring TDP message"),
        }
        Ok(())
    }
}

/// Sends `NewTemplate` followed by `SetNewPrevHash` to activate it.
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
    .await
}

/// Decodes a frame as an owned common message, `None` on failure.
fn parse_common(frame: &mut InboundFrame) -> Option<CommonMessagesOwned> {
    stratum_apps::stratum_core::parsers_sv2::CommonMessages::try_from((
        frame.header().msg_type(),
        frame.payload(),
    ))
    .ok()
    .map(|m| m.into_owned())
}

/// Encodes and writes one SV2 message.
async fn send(writer: &mut NoiseTcpWriteHalf, message: AnyMessageOwned) -> Result<(), String> {
    let frame = OutboundFrame::from_message(message).map_err(|e| format!("frame encode: {e}"))?;
    writer
        .write_frame(frame)
        .await
        .map_err(|e| format!("write: {e}"))
}

async fn send_error(writer: &mut NoiseTcpWriteHalf, code: &'static str) -> Result<(), String> {
    send(
        writer,
        AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionError(
            SetupConnectionErrorOwned {
                flags: 0,
                error_code: code.try_into().expect("ascii fits"),
            },
        )),
    )
    .await
}

async fn send_error_tdp(
    writer: &mut NoiseTcpWriteHalf,
    template_id: u64,
    code: &'static str,
) -> Result<(), String> {
    send(
        writer,
        AnyMessageOwned::TemplateDistribution(
            TemplateDistributionOwned::RequestTransactionDataError(
                RequestTransactionDataErrorOwned {
                    template_id,
                    error_code: code.try_into().expect("ascii fits"),
                },
            ),
        ),
    )
    .await
}
