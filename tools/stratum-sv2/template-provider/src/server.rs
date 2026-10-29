//! Bounded Noise/TDP sessions over an embedded Node. No internal RPC transport.
use crate::{Config, Hub, TEMPLATE_RETRY_DELAY, template::TemplateState};
use bitcoin_rs_mining::{
    BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult, Candidate, CoinbaseBudget,
};
use bitcoin_rs_node::Node;
use bitcoin_rs_primitives::BlockPayload;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use stratum_apps::network_helpers::{accept_noise_connection, noise_stream::NoiseTcpWriteHalf};
use stratum_apps::stratum_core::common_messages_sv2::{
    Protocol, SetupConnectionErrorOwned, SetupConnectionSuccessOwned,
};
use stratum_apps::stratum_core::parsers_sv2::{
    AnyMessageOwned, CommonMessagesOwned, TemplateDistribution, TemplateDistributionOwned,
};
use stratum_apps::stratum_core::template_distribution_sv2::{
    RequestTransactionDataErrorOwned, RequestTransactionDataSuccessOwned,
};
use stratum_apps::utils::types::{InboundFrame, OutboundFrame};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    task::{JoinHandle, JoinSet},
};
use tracing::{debug, info, warn};

const MAX_SESSIONS: usize = 8;

pub async fn run(
    config: Config,
    hub: Hub,
    node: Arc<Node>,
    mut stop: watch::Receiver<bool>,
) -> Result<(), String> {
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|e| e.to_string())?;
    info!(listen = %listener.local_addr().map_err(|e| e.to_string())?, "TDP server listening");
    let mut sessions = JoinSet::new();
    let (session_stop, session_cancel) = watch::channel(false);
    let outcome = loop {
        if *stop.borrow() {
            break Ok(());
        }
        tokio::select! {
            _ = stop.changed() => break Ok(()),
            _ = sessions.join_next(), if !sessions.is_empty() => {},
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        if let Err(error) = wait_after_accept_error(error, &mut stop).await {
                            break Err(error);
                        }
                        continue;
                    }
                };
                if sessions.len() >= MAX_SESSIONS { drop(stream); continue; }
                let session = Session {
                    hub: hub.clone(), node: Arc::clone(&node), stop: session_cancel.clone(),
                    keys: (Secp256k1PublicKey::from(config.secret_key), config.secret_key),
                    cert_validity_secs: config.cert_validity_secs,
                };
                sessions.spawn(async move {
                    if let Err(error) = session.serve(stream).await { warn!(%peer, %error, "pool connection ended"); }
                });
            }
        }
    };
    session_stop.send_replace(true);
    while sessions.join_next().await.is_some() {}
    outcome
}

async fn wait_after_accept_error(
    error: std::io::Error,
    stop: &mut watch::Receiver<bool>,
) -> Result<(), String> {
    use std::io::ErrorKind;
    if matches!(
        error.kind(),
        ErrorKind::InvalidInput
            | ErrorKind::PermissionDenied
            | ErrorKind::Unsupported
            | ErrorKind::NotConnected
    ) {
        return Err(error.to_string());
    }
    warn!(%error, "TDP accept failed; retrying after 100ms");
    if *stop.borrow() {
        return Ok(());
    }
    tokio::select! {
        _ = stop.changed() => {},
        _ = tokio::time::sleep(Duration::from_millis(100)) => {},
    }
    Ok(())
}

struct Session {
    hub: Hub,
    node: Arc<Node>,
    stop: watch::Receiver<bool>,
    keys: (Secp256k1PublicKey, Secp256k1SecretKey),
    cert_validity_secs: u64,
}

#[derive(Default)]
struct Jobs {
    budget: Option<CoinbaseBudget>,
    due: bool,
    retry: Option<tokio::time::Instant>,
    refresh: Option<Refresh>,
    current: Option<Arc<TemplateState>>,
}

impl Jobs {
    fn resolve(&self, hub: &Hub, id: u64) -> Option<Arc<TemplateState>> {
        match &self.current {
            Some(current) if current.id == id => Some(Arc::clone(current)),
            _ => hub.lookup(id),
        }
    }
}

struct Refresh {
    budget: CoinbaseBudget,
    task: JoinHandle<Result<Option<Arc<Candidate>>, String>>,
}

impl Refresh {
    fn start(node: &Arc<Node>, budget: CoinbaseBudget) -> Self {
        let node = Arc::clone(node);
        Self {
            budget,
            task: tokio::task::spawn_blocking(move || candidate_for(&node, budget)),
        }
    }
}

fn candidate_for(node: &Node, budget: CoinbaseBudget) -> Result<Option<Arc<Candidate>>, String> {
    let mining = node.mining_control().map_err(|e| e.to_string())?;
    match mining.get_block_template(BlockTemplateRequest {
        mode: BlockTemplateMode::Template,
        capabilities: vec![],
        rules: vec![],
        long_poll_id: None,
        coinbase_budget: Some(budget),
    }) {
        Ok(BlockTemplateResult::Template(template)) => Ok(Some(template.candidate)),
        Ok(BlockTemplateResult::Proposal(_)) => Err("unexpected proposal response".into()),
        Err(error) if error.is_template_generation_race() => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

async fn refreshed(
    refresh: &mut Option<Refresh>,
) -> (CoinbaseBudget, Result<Option<Arc<Candidate>>, String>) {
    let Some(running) = refresh.as_mut() else {
        return std::future::pending().await;
    };
    let budget = running.budget;
    let outcome = (&mut running.task)
        .await
        .map_err(|e| e.to_string())
        .and_then(|result| result);
    *refresh = None;
    (budget, outcome)
}

async fn retry_due(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

impl Session {
    async fn serve(mut self, stream: TcpStream) -> Result<(), String> {
        let mut jobs = Jobs::default();
        let outcome = self.run(stream, &mut jobs).await;
        if let Some(refresh) = jobs.refresh.take() {
            let _ = refresh.task.await;
        }
        outcome
    }

    async fn run(&mut self, stream: TcpStream, jobs: &mut Jobs) -> Result<(), String> {
        let (public, secret) = self.keys;
        let noise = tokio::select! {
            _ = self.stop.changed() => return Ok(()),
            result = tokio::time::timeout(Duration::from_secs(10), accept_noise_connection(stream, public, secret, self.cert_validity_secs)) => {
                result.map_err(|_| "noise deadline")?.map_err(|e| e.to_string())?
            }
        };
        let (mut reader, mut writer) = noise.into_split();
        let mut frame = tokio::select! {
            _ = self.stop.changed() => return Ok(()),
            result = tokio::time::timeout(Duration::from_secs(10), reader.read_frame()) => {
                result.map_err(|_| "setup deadline")?.map_err(|e| e.to_string())?
            }
        };
        match parse_common(&mut frame) {
            Some(CommonMessagesOwned::SetupConnection(setup))
                if setup.protocol == Protocol::TemplateDistributionProtocol
                    && setup.min_version <= 2
                    && setup.max_version >= 2 => {}
            Some(CommonMessagesOwned::SetupConnection(setup))
                if setup.protocol == Protocol::TemplateDistributionProtocol =>
            {
                send_error(&mut writer, "protocol-version-mismatch").await?;
                return Err("unsupported version".into());
            }
            _ => {
                send_error(&mut writer, "unsupported-protocol").await?;
                return Err("unsupported setup".into());
            }
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
        let mut wakes = self.hub.subscribe();
        loop {
            if *self.stop.borrow() {
                return Ok(());
            }
            let read = reader.read_frame();
            tokio::pin!(read);
            let message = loop {
                if jobs.due
                    && jobs.refresh.is_none()
                    && let Some(budget) = jobs.budget
                {
                    jobs.due = false;
                    jobs.retry = None;
                    jobs.refresh = Some(Refresh::start(&self.node, budget));
                }
                tokio::select! {
                    _ = self.stop.changed() => return Ok(()),
                    changed = wakes.changed() => {
                        changed.map_err(|e| e.to_string())?;
                        jobs.due = true;
                    }
                    _ = retry_due(jobs.retry) => {
                        jobs.retry = None;
                        jobs.due = true;
                    }
                    (asked, outcome) = refreshed(&mut jobs.refresh) => {
                        self.deliver(&mut writer, jobs, asked, outcome?).await?;
                    }
                    frame = &mut read => {
                        let mut frame = frame.map_err(|e| e.to_string())?;
                        break TemplateDistribution::try_from((frame.header().msg_type(), frame.payload()))
                            .map_err(|e| format!("TDP decode: {e}"))?.into_owned();
                    }
                }
            };
            match message {
                TemplateDistributionOwned::CoinbaseOutputConstraints(c) => {
                    jobs.budget = Some(CoinbaseBudget {
                        additional_size: c.coinbase_output_max_additional_size,
                        additional_sigops: c.coinbase_output_max_additional_sigops,
                    });
                    jobs.due = true;
                }
                TemplateDistributionOwned::RequestTransactionData(request) => {
                    match jobs.resolve(&self.hub, request.template_id) {
                        Some(template) => {
                            let list =
                                tokio::task::spawn_blocking(move || template.transaction_data())
                                    .await
                                    .map_err(|e| e.to_string())??;
                            send(
                                &mut writer,
                                AnyMessageOwned::TemplateDistribution(
                                    TemplateDistributionOwned::RequestTransactionDataSuccess(
                                        RequestTransactionDataSuccessOwned {
                                            template_id: request.template_id,
                                            excess_data: Vec::new().try_into().unwrap(),
                                            transaction_list: list,
                                        },
                                    ),
                                ),
                            )
                            .await?;
                            debug!(
                                template_id = request.template_id,
                                "served RequestTransactionData"
                            );
                        }
                        None => {
                            send_error_tdp(&mut writer, request.template_id, "template-not-found")
                                .await?
                        }
                    }
                }
                TemplateDistributionOwned::SubmitSolution(solution) => {
                    let Some(template) = jobs.resolve(&self.hub, solution.template_id) else {
                        warn!(
                            template_id = solution.template_id,
                            "solution names a template no longer retained; not submitted"
                        );
                        continue;
                    };
                    let node = Arc::clone(&self.node);
                    let id = solution.template_id;
                    let started = Instant::now();
                    let result = tokio::task::spawn_blocking(move || {
                        let block = template.assemble_block(&solution)?;
                        node.mining_control()
                            .map_err(|e| e.to_string())?
                            .submit_block(BlockPayload::from_local(block))
                            .map_err(|e| e.to_string())
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                    info!(
                        template_id = id,
                        ?result,
                        submit_us = started.elapsed().as_micros(),
                        height = self.node.snapshot().tip_height,
                        "typed solution submitted"
                    );
                }
                other => debug!(?other, "ignoring TDP message"),
            }
        }
    }

    async fn deliver(
        &self,
        writer: &mut NoiseTcpWriteHalf,
        jobs: &mut Jobs,
        asked: CoinbaseBudget,
        candidate: Option<Arc<Candidate>>,
    ) -> Result<(), String> {
        let Some(candidate) = candidate else {
            debug!("template request lost a race; retrying after the fixed delay");
            jobs.retry = Some(tokio::time::Instant::now() + TEMPLATE_RETRY_DELAY);
            return Ok(());
        };
        if jobs.budget != Some(asked) {
            return Ok(());
        }
        if jobs
            .current
            .as_ref()
            .is_some_and(|current| current.candidate.template_id == candidate.template_id)
        {
            return Ok(());
        }
        let hub = self.hub.clone();
        let state = tokio::task::spawn_blocking(move || hub.issue(candidate))
            .await
            .map_err(|e| e.to_string())?;
        push_template(writer, &mut jobs.current, state, asked).await
    }
}

async fn push_template(
    writer: &mut NoiseTcpWriteHalf,
    pin: &mut Option<Arc<TemplateState>>,
    state: Arc<TemplateState>,
    budget: CoinbaseBudget,
) -> Result<(), String> {
    state
        .candidate
        .admits(budget)
        .map_err(|e| format!("candidate does not admit the coinbase budget: {e}"))?;
    let started = Instant::now();
    send(
        writer,
        AnyMessageOwned::TemplateDistribution(TemplateDistributionOwned::NewTemplate(
            state.new_template_msg()?,
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
    info!(
        template_id = state.id,
        job_us = started.elapsed().as_micros(),
        "pushed template to pool"
    );
    *pin = Some(state);
    Ok(())
}

fn parse_common(frame: &mut InboundFrame) -> Option<CommonMessagesOwned> {
    stratum_apps::stratum_core::parsers_sv2::CommonMessages::try_from((
        frame.header().msg_type(),
        frame.payload(),
    ))
    .ok()
    .map(|m| m.into_owned())
}

async fn send(writer: &mut NoiseTcpWriteHalf, message: AnyMessageOwned) -> Result<(), String> {
    let frame = OutboundFrame::from_message(message).map_err(|e| format!("frame encode: {e}"))?;
    tokio::time::timeout(Duration::from_secs(10), writer.write_frame(frame))
        .await
        .map_err(|_| "write deadline".to_owned())?
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

#[cfg(test)]
mod tests;
