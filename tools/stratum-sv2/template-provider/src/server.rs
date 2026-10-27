//! Bounded Noise/TDP sessions over an embedded Node. No internal RPC transport.
use crate::{Config, Hub, TEMPLATE_RETRY_DELAY, template::TemplateState};
use bitcoin_rs_mining::{
    BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult, Candidate, CoinbaseBudget,
};
use bitcoin_rs_node::Node;
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
    // Sessions cancel incomplete reads by closing the connection, but finish
    // awaited blocking calls before dropping their Node borrows.
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
    // Aborted connections and temporary resource exhaustion need not kill Node.
    // Back off even for OS-specific errors to avoid spinning on a busy listener.
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

/// What one connection knows about its jobs. It lives exactly as long as the
/// connection, so closing it releases the pin and nothing else tracks it.
#[derive(Default)]
struct Jobs {
    /// The pool's latest `CoinbaseOutputConstraints`. No job is sent before it.
    budget: Option<CoinbaseBudget>,
    /// A fresh candidate is owed: the constraints or the generation changed.
    due: bool,
    /// When the last request lost a race and may run again. It is one pending
    /// request per connection at a fixed delay, so churn cannot multiply load.
    retry: Option<tokio::time::Instant>,
    /// At most one candidate request runs for this connection.
    refresh: Option<Refresh>,
    /// The job last delivered in full. The shared history is bounded and other
    /// sessions fill it, so it must not decide whether the pool's current job
    /// can still be answered or solved.
    current: Option<Arc<TemplateState>>,
}

impl Jobs {
    /// Resolves exactly `id`: this connection's current job first, then the
    /// shared history of superseded jobs. An unknown id never resolves to a
    /// newer job, whose body would differ from the one the pool solved.
    fn resolve(&self, hub: &Hub, id: u64) -> Option<Arc<TemplateState>> {
        match &self.current {
            Some(current) if current.id == id => Some(Arc::clone(current)),
            _ => hub.lookup(id),
        }
    }
}

/// A blocking request to the mining owner, tagged with the budget it asked for.
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

/// Asks the mining owner for the candidate that leaves `budget` room in the
/// coinbase. It never long-polls, so the owner's own bounds end the call even if
/// its session is gone. `None` means the owner reported a transient race: the
/// generation moved during assembly, or another budgeted assembly held the
/// owner's single slot for its whole bounded wait.
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

/// Resolves when the running request ends and clears it; pends while none runs.
/// Dropping this future between polls loses nothing: the handle stays in place.
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

/// Resolves at `at`; pends when there is no retry to wait for.
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
        // A blocking call cannot be cancelled and holds a Node borrow. Await it
        // on every exit, whether shutdown, error or disconnect; the owner's
        // bounds make that finite.
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
            // Keep this exact future alive across template refreshes. The SRI
            // Noise reader is NOT cancellation-safe after a partial record.
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
                    // Jobs already delivered keep the meaning they were sent
                    // with; only the next one is built for the new budget.
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
                        // TDP has no reply to a solution. Only a superseded job
                        // can be missing here: the current one is pinned.
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
                            .submit_block(block)
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

    /// Turns a finished candidate request into a job for the pool, unless the
    /// pool asked for a different budget meanwhile or already holds that job.
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
            // The constraints changed while this ran, which already owes a new request.
            return Ok(());
        }
        // Compare owner identities, not retained ids: other sessions may have
        // evicted the pinned job from the history, and issuing it again would
        // hand the pool the same job under a new id.
        if jobs
            .current
            .as_ref()
            .is_some_and(|current| current.candidate.template_id == candidate.template_id)
        {
            return Ok(());
        }
        // Retaining hashes the candidate's merkle branch: keep that off the runtime.
        let hub = self.hub.clone();
        let state = tokio::task::spawn_blocking(move || hub.issue(candidate))
            .await
            .map_err(|e| e.to_string())?;
        push_template(writer, &mut jobs.current, state, asked).await
    }
}

/// Writes one job, then pins it. The previous pin stays until both messages are
/// written, so a failed write leaves the job the pool already holds resolvable.
async fn push_template(
    writer: &mut NoiseTcpWriteHalf,
    pin: &mut Option<Arc<TemplateState>>,
    state: Arc<TemplateState>,
    budget: CoinbaseBudget,
) -> Result<(), String> {
    // The mining owner built this candidate for `budget`. A miss is its contract
    // violation: close the session rather than hand the pool an oversized job.
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
