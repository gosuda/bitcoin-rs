//! Per-connection SV1 session state machine, the shared pool core, and the
//! bounded TCP server.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::pool::core::{Completion, Credited, Lease, ShareRequest, SubmitFailure};
use crate::pool::{
    BlockOutcome, JobId, PoolCore, SessionId, ShareClass, ShareError, ShareTarget, StaleReason,
    WorkerIdentity,
};
use bitcoin_rs_primitives::BlockHash;

use super::{
    AccountResolver, Authorize, ClientRequest, Configure, Difficulty, DifficultyPolicy, Incoming,
    LineBuffer, Request, RequestId, Submit, Subscribe, decode_line, encode_error, encode_hex,
    encode_notify, encode_reject, encode_result, encode_set_difficulty, errors, json_string,
    parse_wire_job_id,
};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Observer callback. Events never carry passwords.
pub type Observer = Arc<dyn Fn(&ServerEvent) + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalReason {
    ConnectionLimit,
    PerIpLimit,
    SpawnFailed,
}

/// How a connection ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEnd {
    ClientClosed,
    Cancelled,
    HandshakeTimeout,
    IdleTimeout,
    FrameTimeout,
    FrameTooLong,
    WriteTimeout,
    Io(io::ErrorKind),
    TooManyViolations,
    TooManyAuthFailures,
    TooManyRejects,
    PoolRefused,
    PoolFault(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerEvent {
    Accepted {
        peer: SocketAddr,
    },
    Refused {
        peer: SocketAddr,
        reason: RefusalReason,
    },
    Subscribed {
        peer: SocketAddr,
        session: SessionId,
        user_agent: Option<String>,
    },
    /// The share passed validation and was credited to the ledger or queued
    /// in the outbox.
    ShareAccepted {
        session: SessionId,
        hash: BlockHash,
        class: ShareClass,
        delivered: bool,
    },
    /// A found block was handed to the node.
    BlockSubmitted {
        hash: BlockHash,
        outcome: BlockOutcome,
    },
    SessionEnded {
        peer: SocketAddr,
        end: SessionEnd,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigError {
    pub field: &'static str,
    pub reason: &'static str,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid server config `{}`: {}", self.field, self.reason)
    }
}

impl Error for ConfigError {}

fn require(ok: bool, field: &'static str, reason: &'static str) -> Result<(), ConfigError> {
    if ok {
        Ok(())
    } else {
        Err(ConfigError { field, reason })
    }
}

/// Bounds and deadlines of one [`Server`].
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub max_frame_bytes: usize,
    pub max_notify_bytes: usize,
    pub poll_interval: Duration,
    pub accept_poll: Duration,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub frame_timeout: Duration,
    pub write_timeout: Duration,
    pub max_workers_per_session: usize,
    pub max_auth_failures: u32,
    pub max_consecutive_violations: u32,
    pub max_consecutive_share_rejects: u32,
    /// After a difficulty change, how long the easier of old and new target
    /// still judges shares (in-flight work).
    pub retarget_grace: Duration,
    pub thread_stack_bytes: usize,
    pub difficulty: DifficultyPolicy,
}

impl ServerConfig {
    #[must_use]
    pub fn new(difficulty: DifficultyPolicy) -> Self {
        Self {
            max_connections: 1024,
            max_connections_per_ip: 64,
            max_frame_bytes: 64 * 1024,
            max_notify_bytes: 1024 * 1024,
            poll_interval: Duration::from_millis(100),
            accept_poll: Duration::from_millis(10),
            handshake_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            frame_timeout: Duration::from_secs(15),
            write_timeout: Duration::from_secs(10),
            max_workers_per_session: 8,
            max_auth_failures: 3,
            max_consecutive_violations: 16,
            max_consecutive_share_rejects: 512,
            retarget_grace: Duration::from_secs(10),
            thread_stack_bytes: 512 * 1024,
            difficulty,
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let day = Duration::new(86_400, 0);
        require(
            self.max_connections > 0,
            "max_connections",
            "must be at least 1",
        )?;
        require(
            self.max_connections_per_ip > 0,
            "max_connections_per_ip",
            "must be at least 1",
        )?;
        require(
            (256..=1 << 20).contains(&self.max_frame_bytes),
            "max_frame_bytes",
            "must be within 256 bytes and 1 MiB",
        )?;
        require(
            (1024..=16 << 20).contains(&self.max_notify_bytes),
            "max_notify_bytes",
            "must be within 1 KiB and 16 MiB",
        )?;
        require(
            !self.poll_interval.is_zero() && self.poll_interval <= self.frame_timeout,
            "poll_interval",
            "must be nonzero and at most frame_timeout",
        )?;
        require(
            !self.accept_poll.is_zero(),
            "accept_poll",
            "must be nonzero",
        )?;
        require(
            !self.handshake_timeout.is_zero() && self.handshake_timeout <= day,
            "handshake_timeout",
            "must be within 1 ns and one day",
        )?;
        require(
            !self.idle_timeout.is_zero() && self.idle_timeout <= day,
            "idle_timeout",
            "must be within 1 ns and one day",
        )?;
        require(
            !self.frame_timeout.is_zero() && self.frame_timeout <= day,
            "frame_timeout",
            "must be within 1 ns and one day",
        )?;
        require(
            !self.write_timeout.is_zero() && self.write_timeout <= day,
            "write_timeout",
            "must be within 1 ns and one day",
        )?;
        require(
            self.max_workers_per_session > 0,
            "max_workers_per_session",
            "must be at least 1",
        )?;
        require(
            self.max_auth_failures > 0,
            "max_auth_failures",
            "must be at least 1",
        )?;
        require(
            self.max_consecutive_violations > 0,
            "max_consecutive_violations",
            "must be at least 1",
        )?;
        require(
            self.max_consecutive_share_rejects > 0,
            "max_consecutive_share_rejects",
            "must be at least 1",
        )?;
        require(
            self.retarget_grace <= Duration::from_secs(3600),
            "retarget_grace",
            "must be at most one hour",
        )?;
        require(
            self.thread_stack_bytes >= 256 * 1024,
            "thread_stack_bytes",
            "must be at least 256 KiB",
        )
    }
}

struct DeferredResponse {
    id: RequestId,
    has_id: bool,
    hash: BlockHash,
    class: ShareClass,
    block: Option<BlockOutcome>,
    completion: Arc<Completion>,
}

fn share_error_wire(error: &ShareError) -> super::WireError {
    match error {
        ShareError::UnknownSession(_) | ShareError::SessionPrefixLength { .. } => errors::INTERNAL,
        ShareError::UnknownJob(_)
        | ShareError::Stale {
            reason: StaleReason::Retired,
            ..
        } => errors::JOB_NOT_FOUND_ERROR,
        ShareError::Stale { .. } => errors::STALE_SHARE,
        ShareError::ExtranonceLength { .. } => errors::INVALID_EXTRANONCE2_LENGTH,
        ShareError::VersionOutsideMask { .. } => errors::VERSION_BITS_OUTSIDE_MASK,
        ShareError::TimeTooEarly { .. } | ShareError::TimeTooLate { .. } => errors::INVALID_NTIME,
        ShareError::Duplicate { .. } => errors::DUPLICATE_SHARE_ERROR,
        ShareError::BelowTarget { .. } => errors::LOW_DIFFICULTY_SHARE,
        ShareError::JobShareCapacity { .. } => errors::JOB_SHARE_CAPACITY,
    }
}

pub struct ServerDeps {
    pub pool: Arc<PoolCore>,
    pub accounts: Arc<dyn AccountResolver>,
    pub observer: Option<Observer>,
}

pub struct ConnectionLimiter {
    max_connections: usize,
    max_connections_per_ip: usize,
    state: Mutex<AdmissionState>,
}

struct AdmissionState {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

pub struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
    ip: IpAddr,
}

impl ConnectionLimiter {
    pub fn new(max_connections: usize, max_connections_per_ip: usize) -> Result<Self, ConfigError> {
        require(max_connections > 0, "max_connections", "must be at least 1")?;
        require(
            max_connections_per_ip > 0,
            "max_connections_per_ip",
            "must be at least 1",
        )?;
        Ok(Self {
            max_connections,
            max_connections_per_ip,
            state: Mutex::new(AdmissionState {
                total: 0,
                per_ip: HashMap::new(),
            }),
        })
    }

    pub fn try_admit(self: &Arc<Self>, ip: IpAddr) -> Result<ConnectionPermit, RefusalReason> {
        let mut state = locked(&self.state);
        if state.total >= self.max_connections {
            return Err(RefusalReason::ConnectionLimit);
        }
        let current = state.per_ip.get(&ip).copied().unwrap_or(0);
        if current >= self.max_connections_per_ip {
            return Err(RefusalReason::PerIpLimit);
        }
        state.total += 1;
        state.per_ip.insert(ip, current + 1);
        Ok(ConnectionPermit {
            limiter: Arc::clone(self),
            ip,
        })
    }

    #[must_use]
    pub fn active(&self) -> usize {
        locked(&self.state).total
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut state = locked(&self.limiter.state);
        state.total = state.total.saturating_sub(1);
        if let Some(current) = state.per_ip.get_mut(&self.ip) {
            *current = current.saturating_sub(1);
            if *current == 0 {
                state.per_ip.remove(&self.ip);
            }
        }
    }
}

struct Shared {
    config: ServerConfig,
    pool: Arc<PoolCore>,
    accounts: Arc<dyn AccountResolver>,
    observer: Option<Observer>,
    cancel: AtomicBool,
    limiter: Arc<ConnectionLimiter>,
    children: Mutex<Vec<JoinHandle<()>>>,
}

impl Shared {
    fn emit(&self, event: &ServerEvent) {
        if let Some(observer) = &self.observer {
            observer(event);
        }
    }
}

struct ConnectionSlot {
    _permit: ConnectionPermit,
}

enum Flow {
    Continue,
    Close(SessionEnd),
}

enum Verdict {
    Good,
    Accepted,
    Ignored,
    Violation,
    Rejected,
    Fatal(SessionEnd),
}

struct SessionState {
    shared: Arc<Shared>,
    ordinal: u64,
    peer: SocketAddr,
    lease: Option<Lease>,
    workers: Vec<(String, WorkerIdentity)>,
    version_rolling: Option<u32>,
    work_started: bool,
    difficulty: Difficulty,
    previous_target: Option<(ShareTarget, Instant)>,
    difficulty_pending: bool,
    seq: u64,
    poll_hint: bool,
    auth_failures: u32,
    violations: u32,
    rejects: u32,
    deferred: Vec<DeferredResponse>,
}

fn emit_line(out: &mut Vec<u8>, line: &str) {
    out.extend_from_slice(line.as_bytes());
}

/// Emits `line` unless `request` is a notification without an `"id"` member.
fn emit_reply(request: &Request, out: &mut Vec<u8>, line: &str) {
    if request.has_id {
        emit_line(out, line);
    }
}

impl SessionState {
    fn new(shared: Arc<Shared>, ordinal: u64, peer: SocketAddr) -> Self {
        let difficulty = shared.config.difficulty.initial().clone();
        Self {
            shared,
            ordinal,
            peer,
            lease: None,
            workers: Vec::new(),
            version_rolling: None,
            work_started: false,
            difficulty,
            previous_target: None,
            difficulty_pending: true,
            seq: 0,
            poll_hint: false,
            auth_failures: 0,
            violations: 0,
            rejects: 0,
            deferred: Vec::new(),
        }
    }

    fn is_ready(&self) -> bool {
        self.lease.is_some() && !self.workers.is_empty()
    }

    fn take_poll_hint(&mut self) -> bool {
        std::mem::take(&mut self.poll_hint)
    }

    fn handle_frame(&mut self, frame: &[u8], out: &mut Vec<u8>) -> Flow {
        let verdict = match decode_line(frame) {
            Err(failure) => {
                if failure.has_id {
                    emit_line(out, &encode_error(&failure.id, &failure.error));
                }
                Verdict::Violation
            }
            Ok(Incoming::Response) => Verdict::Ignored,
            Ok(Incoming::Request(request)) => self.dispatch(&request, out),
        };
        self.apply(verdict)
    }

    fn apply(&mut self, verdict: Verdict) -> Flow {
        let config = &self.shared.config;
        match verdict {
            Verdict::Ignored => Flow::Continue,
            Verdict::Good => {
                self.violations = 0;
                Flow::Continue
            }
            Verdict::Accepted => {
                self.violations = 0;
                self.rejects = 0;
                Flow::Continue
            }
            Verdict::Violation => {
                self.violations = self.violations.saturating_add(1);
                if self.violations >= config.max_consecutive_violations {
                    Flow::Close(SessionEnd::TooManyViolations)
                } else {
                    Flow::Continue
                }
            }
            Verdict::Rejected => {
                self.rejects = self.rejects.saturating_add(1);
                if self.rejects >= config.max_consecutive_share_rejects {
                    Flow::Close(SessionEnd::TooManyRejects)
                } else {
                    Flow::Continue
                }
            }
            Verdict::Fatal(end) => Flow::Close(end),
        }
    }

    fn dispatch(&mut self, request: &Request, out: &mut Vec<u8>) -> Verdict {
        let parsed = match ClientRequest::parse(request) {
            Ok(parsed) => parsed,
            Err(error) => {
                emit_reply(request, out, &encode_error(&request.id, &error));
                return Verdict::Violation;
            }
        };
        match parsed {
            ClientRequest::Configure(configure) => self.on_configure(request, &configure, out),
            ClientRequest::Subscribe(subscribe) => self.on_subscribe(request, subscribe, out),
            ClientRequest::Authorize(authorize) => self.on_authorize(request, authorize, out),
            ClientRequest::Submit(submit) => self.on_submit(request, &submit, out),
            ClientRequest::ExtranonceSubscribe => {
                emit_reply(
                    request,
                    out,
                    &encode_reject(&request.id, &errors::EXTRANONCE_SUBSCRIPTION_UNSUPPORTED),
                );
                Verdict::Ignored
            }
            ClientRequest::SuggestDifficulty(difficulty) => {
                self.on_suggest(request, difficulty, out)
            }
            ClientRequest::Unknown => {
                emit_reply(
                    request,
                    out,
                    &encode_error(&request.id, &errors::METHOD_NOT_FOUND),
                );
                Verdict::Violation
            }
        }
    }

    fn on_configure(
        &mut self,
        request: &Request,
        configure: &Configure,
        out: &mut Vec<u8>,
    ) -> Verdict {
        if self.work_started {
            emit_reply(
                request,
                out,
                &encode_error(&request.id, &errors::CONFIGURE_TOO_LATE),
            );
            return Verdict::Violation;
        }
        let mut members: Vec<String> = Vec::new();
        let mut answered: Vec<&str> = Vec::new();
        for name in &configure.extensions {
            if answered.contains(&name.as_str()) {
                continue;
            }
            answered.push(name);
            if name == "version-rolling" {
                let mask =
                    self.shared.pool.version_mask() & configure.version_rolling_mask.unwrap_or(0);
                if mask != 0 && mask.count_ones() >= configure.version_rolling_min_bits {
                    self.version_rolling = Some(mask);
                    members.push(String::from("\"version-rolling\":true"));
                    members.push(format!("\"version-rolling.mask\":\"{mask:08x}\""));
                } else {
                    self.version_rolling = None;
                    members.push(String::from("\"version-rolling\":false"));
                }
            } else {
                members.push(format!("{}:false", json_string(name)));
            }
        }
        emit_reply(
            request,
            out,
            &encode_result(&request.id, &format!("{{{}}}", members.join(","))),
        );
        Verdict::Good
    }

    fn on_subscribe(
        &mut self,
        request: &Request,
        subscribe: Subscribe,
        out: &mut Vec<u8>,
    ) -> Verdict {
        if self.lease.is_some() {
            emit_reply(
                request,
                out,
                &encode_error(&request.id, &errors::ALREADY_SUBSCRIBED),
            );
            return Verdict::Violation;
        }
        let Some(lease) = self.shared.pool.open_lease().ok() else {
            emit_reply(
                request,
                out,
                &encode_error(&request.id, &errors::POOL_AT_CAPACITY),
            );
            return Verdict::Fatal(SessionEnd::PoolRefused);
        };
        let extranonce1 = encode_hex(lease.session.extranonce_prefix());
        let extranonce2_size = self.shared.pool.layout().rolled_len();
        let tag = format!("{:x}", self.ordinal);
        let result = format!(
            "[[[\"mining.set_difficulty\",\"d{tag}\"],[\"mining.notify\",\"n{tag}\"]],\"{extranonce1}\",{extranonce2_size}]"
        );
        emit_reply(request, out, &encode_result(&request.id, &result));
        self.shared.emit(&ServerEvent::Subscribed {
            peer: self.peer,
            session: lease.session.id(),
            user_agent: subscribe.user_agent,
        });
        self.lease = Some(lease);
        if self.is_ready() {
            self.poll_hint = true;
        }
        Verdict::Good
    }

    fn on_authorize(
        &mut self,
        request: &Request,
        authorize: Authorize,
        out: &mut Vec<u8>,
    ) -> Verdict {
        let Ok(identity) = self
            .shared
            .accounts
            .resolve(&authorize.login, &authorize.password)
        else {
            self.auth_failures = self.auth_failures.saturating_add(1);
            emit_reply(
                request,
                out,
                &encode_reject(&request.id, &errors::UNAUTHORIZED_WORKER_ERROR),
            );
            return if self.auth_failures >= self.shared.config.max_auth_failures {
                Verdict::Fatal(SessionEnd::TooManyAuthFailures)
            } else {
                Verdict::Ignored
            };
        };

        if !self
            .workers
            .iter()
            .any(|(login, _)| *login == authorize.login)
        {
            if self.workers.len() >= self.shared.config.max_workers_per_session {
                emit_reply(
                    request,
                    out,
                    &encode_error(&request.id, &errors::TOO_MANY_WORKERS),
                );
                return Verdict::Violation;
            }
            self.workers.push((authorize.login, identity));
        }
        emit_reply(request, out, &encode_result(&request.id, "true"));
        if self.is_ready() {
            self.poll_hint = true;
        }
        Verdict::Good
    }

    fn on_suggest(
        &mut self,
        request: &Request,
        difficulty: Difficulty,
        out: &mut Vec<u8>,
    ) -> Verdict {
        if !self.shared.config.difficulty.contains(&difficulty) {
            emit_reply(
                request,
                out,
                &encode_reject(&request.id, &errors::DIFFICULTY_OUT_OF_RANGE),
            );
            return Verdict::Ignored;
        }
        if difficulty != self.difficulty {
            let until = Instant::now() + self.shared.config.retarget_grace;
            self.previous_target = Some((self.difficulty.target(), until));
            self.difficulty = difficulty;
            self.difficulty_pending = true;
        }
        emit_reply(request, out, &encode_result(&request.id, "true"));
        if self.is_ready() {
            self.poll_hint = true;
        }
        Verdict::Good
    }

    fn effective_target(&self, now: Instant) -> ShareTarget {
        match self.previous_target {
            Some((previous, until)) if now < until => previous.max(self.difficulty.target()),
            _ => self.difficulty.target(),
        }
    }

    fn on_submit(&mut self, request: &Request, submit: &Submit, out: &mut Vec<u8>) -> Verdict {
        let Some(lease) = self.lease.as_ref() else {
            emit_reply(
                request,
                out,
                &encode_error(&request.id, &errors::NOT_SUBSCRIBED_ERROR),
            );
            return Verdict::Violation;
        };
        let Some(identity) = self
            .workers
            .iter()
            .find(|(login, _)| *login == submit.login)
            .map(|(_, identity)| identity.clone())
        else {
            emit_reply(
                request,
                out,
                &encode_error(&request.id, &errors::UNAUTHORIZED_WORKER_ERROR),
            );
            return Verdict::Violation;
        };
        if let Some(bits) = submit.version_bits {
            let Some(mask) = self.version_rolling else {
                emit_reply(
                    request,
                    out,
                    &encode_error(&request.id, &errors::UNEXPECTED_VERSION_BITS),
                );
                return Verdict::Violation;
            };
            if bits & !mask != 0 {
                emit_reply(
                    request,
                    out,
                    &encode_reject(&request.id, &errors::VERSION_BITS_OUTSIDE_MASK),
                );
                return Verdict::Rejected;
            }
        }
        let Some(job) = parse_wire_job_id(&submit.job_id) else {
            emit_reply(
                request,
                out,
                &encode_reject(&request.id, &errors::JOB_NOT_FOUND_ERROR),
            );
            return Verdict::Rejected;
        };
        if !self.deferred.is_empty() {
            emit_reply(
                request,
                out,
                &encode_reject(&request.id, &errors::ACCOUNTING_UNAVAILABLE),
            );
            return Verdict::Ignored;
        }
        let version = match self.normalized_version(job, submit) {
            Ok(version) => version,
            Err(failure) => return Self::submit_failure_verdict(request, &failure, out),
        };
        let target = self.effective_target(Instant::now());
        let share_request = ShareRequest {
            session: lease.session.id(),
            job,
            rolled: &submit.extranonce2,
            ntime: submit.ntime,
            nonce: submit.nonce,
            version,
        };
        let session = share_request.session;
        match self.shared.pool.submit(&identity, &share_request, &target) {
            Ok(credited) => self.admit_credited(request, session, credited, out),
            Err(failure) => Self::submit_failure_verdict(request, &failure, out),
        }
    }

    fn normalized_version(&self, job: JobId, submit: &Submit) -> Result<u32, SubmitFailure> {
        match self.shared.pool.with_job_book(|book| {
            let job_ref = book.job(job)?;
            Some(match submit.version_bits {
                Some(bits) => job_ref.version_from_rolled_bits(bits),
                None => Ok(job_ref.version()),
            })
        }) {
            Some(result) => result.map_err(SubmitFailure::Share),
            None => Err(SubmitFailure::Share(ShareError::UnknownJob(job))),
        }
    }

    fn admit_credited(
        &mut self,
        request: &Request,
        session: SessionId,
        credited: Credited,
        out: &mut Vec<u8>,
    ) -> Verdict {
        if credited.completion.is_complete() {
            let reply = request.has_id.then_some(&request.id);
            self.emit_credited(reply, session, &credited, out);
        } else {
            self.deferred.push(DeferredResponse {
                id: request.id.clone(),
                has_id: request.has_id,
                hash: credited.hash,
                class: credited.class,
                block: credited.block,
                completion: credited.completion,
            });
            self.poll_hint = true;
        }
        Verdict::Accepted
    }

    fn submit_failure_verdict(
        request: &Request,
        failure: &SubmitFailure,
        out: &mut Vec<u8>,
    ) -> Verdict {
        match failure {
            SubmitFailure::Share(error) => {
                let wire = share_error_wire(error);
                if matches!(error, ShareError::ExtranonceLength { .. }) {
                    emit_reply(request, out, &encode_error(&request.id, &wire));
                    Verdict::Violation
                } else {
                    emit_reply(request, out, &encode_reject(&request.id, &wire));
                    Verdict::Rejected
                }
            }
            SubmitFailure::Duplicate => {
                emit_reply(
                    request,
                    out,
                    &encode_reject(&request.id, &errors::DUPLICATE_SHARE_ERROR),
                );
                Verdict::Rejected
            }
            SubmitFailure::OutboxFull => {
                emit_reply(
                    request,
                    out,
                    &encode_reject(&request.id, &errors::ACCOUNTING_UNAVAILABLE),
                );
                Verdict::Ignored
            }
        }
    }

    fn emit_credited(
        &self,
        id: Option<&RequestId>,
        session: SessionId,
        credited: &Credited,
        out: &mut Vec<u8>,
    ) {
        self.shared.emit(&ServerEvent::ShareAccepted {
            session,
            hash: credited.hash,
            class: credited.class,
            delivered: true,
        });
        if let Some(outcome) = credited.block {
            self.shared.emit(&ServerEvent::BlockSubmitted {
                hash: credited.hash,
                outcome,
            });
        }
        if let Some(id) = id {
            emit_line(out, &encode_result(id, "true"));
        }
    }

    fn emit_deferred_rejected(&self, response: &DeferredResponse, out: &mut Vec<u8>) {
        if response.has_id {
            emit_line(
                out,
                &encode_reject(&response.id, &errors::DUPLICATE_SHARE_ERROR),
            );
        }
    }

    fn settle_deferred(
        &self,
        response: DeferredResponse,
        session: Option<SessionId>,
        out: &mut Vec<u8>,
    ) -> Option<DeferredResponse> {
        if !response.completion.is_complete() {
            return Some(response);
        }
        if response.completion.is_rejected() {
            self.emit_deferred_rejected(&response, out);
            return None;
        }
        let session = session?;
        let credited = Credited {
            hash: response.hash,
            class: response.class,
            completion: response.completion,
            block: response.block,
        };
        let reply = response.has_id.then_some(&response.id);
        self.emit_credited(reply, session, &credited, out);
        None
    }

    fn poll(&mut self, out: &mut Vec<u8>) -> Flow {
        self.poll_hint = false;
        self.work_started = true;
        self.shared.pool.drain_outbox();
        let session = self.lease.as_ref().map(|lease| lease.session.id());
        let mut pending = Vec::with_capacity(self.deferred.len());
        for response in std::mem::take(&mut self.deferred) {
            if let Some(waiter) = self.settle_deferred(response, session, out) {
                pending.push(waiter);
            }
        }
        self.deferred = pending;
        if self.difficulty_pending {
            emit_line(out, &encode_set_difficulty(&self.difficulty));
            self.difficulty_pending = false;
        }
        let latest = self.shared.pool.latest();
        if latest.seq > self.seq
            && let Some(job) = latest.job
        {
            let line = encode_notify(&job, latest.clean_seq > self.seq);
            if line.len() > self.shared.config.max_notify_bytes {
                return Flow::Close(SessionEnd::PoolFault("notify exceeds the configured limit"));
            }
            emit_line(out, &line);
            self.seq = latest.seq;
        }
        Flow::Continue
    }
}

fn flush(stream: &mut TcpStream, out: &mut Vec<u8>) -> Result<(), SessionEnd> {
    if out.is_empty() {
        return Ok(());
    }
    let result = stream.write_all(out);
    out.clear();
    result.map_err(|error| match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => SessionEnd::WriteTimeout,
        kind => SessionEnd::Io(kind),
    })
}

fn run_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    ordinal: u64,
    shared: &Arc<Shared>,
) -> SessionEnd {
    let config = &shared.config;
    let _ = stream.set_nodelay(true);
    if let Err(error) = stream
        .set_nonblocking(false)
        .and_then(|()| stream.set_read_timeout(Some(config.poll_interval)))
        .and_then(|()| stream.set_write_timeout(Some(config.write_timeout)))
    {
        return SessionEnd::Io(error.kind());
    }
    shared.emit(&ServerEvent::Accepted { peer });

    let mut session = SessionState::new(Arc::clone(shared), ordinal, peer);
    let mut framer = LineBuffer::new(config.max_frame_bytes);
    let mut out: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 4096];
    let started = Instant::now();
    let mut last_activity = started;
    let mut last_poll = started;
    let mut partial_since: Option<Instant> = None;

    let end = 'run: loop {
        if shared.cancel.load(Ordering::Acquire) {
            break SessionEnd::Cancelled;
        }
        let mut completed_frame = false;
        match stream.read(&mut chunk) {
            Ok(0) => break SessionEnd::ClientClosed,
            Ok(count) => {
                if framer.push(&chunk[..count]).is_err() {
                    break SessionEnd::FrameTooLong;
                }
                loop {
                    match framer.next_frame() {
                        Ok(Some(frame)) => {
                            completed_frame = true;
                            last_activity = Instant::now();
                            if let Flow::Close(end) = session.handle_frame(&frame, &mut out) {
                                break 'run end;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => break 'run SessionEnd::FrameTooLong,
                    }
                }
            }
            Err(error) => match error.kind() {
                io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
                | io::ErrorKind::Interrupted => {}
                kind => break SessionEnd::Io(kind),
            },
        }
        let now = Instant::now();
        if completed_frame {
            partial_since = None;
        }
        if framer.has_partial() {
            partial_since.get_or_insert(now);
        } else {
            partial_since = None;
        }
        if let Err(end) = flush(&mut stream, &mut out) {
            break end;
        }
        if !session.is_ready() && now.duration_since(started) >= config.handshake_timeout {
            break SessionEnd::HandshakeTimeout;
        }
        if now.duration_since(last_activity) >= config.idle_timeout {
            break SessionEnd::IdleTimeout;
        }
        if partial_since.is_some_and(|since| now.duration_since(since) >= config.frame_timeout) {
            break SessionEnd::FrameTimeout;
        }
        if session.is_ready()
            && (session.take_poll_hint() || now.duration_since(last_poll) >= config.poll_interval)
        {
            last_poll = now;
            if let Flow::Close(end) = session.poll(&mut out) {
                break end;
            }
            if let Err(end) = flush(&mut stream, &mut out) {
                break end;
            }
        }
    };
    let _ = flush(&mut stream, &mut out);
    let _ = stream.shutdown(Shutdown::Both);
    end
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShutdownReport {
    pub sessions_joined: usize,
    pub sessions_panicked: usize,
}

pub struct Server {
    local_addr: SocketAddr,
    shared: Arc<Shared>,
    accept: Option<JoinHandle<(ShutdownReport, Vec<JoinHandle<()>>)>>,
    pending: Vec<JoinHandle<()>>,
}

fn refuse(shared: &Shared, stream: &TcpStream, peer: SocketAddr, reason: RefusalReason) {
    let _ = stream.shutdown(Shutdown::Both);
    shared.emit(&ServerEvent::Refused { peer, reason });
}

fn admit(shared: &Arc<Shared>, stream: TcpStream, peer: &SocketAddr, ordinal: u64) {
    let peer_value = *peer;
    let config = &shared.config;
    let permit = match shared.limiter.try_admit(peer_value.ip()) {
        Ok(permit) => permit,
        Err(reason) => {
            refuse(shared, &stream, peer_value, reason);
            return;
        }
    };
    let slot = ConnectionSlot { _permit: permit };
    let thread_shared = Arc::clone(shared);
    let spawned = thread::Builder::new()
        .name(format!("sv1-conn-{ordinal}"))
        .stack_size(config.thread_stack_bytes)
        .spawn(move || {
            let _slot = slot;
            let end = run_connection(stream, peer_value, ordinal, &thread_shared);
            thread_shared.emit(&ServerEvent::SessionEnded {
                peer: peer_value,
                end,
            });
        });
    match spawned {
        Ok(handle) => locked(&shared.children).push(handle),
        Err(_) => shared.emit(&ServerEvent::Refused {
            peer: peer_value,
            reason: RefusalReason::SpawnFailed,
        }),
    }
}

fn reap(handles: &mut Vec<JoinHandle<()>>, report: &mut ShutdownReport) {
    let mut index = 0;
    while index < handles.len() {
        if handles[index].is_finished() {
            let handle = handles.swap_remove(index);
            if handle.join().is_ok() {
                report.sessions_joined += 1;
            } else {
                report.sessions_panicked += 1;
            }
        } else {
            index += 1;
        }
    }
}

fn take_children(shared: &Shared) -> Vec<JoinHandle<()>> {
    std::mem::take(&mut *locked(&shared.children))
}

fn accept_loop(
    listener: &TcpListener,
    shared: &Arc<Shared>,
) -> (ShutdownReport, Vec<JoinHandle<()>>) {
    let mut report = ShutdownReport::default();
    let mut ordinal = 0_u64;
    while !shared.cancel.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                ordinal += 1;
                admit(shared, stream, &peer, ordinal);
            }
            Err(error) => match error.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => {
                    thread::sleep(shared.config.accept_poll);
                }
                _ => thread::sleep(shared.config.accept_poll * 10),
            },
        }
        let mut children = locked(&shared.children);
        reap(&mut children, &mut report);
    }
    let children = take_children(shared);
    (report, children)
}

impl Server {
    pub fn bind<A: ToSocketAddrs>(
        addr: A,
        config: ServerConfig,
        deps: ServerDeps,
    ) -> io::Result<Self> {
        config
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let limiter = Arc::new(
            ConnectionLimiter::new(config.max_connections, config.max_connections_per_ip)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
        );
        Self::bind_with_limiter(addr, config, deps, limiter)
    }

    pub fn bind_with_limiter<A: ToSocketAddrs>(
        addr: A,
        config: ServerConfig,
        deps: ServerDeps,
        limiter: Arc<ConnectionLimiter>,
    ) -> io::Result<Self> {
        config
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        let shared = Arc::new(Shared {
            config,
            pool: deps.pool,
            accounts: deps.accounts,
            observer: deps.observer,
            cancel: AtomicBool::new(false),
            limiter,
            children: Mutex::new(Vec::new()),
        });
        let accept_shared = Arc::clone(&shared);
        let accept = thread::Builder::new()
            .name(String::from("sv1-accept"))
            .spawn(move || accept_loop(&listener, &accept_shared))?;
        Ok(Self {
            local_addr,
            shared,
            accept: Some(accept),
            pending: Vec::new(),
        })
    }

    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    #[must_use]
    pub fn active_sessions(&self) -> usize {
        self.shared.limiter.active()
    }

    pub fn shutdown(mut self) -> ShutdownReport {
        self.stop()
    }

    pub fn shutdown_until(&mut self, deadline: Instant) -> io::Result<ShutdownReport> {
        self.shared.cancel.store(true, Ordering::Release);
        let Some(accept) = self.accept.take() else {
            return self.join_pending_until(deadline, ShutdownReport::default());
        };

        loop {
            if accept.is_finished() {
                let Ok((report, children)) = accept.join() else {
                    self.pending.extend(take_children(&self.shared));
                    return Err(io::Error::other(
                        "stratum accept thread panicked during shutdown",
                    ));
                };
                self.pending.extend(children);
                return self.join_pending_until(deadline, report);
            }
            let now = Instant::now();
            if now >= deadline {
                self.accept = Some(accept);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stratum server shutdown deadline expired",
                ));
            }
            thread::sleep((deadline - now).min(Duration::from_millis(5)));
        }
    }

    fn join_pending_until(
        &mut self,
        deadline: Instant,
        mut report: ShutdownReport,
    ) -> io::Result<ShutdownReport> {
        loop {
            let mut remaining = Vec::with_capacity(self.pending.len());
            for handle in self.pending.drain(..) {
                if handle.is_finished() {
                    if handle.join().is_ok() {
                        report.sessions_joined += 1;
                    } else {
                        report.sessions_panicked += 1;
                    }
                } else {
                    remaining.push(handle);
                }
            }
            self.pending = remaining;
            if self.pending.is_empty() {
                return Ok(report);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stratum server shutdown deadline expired",
                ));
            }
            thread::sleep((deadline - now).min(Duration::from_millis(5)));
        }
    }

    fn stop(&mut self) -> ShutdownReport {
        self.shared.cancel.store(true, Ordering::Release);
        let mut report = match self.accept.take() {
            Some(handle) => {
                if let Ok((report, children)) = handle.join() {
                    self.pending.extend(children);
                    report
                } else {
                    self.pending.extend(take_children(&self.shared));
                    ShutdownReport {
                        sessions_panicked: 1,
                        ..ShutdownReport::default()
                    }
                }
            }
            None => ShutdownReport::default(),
        };
        for handle in self.pending.drain(..) {
            if handle.join().is_ok() {
                report.sessions_joined += 1;
            } else {
                report.sessions_panicked += 1;
            }
        }
        report
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
