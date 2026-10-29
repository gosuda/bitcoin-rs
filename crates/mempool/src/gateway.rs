use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::entry::MempoolEntry;
use crate::pool::{Mempool, transaction_heap_usage};
use bitcoin_rs_consensus::{
    ConsensusError, ScriptExecutionCache, UtxoView, ValidationEngine, transaction_sigop_cost,
    verify_transaction,
};
use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, Txid, Wtxid};
use bitcoin_rs_script::VerifyFlags;
use bitcoin_rs_script::{is_p2sh, is_witness_program};
use hashbrown::{HashMap, HashSet};
use parking_lot::{Mutex, RwLock, RwLockReadGuard};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

struct PrevoutMap<'a>(&'a [(OutPoint, TxOut)]);

impl UtxoView for PrevoutMap<'_> {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.0
            .iter()
            .find(|(op, _)| op == outpoint)
            .map(|(_, txout)| txout.clone())
    }
}

struct MempoolUtxoView<'a, V> {
    pool: &'a Mempool,
    chain: &'a V,
}

impl<'a, V> MempoolUtxoView<'a, V> {
    #[must_use]
    const fn new(pool: &'a Mempool, chain: &'a V) -> Self {
        Self { pool, chain }
    }
}

impl<V> UtxoView for MempoolUtxoView<'_, V>
where
    V: UtxoView,
{
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        if let Some(entry) = self.pool.entry_by_txid(&outpoint.txid) {
            let vout = usize::try_from(outpoint.vout).ok()?;
            return entry.tx.outputs.get(vout).cloned();
        }
        self.chain.lookup(outpoint)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ChainChangeError {
    /// A chain change is already active (the current generation is odd).
    #[error("a chain change is already active")]
    AlreadyActive,
    /// The reserved odd or even value would overflow `u64`.
    #[error("chain generation overflow")]
    Overflow,
    /// The compare-exchange from the odd value to the reserved even value
    /// failed because the generation moved underneath the guard.
    #[error("chain generation changed before finish")]
    GenerationMoved,
    /// The guard was issued by a different gateway.
    #[error("chain change guard belongs to another gateway")]
    ForeignGuard,
}

pub struct AdmissionRequest {
    pub tx: Arc<Tx>,
    pub context: crate::standardness::PackageTxContext,
    pub prevouts: Vec<(
        bitcoin_rs_primitives::OutPoint,
        bitcoin_rs_primitives::TxOut,
    )>,
    pub prevout_meta: hashbrown::HashMap<OutPoint, crate::PrevoutMeta>,
    /// Median-time-past of the applied chain tip for BIP113 finality checks.
    /// Zero disables the locktime cutoff (pre-genesis).
    pub locktime_cutoff: u32,
    pub csv_active: bool,
    pub next_block_script_flags: VerifyFlags,
    /// Caller-supplied maximum fee rate in sat/kvB; `None` means no cap.
    pub max_feerate_sat_per_kvb: Option<u64>,
    /// Wall-clock seconds for the mempool entry timestamp.
    pub time: u64,
    pub height: u32,
    pub origin: AdmissionOrigin,
    pub expected_generation: u64,
    pub expected_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmitOutcome {
    Committed(crate::mutation::MutationResult),
    AlreadyKnown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdmitError {
    /// The chain generation changed between capture and the write-lock
    /// check. The caller must retry with a fresh stable generation.
    #[error("chain generation changed before admission")]
    GenerationChanged,
    /// The mempool sequence changed between capture and the write-lock
    /// check. The caller must retry with fresh facts.
    #[error("mempool sequence changed before admission")]
    MempoolChanged,
    /// The transaction was rejected by policy. The reason is mempool-owned.
    #[error(transparent)]
    Policy(#[from] crate::standardness::AcceptanceRejectReason),
    /// The transaction failed consensus verification (finality, duplicate
    /// inputs, overspend, sigop limits) or failed its input scripts under
    /// Core's policy flags (`STANDARD_SCRIPT_VERIFY_FLAGS`, validation.cpp
    /// `PolicyScriptChecks`).
    #[error("consensus verification failed")]
    Consensus,
}

pub(crate) struct PreparedAdmission {
    pub(crate) fact: crate::standardness::TxAcceptanceFact,
    prevouts: Vec<(OutPoint, TxOut)>,
    pub(crate) rejection: Option<(AdmitError, RejectScope)>,
    pub(crate) stamp: crate::pool::fee_policy::PolicyStamp,
    pub(crate) refused_bump: Option<crate::rbf::TrimBump>,
    replacement: ReplacementStage,
    engine: ValidationEngine,
    pub(crate) script_cache_key: Option<(Wtxid, VerifyFlags)>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AdmissionMode {
    Single,
    SingleSubmit,
    PackageTest,
    PackageSubmit,
    PackageRpcSubmit(Option<u64>),
}

#[allow(
    clippy::large_enum_variant,
    reason = "Admission stages keep their owned facts inline without an additional heap allocation."
)]
enum ReplacementStage {
    Rejected,
    Package,
    Captured(crate::rbf::ReplacementInputs),
    Verified(crate::rbf::PreparedPoolChange),
}

impl PreparedAdmission {
    pub(crate) fn check_package_max_feerate(&mut self, maximum: Option<u64>) {
        if self.rejection.is_none()
            && self.fact.vsize != 0
            && maximum.is_some_and(|max| {
                self.fact
                    .modified_fee
                    .is_some_and(|fee| fee > i128::from(max) * i128::from(self.fact.vsize) / 1_000)
            })
        {
            self.reject(
                AdmitError::Policy(crate::standardness::AcceptanceRejectReason::MaxFeeExceeded),
                RejectScope::Transaction,
            );
        }
    }

    fn reject(&mut self, error: AdmitError, scope: RejectScope) {
        self.replacement = ReplacementStage::Rejected;
        self.fact.allowed = Some(false);
        self.fact.reject_reason = Some(match error {
            AdmitError::Policy(reason) => reason,
            _ => crate::standardness::AcceptanceRejectReason::ScriptVerify,
        });
        self.rejection = Some((error, scope));
    }

    pub(crate) fn verify(
        &mut self,
        request: &AdmissionRequest,
        script_cache: Option<&ScriptExecutionCache>,
    ) {
        self.verify_policy(request);
        self.verify_scripts(request, script_cache);
    }

    pub(crate) fn verify_policy(&mut self, request: &AdmissionRequest) {
        use crate::standardness::AcceptanceRejectReason;
        if matches!(self.rejection, Some((AdmitError::Consensus, _))) {
            return;
        }
        if matches!(
            self.fact.reject_reason,
            Some(
                AcceptanceRejectReason::NonStandard(_)
                    | AcceptanceRejectReason::MissingInputs
                    | AcceptanceRejectReason::AlreadyInMempool
                    | AcceptanceRejectReason::TooManySigops
            )
        ) {
            return;
        }
        let default_scope = rejection_scope(&request.tx);
        let Some(height) = request.height.checked_add(1) else {
            self.reject(AdmitError::Consensus, default_scope);
            return;
        };
        if bitcoin_rs_consensus::verify_tx::verify_transaction_non_script(
            &request.tx,
            &PrevoutMap(&self.prevouts),
            height,
            request.locktime_cutoff,
            VerifyFlags::STANDARD,
        )
        .is_err()
        {
            self.reject(AdmitError::Consensus, default_scope);
            return;
        }
        for input in &request.tx.inputs {
            if let Some(meta) = request.prevout_meta.get(&input.previous_output)
                && bitcoin_rs_consensus::check_coinbase_maturity(meta.coinbase, meta.height, height)
                    .is_err()
            {
                self.reject(AdmitError::Consensus, default_scope);
                return;
            }
        }
        if self.rejection.is_some() {
            return;
        }
        let replacement = std::mem::replace(&mut self.replacement, ReplacementStage::Rejected);
        if let ReplacementStage::Captured(inputs) = replacement {
            match inputs.verify() {
                Ok(plan) => self.replacement = ReplacementStage::Verified(plan),
                Err(refusal) => {
                    let (error, bump) = refusal.into_parts();
                    self.refused_bump = bump;
                    self.reject(replacement_rejection(error), default_scope);
                }
            }
        } else if matches!(replacement, ReplacementStage::Package) {
            self.replacement = ReplacementStage::Package;
        } else {
            self.reject(AdmitError::MempoolChanged, default_scope);
        }
    }

    pub(crate) fn verify_scripts(
        &mut self,
        request: &AdmissionRequest,
        script_cache: Option<&ScriptExecutionCache>,
    ) {
        let verifying_refusal = self.refused_bump.is_some();
        if self.rejection.is_some() && !verifying_refusal {
            return;
        }
        let Some(height) = request.height.checked_add(1) else {
            self.refused_bump = None;
            return;
        };
        let default_scope = rejection_scope(&request.tx);
        let signature_cache = bitcoin_rs_script::SignatureCache::new();
        if let Err(error) = verify_transaction(
            &request.tx,
            &PrevoutMap(&self.prevouts),
            height,
            request.locktime_cutoff,
            VerifyFlags::STANDARD,
            self.engine,
            Some(&signature_cache),
        ) {
            if verifying_refusal {
                self.refused_bump = None;
                return;
            }
            let possibly_stripped = witness_strippable_failure(&error, &self.prevouts);
            self.reject(
                AdmitError::Consensus,
                if possibly_stripped {
                    RejectScope::Witness
                } else {
                    default_scope
                },
            );
            return;
        }
        let fee_for_max = self.fact.base_fee.unwrap_or(0);
        if crate::standardness::exceeds_max_feerate(
            fee_for_max,
            self.fact.vsize,
            request.max_feerate_sat_per_kvb,
        ) {
            self.refused_bump = None;
            if verifying_refusal {
                return;
            }
            self.reject(
                AdmitError::Policy(crate::standardness::AcceptanceRejectReason::MaxFeeExceeded),
                default_scope,
            );
        }
        if verifying_refusal {
            return;
        }
        if self.rejection.is_some() {
            return;
        }
        let Some(_) = script_cache.filter(|_| self.engine == ValidationEngine::Native) else {
            return;
        };
        let flags = request.next_block_script_flags;
        if let Err(error) = verify_transaction(
            &request.tx,
            &PrevoutMap(&self.prevouts),
            height,
            request.locktime_cutoff,
            flags,
            self.engine,
            Some(&signature_cache),
        ) {
            tracing::warn!(
                txid = %request.tx.txid(),
                flags = flags.bits(),
                error = %error,
                "script cache second pass failed after a STANDARD pass; not caching",
            );
            return;
        }
        self.script_cache_key = Some((request.tx.wtxid(), flags));
    }
}

fn replacement_rejection(error: RbfError) -> AdmitError {
    match error {
        RbfError::StalePlan => AdmitError::MempoolChanged,
        RbfError::Truc(error) => {
            AdmitError::Policy(crate::standardness::AcceptanceRejectReason::Truc(error))
        }
        RbfError::Mempool(crate::pool::MempoolError::Policy(policy)) => AdmitError::Policy(
            crate::standardness::AcceptanceRejectReason::PackageLimit(policy),
        ),
        other => AdmitError::Policy(crate::standardness::AcceptanceRejectReason::Replacement(
            other,
        )),
    }
}

fn rejection_scope(tx: &Tx) -> RejectScope {
    if tx.has_witness() {
        RejectScope::Witness
    } else {
        RejectScope::Transaction
    }
}

fn witness_strippable_failure(error: &ConsensusError, prevouts: &[(OutPoint, TxOut)]) -> bool {
    matches!(error, ConsensusError::Script { .. })
        && prevouts.iter().any(|(_, output)| {
            is_witness_program(&output.script_pubkey) || is_p2sh(&output.script_pubkey)
        })
}

use crate::mutation::{AdmissionOrigin, MutationEnvelope, MutationResult};
use crate::orphan::RejectScope;
use crate::pool::{MempoolError, PrioritiseError, PrioritisedTransaction};
#[cfg(any(test, feature = "test-seam"))]
use crate::rbf::ReplacementCandidate;
use crate::rbf::{LimitEnforcement, RbfError};

pub trait MempoolObserver: Send + Sync {
    /// Called once per committed, non-empty [`MutationEnvelope`].
    fn on_mutation(&self, envelope: &MutationEnvelope);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyInterest {
    /// Retain accepted transaction bodies until ordered publication.
    Bodies,
    /// Envelope metadata only; no body retention.
    Metadata,
}

#[derive(Default)]
pub struct CompositeObserver {
    legs: Mutex<Vec<(&'static str, Arc<dyn MempoolObserver>)>>,
    bodies_wanted: AtomicBool,
}

impl CompositeObserver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            legs: Mutex::new(alloc::vec::Vec::new()),
            bodies_wanted: AtomicBool::new(false),
        }
    }

    pub fn add_leg(
        &self,
        name: &'static str,
        leg: Arc<dyn MempoolObserver>,
        interest: BodyInterest,
    ) {
        self.legs.lock().push((name, leg));
        if interest == BodyInterest::Bodies {
            self.bodies_wanted.store(true, Ordering::Release);
        }
    }

    #[must_use]
    pub fn wants_bodies(&self) -> bool {
        self.bodies_wanted.load(Ordering::Acquire)
    }
}

fn panic_message_and_dispose(panic_payload: Box<dyn core::any::Any + Send>) -> (String, bool) {
    let message = panic_payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            panic_payload
                .downcast_ref::<&str>()
                .map(|message| (*message).to_string())
        })
        .unwrap_or_else(|| "non-string panic payload".to_owned());
    let disposal_panicked = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
        drop(panic_payload);
    }))
    .map_or_else(
        |nested_payload| {
            let _nested_payload = core::mem::ManuallyDrop::new(nested_payload);
            true
        },
        |()| false,
    );
    (message, disposal_panicked)
}

impl MempoolObserver for CompositeObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        let legs = self.legs.lock().clone();
        for (name, leg) in &legs {
            let outcome = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
                leg.on_mutation(envelope);
            }));
            if let Err(panic_payload) = outcome {
                metrics::counter!("node.mempool.observer_failures_total").increment(1);
                let (message, payload_disposal_panicked) = panic_message_and_dispose(panic_payload);
                tracing::warn!(
                    leg = *name,
                    message = %message,
                    payload_disposal_panicked,
                    "mempool observer leg panicked; later legs continue"
                );
            }
        }
    }
}

pub(crate) const BLOCK_RECONSTRUCTION_EXTRA_TXN: usize = 100;
pub(crate) const EXTRA_TXN_MAX_MEMORY_BYTES: usize = 100_000;

struct ExtraTxn {
    txid: Txid,
    wtxid: Wtxid,
    tx: Arc<Tx>,
}

#[derive(Default)]
pub(crate) struct ExtraTxnRing {
    entries: VecDeque<ExtraTxn>,
}

impl ExtraTxnRing {
    fn insert(&mut self, txid: Txid, wtxid: Wtxid, tx: &Arc<Tx>) {
        if tx.is_coinbase() || self.entries.iter().any(|held| held.wtxid == wtxid) {
            return;
        }
        if self.entries.len() == BLOCK_RECONSTRUCTION_EXTRA_TXN {
            self.entries.pop_front();
        }
        self.entries.push_back(ExtraTxn {
            txid,
            wtxid,
            tx: Arc::clone(tx),
        });
    }

    fn by_txid(&self, txid: Txid) -> Option<&Arc<Tx>> {
        self.entries
            .iter()
            .find(|held| held.txid == txid)
            .map(|held| &held.tx)
    }

    fn by_wtxid(&self, wtxid: Wtxid) -> Option<&Arc<Tx>> {
        self.entries
            .iter()
            .find(|held| held.wtxid == wtxid)
            .map(|held| &held.tx)
    }
}

fn retains_rejected_body(pool: &Mempool, tx: &Tx, error: AdmitError) -> bool {
    let AdmitError::Policy(reason) = error else {
        return false;
    };
    transaction_heap_usage(tx) < u64::try_from(EXTRA_TXN_MAX_MEMORY_BYTES).unwrap_or(u64::MAX)
        && !(matches!(
            reason,
            crate::standardness::AcceptanceRejectReason::MissingInputs
        ) && crate::admission::has_unspendable_input(pool, tx))
}

struct PublishState {
    queue: VecDeque<MutationEnvelope>,
    draining: bool,
}

pub struct MempoolGateway {
    pub(crate) pool: Arc<RwLock<Mempool>>,
    pub(crate) lifecycle: Mutex<crate::orphan::AdmissionLifecycle>,
    observer: Option<Arc<CompositeObserver>>,
    commit_order: Mutex<()>,
    publish: Mutex<PublishState>,
    pub(crate) extra_txn: Mutex<ExtraTxnRing>,
    chain_generation: AtomicU64,
    engine: ValidationEngine,
    script_cache: Option<Arc<ScriptExecutionCache>>,
}

impl core::fmt::Debug for MempoolGateway {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MempoolGateway")
            .field("pool", &self.pool)
            .field("observer", &self.observer.as_ref().map(|_| "installed"))
            .finish_non_exhaustive()
    }
}

impl MempoolGateway {
    #[must_use]
    pub fn new(
        pool: Arc<RwLock<Mempool>>,
        observer: Option<(Arc<dyn MempoolObserver>, BodyInterest)>,
        engine: ValidationEngine,
        script_cache: Option<Arc<ScriptExecutionCache>>,
    ) -> Self {
        let composite = observer.map(|(observer, interest)| {
            let composite = CompositeObserver::new();
            composite.add_leg("primary", observer, interest);
            Arc::new(composite)
        });
        Self {
            pool,
            lifecycle: Mutex::new(crate::orphan::AdmissionLifecycle::default()),
            observer: composite,
            commit_order: Mutex::new(()),
            publish: Mutex::new(PublishState {
                queue: VecDeque::new(),
                draining: false,
            }),
            extra_txn: Mutex::new(ExtraTxnRing::default()),
            chain_generation: AtomicU64::new(0),
            engine,
            script_cache,
        }
    }

    #[must_use]
    pub const fn engine(&self) -> ValidationEngine {
        self.engine
    }

    #[must_use]
    pub(crate) fn script_cache(&self) -> Option<&ScriptExecutionCache> {
        self.script_cache.as_deref()
    }

    pub fn attach_observer_leg(
        &self,
        name: &'static str,
        leg: Arc<dyn MempoolObserver>,
        interest: BodyInterest,
    ) -> Result<(), &'static str> {
        let Some(composite) = self.observer.as_ref() else {
            return Err("gateway has no observer slot to extend");
        };
        composite.add_leg(name, leg, interest);
        Ok(())
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn has_observer(&self) -> bool {
        self.observer.is_some()
    }

    #[must_use]
    pub fn reader(&self) -> crate::MempoolReader {
        crate::MempoolReader::new(Arc::clone(&self.pool))
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn pool(&self) -> &Arc<RwLock<Mempool>> {
        &self.pool
    }

    /// Read passthrough for lookup callers. Never mutate through this guard:
    /// mutations must go through the gateway so observers stay in the loop.
    pub fn read(&self) -> RwLockReadGuard<'_, Mempool> {
        self.pool.read()
    }

    /// Returns the exact even chain generation, or `None` when a chain change
    /// is active (odd) or a failed chain change has closed admission.
    #[must_use]
    pub fn stable_generation(&self) -> Option<u64> {
        let value = self.chain_generation.load(Ordering::Acquire);
        value.is_multiple_of(2).then_some(value)
    }

    pub(crate) fn chain_generation(&self) -> u64 {
        self.chain_generation.load(Ordering::Acquire)
    }

    /// Reserves the next chain-change generation and returns a guard that owns
    /// the exact odd value and the reserved next even value.
    pub fn begin_chain_change(self: &Arc<Self>) -> Result<ChainChangeGuard, ChainChangeError> {
        let pool_guard = self.pool.write();
        let current = self.chain_generation.load(Ordering::Relaxed);
        if !current.is_multiple_of(2) {
            return Err(ChainChangeError::AlreadyActive);
        }
        let odd = current.checked_add(1).ok_or(ChainChangeError::Overflow)?;
        let even = odd.checked_add(1).ok_or(ChainChangeError::Overflow)?;
        self.chain_generation.store(odd, Ordering::Release);
        drop(pool_guard);
        Ok(ChainChangeGuard {
            gateway: Arc::clone(self),
            odd,
            even,
        })
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the consuming mutation API retains the entry across bounded optimistic attempts"
    )]
    pub fn insert_entry(
        &self,
        origin: AdmissionOrigin,
        entry: MempoolEntry,
    ) -> Result<MutationResult, MempoolError> {
        for _ in 0..crate::admission::MAX_ADMISSION_RETRIES {
            let inputs = self
                .pool
                .read()
                .capture_insertion(
                    entry.clone(),
                    crate::rbf::FeeEstimation::Estimate,
                    crate::rbf::LimitEnforcement::Full,
                )
                .map_err(RbfError::into_pool_error)?;
            let plan = match inputs.verify() {
                Ok(plan) => plan,
                Err(refusal) => {
                    let mut pool = self.pool.write();
                    let (error, bump) = refusal.into_parts();
                    let error = match bump {
                        Some(bump) if pool.track_refused_trim(bump).is_err() => {
                            MempoolError::StalePolicy
                        }
                        _ => error.into_pool_error(),
                    };
                    if matches!(error, MempoolError::StalePolicy) {
                        continue;
                    }
                    return Err(error);
                }
            };
            let result = self.commit(
                origin,
                move |pool| {
                    pool.commit_pool_change(plan)
                        .map_err(RbfError::into_pool_error)
                },
                |result| Some(result),
            );
            if !matches!(result, Err(MempoolError::StalePolicy)) {
                return result;
            }
        }
        Err(MempoolError::StalePolicy)
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn replace_transaction(
        &self,
        origin: AdmissionOrigin,
        candidate: &ReplacementCandidate,
        time: u64,
        height: u32,
    ) -> Result<crate::mutation::MutationResult, RbfError> {
        for _ in 0..crate::admission::MAX_ADMISSION_RETRIES {
            let inputs = self.pool.read().capture_replacement(
                candidate,
                time,
                height,
                crate::rbf::FeeEstimation::Estimate,
            )?;
            let plan = match inputs.verify() {
                Ok(plan) => plan,
                Err(refusal) => {
                    let mut pool = self.pool.write();
                    let (error, bump) = refusal.into_parts();
                    let error = match bump {
                        Some(bump) if pool.track_refused_trim(bump).is_err() => RbfError::StalePlan,
                        _ => error,
                    };
                    if matches!(error, RbfError::StalePlan) {
                        continue;
                    }
                    return Err(error);
                }
            };
            let result = self.commit(
                origin,
                move |pool| pool.commit_pool_change(plan),
                |result| Some(result),
            );
            if !matches!(result, Err(RbfError::StalePlan)) {
                return result;
            }
        }
        Err(RbfError::StalePlan)
    }

    #[expect(clippy::needless_pass_by_value)]
    #[cfg(any(test, feature = "test-seam"))]
    pub fn admit_transaction(&self, request: AdmissionRequest) -> Result<AdmitOutcome, AdmitError> {
        self.admit_transaction_claimed(&request, None, crate::admission::AdmissionFence::Stable)
    }

    pub(crate) fn admit_transaction_claimed(
        &self,
        request: &AdmissionRequest,
        claim: Option<(&crate::orphan::HeldOrphan, &crate::PeerToken)>,
        fence: crate::admission::AdmissionFence,
    ) -> Result<AdmitOutcome, AdmitError> {
        let mut prepared = {
            let pool = self.pool.read();
            self.check_admission_state(
                &pool,
                request.expected_generation,
                request.expected_sequence,
                fence,
                None,
            )?;
            Self::prepare_admission(
                &pool,
                request,
                AdmissionMode::SingleSubmit,
                fence,
                self.engine(),
            )
        };
        prepared.verify(request, self.script_cache());

        #[cfg(any(test, feature = "test-seam"))]
        ordering_gate::park_if_armed(std::ptr::from_ref(self).expose_provenance());

        let cache_key = prepared.script_cache_key;

        let outcome = self.commit(
            request.origin,
            |pool| {
                self.check_admission_state(
                    pool,
                    request.expected_generation,
                    request.expected_sequence,
                    fence,
                    Some(prepared.stamp),
                )?;
                if claim.is_some_and(|(claim, announcer)| {
                    !self.lifecycle.lock().orphans.is_current(claim, announcer)
                }) {
                    return Ok(AdmitOutcome::AlreadyKnown);
                }
                let txid = request.tx.txid();
                if pool.contains_txid(&txid) {
                    self.lifecycle
                        .lock()
                        .orphans
                        .remove_transaction_variants(txid);
                    return Ok(AdmitOutcome::AlreadyKnown);
                }
                if let Some((error, scope)) = prepared.rejection {
                    if let Some(bump) = prepared.refused_bump {
                        if pool.track_refused_trim(bump).is_err() {
                            return Err(AdmitError::MempoolChanged);
                        }
                    }
                    self.record_peer_failure(pool, request, error, scope);
                    return Err(error);
                }
                let default_reject_scope = rejection_scope(&request.tx);

                let ReplacementStage::Verified(plan) = prepared.replacement else {
                    return Err(AdmitError::MempoolChanged);
                };
                let replaced: Vec<_> = plan
                    .replaced_entries(pool)
                    .map(|entry| (entry.txid, entry.wtxid, Arc::clone(&entry.tx)))
                    .collect();
                pool.commit_pool_change(plan)
                    .map(|result| {
                        self.retain_replaced(&replaced);
                        AdmitOutcome::Committed(result)
                    })
                    .map_err(|error| {
                        let error = replacement_rejection(error);
                        self.record_peer_failure(pool, request, error, default_reject_scope);
                        error
                    })
            },
            |outcome| match outcome {
                AdmitOutcome::AlreadyKnown => None,
                AdmitOutcome::Committed(result) => Some(result),
            },
        )?;
        if matches!(outcome, AdmitOutcome::Committed(_)) {
            if let (Some((wtxid, flags)), Some(cache)) = (cache_key, self.script_cache()) {
                cache.insert(wtxid, flags);
            }
        }
        Ok(outcome)
    }

    pub(crate) fn check_admission_state(
        &self,
        pool: &Mempool,
        expected_generation: u64,
        expected_sequence: u64,
        fence: crate::admission::AdmissionFence,
        stamp: Option<crate::pool::fee_policy::PolicyStamp>,
    ) -> Result<(), AdmitError> {
        if fence.current(self) != Some(expected_generation) {
            return Err(AdmitError::GenerationChanged);
        }
        if pool.sequence_number() != expected_sequence {
            return Err(AdmitError::MempoolChanged);
        }
        if stamp.is_some_and(|stamp| !stamp.matches(pool)) {
            return Err(AdmitError::MempoolChanged);
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "keep policy precedence and the captured preparation stamp in one owner"
    )]
    pub(crate) fn prepare_admission(
        pool: &Mempool,
        request: &AdmissionRequest,
        mode: AdmissionMode,
        fence: crate::admission::AdmissionFence,
        engine: ValidationEngine,
    ) -> PreparedAdmission {
        let policy = pool.policy_snapshot();
        let chain = PrevoutMap(&request.prevouts);
        let view = MempoolUtxoView::new(pool, &chain);
        let standard =
            crate::standardness::is_standard_tx(&request.tx, &policy.standardness).is_ok();
        let prevouts: Vec<_> = if standard && !pool.contains_txid(&request.tx.txid()) {
            request
                .tx
                .inputs
                .iter()
                .filter_map(|input| {
                    view.lookup(&input.previous_output)
                        .map(|output| (input.previous_output, output))
                })
                .collect()
        } else {
            Vec::new()
        };
        let mut context = request.context;
        if standard {
            context.sigop_cost =
                transaction_sigop_cost(&request.tx, &prevouts, VerifyFlags::STANDARD);
            context.vsize = context.vsize.max(crate::accounting::policy_vsize(
                &request.tx,
                context.sigop_cost,
            ));
        }
        let enforcement = match (request.origin, fence) {
            (AdmissionOrigin::Reorg, crate::admission::AdmissionFence::ChainChange(_)) => {
                LimitEnforcement::Deferred
            }
            (_, crate::admission::AdmissionFence::Stable)
                if mode == AdmissionMode::SingleSubmit
                    && !matches!(request.origin, AdmissionOrigin::Reorg) =>
            {
                LimitEnforcement::ExpireBeforeTrim(request.time)
            }
            _ => LimitEnforcement::Full,
        };
        let deferred = enforcement == LimitEnforcement::Deferred;
        let floor = if deferred
            || matches!(
                mode,
                AdmissionMode::PackageSubmit | AdmissionMode::PackageRpcSubmit(_)
            ) {
            None
        } else {
            Some(pool.min_fee_sat_per_kvb(bitcoin_rs_primitives::unix_time_secs()))
        };
        let next_height = request.height.saturating_add(1);
        let resolved_prevouts: HashSet<OutPoint> =
            request.prevouts.iter().map(|(op, _)| *op).collect();
        let finality = crate::standardness::Bip68Admission {
            csv_active: request.csv_active,
            next_height,
            next_mtp: request.locktime_cutoff,
            prevout_meta: Some(&request.prevout_meta),
            resolved_prevouts: Some(&resolved_prevouts),
        };
        let fact = crate::standardness::evaluate_one(
            pool,
            &policy.standardness,
            &request.tx,
            context,
            None,
            floor,
            &finality,
        );
        let rejection = fact
            .reject_reason
            .map(|reason| (AdmitError::Policy(reason), rejection_scope(&request.tx)));
        let mut prepared = PreparedAdmission {
            fact,
            prevouts,
            rejection,
            stamp: pool.policy_stamp(),
            refused_bump: None,
            replacement: ReplacementStage::Rejected,
            engine,
            script_cache_key: None,
        };
        if !pool.contains_txid(&request.tx.txid()) {
            if standard
                && bitcoin_rs_consensus::verify_tx::verify_transaction_input_outpoints(&request.tx)
                    .is_err()
            {
                prepared.reject(AdmitError::Consensus, RejectScope::Transaction);
            } else if crate::admission::has_invalid_mempool_outpoint(pool, &request.tx) {
                prepared.reject(
                    AdmitError::Policy(crate::standardness::AcceptanceRejectReason::MissingInputs),
                    RejectScope::Transaction,
                );
            }
        }
        if matches!(
            mode,
            AdmissionMode::PackageTest
                | AdmissionMode::PackageSubmit
                | AdmissionMode::PackageRpcSubmit(_)
        ) {
            if !pool.contains_txid(&request.tx.txid())
                && !pool.conflicts_for(&request.tx).is_empty()
            {
                prepared.reject(
                    AdmitError::Policy(
                        crate::standardness::AcceptanceRejectReason::MempoolConflict,
                    ),
                    rejection_scope(&request.tx),
                );
            }
            if prepared.rejection.is_none() {
                match pool.truc_conflicts(&request.tx, prepared.fact.vsize, false) {
                    Ok(_) => prepared.replacement = ReplacementStage::Package,
                    Err(error) => {
                        prepared.reject(replacement_rejection(error), rejection_scope(&request.tx));
                    }
                }
            }
        } else if prepared.rejection.is_none() {
            let fee_estimation = crate::rbf::FeeEstimation::from_origin(&request.origin);
            let conflict_set = pool.truc_conflicts(&request.tx, prepared.fact.vsize, true);
            let captured = conflict_set.and_then(|(conflicts, sibling_eviction)| {
                let entry = MempoolEntry::new(
                    Arc::clone(&request.tx),
                    prepared.fact.vsize,
                    prepared.fact.base_fee.unwrap_or(0),
                    request.time,
                    request.height,
                    prepared.fact.sigop_cost,
                );
                if conflicts.is_empty() {
                    pool.capture_insertion(entry, fee_estimation, enforcement)
                } else {
                    pool.capture_admission(
                        entry,
                        conflicts,
                        policy.incremental_relay_fee_sat_per_kvb,
                        sibling_eviction,
                        fee_estimation,
                        enforcement,
                    )
                }
            });
            match captured {
                Ok(inputs) => prepared.replacement = ReplacementStage::Captured(inputs),
                Err(error) => {
                    prepared.reject(replacement_rejection(error), rejection_scope(&request.tx));
                }
            }
            if prepared.rejection.is_none()
                && crate::package::missing_ephemeral_spends(
                    pool,
                    core::slice::from_ref(request.tx.as_ref()),
                    policy.standardness.dust_relay_fee,
                )
                .is_some()
            {
                prepared.reject(
                    AdmitError::Policy(
                        crate::standardness::AcceptanceRejectReason::MissingEphemeralSpends,
                    ),
                    rejection_scope(&request.tx),
                );
            }
        }
        prepared
    }

    pub fn remove_for_reorg(
        &self,
        change: &ChainChangeGuard,
        chain: &dyn crate::admission::AdmissionChain,
    ) -> Result<MutationResult, ChainChangeError> {
        if !change.owns(self) {
            return Err(ChainChangeError::ForeignGuard);
        }
        let residents: Vec<Arc<Tx>> = {
            let pool = self.pool.read();
            pool.iter_entries()
                .map(|entry| Arc::clone(&entry.tx))
                .collect()
        };
        let mut failing = Vec::new();
        for tx in residents {
            let Some(snapshot) = chain.snapshot(&tx) else {
                continue;
            };
            let next_height = snapshot.height.saturating_add(1);
            let fails = {
                let pool = self.pool.read();
                let missing_input = tx.inputs.iter().any(|input| {
                    !pool.contains_txid(&input.previous_output.txid)
                        && !snapshot
                            .prevouts
                            .iter()
                            .any(|(outpoint, _)| *outpoint == input.previous_output)
                });
                let nonfinal = !bitcoin_rs_consensus::verify_tx::is_final_tx(
                    &tx,
                    next_height,
                    snapshot.locktime_cutoff,
                );
                let immature = tx.inputs.iter().any(|input| {
                    snapshot
                        .prevout_meta
                        .get(&input.previous_output)
                        .is_some_and(|meta| {
                            bitcoin_rs_consensus::check_coinbase_maturity(
                                meta.coinbase,
                                meta.height,
                                next_height,
                            )
                            .is_err()
                        })
                });
                let bip68 = !crate::standardness::bip68_final(
                    &pool,
                    &tx,
                    &crate::standardness::Bip68Admission {
                        csv_active: snapshot.csv_active,
                        next_height,
                        next_mtp: snapshot.locktime_cutoff,
                        prevout_meta: Some(&snapshot.prevout_meta),
                        resolved_prevouts: None,
                    },
                );
                missing_input || nonfinal || immature || bip68
            };
            if fails {
                failing.push(tx.txid());
            }
        }
        self.commit(
            AdmissionOrigin::Reorg,
            |pool| {
                let fence = crate::admission::AdmissionFence::ChainChange(change.odd_generation());
                if fence.current(self) != Some(change.odd_generation()) {
                    return Err(ChainChangeError::GenerationMoved);
                }
                Ok(pool.remove_for_reorg(&failing))
            },
            |result| Some(result),
        )
    }

    pub fn remove_for_block(
        &self,
        origin: AdmissionOrigin,
        block_txs: &[&Tx],
        block_txids: &[Txid],
        height: u32,
        now: u64,
    ) -> MutationResult {
        self.commit_infallible(origin, |pool| {
            pool.remove_for_block(block_txs, block_txids, height, now)
        })
    }

    pub fn expire(&self, origin: AdmissionOrigin, now: u64) -> Option<MutationResult> {
        if !self.pool.read().has_expired_entries(now) {
            return None;
        }
        Some(self.commit_infallible(origin, |pool| pool.expire(now)))
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn evict_below_fee_rate(
        &self,
        origin: AdmissionOrigin,
        threshold_sat_per_kvb: u64,
    ) -> MutationResult {
        self.commit_infallible(origin, |pool| {
            pool.evict_below_fee_rate(threshold_sat_per_kvb)
        })
    }

    /// The configured total-size ceiling of the underlying pool, in vbytes.
    #[must_use]
    pub fn max_total_bytes(&self) -> u64 {
        self.pool.read().limits.max_total_bytes
    }

    pub fn enforce_size_limit(
        &self,
        origin: AdmissionOrigin,
        max_bytes: u64,
    ) -> Result<MutationResult, MempoolError> {
        let inputs = self.pool.read().capture_eviction(max_bytes)?;
        let plan = inputs.verify();
        self.commit(
            origin,
            move |pool| {
                pool.commit_pool_change(plan)
                    .map_err(RbfError::into_pool_error)
            },
            |result| Some(result),
        )
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn clear(&self, origin: AdmissionOrigin) -> MutationResult {
        self.commit_infallible(origin, Mempool::clear)
    }

    /// Commits `pool.prioritise`. Never publishes: prioritisation emits no
    /// mutation change, so there is nothing to order.
    pub fn prioritise(&self, txid: Txid, fee_delta: i64) -> Result<(), PrioritiseError> {
        let mut pool = self.pool.write();
        self.apply_prioritise(&mut pool, txid, fee_delta)
    }

    /// A successful P2P getdata response completes initial broadcast of this
    /// exact witness body. Membership and its public sequence do not change.
    pub fn mark_broadcast(&self, wtxid: bitcoin_rs_primitives::Wtxid) {
        self.pool.write().set_unbroadcast(wtxid, false);
    }

    pub(crate) fn restore_unbroadcast(&self, wtxid: bitcoin_rs_primitives::Wtxid) {
        self.pool.write().set_unbroadcast(wtxid, true);
    }

    /// Atomically rejects pooled dust before applying a fee overlay.
    pub fn prioritise_if_not_dust(
        &self,
        txid: Txid,
        fee_delta: i64,
        dust_relay_fee: u64,
    ) -> Result<bool, PrioritiseError> {
        let mut pool = self.pool.write();
        if let Some(entry) = pool.entry_by_txid(&txid)
            && crate::standardness::tx_has_dust_outputs(&entry.tx, dust_relay_fee)
        {
            return Ok(false);
        }
        self.apply_prioritise(&mut pool, txid, fee_delta)?;
        Ok(true)
    }

    fn apply_prioritise(
        &self,
        pool: &mut Mempool,
        txid: Txid,
        fee_delta: i64,
    ) -> Result<(), PrioritiseError> {
        pool.prioritise(txid, fee_delta)?;
        if fee_delta != 0 {
            self.lifecycle.lock().clear_rejects();
        }
        Ok(())
    }

    #[must_use]
    pub fn prioritised_transactions(&self) -> Vec<PrioritisedTransaction> {
        self.read().prioritised_transactions()
    }

    pub(crate) fn commit<T, E>(
        &self,
        origin: AdmissionOrigin,
        mutate: impl FnOnce(&mut Mempool) -> Result<T, E>,
        mutation: impl FnOnce(&T) -> Option<&MutationResult>,
    ) -> Result<T, E> {
        let bodies_wanted = self
            .observer
            .as_ref()
            .is_some_and(|observer| observer.wants_bodies());
        let order = self.commit_order.lock();
        let mut elected = false;
        let mut pending = None;
        let outcome = {
            let mut pool = self.pool.write();
            pool.accepted_capture = bodies_wanted.then(Vec::new);
            let outcome = mutate(&mut pool);
            let captured = pool.accepted_capture.take().unwrap_or_default();
            let outcome = outcome?;
            if let Some(result) = mutation(&outcome) {
                if matches!(origin, AdmissionOrigin::Rpc | AdmissionOrigin::Esplora) {
                    for change in &result.changes {
                        if matches!(change.outcome, crate::MutationOutcome::Accepted)
                            && let Some(wtxid) = pool
                                .entry_by_txid(&Txid(change.txid))
                                .map(|entry| entry.wtxid)
                        {
                            pool.set_unbroadcast(wtxid, true);
                        }
                    }
                }
                self.update_admission_lifecycle(&pool, result);
                if !result.changes.is_empty() && self.observer.is_some() {
                    pending = Some((result.clone(), captured));
                }
            }
            outcome
        };
        if let Some((result, captured)) = pending {
            let transactions = Self::join_accepted_bodies(&result, captured, bodies_wanted);
            let mut publish = self.publish.lock();
            publish.queue.push_back(MutationEnvelope {
                origin,
                result,
                accepted_transactions: transactions,
            });
            elected = !publish.draining;
            publish.draining = true;
        }
        drop(order);
        if elected {
            self.drain();
        }
        Ok(outcome)
    }

    fn join_accepted_bodies(
        result: &MutationResult,
        captured: Vec<(Txid, Arc<Tx>)>,
        bodies_wanted: bool,
    ) -> Vec<(usize, Arc<Tx>)> {
        let mut bodies = HashMap::with_capacity(captured.len());
        for (txid, body) in captured {
            bodies.insert(txid, body);
        }
        result
            .changes
            .iter()
            .enumerate()
            .filter_map(|(index, change)| {
                if !matches!(change.outcome, crate::MutationOutcome::Accepted) {
                    return None;
                }
                let Some(body) = bodies.remove(&Txid(change.txid)) else {
                    if bodies_wanted {
                        tracing::warn!(
                            txid = ?change.txid,
                            "accepted transaction has no captured body; envelope omits it",
                        );
                    }
                    debug_assert!(
                        !bodies_wanted,
                        "capture was enabled but an Accepted change has no body",
                    );
                    return None;
                };
                Some((index, body))
            })
            .collect()
    }

    fn record_peer_failure(
        &self,
        pool: &Mempool,
        request: &AdmissionRequest,
        error: AdmitError,
        scope: RejectScope,
    ) {
        let AdmissionOrigin::Peer(source) = request.origin else {
            return;
        };
        let hold = error
            == AdmitError::Policy(crate::standardness::AcceptanceRejectReason::MissingInputs)
            && crate::admission::can_hold_orphan(
                pool,
                &request.tx,
                &pool.policy_snapshot().standardness,
            );
        let mut lifecycle = self.lifecycle.lock();
        if hold {
            lifecycle
                .orphans
                .insert(Arc::clone(&request.tx), source, request.time);
            self.retain_for_reconstruction(&request.tx);
        } else {
            lifecycle.reject(&request.tx, scope);
            if retains_rejected_body(pool, &request.tx, error) {
                self.retain_for_reconstruction(&request.tx);
            }
        }
    }

    pub(crate) fn record_peer_package_refusal(
        &self,
        pool: &Mempool,
        requests: &[AdmissionRequest],
        prepared: &[PreparedAdmission],
    ) {
        for (request, job) in requests.iter().zip(prepared) {
            if let Some((error, scope)) = job.rejection {
                self.record_peer_failure(pool, request, error, scope);
            }
        }
    }

    fn retain_for_reconstruction(&self, tx: &Arc<Tx>) {
        let (txid, wtxid) = (tx.txid(), tx.wtxid());
        self.extra_txn.lock().insert(txid, wtxid, tx);
    }

    fn retain_replaced(&self, replaced: &[(Txid, Wtxid, Arc<Tx>)]) {
        if replaced.is_empty() {
            return;
        }
        let mut ring = self.extra_txn.lock();
        for (txid, wtxid, tx) in replaced {
            ring.insert(*txid, *wtxid, tx);
        }
    }

    /// Invokes `f` for every transaction a BIP152 reconstruction may match:
    /// each pool entry, then each retained extra not already in the pool.
    pub fn for_each_reconstruction_identity(&self, mut f: impl FnMut(Txid, Wtxid)) {
        let pool = self.pool.read();
        for entry in pool.iter_entries() {
            f(entry.txid, entry.wtxid);
        }
        let ring = self.extra_txn.lock();
        for held in &ring.entries {
            if !pool.contains_wtxid(&held.wtxid) {
                f(held.txid, held.wtxid);
            }
        }
    }

    /// The pool body for `txid`, else a retained reconstruction extra. Hint
    /// use only; see [`Self::for_each_reconstruction_identity`].
    #[must_use]
    pub fn reconstruction_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
        let pool = self.pool.read();
        if let Some(tx) = pool.transaction_by_txid(&txid) {
            return Some((*tx).clone());
        }
        self.extra_txn.lock().by_txid(txid).map(|tx| (**tx).clone())
    }

    /// The pool body for `wtxid`, else a retained reconstruction extra. Hint
    /// use only; see [`Self::for_each_reconstruction_identity`].
    #[must_use]
    pub fn reconstruction_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        let pool = self.pool.read();
        if let Some(entry) = pool.entry_by_wtxid(&wtxid) {
            return Some((*entry.tx).clone());
        }
        self.extra_txn
            .lock()
            .by_wtxid(wtxid)
            .map(|tx| (**tx).clone())
    }

    fn update_admission_lifecycle(&self, pool: &Mempool, result: &MutationResult) {
        if result.changes.is_empty() {
            return;
        }
        let mut lifecycle = self.lifecycle.lock();
        for change in &result.changes {
            if matches!(change.outcome, crate::mutation::MutationOutcome::Accepted) {
                let txid = Txid::from(change.txid);
                lifecycle.orphans.remove_transaction_variants(txid);
                if pool.contains_txid(&txid) {
                    lifecycle.orphans.parent_ready(txid);
                }
            }
        }
    }

    fn commit_infallible(
        &self,
        origin: AdmissionOrigin,
        mutate: impl FnOnce(&mut Mempool) -> MutationResult,
    ) -> MutationResult {
        let Ok(result) = self.commit(
            origin,
            |pool| Ok::<_, core::convert::Infallible>(mutate(pool)),
            |result| Some(result),
        );
        result
    }

    fn drain(&self) {
        loop {
            let envelope = {
                let mut publish = self.publish.lock();
                if let Some(envelope) = publish.queue.pop_front() {
                    envelope
                } else {
                    publish.draining = false;
                    return;
                }
            };
            let Some(observer) = self.observer.as_ref() else {
                continue;
            };
            let outcome = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
                observer.on_mutation(&envelope);
            }));
            if let Err(panic_payload) = outcome {
                let (message, payload_disposal_panicked) = panic_message_and_dispose(panic_payload);
                tracing::warn!(
                    message = %message,
                    payload_disposal_panicked,
                    "mempool observer panicked; the committed mutation stands"
                );
            }
        }
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn force_chain_generation(&self, value: u64) {
        self.chain_generation.store(value, Ordering::Release);
    }
}

/// Owns an active chain-change reservation: the exact odd generation and the
/// reserved next even value.
#[derive(Debug)]
pub struct ChainChangeGuard {
    gateway: Arc<MempoolGateway>,
    odd: u64,
    even: u64,
}

impl ChainChangeGuard {
    #[must_use]
    pub(crate) fn odd_generation(&self) -> u64 {
        self.odd
    }

    #[cfg(test)]
    #[must_use]
    fn reserved_even(&self) -> u64 {
        self.even
    }

    pub(crate) fn owns(&self, gateway: &MempoolGateway) -> bool {
        core::ptr::eq(Arc::as_ptr(&self.gateway), gateway)
    }

    /// Compare-exchanges the exact odd value to the reserved even value.
    pub fn finish(self) -> Result<(), ChainChangeError> {
        let prev = self.gateway.chain_generation.compare_exchange(
            self.odd,
            self.even,
            Ordering::Release,
            Ordering::Relaxed,
        );
        if prev.is_ok() {
            Ok(())
        } else {
            Err(ChainChangeError::GenerationMoved)
        }
    }
}

#[cfg(any(test, feature = "test-seam"))]
mod ordering_gate {
    use parking_lot::Mutex;
    use std::sync::mpsc::{Receiver, Sender};

    struct Gate {
        armed: Option<(usize, Sender<()>, Receiver<()>)>,
    }

    static GATE: Mutex<Gate> = Mutex::new(Gate { armed: None });

    pub(super) fn arm(target: usize, parked_tx: Sender<()>, release_rx: Receiver<()>) {
        let mut gate = GATE.lock();
        assert!(gate.armed.is_none(), "ordering gate armed twice");
        gate.armed = Some((target, parked_tx, release_rx));
    }

    pub(super) fn reset() {
        GATE.lock().armed = None;
    }

    pub(super) fn park_if_armed(target: usize) {
        let Some((parked_tx, release_rx)) = ({
            let mut gate = GATE.lock();
            match gate.armed.take() {
                Some((armed_target, parked_tx, release_rx)) if armed_target == target => {
                    Some((parked_tx, release_rx))
                }
                Some(armed) => {
                    gate.armed = Some(armed);
                    None
                }
                None => None,
            }
        }) else {
            return;
        };
        let _ = parked_tx.send(());
        let _ = release_rx.recv();
    }
}

#[cfg(any(test, feature = "test-seam"))]
pub fn arm_admission_park(
    target: usize,
    parked_tx: std::sync::mpsc::Sender<()>,
    release_rx: std::sync::mpsc::Receiver<()>,
) {
    ordering_gate::arm(target, parked_tx, release_rx);
}

#[cfg(any(test, feature = "test-seam"))]
pub fn reset_admission_park() {
    ordering_gate::reset();
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;
