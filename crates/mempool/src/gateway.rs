use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::entry::MempoolEntry;
use crate::pool::{Mempool, transaction_heap_usage};
use bitcoin_rs_consensus::primitives::{OutPoint, Tx, TxOut, Txid, Wtxid};
use bitcoin_rs_consensus::script::VerifyFlags;
use bitcoin_rs_consensus::script::{is_p2sh, is_witness_program};
use bitcoin_rs_consensus::{
    ConsensusError, ScriptExecutionCache, UtxoView, ValidationEngine, transaction_sigop_cost,
    verify_transaction,
};
use hashbrown::{HashMap, HashSet};
use parking_lot::{Condvar, Mutex, RwLock, RwLockReadGuard};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(test)]
use std::sync::mpsc;

struct PrevoutMap<'a> {
    index: HashMap<OutPoint, &'a TxOut>,
}

#[cfg(test)]
std::thread_local! {
    static PREVOUT_PROBES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
fn bump_prevout_probes(count: usize) {
    PREVOUT_PROBES.with(|probes| probes.set(probes.get() + count));
}

#[cfg(test)]
fn reset_prevout_probes() {
    PREVOUT_PROBES.with(|probes| probes.set(0));
}

#[cfg(test)]
fn prevout_probes() -> usize {
    PREVOUT_PROBES.with(core::cell::Cell::get)
}

impl<'a> PrevoutMap<'a> {
    fn new(prevouts: &'a [(OutPoint, TxOut)]) -> Self {
        let mut index = HashMap::with_capacity(prevouts.len());
        for (outpoint, output) in prevouts {
            index.entry(*outpoint).or_insert(output);
        }
        Self { index }
    }
}

impl UtxoView for PrevoutMap<'_> {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        #[cfg(test)]
        bump_prevout_probes(1);
        self.index.get(outpoint).map(|output| (*output).clone())
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
    #[error("a chain change is already active")]
    AlreadyActive,
    #[error("chain generation overflow")]
    Overflow,
    #[error("chain generation changed before finish")]
    GenerationMoved,
    #[error("chain change guard belongs to another gateway")]
    ForeignGuard,
    #[error("mempool delivery queue is full")]
    DeliveryQueueFull,
}

pub struct AdmissionRequest {
    pub tx: Arc<Tx>,
    pub context: crate::standardness::PackageTxContext,
    pub prevouts: Vec<(
        bitcoin_rs_consensus::primitives::OutPoint,
        bitcoin_rs_consensus::primitives::TxOut,
    )>,
    pub prevout_meta: hashbrown::HashMap<OutPoint, crate::PrevoutMeta>,
    pub locktime_cutoff: u32,
    pub csv_active: bool,
    pub next_block_script_flags: VerifyFlags,
    pub max_feerate_sat_per_kvb: Option<u64>,
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
    #[error("chain generation changed before admission")]
    GenerationChanged,
    #[error("mempool sequence changed before admission")]
    MempoolChanged,
    #[error("mempool delivery queue is full")]
    DeliveryQueueFull,
    #[error(transparent)]
    Policy(#[from] crate::standardness::AcceptanceRejectReason),
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
                    | AcceptanceRejectReason::Coinbase
                    | AcceptanceRejectReason::AlreadyInMempool
                    | AcceptanceRejectReason::TooManySigops
            )
        ) {
            return;
        }
        let default_scope = rejection_scope(&request.tx, None);
        let Some(height) = request.height.checked_add(1) else {
            self.reject(AdmitError::Consensus, default_scope);
            return;
        };
        if bitcoin_rs_consensus::verify_tx::verify_transaction_non_script(
            &request.tx,
            &PrevoutMap::new(&self.prevouts),
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
        let default_scope = rejection_scope(&request.tx, None);
        let signature_cache = bitcoin_rs_consensus::script::SignatureCache::new();
        let standard_pass = {
            let chain = PrevoutMap::new(&self.prevouts);
            verify_transaction(
                &request.tx,
                &chain,
                height,
                request.locktime_cutoff,
                VerifyFlags::STANDARD,
                self.engine,
                Some(&signature_cache),
            )
        };
        if let Err(error) = standard_pass {
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
            &PrevoutMap::new(&self.prevouts),
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

fn rejection_scope(
    tx: &Tx,
    reason: Option<crate::standardness::AcceptanceRejectReason>,
) -> RejectScope {
    if matches!(
        reason,
        Some(crate::standardness::AcceptanceRejectReason::NonStandard(
            crate::standardness::StandardnessError::NonStandardInput,
        ))
    ) {
        return RejectScope::Transaction;
    }
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
    fn on_mutation(&self, envelope: &MutationEnvelope);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyInterest {
    Bodies,
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
/// The delivery queue holds at most this many producer envelopes.
/// The drain thread may queue DELIVERY_REENTRANT_ALLOWANCE envelopes past the bound.
pub(crate) const DELIVERY_QUEUE_CAPACITY: usize = 100;
/// The drain thread may queue this many envelopes past the bound.
pub(crate) const DELIVERY_REENTRANT_ALLOWANCE: usize = 8;

std::thread_local! {
    static IN_DRAIN: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

struct PublishState {
    queue: VecDeque<MutationEnvelope>,
    draining: bool,
    reserved: usize,
    waiters: usize,
    high_water: usize,
}

struct DrainScope;

impl DrainScope {
    fn enter() -> Self {
        IN_DRAIN.with(|active| active.set(true));
        Self
    }
}

impl Drop for DrainScope {
    fn drop(&mut self) {
        IN_DRAIN.with(|active| active.set(false));
    }
}

#[cfg(test)]
#[derive(Default)]
struct BeginChainProbes {
    entered: Option<mpsc::Sender<()>>,
    lock_held: Option<BeginLockHold>,
}

#[cfg(test)]
struct BeginLockHold {
    signal: mpsc::Sender<bool>,
    resume: mpsc::Receiver<()>,
    released_probe: Box<dyn Fn() -> bool + Send>,
}

pub struct MempoolGateway {
    pub(crate) pool: Arc<RwLock<Mempool>>,
    pub(crate) lifecycle: Mutex<crate::orphan::AdmissionLifecycle>,
    observer: Option<Arc<CompositeObserver>>,
    commit_order: Mutex<()>,
    publish: Mutex<PublishState>,
    publish_ready: Condvar,
    pub(crate) extra_txn: Mutex<ExtraTxnRing>,
    chain_generation: AtomicU64,
    engine: ValidationEngine,
    script_cache: Option<Arc<ScriptExecutionCache>>,
    #[cfg(test)]
    begin_probes: Mutex<BeginChainProbes>,
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
                reserved: 0,
                waiters: 0,
                high_water: 0,
            }),
            publish_ready: Condvar::new(),
            extra_txn: Mutex::new(ExtraTxnRing::default()),
            chain_generation: AtomicU64::new(0),
            engine,
            script_cache,
            #[cfg(test)]
            begin_probes: Mutex::new(BeginChainProbes::default()),
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

    pub fn read(&self) -> RwLockReadGuard<'_, Mempool> {
        self.pool.read()
    }

    #[must_use]
    pub fn stable_generation(&self) -> Option<u64> {
        let value = self.chain_generation.load(Ordering::Acquire);
        value.is_multiple_of(2).then_some(value)
    }

    pub(crate) fn chain_generation(&self) -> u64 {
        self.chain_generation.load(Ordering::Acquire)
    }

    pub fn begin_chain_change(self: &Arc<Self>) -> Result<ChainChangeGuard, ChainChangeError> {
        #[cfg(test)]
        self.notify_begin_entry();
        let pool_guard = self.pool.write();
        #[cfg(test)]
        self.hold_at_begin_lock();
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

    #[cfg(test)]
    fn notify_begin_entry(&self) {
        if let Some(entered) = self.begin_probes.lock().entered.as_ref() {
            let _ = entered.send(());
        }
    }

    #[cfg(test)]
    fn hold_at_begin_lock(&self) {
        let Some(hold) = self.begin_probes.lock().lock_held.take() else {
            return;
        };
        let released = (hold.released_probe)();
        if hold.signal.send(released).is_err() {
            return;
        }
        let _ = hold.resume.recv();
    }

    #[cfg(test)]
    pub fn install_begin_chain_change_probes(
        &self,
        entered: mpsc::Sender<()>,
        lock_held: mpsc::Sender<bool>,
        resume: mpsc::Receiver<()>,
        released_probe: Box<dyn Fn() -> bool + Send>,
    ) {
        let mut probes = self.begin_probes.lock();
        probes.entered = Some(entered);
        probes.lock_held = Some(BeginLockHold {
            signal: lock_held,
            resume,
            released_probe,
        });
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn insert_entry(
        &self,
        origin: AdmissionOrigin,
        entry: MempoolEntry,
    ) -> Result<MutationResult, MempoolError> {
        // Keep ownership of entry across bounded optimistic retries.
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
                || crate::MempoolError::DeliveryQueueFull,
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
                || crate::RbfError::from(crate::MempoolError::DeliveryQueueFull),
            );
            if !matches!(result, Err(RbfError::StalePlan)) {
                return result;
            }
        }
        Err(RbfError::StalePlan)
    }

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
                let default_reject_scope = rejection_scope(&request.tx, None);

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
            || AdmitError::DeliveryQueueFull,
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

    pub(crate) fn prepare_admission(
        pool: &Mempool,
        request: &AdmissionRequest,
        mode: AdmissionMode,
        fence: crate::admission::AdmissionFence,
        engine: ValidationEngine,
    ) -> PreparedAdmission {
        let policy = pool.policy_snapshot();
        let standard_result =
            crate::standardness::is_standard_tx(&request.tx, &policy.standardness);
        let already_known = pool.contains_txid(&request.tx.txid());
        let oversize = matches!(
            standard_result,
            Err(crate::standardness::StandardnessError::Weight)
        );
        let prevouts: Vec<_> = if already_known || oversize {
            Vec::new()
        } else {
            let chain = PrevoutMap::new(&request.prevouts);
            let view = MempoolUtxoView::new(pool, &chain);
            request
                .tx
                .inputs
                .iter()
                .filter_map(|input| {
                    view.lookup(&input.previous_output)
                        .map(|output| (input.previous_output, output))
                })
                .collect()
        };
        let standard = standard_result.is_ok();
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
            Some(pool.min_fee_sat_per_kvb(bitcoin_rs_consensus::primitives::unix_time_secs()))
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
            &prevouts,
            context,
            None,
            floor,
            &finality,
        );
        let rejection = fact.reject_reason.map(|reason| {
            (
                AdmitError::Policy(reason),
                rejection_scope(&request.tx, Some(reason)),
            )
        });
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
        if !already_known {
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
                    rejection_scope(&request.tx, None),
                );
            }
            if prepared.rejection.is_none() {
                match pool.truc_conflicts(
                    &request.tx,
                    prepared.fact.vsize,
                    crate::truc::SiblingEviction::Forbidden,
                ) {
                    Ok(_) => prepared.replacement = ReplacementStage::Package,
                    Err(error) => {
                        prepared.reject(
                            replacement_rejection(error),
                            rejection_scope(&request.tx, None),
                        );
                    }
                }
            }
        } else if prepared.rejection.is_none() {
            let fee_estimation = crate::rbf::FeeEstimation::from_origin(&request.origin);
            let conflict_set = pool.truc_conflicts(
                &request.tx,
                prepared.fact.vsize,
                crate::truc::SiblingEviction::Allowed,
            );
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
                    prepared.reject(
                        replacement_rejection(error),
                        rejection_scope(&request.tx, None),
                    );
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
                    rejection_scope(&request.tx, None),
                );
            }
        }
        prepared
    }

    pub fn remove_for_reorg(
        &self,
        change: &ChainChangeGuard,
        chain: &dyn crate::admission::AdmissionChain,
        commit_id: u64,
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
                Ok(pool.settle_for_reorg(&failing, commit_id))
            },
            |result| Some(result),
            || ChainChangeError::DeliveryQueueFull,
        )
    }

    pub fn remove_for_block(
        &self,
        origin: AdmissionOrigin,
        facts: &crate::settlement::TransitionFacts,
        height: u32,
        now: u64,
    ) -> Result<MutationResult, MempoolError> {
        self.commit(
            origin,
            |pool| Ok(pool.remove_for_block(facts, height, now)),
            |result| Some(result),
            || MempoolError::DeliveryQueueFull,
        )
    }

    pub fn settle_block_facts(
        &self,
        origin: AdmissionOrigin,
        facts: &crate::settlement::TransitionFacts,
        commit_id: u64,
        height: u32,
        now: u64,
    ) -> Result<MutationResult, MempoolError> {
        self.commit(
            origin,
            |pool| Ok(pool.settle_for_block(facts, commit_id, height, now)),
            |result| Some(result),
            || MempoolError::DeliveryQueueFull,
        )
    }

    #[must_use]
    pub fn settled_at_commit(&self) -> u64 {
        self.pool.read().settled_at_commit()
    }

    #[must_use]
    pub fn settled_generation(&self) -> (u64, u64, u64) {
        self.pool.read().settled_generation()
    }

    pub fn expire(
        &self,
        origin: AdmissionOrigin,
        now: u64,
    ) -> Result<Option<MutationResult>, MempoolError> {
        if !self.pool.read().has_expired_entries(now) {
            return Ok(None);
        }
        Some(self.commit(
            origin,
            |pool| Ok(pool.expire(now)),
            |result| Some(result),
            || MempoolError::DeliveryQueueFull,
        ))
        .transpose()
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn evict_below_fee_rate(
        &self,
        origin: AdmissionOrigin,
        threshold_sat_per_kvb: u64,
    ) -> Result<MutationResult, MempoolError> {
        self.commit(
            origin,
            |pool| Ok(pool.evict_below_fee_rate(threshold_sat_per_kvb)),
            |result| Some(result),
            || MempoolError::DeliveryQueueFull,
        )
    }

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
            || crate::MempoolError::DeliveryQueueFull,
        )
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn clear(&self, origin: AdmissionOrigin) -> Result<MutationResult, MempoolError> {
        self.commit(
            origin,
            |pool| Ok(Mempool::clear(pool)),
            |result| Some(result),
            || MempoolError::DeliveryQueueFull,
        )
    }

    pub fn prioritise(&self, txid: Txid, fee_delta: i64) -> Result<(), PrioritiseError> {
        let mut pool = self.pool.write();
        self.apply_prioritise(&mut pool, txid, fee_delta)
    }

    pub fn mark_broadcast(&self, wtxid: bitcoin_rs_consensus::primitives::Wtxid) {
        self.pool.write().mark_broadcast(wtxid);
    }

    pub fn commit_broadcast(&self, wtxid: bitcoin_rs_consensus::primitives::Wtxid) {
        self.pool.write().commit_broadcast(wtxid);
    }

    pub fn restore_unbroadcast(&self, wtxid: bitcoin_rs_consensus::primitives::Wtxid) {
        self.pool.write().restore_broadcast(wtxid);
    }

    pub(crate) fn set_pending_broadcast(&self, wtxid: bitcoin_rs_consensus::primitives::Wtxid) {
        self.pool.write().set_unbroadcast(wtxid, true);
    }

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

    fn in_drain() -> bool {
        IN_DRAIN.with(|active| active.get())
    }

    fn reserve_delivery(&self) -> bool {
        if self.observer.is_none() || Self::in_drain() {
            return false;
        }
        let mut publish = self.publish.lock();
        publish.waiters += 1;
        while publish.queue.len() + publish.reserved >= DELIVERY_QUEUE_CAPACITY {
            self.publish_ready.wait(&mut publish);
        }
        publish.waiters -= 1;
        publish.reserved += 1;
        true
    }

    fn release_reservation(&self) {
        let mut publish = self.publish.lock();
        publish.reserved -= 1;
        drop(publish);
        self.publish_ready.notify_one();
    }

    fn reentrant_ceiling_reached(&self) -> bool {
        let publish = self.publish.lock();
        publish.queue.len() + publish.reserved
            >= DELIVERY_QUEUE_CAPACITY + DELIVERY_REENTRANT_ALLOWANCE
    }

    fn reentrant_over_ceiling(&self) -> bool {
        self.observer.is_some() && Self::in_drain() && self.reentrant_ceiling_reached()
    }

    pub(crate) fn commit<T, E>(
        &self,
        origin: AdmissionOrigin,
        mutate: impl FnOnce(&mut Mempool) -> Result<T, E>,
        mutation: impl FnOnce(&T) -> Option<&MutationResult>,
        refused: impl FnOnce() -> E,
    ) -> Result<T, E> {
        if self.reentrant_over_ceiling() {
            return Err(refused());
        }
        let bodies_wanted = self
            .observer
            .as_ref()
            .is_some_and(|observer| observer.wants_bodies());
        let reserved = self.reserve_delivery();
        let order = self.commit_order.lock();
        let mut elected = false;
        let mut pending = None;
        let outcome = {
            let mut pool = self.pool.write();
            pool.accepted_capture = bodies_wanted.then(Vec::new);
            let outcome = mutate(&mut pool);
            let captured = pool.accepted_capture.take().unwrap_or_default();
            let outcome = outcome.inspect_err(|_| {
                if reserved {
                    self.release_reservation();
                }
            })?;
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
            if reserved {
                publish.reserved -= 1;
            }
            publish.queue.push_back(MutationEnvelope {
                origin,
                result,
                accepted_transactions: transactions,
            });
            publish.high_water = publish.high_water.max(publish.queue.len());
            elected = !publish.draining;
            publish.draining = true;
        } else if reserved {
            self.release_reservation();
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

    #[must_use]
    pub fn reconstruction_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
        let pool = self.pool.read();
        if let Some(tx) = pool.transaction_by_txid(&txid) {
            return Some((*tx).clone());
        }
        self.extra_txn.lock().by_txid(txid).map(|tx| (**tx).clone())
    }

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

    fn drain(&self) {
        let _scope = DrainScope::enter();
        loop {
            let envelope = {
                let mut publish = self.publish.lock();
                if let Some(envelope) = publish.queue.pop_front() {
                    drop(publish);
                    self.publish_ready.notify_one();
                    envelope
                } else {
                    publish.draining = false;
                    drop(publish);
                    self.publish_ready.notify_one();
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
    #[must_use]
    pub fn publish_high_water(&self) -> usize {
        self.publish.lock().high_water
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn publish_len(&self) -> usize {
        self.publish.lock().queue.len()
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn publish_waiters(&self) -> usize {
        self.publish.lock().waiters
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn force_chain_generation(&self, value: u64) {
        self.chain_generation.store(value, Ordering::Release);
    }
}

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
        let _receiver_gone = parked_tx.send(());
        let _sender_gone = release_rx.recv();
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
mod tests {
    use super::{
        AdmissionMode, AdmissionRequest, AdmitError, AdmitOutcome, BLOCK_RECONSTRUCTION_EXTRA_TXN,
        BodyInterest, ChainChangeError, CompositeObserver, DELIVERY_QUEUE_CAPACITY,
        DELIVERY_REENTRANT_ALLOWANCE, ExtraTxnRing, MempoolGateway, MempoolObserver,
        ValidationEngine,
    };
    use crate::mutation::{AdmissionOrigin, MutationEnvelope, MutationOutcome, RemovalReason};
    use crate::orphan::RejectScope;
    use crate::standardness::PackageTxContext;
    use crate::test_fixtures::{p2sh_true_script, true_redeem_script_sig};
    use crate::{Mempool, MempoolEntry, MempoolLimits};
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use core::sync::atomic::{AtomicBool, Ordering};
    use parking_lot::{Mutex, RwLock};
    use std::sync::mpsc;

    #[derive(Default)]
    struct CounterKeyRecorder {
        keys: Mutex<Vec<(String, usize)>>,
    }

    impl metrics::Recorder for CounterKeyRecorder {
        fn describe_counter(
            &self,
            _key: metrics::KeyName,
            _unit: Option<metrics::Unit>,
            _description: metrics::SharedString,
        ) {
        }

        fn describe_gauge(
            &self,
            _key: metrics::KeyName,
            _unit: Option<metrics::Unit>,
            _description: metrics::SharedString,
        ) {
        }

        fn describe_histogram(
            &self,
            _key: metrics::KeyName,
            _unit: Option<metrics::Unit>,
            _description: metrics::SharedString,
        ) {
        }

        fn register_counter(
            &self,
            key: &metrics::Key,
            _metadata: &metrics::Metadata<'_>,
        ) -> metrics::Counter {
            self.keys
                .lock()
                .push((key.name().to_owned(), key.labels().count()));
            metrics::Counter::noop()
        }

        fn register_gauge(
            &self,
            _key: &metrics::Key,
            _metadata: &metrics::Metadata<'_>,
        ) -> metrics::Gauge {
            metrics::Gauge::noop()
        }

        fn register_histogram(
            &self,
            _key: &metrics::Key,
            _metadata: &metrics::Metadata<'_>,
        ) -> metrics::Histogram {
            metrics::Histogram::noop()
        }
    }

    fn unit() -> u64 {
        crate::pool::entry_memory_usage(&tx(1))
    }

    fn tx(label: u8) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x51, label].into(),
            }],
        }
    }

    fn entry(tx: &Tx) -> MempoolEntry {
        MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 7, 0)
    }

    fn hash(txid: &Txid) -> Hash256 {
        Hash256::from_le_bytes(txid.as_bytes())
    }

    #[derive(Default)]
    struct RecordingObserver {
        seen: Mutex<Vec<(Hash256, MutationOutcome)>>,
        origins: Mutex<Vec<AdmissionOrigin>>,
    }

    impl MempoolObserver for RecordingObserver {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            self.origins.lock().push(envelope.origin);
            let mut seen = self.seen.lock();
            for change in &envelope.result.changes {
                seen.push((change.txid, change.outcome));
            }
        }
    }

    #[derive(Default)]
    struct PayloadObserver(Mutex<Vec<MutationEnvelope>>);

    impl MempoolObserver for PayloadObserver {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            self.0.lock().push(envelope.clone());
        }
    }

    #[test]
    fn package_expiry_preserves_same_batch_accepted_bodies_and_indices()
    -> Result<(), crate::test_error::TestError> {
        let observer = Arc::new(PayloadObserver::default());
        let gateway = gateway_with_bodies(observer.clone());
        let expired = tx(181);
        let surviving = tx(182);
        let expired_entry = entry(&expired);
        let expired_body = Arc::clone(&expired_entry.tx);
        let mut surviving_entry = entry(&surviving);
        surviving_entry.time = crate::policy::MEMPOOL_EXPIRY_SECS + 2;
        let surviving_body = Arc::clone(&surviving_entry.tx);
        let plan = gateway
            .read()
            .prepare_package(vec![expired_entry, surviving_entry], 1)?;
        let result = gateway.commit(
            AdmissionOrigin::Rpc,
            |pool| pool.commit_package(plan),
            |result| Some(result),
            || crate::MempoolError::DeliveryQueueFull,
        )?;
        assert_eq!(result.changes.len(), 3);
        assert_eq!(result.changes[0].outcome, MutationOutcome::Accepted);
        assert_eq!(result.changes[1].outcome, MutationOutcome::Accepted);
        assert_eq!(
            result.changes[2].outcome,
            MutationOutcome::Removed(RemovalReason::Expiry)
        );
        assert_eq!(result.changes[2].txid, hash(&expired.txid()));
        assert!(gateway.read().entry_by_txid(&expired.txid()).is_none());
        assert_eq!(gateway.read().len(), 1);
        assert!(gateway.pool.read().accepted_capture.is_none());
        let envelopes = observer.0.lock();
        assert_eq!(envelopes.len(), 1);
        let envelope = &envelopes[0];
        assert_eq!(envelope.result, result);
        assert_eq!(envelope.accepted_transactions.len(), 2);
        for ((index, body), expected) in envelope
            .accepted_transactions
            .iter()
            .zip([&expired_body, &surviving_body])
        {
            assert!(
                Arc::ptr_eq(body, expected),
                "retain the admitted allocation"
            );
            assert_eq!(hash(&body.txid()), envelope.result.changes[*index].txid);
            assert_eq!(
                envelope.result.changes[*index].outcome,
                MutationOutcome::Accepted
            );
        }
        assert_eq!(envelope.accepted_transactions[0].0, 0);
        assert_eq!(envelope.accepted_transactions[1].0, 1);
        Ok(())
    }

    #[test]
    fn failed_mutation_clears_capture_scope_before_the_next_success()
    -> Result<(), crate::test_error::TestError> {
        let observer = Arc::new(PayloadObserver::default());
        let gateway = gateway_with_bodies(observer.clone());
        let stale = Arc::new(tx(183));
        let mut capture_enabled = false;
        let failure: Result<crate::MutationResult, ()> = gateway.commit(
            AdmissionOrigin::Rpc,
            |pool| {
                let capture = pool.accepted_capture.as_mut().ok_or(())?;
                capture_enabled = true;
                capture.push((stale.txid(), Arc::clone(&stale)));
                Err(())
            },
            |result| Some(result),
            || (),
        );
        assert!(capture_enabled);
        assert!(failure.is_err());
        assert!(gateway.pool.read().accepted_capture.is_none());
        assert!(observer.0.lock().is_empty());
        assert_eq!(gateway.read().len(), 0);
        let next = tx(184);
        gateway.insert_entry(AdmissionOrigin::Rpc, entry(&next))?;
        let envelopes = observer.0.lock();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].accepted_transactions.len(), 1);
        let (index, body) = &envelopes[0].accepted_transactions[0];
        assert_eq!(*index, 0);
        assert_eq!(body.txid(), next.txid());
        assert!(!Arc::ptr_eq(body, &stale));
        assert!(gateway.pool.read().accepted_capture.is_none());
        Ok(())
    }

    struct LockOrderObserver {
        pool: Arc<RwLock<Mempool>>,
        saw_write_locked: std::sync::atomic::AtomicBool,
        retained: Mutex<Vec<usize>>,
    }

    impl MempoolObserver for LockOrderObserver {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            if self.pool.is_locked_exclusive() {
                self.saw_write_locked.store(true, Ordering::SeqCst);
            }
            self.retained
                .lock()
                .push(envelope.accepted_transactions.len());
        }
    }

    // MPL-01
    #[test]
    fn commit_runs_no_observer_code_under_the_pool_write_lock()
    -> Result<(), crate::test_error::TestError> {
        let composite = CompositeObserver::new();
        assert!(!composite.wants_bodies());
        let metadata = Arc::new(RecordingObserver::default());
        composite.add_leg("metadata", dyn_observer(&metadata), BodyInterest::Metadata);
        assert!(!composite.wants_bodies());
        let bodies = Arc::new(RecordingObserver::default());
        composite.add_leg("bodies", dyn_observer(&bodies), BodyInterest::Bodies);
        assert!(composite.wants_bodies());

        for interest in [BodyInterest::Metadata, BodyInterest::Bodies] {
            let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
            let probe = Arc::new(LockOrderObserver {
                pool: Arc::clone(&pool),
                saw_write_locked: std::sync::atomic::AtomicBool::new(false),
                retained: Mutex::new(Vec::new()),
            });
            let gateway = MempoolGateway::new(
                pool,
                Some((dyn_observer(&probe), interest)),
                ValidationEngine::Native,
                None,
            );
            gateway.insert_entry(AdmissionOrigin::Rpc, entry(&tx(91)))?;
            assert!(
                !probe.saw_write_locked.load(Ordering::SeqCst),
                "no observer code may run under the pool write lock"
            );
            assert_eq!(
                *probe.retained.lock(),
                vec![usize::from(interest == BodyInterest::Bodies)],
                "retention follows the registration-time interest"
            );
        }
        Ok(())
    }

    struct PanickingObserver;

    impl MempoolObserver for PanickingObserver {
        fn on_mutation(&self, _envelope: &MutationEnvelope) {
            panic!("observer exploded");
        }
    }

    fn gateway_with(observer: Option<Arc<dyn MempoolObserver>>) -> Arc<MempoolGateway> {
        Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            observer.map(|observer| (observer, BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        ))
    }

    fn gateway_with_bodies(observer: Arc<dyn MempoolObserver>) -> Arc<MempoolGateway> {
        Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Some((observer, BodyInterest::Bodies)),
            ValidationEngine::Native,
            None,
        ))
    }

    fn dyn_observer<T: MempoolObserver + 'static>(observer: &Arc<T>) -> Arc<dyn MempoolObserver> {
        observer.clone()
    }

    fn removed(reason: RemovalReason) -> MutationOutcome {
        MutationOutcome::Removed(reason)
    }

    fn standard_tx(label: u8) -> Tx {
        let mut script = Vec::with_capacity(25);
        script.push(0x76);
        script.push(0xa9);
        script.push(0x14);
        script.extend_from_slice(&[label; 20]);
        script.push(0x88);
        script.push(0xac);
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
                script_sig: Script::from_bytes(true_redeem_script_sig()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: script.into(),
            }],
        }
    }

    fn p2pkh_prevout_script() -> Vec<u8> {
        [vec![0x76, 0xa9, 0x14], vec![0x2b; 20], vec![0x88, 0xac]].concat()
    }

    fn prevout_spend(prev: OutPoint, value: u64, script: u8) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: prev,
                script_sig: Script::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: vec![script].into(),
            }],
        }
    }

    fn admit_request(
        gateway: &MempoolGateway,
        tx: &Tx,
        origin: AdmissionOrigin,
    ) -> AdmissionRequest {
        let generation = gateway
            .stable_generation()
            .expect("generation is even in test setup");
        let sequence = gateway.read().sequence_number();
        AdmissionRequest {
            tx: Arc::new(tx.clone()),
            context: PackageTxContext {
                fee: 1_000,
                vsize: 100,
                sigop_cost: 0,
                missing_inputs: false,
            },
            prevouts: vec![(
                tx.inputs[0].previous_output,
                TxOut {
                    value: Amount::from_sat(11_000),
                    script_pubkey: Script::from_bytes(p2sh_true_script()),
                },
            )],
            prevout_meta: hashbrown::HashMap::new(),
            csv_active: false,
            next_block_script_flags: bitcoin_rs_consensus::script::VerifyFlags::STANDARD,
            locktime_cutoff: 0,
            max_feerate_sat_per_kvb: None,
            time: 1,
            height: 1,
            origin,
            expected_generation: generation,
            expected_sequence: sequence,
        }
    }

    // MPS-04
    #[test]
    fn accepted_and_block_inclusion_events_arrive_in_commit_order() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));

        let parent = tx(1);
        let parent_txid = parent.txid();
        let mut child = tx(2);
        child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&parent))
            .expect("parent in");
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&child))
            .expect("child in");
        gateway
            .remove_for_block(
                AdmissionOrigin::Rpc,
                &crate::settlement::TransitionFacts::from_txs(&[&parent]),
                8,
                1,
            )
            .expect("block settlement commits");

        let seen = observer.seen.lock();
        assert_eq!(
            *seen,
            vec![
                (hash(&parent_txid), MutationOutcome::Accepted),
                (hash(&child.txid()), MutationOutcome::Accepted),
                (hash(&parent_txid), removed(RemovalReason::BlockInclusion)),
            ],
            "one event per change, in commit order"
        );
        drop(seen);
        assert_eq!(
            *observer.origins.lock(),
            vec![
                AdmissionOrigin::Rpc,
                AdmissionOrigin::Rpc,
                AdmissionOrigin::Rpc
            ],
            "commit must publish the origin that entered the mutation"
        );
    }

    #[test]
    fn remove_for_block_leaves_unmined_child_and_publishes_only_the_parent() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));

        let parent = tx(15);
        let parent_txid = parent.txid();
        let mut child = tx(16);
        child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
        let child_txid = child.txid();
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&parent))
            .expect("parent in");
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&child))
            .expect("child in");
        observer.seen.lock().clear();

        let result = gateway
            .remove_for_block(
                AdmissionOrigin::Rpc,
                &crate::settlement::TransitionFacts::from_txs(&[&parent]),
                8,
                1,
            )
            .expect("block settlement commits");

        assert_eq!(result.changes.len(), 1);
        assert_eq!(
            *observer.seen.lock(),
            vec![(hash(&parent_txid), removed(RemovalReason::BlockInclusion))]
        );
        assert!(gateway.read().contains_txid(&child_txid));
        assert_eq!(gateway.read().len(), 1);
    }

    #[test]
    fn failed_insert_and_noop_remove_publish_nothing() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));
        let before = gateway.read().sequence_number();

        let poor = MempoolEntry::new(Arc::new(tx(4)), 100, 50, 1, 7, 0);
        assert!(gateway.insert_entry(AdmissionOrigin::Rpc, poor).is_err());
        let stranger = tx(5);
        gateway
            .remove_for_block(
                AdmissionOrigin::Rpc,
                &crate::settlement::TransitionFacts::from_txs(&[&stranger]),
                8,
                1,
            )
            .expect("block settlement commits");
        gateway.clear(AdmissionOrigin::Rpc).expect("clear commits");

        assert!(observer.seen.lock().is_empty());
        assert_eq!(
            gateway.read().sequence_number(),
            before,
            "no change may move the sequence"
        );
    }

    #[test]
    fn replacement_tags_direct_conflicts_and_descendants() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));

        let parent = tx(6);
        let parent_txid = parent.txid();
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&parent))
            .expect("parent in");
        let mut child = tx(7);
        child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
        child.inputs[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
        let child_txid = child.txid();
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&child))
            .expect("child in");
        let mut grandchild = tx(8);
        grandchild.inputs[0].previous_output = OutPoint::new(child_txid, 0);
        grandchild.inputs[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
        let grandchild_txid = grandchild.txid();
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&grandchild))
            .expect("grandchild in");
        observer.seen.lock().clear();

        let mut replacement = tx(9);
        replacement.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
        replacement.inputs[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
        let replacement_txid = replacement.txid();
        let result = gateway
            .replace_transaction(
                AdmissionOrigin::Rpc,
                &crate::ReplacementCandidate::new(Arc::new(replacement), 100, 5_000, 1),
                1,
                7,
            )
            .expect("replacement lands");

        assert_eq!(result.changes.len(), 3);
        assert_eq!(
            result.changes,
            vec![
                crate::mutation::change(&child_txid, removed(RemovalReason::Replaced)),
                crate::mutation::change(&grandchild_txid, removed(RemovalReason::Descendant),),
                crate::mutation::change(&replacement_txid, MutationOutcome::Accepted),
            ],
            "conflicts first (parent before descendant), then the replacement"
        );
        let seen = observer.seen.lock();
        assert_eq!(
            &*seen,
            &result
                .changes
                .iter()
                .map(|c| (c.txid, c.outcome))
                .collect::<Vec<_>>()
        );
    }

    // MPS-04
    #[test]
    fn observer_panic_does_not_roll_back_the_mutation() {
        let gateway = gateway_with(Some(Arc::new(PanickingObserver)));

        let committed = tx(9);
        let committed_txid = committed.txid();
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&committed))
            .expect("still returns");

        assert!(
            gateway.read().contains_txid(&committed_txid),
            "the mutation stands after the observer panicked"
        );
    }

    #[test]
    fn no_observer_still_mutates() {
        let gateway = gateway_with(None);
        let result = gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&tx(10)))
            .expect("in");
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.sequence_base, 1);
        assert_eq!(gateway.read().sequence_number(), 1);
    }

    // MPL-02
    #[test]
    fn sequence_base_matches_per_change_assignment() {
        let gateway = gateway_with(None);
        let parent = tx(11);
        let parent_txid = parent.txid();
        let mut child = tx(12);
        child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&parent))
            .expect("in");
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&child))
            .expect("in");
        let removed = gateway
            .remove_for_block(
                AdmissionOrigin::Rpc,
                &crate::settlement::TransitionFacts::from_txs(&[&parent]),
                8,
                1,
            )
            .expect("block settlement commits");

        assert_eq!(removed.changes.len(), 1);
        assert_eq!(removed.sequence_base, 3);
        assert_eq!(removed.sequence_of(0), Some(3));
        assert_eq!(gateway.read().sequence_number(), 3);
    }

    #[test]
    fn insert_reports_accepted_then_policy_evictions() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                max_total_bytes: unit() * 3 / 2,
                ..MempoolLimits::default()
            }))),
            Some((dyn_observer(&observer), BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        );

        let low = MempoolEntry::new(Arc::new(tx(13)), 100, 100, 1, 7, 0);
        let high = MempoolEntry::new(Arc::new(tx(14)), 100, 900, 1, 7, 0);
        gateway
            .insert_entry(AdmissionOrigin::Rpc, low)
            .expect("low in");
        let result = gateway
            .insert_entry(AdmissionOrigin::Rpc, high)
            .expect("high in");

        assert_eq!(
            result.changes.len(),
            2,
            "the eviction is part of the insert"
        );
        assert_eq!(result.changes[0].outcome, MutationOutcome::Accepted);
        assert_eq!(result.changes[0].txid, hash(&tx(14).txid()));
        assert_eq!(
            result.changes[1].outcome,
            MutationOutcome::Removed(RemovalReason::PolicyEviction)
        );
        assert_eq!(result.changes[1].txid, hash(&tx(13).txid()));
        assert_eq!(result.sequence_base, 2);
        assert_eq!(result.sequence_of(1), Some(3));
        assert!(
            observer.seen.lock().ends_with(
                &result
                    .changes
                    .iter()
                    .map(|change| (change.txid, change.outcome))
                    .collect::<Vec<_>>()
            )
        );
    }

    #[test]
    fn clear_reports_every_entry_and_empty_clear_moves_nothing() {
        let gateway = gateway_with(None);
        let first = tx(15);
        let second = tx(16);
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&first))
            .expect("in");
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&second))
            .expect("in");
        let before = gateway.read().sequence_number();

        let cleared = gateway.clear(AdmissionOrigin::Rpc).expect("clear commits");
        assert_eq!(cleared.changes.len(), 2);
        assert!(
            cleared
                .changes
                .iter()
                .all(|change| { change.outcome == MutationOutcome::Removed(RemovalReason::Clear) })
        );
        assert_eq!(cleared.sequence_base, before + 1);
        assert_eq!(gateway.read().sequence_number(), before + 2);

        let empty = gateway.clear(AdmissionOrigin::Rpc).expect("clear commits");
        assert!(empty.is_empty());
        assert_eq!(empty.sequence_base, 0);
        assert_eq!(
            gateway.read().sequence_number(),
            before + 2,
            "clear-on-empty assigns nothing"
        );
    }

    struct GatedObserver {
        entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
        stream: Mutex<Vec<u64>>,
    }

    impl MempoolObserver for GatedObserver {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            let result = &envelope.result;
            let mut stream = self.stream.lock();
            let first_call = stream.is_empty();
            for index in 0..result.len() {
                stream.push(result.sequence_of(index).unwrap_or(u64::MAX));
            }
            drop(stream);
            if first_call {
                self.entered
                    .lock()
                    .take()
                    .expect("entered sender armed once")
                    .send(())
                    .expect("main thread still waiting");
                self.release
                    .lock()
                    .take()
                    .expect("release receiver armed once")
                    .recv()
                    .expect("main thread still alive to release us");
            }
        }
    }

    #[test]
    fn gated_callback_lets_concurrent_mutation_enqueue_and_return() {
        for (first_admission, second_admission) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let observer = Arc::new(GatedObserver {
                entered: Mutex::new(Some(entered_tx)),
                release: Mutex::new(Some(release_rx)),
                stream: Mutex::new(Vec::new()),
            });
            let gateway = gateway_with(Some(dyn_observer(&observer)));

            let first_tx = if first_admission {
                standard_tx(20)
            } else {
                tx(20)
            };
            let first_txid = first_tx.txid();
            let first = Arc::clone(&gateway);
            let first_handle =
                std::thread::spawn(move || commit_ordering_tx(&first, &first_tx, first_admission));
            entered_rx
                .recv_timeout(core::time::Duration::from_secs(10))
                .expect("first observer call started");

            let second_tx = if second_admission {
                standard_tx(21)
            } else {
                tx(21)
            };
            let second_txid = second_tx.txid();
            let second = Arc::clone(&gateway);
            let second_handle = std::thread::spawn(move || {
                let result = commit_ordering_tx(&second, &second_tx, second_admission);
                let _ = done_tx.send(result);
            });

            let queued_result = done_rx
                .recv_timeout(core::time::Duration::from_secs(10))
                .expect("the concurrent mutation must return while the callback is gated");
            assert_eq!(
                queued_result.sequence_base, 2,
                "the enqueued batch keeps its committed sequence"
            );

            assert_eq!(
                observer.stream.lock().len(),
                1,
                "only the gated first batch is published so far"
            );

            release_tx.send(()).expect("gate thread alive");
            first_handle.join().expect("first publisher");
            second_handle.join().expect("second publisher");

            assert_eq!(
                *observer.stream.lock(),
                vec![1, 2],
                "publish order matches sequence order"
            );
            let pool_read = gateway.read();
            assert!(pool_read.contains_txid(&first_txid));
            assert!(pool_read.contains_txid(&second_txid));
        }
    }

    fn commit_ordering_tx(
        gateway: &MempoolGateway,
        tx: &Tx,
        admission: bool,
    ) -> crate::mutation::MutationResult {
        if !admission {
            return gateway
                .insert_entry(AdmissionOrigin::Rpc, entry(tx))
                .expect("inserted");
        }
        let outcome = gateway.admit_transaction(admit_request(gateway, tx, AdmissionOrigin::Rpc));
        let Ok(AdmitOutcome::Committed(result)) = outcome else {
            panic!("admission did not commit: {outcome:?}");
        };
        result
    }

    struct ReentrantObserver {
        gateway: Mutex<Option<Arc<MempoolGateway>>>,
        stream: Mutex<Vec<u64>>,
        nested: Mutex<Vec<crate::mutation::MutationResult>>,
    }

    impl MempoolObserver for ReentrantObserver {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            let result = &envelope.result;
            {
                let mut stream = self.stream.lock();
                for index in 0..result.len() {
                    stream.push(result.sequence_of(index).unwrap_or(u64::MAX));
                }
            }
            if result.sequence_base == 1 {
                let gateway = self.gateway.lock().clone();
                if let Some(gateway) = gateway {
                    let nested = gateway
                        .insert_entry(AdmissionOrigin::Rpc, entry(&tx(99)))
                        .expect("nested in");
                    self.nested.lock().push(nested);
                }
            }
        }
    }

    // MPL-01, MPS-04
    #[test]
    fn reentrant_observer_mutation_completes_with_callback_sequence_1_2() {
        let observer = Arc::new(ReentrantObserver {
            gateway: Mutex::new(None),
            stream: Mutex::new(Vec::new()),
            nested: Mutex::new(Vec::new()),
        });
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Some((dyn_observer(&observer), BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        ));
        *observer.gateway.lock() = Some(Arc::clone(&gateway));

        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&tx(50)))
            .expect("first in");

        let nested = observer.nested.lock();
        assert_eq!(
            nested.len(),
            1,
            "the nested mutation completed and returned"
        );
        let nested = nested.first().cloned();
        let Some(nested) = nested else {
            panic!("nested mutation must be recorded");
        };
        assert_eq!(
            nested.sequence_base, 2,
            "the nested mutation took the next sequence"
        );
        assert_eq!(nested.len(), 1);
        assert_eq!(
            *observer.stream.lock(),
            vec![1, 2],
            "callbacks run exactly once per batch, in sequence order"
        );
    }

    fn insert_contended(gateway: &MempoolGateway, transaction: &Tx) {
        let deadline = std::time::Instant::now() + core::time::Duration::from_secs(10);
        loop {
            match gateway.insert_entry(AdmissionOrigin::Rpc, entry(transaction)) {
                Ok(_) => return,
                Err(crate::MempoolError::StalePolicy) if std::time::Instant::now() < deadline => {
                    std::thread::yield_now();
                }
                other => panic!("concurrent admission did not settle: {other:?}"),
            }
        }
    }

    struct ContiguityObserver {
        gateway: Mutex<Option<Arc<MempoolGateway>>>,
        stream: Mutex<Vec<u64>>,
        nested_vout: std::sync::atomic::AtomicU32,
    }

    fn nested_tx(vout: u32) -> Tx {
        let mut nested = tx(5);
        nested.inputs[0].previous_output =
            OutPoint::new(Txid(Hash256::from_le_bytes(&[5; 32])), vout);
        nested
    }

    impl MempoolObserver for ContiguityObserver {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            let result = &envelope.result;
            {
                let mut stream = self.stream.lock();
                for index in 0..result.len() {
                    stream.push(result.sequence_of(index).unwrap_or(u64::MAX));
                }
            }
            if result.sequence_base % 16 == 1 {
                let gateway = self.gateway.lock().clone();
                if let Some(gateway) = gateway {
                    let vout = self
                        .nested_vout
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    insert_contended(&gateway, &nested_tx(vout));
                }
            }
        }
    }

    #[test]
    fn concurrent_reentrant_stream_is_contiguous() {
        const CYCLES: usize = 60;
        const THREAD_BASES: [u8; 4] = [10, 70, 130, 190];
        let observer = Arc::new(ContiguityObserver {
            gateway: Mutex::new(None),
            stream: Mutex::new(Vec::new()),
            nested_vout: std::sync::atomic::AtomicU32::new(0),
        });
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Some((dyn_observer(&observer), BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        ));
        *observer.gateway.lock() = Some(Arc::clone(&gateway));

        let handles: Vec<_> = THREAD_BASES
            .iter()
            .map(|&base| {
                let gateway = Arc::clone(&gateway);
                std::thread::spawn(move || {
                    for cycle in 0..CYCLES {
                        let label = base + u8::try_from(cycle).expect("label fits in u8");
                        insert_contended(&gateway, &tx(label));
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("mutator thread");
        }

        let deadline = std::time::Instant::now() + core::time::Duration::from_secs(10);
        loop {
            let sequence = gateway.read().sequence_number();
            let published = u64::try_from(observer.stream.lock().len()).expect("length fits u64");
            if published == sequence {
                std::thread::sleep(core::time::Duration::from_millis(20));
                if u64::try_from(observer.stream.lock().len()).expect("length fits u64") == sequence
                {
                    break;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "publication never settled: {published} of {sequence} batches published"
            );
            std::thread::sleep(core::time::Duration::from_millis(1));
        }

        let stream = observer.stream.lock();
        let expected: Vec<u64> =
            (1..=u64::try_from(stream.len()).expect("length fits u64")).collect();
        assert_eq!(
            *stream, expected,
            "the published stream must be exactly the contiguous sequence range"
        );
        assert_eq!(
            u64::try_from(stream.len()).expect("length fits u64"),
            gateway.read().sequence_number(),
            "every committed change was published exactly once"
        );
    }

    fn backpressure_tx(thread: u8, index: u32) -> Tx {
        let mut bytes = [thread; 32];
        bytes[0..4].copy_from_slice(&index.to_le_bytes());
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x51, thread].into(),
            }],
        }
    }

    struct BackpressureObserver {
        entered: Mutex<Option<mpsc::Sender<()>>>,
        release: Mutex<Option<mpsc::Receiver<()>>>,
        stream: Mutex<Vec<u64>>,
    }

    impl MempoolObserver for BackpressureObserver {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            let result = &envelope.result;
            let first = {
                let mut stream = self.stream.lock();
                let first = stream.is_empty();
                for index in 0..result.len() {
                    stream.push(result.sequence_of(index).unwrap_or(u64::MAX));
                }
                first
            };
            std::thread::sleep(core::time::Duration::from_millis(1));
            if first {
                let Some(entered) = self.entered.lock().take() else {
                    return;
                };
                if entered.send(()).is_err() {
                    return;
                }
                let Some(release) = self.release.lock().take() else {
                    return;
                };
                let _ = release.recv();
            }
        }
    }

    fn wait_for_publication_settle(
        gateway: &MempoolGateway,
        stream: &Mutex<Vec<u64>>,
    ) -> Result<(), crate::test_error::TestError> {
        let deadline = std::time::Instant::now() + core::time::Duration::from_secs(10);
        loop {
            let sequence = gateway.read().sequence_number();
            let published = u64::try_from(stream.lock().len())?;
            if published == sequence {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "publication never settled: {published} of {sequence} batches published"
            );
            std::thread::yield_now();
        }
        Ok(())
    }

    // MPS-04
    #[test]
    fn bounded_delivery_queue_never_exceeds_capacity_and_keeps_sequence_order()
    -> Result<(), crate::test_error::TestError> {
        const PRODUCERS: usize = 8;
        const PER_PRODUCER: u32 = 40;
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let observer = Arc::new(BackpressureObserver {
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(Some(release_rx)),
            stream: Mutex::new(Vec::new()),
        });
        let gateway = Arc::new(gateway_with(Some(dyn_observer(&observer))));
        let first = Arc::clone(&gateway);
        let first_handle =
            std::thread::spawn(move || insert_contended(&first, &backpressure_tx(200, 0)));
        entered_rx.recv_timeout(core::time::Duration::from_secs(10))?;
        let mut done_rxs = Vec::with_capacity(PRODUCERS);
        for producer in 0..PRODUCERS {
            let (done_tx, done_rx) = mpsc::channel();
            done_rxs.push(done_rx);
            let gateway = Arc::clone(&gateway);
            let label = u8::try_from(producer)? + 10;
            std::thread::spawn(move || {
                for index in 0..PER_PRODUCER {
                    insert_contended(&gateway, &backpressure_tx(label, index));
                }
                let _ = done_tx.send(());
            });
        }
        let deadline = std::time::Instant::now() + core::time::Duration::from_secs(10);
        let mut saw_backpressure = false;
        while std::time::Instant::now() < deadline {
            if gateway.publish_waiters() > 0 {
                saw_backpressure = true;
                break;
            }
            std::thread::yield_now();
        }
        assert!(
            saw_backpressure,
            "a producer must block on the full delivery queue"
        );
        release_tx.send(())?;
        for done in done_rxs {
            done.recv_timeout(core::time::Duration::from_secs(30))?;
        }
        let Ok(()) = first_handle.join() else {
            return Err("first publisher panicked".into());
        };
        wait_for_publication_settle(&gateway, &observer.stream)?;
        assert!(
            gateway.publish_high_water() <= DELIVERY_QUEUE_CAPACITY,
            "the queue length never exceeds the bound"
        );
        let total = 1 + u64::try_from(PRODUCERS)? * u64::from(PER_PRODUCER);
        let expected: Vec<u64> = (1..=total).collect();
        assert_eq!(
            *observer.stream.lock(),
            expected,
            "every event arrives exactly once in sequence order"
        );
        Ok(())
    }

    struct FullQueueReentrantObserver {
        gateway: Mutex<Option<Arc<MempoolGateway>>>,
        entered: Mutex<Option<mpsc::Sender<()>>>,
        release: Mutex<Option<mpsc::Receiver<()>>>,
        stream: Mutex<Vec<u64>>,
        nested: Mutex<Vec<crate::mutation::MutationResult>>,
    }

    impl MempoolObserver for FullQueueReentrantObserver {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            let result = &envelope.result;
            {
                let mut stream = self.stream.lock();
                for index in 0..result.len() {
                    stream.push(result.sequence_of(index).unwrap_or(u64::MAX));
                }
            }
            if result.sequence_base == 1 {
                let Some(entered) = self.entered.lock().take() else {
                    return;
                };
                if entered.send(()).is_err() {
                    return;
                }
                let Some(release) = self.release.lock().take() else {
                    return;
                };
                if release.recv().is_err() {
                    return;
                }
                let gateway = self.gateway.lock().clone();
                if let Some(gateway) = gateway {
                    let Ok(nested) =
                        gateway.insert_entry(AdmissionOrigin::Rpc, entry(&backpressure_tx(99, 0)))
                    else {
                        return;
                    };
                    self.nested.lock().push(nested);
                }
            }
        }
    }

    // MPS-04
    #[test]
    fn reentrant_mutation_completes_when_the_delivery_queue_is_full()
    -> Result<(), crate::test_error::TestError> {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let observer = Arc::new(FullQueueReentrantObserver {
            gateway: Mutex::new(None),
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(Some(release_rx)),
            stream: Mutex::new(Vec::new()),
            nested: Mutex::new(Vec::new()),
        });
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Some((dyn_observer(&observer), BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        ));
        *observer.gateway.lock() = Some(Arc::clone(&gateway));
        let first = Arc::clone(&gateway);
        let first_handle =
            std::thread::spawn(move || insert_contended(&first, &backpressure_tx(200, 0)));
        entered_rx.recv_timeout(core::time::Duration::from_secs(10))?;
        let flood = u32::try_from(DELIVERY_QUEUE_CAPACITY)? - 1;
        for index in 0..flood {
            insert_contended(&gateway, &backpressure_tx(10, index));
        }
        let (room_tx, room_rx) = mpsc::channel();
        let room = Arc::clone(&gateway);
        let room_handle = std::thread::spawn(move || {
            insert_contended(&room, &backpressure_tx(11, 0));
            let _ = room_tx.send(());
        });
        let deadline = std::time::Instant::now() + core::time::Duration::from_secs(10);
        while gateway.publish_len() != DELIVERY_QUEUE_CAPACITY {
            assert!(
                std::time::Instant::now() < deadline,
                "the delivery queue never filled"
            );
            std::thread::yield_now();
        }
        room_rx.recv_timeout(core::time::Duration::from_secs(10))?;
        let (blocked_tx, blocked_rx) = mpsc::channel();
        let blocked = Arc::clone(&gateway);
        let blocked_handle = std::thread::spawn(move || {
            insert_contended(&blocked, &backpressure_tx(12, 0));
            let _ = blocked_tx.send(());
        });
        let deadline = std::time::Instant::now() + core::time::Duration::from_secs(10);
        while gateway.publish_waiters() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "a producer must block on the full delivery queue"
            );
            std::thread::yield_now();
        }
        release_tx.send(())?;
        blocked_rx.recv_timeout(core::time::Duration::from_secs(20))?;
        let Ok(()) = room_handle.join() else {
            return Err("room producer panicked".into());
        };
        let Ok(()) = blocked_handle.join() else {
            return Err("blocked producer panicked".into());
        };
        let Ok(()) = first_handle.join() else {
            return Err("first publisher panicked".into());
        };
        wait_for_publication_settle(&gateway, &observer.stream)?;
        assert_eq!(
            gateway.publish_high_water(),
            DELIVERY_QUEUE_CAPACITY + 1,
            "only the reentrant envelope queues past the bound"
        );
        let nested = observer.nested.lock();
        assert_eq!(
            nested.len(),
            1,
            "the nested mutation completed and returned"
        );
        let capacity = u64::try_from(DELIVERY_QUEUE_CAPACITY)?;
        assert_eq!(
            nested.first().ok_or("nested recorded")?.sequence_base,
            capacity + 2,
            "the nested mutation took the next sequence past the full queue"
        );
        let expected: Vec<u64> = (1..=(capacity + 3)).collect();
        assert_eq!(
            *observer.stream.lock(),
            expected,
            "every event arrives exactly once in sequence order"
        );
        Ok(())
    }

    struct CeilingObserver {
        gateway: Mutex<Option<Arc<MempoolGateway>>>,
        entered: Mutex<Option<mpsc::Sender<()>>>,
        release: Mutex<Option<mpsc::Receiver<()>>>,
        stream: Mutex<Vec<u64>>,
        nested: Mutex<Vec<Result<crate::mutation::MutationResult, crate::MempoolError>>>,
    }

    impl MempoolObserver for CeilingObserver {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            let result = &envelope.result;
            {
                let mut stream = self.stream.lock();
                for index in 0..result.len() {
                    stream.push(result.sequence_of(index).unwrap_or(u64::MAX));
                }
            }
            if result.sequence_base == 1 {
                let Some(entered) = self.entered.lock().take() else {
                    return;
                };
                if entered.send(()).is_err() {
                    return;
                }
                let Some(release) = self.release.lock().take() else {
                    return;
                };
                if release.recv().is_err() {
                    return;
                }
                let gateway = self.gateway.lock().clone();
                if let Some(gateway) = gateway {
                    let Ok(allowance) = u32::try_from(DELIVERY_REENTRANT_ALLOWANCE) else {
                        return;
                    };
                    let attempts = allowance + 2;
                    for attempt in 0..attempts {
                        let nested = gateway.insert_entry(
                            AdmissionOrigin::Rpc,
                            entry(&backpressure_tx(30, attempt)),
                        );
                        self.nested.lock().push(nested);
                    }
                }
            }
        }
    }

    // MPS-04
    #[test]
    fn reentrant_mutations_past_the_ceiling_are_refused_with_delivery_queue_full()
    -> Result<(), crate::test_error::TestError> {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let observer = Arc::new(CeilingObserver {
            gateway: Mutex::new(None),
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(Some(release_rx)),
            stream: Mutex::new(Vec::new()),
            nested: Mutex::new(Vec::new()),
        });
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Some((dyn_observer(&observer), BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        ));
        *observer.gateway.lock() = Some(Arc::clone(&gateway));
        let first = Arc::clone(&gateway);
        let first_handle =
            std::thread::spawn(move || insert_contended(&first, &backpressure_tx(200, 0)));
        entered_rx.recv_timeout(core::time::Duration::from_secs(10))?;
        let flood = u32::try_from(DELIVERY_QUEUE_CAPACITY)?;
        for index in 0..flood {
            insert_contended(&gateway, &backpressure_tx(10, index));
        }
        let deadline = std::time::Instant::now() + core::time::Duration::from_secs(10);
        while gateway.publish_len() != DELIVERY_QUEUE_CAPACITY {
            assert!(
                std::time::Instant::now() < deadline,
                "the delivery queue never filled"
            );
            std::thread::yield_now();
        }
        release_tx.send(())?;
        let Ok(()) = first_handle.join() else {
            return Err("first publisher panicked".into());
        };
        wait_for_publication_settle(&gateway, &observer.stream)?;
        let allowance = u64::try_from(DELIVERY_REENTRANT_ALLOWANCE)?;
        let capacity = u64::try_from(DELIVERY_QUEUE_CAPACITY)?;
        assert_eq!(
            gateway.publish_high_water(),
            usize::try_from(capacity + allowance)?,
            "the queue never passes the reentrant ceiling"
        );
        let nested = observer.nested.lock();
        let mut committed = Vec::new();
        let mut refused = 0;
        for outcome in nested.iter() {
            match outcome {
                Ok(result) => committed.push(result.sequence_base),
                Err(crate::MempoolError::DeliveryQueueFull) => refused += 1,
                Err(other) => panic!("unexpected nested refusal: {other:?}"),
            }
        }
        assert_eq!(
            committed.len(),
            usize::try_from(allowance)?,
            "only the allowance fits past the bound"
        );
        assert_eq!(refused, 2, "mutations past the ceiling are refused");
        let expected_bases: Vec<u64> = (capacity + 2..capacity + 2 + allowance).collect();
        assert_eq!(
            committed, expected_bases,
            "the admitted burst keeps sequence order"
        );
        let expected: Vec<u64> = (1..=(capacity + 1 + allowance)).collect();
        assert_eq!(
            *observer.stream.lock(),
            expected,
            "every committed event arrives exactly once in sequence order"
        );
        Ok(())
    }

    struct ChainDrivenReentrantObserver {
        gateway: Mutex<Option<Arc<MempoolGateway>>>,
        entered: Mutex<Option<mpsc::Sender<()>>>,
        release: Mutex<Option<mpsc::Receiver<()>>>,
        stream: Mutex<Vec<u64>>,
        residents: Mutex<Vec<Tx>>,
        block_results: Mutex<Vec<Result<crate::mutation::MutationResult, crate::MempoolError>>>,
        clear_results: Mutex<Vec<Result<crate::mutation::MutationResult, crate::MempoolError>>>,
    }

    impl MempoolObserver for ChainDrivenReentrantObserver {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            let result = &envelope.result;
            {
                let mut stream = self.stream.lock();
                for index in 0..result.len() {
                    stream.push(result.sequence_of(index).unwrap_or(u64::MAX));
                }
            }
            if result.sequence_base == 1 {
                let Some(entered) = self.entered.lock().take() else {
                    return;
                };
                if entered.send(()).is_err() {
                    return;
                }
                let Some(release) = self.release.lock().take() else {
                    return;
                };
                if release.recv().is_err() {
                    return;
                }
                let gateway = self.gateway.lock().clone();
                if let Some(gateway) = gateway {
                    let attempts = DELIVERY_REENTRANT_ALLOWANCE + 2;
                    let residents = self.residents.lock().clone();
                    for tx in residents.iter().take(attempts) {
                        let facts = crate::settlement::TransitionFacts::from_txs(&[tx]);
                        self.block_results.lock().push(gateway.remove_for_block(
                            AdmissionOrigin::Rpc,
                            &facts,
                            8,
                            1,
                        ));
                    }
                    for _ in 0..2 {
                        self.clear_results
                            .lock()
                            .push(gateway.clear(AdmissionOrigin::Rpc));
                    }
                }
            }
        }
    }

    // MPS-04
    #[test]
    fn chain_driven_reentrant_mutations_past_the_ceiling_are_refused()
    -> Result<(), crate::test_error::TestError> {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let observer = Arc::new(ChainDrivenReentrantObserver {
            gateway: Mutex::new(None),
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(Some(release_rx)),
            stream: Mutex::new(Vec::new()),
            residents: Mutex::new(Vec::new()),
            block_results: Mutex::new(Vec::new()),
            clear_results: Mutex::new(Vec::new()),
        });
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Some((dyn_observer(&observer), BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        ));
        *observer.gateway.lock() = Some(Arc::clone(&gateway));
        let first = Arc::clone(&gateway);
        let first_handle =
            std::thread::spawn(move || insert_contended(&first, &backpressure_tx(200, 0)));
        entered_rx.recv_timeout(core::time::Duration::from_secs(10))?;
        let flood = u32::try_from(DELIVERY_QUEUE_CAPACITY)?;
        let mut residents = Vec::with_capacity(usize::try_from(flood)?);
        for index in 0..flood {
            let tx = backpressure_tx(10, index);
            insert_contended(&gateway, &tx);
            residents.push(tx);
        }
        *observer.residents.lock() = residents.clone();
        let deadline = std::time::Instant::now() + core::time::Duration::from_secs(10);
        while gateway.publish_len() != DELIVERY_QUEUE_CAPACITY {
            assert!(
                std::time::Instant::now() < deadline,
                "the delivery queue never filled"
            );
            std::thread::yield_now();
        }
        release_tx.send(())?;
        let Ok(()) = first_handle.join() else {
            return Err("first publisher panicked".into());
        };
        wait_for_publication_settle(&gateway, &observer.stream)?;
        let allowance = u64::try_from(DELIVERY_REENTRANT_ALLOWANCE)?;
        let capacity = u64::try_from(DELIVERY_QUEUE_CAPACITY)?;
        assert_eq!(
            gateway.publish_high_water(),
            usize::try_from(capacity + allowance)?,
            "the queue never passes the reentrant ceiling"
        );
        let block_results = observer.block_results.lock();
        let mut settled = Vec::new();
        let mut refused = 0;
        for outcome in block_results.iter() {
            match outcome {
                Ok(result) => settled.push(result.sequence_base),
                Err(crate::MempoolError::DeliveryQueueFull) => refused += 1,
                Err(other) => panic!("unexpected block refusal: {other:?}"),
            }
        }
        assert_eq!(
            settled.len(),
            usize::try_from(allowance)?,
            "only the allowance settles past the bound"
        );
        assert_eq!(refused, 2, "chain mutations past the ceiling are refused");
        let expected_bases: Vec<u64> = (capacity + 2..capacity + 2 + allowance).collect();
        assert_eq!(
            settled, expected_bases,
            "the admitted burst keeps sequence order"
        );
        let clear_results = observer.clear_results.lock();
        assert_eq!(clear_results.len(), 2, "both clears ran to a decision");
        assert!(
            clear_results
                .iter()
                .all(|outcome| matches!(outcome, Err(crate::MempoolError::DeliveryQueueFull))),
            "a clear past the ceiling is refused, never silently skipped"
        );
        assert_eq!(
            gateway.read().len(),
            usize::try_from(capacity + 1)? - usize::try_from(allowance)?,
            "refused mutations leave every resident in place"
        );
        let expected: Vec<u64> = (1..=(capacity + 1 + allowance)).collect();
        assert_eq!(
            *observer.stream.lock(),
            expected,
            "every committed event arrives exactly once in sequence order"
        );
        Ok(())
    }

    #[derive(Default)]
    struct SequenceStreamObserver {
        stream: Mutex<Vec<u64>>,
    }

    impl MempoolObserver for SequenceStreamObserver {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            let result = &envelope.result;
            let mut stream = self.stream.lock();
            for index in 0..result.len() {
                stream.push(result.sequence_of(index).unwrap_or(u64::MAX));
            }
        }
    }

    // MPS-04
    #[test]
    fn concurrent_mutations_publish_in_sequence_order() {
        const CYCLES: usize = 1_500;
        const MEMBER_LABELS: [u8; 4] = [20, 21, 22, 23];
        let observer = Arc::new(SequenceStreamObserver::default());
        let gateway = Arc::new(gateway_with(Some(dyn_observer(&observer))));

        let handles: Vec<_> = MEMBER_LABELS
            .iter()
            .map(|&label| {
                let gateway = Arc::clone(&gateway);
                std::thread::spawn(move || {
                    let member = tx(label);
                    for _ in 0..CYCLES {
                        insert_contended(&gateway, &member);
                        gateway
                            .remove_for_block(
                                AdmissionOrigin::Rpc,
                                &crate::settlement::TransitionFacts::from_txs(&[&member]),
                                8,
                                1,
                            )
                            .expect("block settlement commits");
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("mutator thread");
        }

        let total = u64::try_from(MEMBER_LABELS.len() * CYCLES * 2).expect("change count fits u64");
        let stream = observer.stream.lock();
        assert_eq!(
            u64::try_from(stream.len()).expect("stream length fits u64"),
            total,
            "every committed change published exactly once"
        );
        let expected: Vec<u64> = (1..=total).collect();
        assert_eq!(*stream, expected, "publish order must equal commit order");
    }

    #[test]
    fn refused_insertion_preserves_state_and_publishes_nothing() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                max_total_bytes: unit() * 3 / 2,
                ..MempoolLimits::default()
            }))),
            Some((dyn_observer(&observer), BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        );

        let filler = tx(70);
        let filler_txid = filler.txid();
        gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(filler), 100, 9_000, 1, 7, 0),
            )
            .expect("filler in");
        observer.seen.lock().clear();

        let shed = tx(71);
        let shed_txid = shed.txid();
        let before = (
            gateway.read().sequence_number(),
            gateway.read().estimator_history(),
        );
        let error = gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(shed), 100, 100, 1, 7, 0),
            )
            .expect_err("entry cannot survive trimming");
        assert_eq!(error, crate::MempoolError::Full);
        assert!(!gateway.read().contains_txid(&shed_txid));
        assert_eq!(gateway.read().min_fee_sat_per_kvb(1), 2_000);
        assert!(gateway.read().contains_txid(&filler_txid));
        assert_eq!(gateway.read().sequence_number(), before.0);
        assert_eq!(gateway.read().estimator_history(), before.1);
        assert!(observer.seen.lock().is_empty());
    }

    #[test]
    fn replacement_fitting_after_eviction_is_not_refused_by_dead_links() {
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                ..MempoolLimits::default()
            }))),
            None,
            ValidationEngine::Native,
            None,
        );

        let parents: Vec<Tx> = (0..24u8).map(|index| tx(100 + index)).collect();
        for parent in &parents {
            gateway
                .insert_entry(
                    AdmissionOrigin::Rpc,
                    MempoolEntry::new(Arc::new(parent.clone()), 100, 1_000, 1, 7, 0),
                )
                .expect("parent in");
        }
        let conflict_inputs: Vec<TxIn> = parents
            .iter()
            .map(|parent| TxIn {
                previous_output: OutPoint::new(parent.txid(), 0),
                script_sig: Script::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect();
        let mut conflict = tx(250);
        conflict.inputs = conflict_inputs.clone();
        let conflict_txid = conflict.txid();
        gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(conflict), 100, 1_000, 1, 7, 0),
            )
            .expect("conflict in");

        let mut replacement = tx(251);
        replacement.inputs = conflict_inputs;
        let replacement_entry =
            MempoolEntry::new(Arc::new(replacement.clone()), 100, 100_000, 1, 7, 0);
        let stale_cap = {
            let pool = gateway.read();
            let conflict_id = pool
                .entry_id_by_txid(&conflict_txid)
                .expect("conflict is in the pool");
            pool.dynamic_memory_usage()
                .checked_sub(pool.entry_memory(conflict_id).expect("conflict memory"))
                .and_then(|size| size.checked_add(pool.admission_memory(&replacement_entry)))
                .expect("cap arithmetic fits u64")
                - 1
        };
        gateway.pool.write().limits.max_total_bytes = stale_cap;

        let result = gateway
        .replace_transaction(
            AdmissionOrigin::Rpc,
            &crate::ReplacementCandidate::new(Arc::new(replacement), 100, 100_000, 1),
            1,
            7,
        )
        .expect("each evicted link releases both endpoints, so the replacement fits once the conflict is gone");
        assert_eq!(
            result.changes,
            vec![
                crate::mutation::change(&conflict_txid, removed(RemovalReason::Replaced)),
                crate::mutation::change(&replacement_entry.txid, MutationOutcome::Accepted,),
            ],
            "the eviction removes the conflict, then the replacement lands"
        );
    }

    #[test]
    fn rejected_replacement_preserves_pool_history_and_publication() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                max_total_bytes: unit() * 5 / 2,
                ..MempoolLimits::default()
            }))),
            Some((dyn_observer(&observer), BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        );

        let prev = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x73; 32])), 0);

        let original = prevout_spend(prev, 1_000, 0x51);
        let original_txid = original.txid();
        gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(original), 100, 10_000, 1, 7, 0),
            )
            .expect("original in");

        let bystander = tx(72);
        let bystander_txid = bystander.txid();
        gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(bystander), 850, 8_500_000, 1, 7, 0),
            )
            .expect("bystander in");

        let mut replacement = prevout_spend(prev, 100, 0x52);
        replacement.outputs[0].script_pubkey =
            vec![0x52; usize::try_from(unit()).unwrap_or(usize::MAX)].into();
        let replacement_txid = replacement.txid();
        observer.seen.lock().clear();

        gateway.prioritise(original_txid, 500).expect("fee delta");
        let before = {
            let pool = gateway.read();
            (
                pool.mining_snapshot().entries.clone(),
                pool.estimator_history(),
                pool.prioritised_transactions(),
                pool.policy_stamp(),
            )
        };
        let error = gateway
            .replace_transaction(
                AdmissionOrigin::Rpc,
                &crate::ReplacementCandidate::new(Arc::new(replacement), 900, 100_000, 1)
                    .with_sigop_cost(4),
                2,
                7,
            )
            .expect_err("replacement cannot survive capacity trimming");
        assert_eq!(error, crate::RbfError::Mempool(crate::MempoolError::Full));
        let pool = gateway.read();
        assert!(pool.contains_txid(&original_txid));
        assert!(pool.contains_txid(&bystander_txid));
        assert!(!pool.contains_txid(&replacement_txid));
        assert_eq!(pool.mining_snapshot().entries, before.0);
        assert_eq!(pool.estimator_history(), before.1);
        assert_eq!(pool.prioritised_transactions(), before.2);
        assert_ne!(pool.policy_stamp(), before.3);
        assert!(pool.min_fee_sat_per_kvb(9) > 0);
        assert!(
            observer.seen.lock().is_empty(),
            "failed replacement cannot publish"
        );
    }

    #[test]
    fn admit_transaction_rejects_a_script_invalid_input() {
        let gateway = gateway_with(None);
        let tx = standard_tx(0x83);

        let mut request = admit_request(&gateway, &tx, AdmissionOrigin::Rpc);
        request.prevouts[0].1.script_pubkey = Script::from_bytes(p2pkh_prevout_script());

        let result = gateway.admit_transaction(request);
        assert!(
            matches!(result, Err(AdmitError::Consensus)),
            "a script-invalid spend must fail verification: {result:?}"
        );
        assert!(gateway.read().is_empty());
    }

    #[test]
    fn admission_counts_resolved_sigops_before_verification()
    -> Result<(), crate::test_error::TestError> {
        let gateway = gateway_with(None);
        let mut tx = standard_tx(0x84);
        let witness_script = vec![0xae; 900];
        tx.inputs[0].script_sig = Script::from_bytes(bitcoin_rs_consensus::script::push_data(
            &[vec![0x00, 0x20], vec![1; 32]].concat(),
        ));
        tx.inputs[0].witness = Witness::from_stack(vec![witness_script]);
        let mut request = admit_request(&gateway, &tx, AdmissionOrigin::Rpc);
        request.prevouts[0].1.script_pubkey =
            Script::from_bytes([vec![0xa9, 0x14], vec![1; 20], vec![0x87]].concat());
        request.context.sigop_cost = 0;
        let oracle: bitcoin::Transaction = bitcoin::consensus::deserialize(
            &bitcoin_rs_consensus::primitives::consensus_bytes(&tx),
        )?;
        let previous = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(request.prevouts[0].1.value.to_sat()),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(
                request.prevouts[0].1.script_pubkey.as_bytes().to_vec(),
            ),
        };
        let cost = oracle.total_sigop_cost(|_| Some(previous.clone()));
        assert!(u32::try_from(cost)? > crate::standardness::MAX_STANDARD_TX_SIGOPS_COST);
        assert_eq!(
            gateway.admit_transaction(request),
            Err(AdmitError::Policy(
                crate::standardness::AcceptanceRejectReason::TooManySigops
            ))
        );
        assert!(gateway.read().is_empty());
        assert_eq!(gateway.read().sequence_number(), 0);
        Ok(())
    }

    #[test]
    fn stale_generation_rejects_without_mutation_or_publication() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));
        let candidate = tx(40);

        let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);

        let current = gateway.chain_generation.load(Ordering::Relaxed);
        gateway
            .chain_generation
            .store(current + 1, Ordering::Release);

        request.expected_generation = current;

        let outcome = gateway.admit_transaction(request);
        assert!(
            matches!(outcome, Err(AdmitError::GenerationChanged)),
            "stale generation must return GenerationChanged, got {outcome:?}"
        );
        assert_eq!(
            gateway.read().sequence_number(),
            0,
            "no sequence change on stale generation"
        );
        assert!(
            observer.seen.lock().is_empty(),
            "no observer call on stale generation"
        );
        assert!(
            !gateway.read().contains_txid(&candidate.txid()),
            "no mutation on stale generation"
        );
    }

    #[test]
    fn stale_mempool_sequence_rejects_without_mutation_or_publication() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));
        let candidate = tx(41);

        let other = tx(42);
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&other))
            .expect("other tx admitted");
        observer.seen.lock().clear();

        let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
        let captured_sequence = request.expected_sequence;

        gateway
            .remove_for_block(
                AdmissionOrigin::Rpc,
                &crate::settlement::TransitionFacts::from_txs(&[&other]),
                8,
                1,
            )
            .expect("block settlement commits");

        request.expected_sequence = captured_sequence;

        let outcome = gateway.admit_transaction(request);
        assert!(
            matches!(outcome, Err(AdmitError::MempoolChanged)),
            "stale sequence must return MempoolChanged, got {outcome:?}"
        );
        assert!(
            !gateway.read().contains_txid(&candidate.txid()),
            "no added transaction on stale sequence"
        );
        let seen = observer.seen.lock();
        assert_eq!(
            seen.len(),
            1,
            "only the removal publication, no extra observer call from admission"
        );
    }

    #[test]
    fn admit_write_gate_retries_when_the_stamp_moved_after_prepare()
    -> Result<(), crate::test_error::TestError> {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));
        let resident = tx(60);
        let resident_txid = resident.txid();
        gateway.insert_entry(AdmissionOrigin::Rpc, entry(&resident))?;
        observer.seen.lock().clear();

        let candidate = standard_tx(61);
        let candidate_txid = candidate.txid();
        let request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
        let prepared = {
            let pool = gateway.read();
            MempoolGateway::prepare_admission(
                &pool,
                &request,
                AdmissionMode::Single,
                crate::admission::AdmissionFence::Stable,
                gateway.engine(),
            )
        };

        gateway.prioritise(resident_txid, 500)?;
        assert_eq!(
            gateway.read().sequence_number(),
            request.expected_sequence,
            "prioritisation must leave the membership sequence alone"
        );

        let pool = gateway.pool.write();
        assert_eq!(
            gateway.check_admission_state(
                &pool,
                request.expected_generation,
                request.expected_sequence,
                crate::admission::AdmissionFence::Stable,
                Some(prepared.stamp),
            ),
            Err(AdmitError::MempoolChanged),
            "a moved fee-delta stamp must reject the writer recheck"
        );
        drop(pool);
        assert!(
            !gateway.read().contains_txid(&candidate_txid),
            "the rejected attempt mutates nothing"
        );
        assert!(
            observer.seen.lock().is_empty(),
            "the rejected attempt publishes nothing"
        );

        let retry = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
        assert!(matches!(
            gateway.admit_transaction(retry),
            Ok(AdmitOutcome::Committed(_))
        ));
        assert!(gateway.read().contains_txid(&candidate_txid));
        Ok(())
    }

    fn p2wpkh_prevout_script() -> Vec<u8> {
        [vec![0x00, 0x14], vec![0x2b; 20]].concat()
    }

    fn multi_input_tx(input_count: u32) -> (Tx, Vec<(OutPoint, TxOut)>) {
        let count = usize::try_from(input_count).expect("input count fits usize");
        let mut inputs = Vec::with_capacity(count);
        let mut prevouts = Vec::with_capacity(count);
        for index in 0..input_count {
            let mut bytes = [0_u8; 32];
            bytes[..4].copy_from_slice(&index.to_le_bytes());
            let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), 0);
            inputs.push(TxIn {
                previous_output: outpoint,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            });
            prevouts.push((
                outpoint,
                TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: Script::from_bytes(p2wpkh_prevout_script()),
                },
            ));
        }
        let tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs,
            outputs: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes(p2pkh_prevout_script()),
            }],
        };
        (tx, prevouts)
    }

    fn multi_input_request(
        gateway: &MempoolGateway,
        tx: Tx,
        prevouts: Vec<(OutPoint, TxOut)>,
        fee: u64,
    ) -> AdmissionRequest {
        let generation = gateway
            .stable_generation()
            .expect("generation is even in test setup");
        let sequence = gateway.read().sequence_number();
        AdmissionRequest {
            tx: Arc::new(tx),
            context: PackageTxContext {
                fee,
                vsize: 1,
                sigop_cost: 0,
                missing_inputs: false,
            },
            prevouts,
            prevout_meta: hashbrown::HashMap::new(),
            csv_active: false,
            next_block_script_flags: bitcoin_rs_consensus::script::VerifyFlags::STANDARD,
            locktime_cutoff: 0,
            max_feerate_sat_per_kvb: None,
            time: 1,
            height: 1,
            origin: AdmissionOrigin::Rpc,
            expected_generation: generation,
            expected_sequence: sequence,
        }
    }

    #[test]
    fn oversize_multi_input_tx_is_rejected_before_prevout_resolution() {
        let gateway = gateway_with(None);
        let (tx, prevouts) = multi_input_tx(20_000);
        let oracle: bitcoin::Transaction = bitcoin::consensus::deserialize(
            &bitcoin_rs_consensus::primitives::consensus_bytes(&tx),
        )
        .expect("the attack frame parses as a Core transaction");
        assert!(
            oracle.total_size() <= 4_000_000,
            "the attack frame stays inside the 4,000,000-byte wire limit, got {}",
            oracle.total_size()
        );
        let weight = oracle.weight().to_wu();
        assert!(
            weight > crate::standardness::MAX_STANDARD_TX_WEIGHT,
            "the rust-bitcoin weight oracle {weight} must exceed the Core tx-size limit"
        );
        let request = multi_input_request(&gateway, tx, prevouts, 1_000_000);
        super::reset_prevout_probes();
        let prepared = {
            let pool = gateway.read();
            MempoolGateway::prepare_admission(
                &pool,
                &request,
                AdmissionMode::Single,
                crate::admission::AdmissionFence::Stable,
                gateway.engine(),
            )
        };
        assert_eq!(
            prepared.fact.reject_reason,
            Some(crate::standardness::AcceptanceRejectReason::NonStandard(
                crate::standardness::StandardnessError::Weight
            )),
            "the Core tx-size rule rejects the frame regardless of prevout resolution"
        );
        assert_eq!(
            super::prevout_probes(),
            0,
            "an over-size frame must be rejected before any prevout index probe"
        );
    }

    #[test]
    fn many_input_admission_probes_each_prevout_once() {
        let gateway = gateway_with(None);
        let (tx, prevouts) = multi_input_tx(2_400);
        let oracle: bitcoin::Transaction = bitcoin::consensus::deserialize(
            &bitcoin_rs_consensus::primitives::consensus_bytes(&tx),
        )
        .expect("the attack frame parses as a Core transaction");
        let weight = oracle.weight().to_wu();
        assert!(
            weight <= crate::standardness::MAX_STANDARD_TX_WEIGHT,
            "the rust-bitcoin weight oracle {weight} must stay inside the Core tx-size limit"
        );
        let reference: std::collections::HashMap<OutPoint, TxOut> =
            prevouts.iter().cloned().collect();
        let request = multi_input_request(&gateway, tx, prevouts, 1_000_000);
        super::reset_prevout_probes();
        let prepared = {
            let pool = gateway.read();
            MempoolGateway::prepare_admission(
                &pool,
                &request,
                AdmissionMode::Single,
                crate::admission::AdmissionFence::Stable,
                gateway.engine(),
            )
        };
        assert_eq!(
            prepared.fact.reject_reason, None,
            "the policy oracle accepts a standard spend that stays inside every relay bound"
        );
        assert_eq!(
            prepared.prevouts.len(),
            reference.len(),
            "every input must resolve against the chain prevout index"
        );
        for (outpoint, output) in &prepared.prevouts {
            assert_eq!(
                reference.get(outpoint),
                Some(output),
                "the indexed lookup must return the plain HashMap result for {outpoint:?}"
            );
        }
        let probes = super::prevout_probes();
        assert!(
            probes <= usize::try_from(2_400).expect("input count fits usize"),
            "each input must cost at most one prevout probe, got {probes}"
        );
    }

    #[test]
    fn exact_duplicate_is_success_without_second_publication() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));
        let candidate = tx(43);
        let txid = candidate.txid();

        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&candidate))
            .expect("first insert");
        observer.seen.lock().clear();

        let request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
        let outcome = gateway.admit_transaction(request);
        assert!(
            matches!(outcome, Ok(AdmitOutcome::AlreadyKnown)),
            "exact duplicate must return AlreadyKnown, got {outcome:?}"
        );
        assert!(
            observer.seen.lock().is_empty(),
            "no second publication on duplicate"
        );
        assert_eq!(
            gateway.read().sequence_number(),
            1,
            "no sequence change on duplicate"
        );
        assert!(
            gateway.read().contains_txid(&txid),
            "original entry is still there"
        );
    }

    #[test]
    fn admit_transaction_publishes_ordered_removals_then_one_accept() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));

        let mut original = standard_tx(44);
        original.inputs[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
        let original_txid = original.txid();
        let mut replacement = standard_tx(45);
        replacement.inputs[0].previous_output = original.inputs[0].previous_output;
        replacement.inputs[0].sequence = Sequence::from_consensus(0xFFFF_FFFE);
        replacement.outputs[0].value = Amount::from_sat(5_000);
        let replacement_txid = replacement.txid();

        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&original))
            .expect("original admitted");
        observer.seen.lock().clear();

        let generation = gateway.stable_generation().expect("generation is even");
        let sequence = gateway.read().sequence_number();
        let request = AdmissionRequest {
            tx: Arc::new(replacement.clone()),
            context: PackageTxContext {
                fee: 5_000,
                vsize: 100,
                sigop_cost: 0,
                missing_inputs: false,
            },
            prevouts: vec![(
                replacement.inputs[0].previous_output,
                TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: Script::from_bytes(p2sh_true_script()),
                },
            )],
            prevout_meta: hashbrown::HashMap::new(),
            csv_active: false,
            next_block_script_flags: bitcoin_rs_consensus::script::VerifyFlags::STANDARD,
            locktime_cutoff: 0,
            max_feerate_sat_per_kvb: None,
            time: 1,
            height: 1,
            origin: AdmissionOrigin::Rpc,
            expected_generation: generation,
            expected_sequence: sequence,
        };

        let outcome = gateway.admit_transaction(request);
        assert!(
            matches!(outcome, Ok(AdmitOutcome::Committed(_))),
            "replacement must commit, got {outcome:?}"
        );

        let seen = observer.seen.lock();
        let mut removed_count = 0;
        let mut accepted_count = 0;
        for (_, outcome) in seen.iter() {
            match outcome {
                MutationOutcome::Removed(_) => removed_count += 1,
                MutationOutcome::Accepted => accepted_count += 1,
            }
        }
        assert!(
            removed_count >= 1,
            "at least one removal (the replaced original)"
        );
        assert_eq!(
            accepted_count, 1,
            "exactly one Accepted, not {accepted_count}"
        );
        let accepted_index = seen
            .iter()
            .position(|(_, o)| *o == MutationOutcome::Accepted)
            .expect("an Accepted event");
        for (i, (_, outcome)) in seen.iter().enumerate() {
            if i < accepted_index {
                assert!(
                    matches!(outcome, MutationOutcome::Removed(_)),
                    "removals must precede the Accepted event"
                );
            }
        }
        assert!(
            !gateway.read().contains_txid(&original_txid),
            "replaced original must be gone"
        );
        assert!(
            gateway.read().contains_txid(&replacement_txid),
            "replacement must be in the pool"
        );
    }

    fn reconstruction_identities(
        gateway: &MempoolGateway,
    ) -> Vec<(Txid, bitcoin_rs_consensus::primitives::Wtxid)> {
        let mut seen = Vec::new();
        gateway.for_each_reconstruction_identity(|txid, wtxid| seen.push((txid, wtxid)));
        seen
    }

    fn retain(ring: &mut ExtraTxnRing, tx: &Arc<Tx>) {
        ring.insert(tx.txid(), tx.wtxid(), tx);
    }

    #[test]
    fn extra_txn_ring_is_fifo_bounded_and_ignores_repeats() {
        let bodies: Vec<Arc<Tx>> = (0..=100_u8).map(|label| Arc::new(tx(label))).collect();
        assert_eq!(bodies.len(), BLOCK_RECONSTRUCTION_EXTRA_TXN + 1);
        let mut ring = ExtraTxnRing::default();
        for body in &bodies[..BLOCK_RECONSTRUCTION_EXTRA_TXN] {
            retain(&mut ring, body);
        }
        retain(&mut ring, &bodies[0]);
        assert_eq!(ring.entries.len(), BLOCK_RECONSTRUCTION_EXTRA_TXN);

        retain(&mut ring, &bodies[BLOCK_RECONSTRUCTION_EXTRA_TXN]);
        assert_eq!(ring.entries.len(), BLOCK_RECONSTRUCTION_EXTRA_TXN);
        assert!(
            ring.by_wtxid(bodies[0].wtxid()).is_none(),
            "the repeat did not postpone the oldest body's eviction"
        );
        let held: Vec<_> = ring.entries.iter().map(|entry| entry.wtxid).collect();
        let expected: Vec<_> = bodies[1..].iter().map(|body| body.wtxid()).collect();
        assert_eq!(held, expected, "the newest 100 remain, oldest first");

        let mut coinbase = tx(200);
        coinbase.inputs[0].previous_output = OutPoint::new(Txid::default(), u32::MAX);
        assert!(coinbase.is_coinbase());
        retain(&mut ring, &Arc::new(coinbase));
        assert_eq!(ring.entries.len(), BLOCK_RECONSTRUCTION_EXTRA_TXN);
        assert_eq!(
            ring.entries
                .iter()
                .map(|entry| entry.wtxid)
                .collect::<Vec<_>>(),
            expected,
            "a coinbase changes nothing, not even by evicting"
        );

        let mut variant = (*bodies[1]).clone();
        variant.inputs[0].witness = Witness::from_stack(vec![vec![1]]);
        let variant = Arc::new(variant);
        assert_eq!(variant.txid(), bodies[1].txid());
        assert_ne!(variant.wtxid(), bodies[1].wtxid());
        let mut siblings = ExtraTxnRing::default();
        retain(&mut siblings, &bodies[1]);
        retain(&mut siblings, &variant);
        assert_eq!(siblings.entries.len(), 2);
        assert_eq!(siblings.by_wtxid(bodies[1].wtxid()), Some(&bodies[1]));
        assert_eq!(siblings.by_wtxid(variant.wtxid()), Some(&variant));
        assert_eq!(
            siblings.by_txid(variant.txid()),
            Some(&bodies[1]),
            "a txid lookup answers the oldest variant"
        );
    }

    #[test]
    fn replaced_bodies_are_retained_for_reconstruction_and_stay_hint_only() {
        let gateway = gateway_with(None);
        let mut original = standard_tx(46);
        original.inputs[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
        let child = prevout_spend(OutPoint::new(original.txid(), 0), 5_000, 9);
        let mut replacement = standard_tx(47);
        replacement.inputs[0].previous_output = original.inputs[0].previous_output;
        replacement.inputs[0].sequence = Sequence::from_consensus(0xFFFF_FFFE);
        replacement.outputs[0].value = Amount::from_sat(6_000);
        for resident in [&original, &child] {
            gateway
                .insert_entry(AdmissionOrigin::Rpc, entry(resident))
                .expect("resident admitted");
        }
        let mut request = admit_request(&gateway, &replacement, AdmissionOrigin::Rpc);
        request.context.fee = 5_000;
        let outcome = gateway.admit_transaction(request);
        assert!(
            matches!(outcome, Ok(AdmitOutcome::Committed(_))),
            "replacement must commit, got {outcome:?}"
        );
        assert!(!gateway.read().contains_txid(&original.txid()));
        assert!(!gateway.read().contains_txid(&child.txid()));

        for replaced in [&original, &child] {
            assert_eq!(
                gateway.reconstruction_tx_by_wtxid(replaced.wtxid()),
                Some(replaced.clone())
            );
            assert_eq!(
                gateway.reconstruction_tx_by_txid(replaced.txid()),
                Some(replaced.clone())
            );
            assert_eq!(gateway.get_tx(replaced.txid()), None);
            assert_eq!(gateway.get_tx_by_wtxid(replaced.wtxid()), None);
            assert!(!gateway.have_tx(hash(&replaced.txid()), false));
        }
        let identities = reconstruction_identities(&gateway);
        assert_eq!(identities.len(), 3, "replacement once, then both extras");
        assert_eq!(
            identities
                .iter()
                .filter(|(txid, _)| *txid == replacement.txid())
                .count(),
            1
        );
    }

    #[test]
    fn block_and_size_limit_removals_are_not_retained() {
        let gateway = gateway_with(None);
        let mined = tx(60);
        let first = tx(61);
        let second = tx(62);
        for resident in [&mined, &first, &second] {
            gateway
                .insert_entry(AdmissionOrigin::Rpc, entry(resident))
                .expect("resident admitted");
        }
        gateway
            .remove_for_block(
                AdmissionOrigin::Rpc,
                &crate::settlement::TransitionFacts::from_txs(&[&mined]),
                8,
                1,
            )
            .expect("block settlement commits");
        assert_eq!(gateway.reconstruction_tx_by_wtxid(mined.wtxid()), None);

        let trimmed = gateway
            .enforce_size_limit(AdmissionOrigin::Rpc, unit())
            .expect("size trim");
        assert_eq!(trimmed.removed_txids().len(), 1);
        for resident in [&first, &second] {
            assert_eq!(
                gateway.reconstruction_tx_by_wtxid(resident.wtxid()),
                gateway.get_tx_by_wtxid(resident.wtxid()),
                "an evicted body is not kept as a reconstruction extra"
            );
        }
        assert_eq!(reconstruction_identities(&gateway).len(), 1);
    }

    #[test]
    fn composite_isolates_a_panicking_leg() {
        let recorder = Arc::new(RecordingObserver::default());
        let metric_recorder = CounterKeyRecorder::default();
        let composite = CompositeObserver::new();
        composite.add_leg(
            "panicker",
            Arc::new(PanickingObserver),
            BodyInterest::Metadata,
        );
        composite.add_leg("recorder", dyn_observer(&recorder), BodyInterest::Metadata);
        let composite = Arc::new(composite);
        let gateway = gateway_with(Some(dyn_observer(&composite)));

        let committed = tx(40);
        let committed_txid = committed.txid();
        metrics::with_local_recorder(&metric_recorder, || {
            gateway.insert_entry(AdmissionOrigin::Rpc, entry(&committed))
        })
        .expect("still returns");

        assert!(
            gateway.read().contains_txid(&committed_txid),
            "the mutation stands after a leg panicked"
        );
        assert_eq!(
            *recorder.seen.lock(),
            vec![(hash(&committed_txid), MutationOutcome::Accepted)],
            "the leg after the panicking one still recorded"
        );
        let keys = metric_recorder.keys.lock();
        let failure = keys
            .iter()
            .find(|(name, _)| name == "node.mempool.observer_failures_total")
            .expect("aggregate observer failure counter");
        assert_eq!(
            failure.1, 0,
            "observer identity belongs in tracing, not metric labels"
        );
    }

    #[test]
    fn chain_generation_starts_even_at_zero() {
        let gateway = gateway_with(None);
        assert_eq!(
            gateway.stable_generation(),
            Some(0),
            "initial generation is even zero"
        );
    }

    #[test]
    fn stable_generation_reads_even_values() {
        let gateway = gateway_with(None);
        gateway.chain_generation.store(4, Ordering::Release);
        assert_eq!(gateway.stable_generation(), Some(4));
        gateway.chain_generation.store(7, Ordering::Release);
        assert_eq!(
            gateway.stable_generation(),
            None,
            "odd generation is not stable"
        );
    }

    #[test]
    fn begin_chain_change_rejects_nested_begin() {
        let gateway = gateway_with(None);
        let guard = gateway
            .begin_chain_change()
            .expect("first begin succeeds on even generation");
        assert_eq!(guard.odd_generation(), 1);
        assert_eq!(guard.reserved_even(), 2);
        assert_eq!(
            gateway.stable_generation(),
            None,
            "odd generation is not stable while a chain change is active"
        );
        let err = gateway
            .begin_chain_change()
            .expect_err("nested begin rejected while odd");
        assert_eq!(err, ChainChangeError::AlreadyActive);
        drop(guard);
    }

    #[test]
    fn explicit_finish_restores_even_generation() {
        let gateway = gateway_with(None);
        let guard = gateway.begin_chain_change().expect("begin");
        assert_eq!(guard.odd_generation(), 1);
        assert_eq!(guard.reserved_even(), 2);
        guard
            .finish()
            .expect("finish stores the reserved even value");
        assert_eq!(
            gateway.stable_generation(),
            Some(2),
            "finish restored the exact reserved even value"
        );
    }

    // MPL-04
    #[test]
    fn dropping_chain_change_stays_unstable() {
        let gateway = gateway_with(None);
        {
            let _guard = gateway.begin_chain_change().expect("begin");
            assert_eq!(gateway.stable_generation(), None);
        }
        assert_eq!(
            gateway.stable_generation(),
            None,
            "dropping the guard without finish leaves the generation odd"
        );
        let err = gateway
            .begin_chain_change()
            .expect_err("cannot begin while odd after a dropped guard");
        assert_eq!(err, ChainChangeError::AlreadyActive);
    }

    #[test]
    fn chain_generation_overflow_fails_closed() {
        let gateway = gateway_with(None);
        gateway
            .chain_generation
            .store(u64::MAX - 1, Ordering::Relaxed);
        let err = gateway
            .begin_chain_change()
            .expect_err("overflow must fail before any store");
        assert_eq!(err, ChainChangeError::Overflow);
        assert_eq!(
            gateway.chain_generation.load(Ordering::Relaxed),
            u64::MAX - 1,
            "generation unchanged after overflow failure"
        );
    }

    // MPL-04
    #[test]
    fn begin_chain_change_serializes_with_inflight_admission() {
        let gateway = gateway_with(None);

        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let admission_released = Arc::new(AtomicBool::new(false));
        let released_probe = Arc::clone(&admission_released);
        let gateway_a = Arc::clone(&gateway);
        let a_handle = std::thread::spawn(move || {
            let guard = gateway_a.pool().write();
            held_tx.send(()).expect("test waiting for lock acquisition");
            release_rx.recv().expect("test alive to release");
            released_probe.store(true, Ordering::SeqCst);
            drop(guard);
        });

        held_rx
            .recv()
            .expect("thread A acquired the pool write lock");

        let (entered_tx, entered_rx) = mpsc::channel();
        let (lock_held_tx, lock_held_rx) = mpsc::channel::<bool>();
        let (resume_tx, resume_rx) = mpsc::channel::<()>();
        let held_when_probed = Arc::clone(&admission_released);
        gateway.install_begin_chain_change_probes(
            entered_tx,
            lock_held_tx,
            resume_rx,
            Box::new(move || held_when_probed.load(Ordering::SeqCst)),
        );

        let gateway_b = Arc::clone(&gateway);
        let (b_done_tx, b_done_rx) = mpsc::channel();
        let b_handle = std::thread::spawn(move || {
            let guard = gateway_b
                .begin_chain_change()
                .expect("begin after lock release");
            b_done_tx
                .send(guard)
                .expect("test waiting for begin result");
        });

        entered_rx
            .recv()
            .expect("thread B entered begin_chain_change");
        assert!(
            gateway.pool().is_locked_exclusive(),
            "the admission holds the pool write lock that parks begin_chain_change"
        );
        assert!(
            b_done_rx.try_recv().is_err(),
            "begin_chain_change must not complete while the admission holds the write lock"
        );
        assert_eq!(
            gateway.stable_generation(),
            Some(0),
            "begin must not store odd while an admission holds the write lock"
        );
        assert!(
            lock_held_rx.try_recv().is_err(),
            "begin_chain_change must still be parked on the pool write lock held by the admission"
        );

        release_tx.send(()).expect("thread A alive");
        a_handle.join().expect("thread A completed");

        let lock_held_after_release = lock_held_rx
            .recv()
            .expect("begin_chain_change reached the pool write lock");
        resume_tx.send(()).expect("resume begin_chain_change");
        assert!(
            lock_held_after_release,
            "begin_chain_change must pass the pool write lock only after the admission released it"
        );
        let guard = b_done_rx
            .recv()
            .expect("begin_chain_change returned after lock release");
        assert_eq!(guard.odd_generation(), 1);
        assert_eq!(guard.reserved_even(), 2);
        assert_eq!(gateway.stable_generation(), None);
        guard.finish().expect("finish restores even");
        assert_eq!(gateway.stable_generation(), Some(2));
        b_handle.join().expect("thread B completed");
    }

    #[test]
    fn remove_for_block_distinguishes_mined_from_conflicts() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));

        let mined = tx(10);
        let mined_txid = mined.txid();
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&mined))
            .expect("mined in");

        let conflict_tx = tx(11);
        let conflict_txid = conflict_tx.txid();
        let spent_outpoint = conflict_tx.inputs[0].previous_output;
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&conflict_tx))
            .expect("conflict in");

        let mut child = tx(12);
        child.inputs[0].previous_output = OutPoint::new(conflict_txid, 0);
        let child_txid = child.txid();
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&child))
            .expect("child in");

        let mut double_spend = tx(13);
        double_spend.inputs[0] = TxIn {
            previous_output: spent_outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };
        observer.seen.lock().clear();
        gateway
            .remove_for_block(
                AdmissionOrigin::Block,
                &crate::settlement::TransitionFacts::from_txs(&[&mined, &double_spend]),
                8,
                1,
            )
            .expect("block settlement commits");

        let seen = observer.seen.lock();
        assert_eq!(
            *seen,
            vec![
                (hash(&mined_txid), removed(RemovalReason::BlockInclusion)),
                (hash(&conflict_txid), removed(RemovalReason::Conflict)),
                (hash(&child_txid), removed(RemovalReason::Conflict)),
            ],
            "mined is BlockInclusion, conflict and descendant are Conflict, in deterministic order"
        );
    }

    #[test]
    fn admit_transaction_enforces_finality_at_the_next_block() {
        for (label, tag, lock_time, cutoff, final_now) in [
            ("lock_time == tip_height", 0x80_u8, 100_u32, None, true),
            ("lock_time == tip_height + 1", 0x81, 101, None, false),
            (
                "time lock above the applied-tip MTP",
                0x82,
                1_800_000_000,
                Some(1_700_000_000),
                false,
            ),
        ] {
            let gateway = gateway_with(None);
            let mut tx = standard_tx(tag);
            tx.lock_time = LockTime::from_consensus(lock_time);
            tx.inputs[0].sequence = Sequence::from_consensus(0xFFFF_FFFE);

            let mut request = admit_request(&gateway, &tx, AdmissionOrigin::Rpc);
            request.height = 100;
            if let Some(cutoff) = cutoff {
                request.locktime_cutoff = cutoff;
            }

            let result = gateway.admit_transaction(request);
            if final_now {
                assert!(
                    matches!(result, Ok(AdmitOutcome::Committed(_))),
                    "{label} must be final in the next block: {result:?}"
                );
            } else {
                assert!(
                    matches!(result, Err(AdmitError::Consensus)),
                    "{label} must be non-final: {result:?}"
                );
            }
        }
    }

    #[test]
    fn admit_transaction_rejects_a_transaction_with_no_prevouts() {
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                ..MempoolLimits::default()
            }))),
            None,
            ValidationEngine::Native,
            None,
        );
        let tx = standard_tx(0x44);
        let generation = gateway.stable_generation().expect("generation is even");
        let sequence = gateway.read().sequence_number();
        let request = AdmissionRequest {
            tx: Arc::new(tx),
            context: PackageTxContext {
                fee: 1_000,
                vsize: 100,
                sigop_cost: 0,
                missing_inputs: false,
            },
            prevouts: Vec::new(),
            prevout_meta: hashbrown::HashMap::new(),
            csv_active: false,
            next_block_script_flags: bitcoin_rs_consensus::script::VerifyFlags::STANDARD,
            locktime_cutoff: 0,
            max_feerate_sat_per_kvb: None,
            time: 1,
            height: 1,
            origin: AdmissionOrigin::Rpc,
            expected_generation: generation,
            expected_sequence: sequence,
        };
        let result = gateway.admit_transaction(request);
        assert!(
            matches!(result, Err(AdmitError::Consensus)),
            "a non-coinbase tx with no prevouts must be rejected: {result:?}"
        );
        assert!(gateway.read().is_empty());
    }
    #[test]
    fn admit_transaction_rejects_duplicate_inputs_as_consensus() {
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                ..MempoolLimits::default()
            }))),
            None,
            ValidationEngine::Native,
            None,
        );
        let mut tx = standard_tx(0x45);
        tx.inputs.push(tx.inputs[0].clone());
        let generation = gateway.stable_generation().expect("generation is even");
        let sequence = gateway.read().sequence_number();
        let request = AdmissionRequest {
            tx: Arc::new(tx.clone()),
            context: PackageTxContext {
                fee: 1_000,
                vsize: 100,
                sigop_cost: 0,
                missing_inputs: false,
            },
            prevouts: vec![(
                tx.inputs[0].previous_output,
                TxOut {
                    value: Amount::from_sat(11_000),
                    script_pubkey: Script::new(),
                },
            )],
            prevout_meta: hashbrown::HashMap::new(),
            csv_active: false,
            next_block_script_flags: bitcoin_rs_consensus::script::VerifyFlags::STANDARD,
            locktime_cutoff: 0,
            max_feerate_sat_per_kvb: None,
            time: 1,
            height: 1,
            origin: AdmissionOrigin::Rpc,
            expected_generation: generation,
            expected_sequence: sequence,
        };
        let result = gateway.admit_transaction(request);
        assert!(
            matches!(result, Err(AdmitError::Consensus)),
            "duplicate inputs must fail consensus verification: {result:?}"
        );
        assert!(gateway.read().is_empty());
    }

    #[test]
    fn input_structure_checks_follow_generation_and_sequence_guards() {
        let gateway = gateway_with(None);
        let mut candidate = standard_tx(93);
        candidate.inputs.push(candidate.inputs[0].clone());
        candidate.inputs[0].witness = Witness::from_stack(vec![vec![1]]);
        let origin = AdmissionOrigin::Peer(crate::PeerToken {
            endpoint: Some(bitcoin_rs_consensus::primitives::PeerEndpoint::Ip(
                core::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
            )),
            addr: Some(bitcoin_rs_consensus::primitives::PeerEndpoint::from((
                [127, 0, 0, 1],
                8333,
            ))),
            connection_id: 7,
        });
        let request = admit_request(&gateway, &candidate, origin);
        gateway.chain_generation.store(2, Ordering::Release);
        assert_eq!(
            gateway.admit_transaction(request),
            Err(AdmitError::GenerationChanged)
        );
        assert_eq!(gateway.recent_rejects_count(), 0);

        let request = admit_request(&gateway, &candidate, origin);
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&tx(94)))
            .expect("fixture insert");
        assert_eq!(
            gateway.admit_transaction(request),
            Err(AdmitError::MempoolChanged)
        );
        assert_eq!(gateway.recent_rejects_count(), 0);
        assert_eq!(gateway.orphan_count(), 0);
        assert_eq!(gateway.read().sequence_number(), 1);
    }

    #[test]
    fn input_structure_nonstandard_transactions_keep_policy_precedence() {
        use crate::standardness::{AcceptanceRejectReason, StandardnessError};
        for (version, witness_len, reason) in [
            (0, 1, StandardnessError::Version),
            (2, 400_001, StandardnessError::Weight),
        ] {
            let gateway = gateway_with(None);
            let mut candidate = standard_tx(95);
            candidate.version = version;
            candidate.inputs.push(candidate.inputs[0].clone());
            candidate.inputs[0].witness = Witness::from_stack(vec![vec![0; witness_len]]);
            let request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
            assert_eq!(
                gateway.admit_transaction(request),
                Err(AdmitError::Policy(AcceptanceRejectReason::NonStandard(
                    reason
                )))
            );
            assert!(gateway.read().is_empty());
            assert_eq!(gateway.read().sequence_number(), 0);
        }
    }

    #[test]
    fn nonstandard_inputs_rejection_caches_the_txid_for_witness_transactions() {
        use crate::standardness::{AcceptanceRejectReason, StandardnessError};
        let gateway = gateway_with(None);
        let mut candidate = standard_tx(95);
        candidate.inputs[0].witness = Witness::from_stack(vec![vec![1]]);
        let origin = AdmissionOrigin::Peer(crate::PeerToken {
            endpoint: Some(bitcoin_rs_consensus::primitives::PeerEndpoint::Ip(
                core::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
            )),
            addr: Some(bitcoin_rs_consensus::primitives::PeerEndpoint::from((
                [127, 0, 0, 1],
                8333,
            ))),
            connection_id: 7,
        });
        let mut request = admit_request(&gateway, &candidate, origin);
        request.prevouts[0].1.script_pubkey = Script::new();
        assert_eq!(
            gateway.admit_transaction(request),
            Err(AdmitError::Policy(AcceptanceRejectReason::NonStandard(
                StandardnessError::NonStandardInput
            )))
        );
        let lifecycle = gateway.lifecycle.lock();
        assert!(
            lifecycle.rejects_inventory(Hash256::from(candidate.txid()), false),
            "a txid announcement must be filtered after bad-txns-nonstandard-inputs"
        );
        assert!(lifecycle.rejects_inventory(Hash256::from(candidate.wtxid()), true));
    }

    fn p2sh_prevout() -> TxOut {
        let mut script = Vec::with_capacity(23);
        script.push(0xa9);
        script.push(0x14);
        script.extend_from_slice(&[0x2a; 20]);
        script.push(0x87);
        TxOut {
            value: Amount::from_sat(11_000),
            script_pubkey: script.into(),
        }
    }

    #[test]
    fn admission_fills_script_cache_under_next_block_flags() {
        let cache = Arc::new(bitcoin_rs_consensus::ScriptExecutionCache::new());
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            Some(Arc::clone(&cache)),
        ));
        let candidate = standard_tx(0x60);
        let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
        request.next_block_script_flags = bitcoin_rs_consensus::script::VerifyFlags::MANDATORY;
        let outcome = gateway
            .admit_transaction(request)
            .expect("standard-shaped spend must admit");
        assert!(matches!(outcome, AdmitOutcome::Committed(_)));
        assert!(cache.take(
            candidate.wtxid(),
            bitcoin_rs_consensus::script::VerifyFlags::MANDATORY
        ));
        assert!(!cache.take(
            candidate.wtxid(),
            bitcoin_rs_consensus::script::VerifyFlags::STANDARD
        ));
    }

    #[test]
    fn rejected_admission_fills_no_script_cache_entry() {
        let cache = Arc::new(bitcoin_rs_consensus::ScriptExecutionCache::new());
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            Some(Arc::clone(&cache)),
        ));
        let candidate = standard_tx(0x61);
        let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
        request.prevouts = vec![(request.prevouts[0].0, p2sh_prevout())];
        request.next_block_script_flags = bitcoin_rs_consensus::script::VerifyFlags::MANDATORY;
        let result = gateway.admit_transaction(request);
        assert!(matches!(result, Err(AdmitError::Consensus)));
        assert!(!cache.take(
            candidate.wtxid(),
            bitcoin_rs_consensus::script::VerifyFlags::MANDATORY
        ));
    }

    #[test]
    fn package_fee_cap_keeps_signed_extremes_exact() {
        let gateway = gateway_with(None);
        let candidate = standard_tx(0x63);
        let request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
        for (fee, rejects) in [
            (i128::MIN, false),
            (-1, false),
            (0, false),
            (i128::from(u64::MAX) + i128::from(i64::MAX), true),
            (i128::MAX, true),
        ] {
            let mut prepared = MempoolGateway::prepare_admission(
                &gateway.read(),
                &request,
                AdmissionMode::PackageRpcSubmit(Some(1_000)),
                crate::admission::AdmissionFence::Stable,
                gateway.engine(),
            );
            assert!(prepared.rejection.is_none());
            prepared.fact.modified_fee = Some(fee);
            prepared.fact.effective_fee_rate = None;
            prepared.check_package_max_feerate(Some(1_000));
            assert_eq!(
                prepared.fact.reject_reason,
                rejects.then_some(crate::standardness::AcceptanceRejectReason::MaxFeeExceeded)
            );
        }
    }

    #[test]
    fn fee_capped_admission_fills_no_script_cache_entry() {
        let cache = Arc::new(bitcoin_rs_consensus::ScriptExecutionCache::new());
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            Some(Arc::clone(&cache)),
        ));
        let candidate = standard_tx(0x62);
        let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
        request.max_feerate_sat_per_kvb = Some(1);
        request.next_block_script_flags = bitcoin_rs_consensus::script::VerifyFlags::MANDATORY;
        let result = gateway.admit_transaction(request);
        assert!(matches!(
            result,
            Err(AdmitError::Policy(
                crate::standardness::AcceptanceRejectReason::MaxFeeExceeded
            ))
        ));
        assert!(!cache.take(
            candidate.wtxid(),
            bitcoin_rs_consensus::script::VerifyFlags::MANDATORY
        ));
    }

    #[test]
    fn verify_without_commit_fills_nothing() {
        let cache = Arc::new(bitcoin_rs_consensus::ScriptExecutionCache::new());
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            Some(Arc::clone(&cache)),
        ));
        let candidate = standard_tx(0x63);
        let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
        request.next_block_script_flags = bitcoin_rs_consensus::script::VerifyFlags::MANDATORY;
        {
            let pool = gateway.read();
            let mut prepared = MempoolGateway::prepare_admission(
                &pool,
                &request,
                AdmissionMode::Single,
                crate::admission::AdmissionFence::Stable,
                gateway.engine(),
            );
            prepared.verify(&request, gateway.script_cache());
        }
        assert!(!cache.take(
            candidate.wtxid(),
            bitcoin_rs_consensus::script::VerifyFlags::MANDATORY
        ));
        let outcome = gateway
            .admit_transaction(request)
            .expect("standard-shaped spend must admit");
        assert!(matches!(outcome, AdmitOutcome::Committed(_)));
        assert!(cache.take(
            candidate.wtxid(),
            bitcoin_rs_consensus::script::VerifyFlags::MANDATORY
        ));
    }

    fn script_stage_rejection(engine: ValidationEngine) -> Option<(AdmitError, RejectScope)> {
        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        })));
        let gateway = MempoolGateway::new(Arc::clone(&pool), None, engine, None);
        let candidate = standard_tx(0x51);
        let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
        request.prevouts = vec![(request.prevouts[0].0, p2sh_prevout())];
        let guard = pool.read();
        let mut prepared = MempoolGateway::prepare_admission(
            &guard,
            &request,
            AdmissionMode::Single,
            crate::admission::AdmissionFence::Stable,
            engine,
        );
        prepared.verify(&request, None);
        prepared.rejection
    }

    #[test]
    fn genuine_script_verdicts_on_strippable_prevouts_stay_witness_scoped() {
        assert!(matches!(
            script_stage_rejection(ValidationEngine::Native),
            Some((AdmitError::Consensus, RejectScope::Witness))
        ));
    }

    #[test]
    fn only_genuine_script_verdicts_are_witness_strippable() {
        use bitcoin_rs_consensus::ConsensusError;
        let prevouts = [(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 0),
            p2sh_prevout(),
        )];
        assert!(super::witness_strippable_failure(
            &ConsensusError::Script {
                input_index: 0,
                reason: "script failed: false".to_owned(),
                engine: bitcoin_rs_consensus::ScriptEngine::Native,
            },
            &prevouts,
        ));
        assert!(!super::witness_strippable_failure(
            &ConsensusError::UnsupportedEngine {
                engine: ValidationEngine::Kernel,
            },
            &prevouts,
        ));
        assert!(!super::witness_strippable_failure(
            &ConsensusError::PrevoutCount {
                input_count: 2,
                prevout_count: 1,
            },
            &prevouts,
        ));
        assert!(!super::witness_strippable_failure(
            &ConsensusError::Kernel("kernel parse failed".to_owned()),
            &prevouts,
        ));
    }

    fn floor_trim_gateway_with_filler() -> MempoolGateway {
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                max_total_bytes: unit() * 3 / 2,
                ..MempoolLimits::default()
            }))),
            None,
            ValidationEngine::Native,
            None,
        );
        let filler = standard_tx(70);
        let outcome =
            gateway.admit_transaction(admit_request(&gateway, &filler, AdmissionOrigin::Rpc));
        assert!(
            matches!(outcome, Ok(AdmitOutcome::Committed(_))),
            "filler must commit: {outcome:?}"
        );
        gateway
    }

    fn floor_trim_candidate(gateway: &MempoolGateway) -> AdmissionRequest {
        let shed = standard_tx(71);
        let mut request = admit_request(gateway, &shed, AdmissionOrigin::Rpc);
        request.context.fee = 100;
        request.prevouts[0].1.value = Amount::from_sat(10_100);
        request
    }

    #[test]
    fn admit_transaction_full_refusal_bumps_the_floor() {
        let gateway = floor_trim_gateway_with_filler();
        assert_eq!(gateway.read().min_fee_sat_per_kvb(1), 0);

        let request = floor_trim_candidate(&gateway);
        let error = gateway
            .admit_transaction(request)
            .expect_err("candidate cannot survive trimming");
        assert!(
            matches!(
                error,
                AdmitError::Policy(crate::standardness::AcceptanceRejectReason::Replacement(
                    crate::RbfError::Mempool(crate::MempoolError::Full)
                ))
            ),
            "refusal keeps the mempool-full report: {error:?}"
        );
        assert_eq!(gateway.read().min_fee_sat_per_kvb(1), 2_000);
        assert_eq!(gateway.read().len(), 1);
    }

    #[test]
    fn admit_transaction_invalid_script_refusal_leaves_the_floor() {
        let gateway = floor_trim_gateway_with_filler();

        let mut request = floor_trim_candidate(&gateway);
        request.prevouts[0].1.script_pubkey = Script::from_bytes(p2pkh_prevout_script());
        let error = gateway
            .admit_transaction(request)
            .expect_err("candidate cannot survive trimming");
        assert!(
            matches!(
                error,
                AdmitError::Policy(crate::standardness::AcceptanceRejectReason::Replacement(
                    crate::RbfError::Mempool(crate::MempoolError::Full)
                ))
            ),
            "refusal keeps the mempool-full report: {error:?}"
        );
        assert_eq!(gateway.read().min_fee_sat_per_kvb(1), 0);
        assert_eq!(gateway.read().len(), 1);
    }

    #[test]
    fn admit_transaction_overcap_refusal_earns_no_bump() {
        let gateway = floor_trim_gateway_with_filler();

        let mut request = floor_trim_candidate(&gateway);
        request.max_feerate_sat_per_kvb = Some(500);
        let error = gateway
            .admit_transaction(request)
            .expect_err("candidate cannot survive trimming");
        assert!(
            matches!(
                error,
                AdmitError::Policy(crate::standardness::AcceptanceRejectReason::Replacement(
                    crate::RbfError::Mempool(crate::MempoolError::Full)
                ))
            ),
            "refusal keeps the mempool-full report: {error:?}"
        );
        assert_eq!(gateway.read().min_fee_sat_per_kvb(1), 0);
        assert_eq!(gateway.read().len(), 1);
    }

    #[test]
    fn admission_prepared_before_a_floor_raise_is_retried() {
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                max_total_bytes: unit() * 3 / 2,
                ..MempoolLimits::default()
            }))),
            None,
            ValidationEngine::Native,
            None,
        );
        gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(tx(90)), 100, 9_000, 1, 7, 0),
            )
            .expect("seat");
        let (generation, sequence, stamp) = {
            let pool = gateway.read();
            (
                gateway.stable_generation().expect("even"),
                pool.sequence_number(),
                pool.policy_stamp(),
            )
        };
        let error = gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(
                    Arc::new({
                        let mut padded = tx(92);
                        padded.outputs[0].script_pubkey =
                            vec![92; usize::try_from(unit()).unwrap_or(usize::MAX)].into();
                        padded
                    }),
                    950,
                    100,
                    1,
                    7,
                    0,
                ),
            )
            .expect_err("oversized");
        assert_eq!(error, crate::MempoolError::Full);
        assert!(gateway.read().min_fee_sat_per_kvb(1) > 0);
        {
            let pool = gateway.read();
            assert!(!stamp.matches(&pool));
            assert_eq!(
                gateway.check_admission_state(
                    &pool,
                    generation,
                    sequence,
                    crate::admission::AdmissionFence::Stable,
                    Some(stamp),
                ),
                Err(AdmitError::MempoolChanged)
            );
        }
    }

    #[test]
    fn remove_for_block_stamps_the_floor_for_decay() {
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 1_000,
                max_total_bytes: 2 * unit(),
                ..MempoolLimits::default()
            }))),
            None,
            ValidationEngine::Native,
            None,
        );
        gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(tx(1)), 200, 400, 1, 1, 0),
            )
            .expect("low");
        gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(tx(2)), 200, 800, 1, 1, 0),
            )
            .expect("high");
        gateway
            .enforce_size_limit(AdmissionOrigin::Rpc, unit())
            .expect("eviction");
        assert_eq!(gateway.read().min_fee_sat_per_kvb(1_000), 3_000);
        gateway
            .remove_for_block(
                AdmissionOrigin::Rpc,
                &crate::settlement::TransitionFacts::from_txs(&[]),
                8,
                1_000,
            )
            .expect("block settlement commits");
        assert_eq!(
            gateway.read().min_fee_sat_per_kvb(1_000 + 12 * 60 * 60),
            1_500
        );
    }

    #[test]
    fn expire_returns_none_when_fresh_and_some_when_stale() {
        use crate::policy::MEMPOOL_EXPIRY_SECS;
        let observer = Arc::new(RecordingObserver::default());
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Some((dyn_observer(&observer), BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        );
        let now = MEMPOOL_EXPIRY_SECS + 1;
        let fresh = tx(80);
        gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(fresh), 100, 1_000, now, 1, 0),
            )
            .expect("fresh");
        assert!(!gateway.read().has_expired_entries(now));
        let sequence = gateway.read().sequence_number();
        assert!(
            gateway
                .expire(AdmissionOrigin::Rpc, now)
                .expect("expiry check commits")
                .is_none()
        );
        assert_eq!(gateway.read().sequence_number(), sequence);

        let stale = tx(81);
        let stale_txid = stale.txid();
        gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(stale), 100, 1_000, 0, 1, 0),
            )
            .expect("stale");
        observer.seen.lock().clear();
        let expired = gateway
            .expire(AdmissionOrigin::Rpc, now)
            .expect("expiry commits")
            .expect("stale entries expire");
        assert_eq!(expired.len(), 1);
        assert_eq!(
            *observer.seen.lock(),
            vec![(hash(&stale_txid), removed(RemovalReason::Expiry))],
            "expiry publishes exactly one Expiry change"
        );
        assert!(
            gateway
                .expire(AdmissionOrigin::Rpc, now)
                .expect("expiry check commits")
                .is_none()
        );
    }
}
