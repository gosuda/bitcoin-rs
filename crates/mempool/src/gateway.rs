//! The single mutation gateway in front of the mempool.
//!
//! Every production mempool mutation routes through [`MempoolGateway`]: it
//! owns the pool's write lock, commits the mutation, and then enqueues the
//! ordered [`MutationEnvelope`] for the optional [`MempoolObserver`] — always
//! in commit order, by construction. Publication is eventual: a nested or
//! concurrent mutation call may return before its callback runs, and the
//! elected drainer completes every queued callback exactly once, in
//! sequence order, with no gateway lock held. After this, no production
//! code outside the gateway takes the mempool write lock — lookups go
//! through the [`MempoolGateway::read`] passthrough. One pool, one
//! gateway: [`MempoolGateway::shared`] interns a single
//! [`MempoolGateway`] per pool `Arc` identity, so every route to a pool
//! shares one publish queue and one observer slot.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use bitcoin_rs_primitives::{Tx, Txid};
use hashbrown::HashSet;
use parking_lot::{Mutex, RwLock, RwLockReadGuard};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Why a chain-change reservation or finish failed.
///
/// Every variant leaves the gateway's chain generation unchanged: a failed
/// `begin_chain_change` stores nothing, and a failed `finish` leaves the
/// gateway odd so admission stays closed until a later finish succeeds.
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
}

// ---------------------------------------------------------------------------
// Atomic admission — one generation-revalidated gateway operation.
// ---------------------------------------------------------------------------

/// Resolved context and exact state tokens for one admission attempt.
///
/// The caller captures `expected_generation` (an even value read from
/// [`MempoolGateway::stable_generation`]) and `expected_sequence` (read from
/// the pool under a read guard) **before** resolving UTXO data. The gateway
/// re-checks both under the write lock so a chain change or mempool mutation
/// between capture and commit is caught as a transient error, not a stale
/// write.
pub struct AdmissionRequest {
    /// The transaction to admit.
    pub tx: Arc<Tx>,
    /// Resolved per-transaction context (fee, vsize, sigop cost, missing
    /// inputs) from the mempool and UTXO set.
    pub context: crate::standardness::PackageTxContext,
    /// Caller-supplied maximum fee rate in sat/kvB; `None` means no cap.
    pub max_feerate_sat_per_kvb: Option<u64>,
    /// Wall-clock seconds for the mempool entry timestamp.
    pub time: u64,
    /// Current applied block height for the mempool entry.
    pub height: u32,
    /// How the transaction entered the node.
    pub origin: AdmissionOrigin,
    /// Exact even chain generation the caller captured before admission.
    pub expected_generation: u64,
    /// Exact mempool sequence the caller captured before admission.
    pub expected_sequence: u64,
}

/// The outcome of one admission attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmitOutcome {
    /// The transaction was committed to the pool. The result carries every
    /// `Removed` change in commit order followed by exactly one `Accepted`.
    Committed(crate::mutation::MutationResult),
    /// The exact transaction was already present. No envelope, sequence, or
    /// publication was produced — the caller returns normal txid success.
    AlreadyKnown,
}

/// Why an admission attempt did not commit.
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
}

/// Interns one [`MempoolGateway`] per pool `Arc` identity.
///
/// This is the crate's one piece of process-global state, and it exists
/// because the apply path (`ApplyHandles`) is frozen in this batch and
/// cannot carry a gateway handle: reorg and run-time composition reach the
/// run-composed instance through the pool `Arc` they already hold. The
/// registry holds weak references only, so it never keeps a gateway or a
/// pool alive. Handoff note for ING-R34: once `ApplyHandles` gains a
/// `mempool_gateway` field, the reorg caller can read the handle instead
/// and `shared` shrinks to run-time composition plus tests.
use crate::EntryId;
use crate::entry::MempoolEntry;
use crate::mutation::{AdmissionOrigin, MutationEnvelope, MutationResult};
use crate::pool::{Mempool, MempoolError, PrioritiseError};
use crate::rbf::{RbfError, ReplacementCandidate};

static REGISTRY: LazyLock<Mutex<Vec<Weak<MempoolGateway>>>> =
    LazyLock::new(|| Mutex::new(alloc::vec::Vec::new()));

/// Receives every committed mempool mutation, exactly once, in sequence
/// order.
///
/// Observers are best-effort mirrors: they run after the mutation is
/// already committed, so their failures never affect pool state, and a
/// panic in `on_mutation` is contained by the gateway — the drainer
/// records it and continues with the remaining queued batches. Callbacks
/// run with no gateway lock held, so an observer may route mutations back
/// through the gateway: a nested call commits, enqueues, and returns
/// immediately, and its publication completes after the in-flight callback
/// — possibly after the nested call itself has already returned to its
/// caller.
pub trait MempoolObserver: Send + Sync {
    /// Called once per committed, non-empty [`MutationEnvelope`].
    fn on_mutation(&self, envelope: &MutationEnvelope);
}

/// Fans one committed mutation out to several named observers.
///
/// Each leg runs under its own [`std::panic::catch_unwind`]: a panicking
/// leg is counted (`mempool_observer_leg_failed_total{leg}`) and logged
/// with its name, and the later legs still run. The gateway's outer
/// `catch_unwind` around the composite stays as the backstop. Legs inherit
/// the [`MempoolObserver`] contract: best-effort mirrors that run with no
/// gateway lock held, so a leg may re-enter the gateway.
#[derive(Default)]
pub struct CompositeObserver {
    /// Guarded because a subsystem may attach its leg after the gateway is
    /// interned. Publication clones the list under this lock and releases it
    /// before calling any leg, so a leg re-entering the gateway cannot
    /// deadlock against an attach.
    legs: Mutex<Vec<(&'static str, Arc<dyn MempoolObserver>)>>,
}

impl CompositeObserver {
    /// An empty composite; attach legs with [`Self::add_leg`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            legs: Mutex::new(alloc::vec::Vec::new()),
        }
    }

    /// Appends a named leg. Names identify the leg in failure logs and
    /// metrics only; order is publication order.
    pub fn add_leg(&self, name: &'static str, leg: Arc<dyn MempoolObserver>) {
        self.legs.lock().push((name, leg));
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
            // A hostile panic payload can panic from Drop. Suppress the
            // replacement payload so it cannot escape this boundary.
            let _nested_payload = core::mem::ManuallyDrop::new(nested_payload);
            true
        },
        |()| false,
    );
    (message, disposal_panicked)
}

impl MempoolObserver for CompositeObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        // Clone the roster, then release: a leg is free to re-enter the
        // gateway, and a re-entrant attach must not deadlock behind us.
        let legs = self.legs.lock().clone();
        for (name, leg) in &legs {
            let outcome = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
                leg.on_mutation(envelope);
            }));
            if let Err(panic_payload) = outcome {
                metrics::counter!("mempool_observer_leg_failed_total", "leg" => *name).increment(1);
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

/// The mutation publication queue state, protected by the `publish` mutex.
///
/// Non-empty envelopes are enqueued under the pool write lock; one drainer is
/// elected if none exists. The drainer pops batches one at a time —
/// releasing the publish-state lock before every observer call — and
/// returns the state to idle only once the queue is empty.
struct PublishState {
    /// Committed, non-empty envelopes awaiting their observer callback, in
    /// commit order.
    queue: VecDeque<MutationEnvelope>,
    /// Whether exactly one caller is draining the queue.
    draining: bool,
}

/// Owns the mempool's write lock and publishes ordered mutation events.
///
/// # Ordering invariant
///
/// Every mutating method flows through exactly one path, [`Self::commit`],
/// which runs, in this exact order:
///
/// 1. take the pool write lock,
/// 2. mutate and assign per-change mempool sequences,
/// 3. while still holding the write lock, enqueue the non-empty envelope on
///    the publish state's FIFO queue and elect a drainer if none exists,
/// 4. release the write lock and the publish-state lock,
/// 5. the elected drainer pops batches one at a time — releasing the
///    publish-state lock before every observer call — and returns the
///    publish state to idle only once the queue is empty.
///
/// Commits serialize under the write lock and step 3 enqueues under that
/// same ownership, so the queue order is the commit order and the sequence
/// order: every committed, non-empty batch is published exactly once, in
/// order, even across nested and concurrent callers. Publication is
/// eventual, not synchronous: a nested or concurrent mutation enqueues
/// and returns while a drainer exists, and its callback may run after
/// that call has returned. No gateway lock is ever held across an
/// observer call, so observers may re-enter the gateway freely. An
/// observer panic is caught and recorded; the drainer continues with
/// the remaining queue and only then returns to idle. Empty results and
/// an absent observer enqueue nothing, allocate nothing, and spawn no
/// thread.
pub struct MempoolGateway {
    pool: Arc<RwLock<Mempool>>,
    /// The one observer slot, held as the composite so a second subsystem
    /// can attach its own named leg after construction. An absent composite
    /// means nobody is listening and the publish path stays allocation-free.
    observer: Option<Arc<CompositeObserver>>,
    publish: Mutex<PublishState>,
    /// Even means stable; odd means a chain change is active or a failed
    /// chain change has closed admission. Initialized to `0` (even/stable)
    /// in [`Self::shared`]. Compare only for exact equality — never order or
    /// subtract wrapping counters.
    chain_generation: AtomicU64,
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
    /// Wraps `pool` and optionally installs `observer`.
    ///
    /// Pass `None` — or use the node's no-op publisher behind its observer —
    /// when no `--zmq-pub-sequence` endpoint is configured.
    #[must_use]
    pub fn new(pool: Arc<RwLock<Mempool>>, observer: Option<Arc<dyn MempoolObserver>>) -> Self {
        let composite = observer.map(|observer| {
            let composite = CompositeObserver::new();
            composite.add_leg("primary", observer);
            Arc::new(composite)
        });
        Self {
            pool,
            observer: composite,
            publish: Mutex::new(PublishState {
                queue: VecDeque::new(),
                draining: false,
            }),
            chain_generation: AtomicU64::new(0),
        }
    }

    /// Attaches another named leg to this gateway's observer slot.
    ///
    /// Returns `Err` when the gateway was built without an observer: there
    /// is no composite to extend, and silently creating one here would
    /// diverge from the slot the production wiring installed.
    pub fn attach_observer_leg(
        &self,
        name: &'static str,
        leg: Arc<dyn MempoolObserver>,
    ) -> Result<(), &'static str> {
        let Some(composite) = self.observer.as_ref() else {
            return Err("gateway has no observer slot to extend");
        };
        composite.add_leg(name, leg);
        Ok(())
    }

    /// Returns the one gateway interned for `pool`.
    ///
    /// Two callers holding clones of the same pool `Arc` get the same
    /// gateway — one publish queue, one observer slot. Distinct pools get
    /// distinct gateways. Dead entries are pruned on every call. Lookup
    /// upgrades the weak reference FIRST and only then compares pool
    /// pointers: a live gateway pins its pool alive, so two live `Arc`s
    /// comparing pointer-equal are the same allocation, which makes ABA
    /// (a freed pool's address reused by a new allocation) impossible.
    pub fn shared(pool: Arc<RwLock<Mempool>>) -> Arc<Self> {
        let mut gateways = REGISTRY.lock();
        gateways.retain(|weak| weak.upgrade().is_some());
        for weak in &*gateways {
            if let Some(candidate) = weak.upgrade() {
                if Arc::ptr_eq(&candidate.pool, &pool) {
                    return candidate;
                }
            }
        }
        let gateway = Arc::new(Self::new(pool, None));
        gateways.push(Arc::downgrade(&gateway));
        gateway
    }

    /// Returns the one gateway interned for `pool`, constructed with
    /// `observer`.
    ///
    /// Like [`Self::shared`] but the newly created gateway carries the
    /// supplied observer. If a gateway is already interned for `pool`, it
    /// is returned as-is (its observer is unchanged). The caller is
    /// expected to be the first interner — production code constructs the
    /// gateway through [`crate::state::NodeState`] before any `shared`
    /// call — so the observer lands on the one interned instance.
    pub fn shared_with(
        pool: Arc<RwLock<Mempool>>,
        observer: Arc<dyn MempoolObserver>,
    ) -> Arc<Self> {
        let mut gateways = REGISTRY.lock();
        gateways.retain(|weak| weak.upgrade().is_some());
        for weak in &*gateways {
            if let Some(candidate) = weak.upgrade() {
                if Arc::ptr_eq(&candidate.pool, &pool) {
                    return candidate;
                }
            }
        }
        let gateway = Arc::new(Self::new(pool, Some(observer)));
        gateways.push(Arc::downgrade(&gateway));
        gateway
    }

    /// Returns `true` when the gateway was constructed with an observer.
    #[must_use]
    pub fn has_observer(&self) -> bool {
        self.observer.is_some()
    }

    /// Raw pool access for test fixture staging and read-side composition
    /// only. The raw-site audit's production pattern matches
    /// `.pool().write()` too; production mutations must go through the
    /// gateway so observers stay in the loop.
    pub fn pool(&self) -> &Arc<RwLock<Mempool>> {
        &self.pool
    }

    /// Read passthrough for lookup callers. Never mutate through this guard:
    /// mutations must go through the gateway so observers stay in the loop.
    pub fn read(&self) -> RwLockReadGuard<'_, Mempool> {
        self.pool.read()
    }

    /// Returns the exact even chain generation, or `None` when a chain
    /// change is active (odd) or a failed chain change has closed admission.
    ///
    /// Uses an `Acquire` load so reads after this call observe writes that
    /// preceded the last `Release` store. Compare the returned value only
    /// for exact equality — never order or subtract wrapping counters.
    #[must_use]
    pub fn stable_generation(&self) -> Option<u64> {
        let value = self.chain_generation.load(Ordering::Acquire);
        value.is_multiple_of(2).then_some(value)
    }

    /// Reserves the next chain-change generation and returns a guard that
    /// owns the exact odd value and the reserved next even value.
    ///
    /// Takes `self.pool.write()` before it reads or changes the generation,
    /// so an inflight admission that already holds the write lock blocks
    /// `begin_chain_change` until it releases. It rejects an odd current
    /// value (a chain change is already active). It uses checked arithmetic
    /// to reserve both the odd value and its following even value before it
    /// stores anything; if either increment would overflow, it returns an
    /// error and leaves the generation unchanged. It then stores the odd
    /// value with `Release` ordering and drops the pool guard.
    ///
    /// The returned guard has no `Drop` that changes generation: dropping,
    /// unwinding, or returning an error leaves the gateway odd. Only
    /// [`ChainChangeGuard::finish`] may compare-exchange the odd value to
    /// the reserved even value.
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

    /// Commits `pool.insert_entry` and publishes its result.
    pub fn insert_entry(
        &self,
        origin: AdmissionOrigin,
        entry: MempoolEntry,
    ) -> Result<MutationResult, MempoolError> {
        self.commit(origin, move |pool| pool.insert_entry(entry))
    }

    /// Reconsiders transactions that left the pool with a disconnected block.
    ///
    /// `entries` must arrive in dependency order — parents before the
    /// transactions spending them — which is the order the reversed
    /// disconnect walk produces. Each candidate gets exactly one
    /// commit-and-publish insert; a candidate the pool refuses is recorded,
    /// and any later candidate spending a refused txid is withheld, so a
    /// rejected parent can never leave a partially admitted family behind.
    /// The same withholding follows a parent whose own successful insert
    /// removed it again — size-limit eviction, for example — because a
    /// parent is available to descendants only while it remains in the
    /// pool: every `Removed` change a committed insert reports marks that
    /// txid unavailable to the rest of the batch. An empty iterator is a
    /// no-op: nothing is committed, nothing is published, and the mempool
    /// sequence does not move.
    pub fn reconsider_disconnected(
        &self,
        origin: AdmissionOrigin,
        entries: impl IntoIterator<Item = MempoolEntry>,
    ) -> Vec<MutationResult> {
        let mut refused: HashSet<Txid> = HashSet::new();
        let mut committed = Vec::new();
        for entry in entries {
            let txid = entry.txid;
            let spends_refused = entry
                .tx
                .inputs
                .iter()
                .any(|input| refused.contains(&input.previous_output.txid));
            if spends_refused {
                refused.insert(txid);
                continue;
            }
            match self.insert_entry(origin, entry) {
                Ok(result) => {
                    // A successful insert does not promise the entry stayed:
                    // the same commit can evict it — or any other entry —
                    // under size pressure. Whatever the result says left the
                    // pool is unavailable to later spenders, exactly as if
                    // the pool had refused it up front.
                    for removed in result.removed_txids() {
                        refused.insert(removed);
                    }
                    committed.push(result);
                }
                Err(_) => {
                    refused.insert(txid);
                }
            }
        }
        committed
    }

    /// Commits `pool.replace_transaction` and publishes its result.
    pub fn replace_transaction(
        &self,
        origin: AdmissionOrigin,
        candidate: ReplacementCandidate,
        time: u64,
        height: u32,
        sigop_cost: u32,
    ) -> Result<MutationResult, RbfError> {
        self.commit(origin, move |pool| {
            pool.replace_transaction(candidate, time, height, sigop_cost)
        })
    }

    /// One atomic admission operation. Takes `pool.write()` once, then checks
    /// in this order before any policy mutation:
    ///
    /// 1. exact chain generation equals the request value and is even,
    /// 2. current `pool.sequence_number()` equals the request sequence,
    /// 3. exact transaction identity is already present.
    ///
    /// The exact duplicate returns [`AdmitOutcome::AlreadyKnown`] successfully
    /// and creates no envelope, sequence, or publication. For a new
    /// transaction, policy is evaluated under the same write guard and the
    /// established `replace_transaction` path performs the mutation —
    /// preserving under-lock BIP125 and package-limit revalidation. On
    /// success, one `MutationResult` whose ordered removals precede exactly
    /// one accepted change is published via the existing commit/publish seam.
    ///
    /// Any mismatch or rejection returns before publish-mutex acquisition and
    /// before mutation.
    #[allow(clippy::needless_pass_by_value)]
    pub fn admit_transaction(&self, request: AdmissionRequest) -> Result<AdmitOutcome, AdmitError> {
        // Test-only causal seam: parks the first admission BEFORE acquiring
        // the write lock so a cross-crate test can mutate the pool and
        // generation between the caller's capture and the gateway's
        // re-check, forcing a deterministic transient error. Disarmed, this
        // is a no-op. One shot: the park consumes the arm.
        #[cfg(any(test, feature = "test-seam"))]
        ordering_gate::park_if_armed(std::ptr::from_ref(self).expose_provenance());

        let mut pool = self.pool.write();

        // 1. Exact chain generation check (even and matches request).
        let generation = self.chain_generation.load(Ordering::Acquire);
        if generation != request.expected_generation || !generation.is_multiple_of(2) {
            return Err(AdmitError::GenerationChanged);
        }

        // 2. Exact mempool sequence check.
        if pool.sequence_number() != request.expected_sequence {
            return Err(AdmitError::MempoolChanged);
        }
        // 3. Exact duplicate → AlreadyKnown (no envelope, no sequence, no
        //    publication).
        let txid = request.tx.txid();
        if pool.contains_txid(&txid) {
            return Ok(AdmitOutcome::AlreadyKnown);
        }
        // 4. Policy evaluation under the same write guard. `evaluate_one`
        //    checks standardness, missing inputs, coinbase, min-relay,
        //    max-fee, and replacement — but NOT package limits (those are
        //    enforced by `replace_transaction` below).
        let policy = pool.policy_snapshot();
        let mempool_min_fee = crate::eviction::mempool_min_fee_sat_per_kvb(
            &pool,
            policy.incremental_relay_fee_sat_per_kvb,
        );
        let fact = crate::standardness::evaluate_one(
            &pool,
            &policy.standardness,
            &request.tx,
            request.context,
            request.max_feerate_sat_per_kvb,
            mempool_min_fee,
            policy.incremental_relay_fee_sat_per_kvb,
        );
        if let Some(reason) = fact.reject_reason {
            return Err(AdmitError::Policy(reason));
        }

        // 5. Mutate under the same write guard via `replace_transaction`,
        //    which handles BIP125 replacement, package limits, and insert.
        let candidate = ReplacementCandidate::new(
            Arc::clone(&request.tx),
            fact.vsize,
            fact.base_fee.unwrap_or(0),
            policy.incremental_relay_fee_sat_per_kvb,
        );
        let result = pool
            .replace_transaction(candidate, request.time, request.height, fact.sigop_cost)
            .map_err(|rbf| {
                // Map RbfError to the correct AcceptanceRejectReason variant.
                // `replace_transaction` re-checks replacement and package
                // limits; its errors must map to the same reason class the
                // preview would have reported.
                match rbf {
                    RbfError::Mempool(crate::pool::MempoolError::Policy(policy_err)) => {
                        AdmitError::Policy(
                            crate::standardness::AcceptanceRejectReason::PackageLimit(policy_err),
                        )
                    }
                    other => AdmitError::Policy(
                        crate::standardness::AcceptanceRejectReason::Replacement(other),
                    ),
                }
            })?;

        // 6. Enqueue for publication and elect a drainer if needed.
        let mut elected = false;
        if !result.changes.is_empty() && self.observer.is_some() {
            let mut publish = self.publish.lock();
            publish.queue.push_back(MutationEnvelope {
                origin: request.origin,
                result: result.clone(),
            });
            elected = !publish.draining;
            publish.draining = true;
        }
        drop(pool);
        if elected {
            self.drain();
        }
        Ok(AdmitOutcome::Committed(result))
    }

    /// Commits `pool.remove_entry_and_descendants` and publishes its result.
    pub fn remove_entry_and_descendants(
        &self,
        origin: AdmissionOrigin,
        id: EntryId,
    ) -> MutationResult {
        self.commit_infallible(origin, |pool| pool.remove_entry_and_descendants(id))
    }

    /// Commits `pool.remove_by_txid` and publishes its result.
    pub fn remove_by_txid(&self, origin: AdmissionOrigin, txid: &Txid) -> MutationResult {
        self.commit_infallible(origin, |pool| pool.remove_by_txid(txid))
    }

    /// Commits `pool.remove_for_block` and publishes its result.
    pub fn remove_for_block(
        &self,
        origin: AdmissionOrigin,
        block_txs: &[&Tx],
        block_txids: &[Txid],
        height: u32,
    ) -> MutationResult {
        self.commit_infallible(origin, |pool| {
            pool.remove_for_block(block_txs, block_txids, height)
        })
    }

    /// Commits `pool.evict_below_fee_rate` and publishes its result.
    pub fn evict_below_fee_rate(
        &self,
        origin: AdmissionOrigin,
        threshold_sat_per_kvb: u64,
    ) -> MutationResult {
        self.commit_infallible(origin, |pool| {
            pool.evict_below_fee_rate(threshold_sat_per_kvb)
        })
    }

    /// Commits `pool.enforce_size_limit` and publishes its result.
    pub fn enforce_size_limit(&self, origin: AdmissionOrigin, max_bytes: u64) -> MutationResult {
        self.commit_infallible(origin, |pool| pool.enforce_size_limit(max_bytes))
    }

    /// Commits `pool.clear` and publishes its result.
    pub fn clear(&self, origin: AdmissionOrigin) -> MutationResult {
        self.commit_infallible(origin, Mempool::clear)
    }

    /// Commits `pool.prioritise`. Never publishes: prioritisation emits no
    /// mutation change, so there is nothing to order.
    pub fn prioritise(&self, txid: Txid, fee_delta: i64) -> Result<(), PrioritiseError> {
        let mut pool = self.pool.write();
        pool.prioritise(txid, fee_delta)
    }

    /// The single commit-and-publish path every publishing mutation flows
    /// through. A failed `mutate` returns before the publish mutex is taken.
    /// Successful mutations acquire the publish mutex before releasing the
    /// pool guard, then call observers only after releasing the pool guard.
    fn commit<E>(
        &self,
        origin: AdmissionOrigin,
        mutate: impl FnOnce(&mut Mempool) -> Result<MutationResult, E>,
    ) -> Result<MutationResult, E> {
        let mut elected = false;
        let result = {
            let mut pool = self.pool.write();
            let result = mutate(&mut pool)?;
            if !result.changes.is_empty() && self.observer.is_some() {
                let mut publish = self.publish.lock();
                publish.queue.push_back(MutationEnvelope {
                    origin,
                    result: result.clone(),
                });
                elected = !publish.draining;
                publish.draining = true;
            }
            result
        };
        if elected {
            self.drain();
        }
        Ok(result)
    }

    /// The same path for pool methods that cannot fail.
    fn commit_infallible(
        &self,
        origin: AdmissionOrigin,
        mutate: impl FnOnce(&mut Mempool) -> MutationResult,
    ) -> MutationResult {
        let Ok(result) = self.commit(origin, |pool| {
            Ok::<_, core::convert::Infallible>(mutate(pool))
        });
        result
    }

    /// Publishes queued batches until the queue is empty, then returns
    /// the publish state to idle. Exactly one drainer runs at a time: the
    /// election in [`Self::commit`] is the only place `draining` turns
    /// true, and the idle transition happens under the same mutex only
    /// when the queue is empty, so no enqueue is lost. No gateway lock is
    /// held across an observer call: a nested or concurrent mutation
    /// commits, enqueues, and returns while this loop runs. A panicking
    /// observer is contained per batch — the mutation already committed,
    /// and the panic must not take the caller down with it. The default
    /// panic hook still prints the panic before it is caught here.
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
}

/// Owns an active chain-change reservation: the exact odd generation and
/// the reserved next even value.
///
/// Has no `Drop` that changes generation. Dropping, unwinding, or returning
/// an error leaves the gateway odd — admission stays closed. Only
/// [`Self::finish`] may compare-exchange the odd value to the reserved even
/// value. One guard covers one externally coherent chain operation: one
/// connect, one disconnect, one complete `apply_window`, or one full reorg.
#[derive(Debug)]
pub struct ChainChangeGuard {
    gateway: Arc<MempoolGateway>,
    odd: u64,
    even: u64,
}

impl ChainChangeGuard {
    /// Returns the exact odd generation this guard reserved.
    #[must_use]
    pub fn odd_generation(&self) -> u64 {
        self.odd
    }

    /// Returns the reserved even value `finish` will store on success.
    #[must_use]
    pub fn reserved_even(&self) -> u64 {
        self.even
    }

    /// Compare-exchanges the exact odd value to the reserved even value.
    ///
    /// A failed compare-exchange is an error and leaves admission closed
    /// (the generation stays odd). On success the generation becomes the
    /// reserved even value and admission reopens.
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

/// Test-only causal gate for the publication ordering proof.
///
/// Disarmed, [`park_if_armed`] is a no-op and every mutator passes. Armed,
/// the next mutator parks inside the exact publish-lock acquisition helper
/// after sequencing, while it still holds the pool write guard. It signals
/// the test on `parked` and blocks on `release`. One shot: the park consumes
/// the arm.
#[cfg(any(test, feature = "test-seam"))]
mod ordering_gate {
    use parking_lot::Mutex;
    use std::sync::mpsc::{Receiver, Sender};

    struct Gate {
        armed: Option<(usize, Sender<()>, Receiver<()>)>,
    }

    static GATE: Mutex<Gate> = Mutex::new(Gate { armed: None });

    /// Arms the gate with the test's signaling channels.
    pub(super) fn arm(target: usize, parked_tx: Sender<()>, release_rx: Receiver<()>) {
        let mut gate = GATE.lock();
        assert!(gate.armed.is_none(), "ordering gate armed twice");
        gate.armed = Some((target, parked_tx, release_rx));
    }

    /// Restores the disarmed state; called by tests that may have failed
    /// between arming and the one-shot park.
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
        // The parked mutator holds the pool write guard here; a dead test
        // thread drops the sender and the park dissolves instead of hanging.
        let _ = release_rx.recv();
    }
}

/// Cross-crate test seam: arms the admission park gate so the next
/// `admit_transaction` on the gateway at `target` blocks before the write
/// lock, signalling `parked_tx` and waiting on `release_rx`.
#[cfg(any(test, feature = "test-seam"))]
pub fn arm_admission_park(
    target: usize,
    parked_tx: std::sync::mpsc::Sender<()>,
    release_rx: std::sync::mpsc::Receiver<()>,
) {
    ordering_gate::arm(target, parked_tx, release_rx);
}

/// Cross-crate test seam: disarms the admission park gate.
#[cfg(any(test, feature = "test-seam"))]
pub fn reset_admission_park() {
    ordering_gate::reset();
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{
        AdmissionRequest, AdmitError, AdmitOutcome, ChainChangeError, CompositeObserver,
        MempoolGateway, MempoolObserver,
    };
    use crate::mutation::{
        AdmissionOrigin, MutationEnvelope, MutationOutcome, MutationResult, RemovalReason,
    };
    use crate::standardness::PackageTxContext;
    use crate::{Mempool, MempoolEntry, MempoolLimits};
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut, Txid};
    use core::sync::atomic::Ordering;
    use parking_lot::{Mutex, RwLock};
    use std::sync::mpsc;

    fn tx(label: u8) -> Tx {
        Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
                script_sig: Vec::new(),
                sequence: 0xFFFF_FFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x51, label],
            }],
        }
    }

    fn entry(tx: &Tx) -> MempoolEntry {
        MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 7)
    }

    fn hash(txid: &Txid) -> Hash256 {
        Hash256::from_le_bytes(txid.as_bytes())
    }

    /// Records the txid and outcome of every change the observer sees.
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

    struct PanickingObserver;

    impl MempoolObserver for PanickingObserver {
        fn on_mutation(&self, _envelope: &MutationEnvelope) {
            panic!("observer exploded");
        }
    }

    fn gateway_with(observer: Option<Arc<dyn MempoolObserver>>) -> Arc<MempoolGateway> {
        Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            observer,
        ))
    }

    /// Clones a concrete observer as its trait object without an `as` cast.
    fn dyn_observer<T: MempoolObserver + 'static>(observer: &Arc<T>) -> Arc<dyn MempoolObserver> {
        observer.clone()
    }

    fn removed(reason: RemovalReason) -> MutationOutcome {
        MutationOutcome::Removed(reason)
    }

    fn standard_tx(label: u8) -> Tx {
        let mut script = Vec::with_capacity(25);
        script.push(0x76); // OP_DUP
        script.push(0xa9); // OP_HASH160
        script.push(0x14); // push 20 bytes
        script.extend_from_slice(&[label; 20]);
        script.push(0x88); // OP_EQUALVERIFY
        script.push(0xac); // OP_CHECKSIG
        Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
                script_sig: Vec::new(),
                sequence: 0xFFFF_FFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 10_000,
                script_pubkey: script,
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
            max_feerate_sat_per_kvb: None,
            time: 1,
            height: 1,
            origin,
            expected_generation: generation,
            expected_sequence: sequence,
        }
    }

    #[test]
    fn accepted_and_removed_events_arrive_in_commit_order() {
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
        gateway.remove_by_txid(AdmissionOrigin::Rpc, &parent_txid);

        let seen = observer.seen.lock();
        assert_eq!(
            *seen,
            vec![
                (hash(&parent_txid), MutationOutcome::Accepted),
                (hash(&child.txid()), MutationOutcome::Accepted),
                (hash(&parent_txid), removed(RemovalReason::Explicit)),
                // The child sweeps with its parent, after it.
                (hash(&child.txid()), removed(RemovalReason::Explicit)),
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
    fn remove_for_block_reports_block_inclusion_not_explicit() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));

        let mined = tx(3);
        let mined_txid = mined.txid();
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&mined))
            .expect("in");
        observer.seen.lock().clear();
        gateway.remove_for_block(AdmissionOrigin::Rpc, &[&mined], &[mined_txid], 8);

        let seen = observer.seen.lock();
        assert_eq!(
            *seen,
            vec![(hash(&mined_txid), removed(RemovalReason::BlockInclusion))],
        );
    }

    #[test]
    fn failed_insert_and_noop_remove_publish_nothing() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));
        let before = gateway.read().sequence_number();

        // Below the default min-relay floor (1_000 sat/kvB): rejected before
        // any commit.
        let poor = MempoolEntry::new(Arc::new(tx(4)), 100, 50, 1, 7);
        assert!(gateway.insert_entry(AdmissionOrigin::Rpc, poor).is_err());
        let stranger = tx(5);
        gateway.remove_by_txid(AdmissionOrigin::Rpc, &stranger.txid());
        gateway.clear(AdmissionOrigin::Rpc);

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
        child.inputs[0].sequence = 0xFFFF_FFFD;
        let child_txid = child.txid();
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&child))
            .expect("child in");
        let mut grandchild = tx(8);
        grandchild.inputs[0].previous_output = OutPoint::new(child_txid, 0);
        grandchild.inputs[0].sequence = 0xFFFF_FFFD;
        let grandchild_txid = grandchild.txid();
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&grandchild))
            .expect("grandchild in");
        observer.seen.lock().clear();

        // The replacement double-spends the child's input, so the child is
        // the direct conflict (Replaced) and the grandchild sweeps with it
        // (Descendant). The parent survives.
        let mut replacement = tx(9);
        replacement.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
        replacement.inputs[0].sequence = 0xFFFF_FFFD;
        let replacement_txid = replacement.txid();
        let result = gateway
            .replace_transaction(
                AdmissionOrigin::Rpc,
                crate::ReplacementCandidate::new(Arc::new(replacement), 100, 5_000, 1),
                1,
                7,
                0,
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
        let removed = gateway.remove_by_txid(AdmissionOrigin::Rpc, &parent_txid);

        assert_eq!(removed.changes.len(), 2);
        assert_eq!(removed.sequence_base, 3);
        assert_eq!(removed.sequence_of(0), Some(3));
        assert_eq!(removed.sequence_of(1), Some(4));
        assert_eq!(gateway.read().sequence_number(), 4);
    }

    #[test]
    fn insert_reports_accepted_then_policy_evictions() {
        let observer = Arc::new(RecordingObserver::default());
        // 150-byte budget, 100 vbyte entries at 0 min-relay: the second
        // insert overflows and evicts the lowest-fee package.
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                max_total_bytes: 150,
                ..MempoolLimits::default()
            }))),
            Some(dyn_observer(&observer)),
        );

        let low = MempoolEntry::new(Arc::new(tx(13)), 100, 100, 1, 7);
        let high = MempoolEntry::new(Arc::new(tx(14)), 100, 900, 1, 7);
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
        // Sequences are contiguous across the batch and assigned in order.
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

        let cleared = gateway.clear(AdmissionOrigin::Rpc);
        assert_eq!(cleared.changes.len(), 2);
        assert!(
            cleared
                .changes
                .iter()
                .all(|change| { change.outcome == MutationOutcome::Removed(RemovalReason::Clear) })
        );
        assert_eq!(cleared.sequence_base, before + 1);
        assert_eq!(gateway.read().sequence_number(), before + 2);

        let empty = gateway.clear(AdmissionOrigin::Rpc);
        assert!(empty.is_empty());
        assert_eq!(empty.sequence_base, 0);
        assert_eq!(
            gateway.read().sequence_number(),
            before + 2,
            "clear-on-empty assigns nothing"
        );
    }

    /// A test observer whose first `on_mutation` records the batch and then
    /// blocks until released.
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

    /// Pins the observable signature of the publication state machine.
    /// While the first observer call is gated — holding no gateway lock —
    /// a concurrent mutation must complete its commit-and-enqueue and its
    /// thread must return with the batch's own result; nothing holds the
    /// pool write lock or the publish-state lock across a callback. After
    /// the gate opens, the elected drainer publishes the queued batch
    /// next: the callback stream is exactly [1, 2], the sequence order,
    /// and both mutations are in the pool.
    #[test]
    fn gated_callback_lets_concurrent_mutation_enqueue_and_return() {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        let observer = Arc::new(GatedObserver {
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(Some(release_rx)),
            stream: Mutex::new(Vec::new()),
        });
        let gateway = Arc::new(MempoolGateway::new(
            Arc::clone(&pool),
            Some(dyn_observer(&observer)),
        ));

        let first_txid = tx(20).txid();
        let first = Arc::clone(&gateway);
        let first_handle = std::thread::spawn(move || {
            first
                .insert_entry(AdmissionOrigin::Rpc, entry(&tx(20)))
                .expect("first in")
        });
        entered_rx
            .recv_timeout(core::time::Duration::from_secs(10))
            .expect("first observer call started");

        let second_txid = tx(21).txid();
        let second = Arc::clone(&gateway);
        let second_handle = std::thread::spawn(move || {
            let result = second
                .insert_entry(AdmissionOrigin::Rpc, entry(&tx(21)))
                .expect("second in");
            let _ = done_tx.send(result);
        });

        // The concurrent mutation must enqueue and return while the first
        // callback is still gated: its thread hands back the committed
        // result with the next sequence even though nothing has published.
        let queued_result = done_rx
            .recv_timeout(core::time::Duration::from_secs(10))
            .expect("the concurrent mutation must return while the callback is gated");
        assert_eq!(
            queued_result.sequence_base, 2,
            "the enqueued batch keeps its committed sequence"
        );

        // Nothing may publish while the gate is closed.
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

    /// An observer that re-enters the gateway from its first callback and
    /// records the nested call's returned result.
    struct ReentrantObserver {
        gateway: Mutex<Option<Arc<MempoolGateway>>>,
        stream: Mutex<Vec<u64>>,
        nested: Mutex<Vec<MutationResult>>,
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

    /// A re-entrant mutation from inside a callback must commit, enqueue,
    /// and return — never deadlock — and its callback completes afterwards
    /// in sequence order: the recorded stream is exactly [1, 2] and the
    /// nested call already returned sequence 2 while the outer callback
    /// was still running.
    #[test]
    fn reentrant_observer_mutation_completes_with_callback_sequence_1_2() {
        let observer = Arc::new(ReentrantObserver {
            gateway: Mutex::new(None),
            stream: Mutex::new(Vec::new()),
            nested: Mutex::new(Vec::new()),
        });
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Some(dyn_observer(&observer)),
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
        assert_eq!(
            nested[0].sequence_base, 2,
            "the nested mutation took the next sequence"
        );
        assert_eq!(nested[0].len(), 1);
        drop(nested);
        assert_eq!(
            *observer.stream.lock(),
            vec![1, 2],
            "callbacks run exactly once per batch, in sequence order"
        );
    }

    /// An observer that re-enters the gateway on some batches while other
    /// threads commit concurrently.
    struct ContiguityObserver {
        gateway: Mutex<Option<Arc<MempoolGateway>>>,
        stream: Mutex<Vec<u64>>,
        nested_vout: std::sync::atomic::AtomicU32,
    }

    /// A nested-insert transaction unique for every trigger: the vout of
    /// its only prevout varies, so each nested txid differs and the pool
    /// never refuses one as a duplicate of an earlier nested insert.
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
                    gateway
                        .insert_entry(AdmissionOrigin::Rpc, entry(&nested_tx(vout)))
                        .expect("nested in");
                }
            }
        }
    }

    /// Concurrent mutators plus a re-entering observer: even though some
    /// batches are enqueued from inside other batches' callbacks and may
    /// publish after their calls returned, the published stream must be
    /// exactly the contiguous sequence range — no gap, no duplicate, no
    /// reorder — and the pool sequence must match the stream length.
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
            Some(dyn_observer(&observer)),
        ));
        *observer.gateway.lock() = Some(Arc::clone(&gateway));

        let handles: Vec<_> = THREAD_BASES
            .iter()
            .map(|&base| {
                let gateway = Arc::clone(&gateway);
                std::thread::spawn(move || {
                    for cycle in 0..CYCLES {
                        // Distinct txids per cycle: a repeated txid would
                        // be a DuplicateTransaction, not an ordering test.
                        let label = base + u8::try_from(cycle).expect("label fits in u8");
                        gateway
                            .insert_entry(AdmissionOrigin::Rpc, entry(&tx(label)))
                            .expect("admitted");
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("mutator thread");
        }

        // Publication is eventual: the last elected drainer may still be
        // finishing after the mutators return. Wait until the published
        // stream has caught up with the pool sequence and stays stable.
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

    /// Records every change sequence the observer sees, in publish order.
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

    /// Races mutations from several threads and requires the published
    /// stream to be exactly the full sequence range in order. Sequences
    /// are assigned in commit order under the write lock and enqueued
    /// under that same ownership, so an in-order stream proves publish
    /// order == commit order regardless of which caller is elected to
    /// drain the queue.
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
                    let member_txid = member.txid();
                    for _ in 0..CYCLES {
                        gateway
                            .insert_entry(AdmissionOrigin::Rpc, entry(&member))
                            .expect("admitted");
                        gateway.remove_by_txid(AdmissionOrigin::Rpc, &member_txid);
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
    fn reconsider_disconnected_admits_in_order_once_per_candidate() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));
        let parent = tx(30);
        let parent_txid = parent.txid();
        let mut child = tx(31);
        child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);

        let committed =
            gateway.reconsider_disconnected(AdmissionOrigin::Rpc, [entry(&parent), entry(&child)]);

        assert_eq!(committed.len(), 2, "one committed result per candidate");
        for result in &committed {
            assert_eq!(result.changes.len(), 1);
        }
        assert_eq!(gateway.read().sequence_number(), 2);
        let seen = observer.seen.lock();
        assert_eq!(seen.len(), 2, "one publish per committed candidate");
        assert_eq!(seen[0].0, hash(&parent_txid), "parent commits first");
        assert_eq!(seen[1].0, hash(&child.txid()), "child commits second");
    }

    #[test]
    fn reconsider_disconnected_withholds_descendants_of_a_refused_parent() {
        let gateway = gateway_with(None);
        let parent = tx(32);
        let parent_txid = parent.txid();
        let mut child = tx(33);
        child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
        // Fee 50 over 100 vbytes is 500 sat/kvB, under the 1 000 sat/kvB
        // floor; the child itself is fine and only the refused parent can
        // keep it out.
        let refused_parent = MempoolEntry::new(Arc::new(parent), 100, 50, 1, 7);

        let committed =
            gateway.reconsider_disconnected(AdmissionOrigin::Rpc, [refused_parent, entry(&child)]);

        assert!(
            committed.is_empty(),
            "a refused parent must keep its descendant out"
        );
        assert!(!gateway.read().contains_txid(&parent_txid));
        assert!(!gateway.read().contains_txid(&child.txid()));
    }

    #[test]
    fn reconsider_disconnected_withholds_descendants_of_an_immediately_evicted_parent() {
        let observer = Arc::new(RecordingObserver::default());
        // A 150-byte pool already holding 100 vbytes of high-fee filler: the
        // parent's own insert succeeds and then immediately evicts the parent
        // as the lowest-fee package. The child pays far more than everything
        // else, so once admitted it fits and survives — only the parent's
        // eviction inside the parent's own MutationResult can keep it out.
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                max_total_bytes: 150,
                ..MempoolLimits::default()
            }))),
            Some(dyn_observer(&observer)),
        );
        let filler_txid = tx(36).txid();
        gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(tx(36)), 100, 9_000, 1, 7),
            )
            .expect("filler in");
        // The filler's own publication predates the scenario under test.
        observer.seen.lock().clear();

        let parent = tx(34);
        let parent_txid = parent.txid();
        let mut child = tx(35);
        child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
        let child_txid = child.txid();
        let parent = MempoolEntry::new(Arc::new(parent), 100, 100, 1, 7);
        let child = MempoolEntry::new(Arc::new(child), 100, 9_000, 1, 7);

        let committed = gateway.reconsider_disconnected(AdmissionOrigin::Rpc, [parent, child]);

        assert_eq!(
            committed.len(),
            1,
            "only the parent's insert commits; the child is withheld"
        );
        assert_eq!(
            committed[0].changes,
            vec![
                crate::mutation::change(&parent_txid, MutationOutcome::Accepted),
                crate::mutation::change(&parent_txid, removed(RemovalReason::PolicyEviction)),
            ],
            "the parent was admitted and immediately evicted by its own insert"
        );
        let pool = gateway.read();
        assert!(!pool.contains_txid(&parent_txid));
        assert!(
            !pool.contains_txid(&child_txid),
            "an evicted parent must not admit its descendant"
        );
        assert!(
            pool.contains_txid(&filler_txid),
            "no orphan replaced the parent"
        );
        assert_eq!(
            pool.sequence_number(),
            3,
            "the withheld child assigns nothing"
        );
        assert_eq!(
            *observer.seen.lock(),
            vec![
                (hash(&parent_txid), MutationOutcome::Accepted),
                (hash(&parent_txid), removed(RemovalReason::PolicyEviction)),
            ],
            "the parent's two changes publish once each; the child publishes nothing"
        );
    }

    #[test]
    fn reconsider_disconnected_no_ops_on_an_empty_batch() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));
        let before = gateway.read().sequence_number();

        let committed = gateway.reconsider_disconnected(AdmissionOrigin::Rpc, []);

        assert!(committed.is_empty());
        assert_eq!(gateway.read().sequence_number(), before);
        assert!(observer.seen.lock().is_empty(), "nothing may publish");
    }

    #[test]
    fn stale_generation_rejects_without_mutation_or_publication() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));
        let candidate = tx(40);

        // Capture tokens at the current even generation.
        let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);

        // Simulate a chain change: bump the generation to an odd value
        // directly, as a chain change would.
        let current = gateway.chain_generation.load(Ordering::Relaxed);
        gateway
            .chain_generation
            .store(current + 1, Ordering::Release);

        // The request still carries the old even generation.
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

        // Insert a different tx to bump the sequence.
        let other = tx(42);
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&other))
            .expect("other tx admitted");
        observer.seen.lock().clear();

        // Capture tokens with the current sequence.
        let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
        let captured_sequence = request.expected_sequence;

        // Bump the sequence by removing the other tx.
        gateway.remove_by_txid(AdmissionOrigin::Rpc, &other.txid());

        // The request still carries the old sequence.
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
        // The observer saw the remove_by_txid but no admission publication.
        let seen = observer.seen.lock();
        assert_eq!(
            seen.len(),
            1,
            "only the remove_by_txid publication, no extra observer call from admission"
        );
    }

    #[test]
    fn exact_duplicate_is_success_without_second_publication() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));
        let candidate = tx(43);
        let txid = candidate.txid();

        // Pre-insert the tx.
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&candidate))
            .expect("first insert");
        observer.seen.lock().clear();

        // Admission with the exact same tx must return AlreadyKnown.
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

        // Set up a conflict: insert a tx, then admit a replacement.
        let mut original = standard_tx(44);
        original.inputs[0].sequence = 0xFFFF_FFFD; // RBF signal (< 0xFFFF_FFFE)
        let original_txid = original.txid();
        // The replacement spends the same input as the original but
        // signals RBF (sequence < 0xFFFF_FFFF) and pays a higher fee.
        let mut replacement = standard_tx(45);
        replacement.inputs[0].previous_output = original.inputs[0].previous_output;
        replacement.inputs[0].sequence = 0xFFFF_FFFE; // RBF signal
        // Higher fee to pass BIP125 (original output is 10 000, replacement
        // output is 5 000, so fee = 5 000 > original fee = 0).
        replacement.outputs[0].value = 5_000;
        let replacement_txid = replacement.txid();

        // Fund the original's output in the UTXO set so the replacement
        // can resolve its input. Actually, the pool handles this: the
        // original is in the pool, so the replacement spends a mempool
        // parent. We need the context to reflect this.
        // For the admission test, we build context manually.
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&original))
            .expect("original admitted");
        observer.seen.lock().clear();

        // Build a request for the replacement. The context has
        // missing_inputs: false because the parent is in the pool.
        let generation = gateway.stable_generation().expect("generation is even");
        let sequence = gateway.read().sequence_number();
        let request = AdmissionRequest {
            tx: Arc::new(replacement.clone()),
            context: PackageTxContext {
                fee: 5_000, // 10 000 - 5 000
                vsize: 100,
                sigop_cost: 0,
                missing_inputs: false,
            },
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
        // The replacement evicts the original (Removed) then admits the
        // replacement (Accepted) — removals first, then exactly one Accept.
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
        // The Removed events must precede the Accepted event.
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
        // The original is gone, the replacement is in.
        assert!(
            !gateway.read().contains_txid(&original_txid),
            "replaced original must be gone"
        );
        assert!(
            gateway.read().contains_txid(&replacement_txid),
            "replacement must be in the pool"
        );
    }

    #[test]
    fn composite_isolates_a_panicking_leg() {
        let recorder = Arc::new(RecordingObserver::default());
        let composite = CompositeObserver::new();
        composite.add_leg("panicker", Arc::new(PanickingObserver));
        composite.add_leg("recorder", dyn_observer(&recorder));
        let composite = Arc::new(composite);
        let gateway = gateway_with(Some(dyn_observer(&composite)));

        let committed = tx(40);
        let committed_txid = committed.txid();
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&committed))
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
    }

    #[test]
    fn gateway_contains_a_panicking_payload_destructor() {
        let gateway = gateway_with(Some(Arc::new(PanickingObserver)));
        let committed = tx(52);
        let committed_txid = committed.txid();

        assert!(
            gateway
                .insert_entry(AdmissionOrigin::Rpc, entry(&committed))
                .is_ok()
        );
        assert!(gateway.read().contains_txid(&committed_txid));
    }

    #[test]
    fn shared_interns_one_gateway_per_pool() {
        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        let first = MempoolGateway::shared(Arc::clone(&pool));
        let second = MempoolGateway::shared(Arc::clone(&pool));
        assert!(
            Arc::ptr_eq(&first, &second),
            "one pool must intern exactly one gateway"
        );

        let other = MempoolGateway::shared(Arc::new(RwLock::new(Mempool::new(
            MempoolLimits::default(),
        ))));
        assert!(
            !Arc::ptr_eq(&first, &other),
            "distinct pools must get distinct gateways"
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
        // A fresh begin on the still-odd gateway must fail.
        let err = gateway
            .begin_chain_change()
            .expect_err("cannot begin while odd after a dropped guard");
        assert_eq!(err, ChainChangeError::AlreadyActive);
    }

    #[test]
    fn chain_generation_overflow_fails_closed() {
        let gateway = gateway_with(None);
        // u64::MAX is odd; u64::MAX - 1 is the largest usable even value.
        // begin must reserve odd = u64::MAX (ok) then even = u64::MAX + 1
        // (overflow), and fail before storing anything.
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

    #[test]
    fn begin_chain_change_serializes_with_inflight_admission() {
        let gateway = gateway_with(None);

        // Thread A takes the pool write lock directly, simulating an
        // inflight admission that has acquired pool.write() but has not
        // yet mutated or released.
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let gateway_a = Arc::clone(&gateway);
        let a_handle = std::thread::spawn(move || {
            let _guard = gateway_a.pool().write();
            held_tx.send(()).expect("test waiting for lock acquisition");
            // Hold the write lock until the test signals release.
            release_rx
                .recv_timeout(core::time::Duration::from_secs(10))
                .expect("test alive to release");
            // _guard drops here, releasing the write lock.
        });

        held_rx
            .recv_timeout(core::time::Duration::from_secs(10))
            .expect("thread A acquired the pool write lock");

        // Thread B calls begin_chain_change, which must block on pool.write()
        // until thread A releases. It must NOT store odd while the admission
        // holds the write lock.
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

        // Give thread B time to block on the write lock. The generation must
        // still be even (0) — begin has not stored odd yet.
        std::thread::sleep(core::time::Duration::from_millis(100));
        assert_eq!(
            gateway.stable_generation(),
            Some(0),
            "begin must not store odd while an admission holds the write lock"
        );

        // Release thread A's write lock. Thread B's begin_chain_change should
        // now proceed and store odd.
        release_tx.send(()).expect("thread A alive");
        a_handle.join().expect("thread A completed");

        let guard = b_done_rx
            .recv_timeout(core::time::Duration::from_secs(10))
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

        // A directly mined pool transaction.
        let mined = tx(10);
        let mined_txid = mined.txid();
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&mined))
            .expect("mined in");

        // A pool transaction that spends a known outpoint. The block will
        // include a different transaction spending the same outpoint, making
        // this one a double-spend conflict.
        let conflict_tx = tx(11);
        let conflict_txid = conflict_tx.txid();
        let spent_outpoint = conflict_tx.inputs[0].previous_output;
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&conflict_tx))
            .expect("conflict in");

        // A child of the conflict tx — a removed descendant.
        let mut child = tx(12);
        child.inputs[0].previous_output = OutPoint::new(conflict_txid, 0);
        let child_txid = child.txid();
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&child))
            .expect("child in");

        // The block mines `mined` directly and includes a transaction that
        // double-spends the same outpoint as `conflict_tx`.
        let mut double_spend = tx(13);
        double_spend.inputs[0] = TxIn {
            previous_output: spent_outpoint,
            script_sig: Vec::new(),
            sequence: 0xFFFF_FFFF,
            witness: Vec::new(),
        };
        let double_spend_txid = double_spend.txid();

        observer.seen.lock().clear();
        gateway.remove_for_block(
            AdmissionOrigin::Block,
            &[&mined, &double_spend],
            &[mined_txid, double_spend_txid],
            8,
        );

        let seen = observer.seen.lock();
        // Directly mined: BlockInclusion (no R).
        // Conflict (conflict_tx): Conflict (R).
        // Descendant (child): Conflict (R).
        // Order: mined first, then conflict, then descendant.
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
}
