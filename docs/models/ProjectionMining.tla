(***************************************************************************)
(* Finite model of the optional index projection machine and the mining    *)
(* template machine, plan appendix "Peer, projection, and mining           *)
(* lifecycle contract" section B (B.1-B.5).  Gates owner bodies T29, T30,  *)
(* T35, and T36 through the g20 gate.                                      *)
(*                                                                         *)
(* Fixture (B.4): tips {O, A, B} where A and B both have height 1 and      *)
(* common ancestor O has height 0, so a same-height parent replacement     *)
(* defeats height-only validation; full key records {K0, K1}; single-use   *)
(* jobs {J0, J1}; rows {r0, r1, r2}; pool transactions {x0, x1} with the   *)
(* static dependency x1 -> x0; one request slot; two worker slots; the     *)
(* external-event budget is ExternalBudget = 12 events.                    *)
(*                                                                         *)
(* Exports exactly Init, Next, TypeOK, Safety, TransitionSafety, and       *)
(* ConditionalProgress (FTL-3).  Next is the unrestricted union of the     *)
(* B.2 and B.3 actions, the external and fault inputs of B.4, Seal, Done,  *)
(* and explicit Stutter; it contains no fairness and no priority.          *)
(*                                                                         *)
(* Tool adaptations, verified against apalache-mc 0.62.2 (the same limits  *)
(* are documented in PeerLeases.tla): (1) Apalache supports no WF_/SF_     *)
(* macros and no ENABLED primitive inside temporal properties, and it      *)
(* cannot substitute a quantified variable inside a temporal formula, so   *)
(* B.5's FairServices is realized as the named conjunction of per-instance *)
(* clauses FairX == ((<>[] EnX) => ([]<> <<X>>_vars)) over the finite      *)
(* settlement set, where EnX is the state-level guard of X; (2) --inv      *)
(* accepts state invariants only, so per appendix A.5 the edge obligations *)
(* are observed: every non-stutter action sets stepOK' = EdgeOK, explicit  *)
(* stutter leaves stepOK unchanged, and TransitionSafety is exactly        *)
(* stepOK.  Every settlement guard forces a state change, so each action   *)
(* equals its own nonstuttering form.  The verification bound K = 128 is   *)
(* supplied on the command line (--length), never here.  (3) The 0.62.2  *)
(* temporal-lane Desugarer mints auxiliary LET-bound helpers named t_1,  *)
(* t_2, ... (the tool's fresh-name namespace; spec binder t renames to   *)
(* t$N) for multi-key EXCEPT accessors, and its temporal inliner cannot  *)
(* unify those helpers ("Unable to unify the signature ... of t_N$M").   *)
(* Every EXCEPT below uses single-key nested form, so none are minted.   *)
(* Record encodings are uniform:                                         *)
(* every construction of a given record type uses one fixed field order,  *)
(* matching the @type annotations.                                        *)
(*                                                                         *)
(* Why string atoms: every identity, kind, phase, and outcome is a string, *)
(* so the whole model carries one uniform element type and Apalache type   *)
(* checking never meets a mixed-type set or comparison.                    *)
(***************************************************************************)
---------------------------- MODULE ProjectionMining ---------------------------
EXTENDS Integers, FiniteSets

CONSTANTS
  \* Chain tips of the finite fixture, fixed by ProjectionMining.cfg.
  \* @type: Str;
  O,                    \* common ancestor, height 0, the genesis anchor
  \* @type: Str;
  A,                    \* height-1 tip, child of O
  \* @type: Str;
  B,                    \* height-1 tip, child of O (same-height rival of A)
  \* Projection capabilities, fixed by ProjectionMining.cfg.
  \* @type: Str;
  TxLookup,
  \* @type: Str;
  ScriptLive,
  \* @type: Str;
  ScriptHistory,
  \* Single-use mining worker slots, fixed by ProjectionMining.cfg.
  \* @type: Str;
  J0,
  \* @type: Str;
  J1,
  \* Abstract row identities, fixed by ProjectionMining.cfg.
  \* @type: Str;
  Rw0,
  \* @type: Str;
  Rw1,
  \* @type: Str;
  Rw2,
  \* Abstract pool transaction identities, fixed by ProjectionMining.cfg.
  \* @type: Str;
  X0,                   \* dependency root: x1 statically depends on x0
  \* @type: Str;
  X1,
  \* Scale constant from appendix B.4.
  \* @type: Int;
  ExternalBudget

-------------------------------------------------------------------------------
(*** B.4 finite fixture domains ***)

Tips == {O, A, B}
Capabilities == {TxLookup, ScriptLive, ScriptHistory}
Jobs == {J0, J1}
Rows == {Rw0, Rw1, Rw2}
PoolTxs == {X0, X1}

\* A and B are height-1 children of the anchor O.  Switching A <-> B is a
\* same-height parent replacement; only the full (height, hash) comparison
\* distinguishes it, never height alone.
TipHeight == [t \in Tips |-> IF t = O THEN 0 ELSE 1]
Parent == [t \in Tips |-> O]

Phases ==
  {"Disabled", "Opening", "CatchingUp", "Ready",
   "RollingBack", "Rebuilding", "Failed", "Shutdown"}
IOStates == {"Idle", "Pending", "Unknown", "Committed", "Failed"}
JobStates ==
  {"Unused", "Captured", "Selected", "Validated",
   "PendingSubmit", "Settled", "Rejected"}

\* Full template keys (B.3): the entire key is the ReadStamp-derived record
\* (process epoch, mempool sequence, policy epoch) plus the template-policy,
\* fee-delta and time-validity revisions, generation, and tip.  K0 and K1
\* are two fixed records of that finite record domain; the paired
\* configuration varies individual key fields and the tip.  NoKey is the
\* inactive sentinel.
NoKey == [active |-> FALSE, epoch |-> 0, poolSeq |-> 0, policyEpoch |-> 0,
          tplRev |-> 0, feeRev |-> 0, timeRev |-> 0, gen |-> 0, tip |-> O]
K0 == [active |-> TRUE, epoch |-> 0, poolSeq |-> 0, policyEpoch |-> 0,
       tplRev |-> 0, feeRev |-> 0, timeRev |-> 0, gen |-> 0, tip |-> O]
K1 == [active |-> TRUE, epoch |-> 0, poolSeq |-> 1, policyEpoch |-> 1,
       tplRev |-> 1, feeRev |-> 1, timeRev |-> 1, gen |-> 0, tip |-> A]
Keys == {NoKey, K0, K1}

\* Inactive sentinels and record constructors for the projection state.
NoWm(c) == [active |-> FALSE, cap |-> c, h |-> 0, tip |-> O, sch |-> 0, rev |-> 0]
Wm(c, h, t, s, r) == [active |-> TRUE, cap |-> c, h |-> h, tip |-> t,
                      sch |-> s, rev |-> r]
NoContr == [active |-> FALSE, after |-> {}, before |-> {}]
NoPrep(c) == [active |-> FALSE, after |-> {}, before |-> {}, cap |-> c,
              parent |-> O, rev |-> 0, sch |-> 0, target |-> O]

-------------------------------------------------------------------------------
(*** Variables, each with its Apalache type annotation (B.4 finite domains) ***)

VARIABLE
  \* @type: Str;
  tip,                  \* active published tip
  \* @type: Int;
  height,               \* height of tip: {0, 1}, constrained by tip
  \* @type: Int;
  generation,           \* {0, 1, 2}: even 0/2 stable, odd 1 fenced
  \* @type: Str -> Str;
  phase,                \* per-capability machine phase
  \* @type: Str -> Bool;
  enabled,              \* per-capability operator switch
  \* @type: Str -> Int;
  revision,             \* per-capability runtime revision {0, 1, 2}
  \* @type: Str -> Int;
  schema,               \* per-capability schema version {0, 1}
  \* @type: Str -> {active: Bool, cap: Str, h: Int, tip: Str, sch: Int, rev: Int};
  watermark,            \* runtime watermark: None or (cap, h, hash, sch, rev)
  \* @type: Str -> Set(Str);
  rows,                 \* volatile row set of the capability
  \* @type: Str -> Set(Str);
  durableRows,          \* committed row set (atomic mirror of rows)
  \* @type: Str -> (Str -> {active: Bool, after: Set(Str), before: Set(Str)});
  contribution,         \* volatile per-tip reversal record
  \* @type: Str -> {active: Bool, cap: Str, h: Int, tip: Str, sch: Int, rev: Int};
  durableWatermark,     \* committed watermark: durable mirror of watermark
  \* @type: Str -> (Str -> {active: Bool, after: Set(Str), before: Set(Str)});
  durableContribution,  \* committed per-tip reversal record
  \* @type: Str -> Str;
  io,                   \* per-capability durable I/O state
  \* @type: Str -> Bool;
  body,                 \* block-body availability per tip
  \* @type: Str -> Bool;
  healthy,              \* per-capability health
  \* @type: Str -> {active: Bool, after: Set(Str), before: Set(Str), cap: Str, parent: Str, rev: Int, sch: Int, target: Str};
  prepared,             \* bounded prepared batch record
  \* @type: Str -> Str;
  target,               \* retained hash-tagged target per capability
  \* @type: {active: Bool, epoch: Int, poolSeq: Int, policyEpoch: Int, tplRev: Int, feeRev: Int, timeRev: Int, gen: Int, tip: Str};
  key,                  \* current full template key
  \* @type: Str -> {active: Bool, epoch: Int, poolSeq: Int, policyEpoch: Int, tplRev: Int, feeRev: Int, timeRev: Int, gen: Int, tip: Str};
  captured,             \* key captured by each single-use job
  \* @type: {active: Bool, epoch: Int, poolSeq: Int, policyEpoch: Int, tplRev: Int, feeRev: Int, timeRev: Int, gen: Int, tip: Str};
  cacheKey,             \* key of the cached validated template
  \* @type: Str -> Str;
  job,                  \* per-job lifecycle state
  \* @type: Set(Str);
  allocated,            \* allocated worker slots (never reused)
  \* @type: Set(Str);
  pool,                 \* admitted mempool snapshot identities (only grows)
  \* @type: Str -> Set(Str);
  selected,             \* dependency-closed selection per job
  \* @type: Str -> Int;
  fee,                  \* actual fee per job {0, 1, 2}: real fees pay
  \* @type: Str -> Int;
  modifiedFee,          \* modified fee per job {-2..2}: ranking only
  \* @type: Str -> Int;
  weight,               \* reserved weight per job {0, 1, 2}
  \* @type: Str -> Int;
  sigops,               \* reserved sigops per job {0, 1, 2}
  \* @type: Str -> Int;
  work,                 \* bounded selection work per job {0, 1, 2}
  \* @type: Str -> Bool;
  valid,                \* per-job validated flag
  \* @type: Bool;
  cacheValid,           \* a validated current candidate is cached
  \* @type: Bool;
  timeValid,            \* the time-validity predicate itself
  \* @type: Bool;
  wake,                 \* coalesced long-poll wake bit
  \* @type: Bool;
  waiting,              \* a long-poll waiter is registered
  \* @type: Bool;
  shutdown,             \* owner shutdown requested
  \* @type: Bool;
  closed,               \* external input sealed
  \* @type: Bool;
  done,                 \* terminal: only stutter afterwards
  \* @type: Bool;
  fenceHeld,            \* a chain-transition fence is held unresolved
  \* @type: Bool;
  reconciled,           \* pool reconciled for the held transition
  \* @type: Str;
  request,              \* the single bounded request slot
  \* @type: Str;
  result,               \* typed result of the held request
  \* @type: Str;
  submitIO,             \* durable solved-submission I/O state
  \* @type: Int;
  budget,               \* external-event budget 0..ExternalBudget
  \* @type: Bool;
  stepOK                \* observer of the preceding edge, TRUE initially

\* The flat framed tuple: all 44 B.4 state variables plus the stepOK
\* edge observer.  UNCHANGED vars in Stuttering keeps the observer fixed.
vars == <<
  tip, height, generation, phase, enabled, revision, schema, watermark,
  rows, durableRows, contribution, durableWatermark, durableContribution,
  io, body, healthy, prepared, target, key, captured, cacheKey, job,
  allocated, pool, selected, fee, modifiedFee, weight, sigops, work, valid,
  cacheValid, timeValid, wake, waiting, shutdown, closed, done, fenceHeld,
  reconciled, request, result, submitIO, budget, stepOK >>

-------------------------------------------------------------------------------
(*** Derived facts ***)

ReadyAt(c) ==
  /\ phase[c] = "Ready"
  /\ watermark[c].active
  /\ watermark[c].tip = tip
  /\ watermark[c].h = height

\* A query succeeds only when at least one capability is consumed and every
\* consumed capability is Ready at the queried active identity; an empty
\* answer is never a successful history.
AllReady ==
  /\ \E c \in Capabilities : enabled[c]
  /\ \A c \in Capabilities : ~enabled[c] \/ ReadyAt(c)

\* The entire key is compared: exact record equality with the current key,
\* the key's generation and tip fields against the live coherent state, and
\* the time-validity predicate itself.  Matching revisions alone never
\* authorize an expired template.
FullKeyMatch(k) ==
  /\ k.active
  /\ k = key
  /\ k.gen = generation
  /\ k.tip = tip
  /\ timeValid

PreparedCurrent(c) ==
  /\ prepared[c].active
  /\ prepared[c].target = tip
  /\ prepared[c].sch = schema[c]
  /\ prepared[c].rev = revision[c]

\* Static dependency fact of the fixture: x1 depends on x0, so a
\* dependency-closed selection contains x0 whenever it contains x1.
DepClosed(S) == (X1 \in S) => (X0 \in S)

AllJobsTerminal == \A j \in Jobs : job[j] \in {"Unused", "Settled", "Rejected"}

DoneGuard ==
  /\ closed                                   \* input sealed
  /\ AllJobsTerminal                          \* allocated jobs terminal
  /\ (request = "None" \/ result # "None")    \* request absent or terminal
  /\ ~waiting                                 \* waiter drained
  /\ \A c \in Capabilities : io[c] \notin {"Pending", "Unknown"}
  /\ submitIO \notin {"Pending", "Unknown"}   \* no pending or unknown I/O
  /\ ~fenceHeld                               \* no unresolved held fence

-------------------------------------------------------------------------------
(*** Initial state ***)

Init ==
  /\ tip = O
  /\ height = 0
  /\ generation = 0
  /\ phase = [c \in Capabilities |-> "Disabled"]
  /\ enabled = [c \in Capabilities |-> TRUE]
  /\ revision = [c \in Capabilities |-> 0]
  /\ schema = [c \in Capabilities |-> 0]
  /\ watermark = [c \in Capabilities |-> NoWm(c)]
  /\ rows = [c \in Capabilities |-> {}]
  /\ durableRows = [c \in Capabilities |-> {}]
  /\ contribution = [c \in Capabilities |-> [t \in Tips |-> NoContr]]
  /\ durableWatermark = [c \in Capabilities |-> NoWm(c)]
  /\ durableContribution = [c \in Capabilities |-> [t \in Tips |-> NoContr]]
  /\ io = [c \in Capabilities |-> "Idle"]
  /\ body = [t \in Tips |-> TRUE]
  /\ healthy = [c \in Capabilities |-> TRUE]
  /\ prepared = [c \in Capabilities |-> NoPrep(c)]
  /\ target = [c \in Capabilities |-> O]
  /\ key = K0
  /\ captured = [j \in Jobs |-> NoKey]
  /\ cacheKey = NoKey
  /\ job = [j \in Jobs |-> "Unused"]
  /\ allocated = {}
  /\ pool = {}
  /\ selected = [j \in Jobs |-> {}]
  /\ fee = [j \in Jobs |-> 0]
  /\ modifiedFee = [j \in Jobs |-> 0]
  /\ weight = [j \in Jobs |-> 0]
  /\ sigops = [j \in Jobs |-> 0]
  /\ work = [j \in Jobs |-> 0]
  /\ valid = [j \in Jobs |-> FALSE]
  /\ cacheValid = FALSE
  /\ timeValid = TRUE
  /\ wake = FALSE
  /\ waiting = FALSE
  /\ shutdown = FALSE
  /\ closed = FALSE
  /\ done = FALSE
  /\ fenceHeld = FALSE
  /\ reconciled = TRUE
  /\ request = "None"
  /\ result = "None"
  /\ submitIO = "Idle"
  /\ budget = ExternalBudget
  /\ stepOK = TRUE

-------------------------------------------------------------------------------
(*** Edge obligations (B.5 TransitionSafety) ***
 * Apalache 0.62.2 accepts state invariants only under --inv, so per
 * appendix A.5 each non-stutter action sets stepOK' = EdgeOK and explicit
 * stutter leaves stepOK unchanged; TransitionSafety is exactly stepOK.
 * These eight named predicates are the appendix's separate edge checks,
 * evaluated on the (old, new) pair of every executed edge.            ***)

\* Stale prepared work has no publishing effect: durable rows and the
\* watermark move only from current, rechecked evidence.
StaleNoPublish ==
  \A c \in Capabilities :
    (prepared[c].active /\ ~PreparedCurrent(c) /\ phase[c] # "Rebuilding") =>
      (durableRows' = durableRows /\ durableWatermark' = durableWatermark)

\* Runtime revisions advance by at most one and never wrap.
RevisionMonotonic ==
  \A c \in Capabilities :
    /\ revision[c] <= revision'[c]
    /\ revision'[c] <= revision[c] + 1

\* Rollback applies the exact recorded inverse, never a partial one.
RollbackInversion ==
  \A c \in Capabilities :
    (phase[c] = "RollingBack" /\ durableWatermark[c].active
     /\ durableContribution[c][durableWatermark[c].tip].active
     /\ durableWatermark'[c] # durableWatermark[c]) =>
      (durableRows'[c] = durableContribution[c][durableWatermark[c].tip].before
       /\ durableWatermark'[c].tip = Parent[durableWatermark[c].tip])

\* BIP22 proposal evaluation is nonmutating: only the result is produced.
ProposalNonmutation ==
  (request' = "Proposal" /\ result = "None" /\ result' # "None") =>
    /\ tip' = tip
    /\ height' = height
    /\ generation' = generation
    /\ phase' = phase
    /\ enabled' = enabled
    /\ revision' = revision
    /\ schema' = schema
    /\ watermark' = watermark
    /\ rows' = rows
    /\ durableRows' = durableRows
    /\ contribution' = contribution
    /\ durableWatermark' = durableWatermark
    /\ durableContribution' = durableContribution
    /\ io' = io
    /\ body' = body
    /\ healthy' = healthy
    /\ prepared' = prepared
    /\ target' = target
    /\ key' = key
    /\ captured' = captured
    /\ cacheKey' = cacheKey
    /\ job' = job
    /\ allocated' = allocated
    /\ pool' = pool
    /\ selected' = selected
    /\ fee' = fee
    /\ modifiedFee' = modifiedFee
    /\ weight' = weight
    /\ sigops' = sigops
    /\ work' = work
    /\ valid' = valid
    /\ cacheValid' = cacheValid
    /\ timeValid' = timeValid
    /\ wake' = wake
    /\ waiting' = waiting
    /\ shutdown' = shutdown
    /\ closed' = closed
    /\ done' = done
    /\ fenceHeld' = fenceHeld
    /\ reconciled' = reconciled
    /\ request' = request
    /\ submitIO' = submitIO
    /\ budget' = budget

\* Cancellation revokes publication eligibility and drains outstanding work.
CancelRevocation ==
  (result' = "Cancelled") =>
    (request' = "None"
     /\ prepared' = [c \in Capabilities |-> NoPrep(c)]
     /\ \A c \in Capabilities : io'[c] \notin {"Pending", "Unknown"}
     /\ \A j \in Jobs : job'[j] \notin {"Captured", "Selected", "Validated"}
     /\ ~waiting')

\* Durable atomicity: the watermark never moves without its rows, and row
\* mutations happen only inside legitimate commit, rollback, or rebuild
\* scopes - faults never manufacture a half-committed durable state.
\* Commit scope includes the ambiguous-completion resolution: ResolveCommit
\* confirms current evidence from Unknown and installs rows as one durable
\* state, matching the Pending path.
FaultAtomicity ==
  /\ \A c \in Capabilities :
       (durableWatermark'[c] # durableWatermark[c]) =>
         (durableRows'[c] # durableRows[c])
  /\ \A c \in Capabilities :
       (durableRows'[c] # durableRows[c]) =>
         (io[c] \in {"Pending", "Unknown"}
            \/ phase[c] = "RollingBack" \/ phase[c] = "Rebuilding")

\* Fence ordering: the tip moves only through the reconciled stable
\* publication edge, and generations only ever advance by one.
FenceOrdering ==
  /\ (tip' # tip) =>
       (fenceHeld /\ reconciled /\ ~fenceHeld'
        /\ generation' = generation + 1 /\ height' = TipHeight[tip'])
  /\ (generation' # generation) => generation' = generation + 1

\* Done absorbs every edge: all actions are guarded by ~done, so from a
\* terminal state only explicit stutter remains.
DoneAbsorption ==
  done =>
           /\ tip' = tip
           /\ height' = height
           /\ generation' = generation
           /\ phase' = phase
           /\ enabled' = enabled
           /\ revision' = revision
           /\ schema' = schema
           /\ watermark' = watermark
           /\ rows' = rows
           /\ durableRows' = durableRows
           /\ contribution' = contribution
           /\ durableWatermark' = durableWatermark
           /\ durableContribution' = durableContribution
           /\ io' = io
           /\ body' = body
           /\ healthy' = healthy
           /\ prepared' = prepared
           /\ target' = target
           /\ key' = key
           /\ captured' = captured
           /\ cacheKey' = cacheKey
           /\ job' = job
           /\ allocated' = allocated
           /\ pool' = pool
           /\ selected' = selected
           /\ fee' = fee
           /\ modifiedFee' = modifiedFee
           /\ weight' = weight
           /\ sigops' = sigops
           /\ work' = work
           /\ valid' = valid
           /\ cacheValid' = cacheValid
           /\ timeValid' = timeValid
           /\ wake' = wake
           /\ waiting' = waiting
           /\ shutdown' = shutdown
           /\ closed' = closed
           /\ done' = done
           /\ fenceHeld' = fenceHeld
           /\ reconciled' = reconciled
           /\ request' = request
           /\ result' = result
           /\ submitIO' = submitIO
           /\ budget' = budget

EdgeOK ==
  /\ StaleNoPublish
  /\ RevisionMonotonic
  /\ RollbackInversion
  /\ ProposalNonmutation
  /\ CancelRevocation
  /\ FaultAtomicity
  /\ FenceOrdering
  /\ DoneAbsorption

-------------------------------------------------------------------------------
(*** State-level guards of the settlement actions (appendix A.5 form) ***
 * Each guard is a no-prime state predicate; every settlement action is
 * defined as its guard conjoined with effects, so guard and action cannot
 * drift, and every guard forces a state change.                     ***)

EnOpen(c) ==
  /\ ~done
  /\ ~shutdown
  /\ enabled[c]
  /\ phase[c] \in {"Disabled", "Failed"}

EnInspect(c) ==
  /\ ~done
  /\ phase[c] = "Opening"
  /\ io[c] = "Idle"

EnPrepare(c) ==
  /\ ~done
  /\ ~shutdown
  /\ phase[c] \in {"CatchingUp", "Rebuilding"}
  /\ io[c] = "Idle"
  /\ body[tip]
  /\ ~prepared[c].active

\* True exactly when Rebuild has something left to reset, so Rebuild is
\* never a hidden stutter.
HasProjectionWork(c) ==
  \/ rows[c] # {}
  \/ durableRows[c] # {}
  \/ watermark[c].active
  \/ durableWatermark[c].active
  \/ prepared[c].active
  \/ io[c] # "Idle"
  \/ ~healthy[c]

EnRebuild(c) ==
  /\ ~done
  /\ phase[c] = "Rebuilding"
  /\ body[tip]
  /\ HasProjectionWork(c)

EnCommit(c) ==
  /\ ~done
  /\ ~shutdown
  /\ phase[c] \in {"CatchingUp", "Rebuilding"}
  /\ prepared[c].active
  /\ PreparedCurrent(c)
  /\ io[c] = "Idle"

EnResolveCommit(c) ==
  /\ ~done
  /\ io[c] \in {"Pending", "Unknown"}

EnRollBack(c) ==
  /\ ~done
  /\ phase[c] = "RollingBack"
  /\ durableWatermark[c].active

EnMarkReady(c) ==
  /\ ~done
  /\ phase[c] = "CatchingUp"
  /\ ~fenceHeld
  /\ generation # 1
  /\ io[c] = "Idle"
  /\ target[c] = tip
  /\ watermark[c].active
  /\ watermark[c].tip = tip
  /\ watermark[c].h = height
  /\ watermark[c].sch = schema[c]
  /\ watermark[c].rev = revision[c]
  /\ healthy[c]

EnRecover(c) ==
  /\ ~done
  /\ (phase[c] \in {"Opening", "Failed"}) \/ (io[c] = "Unknown")

EnSelect(j) == /\ ~done /\ job[j] = "Captured"
EnAssemble(j) == /\ ~done /\ job[j] = "Selected"
EnComplete(j) == /\ ~done /\ job[j] = "Validated"

EnEvaluateQuery == /\ ~done /\ request = "Query" /\ result = "None"
EnSettleRequest == /\ ~done /\ request # "None" /\ result # "None"
EnEvaluateProposal == /\ ~done /\ request = "Proposal" /\ result = "None"
EnResolveSubmit == /\ ~done /\ request = "Submit" /\ submitIO \in {"Pending", "Unknown"}

\* One clear rule for every request-clearing site: an unresolved Submit
\* owns its I/O ladder until ResolveSubmit settles it, so no fence, crash,
\* cancellation, or settlement may orphan the ladder mid-flight.
ClearReq ==
  IF request = "Submit" /\ submitIO \in {"Pending", "Unknown"}
  THEN request ELSE "None"

\* The durable-submission channel resets exactly when its request resolves
\* and clears: a terminal Failed or Committed outcome belongs to the request
\* being cleared and must not leak into the honesty accounting of a later
\* request.  An unresolved Submit (Pending or Unknown) pins its request via
\* ClearReq and keeps its channel state.
ClearSubmitIO ==
  IF ClearReq = "None" /\ submitIO \in {"Failed", "Committed"}
  THEN "Idle" ELSE submitIO
EnServeCache ==
  /\ ~done
  /\ request = "Template"
  /\ result = "None"
  /\ ~fenceHeld
  /\ generation # 1

EnCancel ==
  /\ ~done
  /\ \/ /\ request # "None"
        /\ (request # "Submit" \/ submitIO \notin {"Pending", "Unknown"})
     \/ \E c \in Capabilities :
          prepared[c].active \/ io[c] \in {"Pending", "Unknown"}
     \/ \E j \in Jobs : job[j] \in {"Captured", "Selected", "Validated"}
     \/ waiting

EnPublishStable == /\ ~done /\ fenceHeld /\ reconciled
EnReconcileFence == /\ ~done /\ fenceHeld /\ ~reconciled
EnWake == /\ ~done /\ wake /\ waiting
EnDone == /\ ~done /\ DoneGuard

-------------------------------------------------------------------------------
(*** B.1 fence and B.4 external environment ***
 * External inputs consume one budget event; the fence closes admission and
 * mixed reads at an odd generation, reconciliation precedes the stable
 * publication, and the tip moves only through that publication edge.  ***)

ChainSwitch ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ generation = 0 /\ ~fenceHeld
  /\ budget' = budget - 1
  /\ generation' = 1
  /\ fenceHeld' = TRUE
  /\ reconciled' = FALSE
  /\ wake' = TRUE
  /\ request' = ClearReq /\ result' = "None"
  /\ submitIO' = ClearSubmitIO
  /\ UNCHANGED << tip, height, phase, enabled, revision, schema, watermark,
                   rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, job, allocated, pool, selected,
                   fee, modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, waiting, shutdown, closed, done >>
  /\ stepOK' = EdgeOK

ReconcileFence ==
  /\ EnReconcileFence
  /\ reconciled' = TRUE
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, job, allocated, pool, selected,
                   fee, modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, wake, waiting, shutdown, closed, done, fenceHeld,
                   request, result, submitIO, budget >>
  /\ stepOK' = EdgeOK

PublishStable ==
  /\ EnPublishStable
  /\ \E t \in Tips \ {tip} :
       /\ tip' = t
       /\ height' = TipHeight[t]
       /\ generation' = generation + 1
       /\ fenceHeld' = FALSE
       /\ wake' = TRUE
       /\ cacheValid' = FALSE
       /\ cacheKey' = NoKey
       /\ valid' = [j \in Jobs |-> FALSE]
       /\ phase' = [c \in Capabilities |->
                      IF phase[c] = "Ready" THEN "CatchingUp" ELSE phase[c]]
       /\ UNCHANGED << enabled, revision, schema, watermark, rows, durableRows,
                       contribution, durableWatermark, durableContribution, io,
                       body, healthy, prepared, target, key, captured, job,
                       allocated, pool, selected, fee, modifiedFee, weight,
                       sigops, work, timeValid, waiting, shutdown, closed,
                       done, reconciled, request, result, submitIO, budget >>
       /\ stepOK' = EdgeOK

AdmitPoolTx ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ \E x \in PoolTxs \ pool :
       /\ pool' = pool \cup {x}
       /\ budget' = budget - 1
       /\ UNCHANGED << tip, height, generation, phase, enabled, revision,
                       schema, watermark, rows, durableRows, contribution,
                       durableWatermark, durableContribution, io, body,
                       healthy, prepared, target, key, captured, cacheKey,
                       job, allocated, selected, fee, modifiedFee, weight,
                       sigops, work, valid, cacheValid, timeValid, wake,
                       waiting, shutdown, closed, done, fenceHeld, reconciled,
                       request, result, submitIO >>
       /\ stepOK' = EdgeOK

\* B.3 Invalidate: the owner advances its key revision; advancing is
\* exhausted at K1 and never wraps.  Notification delivery and the wake bit
\* are independent of invalidation, so wake is unchanged here.
InvalidateKey ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ key = K0
  /\ key' = K1
  /\ budget' = budget - 1
  /\ cacheValid' = FALSE
  /\ cacheKey' = NoKey
  /\ valid' = [j \in Jobs |-> FALSE]
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   captured, job, allocated, pool, selected, fee, modifiedFee,
                   weight, sigops, work, timeValid, wake, waiting, shutdown,
                   closed, done, fenceHeld, reconciled, request, result,
                   submitIO >>
  /\ stepOK' = EdgeOK

\* External time-validity input: flips the predicate itself and wakes the
\* long polls; matching revisions alone do not authorize an expired template.
TickTime ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ timeValid' = ~timeValid
  /\ wake' = TRUE
  /\ budget' = budget - 1
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, job, allocated, pool, selected,
                   fee, modifiedFee, weight, sigops, work, valid, cacheValid,
                   waiting, shutdown, closed, done, fenceHeld, reconciled,
                   request, result, submitIO >>
  /\ stepOK' = EdgeOK

Seal ==
  /\ ~done /\ ~closed
  /\ closed' = TRUE
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, job, allocated, pool, selected,
                   fee, modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, wake, waiting, shutdown, done, fenceHeld,
                   reconciled, request, result, submitIO, budget >>
  /\ stepOK' = EdgeOK

Done ==
  /\ EnDone
  /\ done' = TRUE
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, job, allocated, pool, selected,
                   fee, modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, wake, waiting, shutdown, closed, fenceHeld,
                   reconciled, request, result, submitIO, budget >>
  /\ stepOK' = EdgeOK

-------------------------------------------------------------------------------
(*** B.4 faults: missing bodies and contributions, worker failure, lost
 * notification, crash, and ambiguous write completion.  A crash discards
 * volatile eligibility only; durable bytes survive within completed sync
 * guarantees, never manufacturing partially durable success.       ***)

FaultWorkerFail(j) ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ job[j] \in {"Captured", "Selected", "Validated"}
  /\ budget' = budget - 1
  /\ job' = [job EXCEPT ![j] = "Rejected"]
  /\ valid' = [valid EXCEPT ![j] = FALSE]
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, allocated, pool, selected, fee,
                   modifiedFee, weight, sigops, work, cacheValid, timeValid,
                   wake, waiting, shutdown, closed, done, fenceHeld,
                   reconciled, request, result, submitIO >>
  /\ stepOK' = EdgeOK

FaultMissingBody(t) ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ body[t]
  /\ budget' = budget - 1
  /\ body' = [body EXCEPT ![t] = FALSE]
  /\ prepared' = [c \in Capabilities |->
                    IF prepared[c].target = t THEN NoPrep(c) ELSE prepared[c]]
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, healthy, target, key, captured,
                   cacheKey, job, allocated, pool, selected, fee, modifiedFee,
                   weight, sigops, work, valid, cacheValid, timeValid, wake,
                   waiting, shutdown, closed, done, fenceHeld, reconciled,
                   request, result, submitIO >>
  /\ stepOK' = EdgeOK

FaultMissingContribution(c) ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ durableContribution[c][durableWatermark[c].tip].active
  /\ budget' = budget - 1
  /\ durableContribution' =
       [durableContribution EXCEPT ![c] =
          [durableContribution[c] EXCEPT ![durableWatermark[c].tip] = NoContr]]
  /\ contribution' =
       [contribution EXCEPT ![c] =
          [contribution[c] EXCEPT ![durableWatermark[c].tip] = NoContr]]
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, durableWatermark, io, body,
                   healthy, prepared, target, key, captured, cacheKey, job,
                   allocated, pool, selected, fee, modifiedFee, weight,
                   sigops, work, valid, cacheValid, timeValid, wake, waiting,
                   shutdown, closed, done, fenceHeld, reconciled, request,
                   result, submitIO >>
  /\ stepOK' = EdgeOK

FaultLostNotification ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ wake
  /\ budget' = budget - 1
  /\ wake' = FALSE
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, job, allocated, pool, selected,
                   fee, modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, waiting, shutdown, closed, done, fenceHeld,
                   reconciled, request, result, submitIO >>
  /\ stepOK' = EdgeOK

FaultCrash ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ budget' = budget - 1
  /\ cacheValid' = FALSE
  /\ cacheKey' = NoKey
  /\ valid' = [j \in Jobs |-> FALSE]
  /\ wake' = FALSE
  /\ waiting' = FALSE
  /\ request' = ClearReq
  /\ result' = "None"
  /\ submitIO' = ClearSubmitIO
  /\ prepared' = [c \in Capabilities |-> NoPrep(c)]
  /\ healthy' = [c \in Capabilities |-> FALSE]
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, target, key, captured, job,
                   allocated, pool, selected, fee, modifiedFee, weight,
                   sigops, work, timeValid, shutdown, closed, done, fenceHeld,
                   reconciled >>
  /\ stepOK' = EdgeOK

FaultAmbiguousIO ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ budget' = budget - 1
  /\ \/ \E c \in Capabilities :
         /\ io[c] \in {"Idle", "Pending"}
         /\ io' = [io EXCEPT ![c] = "Unknown"]
         /\ UNCHANGED << tip, height, generation, phase, enabled, revision,
                         schema, watermark, rows, durableRows, contribution,
                         durableWatermark, durableContribution, body, healthy,
                         prepared, target, key, captured, cacheKey, job,
                         allocated, pool, selected, fee, modifiedFee, weight,
                         sigops, work, valid, cacheValid, timeValid, wake,
                         waiting, shutdown, closed, done, fenceHeld,
                         reconciled, request, result, submitIO >>
     \/ (/\ submitIO = "Pending"
         /\ submitIO' = "Unknown"
         /\ UNCHANGED << tip, height, generation, phase, enabled, revision,
                         schema, watermark, rows, durableRows, contribution,
                         durableWatermark, durableContribution, io, body,
                         healthy, prepared, target, key, captured, cacheKey,
                         job, allocated, pool, selected, fee, modifiedFee,
                         weight, sigops, work, valid, cacheValid, timeValid,
                         wake, waiting, shutdown, closed, done, fenceHeld,
                         reconciled, request, result >>)
  /\ stepOK' = EdgeOK

-------------------------------------------------------------------------------
(*** B.2 optional projection machine ***)

Open(c) ==
  /\ EnOpen(c)
  /\ phase' = [phase EXCEPT ![c] = "Opening"]
  /\ UNCHANGED << tip, height, generation, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, job, allocated, pool, selected,
                   fee, modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, wake, waiting, shutdown, closed, done, fenceHeld,
                   reconciled, request, result, submitIO, budget >>
  /\ stepOK' = EdgeOK

\* Resolution of Opening: reopen the durable view as one state; a compatible
\* committed root leads to CatchingUp, an incompatible or incomplete one to
\* Rebuilding or Failed - never fabricated readiness.
InspectDurable(c) ==
  /\ EnInspect(c)
  /\ watermark' = [watermark EXCEPT ![c] = durableWatermark[c]]
  /\ rows' = [rows EXCEPT ![c] = durableRows[c]]
  /\ contribution' = [contribution EXCEPT ![c] = durableContribution[c]]
  /\ \E p \in (IF durableWatermark[c].active
                  /\ durableWatermark[c].sch = schema[c]
               THEN {"CatchingUp", "Rebuilding", "Failed"}
               ELSE {"Rebuilding", "Failed"}) :
       phase' = [phase EXCEPT ![c] = p]
  /\ UNCHANGED << tip, height, generation, enabled, revision, schema,
                   durableRows, durableWatermark, durableContribution, io,
                   body, healthy, prepared, target, key, captured, cacheKey,
                   job, allocated, pool, selected, fee, modifiedFee, weight,
                   sigops, work, valid, cacheValid, timeValid, wake, waiting,
                   shutdown, closed, done, fenceHeld, reconciled, request,
                   result, submitIO, budget >>
  /\ stepOK' = EdgeOK

\* External retarget input: a coherent published target or a detected gap.
\* Height equality alone cannot preserve Ready; the hash-tagged target is
\* retained, prepared work is revoked, and the selection follows the
\* ancestor and coverage facts.
Retarget(c) ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ phase[c] \in {"Opening", "CatchingUp", "Ready", "RollingBack", "Rebuilding"}
  /\ revision[c] < 2
  /\ revision' = [revision EXCEPT ![c] = revision[c] + 1]
  /\ target' = [target EXCEPT ![c] = tip]
  /\ prepared' = [prepared EXCEPT ![c] = NoPrep(c)]
  /\ request' = IF request = "Query" THEN "None" ELSE request
  /\ result' = IF request = "Query" THEN "None" ELSE result
  /\ \E p \in (IF durableWatermark[c].active
               THEN {"CatchingUp", "RollingBack", "Rebuilding"}
               ELSE {"CatchingUp", "Rebuilding"}) :
       phase' = [phase EXCEPT ![c] = p]
  /\ budget' = budget - 1
  /\ UNCHANGED << tip, height, generation, enabled, schema, watermark, rows,
                   durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, key, captured,
                   cacheKey, job, allocated, pool, selected, fee, modifiedFee,
                   weight, sigops, work, valid, cacheValid, timeValid, wake,
                   waiting, shutdown, closed, done, fenceHeld, reconciled,
                   submitIO >>
  /\ stepOK' = EdgeOK

\* Bounded body batch, parsed once across aligned capabilities; the record
\* carries parent, target hash, schema, revision, the exact before-image,
\* and a nonempty distinct row change.  Empty batches do not exist.
PrepareBackfill(c) ==
  /\ EnPrepare(c)
  /\ \E act \in SUBSET Rows :
       /\ act # {}
       /\ act # durableRows[c]
       /\ prepared' = [prepared EXCEPT ![c] =
            [active |-> TRUE, after |-> act, before |-> durableRows[c],
             cap |-> c,
             parent |-> IF durableWatermark[c].active
                        THEN durableWatermark[c].tip ELSE O,
             rev |-> revision[c], sch |-> schema[c], target |-> tip]]
       /\ UNCHANGED << tip, height, generation, phase, enabled, revision,
                       schema, watermark, rows, durableRows, contribution,
                       durableWatermark, durableContribution, io, body,
                       healthy, target, key, captured, cacheKey, job,
                       allocated, pool, selected, fee, modifiedFee, weight,
                       sigops, work, valid, cacheValid, timeValid, wake,
                       waiting, shutdown, closed, done, fenceHeld, reconciled,
                       request, result, submitIO, budget >>
       /\ stepOK' = EdgeOK

\* Commit boundary: identity and revision were rechecked by the guard; the
\* batch goes out as one named-family submission and stays unresolved until
\* completion arrives.
CommitBatch(c) ==
  /\ EnCommit(c)
  /\ io' = [io EXCEPT ![c] = "Pending"]
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, body, healthy, prepared, target, key,
                   captured, cacheKey, job, allocated, pool, selected, fee,
                   modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, wake, waiting, shutdown, closed, done, fenceHeld,
                   reconciled, request, result, submitIO, budget >>
  /\ stepOK' = EdgeOK

\* Commit resolution.  Stale or absent evidence is discarded without
\* publication; current evidence resolves to Committed, Unknown (only from
\* Pending - an Unknown self-loop would be an unfair forever-pending
\* lasso), or Failed.  Committed installs rows, per-block contribution, and
\* watermark as one durable state; Failed and Unknown touch no durable bytes.
ResolveCommit(c) ==
  /\ EnResolveCommit(c)
  /\ \/ (/\ ~PreparedCurrent(c)
         /\ io' = [io EXCEPT ![c] = "Idle"]
         /\ prepared' = [prepared EXCEPT ![c] = NoPrep(c)]
         /\ UNCHANGED << tip, height, generation, phase, enabled, revision,
                         schema, watermark, rows, durableRows, contribution,
                         durableWatermark, durableContribution, body, healthy,
                         target, key, captured, cacheKey, job, allocated,
                         pool, selected, fee, modifiedFee, weight, sigops,
                         work, valid, cacheValid, timeValid, wake, waiting,
                         shutdown, closed, done, fenceHeld, reconciled,
                         request, result, submitIO, budget >>)
     \/ (/\ PreparedCurrent(c)
         /\ \E out \in (IF io[c] = "Pending"
                        THEN {"Committed", "Unknown", "Failed"}
                        ELSE {"Committed", "Failed"}) :
              \/ (/\ out = "Unknown"
                  /\ io' = [io EXCEPT ![c] = "Unknown"]
                  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema, watermark, rows, durableRows, contribution, durableWatermark, durableContribution, body, healthy, prepared, target, key, captured, cacheKey, job, allocated, pool, selected, fee, modifiedFee, weight, sigops, work, valid, cacheValid, timeValid, wake, waiting, shutdown, closed, done, fenceHeld, reconciled, request, result, submitIO, budget >>)
              \/ (/\ out = "Failed"
                  /\ io' = [io EXCEPT ![c] = "Failed"]
                  /\ phase' = [phase EXCEPT ![c] = "Failed"]
                  /\ prepared' = [prepared EXCEPT ![c] = NoPrep(c)]
                  /\ UNCHANGED << tip, height, generation, enabled, revision, schema, watermark, rows, durableRows, contribution, durableWatermark, durableContribution, body, healthy, target, key, captured, cacheKey, job, allocated, pool, selected, fee, modifiedFee, weight, sigops, work, valid, cacheValid, timeValid, wake, waiting, shutdown, closed, done, fenceHeld, reconciled, request, result, submitIO, budget >>)
              \/ (/\ out = "Committed"
                  /\ io' = [io EXCEPT ![c] = "Committed"]
                  /\ durableRows' = [durableRows EXCEPT ![c] = prepared[c].after]
                  /\ rows' = [rows EXCEPT ![c] = prepared[c].after]
                  /\ durableWatermark' = [durableWatermark EXCEPT ![c] = Wm(c, TipHeight[prepared[c].target], prepared[c].target, prepared[c].sch, prepared[c].rev)]
                  /\ watermark' = [watermark EXCEPT ![c] = Wm(c, TipHeight[prepared[c].target], prepared[c].target, prepared[c].sch, prepared[c].rev)]
                  /\ durableContribution' = [durableContribution EXCEPT ![c] = [durableContribution[c] EXCEPT ![prepared[c].target] = [active |-> TRUE, after |-> prepared[c].after, before |-> prepared[c].before]]]
                  /\ contribution' = [contribution EXCEPT ![c] = [contribution[c] EXCEPT ![prepared[c].target] = [active |-> TRUE, after |-> prepared[c].after, before |-> prepared[c].before]]]
                  /\ phase' = [phase EXCEPT ![c] = "CatchingUp"]
                  /\ prepared' = [prepared EXCEPT ![c] = NoPrep(c)]
                  /\ UNCHANGED << tip, height, generation, enabled, revision, schema, body, healthy, target, key, captured, cacheKey, job, allocated, pool, selected, fee, modifiedFee, weight, sigops, work, valid, cacheValid, timeValid, wake, waiting, shutdown, closed, done, fenceHeld, reconciled, request, result, submitIO, budget >>) )
  /\ stepOK' = EdgeOK

\* Exact inverse per block; missing contributions enter Rebuilding for the
\* affected capability only.
RollBack(c) ==
  /\ EnRollBack(c)
  /\ \/ (/\ durableContribution[c][durableWatermark[c].tip].active
         /\ durableRows' = [durableRows EXCEPT ![c] =
               durableContribution[c][durableWatermark[c].tip].before]
         /\ rows' = [rows EXCEPT ![c] =
               durableContribution[c][durableWatermark[c].tip].before]
         /\ durableWatermark' = [durableWatermark EXCEPT ![c] =
               Wm(c, TipHeight[Parent[durableWatermark[c].tip]],
                  Parent[durableWatermark[c].tip],
                  durableWatermark[c].sch, durableWatermark[c].rev)]
         /\ watermark' = [watermark EXCEPT ![c] =
               Wm(c, TipHeight[Parent[durableWatermark[c].tip]],
                  Parent[durableWatermark[c].tip],
                  durableWatermark[c].sch, durableWatermark[c].rev)]
         /\ durableContribution' = [durableContribution EXCEPT ![c] =
               [durableContribution[c] EXCEPT ![durableWatermark[c].tip] = NoContr]]
         /\ contribution' = [contribution EXCEPT ![c] =
               [contribution[c] EXCEPT ![durableWatermark[c].tip] = NoContr]]
         /\ UNCHANGED << tip, height, generation, phase, enabled, revision,
                         schema, io, body, healthy, prepared, target, key,
                         captured, cacheKey, job, allocated, pool, selected,
                         fee, modifiedFee, weight, sigops, work, valid,
                         cacheValid, timeValid, wake, waiting, shutdown,
                         closed, done, fenceHeld, reconciled, request, result,
                         submitIO, budget >> )
     \/ (/\ ~durableContribution[c][durableWatermark[c].tip].active
         /\ phase' = [phase EXCEPT ![c] = "Rebuilding"]
         /\ UNCHANGED << tip, height, generation, enabled, revision, schema,
                         watermark, rows, durableRows, contribution,
                         durableWatermark, durableContribution, io, body,
                         healthy, prepared, target, key, captured, cacheKey,
                         job, allocated, pool, selected, fee, modifiedFee,
                         weight, sigops, work, valid, cacheValid, timeValid,
                         wake, waiting, shutdown, closed, done, fenceHeld,
                         reconciled, request, result, submitIO, budget >> )

\* Bounded reset of the affected capability only; ScriptLive reseeds here
\* and stays unqueryable until the final watermark commits.
  /\ stepOK' = EdgeOK
Rebuild(c) ==
  /\ EnRebuild(c)
  /\ rows' = [rows EXCEPT ![c] = {}]
  /\ durableRows' = [durableRows EXCEPT ![c] = {}]
  /\ watermark' = [watermark EXCEPT ![c] = NoWm(c)]
  /\ durableWatermark' = [durableWatermark EXCEPT ![c] = NoWm(c)]
  /\ contribution' = [contribution EXCEPT ![c] = [t \in Tips |-> NoContr]]
  /\ durableContribution' =
       [durableContribution EXCEPT ![c] = [t \in Tips |-> NoContr]]
  /\ prepared' = [prepared EXCEPT ![c] = NoPrep(c)]
  /\ io' = [io EXCEPT ![c] = "Idle"]
  /\ healthy' = [healthy EXCEPT ![c] = TRUE]
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   body, target, key, captured, cacheKey, job, allocated,
                   pool, selected, fee, modifiedFee, weight, sigops, work,
                   valid, cacheValid, timeValid, wake, waiting, shutdown,
                   closed, done, fenceHeld, reconciled, request, result,
                   submitIO, budget >>
  /\ stepOK' = EdgeOK

MarkReady(c) ==
  /\ EnMarkReady(c)
  /\ phase' = [phase EXCEPT ![c] = "Ready"]
  /\ UNCHANGED << tip, height, generation, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, job, allocated, pool, selected,
                   fee, modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, wake, waiting, shutdown, closed, done, fenceHeld,
                   reconciled, request, result, submitIO, budget >>
  /\ stepOK' = EdgeOK

Query ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ request = "None"
  /\ ~fenceHeld
  /\ request' = "Query"
  /\ budget' = budget - 1
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, job, allocated, pool, selected,
                   fee, modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, wake, waiting, shutdown, closed, done, fenceHeld,
                   reconciled, result, submitIO >>
  /\ stepOK' = EdgeOK

Disable(c) ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ phase[c] # "Shutdown"
  /\ enabled' = [enabled EXCEPT ![c] = FALSE]
  /\ phase' = [phase EXCEPT ![c] = "Disabled"]
  /\ prepared' = [prepared EXCEPT ![c] = NoPrep(c)]
  /\ io' = [io EXCEPT ![c] =
              IF io[c] \in {"Pending", "Unknown"} THEN "Failed" ELSE io[c]]
  /\ request' = IF request = "Query" THEN "None" ELSE request
  /\ result' = IF request = "Query" THEN "None" ELSE result
  /\ budget' = budget - 1
  /\ UNCHANGED << tip, height, generation, revision, schema, watermark, rows,
                   durableRows, contribution, durableWatermark,
                   durableContribution, body, healthy, target, key, captured,
                   cacheKey, job, allocated, pool, selected, fee, modifiedFee,
                   weight, sigops, work, valid, cacheValid, timeValid, wake,
                   waiting, shutdown, closed, done, fenceHeld, reconciled,
                   submitIO >>
  /\ stepOK' = EdgeOK

\* Recovery reopens rows, contributions, and watermark as one durable state;
\* readiness always requires a fresh MarkReady.  From Failed the capability
\* never resolves to Failed again, so the edge always changes state.
Recover(c) ==
  /\ EnRecover(c)
  /\ io' = [io EXCEPT ![c] = "Idle"]
  /\ rows' = [rows EXCEPT ![c] = durableRows[c]]
  /\ watermark' = [watermark EXCEPT ![c] = durableWatermark[c]]
  /\ contribution' = [contribution EXCEPT ![c] = durableContribution[c]]
  /\ prepared' = [prepared EXCEPT ![c] = NoPrep(c)]
  /\ healthy' = [healthy EXCEPT ![c] = TRUE]
  /\ request' = IF request = "Query" THEN "None" ELSE request
  /\ result' = IF request = "Query" THEN "None" ELSE result
  /\ \E p \in (IF phase[c] = "Failed"
               THEN {"CatchingUp", "Rebuilding"}
               ELSE (IF durableWatermark[c].active
                     THEN {"CatchingUp", "Rebuilding", "Failed"}
                     ELSE {"Rebuilding", "Failed"})) :
       phase' = [phase EXCEPT ![c] = p]
  /\ UNCHANGED << tip, height, generation, enabled, revision, schema,
                   durableRows, durableWatermark, durableContribution, body,
                   target, key, captured, cacheKey, job, allocated, pool,
                   selected, fee, modifiedFee, weight, sigops, work, valid,
                   cacheValid, timeValid, wake, waiting, shutdown, closed,
                   done, fenceHeld, reconciled, submitIO, budget >>
  /\ stepOK' = EdgeOK

-------------------------------------------------------------------------------
(*** B.3 mining template machine ***
 * Selection ranks by modified fees but actual fees pay the coinbase; the
 * fee facts stay distinct per job.  Every key comparison is the full-key
 * comparison of FullKeyMatch.                                        ***)

\* External template admission: stable coherent fence, free single-use
\* worker slot, and an immutable capture of the entire current key.
Capture ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ request = "None"
  /\ ~fenceHeld /\ generation # 1
  /\ key.active
  /\ budget' = budget - 1
  /\ request' = "Template"
  /\ \E j \in Jobs :
       \E f \in {0, 1, 2} :
       \E mf \in {-2, -1, 0, 1, 2} :
       \E w \in {0, 1, 2} :
       \E s \in {0, 1, 2} :
         /\ j \notin allocated
         /\ allocated' = allocated \cup {j}
         /\ job' = [job EXCEPT ![j] = "Captured"]
         /\ captured' = [captured EXCEPT ![j] = key]
         /\ selected' = [selected EXCEPT ![j] = {}]
         /\ valid' = [valid EXCEPT ![j] = FALSE]
         /\ fee' = [fee EXCEPT ![j] = f]
         /\ modifiedFee' = [modifiedFee EXCEPT ![j] = mf]
         /\ weight' = [weight EXCEPT ![j] = w]
         /\ sigops' = [sigops EXCEPT ![j] = s]
         /\ work' = [work EXCEPT ![j] = 0]
         /\ UNCHANGED << tip, height, generation, phase, enabled, revision,
                         schema, watermark, rows, durableRows, contribution,
                         durableWatermark, durableContribution, io, body,
                         healthy, prepared, target, key, cacheKey, pool,
                         cacheValid, timeValid, wake, waiting, shutdown,
                         closed, done, fenceHeld, reconciled, result,
                         submitIO >>
         /\ stepOK' = EdgeOK

\* Dependency-closed selection from the snapshot: x1 requires x0, and the
\* checked exact domains of fee, weight, and sigops are fixed by TypeOK.
Select(j) ==
  /\ EnSelect(j)
  /\ \E S \in {{}, {X0}, {X1}, {X0, X1}} :
       /\ S \subseteq pool
       /\ DepClosed(S)
       /\ selected' = [selected EXCEPT ![j] = S]
       /\ job' = [job EXCEPT ![j] = "Selected"]
       /\ UNCHANGED << tip, height, generation, phase, enabled, revision,
                       schema, watermark, rows, durableRows, contribution,
                       durableWatermark, durableContribution, io, body,
                       healthy, prepared, target, key, captured, cacheKey,
                       allocated, pool, fee, modifiedFee, weight, sigops,
                       work, valid, cacheValid, timeValid, wake, waiting,
                       shutdown, closed, done, fenceHeld, reconciled,
                       request, result, submitIO, budget >>
       /\ stepOK' = EdgeOK

\* Assembly and shared contextual validation of the fully rendered
\* candidate; failure is preserved as a typed rejection.
AssembleValidate(j) ==
  /\ EnAssemble(j)
  /\ \/ (/\ FullKeyMatch(captured[j])
         /\ job' = [job EXCEPT ![j] = "Validated"]
         /\ valid' = [valid EXCEPT ![j] = TRUE]
         /\ UNCHANGED << tip, height, generation, phase, enabled, revision,
                         schema, watermark, rows, durableRows, contribution,
                         durableWatermark, durableContribution, io, body,
                         healthy, prepared, target, key, captured, cacheKey,
                         allocated, pool, selected, fee, modifiedFee, weight,
                         sigops, work, cacheValid, timeValid, wake, waiting,
                         shutdown, closed, done, fenceHeld, reconciled,
                         request, result, submitIO, budget >> )
     \/ (/\ job' = [job EXCEPT ![j] = "Rejected"]
         /\ UNCHANGED << tip, height, generation, phase, enabled, revision,
                         schema, watermark, rows, durableRows, contribution,
                         durableWatermark, durableContribution, io, body,
                         healthy, prepared, target, key, captured, cacheKey,
                         allocated, pool, selected, fee, modifiedFee, weight,
                         sigops, work, valid, cacheValid, timeValid, wake,
                         waiting, shutdown, closed, done, fenceHeld,
                         reconciled, request, result, submitIO, budget >> )

\* Bounded cache insertion: only a successfully validated current candidate
\* is inserted; a stale completion is silently discarded.
  /\ stepOK' = EdgeOK
Complete(j) ==
  /\ EnComplete(j)
  /\ job' = [job EXCEPT ![j] = "Settled"]
  /\ IF FullKeyMatch(captured[j])
     THEN (cacheKey' = captured[j] /\ cacheValid' = TRUE)
     ELSE (cacheKey' = cacheKey /\ cacheValid' = cacheValid)
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, allocated, pool, selected, fee, modifiedFee,
                   weight, sigops, work, valid, timeValid, wake, waiting,
                   shutdown, closed, done, fenceHeld, reconciled, request,
                   result, submitIO, budget >>
  /\ stepOK' = EdgeOK

\* Serving under the bounded coherent read fence: only a matching validated
\* entry succeeds; a miss answers Retry or Unavailable and revokes the
\* ineligible cache - never stale success.
ServeCache ==
  /\ EnServeCache
  /\ \/ (/\ cacheValid
         /\ FullKeyMatch(cacheKey)
         /\ result' = "Success"
         /\ UNCHANGED << tip, height, generation, phase, enabled, revision,
                         schema, watermark, rows, durableRows, contribution,
                         durableWatermark, durableContribution, io, body,
                         healthy, prepared, target, key, captured, cacheKey,
                         job, allocated, pool, selected, fee, modifiedFee,
                         weight, sigops, work, valid, cacheValid, timeValid,
                         wake, waiting, shutdown, closed, done, fenceHeld,
                         reconciled, request, submitIO, budget >> )
     \/ (/\ result' \in {"Retry", "Unavailable"}
         /\ cacheValid' = FALSE
         /\ cacheKey' = NoKey
         /\ UNCHANGED << tip, height, generation, phase, enabled, revision,
                         schema, watermark, rows, durableRows, contribution,
                         durableWatermark, durableContribution, io, body,
                         healthy, prepared, target, key, captured, job,
                         allocated, pool, selected, fee, modifiedFee, weight,
                         sigops, work, valid, timeValid, wake, waiting,
                         shutdown, closed, done, fenceHeld, reconciled,
                         request, submitIO, budget >> )

  /\ stepOK' = EdgeOK
Wait ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ ~waiting
  /\ waiting' = TRUE
  /\ budget' = budget - 1
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, job, allocated, pool, selected,
                   fee, modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, wake, shutdown, closed, done, fenceHeld,
                   reconciled, request, result, submitIO >>
  /\ stepOK' = EdgeOK

Wake ==
  /\ EnWake
  /\ wake' = FALSE
  /\ waiting' = FALSE
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, job, allocated, pool, selected,
                   fee, modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, shutdown, closed, done, fenceHeld, reconciled,
                   request, result, submitIO, budget >>
  /\ stepOK' = EdgeOK

Proposal ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ request = "None"
  /\ request' = "Proposal"
  /\ budget' = budget - 1
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, job, allocated, pool, selected,
                   fee, modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, wake, waiting, shutdown, closed, done, fenceHeld,
                   reconciled, result, submitIO >>
  /\ stepOK' = EdgeOK

EvaluateProposal ==
  /\ EnEvaluateProposal
  /\ \E r \in {"Success", "Rejected"} : result' = r
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, job, allocated, pool, selected,
                   fee, modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, wake, waiting, shutdown, closed, done, fenceHeld,
                   reconciled, request, submitIO, budget >>
  /\ stepOK' = EdgeOK

\* Solved or raw submission: ordinary validation and chainstate
\* orchestration abstracted to the durable I/O ladder; blocks may carry
\* transactions absent from the pool.
SolvedSubmit ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ request = "None"
  /\ submitIO = "Idle"
  /\ request' = "Submit"
  /\ submitIO' = "Pending"
  /\ job' = [j \in Jobs |->
               IF job[j] = "Validated" THEN "PendingSubmit" ELSE job[j]]
  /\ budget' = budget - 1
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, allocated, pool, selected, fee,
                   modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, wake, waiting, shutdown, closed, done, fenceHeld,
                   reconciled, result >>
  /\ stepOK' = EdgeOK

\* Completion of the solved submission; a live success abstracts waiting for
\* durable body, undo, coins, head, pool reconciliation, and coherent
\* publication - an ambiguous completion resolves from durable state, and
\* I/O failure never succeeds.
ResolveSubmit ==
  /\ EnResolveSubmit
  /\ request = "Submit"
  /\ \E out \in {"Committed", "Failed"} :
       /\ submitIO' = out
       /\ job' = [j \in Jobs |->
                    IF job[j] = "PendingSubmit" THEN "Settled" ELSE job[j]]
       /\ result' = IF out = "Committed" THEN "Success" ELSE "Rejected"
       /\ UNCHANGED << tip, height, generation, phase, enabled, revision,
                       schema, watermark, rows, durableRows, contribution,
                       durableWatermark, durableContribution, io, body,
                       healthy, prepared, target, key, captured, cacheKey,
                       allocated, pool, selected, fee, modifiedFee, weight,
                       sigops, work, valid, cacheValid, timeValid, wake,
                       waiting, shutdown, closed, done, fenceHeld, reconciled,
                       request, budget >>
       /\ stepOK' = EdgeOK

EvaluateQuery ==
  /\ EnEvaluateQuery
  /\ IF AllReady
     THEN result' = "Success"
     ELSE \E r \in {"Unavailable", "Retry"} : result' = r
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, job, allocated, pool, selected,
                   fee, modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, wake, waiting, shutdown, closed, done, fenceHeld,
                   reconciled, request, submitIO, budget >>
  /\ stepOK' = EdgeOK

SettleRequest ==
  /\ EnSettleRequest
  /\ request' = ClearReq
  /\ result' = "None"
  /\ submitIO' = ClearSubmitIO
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, prepared, target,
                   key, captured, cacheKey, job, allocated, pool, selected,
                   fee, modifiedFee, weight, sigops, work, valid, cacheValid,
                   timeValid, wake, waiting, shutdown, closed, done, fenceHeld,
                   reconciled, budget >>
  /\ stepOK' = EdgeOK

Cancel ==
  /\ EnCancel
  /\ request' = ClearReq
  /\ result' = "None"
  /\ submitIO' = ClearSubmitIO
  /\ prepared' = [c \in Capabilities |-> NoPrep(c)]
  /\ io' = [c \in Capabilities |->
              IF io[c] \in {"Pending", "Unknown"} THEN "Failed" ELSE io[c]]
  /\ job' = [j \in Jobs |->
               IF job[j] \in {"Captured", "Selected", "Validated"}
               THEN "Settled" ELSE job[j]]
  /\ waiting' = FALSE
  /\ UNCHANGED << tip, height, generation, phase, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, body, healthy, target, key, captured,
                   cacheKey, allocated, pool, selected, fee, modifiedFee,
                   weight, sigops, work, valid, cacheValid, timeValid, wake,
                   shutdown, closed, done, fenceHeld, reconciled, budget >>
  /\ stepOK' = EdgeOK

\* Owner shutdown: stop starts, drain bounded work, record unresolved
\* durable completion (io Unknown persists) for recovery, revoke pending
\* template publication, and drain waiters.  Already-started durable
\* submissions are reconciled, not undone.
ShutdownOwner ==
  /\ ~done /\ ~closed /\ ~shutdown
  /\ budget > 0
  /\ shutdown' = TRUE
  /\ budget' = budget - 1
  /\ phase' = [c \in Capabilities |->
                 IF phase[c] \in {"Disabled", "Failed", "Shutdown"}
                 THEN phase[c] ELSE "Shutdown"]
  /\ prepared' = [c \in Capabilities |-> NoPrep(c)]
  /\ waiting' = FALSE
  /\ wake' = FALSE
  /\ cacheValid' = FALSE
  /\ cacheKey' = NoKey
  /\ job' = [j \in Jobs |->
               IF job[j] \in {"Captured", "Selected", "Validated"}
               THEN "Settled" ELSE job[j]]
  /\ request' = IF request = "Submit" /\ submitIO \in {"Pending", "Unknown"}
                THEN "Submit" ELSE "None"
  /\ result' = "None"
  /\ UNCHANGED << tip, height, generation, enabled, revision, schema,
                   watermark, rows, durableRows, contribution, durableWatermark,
                   durableContribution, io, body, healthy, target, key,
                   captured, allocated, pool, selected, fee, modifiedFee,
                   weight, sigops, work, valid, timeValid, closed, done,
                   fenceHeld, reconciled, submitIO >>
  /\ stepOK' = EdgeOK

-------------------------------------------------------------------------------
(*** Next: the unrestricted union of every action plus explicit Stutter ***
 * No priority, no scheduler restriction, and no fairness inside Next.  ***)

Stuttering == UNCHANGED vars

Next ==
  \/ Stuttering
  \/ ChainSwitch
  \/ ReconcileFence
  \/ PublishStable
  \/ AdmitPoolTx
  \/ InvalidateKey
  \/ TickTime
  \/ Seal
  \/ Done
  \/ FaultWorkerFail(J0)
  \/ FaultWorkerFail(J1)
  \/ \E t \in Tips : FaultMissingBody(t)
  \/ \E c \in Capabilities : FaultMissingContribution(c)
  \/ FaultLostNotification
  \/ FaultCrash
  \/ FaultAmbiguousIO
  \/ \E c \in Capabilities : Open(c)
  \/ \E c \in Capabilities : InspectDurable(c)
  \/ \E c \in Capabilities : Retarget(c)
  \/ \E c \in Capabilities : PrepareBackfill(c)
  \/ \E c \in Capabilities : CommitBatch(c)
  \/ \E c \in Capabilities : ResolveCommit(c)
  \/ \E c \in Capabilities : RollBack(c)
  \/ \E c \in Capabilities : Rebuild(c)
  \/ \E c \in Capabilities : MarkReady(c)
  \/ Query
  \/ \E c \in Capabilities : Disable(c)
  \/ \E c \in Capabilities : Recover(c)
  \/ Capture
  \/ \E j \in Jobs : Select(j)
  \/ \E j \in Jobs : AssembleValidate(j)
  \/ \E j \in Jobs : Complete(j)
  \/ ServeCache
  \/ Wait
  \/ Wake
  \/ Proposal
  \/ EvaluateProposal
  \/ SolvedSubmit
  \/ ResolveSubmit
  \/ EvaluateQuery
  \/ SettleRequest
  \/ Cancel
  \/ ShutdownOwner

-------------------------------------------------------------------------------
(*** TypeOK: exactly the B.4 finite domains, watermark capability tags, and
 * height/hash consistency.                                          ***)

TypeOK ==
  /\ tip \in Tips
  /\ height \in {0, 1}
  /\ height = TipHeight[tip]
  /\ generation \in {0, 1, 2}
  /\ \A c \in Capabilities :
       /\ phase[c] \in Phases
       /\ enabled[c] \in BOOLEAN
       /\ revision[c] \in {0, 1, 2}
       /\ schema[c] \in {0, 1}
       /\ watermark[c].cap = c
       /\ watermark[c].h \in {0, 1}
       /\ watermark[c].tip \in Tips
       /\ watermark[c].sch \in {0, 1}
       /\ watermark[c].rev \in {0, 1, 2}
       /\ (watermark[c].active => watermark[c].h = TipHeight[watermark[c].tip])
       /\ rows[c] \subseteq Rows
       /\ durableRows[c] \subseteq Rows
       /\ io[c] \in IOStates
       /\ healthy[c] \in BOOLEAN
       /\ prepared[c].cap = c
       /\ prepared[c].parent \in Tips
       /\ prepared[c].target \in Tips
       /\ prepared[c].sch \in {0, 1}
       /\ prepared[c].rev \in {0, 1, 2}
       /\ prepared[c].before \subseteq Rows
       /\ prepared[c].after \subseteq Rows
       /\ target[c] \in Tips
  /\ \A c \in Capabilities, t \in Tips :
       /\ contribution[c][t].before \subseteq Rows
       /\ contribution[c][t].after \subseteq Rows
       /\ durableContribution[c][t].before \subseteq Rows
       /\ durableContribution[c][t].after \subseteq Rows
  /\ \A t \in Tips : body[t] \in BOOLEAN
  /\ key \in Keys
  /\ \A j \in Jobs : captured[j] \in Keys
  /\ cacheKey \in Keys
  /\ \A j \in Jobs : job[j] \in JobStates
  /\ allocated \subseteq Jobs
  /\ Cardinality(allocated) <= 2
  /\ pool \subseteq PoolTxs
  /\ \A j \in Jobs :
       /\ selected[j] \subseteq PoolTxs
       /\ fee[j] \in {0, 1, 2}
       /\ modifiedFee[j] \in {-2, -1, 0, 1, 2}
       /\ weight[j] \in {0, 1, 2}
       /\ sigops[j] \in {0, 1, 2}
       /\ work[j] \in {0, 1, 2}
       /\ valid[j] \in BOOLEAN
  /\ cacheValid \in BOOLEAN
  /\ timeValid \in BOOLEAN
  /\ wake \in BOOLEAN
  /\ waiting \in BOOLEAN
  /\ shutdown \in BOOLEAN
  /\ closed \in BOOLEAN
  /\ done \in BOOLEAN
  /\ fenceHeld \in BOOLEAN
  /\ reconciled \in BOOLEAN
  /\ request \in {"None", "Query", "Template", "Proposal", "Submit"}
  /\ result \in {"None", "Success", "Retry", "Unavailable", "Rejected",
                 "Cancelled"}
  /\ submitIO \in IOStates
  /\ budget \in 0..ExternalBudget
  /\ stepOK \in BOOLEAN

-------------------------------------------------------------------------------
(*** Safety: per-capability atomic durable projection, exact reversible
 * lineage, readiness and query coherence, complete-key cache eligibility,
 * admitted dependency-closed selection, actual-versus-modified fee
 * separation, validated-only success, durable submission honesty, state
 * coherence, and bounded resources.  Owner separation is structural
 * (disjoint variable ownership per machine) and enforced at the edges by
 * StaleNoPublish, FaultAtomicity, FenceOrdering, ProposalNonmutation, and
 * CancelRevocation in TransitionSafety.                           ***)

\* The volatile projection is always the committed projection: rows,
\* watermark, and contributions publish atomically, never partially.
MirrorProjection ==
  /\ rows = durableRows
  /\ watermark = durableWatermark
  /\ contribution = durableContribution

\* A stored reversal record binds to the watermark tip it undoes.
Lineage ==
  \A c \in Capabilities, t \in Tips :
    durableContribution[c][t].active =>
      (durableWatermark[c].active /\ durableWatermark[c].tip = t)

ReadinessQueryCoherence ==
  /\ \A c \in Capabilities :
       (phase[c] = "Ready") =>
         (watermark[c].active /\ target[c] = tip
          /\ watermark[c].tip = tip /\ watermark[c].h = height
          /\ watermark[c].sch = schema[c] /\ watermark[c].rev = revision[c])
  /\ (request = "Query" /\ result = "Success") => AllReady

CacheEligibility ==
  /\ cacheValid => (cacheKey.active /\ cacheKey = key)
  /\ cacheValid => \E j \in Jobs :
         captured[j] = cacheKey
         /\ job[j] \in {"Validated", "PendingSubmit", "Settled"}

DependencyClosed ==
  \A j \in Jobs :
    /\ selected[j] \subseteq pool
    /\ DepClosed(selected[j])

\* Actual and modified fees stay distinct in their exact integer domains:
\* modified fees rank, actual fees pay.
ActualVsModifiedFee ==
  \A j \in Jobs :
    /\ fee[j] \in {0, 1, 2}
    /\ modifiedFee[j] \in {-2, -1, 0, 1, 2}

ValidatedOnly ==
  \A j \in Jobs : valid[j] => job[j] \in {"Validated", "PendingSubmit", "Settled"}

DurableSubmission ==
  /\ submitIO = "Failed" => result # "Success"
  /\ (request = "Submit" /\ result = "Success") => submitIO = "Committed"

StateCoherence == request = "None" => result = "None"

BoundedResources ==
  /\ budget \in 0..ExternalBudget
  /\ Cardinality(allocated) <= 2
  /\ \A c \in Capabilities : prepared[c].after \subseteq Rows

Safety ==
  /\ MirrorProjection
  /\ Lineage
  /\ ReadinessQueryCoherence
  /\ CacheEligibility
  /\ DependencyClosed
  /\ ActualVsModifiedFee
  /\ ValidatedOnly
  /\ DurableSubmission
  /\ StateCoherence
  /\ BoundedResources

TransitionSafety == stepOK

-------------------------------------------------------------------------------
(*** B.5 conditional progress ***
 * Apalache 0.62.2 supports no WF_/SF_ macros, no ENABLED primitive inside
 * temporal properties, and no substitution of a quantified variable inside
 * a temporal formula (all three measured on this binary: exit 75
 * "unsupported expression: ENABLED"; exit 255 "SubstRule: Variable a$1 is
 * not assigned a value").  B.5's FairServices over the finite settlement
 * set is therefore realized as the named conjunction of per-instance
 * clauses FairX == ((<>[] EnX) => ([]<> <<X>>_vars)) - the appendix A.5
 * expansion.  The set covers pending preparation, commit resolution,
 * rollback and rebuild steps, selection completion, typed rejection and
 * cancellation, recovery, request answering, waiter draining, fence
 * resolution, and Done; allocating external starts carry no fairness. ***)

FairPrepareTxLookup ==
  ((<>[] EnPrepare(TxLookup)) => ([]<> <<PrepareBackfill(TxLookup)>>_vars))
FairPrepareScriptLive ==
  ((<>[] EnPrepare(ScriptLive)) => ([]<> <<PrepareBackfill(ScriptLive)>>_vars))
FairPrepareScriptHistory ==
  ((<>[] EnPrepare(ScriptHistory)) => ([]<> <<PrepareBackfill(ScriptHistory)>>_vars))

FairResolveCommitTxLookup ==
  ((<>[] EnResolveCommit(TxLookup)) => ([]<> <<ResolveCommit(TxLookup)>>_vars))
FairResolveCommitScriptLive ==
  ((<>[] EnResolveCommit(ScriptLive)) => ([]<> <<ResolveCommit(ScriptLive)>>_vars))
FairResolveCommitScriptHistory ==
  ((<>[] EnResolveCommit(ScriptHistory)) => ([]<> <<ResolveCommit(ScriptHistory)>>_vars))

FairRollBackTxLookup ==
  ((<>[] EnRollBack(TxLookup)) => ([]<> <<RollBack(TxLookup)>>_vars))
FairRollBackScriptLive ==
  ((<>[] EnRollBack(ScriptLive)) => ([]<> <<RollBack(ScriptLive)>>_vars))
FairRollBackScriptHistory ==
  ((<>[] EnRollBack(ScriptHistory)) => ([]<> <<RollBack(ScriptHistory)>>_vars))

FairRebuildTxLookup ==
  ((<>[] EnRebuild(TxLookup)) => ([]<> <<Rebuild(TxLookup)>>_vars))
FairRebuildScriptLive ==
  ((<>[] EnRebuild(ScriptLive)) => ([]<> <<Rebuild(ScriptLive)>>_vars))
FairRebuildScriptHistory ==
  ((<>[] EnRebuild(ScriptHistory)) => ([]<> <<Rebuild(ScriptHistory)>>_vars))

FairRecoverTxLookup ==
  ((<>[] EnRecover(TxLookup)) => ([]<> <<Recover(TxLookup)>>_vars))
FairRecoverScriptLive ==
  ((<>[] EnRecover(ScriptLive)) => ([]<> <<Recover(ScriptLive)>>_vars))
FairRecoverScriptHistory ==
  ((<>[] EnRecover(ScriptHistory)) => ([]<> <<Recover(ScriptHistory)>>_vars))

FairSelectJ0 == ((<>[] EnSelect(J0)) => ([]<> <<Select(J0)>>_vars))
FairSelectJ1 == ((<>[] EnSelect(J1)) => ([]<> <<Select(J1)>>_vars))
FairAssembleJ0 == ((<>[] EnAssemble(J0)) => ([]<> <<AssembleValidate(J0)>>_vars))
FairAssembleJ1 == ((<>[] EnAssemble(J1)) => ([]<> <<AssembleValidate(J1)>>_vars))
FairCompleteJ0 == ((<>[] EnComplete(J0)) => ([]<> <<Complete(J0)>>_vars))
FairCompleteJ1 == ((<>[] EnComplete(J1)) => ([]<> <<Complete(J1)>>_vars))

FairEvaluateQuery == ((<>[] EnEvaluateQuery) => ([]<> <<EvaluateQuery>>_vars))
FairSettleRequest == ((<>[] EnSettleRequest) => ([]<> <<SettleRequest>>_vars))
FairEvaluateProposal == ((<>[] EnEvaluateProposal) => ([]<> <<EvaluateProposal>>_vars))
FairResolveSubmit == ((<>[] EnResolveSubmit) => ([]<> <<ResolveSubmit>>_vars))
FairServeCache == ((<>[] EnServeCache) => ([]<> <<ServeCache>>_vars))
FairCancel == ((<>[] EnCancel) => ([]<> <<Cancel>>_vars))
FairPublishStable == ((<>[] EnPublishStable) => ([]<> <<PublishStable>>_vars))
FairReconcileFence == ((<>[] EnReconcileFence) => ([]<> <<ReconcileFence>>_vars))
FairWake == ((<>[] EnWake) => ([]<> <<Wake>>_vars))
FairDone == ((<>[] EnDone) => ([]<> <<Done>>_vars))

FairServices ==
  /\ FairPrepareTxLookup
  /\ FairPrepareScriptLive
  /\ FairPrepareScriptHistory
  /\ FairResolveCommitTxLookup
  /\ FairResolveCommitScriptLive
  /\ FairResolveCommitScriptHistory
  /\ FairRollBackTxLookup
  /\ FairRollBackScriptLive
  /\ FairRollBackScriptHistory
  /\ FairRebuildTxLookup
  /\ FairRebuildScriptLive
  /\ FairRebuildScriptHistory
  /\ FairRecoverTxLookup
  /\ FairRecoverScriptLive
  /\ FairRecoverScriptHistory
  /\ FairSelectJ0
  /\ FairSelectJ1
  /\ FairAssembleJ0
  /\ FairAssembleJ1
  /\ FairCompleteJ0
  /\ FairCompleteJ1
  /\ FairEvaluateQuery
  /\ FairSettleRequest
  /\ FairEvaluateProposal
  /\ FairResolveSubmit
  /\ FairServeCache
  /\ FairCancel
  /\ FairPublishStable
  /\ FairReconcileFence
  /\ FairWake
  /\ FairDone

\* Under Init, the Next relation, eventual input closure, and weak fairness
\* of every settlement instance, every chain job and request settles or is
\* typed-rejected and the machine reaches Done.  Only eventual settlement is
\* promised - never Ready, successful mining, or optimal packing.
ConditionalProgress ==
  ((Init /\ [][Next]_vars) /\ <>closed /\ FairServices)
    => <>done


=============================================================================
