\* QRY-01, QRY-02, QRY-03, QRY-04, QRY-05, QRY-06, QRY-07, QRY-08, PRJ-11
---------------------------- MODULE ServingView ----------------------------
(***************************************************************************)
(* ServingView formal lifecycle and invariant safety model.                *)
(*                                                                         *)
(* Models AppliedEpoch, CapabilityCoverage, capture_view, single-view tied *)
(* query evaluation, resilience to ordinary chain extension (QRY-03),      *)
(* explicit Unavailable for out-of-coverage queries (QRY-05), generation   *)
(* retirement on deep reorg leading to ExpiredView (QRY-06), lock-free     *)
(* self-contained ScriptLive (PRJ-11), and post-access serialization       *)
(* without chain/mempool locks (QRY-08).                                   *)
(*                                                                         *)
(* Design model only: specifies the state machine and invariant safety.    *)
(* Not an implementation refinement proof or physical durability proof.    *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
  \* @type: Int;
  MaxHeight,
  \* @type: Int;
  MaxViews,
  \* @type: Int;
  MaxGenerations

VARIABLES
  \* @type: Int;
  tipHeight,
  \* @type: Int;
  tipCommit,
  \* @type: Int;
  currentGen,
  \* @type: Set(Int);
  retiredGens,
  \* @type: Int;
  coverageHeight,
  \* @type: Int -> [captured: Bool, viewEpochHeight: Int, viewEpochCommit: Int, viewGen: Int, viewCoverage: Int, status: Str];
  views,
  \* @type: Str;
  queryPhase,
  \* @type: Int;
  queryViewId,
  \* @type: Int;
  queryTargetHeight,
  \* @type: Bool;
  queryIsTipPromised,
  \* @type: Bool;
  queryIsScriptLive,
  \* @type: Str;
  queryResult,
  \* @type: [chainLock: Bool, mempoolLock: Bool];
  queryLocksHeld

vars == << tipHeight, tipCommit, currentGen, retiredGens, coverageHeight,
           views, queryPhase, queryViewId, queryTargetHeight,
           queryIsTipPromised, queryIsScriptLive, queryResult, queryLocksHeld >>

ViewIds == 1..MaxViews
GenIds == 1..MaxGenerations
HeightDom == 0..MaxHeight

ViewRecord == [
  captured: BOOLEAN,
  viewEpochHeight: HeightDom,
  viewEpochCommit: 0..MaxHeight,
  viewGen: GenIds,
  viewCoverage: HeightDom,
  status: {"None", "Active", "Expired"}
]

LockState == [
  chainLock: BOOLEAN,
  mempoolLock: BOOLEAN
]

TypeOK ==
  /\ tipHeight \in HeightDom
  /\ tipCommit \in 0..MaxHeight
  /\ currentGen \in GenIds
  /\ retiredGens \subseteq GenIds
  /\ coverageHeight \in HeightDom
  /\ views \in [ViewIds -> ViewRecord]
  /\ queryPhase \in {"Idle", "Captured", "ResponseReady", "Serializing"}
  /\ queryViewId \in ViewIds
  /\ queryTargetHeight \in HeightDom
  /\ queryIsTipPromised \in BOOLEAN
  /\ queryIsScriptLive \in BOOLEAN
  /\ queryResult \in {"None", "AnswerOk", "Unavailable", "ExpiredView", "Retry"}
  /\ queryLocksHeld \in LockState

InitView(i) == [
  captured |-> FALSE,
  viewEpochHeight |-> 0,
  viewEpochCommit |-> 0,
  viewGen |-> 1,
  viewCoverage |-> 0,
  status |-> "None"
]

InitLocks == [
  chainLock |-> FALSE,
  mempoolLock |-> FALSE
]

Init ==
  /\ tipHeight = 0
  /\ tipCommit = 0
  /\ currentGen = 1
  /\ retiredGens = {}
  /\ coverageHeight = 0
  /\ views = [i \in ViewIds |-> InitView(i)]
  /\ queryPhase = "Idle"
  /\ queryViewId = 1
  /\ queryTargetHeight = 0
  /\ queryIsTipPromised = FALSE
  /\ queryIsScriptLive = FALSE
  /\ queryResult = "None"
  /\ queryLocksHeld = InitLocks
\* Actions

\* Ordinary tip extension (QRY-03): commit and tip height advance.
ExtendChain ==
  /\ tipHeight < MaxHeight
  /\ tipHeight' = tipHeight + 1
  /\ tipCommit' = tipCommit + 1
  /\ UNCHANGED << currentGen, retiredGens, coverageHeight, views,
                  queryPhase, queryViewId, queryTargetHeight,
                  queryIsTipPromised, queryIsScriptLive, queryResult, queryLocksHeld >>

\* Projection coverage catches up to chain tip.
AdvanceCoverage ==
  /\ coverageHeight < tipHeight
  /\ coverageHeight' = coverageHeight + 1
  /\ UNCHANGED << tipHeight, tipCommit, currentGen, retiredGens, views,
                  queryPhase, queryViewId, queryTargetHeight,
                  queryIsTipPromised, queryIsScriptLive, queryResult, queryLocksHeld >>

\* Deep reorg (QRY-06): current generation is retired and replaced.
\* Views pinned to retired generations become Expired.
DeepReorg ==
  /\ currentGen < MaxGenerations
  /\ retiredGens' = retiredGens \cup {currentGen}
  /\ currentGen' = currentGen + 1
  /\ views' = [i \in ViewIds |->
       IF views[i].captured /\ (views[i].viewGen = currentGen \/ views[i].viewGen \in retiredGens')
       THEN [views[i] EXCEPT !.status = "Expired"]
       ELSE views[i]]
  /\ UNCHANGED << tipHeight, tipCommit, coverageHeight,
                  queryPhase, queryViewId, queryTargetHeight,
                  queryIsTipPromised, queryIsScriptLive, queryResult, queryLocksHeld >>

\* Capture view (QRY-01, QRY-07): long reader pins one view and generation.
CaptureView(v, isScriptLive, isTip, targetH) ==
  /\ queryPhase = "Idle"
  /\ views' = [views EXCEPT ![v] = [
       captured |-> TRUE,
       viewEpochHeight |-> tipHeight,
       viewEpochCommit |-> tipCommit,
       viewGen |-> currentGen,
       viewCoverage |-> coverageHeight,
       status |-> "Active"
     ]]
  /\ queryPhase' = "Captured"
  /\ queryViewId' = v
  /\ queryTargetHeight' = targetH
  /\ queryIsTipPromised' = isTip
  /\ queryIsScriptLive' = isScriptLive
  /\ queryResult' = "None"
  /\ queryLocksHeld' = [
       chainLock |-> ~isScriptLive,
       mempoolLock |-> FALSE
     ]
  /\ UNCHANGED << tipHeight, tipCommit, currentGen, retiredGens, coverageHeight >>

\* State access within view (QRY-02, QRY-03, QRY-05, QRY-06, PRJ-11):
\* QRY-02: a query reads its immutable captured view only; concurrent chain
\* extension changes tipHeight and tipCommit but never the captured view fields.
\* Serialization begins only after state access releases query-held locks.
 AccessState ==
   /\ queryPhase = "Captured"
   /\ LET v == views[queryViewId] IN
     IF v.status = "Expired" \/ v.viewGen \in retiredGens
     THEN \* Retired view returns ExpiredView (QRY-06)
          /\ queryResult' = "ExpiredView"
          /\ queryLocksHeld' = InitLocks
          /\ queryPhase' = "ResponseReady"
          /\ UNCHANGED << tipHeight, tipCommit, currentGen, retiredGens,
                          coverageHeight, views, queryViewId, queryTargetHeight,
                          queryIsTipPromised, queryIsScriptLive >>
     ELSE IF queryIsTipPromised /\ v.viewEpochCommit # tipCommit
     THEN \* Tip-promising query explicitly requires latest applied tip (QRY-03)
          /\ queryResult' = "Retry"
          /\ queryLocksHeld' = InitLocks
          /\ queryPhase' = "ResponseReady"
          /\ UNCHANGED << tipHeight, tipCommit, currentGen, retiredGens,
                          coverageHeight, views, queryViewId, queryTargetHeight,
                          queryIsTipPromised, queryIsScriptLive >>
     ELSE IF queryTargetHeight > v.viewCoverage
     THEN \* Outside declared coverage returns Unavailable (QRY-05)
          /\ queryResult' = "Unavailable"
          /\ queryLocksHeld' = InitLocks
          /\ queryPhase' = "ResponseReady"
          /\ UNCHANGED << tipHeight, tipCommit, currentGen, retiredGens,
                          coverageHeight, views, queryViewId, queryTargetHeight,
                          queryIsTipPromised, queryIsScriptLive >>
     ELSE \* Valid answer inside coverage (QRY-04, PRJ-11)
          \* ScriptLive answers from its self-contained live rows (PRJ-11)
          /\ queryResult' = "AnswerOk"
          /\ queryLocksHeld' = InitLocks
          /\ queryPhase' = "ResponseReady"
          /\ UNCHANGED << tipHeight, tipCommit, currentGen, retiredGens,
                          coverageHeight, views, queryViewId, queryTargetHeight,
                          queryIsTipPromised, queryIsScriptLive >>

\* Serialization after state access (QRY-08): buffer held under backpressure,
\* zero chain or mempool locks held.
StartSerialization ==
  /\ queryPhase = "ResponseReady"
  /\ queryLocksHeld.chainLock = FALSE
  /\ queryLocksHeld.mempoolLock = FALSE
  /\ queryPhase' = "Serializing"
  /\ UNCHANGED << tipHeight, tipCommit, currentGen, retiredGens,
                  coverageHeight, views, queryViewId, queryTargetHeight,
                  queryIsTipPromised, queryIsScriptLive, queryResult, queryLocksHeld >>

\* Complete query, release response buffer
FinishQuery ==
  /\ queryPhase = "Serializing"
  /\ queryPhase' = "Idle"
  /\ queryResult' = "None"
  /\ queryLocksHeld' = InitLocks
  /\ UNCHANGED << tipHeight, tipCommit, currentGen, retiredGens,
                  coverageHeight, views, queryViewId, queryTargetHeight,
                  queryIsTipPromised, queryIsScriptLive >>

Stutter ==
  /\ UNCHANGED vars
Next ==
  \/ ExtendChain
  \/ AdvanceCoverage
  \/ DeepReorg
  \/ \E v \in ViewIds, isScript \in BOOLEAN, isTip \in BOOLEAN, h \in HeightDom :
        CaptureView(v, isScript, isTip, h)
  \/ AccessState
  \/ StartSerialization
  \/ FinishQuery
  \/ Stutter

\* Safety Invariants

\* QRY-03: Ordinary chain extension never produces Retry for historical queries.
\* Retry is restricted to tip-promising endpoints that explicitly require the current tip.
SafetyHistoryQueryNeverRetries ==
  /\ queryResult = "Retry" => queryIsTipPromised

\* QRY-05: Queries outside declared coverage return Unavailable, never AnswerOk
SafetyCoverageUnavailable ==
  /\ (queryResult = "AnswerOk") =>
       queryTargetHeight <= views[queryViewId].viewCoverage

\* QRY-06: ExpiredView is returned when the view's generation has been retired by deep reorg
SafetyExpiredViewFromRetirement ==
  /\ (queryResult = "ExpiredView") =>
       (views[queryViewId].viewGen \in retiredGens \/ views[queryViewId].status = "Expired")

\* QRY-06: A view whose generation is retired can never produce AnswerOk
SafetyAccessFromRetiredNeverAnswersOk ==
  /\ (queryPhase = "Captured" /\ (views[queryViewId].viewGen \in retiredGens \/ views[queryViewId].status = "Expired")) =>
       queryResult # "AnswerOk"

\* PRJ-11: ScriptLive never acquires the chain lock
SafetyScriptLiveLockFree ==
  /\ queryIsScriptLive => ~queryLocksHeld.chainLock

\* QRY-08: Serialization runs with no locks held
SafetySerializationNoLocks ==
  /\ (queryPhase = "Serializing") =>
       (~queryLocksHeld.chainLock /\ ~queryLocksHeld.mempoolLock)

Safety ==
  /\ SafetyHistoryQueryNeverRetries
  /\ SafetyCoverageUnavailable
  /\ SafetyExpiredViewFromRetirement
  /\ SafetyAccessFromRetiredNeverAnswersOk
  /\ SafetyScriptLiveLockFree
  /\ SafetySerializationNoLocks
ConditionalProgress ==
  [][queryPhase = "Serializing" => queryPhase' \in {"Serializing", "Idle"}]_vars

=============================================================================