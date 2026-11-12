\* EMB-01
------------------------------ MODULE Open ------------------------------
(***************************************************************************)
(* Index store open helper ownership and lifecycle model.                  *)
(*                                                                         *)
(* Models derived-index worker and helper thread phases, joined            *)
(* cancellation, store acquisition, error/panic diagnostics, startup       *)
(* timeouts, host teardown deadlines, and checkpoint gating under EMB-01.  *)
(*                                                                         *)
(* Design model only: specifies the state machine and invariant safety.    *)
(* Not an implementation refinement proof or physical durability proof.    *)
(***************************************************************************)

EXTENDS Naturals

\* Worker phases
WorkerIdle      == 0
WorkerOpening   == 1
WorkerReady     == 2
WorkerServing   == 3
WorkerStopping  == 4
WorkerStopped   == 5
WorkerAbandoned == 6

WorkerPhaseDom == 0..6

\* Helper phases
HelperAbsent  == 0
HelperRunning == 1
HelperExited  == 2
HelperJoined  == 3

HelperPhaseDom == 0..3

\* Result kinds
ResultNone     == 0
ResultOpened   == 1
ResultFailed   == 2
ResultPanicked == 3

ResultKindDom == 0..3

\* Host outcomes
HostPending == 0
HostClean   == 1
HostFailed  == 2

HostOutcomeDom == 0..2

VARIABLES
  \* @type: Int;
  workerPhase,
  \* @type: Int;
  helperPhase,
  \* @type: Bool;
  shutdownRequested,
  \* @type: Bool;
  storeHeld,
  \* @type: Int;
  resultKind,
  \* @type: Bool;
  poisoned,
  \* @type: Int;
  hostOutcome,
  \* @type: Bool;
  checkpointPublished

vars == << workerPhase, helperPhase, shutdownRequested, storeHeld,
           resultKind, poisoned, hostOutcome, checkpointPublished >>

TypeOK ==
  /\ workerPhase \in WorkerPhaseDom
  /\ helperPhase \in HelperPhaseDom
  /\ shutdownRequested \in BOOLEAN
  /\ storeHeld \in BOOLEAN
  /\ resultKind \in ResultKindDom
  /\ poisoned \in BOOLEAN
  /\ hostOutcome \in HostOutcomeDom
  /\ checkpointPublished \in BOOLEAN

Init ==
  /\ workerPhase = WorkerIdle
  /\ helperPhase = HelperAbsent
  /\ shutdownRequested = FALSE
  /\ storeHeld = FALSE
  /\ resultKind = ResultNone
  /\ poisoned = FALSE
  /\ hostOutcome = HostPending
  /\ checkpointPublished = FALSE

\* Early or late shutdown request
RequestShutdown ==
  /\ ~shutdownRequested
  /\ shutdownRequested' = TRUE
  /\ UNCHANGED << workerPhase, helperPhase, storeHeld, resultKind,
                  poisoned, hostOutcome, checkpointPublished >>

\* Pre-spawn cancellation: stop before spawning helper; no open performed
PreSpawnStop ==
  /\ workerPhase = WorkerIdle
  /\ shutdownRequested = TRUE
  /\ helperPhase = HelperAbsent
  /\ workerPhase' = WorkerStopped
  /\ UNCHANGED << helperPhase, shutdownRequested, storeHeld, resultKind,
                  poisoned, hostOutcome, checkpointPublished >>

\* Spawn helper thread only before cancellation
SpawnHelper ==
  /\ workerPhase = WorkerIdle
  /\ ~shutdownRequested
  /\ helperPhase = HelperAbsent
  /\ hostOutcome = HostPending
  /\ workerPhase' = WorkerOpening
  /\ helperPhase' = HelperRunning
  /\ UNCHANGED << shutdownRequested, storeHeld, resultKind,
                  poisoned, hostOutcome, checkpointPublished >>

\* Helper acquires native RocksDB store handle
NativeStoreAcquire ==
  /\ helperPhase = HelperRunning
  /\ ~storeHeld
  /\ resultKind = ResultNone
  /\ storeHeld' = TRUE
  /\ UNCHANGED << workerPhase, helperPhase, shutdownRequested,
                  resultKind, poisoned, hostOutcome, checkpointPublished >>

\* Helper posts opened success result across channel while thread is still running
HelperPostSuccess ==
  /\ helperPhase = HelperRunning
  /\ storeHeld = TRUE
  /\ resultKind = ResultNone
  /\ resultKind' = ResultOpened
  /\ UNCHANGED << workerPhase, helperPhase, shutdownRequested, storeHeld,
                  poisoned, hostOutcome, checkpointPublished >>

\* Helper posts failed error diagnostic across channel while thread is still running
HelperPostFailed ==
  /\ helperPhase = HelperRunning
  /\ resultKind = ResultNone
  /\ resultKind' = ResultFailed
  /\ storeHeld' = FALSE
  /\ UNCHANGED << workerPhase, helperPhase, shutdownRequested,
                  poisoned, hostOutcome, checkpointPublished >>

\* Helper posts panic diagnostic across channel while thread is still running
HelperPostPanicked ==
  /\ helperPhase = HelperRunning
  /\ resultKind = ResultNone
  /\ resultKind' = ResultPanicked
  /\ storeHeld' = FALSE
  /\ UNCHANGED << workerPhase, helperPhase, shutdownRequested,
                  poisoned, hostOutcome, checkpointPublished >>

\* Helper thread exits: owned worker requires posted result; abandoned helper self-cleans store
HelperExit ==
  /\ helperPhase = HelperRunning
  /\ \/ (workerPhase # WorkerAbandoned /\ resultKind # ResultNone)
     \/ (workerPhase = WorkerAbandoned)
  /\ helperPhase' = HelperExited
  /\ storeHeld' = IF workerPhase = WorkerAbandoned THEN FALSE ELSE storeHeld
  /\ UNCHANGED << workerPhase, shutdownRequested, resultKind,
                  poisoned, hostOutcome, checkpointPublished >>

\* Worker receives opened result from channel before thread join
WorkerReceiveOpened ==
  /\ workerPhase = WorkerOpening
  /\ resultKind = ResultOpened
  /\ ~shutdownRequested
  /\ workerPhase' = WorkerReady
  /\ UNCHANGED << helperPhase, shutdownRequested, storeHeld,
                  resultKind, poisoned, hostOutcome, checkpointPublished >>

\* Normal opened result may serve queries only after helper joined
WorkerStartServing ==
  /\ workerPhase = WorkerReady
  /\ helperPhase = HelperJoined
  /\ ~shutdownRequested
  /\ workerPhase' = WorkerServing
  /\ UNCHANGED << helperPhase, shutdownRequested, storeHeld,
                  resultKind, poisoned, hostOutcome, checkpointPublished >>

\* Worker handles failed or panicked open diagnostic: stopping for teardown, no poison
WorkerHandleFailed ==
  /\ workerPhase = WorkerOpening
  /\ resultKind \in {ResultFailed, ResultPanicked}
  /\ ~shutdownRequested
  /\ workerPhase' = WorkerStopping
  /\ UNCHANGED << helperPhase, shutdownRequested, storeHeld,
                  resultKind, poisoned, hostOutcome, checkpointPublished >>

\* Cancellation during opening: worker enters stopping to join helper
WorkerCancelDuringOpening ==
  /\ workerPhase = WorkerOpening
  /\ shutdownRequested = TRUE
  /\ workerPhase' = WorkerStopping
  /\ UNCHANGED << helperPhase, shutdownRequested, storeHeld,
                  resultKind, poisoned, hostOutcome, checkpointPublished >>

\* Cancellation from ready or serving states
WorkerCancelFromReadyOrServing ==
  /\ workerPhase \in {WorkerReady, WorkerServing}
  /\ shutdownRequested = TRUE
  /\ workerPhase' = WorkerStopping
  /\ UNCHANGED << helperPhase, shutdownRequested, storeHeld,
                  resultKind, poisoned, hostOutcome, checkpointPublished >>

\* Helper join: distinct from merely receiving result across channel; forbidden for abandoned worker
WorkerJoinHelper ==
  /\ workerPhase # WorkerAbandoned
  /\ helperPhase = HelperExited
  /\ helperPhase' = HelperJoined
  /\ UNCHANGED << workerPhase, shutdownRequested, storeHeld,
                  resultKind, poisoned, hostOutcome, checkpointPublished >>

\* Worker clean stop: requires helper absent (pre-spawn) or joined, drops store
WorkerCleanStop ==
  /\ workerPhase = WorkerStopping
  /\ helperPhase \in {HelperAbsent, HelperJoined}
  /\ workerPhase' = WorkerStopped
  /\ storeHeld' = FALSE
  /\ UNCHANGED << helperPhase, shutdownRequested, resultKind,
                  poisoned, hostOutcome, checkpointPublished >>

\* Genuine startup timeout: only when not canceled; abandons and poisons
WorkerStartupTimeout ==
  /\ workerPhase = WorkerOpening
  /\ ~shutdownRequested
  /\ helperPhase = HelperRunning
  /\ resultKind = ResultNone
  /\ workerPhase' = WorkerAbandoned
  /\ poisoned' = TRUE
  /\ UNCHANGED << helperPhase, shutdownRequested, storeHeld,
                  resultKind, hostOutcome, checkpointPublished >>

\* Outer host teardown deadline expires while worker still opening or joining
HostDeadlineExpire ==
  /\ hostOutcome = HostPending
  /\ shutdownRequested
  /\ workerPhase \notin {WorkerStopped, WorkerAbandoned}
  /\ hostOutcome' = HostFailed
  /\ poisoned' = TRUE
  /\ UNCHANGED << workerPhase, helperPhase, shutdownRequested,
                  storeHeld, resultKind, checkpointPublished >>

\* Host reports abandonment or poisoned stopped worker as failed teardown
HostReportsAbandonment ==
  /\ hostOutcome = HostPending
  /\ (workerPhase = WorkerAbandoned \/ (workerPhase = WorkerStopped /\ poisoned))
  /\ hostOutcome' = HostFailed
  /\ poisoned' = TRUE
  /\ UNCHANGED << workerPhase, helperPhase, shutdownRequested,
                  storeHeld, resultKind, checkpointPublished >>

\* Host clean completion: observes stopped worker and unpoisoned state without inspecting helper handles
HostCleanCompletion ==
  /\ hostOutcome = HostPending
  /\ workerPhase = WorkerStopped
  /\ ~poisoned
  /\ hostOutcome' = HostClean
  /\ UNCHANGED << workerPhase, helperPhase, shutdownRequested,
                  storeHeld, resultKind, poisoned, checkpointPublished >>

\* Checkpoint publication: permitted only after clean host teardown
PublishCheckpoint ==
  /\ hostOutcome = HostClean
  /\ ~checkpointPublished
  /\ ~poisoned
  /\ checkpointPublished' = TRUE
  /\ UNCHANGED << workerPhase, helperPhase, shutdownRequested,
                  storeHeld, resultKind, poisoned, hostOutcome >>

Stutter ==
  UNCHANGED vars

Next ==
  \/ RequestShutdown
  \/ PreSpawnStop
  \/ SpawnHelper
  \/ NativeStoreAcquire
  \/ HelperPostSuccess
  \/ HelperPostFailed
  \/ HelperPostPanicked
  \/ HelperExit
  \/ WorkerReceiveOpened
  \/ WorkerStartServing
  \/ WorkerHandleFailed
  \/ WorkerCancelDuringOpening
  \/ WorkerCancelFromReadyOrServing
  \/ WorkerJoinHelper
  \/ WorkerCleanStop
  \/ WorkerStartupTimeout
  \/ HostDeadlineExpire
  \/ HostReportsAbandonment
  \/ HostCleanCompletion
  \/ PublishCheckpoint
  \/ Stutter

Safety ==
  \* EMB-01: stopped worker requires no store held and closed helper (absent or joined)
  /\ (workerPhase = WorkerStopped => (helperPhase \in {HelperAbsent, HelperJoined} /\ ~storeHeld))
  \* EMB-01: clean host requires stopped worker
  /\ (hostOutcome = HostClean => workerPhase = WorkerStopped)
  \* EMB-01: serving worker requires joined helper
  /\ (workerPhase = WorkerServing => helperPhase = HelperJoined)
  \* EMB-01: checkpoint requires clean host, unpoisoned, no store held, helper absent or joined
  /\ (checkpointPublished => (hostOutcome = HostClean /\ ~poisoned /\ ~storeHeld /\ helperPhase \in {HelperAbsent, HelperJoined}))
  \* EMB-01: pre-spawn canceled stop never initiated store I/O
  /\ ((workerPhase = WorkerStopped /\ helperPhase = HelperAbsent) => (~storeHeld /\ resultKind = ResultNone))
  \* EMB-01: poisoned, abandoned worker, or failed host can never produce clean outcome or checkpoint
  /\ ((poisoned \/ workerPhase = WorkerAbandoned \/ hostOutcome = HostFailed) => (hostOutcome # HostClean /\ ~checkpointPublished))
  \* EMB-01: abandoned worker is poisoned
  /\ (workerPhase = WorkerAbandoned => poisoned)
  \* EMB-01: failed host is poisoned
  /\ (hostOutcome = HostFailed => poisoned)
  \* EMB-01: store is never held by an absent helper
  /\ (storeHeld => helperPhase \in {HelperRunning, HelperExited, HelperJoined})
  \* EMB-01: absent helper implies no result posted and no store held
  /\ (helperPhase = HelperAbsent => (~storeHeld /\ resultKind = ResultNone))

ConditionalProgress ==
  []((poisoned \/ workerPhase = WorkerAbandoned \/ hostOutcome = HostFailed) =>
     [](poisoned /\ hostOutcome # HostClean /\ ~checkpointPublished))

=============================================================================
