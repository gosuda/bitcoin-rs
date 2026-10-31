\* RCV-02, SYNC-05
---------------------------- MODULE Commit ----------------------------
(***************************************************************************)
(* Commit sub-machine of the coordinated chain-transition model.           *)
(*                                                                         *)
(* Owned state: the publication epoch and generation, the four durable     *)
(* semantic roots (prior, proposed, disk, live), the body and undo frame   *)
(* cursors, their sync flags, the retry budget and the attempt counter.    *)
(* Admission-job state (request slots, plans, outcomes, request queues) is  *)
(* an environment input: `proved` reports that the environment finished    *)
(* preparing and proving the proposed transition. The admission sub-       *)
(* machine is Frontier.tla.                                                *)
(***************************************************************************)

EXTENDS Naturals

CONSTANTS
  \* @type: Int;
  MaxAttempts,
  \* @type: Int;
  CounterBound,
  \* @type: Int;
  FrameBound

(* 0 = Idle, 1 = Preparing, 2 = Proved, 3 = Committed, 4 = Failed. *)
PhaseDom == 0..4

VARIABLES
  \* @type: Int;
  epoch,
  \* @type: Int;
  generation,
  \* @type: Int;
  priorRoot,
  \* @type: Int;
  proposedRoot,
  \* @type: Int;
  diskRoot,
  \* @type: Int;
  liveRoot,
  \* @type: Int;
  bodyPos,
  \* @type: Int;
  undoPos,
  \* @type: Bool;
  syncBody,
  \* @type: Bool;
  syncUndo,
  \* @type: Bool;
  fileSync,
  \* @type: Bool;
  dirSync,
  \* @type: Int;
  attempts,
  \* @type: Int;
  phase,
  \* @type: Bool;
  proved

vars == << epoch, generation, priorRoot, proposedRoot, diskRoot, liveRoot,
          bodyPos, undoPos, syncBody, syncUndo, fileSync, dirSync, attempts,
          phase, proved >>

Init ==
  /\ epoch = 0
  /\ generation = 0
  /\ priorRoot = 0
  /\ proposedRoot = 0
  /\ diskRoot = 0
  /\ liveRoot = 0
  /\ bodyPos = 0
  /\ undoPos = 0
  /\ syncBody = FALSE
  /\ syncUndo = FALSE
  /\ fileSync = FALSE
  /\ dirSync = FALSE
  /\ attempts = 0
  /\ phase = 0
  /\ proved = FALSE

(* Environment: the admission job has finished preparing and proving. *)
Env ==
  /\ ~proved
  /\ proved' = TRUE
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, fileSync,
                  dirSync, attempts, phase >>

StartJob ==
  /\ phase = 0
  /\ attempts < MaxAttempts
  /\ proposedRoot < CounterBound
  /\ phase' = 1
  /\ proposedRoot' = proposedRoot + 1
  /\ UNCHANGED << epoch, generation, priorRoot, diskRoot, liveRoot, bodyPos,
                  undoPos, syncBody, syncUndo, fileSync, dirSync, attempts,
                  proved >>

Prove ==
  /\ phase = 1
  /\ proved
  /\ phase' = 2
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, fileSync,
                  dirSync, attempts, proved >>

MarkBody ==
  /\ phase = 2
  /\ bodyPos < FrameBound
  /\ bodyPos' = bodyPos + 1
  /\ syncBody' = TRUE
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, undoPos, syncUndo, fileSync, dirSync, attempts,
                  phase, proved >>

MarkUndo ==
  /\ phase = 2
  /\ undoPos < FrameBound
  /\ undoPos' = undoPos + 1
  /\ syncUndo' = TRUE
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, syncBody, fileSync, dirSync, attempts,
                  phase, proved >>

SyncFile ==
  /\ phase = 2
  /\ syncBody /\ syncUndo /\ ~fileSync
  /\ fileSync' = TRUE
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, dirSync,
                  attempts, phase, proved >>

SyncDirectory ==
  /\ phase = 2
  /\ fileSync /\ ~dirSync
  /\ dirSync' = TRUE
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, fileSync,
                  attempts, phase, proved >>

Commit ==
  /\ phase = 2
  /\ fileSync /\ dirSync
  /\ diskRoot' = proposedRoot
  /\ phase' = 3
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, liveRoot,
                  bodyPos, undoPos, syncBody, syncUndo, fileSync, dirSync,
                  attempts, proved >>

Publish ==
  /\ phase = 3
  /\ liveRoot' = diskRoot
  /\ epoch' = epoch + 1
  /\ generation' = generation + 2
  /\ priorRoot' = liveRoot
  /\ phase' = 0
  /\ bodyPos' = 0
  /\ undoPos' = 0
  /\ syncBody' = FALSE
  /\ syncUndo' = FALSE
  /\ fileSync' = FALSE
  /\ dirSync' = FALSE
  /\ proved' = FALSE
  /\ UNCHANGED << proposedRoot, diskRoot, attempts >>

Fail ==
  /\ phase = 2
  /\ phase' = 4
  /\ attempts' = attempts + 1
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, fileSync,
                  dirSync, proved >>

Retry ==
  /\ phase = 4
  /\ attempts < MaxAttempts
  /\ phase' = 0
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, fileSync,
                  dirSync, attempts, proved >>

Stutter ==
  /\ UNCHANGED vars

Next ==
  \/ Env
  \/ StartJob
  \/ Prove
  \/ MarkBody
  \/ MarkUndo
  \/ SyncFile
  \/ SyncDirectory
  \/ Commit
  \/ Publish
  \/ Fail
  \/ Retry
  \/ Stutter

TypeOK ==
  /\ epoch \in 0..CounterBound
  /\ generation \in 0..CounterBound
  /\ priorRoot \in 0..CounterBound
  /\ proposedRoot \in 0..CounterBound
  /\ diskRoot \in 0..CounterBound
  /\ liveRoot \in 0..CounterBound
  /\ bodyPos \in 0..FrameBound
  /\ undoPos \in 0..FrameBound
  /\ syncBody \in BOOLEAN
  /\ syncUndo \in BOOLEAN
  /\ fileSync \in BOOLEAN
  /\ dirSync \in BOOLEAN
  /\ attempts \in 0..MaxAttempts
  /\ phase \in PhaseDom
  /\ proved \in BOOLEAN

EnCommit == phase = 2 /\ fileSync /\ dirSync
EnPublish == phase = 3

FairCommit == ((<>[] EnCommit) => ([]<> <<Commit>>_vars))
FairPublish == ((<>[] EnPublish) => ([]<> <<Publish>>_vars))

ConditionalProgress ==
  (FairCommit /\ FairPublish)
  =>
  ([] ((phase = 3) => <> (phase = 0 /\ liveRoot = diskRoot)))

=============================================================================
