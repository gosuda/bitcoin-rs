\* RCV-02, SYNC-05, WIN-01, WIN-03, WIN-04, WIN-05, WIN-06, WIN-07, WIN-08, CMT-01, CMT-02, CMT-03, CMT-04, CMT-05, REO-02, REO-03
---------------------------- MODULE Commit ----------------------------
(***************************************************************************)
(* Commit sub-machine of the coordinated chain-transition model.           *)
(*                                                                         *)
(* Owned state: the publication epoch and generation, the four durable     *)
(* semantic roots (prior, proposed, disk, live), the body and undo frame   *)
(* cursors, their sync flags, the retry budget and the attempt counter.    *)
(* Updated for Phase 3.6 window commit, engine coin store, cache install,  *)
(* failure-at-j prefix commit, and ambiguous failure admission closure.    *)
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

CoinRoles == {"c1", "c2", "c_int", "c_bip"}

nextCoin(c) == IF c = "c1" THEN "c2" ELSE "c1"

DeltaRecord == [
  len: 0..FrameBound,
  created: SUBSET CoinRoles,
  spent: SUBSET CoinRoles,
  spentInternal: SUBSET CoinRoles,
  bip30Overwrites: SUBSET CoinRoles
]

DeltaInit == [
  len |-> 0,
  created |-> {},
  spent |-> {},
  spentInternal |-> {},
  bip30Overwrites |-> {}
]

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
  proved,
  \* @type: [len: Int, created: Set(Str), spent: Set(Str), spentInternal: Set(Str), bip30Overwrites: Set(Str)];
  windowDelta,
  \* @type: Bool;
  cacheInstalled,
  \* @type: Bool;
  admissionClosed,
  \* @type: Int;
  blockIdx,
  \* @type: Int;
  validPrefixLen,
  \* @type: Int;
  failedBlock,
  \* @type: Set(Str);
  coinStore,
  \* @type: Set(Str);
  coinCache

vars == << epoch, generation, priorRoot, proposedRoot, diskRoot, liveRoot,
          bodyPos, undoPos, syncBody, syncUndo, fileSync, dirSync, attempts,
          phase, proved, windowDelta, cacheInstalled, admissionClosed,
          blockIdx, validPrefixLen, failedBlock, coinStore, coinCache >>

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
  /\ windowDelta = DeltaInit
  /\ cacheInstalled = FALSE
  /\ admissionClosed = FALSE
  /\ blockIdx = 0
  /\ validPrefixLen = 0
  /\ failedBlock = 0
  /\ coinStore = {"c1", "c_bip"}
  /\ coinCache = {"c1", "c_bip"}

(* Environment: the admission job has finished preparing and proving. *)
Env ==
  /\ phase = 1
  /\ ~proved
  /\ proved' = TRUE
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, fileSync,
                  dirSync, attempts, phase, windowDelta, cacheInstalled,
                  admissionClosed, blockIdx, validPrefixLen, failedBlock,
                  coinStore, coinCache >>

(* Step 1 of window lifecycle: reserve capacity, admit job if admission open *)
StartJob ==
  /\ phase = 0
  /\ ~admissionClosed
  /\ attempts < MaxAttempts
  /\ proposedRoot < CounterBound
  /\ epoch < CounterBound
  /\ generation + 2 <= CounterBound
  /\ phase' = 1
  /\ proposedRoot' = proposedRoot + 1
  /\ windowDelta' = DeltaInit
  /\ cacheInstalled' = FALSE
  /\ blockIdx' = 0
  /\ validPrefixLen' = 0
  /\ failedBlock' = 0
  /\ UNCHANGED << epoch, generation, priorRoot, diskRoot, liveRoot, bodyPos,
                  undoPos, syncBody, syncUndo, fileSync, dirSync, attempts,
                  proved, admissionClosed, coinStore, coinCache >>

EvalBlock1 ==
  /\ phase = 1
  /\ blockIdx = 0
  /\ blockIdx' = 1
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, fileSync,
                  dirSync, attempts, phase, proved, windowDelta,
                  cacheInstalled, admissionClosed, validPrefixLen,
                  failedBlock, coinStore, coinCache >>

EvalBlock2 ==
  /\ phase = 1
  /\ blockIdx = 1
  /\ blockIdx' = 2
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, fileSync,
                  dirSync, attempts, phase, proved, windowDelta,
                  cacheInstalled, admissionClosed, validPrefixLen,
                  failedBlock, coinStore, coinCache >>

(* WIN-08: block j=1 fails -> entire window fails *)
FailBlock1 ==
  /\ phase = 1
  /\ blockIdx = 0
  /\ attempts < MaxAttempts
  /\ phase' = 4
  /\ attempts' = attempts + 1
  /\ failedBlock' = 1
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, fileSync,
                  dirSync, proved, windowDelta, cacheInstalled,
                  admissionClosed, blockIdx, validPrefixLen, coinStore,
                  coinCache >>

(* WIN-08: block j=2 fails -> commit valid prefix 0..j-1 = 0..0 (block 1) *)
FailBlock2 ==
  /\ phase = 1
  /\ blockIdx = 1
  /\ proved
  /\ phase' = 2
  /\ validPrefixLen' = 1
  /\ failedBlock' = 2
  /\ \E c \in (coinStore \ {"c_bip"}):
       windowDelta' = [
         len |-> 1,
         created |-> {nextCoin(c)},
         spent |-> {c},
         spentInternal |-> {},
         bip30Overwrites |-> {}
       ]
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, fileSync,
                  dirSync, attempts, proved, cacheInstalled, admissionClosed,
                  blockIdx, coinStore, coinCache >>

(* Complete full window: block 1 created c_int, block 2 spent c_int and created nextCoin(c) *)
(* c_int is created and spent in prefix -> spentInternal; c_bip is bip30 overwrite *)
CompleteWindow ==
  /\ phase = 1
  /\ blockIdx = 2
  /\ proved
  /\ phase' = 2
  /\ validPrefixLen' = FrameBound
  /\ failedBlock' = 0
  /\ \E c \in (coinStore \ {"c_bip"}):
       windowDelta' = [
         len |-> FrameBound,
         created |-> {nextCoin(c), "c_bip"},
         spent |-> {c},
         spentInternal |-> {"c_int"},
         bip30Overwrites |-> {"c_bip"}
       ]
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, fileSync,
                  dirSync, attempts, proved, cacheInstalled, admissionClosed,
                  blockIdx, coinStore, coinCache >>

(* CMT-02 Step 2: append block body bytes for valid prefix *)
MarkBody ==
  /\ phase = 2
  /\ ~fileSync
  /\ bodyPos = 0
  /\ bodyPos' = validPrefixLen
  /\ syncBody' = TRUE
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, undoPos, syncUndo, fileSync, dirSync, attempts,
                  phase, proved, windowDelta, cacheInstalled, admissionClosed,
                  blockIdx, validPrefixLen, failedBlock, coinStore, coinCache >>

(* CMT-02 Step 2: append undo bytes for valid prefix *)
MarkUndo ==
  /\ phase = 2
  /\ ~fileSync
  /\ undoPos = 0
  /\ undoPos' = validPrefixLen
  /\ syncUndo' = TRUE
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, syncBody, fileSync, dirSync, attempts,
                  phase, proved, windowDelta, cacheInstalled, admissionClosed,
                  blockIdx, validPrefixLen, failedBlock, coinStore, coinCache >>

(* CMT-02 Step 3: sync appended block and recovery files *)
SyncFile ==
  /\ phase = 2
  /\ syncBody /\ syncUndo /\ ~fileSync
  /\ fileSync' = TRUE
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, dirSync,
                  attempts, phase, proved, windowDelta, cacheInstalled,
                  admissionClosed, blockIdx, validPrefixLen, failedBlock,
                  coinStore, coinCache >>

(* CMT-02 Step 3: sync parent directory entries *)
SyncDirectory ==
  /\ phase = 2
  /\ fileSync /\ ~dirSync
  /\ dirSync' = TRUE
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, fileSync,
                  attempts, phase, proved, windowDelta, cacheInstalled,
                  admissionClosed, blockIdx, validPrefixLen, failedBlock,
                  coinStore, coinCache >>

(* CMT-01, CMT-02 Step 4: atomic engine batch (head, undo, body, coins) *)
(* Canonical coin mutation occurs ONLY here under commit authority *)
Commit ==
  /\ phase = 2
  /\ fileSync /\ dirSync
  /\ diskRoot' = proposedRoot
  /\ phase' = 3
  /\ cacheInstalled' = FALSE
  /\ coinStore' = (coinStore \ windowDelta.spent) \cup windowDelta.created
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, liveRoot,
                  bodyPos, undoPos, syncBody, syncUndo, fileSync, dirSync,
                  attempts, proved, windowDelta, admissionClosed, blockIdx,
                  validPrefixLen, failedBlock, coinCache >>

(* CMT-02 Step 5: install resident state (cache) after successful commit *)
InstallCache ==
  /\ phase = 3
  /\ ~cacheInstalled
  /\ cacheInstalled' = TRUE
  /\ coinCache' = coinStore
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, fileSync,
                  dirSync, attempts, phase, proved, windowDelta,
                  admissionClosed, blockIdx, validPrefixLen, failedBlock,
                  coinStore >>

(* CMT-02 Step 6: publish applied epoch, monotonically increasing epoch & gen *)
(* CMT-01: PublishPrefix leaves canonical coinStore and coinCache UNCHANGED *)
PublishPrefix ==
  /\ phase = 3
  /\ cacheInstalled
  /\ epoch < CounterBound
  /\ generation + 2 <= CounterBound
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
  /\ windowDelta' = DeltaInit
  /\ cacheInstalled' = FALSE
  /\ blockIdx' = 0
  /\ validPrefixLen' = 0
  /\ failedBlock' = 0
  /\ UNCHANGED << proposedRoot, diskRoot, attempts, admissionClosed,
                  coinStore, coinCache >>

(* CMT-04: ambiguous failure closes admission permanently; no retry *)
FailAmbiguous ==
  /\ phase = 2
  /\ fileSync /\ dirSync
  /\ phase' = 4
  /\ attempts' = attempts + 1
  /\ admissionClosed' = TRUE
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, bodyPos, undoPos, syncBody, syncUndo, fileSync,
                  dirSync, proved, windowDelta, cacheInstalled, blockIdx,
                  validPrefixLen, failedBlock, coinStore, coinCache >>

Retry ==
  /\ phase = 4
  /\ ~admissionClosed
  /\ attempts < MaxAttempts
  /\ phase' = 0
  /\ bodyPos' = 0
  /\ undoPos' = 0
  /\ syncBody' = FALSE
  /\ syncUndo' = FALSE
  /\ fileSync' = FALSE
  /\ dirSync' = FALSE
  /\ proved' = FALSE
  /\ windowDelta' = DeltaInit
  /\ cacheInstalled' = FALSE
  /\ blockIdx' = 0
  /\ validPrefixLen' = 0
  /\ failedBlock' = 0
  /\ UNCHANGED << epoch, generation, priorRoot, proposedRoot, diskRoot,
                  liveRoot, attempts, admissionClosed, coinStore, coinCache >>

Stutter ==
  /\ UNCHANGED vars

Next ==
  \/ Env
  \/ StartJob
  \/ EvalBlock1
  \/ EvalBlock2
  \/ FailBlock1
  \/ FailBlock2
  \/ CompleteWindow
  \/ MarkBody
  \/ MarkUndo
  \/ SyncFile
  \/ SyncDirectory
  \/ Commit
  \/ InstallCache
  \/ PublishPrefix
  \/ FailAmbiguous
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
  /\ windowDelta \in DeltaRecord
  /\ cacheInstalled \in BOOLEAN
  /\ admissionClosed \in BOOLEAN
  /\ blockIdx \in 0..2
  /\ validPrefixLen \in 0..FrameBound
  /\ failedBlock \in 0..FrameBound
  /\ coinStore \subseteq CoinRoles
  /\ coinCache \subseteq CoinRoles

Safety ==
  /\ (phase = 3 => diskRoot = proposedRoot)
  /\ (phase # 3 => liveRoot = diskRoot)
  /\ (phase = 3 => fileSync /\ dirSync /\ bodyPos > 0 /\ undoPos > 0)
  /\ (fileSync => syncBody /\ syncUndo)
  /\ (dirSync => fileSync)
  /\ (syncBody <=> bodyPos > 0)
  /\ (syncUndo <=> undoPos > 0)
  /\ (bodyPos > 0 => bodyPos = validPrefixLen)
  /\ (undoPos > 0 => undoPos = validPrefixLen)
  /\ (phase = 3 => windowDelta.len = validPrefixLen)
  /\ (cacheInstalled => (phase = 3 /\ diskRoot = proposedRoot /\ coinCache = coinStore))
  /\ (admissionClosed => phase = 4)
  /\ generation = 2 * epoch
  \* CMT-01: canonical coinStore and cache updated only after commit
  /\ (phase = 0 => coinCache = coinStore)
  \* WIN-04: create-and-spend inside prefix never enters coin store
  /\ windowDelta.spentInternal \cap coinStore = {}
  \* WIN-05: delta created and spent are disjoint (one final replacement)
  /\ windowDelta.created \cap windowDelta.spent = {}
  \* WIN-07: BIP30 overwrite is explicit
  /\ (windowDelta.bip30Overwrites # {} => windowDelta.bip30Overwrites \subseteq windowDelta.created)
  \* WIN-08: failure at block j commits prefix 0..j-1 only
  /\ (failedBlock > 0 /\ phase = 2 => validPrefixLen = failedBlock - 1)

EnCommit == phase = 2 /\ fileSync /\ dirSync
EnInstall == phase = 3 /\ ~cacheInstalled
EnPublish == phase = 3 /\ cacheInstalled

FairCommit == ((<>[] EnCommit) => ([]<> <<Commit>>_vars))
FairInstall == ((<>[] EnInstall) => ([]<> <<InstallCache>>_vars))
FairPublish == ((<>[] EnPublish) => ([]<> <<PublishPrefix>>_vars))

ConditionalProgress ==
  (FairCommit /\ FairInstall /\ FairPublish)
  =>
  ([] ((phase = 3) => <> (phase = 0 /\ liveRoot = diskRoot)))

=============================================================================
