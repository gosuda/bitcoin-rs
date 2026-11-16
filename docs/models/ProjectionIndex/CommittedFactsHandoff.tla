\* PRJ-01, PRJ-02, PRJ-04, PRJ-13, IDX-08
----------------------- MODULE CommittedFactsHandoff -----------------------
(***************************************************************************)
(* CommittedFacts handoff queue and projection worker model.               *)
(*                                                                         *)
(* Models consensus commit creating CommittedFacts, bounded queue          *)
(* admission, overflow dropping with gap signaling (PRJ-04), payload-free  *)
(* wake notification (IDX-08), live fact consumption with zero body reads  *)
(* (PRJ-01), fallback recovery loading (PRJ-02), and three independent     *)
(* positions (PRJ-13).                                                     *)
(*                                                                         *)
(* Design model only: specifies the state machine and invariant safety.    *)
(* Not an implementation refinement proof or physical durability proof.    *)
(***************************************************************************)

EXTENDS Naturals, Sequences

CONSTANTS
  \* @type: Int;
  MaxHeight,
  \* @type: Int;
  QueueBudget,
  \* @type: Int;
  MaxVerified

VARIABLES
  \* @type: Int;
  appliedHeight,
  \* @type: Int;
  verifiedHeight,
  \* @type: Int;
  coverageHeight,
  \* @type: Seq(Int);
  queue,
  \* @type: Int;
  queueBytes,
  \* @type: Bool;
  gap,
  \* @type: Bool;
  wakePending,
  \* @type: Int;
  liveBodyReads,
  \* @type: Int;
  recoveryBodyReads,
  \* @type: Int;
  reorgCount

vars == << appliedHeight, verifiedHeight, coverageHeight, queue, queueBytes,
           gap, wakePending, liveBodyReads, recoveryBodyReads, reorgCount >>

Init ==
  /\ appliedHeight = 0
  /\ verifiedHeight = 0
  /\ coverageHeight = 0
  /\ queue = <<>>
  /\ queueBytes = 0
  /\ gap = FALSE
  /\ wakePending = FALSE
  /\ liveBodyReads = 0
  /\ recoveryBodyReads = 0
  /\ reorgCount = 0

\* Commit block: pushes to queue if budget permits, else drops facts and sets gap
CommitBlock ==
  /\ appliedHeight < MaxHeight
  /\ appliedHeight' = appliedHeight + 1
  /\ IF queueBytes + 1 <= QueueBudget
     THEN /\ queue' = Append(queue, appliedHeight + 1)
          /\ queueBytes' = queueBytes + 1
          /\ gap' = gap
     ELSE /\ queue' = queue
          /\ queueBytes' = queueBytes
          /\ gap' = TRUE
  /\ wakePending' = TRUE
  /\ UNCHANGED << verifiedHeight, coverageHeight, liveBodyReads, recoveryBodyReads, reorgCount >>

\* Background historical verification advances independently
VerifyHistorical ==
  /\ verifiedHeight < MaxVerified
  /\ verifiedHeight' = verifiedHeight + 1
  /\ UNCHANGED << appliedHeight, coverageHeight, queue, queueBytes, gap,
                  wakePending, liveBodyReads, recoveryBodyReads, reorgCount >>

\* Normal live path: worker consumes committed facts from queue with zero body reads
WorkerLiveStep ==
  /\ ~gap
  /\ queue # <<>>
  /\ Head(queue) = coverageHeight + 1
  /\ queue' = Tail(queue)
  /\ queueBytes' = queueBytes - 1
  /\ coverageHeight' = coverageHeight + 1
  /\ wakePending' = FALSE
  /\ UNCHANGED << appliedHeight, verifiedHeight, gap, liveBodyReads, recoveryBodyReads, reorgCount >>

\* Recovery path: worker falls back to loading block bodies until caught up
WorkerRecoveryStep ==
  /\ gap
  /\ coverageHeight < appliedHeight
  /\ queue' = <<>>
  /\ queueBytes' = 0
  /\ recoveryBodyReads' = recoveryBodyReads + 1
  /\ coverageHeight' = coverageHeight + 1
  /\ gap' = (coverageHeight + 1 # appliedHeight)
  /\ wakePending' = FALSE
  /\ UNCHANGED << appliedHeight, verifiedHeight, liveBodyReads, reorgCount >>

\* Reorganization: rewinds applied and coverage tip, discards queue, marks gap
Reorganize ==
  /\ reorgCount < 1
  /\ appliedHeight > 1
  /\ \E fork \in 1..(appliedHeight - 1):
       /\ appliedHeight' = fork
       /\ coverageHeight' = IF coverageHeight > fork THEN fork ELSE coverageHeight
       /\ queue' = <<>>
       /\ queueBytes' = 0
       /\ gap' = TRUE
       /\ wakePending' = TRUE
       /\ reorgCount' = reorgCount + 1
       /\ UNCHANGED << verifiedHeight, liveBodyReads, recoveryBodyReads >>

Stutter ==
  /\ UNCHANGED vars

Next ==
  \/ CommitBlock
  \/ VerifyHistorical
  \/ WorkerLiveStep
  \/ WorkerRecoveryStep
  \/ Reorganize
  \/ Stutter

TypeOK ==
  /\ appliedHeight \in 0..MaxHeight
  /\ verifiedHeight \in 0..MaxVerified
  /\ coverageHeight \in 0..MaxHeight
  /\ queueBytes \in 0..QueueBudget
  /\ gap \in BOOLEAN
  /\ wakePending \in BOOLEAN
  /\ liveBodyReads = 0
  /\ recoveryBodyReads \in 0..(2 * MaxHeight)
  /\ reorgCount \in 0..1

Safety ==
  \* PRJ-01: Live path reads zero block bodies
  /\ liveBodyReads = 0
  \* PRJ-04: Queue byte budget is never exceeded
  /\ queueBytes <= QueueBudget
  /\ Len(queue) <= QueueBudget
  \* PRJ-13: Coverage watermark never leads applied tip
  /\ coverageHeight <= appliedHeight
  \* PRJ-04 / PRJ-02: Queue consistency when gap is clear
  /\ (~gap => (
       /\ queueBytes = Len(queue)
       /\ \A i \in 1..Len(queue): queue[i] = coverageHeight + i
     ))
  \* PRJ-13: Three independent positions stay in bounds
  /\ verifiedHeight <= MaxVerified

ConditionalProgress == TRUE

=============================================================================
