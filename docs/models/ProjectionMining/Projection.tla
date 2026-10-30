---------------------------- MODULE Projection ----------------------------
(***************************************************************************)
(* Projection sub-machine of the projection and mining model.              *)
(*                                                                         *)
(* Owned state: the forward watermark, committed row count and batch phase. *)
(* The applied chain height is an environment input: `AppliedHeight` is     *)
(* the fixed height the environment asks this sub-machine to reach. The     *)
(* mining-only actions belong to Mining.tla.                               *)
(***************************************************************************)

EXTENDS Naturals

CONSTANTS
  \* @type: Int;
  AppliedHeight,
  \* @type: Int;
  CounterBound

(* 0 = Idle, 1 = Preparing, 2 = Committing. *)
PhaseDom == 0..2

VARIABLES
  \* @type: Int;
  watermark,
  \* @type: Int;
  rowsCommitted,
  \* @type: Int;
  phase

\* @type: <<Int, Int, Int>>;
vars == << watermark, rowsCommitted, phase >>

Init ==
  /\ watermark = 0
  /\ rowsCommitted = 0
  /\ phase = 0

Wake ==
  /\ phase = 0
  /\ watermark < AppliedHeight
  /\ phase' = 1
  /\ UNCHANGED << watermark, rowsCommitted >>

Prepare ==
  /\ phase = 1
  /\ watermark < AppliedHeight
  /\ phase' = 2
  /\ UNCHANGED << watermark, rowsCommitted >>

CommitBatch ==
  /\ phase = 2
  /\ watermark < AppliedHeight
  /\ watermark' = watermark + 1
  /\ rowsCommitted' = rowsCommitted + 1
  /\ phase' = IF watermark + 1 = AppliedHeight THEN 0 ELSE 1

CaughtUp ==
  /\ phase = 0
  /\ watermark = AppliedHeight
  /\ UNCHANGED << watermark, rowsCommitted, phase >>

Stutter ==
  /\ UNCHANGED vars

Next ==
  \/ Wake
  \/ Prepare
  \/ CommitBatch
  \/ CaughtUp
  \/ Stutter

TypeOK ==
  /\ watermark \in 0..AppliedHeight
  /\ rowsCommitted \in 0..CounterBound
  /\ phase \in PhaseDom

EnWake == phase = 0 /\ watermark < AppliedHeight
EnPrepare == phase = 1 /\ watermark < AppliedHeight
EnCommit == phase = 2 /\ watermark < AppliedHeight

FairWake == ((<>[] EnWake) => ([]<> <<Wake>>_vars))
FairPrepare == ((<>[] EnPrepare) => ([]<> <<Prepare>>_vars))
FairCommit == ((<>[] EnCommit) => ([]<> <<CommitBatch>>_vars))

ConditionalProgress ==
  (FairWake /\ FairPrepare /\ FairCommit)
  =>
  (<> (watermark = AppliedHeight))

=============================================================================
