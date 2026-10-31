\* SYNC-05
---------------------------- MODULE Frontier ----------------------------
(***************************************************************************)
(* Admission-frontier sub-machine of the coordinated chain-transition     *)
(* model.                                                                  *)
(*                                                                         *)
(* Owned state: the admission request slots, the chain-job slots, the      *)
(* external-event budget, the input latch and the terminal flag. Committed *)
(* root state is an environment input owned by the commit sub-machine:     *)
(* `committed` reports that a published generation exists. The commit      *)
(* sub-machine is Commit.tla.                                              *)
(***************************************************************************)

EXTENDS Naturals

CONSTANTS
  \* @type: Int;
  JobSlots,
  \* @type: Int;
  ReqSlots,
  \* @type: Int;
  EventBudget

VARIABLES
  \* @type: Int;
  requests,
  \* @type: Int;
  jobsUsed,
  \* @type: Int;
  eventsLeft,
  \* @type: Bool;
  inputClosed,
  \* @type: Bool;
  done,
  \* @type: Bool;
  committed

vars == << requests, jobsUsed, eventsLeft, inputClosed, done, committed >>

Init ==
  /\ requests = 0
  /\ jobsUsed = 0
  /\ eventsLeft = EventBudget
  /\ inputClosed = FALSE
  /\ done = FALSE
  /\ committed = FALSE

(* Environment: the commit sub-machine publishes a generation. *)
Env ==
  /\ ~committed
  /\ committed' = TRUE
  /\ UNCHANGED << requests, jobsUsed, eventsLeft, inputClosed, done >>

Admit ==
  /\ ~inputClosed
  /\ eventsLeft > 0
  /\ requests < ReqSlots
  /\ jobsUsed < JobSlots
  /\ requests' = requests + 1
  /\ jobsUsed' = jobsUsed + 1
  /\ eventsLeft' = eventsLeft - 1
  /\ UNCHANGED << inputClosed, done, committed >>

Serve ==
  /\ requests > 0
  /\ requests' = requests - 1
  /\ UNCHANGED << jobsUsed, eventsLeft, inputClosed, done, committed >>

Complete ==
  /\ jobsUsed > 0
  /\ jobsUsed' = jobsUsed - 1
  /\ UNCHANGED << requests, eventsLeft, inputClosed, done, committed >>

CloseInput ==
  /\ ~inputClosed
  /\ inputClosed' = TRUE
  /\ UNCHANGED << requests, jobsUsed, eventsLeft, done, committed >>

Finish ==
  /\ ~done
  /\ inputClosed
  /\ requests = 0
  /\ jobsUsed = 0
  /\ done' = TRUE
  /\ UNCHANGED << requests, jobsUsed, eventsLeft, inputClosed, committed >>

Stutter ==
  /\ UNCHANGED vars

Next ==
  \/ Env
  \/ Admit
  \/ Serve
  \/ Complete
  \/ CloseInput
  \/ Finish
  \/ Stutter

TypeOK ==
  /\ requests \in 0..ReqSlots
  /\ jobsUsed \in 0..JobSlots
  /\ eventsLeft \in 0..EventBudget
  /\ inputClosed \in BOOLEAN
  /\ done \in BOOLEAN
  /\ committed \in BOOLEAN

EnServe == requests > 0
EnComplete == jobsUsed > 0
EnFinish == ~done /\ inputClosed /\ requests = 0 /\ jobsUsed = 0

FairServe == ((<>[] EnServe) => ([]<> <<Serve>>_vars))
FairComplete == ((<>[] EnComplete) => ([]<> <<Complete>>_vars))
FairFinish == ((<>[] EnFinish) => ([]<> <<Finish>>_vars))

ConditionalProgress ==
  ((<> inputClosed) /\ FairServe /\ FairComplete /\ FairFinish)
  =>
  (<> done)

=============================================================================
