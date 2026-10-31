---------------------------- MODULE Lease ----------------------------
(***************************************************************************)
(* Ticket-lease sub-machine of the peer lease model.                       *)
(*                                                                         *)
(* Owned state: the four request/fallback tickets with their allocation,   *)
(* issuance, release, outcome and custody bits. Session state (which       *)
(* session a ticket is tagged to, when a session closes) is an             *)
(* environment input: `closing` states whether the environment has begun   *)
(* closing the session that owns the ticket. The session machine is        *)
(* Session.tla.                                                            *)
(***************************************************************************)

EXTENDS Naturals

CONSTANTS
  \* @type: Str;
  R0,
  \* @type: Str;
  R1,
  \* @type: Str;
  F0,
  \* @type: Str;
  F1

Q == {R0, R1, F0, F1}

(* 0 = Unused, 1 = Reserved, 2 = Issued, 3 = Terminal. *)
PhaseDom == 0..3
(* 0 = Pending, 1 = Active, 2 = Satisfied, 3 = Settled. *)
CustodyDom == 0..3

VARIABLES
  \* @type: Str -> Int;
  phase,
  \* @type: Str -> Int;
  allocated,
  \* @type: Str -> Int;
  everIssued,
  \* @type: Str -> Int;
  releases,
  \* @type: Str -> Int;
  custody,
  \* @type: Bool;
  closing

vars == << phase, allocated, everIssued, releases, custody, closing >>

Init ==
  /\ phase = [q \in Q |-> 0]
  /\ allocated = [q \in Q |-> 0]
  /\ everIssued = [q \in Q |-> 0]
  /\ releases = [q \in Q |-> 0]
  /\ custody = [q \in Q |-> 0]
  /\ closing = FALSE

(* Environment input: the owning session may begin closing at any time. *)
Env ==
  /\ closing' = TRUE
  /\ UNCHANGED << phase, allocated, everIssued, releases, custody >>

Reserve(q) ==
  /\ allocated[q] = 0
  /\ phase' = [phase EXCEPT ![q] = 1]
  /\ allocated' = [allocated EXCEPT ![q] = 1]
  /\ custody' = [custody EXCEPT ![q] = 1]
  /\ UNCHANGED << everIssued, releases, closing >>

Issue(q) ==
  /\ phase[q] = 1
  /\ phase' = [phase EXCEPT ![q] = 2]
  /\ everIssued' = [everIssued EXCEPT ![q] = 1]
  /\ UNCHANGED << allocated, releases, custody, closing >>

Terminalize(q) ==
  /\ phase[q] = 2
  /\ phase' = [phase EXCEPT ![q] = 3]
  /\ releases' = [releases EXCEPT ![q] = 1]
  /\ custody' = [custody EXCEPT ![q] = 2]
  /\ UNCHANGED << allocated, everIssued, closing >>

Settle(q) ==
  /\ phase[q] = 3
  /\ closing
  /\ custody[q] = 2
  /\ custody' = [custody EXCEPT ![q] = 3]
  /\ UNCHANGED << phase, allocated, everIssued, releases, closing >>

Stutter ==
  /\ UNCHANGED vars

Next ==
  \/ Env
  \/ \E q \in Q : Reserve(q)
  \/ \E q \in Q : Issue(q)
  \/ \E q \in Q : Terminalize(q)
  \/ \E q \in Q : Settle(q)
  \/ Stutter

TypeOK ==
  /\ phase \in [Q -> PhaseDom]
  /\ allocated \in [Q -> 0..1]
  /\ everIssued \in [Q -> 0..1]
  /\ releases \in [Q -> 0..1]
  /\ custody \in [Q -> CustodyDom]
  /\ closing \in BOOLEAN

\* @type: (Str) => Bool;
EnIssue(q) == phase[q] = 1
\* @type: (Str) => Bool;
EnTerminalize(q) == phase[q] = 2

FairIssueR0 == ((<>[] EnIssue(R0)) => ([]<> <<Issue(R0)>>_vars))
FairIssueR1 == ((<>[] EnIssue(R1)) => ([]<> <<Issue(R1)>>_vars))
FairIssueF0 == ((<>[] EnIssue(F0)) => ([]<> <<Issue(F0)>>_vars))
FairIssueF1 == ((<>[] EnIssue(F1)) => ([]<> <<Issue(F1)>>_vars))

FairTerminalizeR0 == ((<>[] EnTerminalize(R0)) => ([]<> <<Terminalize(R0)>>_vars))
FairTerminalizeR1 == ((<>[] EnTerminalize(R1)) => ([]<> <<Terminalize(R1)>>_vars))
FairTerminalizeF0 == ((<>[] EnTerminalize(F0)) => ([]<> <<Terminalize(F0)>>_vars))
FairTerminalizeF1 == ((<>[] EnTerminalize(F1)) => ([]<> <<Terminalize(F1)>>_vars))

\* @type: (Str) => Bool;
Settled(q) == phase[q] = 3 /\ releases[q] = 1

\* @type: (Str) => Bool;
Issued(q) == everIssued[q] = 1

ConditionalProgress ==
  (/\ FairIssueR0 /\ FairIssueR1 /\ FairIssueF0 /\ FairIssueF1
   /\ FairTerminalizeR0 /\ FairTerminalizeR1 /\ FairTerminalizeF0
   /\ FairTerminalizeF1)
  =>
  (/\ [] (Issued(R0) => <> Settled(R0))
   /\ [] (Issued(R1) => <> Settled(R1))
   /\ [] (Issued(F0) => <> Settled(F0))
   /\ [] (Issued(F1) => <> Settled(F1)))

=============================================================================
