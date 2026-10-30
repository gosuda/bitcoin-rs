---------------------------- MODULE Session ----------------------------
(***************************************************************************)
(* Session sub-machine of the peer lease model.                            *)
(*                                                                         *)
(* Owned state: the two session incarnations, the current-session cursor,  *)
(* the external-input latch, the terminal flag, and the event budget.      *)
(* Close settlement of every lease tagged to a closing session is a        *)
(* guarantee of the lease sub-machine (Lease.tla), so this machine needs   *)
(* no lease state and no environment input.                                *)
(***************************************************************************)

EXTENDS Naturals

CONSTANTS
  \* @type: Str;
  S0,
  \* @type: Str;
  S1,
  \* @type: Int;
  ExternalBudget

Sess == {S0, S1}

(* 0 = Absent, 1 = Handshaking, 2 = Established, 3 = Closing, 4 = Closed. *)
PhaseDom == 0..4

VARIABLES
  \* @type: Str -> Int;
  phase,
  \* @type: Str;
  current,
  \* @type: Int;
  nextSession,
  \* @type: Bool;
  inputOpen,
  \* @type: Bool;
  done,
  \* @type: Int;
  eventsLeft

vars == << phase, current, nextSession, inputOpen, done, eventsLeft >>

SessionIndex(s) == IF s = S0 THEN 0 ELSE 1
Partner(s) == IF s = S0 THEN S1 ELSE S0

Init ==
  /\ phase = [s \in Sess |-> 0]
  /\ current = "None"
  /\ nextSession = 0
  /\ inputOpen = TRUE
  /\ done = FALSE
  /\ eventsLeft = ExternalBudget

Start(s) ==
  /\ ~done
  /\ inputOpen /\ eventsLeft > 0
  /\ current = "None"
  /\ nextSession = SessionIndex(s)
  /\ phase[s] = 0
  /\ (s = S1) => phase[S0] = 4
  /\ phase' = [phase EXCEPT ![s] = 1]
  /\ current' = s
  /\ nextSession' = nextSession + 1
  /\ eventsLeft' = eventsLeft - 1
  /\ UNCHANGED << inputOpen, done >>

HandshakeDone(s) ==
  /\ ~done
  /\ phase[s] = 1
  /\ current = s
  /\ phase' = [phase EXCEPT ![s] = 2]
  /\ UNCHANGED << current, nextSession, inputOpen, done, eventsLeft >>

BeginClose(s) ==
  /\ ~done
  /\ phase[s] = 2
  /\ current = s
  /\ phase' = [phase EXCEPT ![s] = 3]
  /\ UNCHANGED << current, nextSession, inputOpen, done, eventsLeft >>

FinishClose(s) ==
  /\ ~done
  /\ phase[s] = 3
  /\ current = s
  /\ phase' = [phase EXCEPT ![s] = 4]
  /\ current' = "None"
  /\ UNCHANGED << nextSession, inputOpen, done, eventsLeft >>

Seal ==
  /\ ~done
  /\ inputOpen
  /\ inputOpen' = FALSE
  /\ UNCHANGED << phase, current, nextSession, done, eventsLeft >>

Done ==
  /\ ~done
  /\ ~inputOpen
  /\ current = "None"
  /\ done' = TRUE
  /\ UNCHANGED << phase, current, nextSession, inputOpen, eventsLeft >>

Stutter ==
  /\ UNCHANGED vars

Next ==
  \/ \E s \in Sess : Start(s)
  \/ \E s \in Sess : HandshakeDone(s)
  \/ \E s \in Sess : BeginClose(s)
  \/ \E s \in Sess : FinishClose(s)
  \/ Seal
  \/ Done
  \/ Stutter

TypeOK ==
  /\ phase \in [Sess -> PhaseDom]
  /\ current \in {"None"} \cup Sess
  /\ nextSession \in 0..2
  /\ inputOpen \in BOOLEAN
  /\ done \in BOOLEAN
  /\ eventsLeft \in 0..ExternalBudget

\* @type: (Str) => Bool;
EnClose(s) == ~done /\ phase[s] \in {1, 2}
\* @type: (Str) => Bool;
EnFinishClose(s) == ~done /\ phase[s] = 3
EnDone == ~done /\ ~inputOpen /\ current = "None"

FairCloseS0 == ((<>[] EnClose(S0)) => ([]<> <<BeginClose(S0)>>_vars))
FairCloseS1 == ((<>[] EnClose(S1)) => ([]<> <<BeginClose(S1)>>_vars))
FairFinishS0 == ((<>[] EnFinishClose(S0)) => ([]<> <<FinishClose(S0)>>_vars))
FairFinishS1 == ((<>[] EnFinishClose(S1)) => ([]<> <<FinishClose(S1)>>_vars))
FairDone == ((<>[] EnDone) => ([]<> <<Done>>_vars))

ConditionalProgress ==
  ((<> ~inputOpen) /\ FairCloseS0 /\ FairCloseS1 /\ FairFinishS0 /\ FairFinishS1
   /\ FairDone)
  =>
  (<> done)

=============================================================================
