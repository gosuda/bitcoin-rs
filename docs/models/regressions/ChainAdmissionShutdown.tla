---- MODULE ChainAdmissionShutdown ----
(* Additional regression, not a replacement for the full model check. *)
(* Follow four real shutdown actions, then require canonical Next to    *)
(* allow the terminal state to persist. Removing its stutter branch     *)
(* makes this check deadlock at step five. Constants remain unchanged.  *)
EXTENDS ChainAdmission

VARIABLE
  \* @type: Int;
  pc

ProbeInit == Init /\ pc' = 0

Prefix ==
  \/ /\ pc = 0 /\ CloseInput /\ pc' = 1
  \/ /\ pc = 1 /\ ChainFinish /\ pc' = 2
  \/ /\ pc = 2 /\ Settle /\ pc' = 3
  \/ /\ pc = 3 /\ EnterDone /\ pc' = 4

ProbeNext ==
  \/ /\ Prefix /\ stepOK' = StepSafe
  \/ /\ pc = 4 /\ Next /\ UNCHANGED pc

ReachedDone == pc = 4 => lifePhase = 3 /\ chainPhase = 11 /\ inputClosed
====
