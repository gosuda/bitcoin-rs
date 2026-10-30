/-
Safety invariants of the projection and mining machine (Rust owners
`crates/index/src/projection_model.rs` and
`crates/mining/src/projection_model.rs`): the projection never leads the
applied chain, committed rows never exceed the watermark, the template
generation never leads the tip, and pending shares stay bounded.
This file proves an abstract projection-and-mining machine. `docs/models/ProjectionMining/*.tla`
own the liveness checks and the per-capability detail. Field and action names are frozen
for the Rust model.
-/

namespace ProjectionMining

structure State where
  appliedHeight : Nat
  watermark : Nat
  rowsCommitted : Nat
  phase : Nat
  activeGen : Nat
  tipGen : Nat
  pendingShares : Nat

/-- Share cap per template. -/
def shareCap : Nat := 2

def init : State :=
  { appliedHeight := 12, watermark := 0, rowsCommitted := 0, phase := 0,
    activeGen := 0, tipGen := 4, pendingShares := 0 }

inductive Action
  | wake | prepare | commitBatch | caughtUp
  | advance | acceptShare | drainShare | stutter

def step (s : State) : Action → State
  | .wake => if s.phase = 0 ∧ s.watermark < s.appliedHeight then { s with phase := 1 } else s
  | .prepare => if s.phase = 1 then { s with phase := 2 } else s
  | .commitBatch =>
    if s.phase = 2 ∧ s.watermark < s.appliedHeight then
      { s with watermark := s.watermark + 1, rowsCommitted := s.rowsCommitted + 1,
               phase := 0 } else s
  | .caughtUp => if s.watermark = s.appliedHeight then { s with phase := 0 } else s
  | .advance =>
    if s.activeGen < s.tipGen then
      { s with activeGen := s.activeGen + 1, pendingShares := 0 } else s
  | .acceptShare =>
    if s.activeGen = s.tipGen ∧ s.pendingShares < shareCap then
      { s with pendingShares := s.pendingShares + 1 } else s
  | .drainShare =>
    if 0 < s.pendingShares then { s with pendingShares := s.pendingShares - 1 } else s
  | .stutter => s

def safety (s : State) : Prop :=
  s.watermark ≤ s.appliedHeight
  ∧ s.rowsCommitted ≤ s.watermark
  ∧ s.phase ≤ 2
  ∧ s.activeGen ≤ s.tipGen
  ∧ s.pendingShares ≤ shareCap

theorem safety_init : safety init := by
  unfold safety init shareCap
  decide

-- IDX-06, POOL-05
/-- `safety` is an inductive invariant of `step` from `init`. -/
theorem safety_inductive (s : State) (a : Action) (h : safety s) :
    safety (step s a) := by
  unfold safety at *
  cases a <;> simp only [step] <;> (try split)
  all_goals
    simp only [shareCap] at *
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
  all_goals omega

end ProjectionMining
