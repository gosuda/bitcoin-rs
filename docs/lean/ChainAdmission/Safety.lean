/-
Safety invariants of the chain-admission machine (Rust owner
`crates/execution/src/admission_model.rs`). The state abstraction keeps the
fields the ordered-commit rules constrain: retry and job budgets, the commit
counter chain, the window delta extent, the writer/reader exclusion, and the observer cursor.
Field and action names are frozen for the Rust model.
-/

namespace ChainAdmission

structure State where
  attempts : Nat
  jobs : Nat
  proposed : Nat
  committed : Nat
  published : Nat
  writer : Nat
  reader : Nat
  subscribed : Nat
  cursor : Nat
  windowDelta : Nat

/-- Retry bound, job slots and publication counter bound. -/
def maxAttempts : Nat := 4
def jobSlots : Nat := 12
def counterBound : Nat := 1024

def init : State :=
  { attempts := 0, jobs := 0, proposed := 0, committed := 0, published := 0,
    writer := 0, reader := 0, subscribed := 0, cursor := 0, windowDelta := 0 }

inductive Action
  | startJob
  | finishJob
  | prepare
  | commitBatch
  | publishPrefix
  | failBatch
  | retry
  | subscribe
  | observe
  | acquireWriter
  | releaseWriter
  | acquireReader
  | releaseReader
  | stutter

/-- One machine step. A blocked action leaves the state unchanged. -/
def step (s : State) : Action → State
  | .startJob => if s.jobs < jobSlots then { s with jobs := s.jobs + 1 } else s
  | .finishJob => if 0 < s.jobs then { s with jobs := s.jobs - 1 } else s
  | .prepare =>
    if s.proposed < counterBound then
      { s with proposed := s.proposed + 1, windowDelta := s.proposed + 1 }
    else s
  | .commitBatch =>
    if s.committed < s.windowDelta then { s with committed := s.windowDelta } else s
  | .publishPrefix =>
    if s.published < s.committed then { s with published := s.committed } else s
  | .failBatch => if s.attempts < maxAttempts then { s with attempts := s.attempts + 1 } else s
  | .retry => { s with windowDelta := s.committed }
  | .subscribe => { s with subscribed := 1, cursor := 0 }
  | .observe =>
    if s.subscribed = 1 ∧ s.cursor < s.published then { s with cursor := s.cursor + 1 } else s
  | .acquireWriter => if 0 < s.reader then s else { s with writer := 1 }
  | .releaseWriter => { s with writer := 0 }
  | .acquireReader => if 0 < s.writer then s else { s with reader := 1 }
  | .releaseReader => { s with reader := 0 }
  | .stutter => s

/-- Ordered-commit safety: bounded work, monotone publication chain, window-delta validity,
exclusive durable writer, and an observer that never leads publication. -/
def safety (s : State) : Prop :=
  s.attempts ≤ maxAttempts
  ∧ s.jobs ≤ jobSlots
  ∧ s.published ≤ s.committed
  ∧ s.committed ≤ s.windowDelta
  ∧ s.windowDelta ≤ s.proposed
  ∧ s.proposed ≤ counterBound
  ∧ s.writer + s.reader ≤ 1
  ∧ s.cursor ≤ s.published
  ∧ (s.subscribed = 1 ∨ s.cursor = 0)

theorem safety_init : safety init := by
  unfold safety init maxAttempts jobSlots counterBound
  decide

-- RCV-02, SYNC-05, WIN-03, WIN-06, CMT-02, CMT-03
/-- `safety` is an inductive invariant of `step` from `init`. -/
theorem safety_inductive (s : State) (a : Action) (h : safety s) :
    safety (step s a) := by
  unfold safety at *
  cases a <;> simp only [step] <;> (try split)
  all_goals
    simp only [maxAttempts, jobSlots, counterBound] at *
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  all_goals
    first
      | omega
      | trivial
      | (left; trivial)
      | (right; trivial)
      | (rcases h with ⟨_, _, _, _, _, _, _, _, hlast⟩
         rcases hlast with hsub | hcur <;> omega)

end ChainAdmission
