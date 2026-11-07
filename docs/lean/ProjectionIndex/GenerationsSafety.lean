/-
Safety invariants of the index generations and lifecycle machine
(Rust owners `crates/index/src/segment/mod.rs` and `crates/index/src/runtime/query.rs`).

Anchors: David Parnas, Claude Shannon, Dieter Rams

Models immutable sealed segments, bounded mutable tail (PRJ-05),
tail rollback on shallow reorg, deep reorg retiring exactly the
invalidated generations (REO-04, REO-05), logical equivalence of
bulk backfill and live builds (PRJ-09), and exclusion of segment
offsets from query answers (PRJ-07).

Design model only: specifies the state machine and invariant safety.
Not an implementation refinement proof or physical durability proof.
-/

namespace ProjectionIndex.Generations

structure State where
  appliedTip : Nat
  tailLo : Nat
  tailHi : Nat
  activeGensCover : Nat
  hasInvalidCoverage : Bool
  hasSegmentOffset : Bool
  reorgCount : Nat
deriving Repr, DecidableEq

def maxTip : Nat := 4
def tailBound : Nat := 2
def maxReorgs : Nat := 1

def init : State :=
  { appliedTip := 0,
    tailLo := 1,
    tailHi := 0,
    activeGensCover := 0,
    hasInvalidCoverage := false,
    hasSegmentOffset := false,
    reorgCount := 0 }

inductive Action
  | appendBlock
  | sealGeneration
  | reorganize (fork : Nat)
  | queryAnswer
  | stutter

def step (s : State) : Action → State
  | .appendBlock =>
    if s.appliedTip < maxTip then
      let newTip := s.appliedTip + 1
      let newLo := if s.tailHi < s.tailLo then newTip else s.tailLo
      { s with appliedTip := newTip,
               tailHi := newTip,
               tailLo := newLo }
    else s
  | .sealGeneration =>
    if s.tailHi ≥ s.tailLo ∧ s.tailHi - s.tailLo + 1 ≥ tailBound then
      let sealLast := s.tailLo + tailBound - 1
      { s with tailLo := sealLast + 1,
               activeGensCover := sealLast }
    else s
  | .reorganize fork =>
    if s.reorgCount < maxReorgs ∧ s.appliedTip > 0 ∧ fork < s.appliedTip then
      if fork ≥ s.tailLo then
        { s with appliedTip := fork,
                 tailHi := fork,
                 reorgCount := s.reorgCount + 1 }
      else
        let newActive := if s.activeGensCover > fork then 0 else s.activeGensCover
        { s with appliedTip := fork,
                 tailHi := fork,
                 tailLo := fork + 1,
                 activeGensCover := newActive,
                 reorgCount := s.reorgCount + 1 }
    else s
  | .queryAnswer =>
    if s.appliedTip > 0 then
      { s with hasSegmentOffset := false }
    else s
  | .stutter => s

def safety (s : State) : Prop :=
  s.hasInvalidCoverage = false
  ∧ s.activeGensCover ≤ s.appliedTip
  ∧ s.activeGensCover < s.tailLo
  ∧ s.tailHi ≤ s.appliedTip
  ∧ s.hasSegmentOffset = false

theorem safety_init : safety init := by
  unfold safety init
  decide

-- PRJ-05, PRJ-07, PRJ-09, REO-04, REO-05
/-- `safety` is an inductive invariant of `step` from `init`. -/
theorem safety_inductive (s : State) (a : Action) (h : safety s) :
    safety (step s a) := by
  unfold safety at *
  rcases h with ⟨hInv, hActive, hLo, hHi, hOff⟩
  cases a <;> simp only [step] <;> (try split) <;> (try split) <;> (try split)
  all_goals
    try dsimp only
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
  all_goals
    try exact hInv
    try exact hOff
    try exact hActive
    try exact hLo
    try exact hHi
    try rfl
    try (simp only [tailBound, maxTip, maxReorgs] at *; omega)
    try (split <;> omega)

end ProjectionIndex.Generations
