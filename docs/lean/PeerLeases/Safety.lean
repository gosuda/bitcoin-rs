/-
Safety invariants of the peer-lease machine (Rust owner
`crates/p2p/src/lease_model.rs`): session-generation ordering, the single
current session, and the ticket allocation, issuance, release and free chain.
This file proves an abstract session-and-ticket machine. `docs/models/PeerLeases/*.tla`
own the liveness checks and the buffer, tag and custody detail. Field and action names
are frozen for the Rust model.
-/

namespace PeerLeases

structure State where
  nextSession : Nat
  phase0 : Nat
  phase1 : Nat
  current : Nat
  alloc0 : Nat
  ever0 : Nat
  rel0 : Nat
  freed0 : Nat
  alloc1 : Nat
  ever1 : Nat
  rel1 : Nat
  freed1 : Nat

def init : State :=
  { nextSession := 0, phase0 := 0, phase1 := 0, current := 0,
    alloc0 := 0, ever0 := 0, rel0 := 0, freed0 := 0,
    alloc1 := 0, ever1 := 0, rel1 := 0, freed1 := 0 }

inductive Action
  | startS0 | handshake0 | establish0 | close0
  | startS1 | handshake1 | establish1 | close1
  | reserve0 | issue0 | release0 | free0
  | reserve1 | issue1 | release1 | free1
  | stutter

/-- One machine step. A blocked action leaves the state unchanged. -/
def step (s : State) : Action → State
  | .startS0 => if s.nextSession = 0 ∧ s.phase0 = 0 then { s with nextSession := 1, phase0 := 1, current := 1 } else s
  | .handshake0 => if s.phase0 = 1 then { s with phase0 := 2 } else s
  | .establish0 => if s.phase0 = 2 then { s with phase0 := 3 } else s
  | .close0 => if s.phase0 = 3 then { s with phase0 := 4, current := 0 } else s
  | .startS1 => if s.nextSession = 1 ∧ s.phase0 = 4 ∧ s.phase1 = 0 then { s with nextSession := 2, phase1 := 1, current := 2 } else s
  | .handshake1 => if s.phase1 = 1 then { s with phase1 := 2 } else s
  | .establish1 => if s.phase1 = 2 then { s with phase1 := 3 } else s
  | .close1 => if s.phase1 = 3 then { s with phase1 := 4, current := 0 } else s
  | .reserve0 => if s.alloc0 = 0 then { s with alloc0 := 1 } else s
  | .issue0 => if s.alloc0 = 1 ∧ s.ever0 = 0 then { s with ever0 := 1 } else s
  | .release0 => if s.ever0 = 1 ∧ s.rel0 = 0 then { s with rel0 := 1 } else s
  | .free0 => if s.rel0 = 1 ∧ s.freed0 = 0 then { s with freed0 := 1 } else s
  | .reserve1 => if s.alloc1 = 0 then { s with alloc1 := 1 } else s
  | .issue1 => if s.alloc1 = 1 ∧ s.ever1 = 0 then { s with ever1 := 1 } else s
  | .release1 => if s.ever1 = 1 ∧ s.rel1 = 0 then { s with rel1 := 1 } else s
  | .free1 => if s.rel1 = 1 ∧ s.freed1 = 0 then { s with freed1 := 1 } else s
  | .stutter => s

def safety (s : State) : Prop :=
  s.nextSession ≤ 2
  ∧ s.phase0 ≤ 4
  ∧ s.phase1 ≤ 4
  ∧ s.current ≤ 2
  ∧ s.nextSession ≤ s.phase0 + 1
  ∧ s.phase1 ≤ 4 * s.nextSession
  ∧ s.alloc0 ≤ 1
  ∧ s.ever0 ≤ s.alloc0
  ∧ s.rel0 ≤ s.alloc0
  ∧ s.freed0 ≤ s.rel0
  ∧ s.alloc1 ≤ 1
  ∧ s.ever1 ≤ s.alloc1
  ∧ s.rel1 ≤ s.alloc1
  ∧ s.freed1 ≤ s.rel1

theorem safety_init : safety init := by
  unfold safety init
  decide

-- P2P-02
/-- `safety` is an inductive invariant of `step` from `init`. -/
theorem safety_inductive (s : State) (a : Action) (h : safety s) :
    safety (step s a) := by
  unfold safety at *
  cases a <;> dsimp only [step]
  · by_cases hc : s.nextSession = 0 ∧ s.phase0 = 0
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · by_cases hc : s.phase0 = 1
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · by_cases hc : s.phase0 = 2
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · by_cases hc : s.phase0 = 3
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · by_cases hc : s.nextSession = 1 ∧ s.phase0 = 4 ∧ s.phase1 = 0
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · by_cases hc : s.phase1 = 1
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · by_cases hc : s.phase1 = 2
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · by_cases hc : s.phase1 = 3
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · by_cases hc : s.alloc0 = 0
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · by_cases hc : s.alloc0 = 1 ∧ s.ever0 = 0
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · by_cases hc : s.ever0 = 1 ∧ s.rel0 = 0
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · by_cases hc : s.rel0 = 1 ∧ s.freed0 = 0
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · by_cases hc : s.alloc1 = 0
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · by_cases hc : s.alloc1 = 1 ∧ s.ever1 = 0
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · by_cases hc : s.ever1 = 1 ∧ s.rel1 = 0
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · by_cases hc : s.rel1 = 1 ∧ s.freed1 = 0
    · rw [ite_eq_left hc]
      try dsimp only []
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        first
          | omega
          | (left; omega)
          | (right; omega)
          | (rcases h with ⟨_, _, _, _, hd0, hd1, _, _, _, _, _, _, _, _⟩; omega)
    · rw [ite_eq_right hc]
      exact h
  · exact h

end PeerLeases
