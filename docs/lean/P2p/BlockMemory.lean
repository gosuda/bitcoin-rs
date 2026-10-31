/-
Block decoding admission accounting for `crates/p2p/src/inbound/block_memory.rs`.
-/

namespace P2p.BlockMemory

/-- Ingress budget floor: 512 MiB. -/
def blockIngressBytes : Nat := 512 * 1024 * 1024

/-- State of the block admission accountant: current live usage. -/
@[ext]
structure State where
  used : Nat
deriving DecidableEq, Repr

/-- State of an outstanding credit. -/
structure Credit where
  bytes : Nat
deriving DecidableEq, Repr

/-- Reserve `reserved` bytes against the budget. -/
def reserve (s : State) (reserved : Nat) : Option (State × Credit) :=
  if reserved ≤ blockIngressBytes ∧ s.used + reserved ≤ blockIngressBytes then
    some ({ used := s.used + reserved }, { bytes := reserved })
  else
    none

/-- Settle down to the retained size after decoding. -/
def retain (s : State) (c : Credit) (retained : Nat) : State × Credit :=
  if retained ≤ c.bytes then
    ({ used := s.used - (c.bytes - retained) }, { bytes := retained })
  else
    (s, c)

/-- Release on drop. -/
def release (s : State) (c : Credit) : State :=
  { used := s.used - c.bytes }

-- P2P-07, SYNC-03
/-- `retain` never increases the used byte total. -/
theorem retain_never_raises_used (s : State) (c : Credit) (retained : Nat)
    (_h : c.bytes ≤ s.used) :
    (retain s c retained).1.used ≤ s.used := by
  unfold retain
  split
  · dsimp only
    omega
  · dsimp only
    omega

/-- Dropping the credit returns `used` to the pre-reservation total. -/
theorem reserve_retain_release_identity (s : State) (reserved retained : Nat)
    (hres : reserved ≤ blockIngressBytes) (hfit : s.used + reserved ≤ blockIngressBytes) :
    let pair := (reserve s reserved).get (by simp [reserve, hres, hfit])
    let pair2 := retain pair.1 pair.2 retained
    release pair2.1 pair2.2 = s := by
  dsimp only [reserve, retain, release]
  simp only [hres, hfit, and_self, ite_true, Option.get_some]
  split
  · ext
    dsimp only
    omega
  · ext
    dsimp only
    omega

end P2p.BlockMemory
