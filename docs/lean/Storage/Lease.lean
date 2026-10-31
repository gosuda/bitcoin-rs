namespace Storage.Lease

structure RegistryInner where
  pruned_below : Nat
  reservations : List Nat
deriving DecidableEq, Repr

def maxReservation (reservations : List Nat) : Nat :=
  reservations.foldl max 0

def refusal_line (pruned_below : Nat) (reservations : List Nat) : Nat :=
  max pruned_below (maxReservation reservations)

def RegistryInner.refusalLine (inner : RegistryInner) : Nat :=
  refusal_line inner.pruned_below inner.reservations

theorem foldl_max_le (l : List Nat) (init floor : Nat) (hinit : init ≤ floor)
    (hl : ∀ r ∈ l, r ≤ floor) :
    l.foldl max init ≤ floor := by
  induction l generalizing init with
  | nil =>
    exact hinit
  | cons x xs ih =>
    dsimp [List.foldl]
    apply ih
    · have hx : x ≤ floor := hl x (by simp)
      omega
    · intro r hr
      exact hl r (by simp [hr])

-- SYNC-07
theorem refusal_line_never_passes_floor (floor pruned_below : Nat) (reservations : List Nat)
    (hp : pruned_below ≤ floor) (hr : ∀ r ∈ reservations, r ≤ floor) :
    refusal_line pruned_below reservations ≤ floor := by
  unfold refusal_line maxReservation
  have hmax : reservations.foldl max 0 ≤ floor := by
    apply foldl_max_le
    · omega
    · exact hr
  omega

end Storage.Lease
