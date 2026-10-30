set_option exponentiation.threshold 4096

/-
Reduction modulo `2^3072 - 1103717` for the MuHash field used by
`crates/utxo/src/stats/muhash3072.rs`. The reduction lemmas hold for every positive modulus; the
last three instantiate the field modulus.
-/

namespace Utxo.Muhash

/-- `2^3072`, kept as a named atom so arithmetic reasoning never expands it. -/
def twoPow3072 : Nat := 2 ^ 3072

/-- The MuHash3072 field modulus. -/
def modulus : Nat := twoPow3072 - 1103717

theorem modulus_pos : 0 < modulus := by
  have hpow : (2 : Nat) ^ 21 ≤ twoPow3072 := by
    unfold twoPow3072
    exact Nat.pow_le_pow_right (by decide) (by decide)
  have hsmall : (1103717 : Nat) < 2 ^ 21 := by decide
  unfold modulus
  omega

/-- One conditional subtraction, as the limb fold performs. -/
def reduceStep (m : Nat) (x : Nat) : Nat :=
  if m ≤ x then x - m else x

/-- Perform `k` conditional subtractions. -/
def fold (m : Nat) : Nat → Nat → Nat
  | 0, x => x
  | k + 1, x => reduceStep m (fold m k x)

theorem fold_succ_apply (m k x : Nat) :
    fold m (k + 1) x = fold m k (reduceStep m x) := by
  induction k generalizing x with
  | zero => rfl
  | succ k ih =>
    show reduceStep m (fold m (k + 1) x) = reduceStep m (fold m k (reduceStep m x))
    rw [ih]

theorem reduceStep_apply {m x : Nat} (hle : m ≤ x) : reduceStep m x = x - m := by
  unfold reduceStep
  simp [hle]

theorem reduceStep_id {m x : Nat} (hlt : x < m) : reduceStep m x = x := by
  unfold reduceStep
  simp [Nat.not_le.mpr hlt]

/-- One conditional subtraction preserves the residue class, with no bound on `x`. -/
theorem reduceStep_mod {m x : Nat} (_hm : 0 < m) :
    reduceStep m x % m = x % m := by
  unfold reduceStep
  split
  · rename_i hle
    have hx : x = m + (x - m) := (Nat.add_sub_cancel' hle).symm
    have hxm : x % m = (x - m) % m := by
      rw [hx, Nat.add_mod, Nat.mod_self, Nat.zero_add, Nat.mod_mod,
        Nat.add_sub_cancel_left]
    exact hxm.symm
  · rfl

/-- One conditional subtraction of a positive modulus keeps the value below the modulus. -/
theorem reduceStep_lt {m x : Nat} (_hm : 0 < m) (h : x < 2 * m) : reduceStep m x < m := by
  by_cases hle : m ≤ x
  · rw [reduceStep_apply hle]
    have h2 : 2 * m = m + m := Nat.two_mul m
    rw [h2] at h
    rw [Nat.sub_lt_iff_lt_add hle]
    exact h
  · rw [reduceStep_id (Nat.lt_of_not_le hle)]
    exact Nat.lt_of_not_le hle

/-- Folding `k` conditional subtractions reduces every `x < (k + 1) * m` to `x mod m`. -/
theorem fold_reduces (m : Nat) (hm : 0 < m) (k x : Nat) (h : x < (k + 1) * m) :
    fold m k x = x % m := by
  induction k generalizing x with
  | zero =>
    show x = x % m
    exact (Nat.mod_eq_of_lt (by omega)).symm
  | succ k ih =>
    have hexpand : (k + 1 + 1) * m = (k + 1) * m + m := by
      rw [Nat.succ_mul]
    have hstep : reduceStep m x < (k + 1) * m := by
      by_cases hle : m ≤ x
      · rw [reduceStep_apply hle]
        omega
      · rw [reduceStep_id (Nat.lt_of_not_le hle)]
        have hle' : m ≤ (k + 1) * m := by
          have := Nat.mul_le_mul_right m (by omega : (1 : Nat) ≤ k + 1)
          simpa using this
        omega
    rw [fold_succ_apply, ih (reduceStep m x) hstep, reduceStep_mod hm]

/-- A 3072-bit field element above the modulus reduces with one conditional subtraction. -/
theorem field_reduce (x : Nat) (h : modulus ≤ x) :
    reduceStep modulus x = x - modulus :=
  reduceStep_apply h

theorem field_reduce_lt (x : Nat) (h : x < 2 * modulus) :
    reduceStep modulus x < modulus :=
  reduceStep_lt modulus_pos h

-- ARCH-07b
theorem field_fold_reduces (x k : Nat) (h : x < (k + 1) * modulus) :
    fold modulus k x = x % modulus :=
  fold_reduces modulus modulus_pos k x h

end Utxo.Muhash
