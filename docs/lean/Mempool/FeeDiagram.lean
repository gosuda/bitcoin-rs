/-
Fee-rate ordering for the mempool fee diagram
(`crates/mempool/src/fee_diagram.rs`). `rate_cmp` compares two fee/weight pairs
by cross multiplication; the theorems below show that relation is a total
preorder, which is what the diagram solver relies on.
-/

namespace Mempool.FeeDiagram

/-- A fee and a strictly positive weight. The Rust owner keeps the weight in
`0..i32::MAX`, so positivity is the only fact the ordering needs. -/
structure FeeWeight where
  fee : Int
  weight : Int
  weight_pos : 0 < weight

/-- Left side of the cross multiplication. -/
def cross (a b : FeeWeight) : Int := a.fee * b.weight

/-- `rate_cmp`: `a` compares below `b` when `a.fee * b.weight < b.fee * a.weight`. -/
def rateCmp (a b : FeeWeight) : Ordering :=
  if cross a b < cross b a then Ordering.lt
  else if cross a b = cross b a then Ordering.eq
  else Ordering.gt

/-- Non-strict rate order. -/
def rateLe (a b : FeeWeight) : Prop := cross a b ≤ cross b a

/-- Rate equality is mutual cross-multiplication equality. -/
def rateEq (a b : FeeWeight) : Prop := cross a b = cross b a

/-- Strict rate order. -/
def rateLt (a b : FeeWeight) : Prop := rateLe a b ∧ ¬ rateLe b a

theorem rotate (x y z : Int) : x * y * z = x * z * y := by
  rw [Int.mul_assoc, Int.mul_assoc, Int.mul_comm y z]

theorem rateLe_refl (a : FeeWeight) : rateLe a a := by
  unfold rateLe
  exact Int.le_refl _

/-- Cross-multiplied comparison is transitive on positive weights. -/
theorem rateLe_trans {a b c : FeeWeight} (hab : rateLe a b) (hbc : rateLe b c) :
    rateLe a c := by
  unfold rateLe cross at *
  have h1 : a.fee * b.weight * c.weight ≤ b.fee * a.weight * c.weight :=
    Int.mul_le_mul_of_nonneg_right hab (Int.le_of_lt c.weight_pos)
  have h2 : b.fee * c.weight * a.weight ≤ c.fee * b.weight * a.weight :=
    Int.mul_le_mul_of_nonneg_right hbc (Int.le_of_lt a.weight_pos)
  rw [rotate a.fee b.weight c.weight] at h1
  rw [rotate b.fee c.weight a.weight, rotate c.fee b.weight a.weight] at h2
  exact Int.le_of_mul_le_mul_right (Int.le_trans h1 h2) b.weight_pos

theorem rateLe_total (a b : FeeWeight) : rateLe a b ∨ rateLe b a := by
  unfold rateLe
  exact Int.le_total _ _

theorem rateLe_antisymm {a b : FeeWeight} (hab : rateLe a b) (hba : rateLe b a) :
    rateEq a b := by
  unfold rateLe rateEq at *
  exact Int.le_antisymm hab hba

theorem rateLt_trichotomy (a b : FeeWeight) :
    rateLt a b ∨ rateEq a b ∨ rateLt b a := by
  unfold rateLt rateEq rateLe
  rcases Int.lt_trichotomy (cross a b) (cross b a) with hlt | heq | hgt
  · exact Or.inl ⟨Int.le_of_lt hlt, Int.not_le.mpr hlt⟩
  · exact Or.inr (Or.inl heq)
  · exact Or.inr (Or.inr ⟨Int.le_of_lt hgt, Int.not_le.mpr hgt⟩)

theorem rateCmp_eq_iff {a b : FeeWeight} :
    (rateCmp a b = Ordering.eq) ↔ rateEq a b := by
  unfold rateCmp rateEq
  split
  · rename_i hlt; simp; omega
  · split
    · rename_i hlt heq; simp; omega
    · rename_i hlt hne; simp; omega
theorem rateCmp_lt_iff {a b : FeeWeight} :
    (rateCmp a b = Ordering.lt) ↔ cross a b < cross b a := by
  unfold rateCmp
  split
  · rename_i hlt; simp; omega
  · split
    · rename_i hlt heq; simp; omega
    · rename_i hlt hne; simp; omega
theorem rateCmp_gt_iff {a b : FeeWeight} :
    (rateCmp a b = Ordering.gt) ↔ cross b a < cross a b := by
  unfold rateCmp
  split
  · rename_i hlt; simp; omega
  · split
    · rename_i hlt heq; simp; omega
    · rename_i hlt hne; simp; omega
theorem rateCmp_not_gt_iff {a b : FeeWeight} :
    (rateCmp a b ≠ Ordering.gt) ↔ rateLe a b := by
  unfold rateCmp rateLe
  split
  · rename_i hlt; simp; omega
  · split
    · rename_i hlt heq; simp; omega
    · rename_i hlt hne; simp; omega
-- POL-05
/-- `rate_cmp` is a total preorder: reflexive, transitive, total, and
antisymmetric up to rate equality. -/
theorem rateCmp_total_preorder (a b c : FeeWeight) :
    (rateCmp a a = Ordering.eq)
    ∧ (rateCmp a b ≠ Ordering.gt → rateCmp b c ≠ Ordering.gt →
        rateCmp a c ≠ Ordering.gt)
    ∧ (rateCmp a b = Ordering.lt ∨ rateCmp a b = Ordering.eq
        ∨ rateCmp a b = Ordering.gt) := by
  refine ⟨?_, ?_, ?_⟩
  · rw [rateCmp_eq_iff]
    exact rateLe_antisymm (rateLe_refl a) (rateLe_refl a)
  · intro hab hbc
    rw [rateCmp_not_gt_iff] at hab hbc ⊢
    exact rateLe_trans hab hbc
  · rcases Int.lt_trichotomy (cross a b) (cross b a) with hlt | heq | hgt
    · exact Or.inl (rateCmp_lt_iff.mpr hlt)
    · exact Or.inr (Or.inl (rateCmp_eq_iff.mpr heq))
    · exact Or.inr (Or.inr (rateCmp_gt_iff.mpr hgt))

end Mempool.FeeDiagram
