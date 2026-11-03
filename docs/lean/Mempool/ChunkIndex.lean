/-
Chunk ordering for the mempool chunk index
(`crates/mempool/src/chunk_index.rs`). `ChunkKey::cmp` orders by rate first and
then by four deterministic tie-breakers; the theorems below show that order is
a strict total order on rate-equivalence classes.
-/

import Mempool.FeeDiagram

namespace Mempool.ChunkIndex

open Mempool.FeeDiagram

structure ChunkKey where
  rate : FeeWeight
  prefixWeight : Nat
  maxTxid : Nat
  component : Nat
  ordinal : Nat

/-- Deterministic tie-breaker order over the four remaining fields. -/
def tailLt (a b : ChunkKey) : Prop :=
  a.prefixWeight < b.prefixWeight
  ∨ (a.prefixWeight = b.prefixWeight
      ∧ (a.maxTxid < b.maxTxid
          ∨ (a.maxTxid = b.maxTxid
              ∧ (a.component < b.component
                  ∨ (a.component = b.component ∧ a.ordinal < b.ordinal)))))

/-- The key order: rate first, tie-breakers second. -/
def keyLt (a b : ChunkKey) : Prop :=
  rateLt a.rate b.rate ∨ (rateEq a.rate b.rate ∧ tailLt a b)

theorem tailLt_irrefl (a : ChunkKey) : ¬ tailLt a a := by
  unfold tailLt
  omega

theorem tailLt_trans {a b c : ChunkKey} (hab : tailLt a b) (hbc : tailLt b c) :
    tailLt a c := by
  unfold tailLt at *
  omega

theorem tailLt_total (a b : ChunkKey) :
    tailLt a b ∨ tailLt b a
    ∨ (a.prefixWeight = b.prefixWeight ∧ a.maxTxid = b.maxTxid
        ∧ a.component = b.component ∧ a.ordinal = b.ordinal) := by
  unfold tailLt
  omega

theorem rateLt_irrefl (a : FeeWeight) : ¬ rateLt a a := by
  intro h
  exact h.2 (rateLe_refl a)

theorem rateLt_asymm {a b : FeeWeight} (h : rateLt a b) : ¬ rateLt b a := by
  intro hba
  exact h.2 hba.1

theorem rateLt_trans {a b c : FeeWeight} (hab : rateLt a b) (hbc : rateLt b c) :
    rateLt a c := by
  refine ⟨rateLe_trans hab.1 hbc.1, ?_⟩
  intro hca
  exact hbc.2 (rateLe_trans hca hab.1)

theorem rateEq_iff_le (a b : FeeWeight) : rateEq a b ↔ rateLe a b ∧ rateLe b a := by
  unfold rateEq rateLe
  constructor
  · intro h; exact ⟨Int.le_of_eq h, Int.le_of_eq h.symm⟩
  · intro h; exact Int.le_antisymm h.1 h.2

theorem rateEq_symm {a b : FeeWeight} (h : rateEq a b) : rateEq b a := by
  rw [rateEq_iff_le] at h ⊢
  exact ⟨h.2, h.1⟩

theorem rateEq_trans {a b c : FeeWeight} (hab : rateEq a b) (hbc : rateEq b c) :
    rateEq a c := by
  rw [rateEq_iff_le] at hab hbc ⊢
  exact ⟨rateLe_trans hab.1 hbc.1, rateLe_trans hbc.2 hab.2⟩

theorem rateLt_mixed_left {a b c : FeeWeight} (hab : rateLt a b) (hbc : rateEq b c) :
    rateLt a c := by
  rw [rateEq_iff_le] at hbc
  refine ⟨rateLe_trans hab.1 hbc.1, ?_⟩
  intro hca
  exact hab.2 (rateLe_trans hbc.1 hca)

theorem rateLt_mixed_right {a b c : FeeWeight} (hab : rateEq a b) (hbc : rateLt b c) :
    rateLt a c := by
  rw [rateEq_iff_le] at hab
  refine ⟨rateLe_trans hab.1 hbc.1, ?_⟩
  intro hca
  exact hbc.2 (rateLe_trans hca hab.1)

theorem keyLt_irrefl (a : ChunkKey) : ¬ keyLt a a := by
  intro h
  rcases h with h | ⟨_, h⟩
  · exact rateLt_irrefl a.rate h
  · exact tailLt_irrefl a h

theorem keyLt_trans {a b c : ChunkKey} (hab : keyLt a b) (hbc : keyLt b c) :
    keyLt a c := by
  rcases hab with hab | ⟨hab, habt⟩
  · rcases hbc with hbc | ⟨hbc, _⟩
    · exact Or.inl (rateLt_trans hab hbc)
    · exact Or.inl (rateLt_mixed_left hab hbc)
  · rcases hbc with hbc | ⟨hbc, hbct⟩
    · exact Or.inl (rateLt_mixed_right hab hbc)
    · exact Or.inr ⟨rateEq_trans hab hbc, tailLt_trans habt hbct⟩

theorem keyLt_asymm {a b : ChunkKey} (h : keyLt a b) : ¬ keyLt b a := by
  intro hba
  rcases h with h | ⟨hrate, htail⟩
  · rcases hba with hba | ⟨hba, _⟩
    · exact rateLt_asymm h hba
    · rw [rateEq_iff_le] at hba
      exact h.2 hba.1
  · rcases hba with hba | ⟨hba, htail'⟩
    · rw [rateEq_iff_le] at hrate
      exact hba.2 hrate.1
    · exact tailLt_irrefl a (tailLt_trans htail htail')

theorem keyLt_comparable (a b : ChunkKey) :
    keyLt a b ∨ keyLt b a
    ∨ (rateEq a.rate b.rate ∧ ¬ tailLt a b ∧ ¬ tailLt b a) := by
  rcases rateLt_trichotomy a.rate b.rate with hlt | heq | hgt
  · exact Or.inl (Or.inl hlt)
  · rcases tailLt_total a b with htail | htail | ⟨h1, h2, h3, h4⟩
    · exact Or.inl (Or.inr ⟨heq, htail⟩)
    · exact Or.inr (Or.inl (Or.inr ⟨rateEq_symm heq, htail⟩))
    · refine Or.inr (Or.inr ⟨heq, ?_, ?_⟩)
      · intro h; unfold tailLt at h; omega
      · intro h; unfold tailLt at h; omega
  · exact Or.inr (Or.inl (Or.inl hgt))

-- POL-05
/-- `ChunkKey` comparison is a strict total order on rate-equivalence classes:
irreflexive, transitive, asymmetric, and comparable. -/
theorem chunkKey_strict_total_order (a b c : ChunkKey) :
    (¬ keyLt a a)
    ∧ (keyLt a b → keyLt b c → keyLt a c)
    ∧ (keyLt a b → ¬ keyLt b a)
    ∧ (keyLt a b ∨ keyLt b a
        ∨ (rateEq a.rate b.rate ∧ ¬ tailLt a b ∧ ¬ tailLt b a)) :=
  ⟨keyLt_irrefl a, keyLt_trans, keyLt_asymm, keyLt_comparable a b⟩

end Mempool.ChunkIndex
