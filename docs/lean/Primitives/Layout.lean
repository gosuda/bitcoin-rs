/-
Decode reservation bound for the borrowed wire layout in
`crates/primitives/src/layout.rs`.
-/

namespace Primitives.Layout

/-- Largest `usize` value on a 64-bit target; the Rust decoder is built for that width. -/
def usizeMax : Nat := 2 ^ 64 - 1

/-- Saturating multiply, as `usize::saturating_mul` behaves on the host. -/
def satMul (a b : Nat) : Nat :=
  if a * b ≤ usizeMax then a * b else usizeMax

/-- `DECODE_EXPANSION` is the largest per-element heap factor over the exclusive wire minimums. -/
def decodeReservation (expansion wire : Nat) : Nat :=
  satMul wire (1 + expansion)

theorem satMul_eq_min (a b : Nat) : satMul a b = min (a * b) usizeMax := by
  unfold satMul
  simp [Nat.min_def]

theorem decodeReservation_eq_min (expansion wire : Nat) :
    decodeReservation expansion wire = min (wire * (1 + expansion)) usizeMax := by
  unfold decodeReservation
  exact satMul_eq_min wire (1 + expansion)

theorem min_le_min {a b c d : Nat} (h1 : a ≤ b) (h2 : c ≤ d) : min a c ≤ min b d := by
  rw [Nat.min_def, Nat.min_def]
  split <;> split <;> omega

theorem decodeReservation_mono {expansion a b : Nat} (h : a ≤ b) :
    decodeReservation expansion a ≤ decodeReservation expansion b := by
  rw [decodeReservation_eq_min, decodeReservation_eq_min]
  exact min_le_min (Nat.mul_le_mul_right (1 + expansion) h) (Nat.le_refl usizeMax)

/-- The reservation never exceeds the wire image plus one heap multiple per wire byte. -/
theorem decodeReservation_le_succ (expansion wire : Nat) :
    decodeReservation expansion wire ≤ wire * (1 + expansion) := by
  rw [decodeReservation_eq_min]
  exact Nat.min_le_left _ _

/-- With every element factor at most fifteen, the reservation is at most sixteen wire multiples.
-/
theorem decodeReservation_linear {expansion wire : Nat} (he : expansion ≤ 15) :
    decodeReservation expansion wire ≤ 16 * wire := by
  have hfactor : 1 + expansion ≤ 16 := by omega
  have h1 := decodeReservation_le_succ expansion wire
  have h2 : wire * (1 + expansion) ≤ wire * 16 := Nat.mul_le_mul_left wire hfactor
  omega

/-- A four-million-byte maximum block stays inside the 64 MiB historical staging clamp when every
element factor is at most fifteen. -/
theorem decodeReservation_block_clamp {expansion : Nat} (he : expansion ≤ 15) :
    decodeReservation expansion 4_000_000 ≤ 64 * 1024 * 1024 := by
  have hlin := decodeReservation_linear (wire := 4_000_000) he
  omega

end Primitives.Layout
