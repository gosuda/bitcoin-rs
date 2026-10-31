/-
Amount compression for the UTXO record codec
(`crates/utxo/src/compress.rs`). `enc` and `dec` are Core's compressor formulas;
`dec_enc` proves they are inverse on every reachable compressed form, which is
the bijection property the record codec relies on.
-/

namespace Utxo.Compress

/-- Largest amount the compression is defined for: 21,000,000 BTC in satoshis. -/
def maxMoney : Nat := 2_100_000_000_000_000

/-- Compressed code for the canonical decimal form `n * 10^e`. -/
def enc (n e : Nat) : Nat :=
  if e < 9 then 1 + ((n / 10) * 9 + n % 10 - 1) * 10 + e
  else 1 + (n - 1) * 10 + 9

/-- Amount named by a compressed code. -/
def dec (c : Nat) : Nat :=
  if c = 0 then 0
  else
    let x := c - 1
    let e := x % 10
    let m := x / 10
    if e < 9 then (m / 9 * 10 + (m % 9 + 1)) * 10 ^ e else (m + 1) * 10 ^ 9

theorem compressible_bound (a : Nat) (h : a ≤ maxMoney) : a < 10 ^ 16 := by
  unfold maxMoney at h
  have hpow : (10 : Nat) ^ 16 = 10 ^ 15 * 10 := Nat.pow_succ 10 15
  omega

theorem canonical_digit {n : Nat} (_hn : 0 < n) (h : n % 10 ≠ 0) :
    1 ≤ n % 10 ∧ n % 10 ≤ 9 := by
  have hlt : n % 10 < 10 := Nat.mod_lt n (by decide)
  omega

/-- `dec` is a left inverse of `enc` on every canonical decimal form of at most
nine trailing-zero digits. -/
theorem dec_enc (n e : Nat) (hn : 0 < n) (he : e ≤ 9) (hcanon : e < 9 → n % 10 ≠ 0) :
    dec (enc n e) = n * 10 ^ e := by
  by_cases h9 : e < 9
  · have hdigit : 1 ≤ n % 10 ∧ n % 10 ≤ 9 := canonical_digit hn (hcanon h9)
    have hcode : enc n e = 1 + ((n / 10) * 9 + n % 10 - 1) * 10 + e := by
      unfold enc
      rw [ite_eq_left h9]
    rw [hcode]
    have hne : 1 + ((n / 10) * 9 + n % 10 - 1) * 10 + e ≠ 0 := by omega
    have hmod : (1 + ((n / 10) * 9 + n % 10 - 1) * 10 + e - 1) % 10 = e := by omega
    have hdiv : (1 + ((n / 10) * 9 + n % 10 - 1) * 10 + e - 1) / 10
        = (n / 10) * 9 + n % 10 - 1 := by omega
    have hdec : ((n / 10 * 9 + n % 10 - 1) / 9 * 10
        + ((n / 10 * 9 + n % 10 - 1) % 9 + 1)) = n := by omega
    unfold dec
    rw [ite_eq_right (by omega : ¬ (1 + ((n / 10) * 9 + n % 10 - 1) * 10 + e = 0))]
    simp only [hmod, hdiv, h9, ite_true]
    rw [hdec]
  · have he9 : e = 9 := by omega
    subst he9
    have hcode : enc n 9 = 1 + (n - 1) * 10 + 9 := by
      unfold enc
      rw [ite_eq_right (by omega : ¬ (9 : Nat) < 9)]
    rw [hcode]
    have hmod : (1 + (n - 1) * 10 + 9 - 1) % 10 = 9 := by omega
    have hdiv : (1 + (n - 1) * 10 + 9 - 1) / 10 = n - 1 := by omega
    unfold dec
    rw [ite_eq_right (by omega : ¬ (1 + (n - 1) * 10 + 9 = 0))]
    simp only [hmod, hdiv]
    rw [ite_eq_right (by omega : ¬ (9 : Nat) < 9)]
    have hstep : n - 1 + 1 = n := by omega
    rw [hstep]

/-- Every canonical form below the money supply round-trips through the codec. -/
theorem roundtrip (n e : Nat) (hn : 0 < n) (he : e ≤ 9) (hcanon : e < 9 → n % 10 ≠ 0)
    (_hbound : n * 10 ^ e ≤ maxMoney) :
    dec (enc n e) = n * 10 ^ e :=
  dec_enc n e hn he hcanon

end Utxo.Compress
