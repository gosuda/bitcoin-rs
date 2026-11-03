/-
Canonical CompactSize encoding, mirroring `crates/primitives/src/varint.rs`.
-/

namespace Primitives.Varint

abbrev Bytes := List UInt8

/-- Little-endian value of a byte list. -/
def leVal : Bytes → Nat
  | [] => 0
  | b :: rest => b.toNat + 256 * leVal rest

/-- Exactly `k` little-endian bytes of `v`. -/
def leBytes : Nat → Nat → Bytes
  | 0, _ => []
  | k + 1, v => UInt8.ofNat (v % 256) :: leBytes k (v / 256)

theorem leBytes_length (k v : Nat) : (leBytes k v).length = k := by
  induction k generalizing v with
  | zero => rfl
  | succ k ih => simp [leBytes, ih]

theorem leVal_lt (bs : Bytes) : leVal bs < 256 ^ bs.length := by
  induction bs with
  | nil => simp [leVal]
  | cons b rest ih =>
    have hb : b.toNat < 256 := UInt8.toNat_lt b
    have hmul : 256 * leVal rest < 256 * 256 ^ rest.length :=
      Nat.mul_lt_mul_of_pos_left ih (by decide)
    have hpow : 256 ^ (rest.length + 1) = 256 ^ rest.length * 256 :=
      Nat.pow_succ 256 rest.length
    simp only [leVal, List.length_cons]
    omega

theorem leVal_leBytes (k v : Nat) (h : v < 256 ^ k) : leVal (leBytes k v) = v := by
  induction k generalizing v with
  | zero =>
    have hv : v = 0 := by
      have : 256 ^ 0 = 1 := Nat.pow_zero 256
      omega
    subst hv
    rfl
  | succ k ih =>
    have hpow : 256 ^ (k + 1) = 256 ^ k * 256 := Nat.pow_succ 256 k
    have hv : v / 256 < 256 ^ k := by omega
    simp only [leBytes, leVal]
    rw [UInt8.toNat_ofNat', ih (v / 256) hv, Nat.mod_mod]
    omega

theorem leBytes_leVal (xs : Bytes) : leBytes xs.length (leVal xs) = xs := by
  induction xs with
  | nil => rfl
  | cons b rest ih =>
    have hb : b.toNat < 256 := UInt8.toNat_lt b
    have hdiv : leVal (b :: rest) / 256 = leVal rest := by
      simp only [leVal]
      omega
    have hmod : leVal (b :: rest) % 256 = b.toNat := by
      simp only [leVal]
      omega
    show leBytes (rest.length + 1) (leVal (b :: rest)) = b :: rest
    rw [show leBytes (rest.length + 1) (leVal (b :: rest))
        = UInt8.ofNat (leVal (b :: rest) % 256)
            :: leBytes rest.length (leVal (b :: rest) / 256) from rfl]
    rw [hmod, hdiv]
    rw [show UInt8.ofNat b.toNat = b from UInt8.ofNat_toNat, ih]

/-- Canonical CompactSize encoding. -/
def encode (v : Nat) : Bytes :=
  if v ≤ 0xfc then [UInt8.ofNat v]
  else if v ≤ 0xffff then 0xfd :: leBytes 2 v
  else if v ≤ 0xffffffff then 0xfe :: leBytes 4 v
  else 0xff :: leBytes 8 v

/-- Decoder that accepts only the canonical width for the value it reads. -/
def decode : Bytes → Option (Nat × Nat)
  | [] => none
  | b :: rest =>
    if b.toNat ≤ 0xfc then some (b.toNat, 1)
    else if b.toNat = 0xfd then
      match rest with
      | c :: d :: _ =>
        let v := leVal [c, d]
        if v < 0xfd then none else some (v, 3)
      | _ => none
    else if b.toNat = 0xfe then
      match rest with
      | c :: d :: e :: f :: _ =>
        let v := leVal [c, d, e, f]
        if v ≤ 0xffff then none else some (v, 5)
      | _ => none
    else if b.toNat = 0xff then
      match rest with
      | c :: d :: e :: f :: g :: h :: i :: j :: _ =>
        let v := leVal [c, d, e, f, g, h, i, j]
        if v ≤ 0xffffffff then none else some (v, 9)
      | _ => none
    else none

theorem toNat_ofNat_lt {n : Nat} (h : n < 256) : (UInt8.ofNat n).toNat = n := by
  rw [UInt8.toNat_ofNat', Nat.mod_eq_of_lt h]

theorem byte_eq_of_toNat {b : UInt8} {n : Nat} (h : b.toNat = n) (_hn : n < 256) :
    b = UInt8.ofNat n := by
  have : UInt8.ofNat b.toNat = b := UInt8.ofNat_toNat
  rw [h] at this
  exact this.symm

theorem leVal_two (c d : UInt8) : leVal [c, d] = c.toNat + 256 * d.toNat := by
  simp only [leVal]
  omega

theorem leBytes_two {v : Nat} (c d : UInt8) (h : v = leVal [c, d]) :
    leBytes 2 v = [c, d] := by
  rw [h]
  exact leBytes_leVal [c, d]

theorem leBytes_four {v : Nat} (c d e f : UInt8) (h : v = leVal [c, d, e, f]) :
    leBytes 4 v = [c, d, e, f] := by
  rw [h]
  exact leBytes_leVal [c, d, e, f]

theorem leBytes_eight {v : Nat} (c d e f g h i j : UInt8)
    (hv : v = leVal [c, d, e, f, g, h, i, j]) :
    leBytes 8 v = [c, d, e, f, g, h, i, j] := by
  rw [hv]
  exact leBytes_leVal [c, d, e, f, g, h, i, j]

theorem encode_length_le (v : Nat) : (encode v).length ≤ 9 := by
  unfold encode
  by_cases h1 : v ≤ 0xfc
  · simp [h1]
  · by_cases h2 : v ≤ 0xffff
    · simp [h1, h2, leBytes_length]
    · by_cases h3 : v ≤ 0xffffffff
      · simp [h1, h2, h3, leBytes_length]
      · simp [h1, h2, h3, leBytes_length]

-- P2P-01
theorem decode_encode (v : Nat) (hv : v < 2 ^ 64) :
    decode (encode v) = some (v, (encode v).length) := by
  have hprefix : ∀ n : Nat, n < 256 → (UInt8.ofNat n).toNat = n :=
    fun n hn => toNat_ofNat_lt (n := n) hn
  unfold encode
  by_cases h1 : v ≤ 0xfc
  · have hlt : v < 256 := by omega
    simp [h1, decode, hprefix v hlt]
  · by_cases h2 : v ≤ 0xffff
    · have hval : leVal (leBytes 2 v) = v := leVal_leBytes 2 v (by omega)
      have hnot : ¬ v < 0xfd := by omega
      have hlist : leBytes 2 v
          = [UInt8.ofNat (v % 256), UInt8.ofNat (v / 256 % 256)] := rfl
      have hval2 : leVal [UInt8.ofNat (v % 256), UInt8.ofNat (v / 256 % 256)] = v := by
        rw [← hlist]
        exact hval
      rw [hlist]
      simp [h1, h2, decode, hval2, hnot]
    · by_cases h3 : v ≤ 0xffffffff
      · have hval : leVal (leBytes 4 v) = v := leVal_leBytes 4 v (by omega)
        have hnot : ¬ v ≤ 0xffff := by omega
        have hlist : leBytes 4 v
            = [UInt8.ofNat (v % 256), UInt8.ofNat (v / 256 % 256),
               UInt8.ofNat (v / 256 / 256 % 256), UInt8.ofNat (v / 256 / 256 / 256 % 256)]
            := rfl
        have hval2 : leVal [UInt8.ofNat (v % 256), UInt8.ofNat (v / 256 % 256),
            UInt8.ofNat (v / 256 / 256 % 256),
            UInt8.ofNat (v / 256 / 256 / 256 % 256)] = v := by
          rw [← hlist]
          exact hval
        rw [hlist]
        simp [h1, h2, h3, decode, hval2]
      · have hval : leVal (leBytes 8 v) = v := leVal_leBytes 8 v (by omega)
        have hnot : ¬ v ≤ 0xffffffff := by omega
        have hlist : leBytes 8 v
            = [UInt8.ofNat (v % 256), UInt8.ofNat (v / 256 % 256),
               UInt8.ofNat (v / 256 / 256 % 256), UInt8.ofNat (v / 256 / 256 / 256 % 256),
               UInt8.ofNat (v / 256 / 256 / 256 / 256 % 256),
               UInt8.ofNat (v / 256 / 256 / 256 / 256 / 256 % 256),
               UInt8.ofNat (v / 256 / 256 / 256 / 256 / 256 / 256 % 256),
               UInt8.ofNat (v / 256 / 256 / 256 / 256 / 256 / 256 / 256 % 256)] := rfl
        have hval2 : leVal [UInt8.ofNat (v % 256), UInt8.ofNat (v / 256 % 256),
            UInt8.ofNat (v / 256 / 256 % 256),
            UInt8.ofNat (v / 256 / 256 / 256 % 256),
            UInt8.ofNat (v / 256 / 256 / 256 / 256 % 256),
            UInt8.ofNat (v / 256 / 256 / 256 / 256 / 256 % 256),
            UInt8.ofNat (v / 256 / 256 / 256 / 256 / 256 / 256 % 256),
            UInt8.ofNat (v / 256 / 256 / 256 / 256 / 256 / 256 / 256 % 256)] = v := by
          rw [← hlist]
          exact hval
        rw [hlist]
        simp [h1, h2, h3, decode, hval2]

/-- A two-byte-wide prefix that would name a smaller value is rejected: the canonical width for
every value below `0xfd` is one byte. -/
theorem decode_rejects_narrow_two (c d : UInt8) (rest : Bytes)
    (hsmall : leVal [c, d] < 0xfd) : decode (0xfd :: c :: d :: rest) = none := by
  simp [decode, leVal_two] at hsmall ⊢
  omega

/-- A four-byte-wide prefix that would name a smaller value is rejected. -/
theorem decode_rejects_narrow_four (c d e f : UInt8) (rest : Bytes)
    (hsmall : leVal [c, d, e, f] ≤ 0xffff) :
    decode (0xfe :: c :: d :: e :: f :: rest) = none := by
  simp [decode] at hsmall ⊢
  omega

/-- An eight-byte-wide prefix that would name a smaller value is rejected. -/
theorem decode_rejects_narrow_eight (c d e f g h i j : UInt8) (rest : Bytes)
    (hsmall : leVal [c, d, e, f, g, h, i, j] ≤ 0xffffffff) :
    decode (0xff :: c :: d :: e :: f :: g :: h :: i :: j :: rest) = none := by
  simp [decode] at hsmall ⊢
  omega

/-- `encode` is injective on the 64-bit CompactSize domain. -/
theorem encode_injective {a b : Nat} (ha : a < 2 ^ 64) (hb : b < 2 ^ 64)
    (h : encode a = encode b) : a = b := by
  have ha' := decode_encode a ha
  rw [h] at ha'
  have hb' := decode_encode b hb
  rw [hb'] at ha'
  simp only [Option.some.injEq, Prod.mk.injEq] at ha'
  exact ha'.1.symm

end Primitives.Varint
