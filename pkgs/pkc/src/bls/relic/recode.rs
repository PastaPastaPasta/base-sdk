//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! relic's scalar recodings, `bn_rec_naf`, `bn_rec_glv` and `bn_rec_frb`,
//! with the `bn_t` sign rules they rely on.
//!
//! A recoding's signs pick the table a multiplication runs on, so they are
//! ported as relic computes them, zero's sign included: `bn_add` and
//! `bn_sub` can leave a zero negative, while `bn_mul` and `bn_neg` cannot.

use crate::prelude::*;

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use zeroize::Zeroize;

use core::cmp::Ordering;

/// Limbs of a [`Bn`] magnitude, enough for the GLV products (384 bits).
const LIMBS: usize = 8;

/// The group order r: `ep_curve_get_ord`.
const R: [u64; 4] = [
  0xffff_ffff_0000_0001,
  0x53bd_a402_fffe_5bfe,
  0x3339_d808_09a1_d805,
  0x73ed_a753_299d_7d48,
];

/// relic's `bn_bits(r)`.
const R_BITS: usize = 255;

/// |x| for the BLS12-381 parameter x = -0xd201000000010000,
/// `fp_prime_get_par`; `bn_rec_frb`'s digit base.
const X_ABS: u64 = 0xd201_0000_0001_0000;

/// The G1 GLV basis `ctx->ep_v1` and `ctx->ep_v2` (`ep_curve_get_v1`/`v2`),
/// as `ep_curve_set_endom` leaves them: entry 0 is the rounding constant,
/// entries 1 and 2 a lattice vector (a, b) with a + b lambda = 0 mod r for
/// lambda = x² - 1.
const V1: [Bn; 3] = [
  Bn::pos(&[1]),
  Bn::pos(&[1]),
  Bn::pos(&[0x0000_0001_0000_0000, 0xac45_a401_0001_a402]),
];
const V2: [Bn; 3] = [
  Bn::pos(&[0x63f6_e522_f6cf_ee2f, 0x7c6b_ecf1_e01f_aadd, 1]),
  Bn::pos(&[0x0000_0000_ffff_ffff, 0xac45_a401_0001_a402]),
  Bn::NEG_ONE,
];

/// A relic `bn_t`: a sign and a magnitude.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub(crate) struct Bn {
  neg: bool,
  mag: [u64; LIMBS],
}

impl Bn {
  #[cfg(test)]
  const ZERO: Self = Self::pos(&[]);
  const NEG_ONE: Self = Self {
    neg: true,
    mag: Self::pos(&[1]).mag,
  };

  /// A non-negative value from little-endian limbs.
  const fn pos(limbs: &[u64]) -> Self {
    let mut mag = [0; LIMBS];
    let mut i = 0;
    while i < limbs.len() {
      mag[i] = limbs[i];
      i += 1;
    }
    Self { neg: false, mag }
  }

  /// `bn_read_bin` of a 32-byte big-endian scalar, which is never negative.
  pub(crate) fn from_bendian(bytes: &[u8; 32]) -> Self {
    let mut mag = [0; LIMBS];
    for (limb, chunk) in mag.iter_mut().zip(bytes.rchunks_exact(8)) {
      *limb = u64::from_be_bytes(chunk.try_into().unwrap_or_default());
    }
    Self { neg: false, mag }
  }

  /// The 32-byte little-endian magnitude, which blst's `mult` reads.
  pub(crate) fn to_lendian(self) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, limb) in out.chunks_exact_mut(8).zip(self.mag) {
      chunk.copy_from_slice(&limb.to_le_bytes());
    }
    out
  }

  /// `bn_sign(a) == RLC_NEG`.
  pub(crate) fn is_neg(&self) -> bool {
    self.neg
  }

  /// `bn_is_zero`.
  pub(crate) fn is_zero(&self) -> bool {
    self.mag == [0; LIMBS]
  }

  /// `bn_bits`: the bit length of the magnitude.
  pub(crate) fn bits(&self) -> usize {
    self
      .mag
      .iter()
      .rposition(|&l| l != 0)
      .map_or(0, |i| 64 * i + 64 - self.mag[i].leading_zeros() as usize)
  }

  /// The low digit, `dp[0]`.
  pub(crate) fn low(&self) -> u64 {
    self.mag[0]
  }

  /// `bn_trim`'s rule: zero is never negative.
  fn trim(mut self) -> Self {
    if self.is_zero() {
      self.neg = false;
    }
    self
  }

  /// `bn_abs`.
  fn abs(self) -> Self {
    Self { neg: false, ..self }
  }

  /// `bn_neg`: a zero keeps its sign.
  fn neg(self) -> Self {
    Self {
      neg: self.neg ^ !self.is_zero(),
      ..self
    }
  }

  /// `bn_add` (`relic_bn_add.c`): equal signs set the sign before the
  /// trimming add; unequal signs set it after the subtraction, so
  /// -a + a = -0.
  fn add(self, b: Self) -> Self {
    if self.neg == b.neg {
      Self {
        neg: self.neg,
        mag: add_mag(&self.mag, &b.mag),
      }
      .trim()
    } else if cmp_mag(&self.mag, &b.mag) == Ordering::Less {
      Self {
        neg: b.neg,
        mag: sub_mag(&b.mag, &self.mag),
      }
    } else {
      Self {
        neg: self.neg,
        mag: sub_mag(&self.mag, &b.mag),
      }
    }
  }

  /// `bn_sub`: unequal signs set the sign before the trimming add; equal
  /// signs set it after the subtraction, so -a - (-a) = -0.
  fn sub(self, b: Self) -> Self {
    if self.neg != b.neg {
      Self {
        neg: self.neg,
        mag: add_mag(&self.mag, &b.mag),
      }
      .trim()
    } else if cmp_mag(&self.mag, &b.mag) != Ordering::Less {
      Self {
        neg: self.neg,
        mag: sub_mag(&self.mag, &b.mag),
      }
    } else {
      Self {
        neg: !self.neg,
        mag: sub_mag(&b.mag, &self.mag),
      }
    }
  }

  /// `bn_mul`: the sign is the product's, then trimmed.
  fn mul(self, b: Self) -> Self {
    let mut mag = [0u64; LIMBS];
    for (i, &x) in self.mag.iter().enumerate() {
      let mut carry = 0u128;
      for (j, &y) in b.mag.iter().enumerate().take(LIMBS - i) {
        let t = u128::from(mag[i + j]) + u128::from(x) * u128::from(y) + carry;
        mag[i + j] = t as u64;
        carry = t >> 64;
      }
    }
    Self {
      neg: self.neg ^ b.neg,
      mag,
    }
    .trim()
  }

  /// `bn_rsh`: the magnitude shifted right, the sign kept, then trimmed.
  fn rsh(self, bits: usize) -> Self {
    let (limbs, rem) = (bits / 64, bits % 64);
    let mut mag = [0u64; LIMBS];
    for (i, out) in mag.iter_mut().enumerate().take(LIMBS - limbs) {
      let lo = self.mag[i + limbs] >> rem;
      let hi = match (rem, self.mag.get(i + limbs + 1)) {
        (0, _) | (_, None) => 0,
        (_, Some(&next)) => next << (64 - rem),
      };
      *out = lo | hi;
    }
    Self { neg: self.neg, mag }.trim()
  }

  /// `bn_get_bit`.
  fn bit(&self, i: usize) -> u64 {
    self.mag[i / 64] >> (i % 64) & 1
  }

  /// `bn_add_dig` on a non-negative value, the only kind it is given here.
  fn add_dig(self, d: u64) -> Self {
    debug_assert!(!self.neg);
    Self {
      neg: false,
      mag: add_mag(&self.mag, &Self::pos(&[d]).mag),
    }
  }

  /// `bn_mod(c, a, r)` of a non-negative value below 2^256: at most three
  /// subtractions of r.
  pub(crate) fn mod_r(mut self) -> Self {
    let r = Self::pos(&R);
    while cmp_mag(&self.mag, &r.mag) != Ordering::Less {
      self.mag = sub_mag(&self.mag, &r.mag);
    }
    self
  }

  /// `bn_mod` and `bn_div` of a non-negative value by a digit: the
  /// remainder and the quotient, both non-negative.
  fn div_rem_dig(self, d: u64) -> (Self, Self) {
    let mut quo = [0u64; LIMBS];
    let mut rem = 0u128;
    for (q, &limb) in quo.iter_mut().zip(&self.mag).rev() {
      let cur = rem << 64 | u128::from(limb);
      *q = (cur / u128::from(d)) as u64;
      rem = cur % u128::from(d);
    }
    (Self::pos(&[rem as u64]), Self { neg: false, mag: quo })
  }

  /// Overwrites the value with zero, for a copy of a secret scalar
  /// (BS11a-3 D33). `Bn` does not implement `Zeroize`: base-sdk's CodeQL
  /// policy treats any type that does as secret (no `Debug` or
  /// `PartialEq`), and public scalars use `Bn` too.
  pub(crate) fn wipe(&mut self) {
    self.neg.zeroize();
    self.mag.zeroize();
  }
}

fn cmp_mag(a: &[u64; LIMBS], b: &[u64; LIMBS]) -> Ordering {
  a.iter().rev().cmp(b.iter().rev())
}

fn add_mag(a: &[u64; LIMBS], b: &[u64; LIMBS]) -> [u64; LIMBS] {
  let mut out = [0u64; LIMBS];
  let mut carry = false;
  for ((o, &x), &y) in out.iter_mut().zip(a).zip(b) {
    let (s, c1) = x.overflowing_add(y);
    let (s, c2) = s.overflowing_add(u64::from(carry));
    *o = s;
    carry = c1 || c2;
  }
  debug_assert!(!carry);
  out
}

/// `a - b` for `a >= b`.
fn sub_mag(a: &[u64; LIMBS], b: &[u64; LIMBS]) -> [u64; LIMBS] {
  let mut out = [0u64; LIMBS];
  let mut borrow = false;
  for ((o, &x), &y) in out.iter_mut().zip(a).zip(b) {
    let (d, b1) = x.overflowing_sub(y);
    let (d, b2) = d.overflowing_sub(u64::from(borrow));
    *o = d;
    borrow = b1 || b2;
  }
  debug_assert!(!borrow);
  out
}

/// `bn_rec_naf(naf, &len, k, w)` (`relic_bn_rec.c`), least significant
/// digit first. It recodes |k|; callers handle the sign.
pub(crate) fn rec_naf(k: &Bn, w: u32) -> Vec<i8> {
  let mut t = k.abs();
  let mask = (1u64 << w) - 1;
  let half = 1i8 << (w - 1);
  let mut naf = Vec::with_capacity(t.bits() + 1);
  while !t.is_zero() {
    if t.low() & 1 == 1 {
      let digit = (t.low() & mask) as i8;
      let u = if w == 2 {
        2 - digit
      } else if digit > half {
        digit - (1i8 << (w - 1)) * 2
      } else {
        digit
      };
      t = if u < 0 {
        t.add_dig(u.unsigned_abs().into())
      } else {
        Bn {
          neg: false,
          mag: sub_mag(&t.mag, &Bn::pos(&[u as u64]).mag),
        }
      };
      naf.push(u);
    } else {
      naf.push(0);
    }
    t = t.rsh(1);
  }
  naf
}

/// `bn_rec_glv(k0, k1, k, r, v1, v2)` (`relic_bn_rec.c`): Babai rounding
/// against the G1 basis, so that k = k0 + k1·lambda (mod r). k may be a
/// secret key, so its named copies are wiped, and the caller wipes k0 and
/// k1 (BS11a-3 D33).
pub(crate) fn rec_glv(k: &Bn) -> (Bn, Bn) {
  let mut t = k.abs();
  let round = |v: &Bn| {
    let mut b = t.mul(*v);
    let r = b.bit(R_BITS);
    let out = b.rsh(R_BITS + 1).add_dig(r);
    b.wipe();
    out
  };
  let mut b1 = round(&V1[0]);
  let mut b2 = round(&V2[0]);
  let k0 = t.sub(b1.mul(V1[1]).add(b2.mul(V2[1])));
  let k1 = b1.mul(V1[2]).add(b2.mul(V2[2])).neg();
  t.wipe();
  b1.wipe();
  b2.wipe();
  (k0, k1)
}

/// `bn_rec_frb(ki, 4, k, x, r, bls = 1)` (`relic_bn_rec.c:875-901`): the
/// base-|x| digits of |k|, the odd ones negated as x < 0 and all of them
/// negated for k < 0.
pub(crate) fn rec_frb(k: &Bn) -> [Bn; 4] {
  let mut v = k.abs();
  core::array::from_fn(|i| {
    let (rem, quo) = v.div_rem_dig(X_ABS);
    v = quo;
    let rem = if i % 2 != 0 { rem.neg() } else { rem };
    if k.neg {
      rem.neg()
    } else {
      rem
    }
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  fn int(v: i128) -> Bn {
    let b = Bn::pos(&[v.unsigned_abs() as u64, (v.unsigned_abs() >> 64) as u64]);
    if v < 0 {
      b.neg()
    } else {
      b
    }
  }

  fn neg_zero() -> Bn {
    Bn {
      neg: true,
      mag: [0; LIMBS],
    }
  }

  /// The value of a signed-digit recoding, digit i weighted 2^i.
  fn naf_value(naf: &[i8]) -> i128 {
    naf.iter().rev().fold(0i128, |acc, &d| acc * 2 + i128::from(d))
  }

  /// (a + b·m) mod r for a, b < 2^256 and m < 2^128.
  fn reduce(a: Bn, b: Bn, m: Bn) -> Bn {
    let r = Bn::pos(&R);
    let mut acc = a.add(b.mul(m));
    // The values here stay below 2^390, so a shift-and-subtract reduction
    // over the 512-bit magnitude is exact.
    let mut shifted = Vec::new();
    let mut s = r;
    while s.bits() <= acc.bits().max(R_BITS) + 1 {
      shifted.push(s);
      s = s.add(s);
    }
    let neg = acc.neg;
    acc = acc.abs();
    for s in shifted.iter().rev() {
      if cmp_mag(&acc.mag, &s.mag) != Ordering::Less {
        acc.mag = sub_mag(&acc.mag, &s.mag);
      }
    }
    if neg && !acc.is_zero() {
      r.sub(acc)
    } else {
      acc
    }
  }

  #[test]
  fn signs_follow_relic() {
    // Unequal-sign addition and equal-sign subtraction can leave -0.
    assert_eq!(int(-5).add(int(5)), neg_zero());
    assert_eq!(int(5).add(int(-5)), Bn::ZERO);
    assert_eq!(int(-5).sub(int(-5)), neg_zero());
    assert_eq!(int(5).sub(int(5)), Bn::ZERO);
    assert_eq!(int(3).sub(int(5)), int(-2));
    assert_eq!(int(-3).sub(int(-5)), int(2));
    assert_eq!(int(-3).sub(int(5)), int(-8));
    assert_eq!(int(3).add(int(-5)), int(-2));
    // The trimming paths cannot.
    assert_eq!(neg_zero().add(neg_zero()), Bn::ZERO);
    assert_eq!(int(-5).mul(Bn::ZERO), Bn::ZERO);
    assert_eq!(int(-5).mul(int(3)), int(-15));
    assert_eq!(neg_zero().rsh(1), Bn::ZERO);
    assert_eq!(Bn::ZERO.neg(), Bn::ZERO);
    assert_eq!(neg_zero().neg(), neg_zero());
    assert_eq!(int(7).neg(), int(-7));
  }

  #[test]
  fn reads_big_endian_scalars() {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x80;
    bytes[31] = 0x01;
    let k = Bn::from_bendian(&bytes);
    assert_eq!(k.bits(), 256);
    assert_eq!(k.low(), 1);
    assert!(!k.is_neg());
    let mut le = bytes;
    le.reverse();
    assert_eq!(k.to_lendian(), le);
    assert_eq!(Bn::ZERO.bits(), 0);
  }

  #[test]
  fn reduces_modulo_r() {
    let r = Bn::pos(&R);
    assert_eq!(r.mod_r(), Bn::ZERO);
    assert_eq!(r.add(int(5)).mod_r(), int(5));
    let max = Bn::from_bendian(&[0xff; 32]);
    assert_eq!(max.mod_r().add(r.add(r)), max);
  }

  #[test]
  fn naf_digits_recompose_and_are_odd_and_bounded() {
    for (k, w) in [
      (1i128, 2),
      (3, 2),
      (0x5555, 2),
      (u64::MAX.into(), 2),
      (7, 4),
      (0x1234_5678_9abc, 4),
      (-9, 4),
    ] {
      let naf = rec_naf(&int(k), w);
      assert_eq!(naf_value(&naf), k.abs(), "k = {k}, w = {w}");
      for (i, &d) in naf.iter().enumerate() {
        assert!(d == 0 || (d % 2 != 0 && d.abs() < 1 << (w - 1)), "digit {d}");
        if d != 0 {
          // No two nonzero digits within a window.
          assert!(naf[i + 1..].iter().take(w as usize - 1).all(|&e| e == 0));
        }
      }
    }
    assert!(rec_naf(&Bn::ZERO, 4).is_empty());
    assert_eq!(rec_naf(&int(3), 2), [-1, 0, 1]);
    assert_eq!(rec_naf(&int(15), 4), [-1, 0, 0, 0, 1]);
  }

  #[test]
  fn glv_basis_spans_the_lambda_lattice() {
    // lambda = x² - 1 = V2[1], and V1 = (1, x²) with 1 + x² lambda = 0.
    let lambda = V2[1];
    assert_eq!(reduce(V1[1], V1[2], lambda), Bn::ZERO);
    assert_eq!(reduce(V2[1], V2[2], lambda), Bn::ZERO);
    let x2 = Bn::pos(&[X_ABS]).mul(Bn::pos(&[X_ABS]));
    assert_eq!(V1[2], x2);
    assert_eq!(V2[1], x2.sub(int(1)));
  }

  #[test]
  fn glv_decomposition_is_short_and_exact() {
    let lambda = V2[1];
    let r = Bn::pos(&R);
    let mut samples = vec![int(1), int(2), r.sub(int(1)), V2[1], V1[2], r.rsh(1)];
    let mut seed = 0x0123_4567_89ab_cdefu64;
    for _ in 0..64 {
      let mut bytes = [0u8; 32];
      for b in bytes.iter_mut() {
        seed = seed
          .wrapping_mul(6_364_136_223_846_793_005)
          .wrapping_add(1_442_695_040_888_963_407);
        *b = (seed >> 56) as u8;
      }
      samples.push(Bn::from_bendian(&bytes).mod_r());
    }
    for k in samples {
      let (k0, k1) = rec_glv(&k);
      assert!(k0.bits() <= 129 && k1.bits() <= 129, "{k:?}");
      assert!(!k1.is_neg());
      assert_eq!(reduce(k0, k1, lambda), k, "{k:?}");
    }
  }

  #[test]
  fn frobenius_digits_recompose() {
    let x = int(-(i128::from(X_ABS)));
    let r = Bn::pos(&R);
    for k in [int(1), int(X_ABS.into()), r.sub(int(1)), r.rsh(3)] {
      let digits = rec_frb(&k);
      // The sum of k_i x^i with the digits' signs equals k exactly.
      let mut acc = Bn::ZERO;
      for d in digits.iter().rev() {
        acc = acc.mul(x).add(*d);
      }
      assert_eq!(acc.abs(), k, "{k:?}");
      assert!(digits
        .iter()
        .enumerate()
        .all(|(i, d)| d.is_neg() == (i % 2 == 1 && !d.is_zero())));
    }
    // The odd digits of a negative scalar come out positive.
    let digits = rec_frb(&int(-(i128::from(X_ABS) + 3)));
    assert_eq!(digits[0], int(-3));
    assert_eq!(digits[1], int(1));
  }
}
