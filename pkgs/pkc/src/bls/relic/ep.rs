//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! relic's G1, `ep_*` at the pin: homogeneous projective coordinates with
//! the complete Renes-Costello-Batina formulas for a = 0 (EP_ADD = PROJC,
//! EP_MIXED), and GLV multiplication with a width-4 table (EP_MUL = LWNAF,
//! EP_ENDOM, EP_WIDTH = 4).
//!
//! Each function is a transliteration and keeps relic's branches, which test
//! the coord tag and z = 0 rather than the curve, so it computes Core's
//! result on any input, on the curve or not. Field operations are exact, so
//! only the polynomials and the branches are ported, not the operation order.

use super::super::scalar::Fp;
use super::field::{self, B3, BETA, ONE};
use super::recode::{self, Bn};
use super::Coord;
#[cfg(test)]
use crate::prelude::*;

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use zeroize::{Zeroize, Zeroizing};

/// A relic `ep_t`: x, y, z and the coord tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct Ep {
  pub(crate) x: Fp,
  pub(crate) y: Fp,
  pub(crate) z: Fp,
  pub(crate) coord: Coord,
}

/// `ep_mul`'s table size, 2^(EP_WIDTH - 2).
const TAB: usize = 4;

impl Ep {
  /// `ep_set_infty` (`relic_ep_util.c:43-48`): (0, 0, 0), `BASIC`.
  pub(crate) const INFTY: Self = Self {
    x: field::fp([0; 6]),
    y: field::fp([0; 6]),
    z: field::fp([0; 6]),
    coord: Coord::Basic,
  };

  /// An affine point, (x, y, 1) with tag `coord`.
  pub(crate) fn affine(x: Fp, y: Fp, coord: Coord) -> Self {
    Self { x, y, z: ONE, coord }
  }

  /// `ep_is_infty` (`relic_ep_util.c:39-41`): z = 0.
  pub(crate) fn is_infty(&self) -> bool {
    field::is_zero(&self.z)
  }

  /// `ep_add_projc` (`relic_ep_add.c:742-754`): an infinite operand gives a
  /// copy of the other, tag included.
  pub(crate) fn add(&self, q: &Self) -> Self {
    if self.is_infty() {
      *q
    } else if q.is_infty() {
      *self
    } else if q.coord == Coord::Basic {
      // `ep_add_projc_imp` takes the mixed formulas for a `BASIC` q.
      self.add_mix(q)
    } else {
      self.add_imp(q)
    }
  }

  /// `ep_add_projc_mix` (`relic_ep_add.c:126-157, 255`) for a = 0. It reads
  /// q as affine, whatever q's z.
  fn add_mix(&self, q: &Self) -> Self {
    let p = self;
    let mut t0 = p.x * q.x;
    let mut t1 = p.y * q.y;
    let t3 = (q.x + q.y) * (p.x + p.y) - (t0 + t1);
    let (t4, ry, rz);
    if p.coord == Coord::Basic {
      t4 = q.y + p.y;
      ry = q.x + p.x;
      rz = t1 + B3;
      t1 = t1 - B3;
    } else {
      t4 = q.y * p.z + p.y;
      ry = q.x * p.z + p.x;
      let t2 = B3 * p.z;
      rz = t1 + t2;
      t1 = t1 - t2;
    }
    t0 = t0 + field::dbl(t0);
    let ry = B3 * ry;
    Self {
      x: t3 * t1 - t4 * ry,
      y: t1 * rz + t0 * ry,
      z: rz * t4 + t0 * t3,
      coord: Coord::Projc,
    }
  }

  /// `ep_add_projc_imp`'s general formulas (`relic_ep_add.c:288-339`) for
  /// a = 0.
  fn add_imp(&self, q: &Self) -> Self {
    let p = self;
    let mut t0 = p.x * q.x;
    let mut t1 = p.y * q.y;
    let mut t2 = p.z * q.z;
    let t3 = (p.x + p.y) * (q.x + q.y) - (t0 + t1);
    let t4 = (p.y + p.z) * (q.y + q.z) - (t1 + t2);
    let ry = (p.x + p.z) * (q.x + q.z) - (t0 + t2);
    t0 = t0 + field::dbl(t0);
    t2 = B3 * t2;
    let rz = t1 + t2;
    t1 = t1 - t2;
    let ry = B3 * ry;
    Self {
      x: t3 * t1 - t4 * ry,
      y: t1 * rz + t0 * ry,
      z: rz * t4 + t0 * t3,
      coord: Coord::Projc,
    }
  }

  /// `ep_sub` (`relic_ep_add.c:776-796`): p + (-q). Its `p == q` pointer
  /// test has no caller here that passes one object twice.
  pub(crate) fn sub(&self, q: &Self) -> Self {
    self.add(&q.neg())
  }

  /// `ep_dbl_projc` (`relic_ep_dbl.c:204-255, 510-517`) for a = 0.
  pub(crate) fn dbl(&self) -> Self {
    let p = self;
    if p.is_infty() {
      return Self::INFTY;
    }
    let yy = p.y.square();
    let xy = p.x * p.y;
    // z = 1 is assumed for a BASIC point.
    let (t1, t2) = if p.coord == Coord::Basic {
      (p.y, B3)
    } else {
      (p.y * p.z, B3 * p.z.square())
    };
    let yy8 = field::dbl(field::dbl(field::dbl(yy)));
    let t0 = yy - (field::dbl(t2) + t2);
    Self {
      x: field::dbl(t0 * xy),
      y: t2 * yy8 + t0 * (yy + t2),
      z: t1 * yy8,
      coord: Coord::Projc,
    }
  }

  /// `ep_neg` (`relic_ep_neg.c:38-52`): infinity becomes `set_infty`, so
  /// `BASIC`; otherwise y is negated and the tag kept.
  pub(crate) fn neg(&self) -> Self {
    if self.is_infty() {
      Self::INFTY
    } else {
      Self { y: -self.y, ..*self }
    }
  }

  /// `ep_norm` (`relic_ep_norm.c`): infinity becomes `set_infty`, a `BASIC`
  /// point is copied as it is, and a `PROJC` one is divided by z.
  pub(crate) fn norm(&self) -> Self {
    if self.is_infty() {
      Self::INFTY
    } else if self.coord == Coord::Basic {
      *self
    } else {
      self.norm_imp(field::inv(self.z))
    }
  }

  /// `ep_norm_imp` with z's inverse given: a `PROJC` point becomes
  /// (x·zi, y·zi, 1); either way the tag becomes `BASIC`.
  fn norm_imp(&self, zi: Fp) -> Self {
    if self.coord == Coord::Basic {
      *self
    } else {
      Self::affine(self.x * zi, self.y * zi, Coord::Basic)
    }
  }

  /// `ep_norm_sim(t, t, n)`: one batch inversion of the z's. An infinite
  /// entry keeps z = 0, so a `PROJC` one becomes (0, 0, 1) `BASIC`; a zero
  /// anywhere zeroes every inverse, and a `BASIC` entry takes its inverse as
  /// its z.
  fn norm_sim<const N: usize>(t: [Self; N]) -> [Self; N] {
    let inv = field::inv_sim(t.map(|e| e.z));
    core::array::from_fn(|i| {
      let mut e = t[i];
      if !e.is_infty() {
        e.z = inv[i];
      }
      e.norm_imp(e.z)
    })
  }

  /// `ep_psi` (`relic_ep_psi.c`) for a = 0: (beta x, y, z), tag kept.
  fn psi(&self) -> Self {
    if self.is_infty() {
      Self::INFTY
    } else {
      Self {
        x: self.x * BETA,
        ..*self
      }
    }
  }

  /// `ep_tab(t, p, 4)` (`relic_ep_util.c`): p, then 3p, 5p, 7p from the
  /// normalized double, batch-normalized together.
  fn tab(&self) -> [Self; TAB] {
    let p = self;
    let d = p.dbl().norm();
    let t1 = d.add(p);
    let t2 = t1.add(&d);
    let t3 = t2.add(&d);
    let [t1, t2, t3] = Self::norm_sim([t1, t2, t3]);
    [*p, t1, t2, t3]
  }

  /// `g1_mul` (`relic_pc_exp.c:38-66`) for a scalar `bn_read_bin` gives,
  /// which is never negative: up to 64 bits `ep_mul_dig`, otherwise
  /// `ep_mul_lwnaf` of k mod r.
  ///
  /// k may be a secret key (`ies_key`), so its copies, recodings and the
  /// accumulator are wiped (BS11a-3 D33).
  pub(crate) fn mul(&self, k: &Bn) -> Self {
    if k.bits() <= 64 {
      self.mul_dig(k.low())
    } else {
      let mut k = k.mod_r();
      let out = self.mul_lwnaf(&k);
      k.wipe();
      out
    }
  }

  /// `ep_mul_dig` (`relic_ep_mul.c`): left-to-right over the width-2 NAF of
  /// k, ending in `ep_norm`.
  fn mul_dig(&self, k: u64) -> Self {
    if k == 0 || self.is_infty() {
      return Self::INFTY;
    }
    let mut kb = Bn::from_bendian(&u256(k));
    let naf = Zeroizing::new(recode::rec_naf(&kb, 2));
    kb.wipe();
    let mut t = Self::INFTY;
    for &u in naf.iter().rev() {
      t = t.dbl();
      if u > 0 {
        t = t.add(self);
      } else if u < 0 {
        t = t.sub(self);
      }
    }
    let out = t.norm();
    t.wipe();
    out
  }

  /// `ep_mul_lwnaf` (`relic_ep_mul.c`): zero or an infinite point gives
  /// `set_infty`, otherwise the GLV path.
  fn mul_lwnaf(&self, k: &Bn) -> Self {
    if k.is_zero() || self.is_infty() {
      Self::INFTY
    } else {
      self.mul_glv(k)
    }
  }

  /// `ep_mul_glv_imp` (`relic_ep_mul.c:43-140`). k0's sign picks the table
  /// of p or -p; psi of a table entry is negated when the two signs differ.
  fn mul_glv(&self, k: &Bn) -> Self {
    let (mut k0, mut k1) = recode::rec_glv(k);
    let (s0, s1) = (k0.is_neg(), k1.is_neg());
    let t = if s0 { self.neg().tab() } else { self.tab() };
    let naf0 = Zeroizing::new(recode::rec_naf(&k0, 4));
    let naf1 = Zeroizing::new(recode::rec_naf(&k1, 4));
    k0.wipe();
    k1.wipe();
    let digit = |naf: &[i8], i: usize| naf.get(i).copied().unwrap_or(0);
    let entry = |n: i8| &t[usize::from(n.unsigned_abs() / 2)];
    let mut r = Self::INFTY;
    for i in (0..naf0.len().max(naf1.len())).rev() {
      r = r.dbl();
      let n0 = digit(&naf0, i);
      if n0 > 0 {
        r = r.add(entry(n0));
      } else if n0 < 0 {
        r = r.sub(entry(n0));
      }
      let n1 = digit(&naf1, i);
      if n1 != 0 {
        let mut q = entry(n1).psi();
        if s0 != s1 {
          q = q.neg();
        }
        r = if n1 > 0 { r.add(&q) } else { r.sub(&q) };
      }
    }
    let out = r.norm();
    r.wipe();
    if k.is_neg() {
      out.neg()
    } else {
      out
    }
  }

  /// `ep_cmp` (`relic_ep_cmp.c:38-92`): two infinities are equal; otherwise
  /// each side's x and y are scaled by the other's z when the other is
  /// `PROJC`, and compared. A `BASIC` side is not normalized.
  pub(crate) fn cmp(&self, q: &Self) -> bool {
    if self.is_infty() && q.is_infty() {
      return true;
    }
    let scale = |a: &Self, by: &Self| match by.coord {
      Coord::Projc => (a.x * by.z, a.y * by.z),
      Coord::Basic => (a.x, a.y),
    };
    scale(self, q) == scale(q, self)
  }

  /// `ep_write_bin(..., pack = 1)`'s content (`relic_ep_util.c`, `ep_pck`):
  /// `None` for infinity, else the normalized x and the sign of y.
  pub(crate) fn write_bin(&self) -> Option<(Fp, bool)> {
    if self.is_infty() {
      return None;
    }
    let t = self.norm();
    Some((t.x, field::sign(t.y)))
  }

  /// Overwrites the coordinates with zero, for an accumulator of a secret
  /// multiple (BS11a-3 D33). As for `Bn::wipe`, `Ep` implements no
  /// `Zeroize`.
  fn wipe(&mut self) {
    for c in [&mut self.x, &mut self.y, &mut self.z] {
      c.0.l.zeroize();
    }
  }
}

/// A digit as a 32-byte big-endian scalar.
fn u256(k: u64) -> [u8; 32] {
  let mut out = [0u8; 32];
  out[24..].copy_from_slice(&k.to_be_bytes());
  out
}

#[cfg(test)]
mod tests {
  use super::super::super::group::Point as _;
  use super::super::super::group::{G1Affine, G1};
  use super::*;

  fn generator() -> Ep {
    let g = G1Affine::generator();
    Ep::affine(g.x(), g.y(), Coord::Basic)
  }

  fn to_blst(p: &Ep) -> G1Affine {
    let n = p.norm();
    if n.is_infty() {
      G1Affine::default()
    } else {
      G1Affine::from_coords(n.x, n.y)
    }
  }

  fn scalar(k: u64) -> Bn {
    Bn::from_bendian(&u256(k))
  }

  #[test]
  fn add_and_dbl_agree_with_blst_on_the_subgroup() {
    let g = generator();
    let bg = G1::generator();
    let two = g.dbl();
    assert_eq!(two.coord, Coord::Projc);
    assert_eq!(to_blst(&two), bg.double().to_affine());
    // Mixed (q BASIC) and general (q PROJC) addition.
    let three = two.add(&g);
    assert_eq!(to_blst(&three), (bg.double() + bg).to_affine());
    let five = three.add(&two);
    assert_eq!(to_blst(&five), bg.mul_scalar(&[5], 8).to_affine());
    // p BASIC with q BASIC.
    let three_affine = three.norm();
    assert_eq!(to_blst(&g.add(&three_affine)), bg.mul_scalar(&[4], 8).to_affine());
    // Doubling through the addition formulas.
    assert!(g.add(&g).cmp(&two));
  }

  #[test]
  fn infinity_shapes_follow_relic() {
    let g = generator();
    // P + (-P) leaves (0, y, 0) tagged PROJC, which is infinite.
    let z = g.add(&g.neg());
    assert!(z.is_infty());
    assert_eq!(z.coord, Coord::Projc);
    assert!(!field::is_zero(&z.y));
    // Adding infinity copies the other operand, tag included.
    assert_eq!(z.add(&g), g);
    assert_eq!(g.add(&z), g);
    // Negating or doubling infinity gives set_infty.
    assert_eq!(z.neg(), Ep::INFTY);
    assert_eq!(z.dbl(), Ep::INFTY);
    // set_infty equals the affine (0, 0), which the PROJC infinity does not.
    let origin = Ep::affine(Fp::default(), Fp::default(), Coord::Basic);
    assert!(Ep::INFTY.cmp(&origin));
    assert!(!z.cmp(&origin));
    assert!(z.cmp(&Ep::INFTY));
    assert!(!z.cmp(&g.dbl()));
  }

  #[test]
  fn multiplication_agrees_with_blst_on_the_subgroup() {
    let g = generator();
    let bg = G1::generator();
    let mut ks: Vec<[u8; 32]> = vec![u256(1), u256(2), u256(7), u256(u64::MAX)];
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..16 {
      let mut k = [0u8; 32];
      for b in k.iter_mut() {
        seed = seed
          .wrapping_mul(6_364_136_223_846_793_005)
          .wrapping_add(1_442_695_040_888_963_407);
        *b = (seed >> 56) as u8;
      }
      ks.push(k);
    }
    // r - 1 and r + 1 exercise the reduction.
    let r = hex_conservative::hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    let mut r_minus = r;
    r_minus[31] = 0;
    let mut r_plus = r;
    r_plus[31] = 2;
    ks.extend([r_minus, r_plus]);
    for k in ks {
      let bn = Bn::from_bendian(&k);
      let got = g.mul(&bn);
      assert_eq!(got.coord, Coord::Basic);
      let mut le = bn.mod_r().to_lendian();
      let expect = bg.mul_scalar(&le, 256).to_affine();
      le.fill(0);
      assert_eq!(to_blst(&got), expect, "{k:02x?}");
      // The engine on the PROJC form of the same point agrees.
      let projc = g.dbl().add(&g).add(&g.neg()).add(&g.neg());
      assert!(projc.cmp(&g));
      assert!(projc.mul(&bn).cmp(&got));
    }
    assert_eq!(g.mul(&Bn::from_bendian(&r)), Ep::INFTY);
    assert_eq!(g.mul(&scalar(0)), Ep::INFTY);
    assert_eq!(Ep::INFTY.mul(&scalar(5)), Ep::INFTY);
  }

  #[test]
  fn psi_is_multiplication_by_lambda() {
    // lambda = x² - 1 for x = -0xd201000000010000.
    let lambda = hex_conservative::hex!("00000000000000000000000000000000ac45a4010001a40200000000ffffffff");
    let g = generator();
    assert!(g.psi().cmp(&g.mul(&Bn::from_bendian(&lambda))));
  }

  #[test]
  fn batch_normalization_with_an_infinite_entry_zeroes_the_batch() {
    let g = generator();
    let z = g.add(&g.neg());
    let two = g.dbl();
    let [a, b, c] = Ep::norm_sim([two, z, g]);
    let origin = Ep::affine(Fp::default(), Fp::default(), Coord::Basic);
    assert_eq!(a, origin);
    assert_eq!(b, origin);
    // A BASIC entry keeps x and y and takes the zero inverse as z.
    assert_eq!(c, Ep { z: Fp::default(), ..g });
    assert!(c.is_infty());
  }

  #[test]
  fn write_bin_signs_by_half_p() {
    let g = generator();
    let (x, s) = g.write_bin().unwrap_or_default();
    let (nx, ns) = g.neg().write_bin().unwrap_or_default();
    assert_eq!(x, nx);
    assert_ne!(s, ns);
    assert_eq!(Ep::INFTY.write_bin(), None);
  }
}
