//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! relic's G2, `ep2_*` at the pin: Jacobian coordinates under the `PROJC`
//! tag (EP_ADD = PROJC, EP_MIXED), and four-way GLS multiplication over the
//! Frobenius (EP_MUL = LWNAF, EP_ENDOM).
//!
//! As in [`super::ep`], each function keeps relic's branches on the tag and
//! on zero, so it computes Core's result on and off the curve.

use super::super::scalar::Fp2;
use super::field::{self, EP2_FRB, ONE};
use super::recode::{self, Bn};
use super::Coord;

use crate::prelude::*;

/// A relic `ep2_t`: x, y, z and the coord tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ep2 {
  pub(crate) x: Fp2,
  pub(crate) y: Fp2,
  pub(crate) z: Fp2,
  pub(crate) coord: Coord,
}

fn dbl2(a: Fp2) -> Fp2 {
  a + a
}

impl Ep2 {
  /// `ep2_set_infty` (`relic_ep2_util.c:43-48`): (0, 0, 0), `BASIC`.
  pub(crate) const INFTY: Self = Self {
    x: field::fp2([0; 6], [0; 6]),
    y: field::fp2([0; 6], [0; 6]),
    z: field::fp2([0; 6], [0; 6]),
    coord: Coord::Basic,
  };

  /// An affine point, (x, y, 1) with tag `coord`.
  pub(crate) fn affine(x: Fp2, y: Fp2, coord: Coord) -> Self {
    Self {
      x,
      y,
      z: Fp2::from(ONE),
      coord,
    }
  }

  /// `ep2_is_infty` (`relic_ep2_util.c:39-41`): z = 0.
  pub(crate) fn is_infty(&self) -> bool {
    self.z.is_zero()
  }

  /// `ep2_add_projc` (`relic_ep2_add.c:390-407`): an infinite operand gives
  /// a copy of the other. Its `p == q` pointer test, which doubles, gives
  /// what the formulas give for equal operands, and no caller here passes
  /// one object twice.
  pub(crate) fn add(&self, q: &Self) -> Self {
    if self.is_infty() {
      *q
    } else if q.is_infty() {
      *self
    } else if q.coord == Coord::Basic {
      self.add_mix(q)
    } else {
      self.add_imp(q)
    }
  }

  /// `ep2_add_projc_mix` (`relic_ep2_add.c:127-210`): madd with R = S2 - y1,
  /// not doubled. H = 0 doubles p when R = 0 and gives `set_infty`
  /// otherwise; every branch ends tagged `PROJC`, the infinity included.
  fn add_mix(&self, q: &Self) -> Self {
    let p = self;
    let (h, r) = if p.coord == Coord::Basic {
      (q.x - p.x, q.y - p.y)
    } else {
      let zz = p.z.square();
      (q.x * zz - p.x, zz * p.z * q.y - p.y)
    };
    let out = if h.is_zero() {
      if r.is_zero() {
        p.dbl()
      } else {
        Self::INFTY
      }
    } else {
      let hh = h.square();
      let j = h * hh;
      let v = p.x * hh;
      let x = r.square() - j - dbl2(v);
      Self {
        x,
        y: (v - x) * r - p.y * j,
        z: if p.coord == Coord::Basic { h } else { p.z * h },
        coord: Coord::Projc,
      }
    };
    Self {
      coord: Coord::Projc,
      ..out
    }
  }

  /// `ep2_add_projc_imp`'s general formulas (`relic_ep2_add.c:236-333`),
  /// add-2007-bl, with the same H = 0 branches.
  fn add_imp(&self, q: &Self) -> Self {
    let p = self;
    let z1z1 = p.z.square();
    let z2z2 = q.z.square();
    let u1 = p.x * z2z2;
    let u2 = q.x * z1z1;
    let s1 = z2z2 * q.z * p.y;
    let s2 = z1z1 * p.z * q.y;
    let h = u2 - u1;
    let r = dbl2(s2 - s1);
    let out = if h.is_zero() {
      if r.is_zero() {
        p.dbl()
      } else {
        Self::INFTY
      }
    } else {
      let i = dbl2(h).square();
      let j = h * i;
      let v = u1 * i;
      let x = r.square() - j - dbl2(v);
      Self {
        x,
        y: (v - x) * r - dbl2(s1 * j),
        z: ((p.z + q.z).square() - (z1z1 + z2z2)) * h,
        coord: Coord::Projc,
      }
    };
    Self {
      coord: Coord::Projc,
      ..out
    }
  }

  /// `ep2_sub` (`relic_ep2_add.c:412-430`): p + (-q).
  pub(crate) fn sub(&self, q: &Self) -> Self {
    self.add(&q.neg())
  }

  /// `ep2_dbl_projc` (`relic_ep2_dbl.c:119-150`, the a = 0 formulas): z is
  /// read whatever the tag.
  pub(crate) fn dbl(&self) -> Self {
    let p = self;
    if p.is_infty() {
      return Self::INFTY;
    }
    let xx = p.x.square();
    let m = dbl2(xx) + xx;
    let yy = p.y.square();
    let s = dbl2(dbl2(yy * p.x));
    let x = m.square() - dbl2(s);
    Self {
      x,
      y: m * (s - x) - dbl2(dbl2(yy).square()),
      z: dbl2(p.z * p.y),
      coord: Coord::Projc,
    }
  }

  /// `ep2_neg` (`relic_ep2_neg.c:39-52`): infinity becomes `set_infty`,
  /// otherwise y is negated and the tag kept.
  pub(crate) fn neg(&self) -> Self {
    if self.is_infty() {
      Self::INFTY
    } else {
      Self { y: -self.y, ..*self }
    }
  }

  /// `ep2_norm` (`relic_ep2_norm.c`): infinity becomes `set_infty`, a
  /// `BASIC` point is copied, and a `PROJC` one becomes (x/z², y/z³, 1).
  pub(crate) fn norm(&self) -> Self {
    if self.is_infty() {
      Self::INFTY
    } else if self.coord == Coord::Basic {
      *self
    } else {
      let zi = field::inv2(self.z);
      let zi2 = zi.square();
      Self::affine(self.x * zi2, self.y * zi2 * zi, Coord::Basic)
    }
  }

  /// `ep2_frb(r, p, 1)` (`relic_ep2_frb.c:38-48`): conjugate every
  /// coordinate, then scale x and y by the twist constants; tag kept.
  fn frb(&self) -> Self {
    Self {
      x: field::conj(self.x) * EP2_FRB[0],
      y: field::conj(self.y) * EP2_FRB[1],
      z: field::conj(self.z),
      coord: self.coord,
    }
  }

  /// `g2_mul` (`relic_pc_exp.c:90-118`) for a non-negative scalar: up to 64
  /// bits `ep2_mul_dig`, otherwise `ep2_mul_lwnaf` of k mod r.
  pub(crate) fn mul(&self, k: &Bn) -> Self {
    if k.bits() <= 64 {
      self.mul_dig(k.low())
    } else {
      self.mul_lwnaf(&k.mod_r())
    }
  }

  /// `ep2_mul_dig` (`relic_ep2_mul.c:385-420`).
  fn mul_dig(&self, k: u64) -> Self {
    if k == 0 || self.is_infty() {
      return Self::INFTY;
    }
    let mut kb = [0u8; 32];
    kb[24..].copy_from_slice(&k.to_be_bytes());
    let naf = recode::rec_naf(&Bn::from_bendian(&kb), 2);
    let mut t = Self::INFTY;
    for &u in naf.iter().rev() {
      t = t.dbl();
      if u > 0 {
        t = t.add(self);
      } else if u < 0 {
        t = t.sub(self);
      }
    }
    t.norm()
  }

  /// `ep2_mul_lwnaf` (`relic_ep2_mul.c:332-356`): zero or an infinite
  /// point gives `set_infty`, otherwise the GLS path (a = 0).
  fn mul_lwnaf(&self, k: &Bn) -> Self {
    if k.is_zero() || self.is_infty() {
      Self::INFTY
    } else {
      self.mul_glv(k)
    }
  }

  /// `ep2_mul_glv_imp` (`relic_ep2_mul.c:43-110`): k's base-|x| digits
  /// against p and its Frobenius images, each negated with its digit, by
  /// interleaved width-2 NAFs.
  fn mul_glv(&self, k: &Bn) -> Self {
    let digits = recode::rec_frb(k);
    let q0 = self.norm();
    let q1 = q0.frb();
    let q2 = q1.frb();
    let q3 = q2.frb();
    let q = [q0, q1, q2, q3];
    let q: [Self; 4] = core::array::from_fn(|i| if digits[i].is_neg() { q[i].neg() } else { q[i] });
    let naf = digits.map(|d| recode::rec_naf(&d, 2));
    let len = naf.iter().map(Vec::len).max().unwrap_or(0);
    let mut r = Self::INFTY;
    for j in (0..len).rev() {
      r = r.dbl();
      for (n, qi) in naf.iter().zip(&q) {
        match n.get(j).copied().unwrap_or(0) {
          d if d > 0 => r = r.add(qi),
          d if d < 0 => r = r.sub(qi),
          _ => {}
        }
      }
    }
    r.norm()
  }

  /// `ep2_cmp` (`relic_ep2_cmp.c:38-82`): two infinities are equal. When
  /// both tags are `PROJC` the Jacobian cross-products are compared, so a
  /// `PROJC` infinity (z = 0) equals every `PROJC` point; otherwise both
  /// sides are normalized first.
  pub(crate) fn cmp(&self, q: &Self) -> bool {
    if self.is_infty() && q.is_infty() {
      return true;
    }
    if self.coord != Coord::Basic && q.coord != Coord::Basic {
      let (pz2, qz2) = (self.z.square(), q.z.square());
      self.x * qz2 == q.x * pz2 && self.y * qz2 * q.z == q.y * pz2 * self.z
    } else {
      let (r, s) = (self.norm(), q.norm());
      r.x == s.x && r.y == s.y
    }
  }

  /// `ep2_write_bin(..., pack = 1)`'s content (`relic_ep2_util.c`,
  /// `ep2_pck`): `None` for infinity, else the normalized x and the sign of
  /// y's `c1` alone.
  pub(crate) fn write_bin(&self) -> Option<(Fp2, bool)> {
    if self.is_infty() {
      return None;
    }
    let t = self.norm();
    Some((t.x, field::sign(t.y.c1())))
  }
}

#[cfg(test)]
mod tests {
  use super::super::super::group::Point as _;
  use super::super::super::group::{G2Affine, G2};
  use super::*;

  fn generator() -> Ep2 {
    let g = G2::generator().to_affine();
    Ep2::affine(g.x(), g.y(), Coord::Basic)
  }

  fn to_blst(p: &Ep2) -> G2Affine {
    let n = p.norm();
    if n.is_infty() {
      G2Affine::default()
    } else {
      G2Affine::from_coords(n.x, n.y)
    }
  }

  fn scalar(k: u64) -> Bn {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&k.to_be_bytes());
    Bn::from_bendian(&b)
  }

  #[test]
  fn add_and_dbl_agree_with_blst_on_the_subgroup() {
    let g = generator();
    let bg = G2::generator();
    let two = g.dbl();
    assert_eq!(to_blst(&two), bg.double().to_affine());
    let three = two.add(&g);
    assert_eq!(three.coord, Coord::Projc);
    assert_eq!(to_blst(&three), bg.mul_scalar(&[3], 8).to_affine());
    let five = three.add(&two);
    assert_eq!(to_blst(&five), bg.mul_scalar(&[5], 8).to_affine());
    // Equal operands double, through both formulas.
    assert!(g.add(&g).cmp(&two));
    assert!(three.add(&three).cmp(&three.dbl()));
  }

  #[test]
  fn infinity_shapes_follow_relic() {
    let g = generator();
    // P + (-P) is set_infty, then tagged PROJC.
    let z = g.add(&g.neg());
    assert_eq!(
      z,
      Ep2 {
        coord: Coord::Projc,
        ..Ep2::INFTY
      }
    );
    let three = g.dbl().add(&g);
    let w = three.add(&three.neg());
    assert_eq!(w, z);
    // A PROJC infinity equals every PROJC point (relic_ep2_cmp.c:51-63)
    // and no finite BASIC one.
    assert!(z.cmp(&three) && three.cmp(&z));
    assert!(!z.cmp(&g) && !g.cmp(&z));
    assert!(z.cmp(&Ep2::INFTY));
    assert_eq!(z.neg(), Ep2::INFTY);
  }

  #[test]
  fn frobenius_is_multiplication_by_p_on_the_subgroup() {
    // psi acts on G2 as multiplication by p mod r, here x mod r for x the
    // BLS parameter, -0xd201000000010000 = r - 0xd201000000010000 mod r.
    let g = generator();
    let r = hex_conservative::hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    let mut x_mod_r = r;
    let x: u128 = 0xd201_0000_0001_0000;
    let low = u128::from_be_bytes(x_mod_r[16..].try_into().unwrap_or_default()) - x;
    x_mod_r[16..].copy_from_slice(&low.to_be_bytes());
    assert!(g.frb().cmp(&g.mul(&Bn::from_bendian(&x_mod_r))));
  }

  #[test]
  fn multiplication_agrees_with_blst_on_the_subgroup() {
    let g = generator();
    let bg = G2::generator();
    let mut ks: Vec<[u8; 32]> = Vec::new();
    for k in [1u64, 2, 3, 0xd201_0000_0001_0000, u64::MAX] {
      let mut b = [0u8; 32];
      b[24..].copy_from_slice(&k.to_be_bytes());
      ks.push(b);
    }
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    for _ in 0..12 {
      let mut k = [0u8; 32];
      for b in k.iter_mut() {
        seed = seed
          .wrapping_mul(6_364_136_223_846_793_005)
          .wrapping_add(1_442_695_040_888_963_407);
        *b = (seed >> 56) as u8;
      }
      ks.push(k);
    }
    let projc = g.dbl().add(&g).add(&g.neg()).add(&g.neg());
    assert!(projc.cmp(&g));
    for k in ks {
      let bn = Bn::from_bendian(&k);
      let got = g.mul(&bn);
      assert_eq!(got.coord, Coord::Basic);
      let expect = bg.mul_scalar(&bn.mod_r().to_lendian(), 256).to_affine();
      assert_eq!(to_blst(&got), expect, "{k:02x?}");
      assert_eq!(projc.mul(&bn), got);
    }
    assert_eq!(g.mul(&scalar(0)), Ep2::INFTY);
    assert_eq!(Ep2::INFTY.mul(&scalar(9)), Ep2::INFTY);
  }

  #[test]
  fn write_bin_signs_by_c1() {
    let g = generator();
    let (x, s) = g.write_bin().unwrap_or_default();
    let (nx, ns) = g.neg().write_bin().unwrap_or_default();
    assert_eq!(x, nx);
    assert_ne!(s, ns);
    // y with c1 = 0 has sign 0 either way.
    let real = Ep2::affine(g.x, g.y.with_c1(Default::default()), Coord::Basic);
    assert_eq!(real.write_bin().map(|(_, s)| s), Some(false));
    assert_eq!(real.neg().write_bin().map(|(_, s)| s), Some(false));
  }
}
