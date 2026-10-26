//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! relic's optimal-ate Miller loop at the pin (PP_METHD "LAZYR;OATEP",
//! EP_ADD = PROJC, the B12 branch of `pp_map_sim_oatep_k12`), up to the final
//! exponentiation, which blst computes (design Lemma E, D7).
//!
//! Off the curve or the subgroup, the Miller value depends on relic's chain:
//! which points it doubles and adds, in which coordinates, and where each
//! line lands. Those are ported line by line. The `Fp12` products are exact,
//! so blst forms them: `fp12_mul_dxs` multiplies by a line whose other slots
//! are zero, which is the full product with that line.
//!
//! BLS12-381's twist is an M-type one, so both line functions write slots
//! `[0][0]`, `[0][1]` and `[1][1]`, the ones `fp12_mul_dxs_lazyr` reads
//! (`relic_fp12_mul.c:320-420`); the shared line buffer never holds anything
//! else.

use super::super::scalar::{Fp, Fp12, Fp2};
use super::ep::Ep;
use super::ep2::Ep2;
use super::field::TWIST_B;
use super::recode::{self, Bn, X_ABS};
use super::Coord;
use crate::prelude::*;

/// `a` times an element of the base field, relic's pair of `fp_mul`s on the
/// two coefficients.
fn scale(a: Fp2, k: Fp) -> Fp2 {
  Fp2::new(a.c0() * k, a.c1() * k)
}

/// `pp_dbl_k12_projc_lazyr` (`relic_pp_dbl_k12.c:237-399`), the general-b
/// branch (b = 4 is `RLC_TINY`), M-type slots: doubles `t` in projective
/// coordinates and writes the tangent line at `p` into `l`. `p` is
/// `pp_mil_k12`'s `_p`, (3x_P, -y_P).
fn dbl(l: &mut Fp12, t: &mut Ep2, p: &Ep) {
  let a = t.x.square();
  let b = t.y.square();
  let c = t.z.square();
  let d = (c + c + c) * TWIST_B;
  let e = (t.x + t.y).square() - a - b;
  let f = (t.y + t.z).square() - b - c;
  let g = d + d + d;

  let x3 = e * (b - g);
  let d2 = d.square();
  let three_d2 = d2 + d2 + d2;
  let y3 = (b + g).square() - (three_d2 + three_d2 + three_d2 + three_d2);
  let z3 = (b + b + b + b) * f;

  l.set_coeff(0, 0, d - b);
  l.set_coeff(0, 1, scale(a, p.x));
  l.set_coeff(1, 1, scale(f, p.y));
  *t = Ep2 {
    x: x3,
    y: y3,
    z: z3,
    coord: Coord::Projc,
  };
}

/// `pp_add_k12_projc_lazyr` (`relic_pp_add_k12.c:173-255`), M-type slots:
/// adds the affine `q` to `t` and writes the line through them at `p` into
/// `l`.
fn add(l: &mut Fp12, t: &mut Ep2, q: &Ep2, p: &Ep) {
  let t0 = t.x - t.z * q.x;
  let t1 = t.y - t.z * q.y;
  let t0_2 = t0.square();
  let x1 = t0_2 * t.x;
  let t0_3 = t0 * t0_2;
  let t3 = t0_3 + t1.square() * t.z - x1 - x1;
  let x2 = x1 - t3;

  let y3 = t1 * x2 - t0_3 * t.y;
  let x3 = t0 * t3;
  let z3 = t.z * t0_3;

  l.set_coeff(0, 1, scale(t1, -p.x));
  l.set_coeff(0, 0, q.x * t1 - q.y * t0);
  l.set_coeff(1, 1, scale(t0, p.y));
  *t = Ep2 {
    x: x3,
    y: y3,
    z: z3,
    coord: Coord::Projc,
  };
}

/// `pp_mil_k12` (`relic_pp_map_k12.c:51-133`) over non-empty normalized
/// pairs: the simultaneous Miller loop over the width-2 NAF of |x|. The
/// first doubling's line is written into `r`, which holds one; its slot
/// `[0][0]` is among those written, so `r` becomes that line. relic then adds
/// when the NAF's second digit is non-zero; for BLS12-381's x it is zero, so
/// that step is not ported (`x_naf_has_a_zero_second_digit`).
fn mil(pairs: &[(Ep, Ep2)]) -> Fp12 {
  let s = recode::rec_naf(&Bn::pos(&[X_ABS]), 2);
  let mut t: Vec<Ep2> = pairs.iter().map(|&(_, q)| q).collect();
  // EP_ADD = PROJC: _p = (3x, -y), z untouched.
  let tripled: Vec<Ep> = pairs
    .iter()
    .map(|(p, _)| Ep {
      x: p.x + p.x + p.x,
      y: -p.y,
      ..*p
    })
    .collect();

  let mut r = Fp12::one();
  let mut l = Fp12::ZERO;
  dbl(&mut r, &mut t[0], &tripled[0]);
  for j in 1..pairs.len() {
    dbl(&mut l, &mut t[j], &tripled[j]);
    r = r * l;
  }

  for &digit in s[..s.len() - 2].iter().rev() {
    r = r.square();
    for (j, (p, q)) in pairs.iter().enumerate() {
      dbl(&mut l, &mut t[j], &tripled[j]);
      r = r * l;
      if digit > 0 {
        add(&mut l, &mut t[j], q, p);
        r = r * l;
      }
      if digit < 0 {
        add(&mut l, &mut t[j], &q.neg(), p);
        r = r * l;
      }
    }
  }
  r
}

/// `pp_map_sim_oatep_k12` (`relic_pp_map_k12.c:523-599`, `EP_B12`) up to its
/// final `pp_exp_k12`: pairs with an infinity side are dropped and the rest
/// normalized; with none left the value is one. x < 0, so the Miller value
/// is conjugated (`fp12_inv_cyc`).
///
/// It is checked against relic only after the final exponentiation, so use
/// it only through [`Fp12::final_exp`] of a product of such values (zero
/// stays zero).
pub(crate) fn map_sim(pairs: &[(Ep, Ep2)]) -> Fp12 {
  let kept: Vec<(Ep, Ep2)> = pairs
    .iter()
    .filter(|(p, q)| !p.is_infty() && !q.is_infty())
    .map(|(p, q)| (p.norm(), q.norm()))
    .collect();
  if kept.is_empty() {
    return Fp12::one();
  }
  mil(&kept).conjugate()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bls::blst_ffi::miller_loop;
  use crate::bls::group::{G1Affine, G2Affine, Point, G1, G2};

  fn g1_affine(v: u64) -> G1Affine {
    G1::generator().mul_scalar(&v.to_le_bytes(), 64).to_affine()
  }

  fn g2_affine(v: u64) -> G2Affine {
    G2::generator().mul_scalar(&v.to_le_bytes(), 64).to_affine()
  }

  fn g1(v: u64) -> Ep {
    let a = g1_affine(v);
    Ep::affine(a.x(), a.y(), Coord::Basic)
  }

  fn g2(v: u64) -> Ep2 {
    let a = g2_affine(v);
    Ep2::affine(a.x(), a.y(), Coord::Basic)
  }

  /// blst's Miller value for subgroup pairs [a]G1, [b]G2.
  fn blst_mil(pairs: &[(u64, u64)]) -> Fp12 {
    pairs.iter().fold(Fp12::one(), |acc, &(a, b)| {
      acc * miller_loop(&g1_affine(a), &g2_affine(b))
    })
  }

  /// The engine's Miller value for the same pairs.
  fn engine_mil(pairs: &[(u64, u64)]) -> Fp12 {
    let pairs: Vec<(Ep, Ep2)> = pairs.iter().map(|&(a, b)| (g1(a), g2(b))).collect();
    map_sim(&pairs)
  }

  /// Lemma U: on subgroup pairs the engine's Miller value and blst's give
  /// the same pairing after the final exponentiation, so chunks of either
  /// kind multiply into one product (BS11a-4 D1, D6).
  #[test]
  fn engine_and_blst_miller_values_agree_after_the_final_exponentiation() {
    for pairs in [&[(1, 1)][..], &[(7, 11)], &[(3, 5), (1 << 40, 9), (12345, 1)]] {
      let e = engine_mil(pairs);
      let b = blst_mil(pairs);
      assert!(!e.final_exp().is_one());
      assert!((e * b.conjugate()).final_exp().is_one());
    }
  }

  /// relic's addition after the first doubling runs only for a non-zero
  /// second NAF digit, which BLS12-381's |x| = 0xd201000000010000 lacks: its
  /// top digits are 1, 0, -1 (13 = 16 - 4 + 1).
  #[test]
  fn x_naf_has_a_zero_second_digit() {
    let s = recode::rec_naf(&Bn::pos(&[X_ABS]), 2);
    assert_eq!(s[s.len() - 3..], [-1, 0, 1]);
  }

  /// Bilinearity through the engine alone: e(aP, bQ) e(-abP, Q) = 1.
  #[test]
  fn the_engine_pairing_is_bilinear() {
    let pairs = [(g1(6), g2(7)), (g1(42).neg(), g2(1))];
    assert!(map_sim(&pairs).final_exp().is_one());
    let pairs = [(g1(6), g2(7)), (g1(41).neg(), g2(1))];
    assert!(!map_sim(&pairs).final_exp().is_one());
  }

  /// A model check of the port, not of relic.
  #[test]
  fn infinity_pairs_are_dropped_and_none_left_gives_one() {
    assert_eq!(map_sim(&[]), Fp12::one());
    assert_eq!(map_sim(&[(Ep::INFTY, g2(3)), (g1(2), Ep2::INFTY)]), Fp12::one());
    let one_pair = map_sim(&[(g1(2), g2(3))]);
    assert_eq!(map_sim(&[(Ep::INFTY, g2(5)), (g1(2), g2(3))]), one_pair);
  }

  /// The inputs are normalized, so a projective representation gives the
  /// affine point's value exactly. A model check of the port, not of relic.
  #[test]
  fn projective_inputs_are_normalized() {
    let (p, q) = (g1(2), g2(3));
    let lambda = Fp::from_u64(7);
    let l = Fp2::from(lambda);
    let l2 = l.square();
    let pp = Ep {
      x: p.x * lambda,
      y: p.y * lambda,
      z: lambda,
      coord: Coord::Projc,
    };
    let qq = Ep2 {
      x: q.x * l2,
      y: q.y * l2 * l,
      z: l,
      coord: Coord::Projc,
    };
    assert_eq!(map_sim(&[(pp, qq)]), map_sim(&[(p, q)]));
  }
}
