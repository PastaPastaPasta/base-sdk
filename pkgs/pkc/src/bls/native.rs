//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! dashbls's `CoreMPL::NativeVerify` on Core's elements, whatever their
//! class (BS11a-4 D1): blst pairs a chunk whose every point is in the
//! subgroup, and the relic engine any other chunk, whole.

use super::blst_ffi::miller_product;
use super::group::{G1Affine, G2Affine};
use super::relic::ep::Ep;
use super::relic::ep2::Ep2;
use super::relic::{pp, Coord};
use super::scalar::Fp12;
use crate::prelude::*;

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

/// One side of a pair `NativeVerify` pairs.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub(crate) enum Operand<A, E> {
  /// A point in the prime-order subgroup, or the identity, which blst pairs.
  Group(A),
  /// relic's coordinates, which only the engine pairs.
  Engine(E),
}

/// A G1 side.
pub(crate) type G1Operand = Operand<G1Affine, Ep>;
/// A G2 side.
pub(crate) type G2Operand = Operand<G2Affine, Ep2>;

impl<A, E> Operand<A, E> {
  /// Whether the side is a Group point. For a wrapper's element, as
  /// `BlsElem::pairing_operand` gives it, that is dashbls's `IsValid`.
  pub(crate) const fn is_group(&self) -> bool {
    matches!(self, Self::Group(_))
  }
}

impl G1Operand {
  /// The side as relic's coordinates. relic normalizes every point it
  /// pairs, so a Group point's affine coordinates stand for any of its
  /// representations; the identity stays the infinity relic drops.
  fn engine(&self) -> Ep {
    match self {
      Self::Group(a) if a.is_inf() => Ep::INFTY,
      Self::Group(a) => Ep::affine(a.x(), a.y(), Coord::Basic),
      Self::Engine(e) => *e,
    }
  }
}

impl G2Operand {
  /// As [`G1Operand::engine`].
  fn engine(&self) -> Ep2 {
    match self {
      Self::Group(a) if a.is_inf() => Ep2::INFTY,
      Self::Group(a) => Ep2::affine(a.x(), a.y(), Coord::Basic),
      Self::Engine(e) => *e,
    }
  }
}

/// The pairs `NativeVerify` hands to one `pc_map_sim` call
/// (`schemes.cpp:337-341`), kept as Core's structure: the final
/// exponentiation is multiplicative (BS11a-4 D5), so no partition of the
/// pairs changes the product, and the chunk size is not observable.
const CHUNK: usize = 250;

/// One chunk's Miller value: blst's when every pair is Group, otherwise the
/// engine's over the whole chunk (D1).
fn chunk_miller(chunk: &[(G1Operand, G2Operand)]) -> Fp12 {
  let group: Option<Vec<(G1Affine, G2Affine)>> = chunk
    .iter()
    .map(|pair| match pair {
      (Operand::Group(p), Operand::Group(q)) => Some((*p, *q)),
      _ => None,
    })
    .collect();
  match group {
    Some(group) => miller_product(&group),
    None => pp::map_sim(&chunk.iter().map(|(p, q)| (p.engine(), q.engine())).collect::<Vec<_>>()),
  }
}

/// The Miller values of `NativeVerify`'s chunks, multiplied.
fn chunked_miller_product(pairs: &[(G1Operand, G2Operand)]) -> Fp12 {
  pairs
    .chunks(CHUNK)
    .map(chunk_miller)
    .fold(Fp12::one(), |acc, m| acc * m)
}

/// `CoreMPL::NativeVerify` (`schemes.cpp:326-350`): whether the product of
/// `e(g1, g2)` over the pairs is one.
///
/// Core multiplies one relic pairing per chunk, a Miller value raised by
/// `pp_exp_k12`. That exponentiation is a power map, which blst's
/// `blst_final_exp` computes alike on every element, zero included (Lemma E,
/// BS11a-4 D5), so a single one over the product of the chunks' Miller
/// values gives Core's product. relic's pairing sets no error code on any
/// point class (the probe's `pairs` mode checks it), so Core's check of the
/// code never decides.
pub(crate) fn native_verify(pairs: &[(G1Operand, G2Operand)]) -> bool {
  chunked_miller_product(pairs).final_exp().is_one()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bls::group::{Point, G1, G2};
  use crate::bls::scalar::{Fp, Fp2};

  fn g1(v: u64) -> G1Affine {
    G1::generator().mul_scalar(&v.to_le_bytes(), 64).to_affine()
  }

  fn g2(v: u64) -> G2Affine {
    G2::generator().mul_scalar(&v.to_le_bytes(), 64).to_affine()
  }

  /// Subgroup pairs [i + 1]G1, [3i + 2]G2, more than one chunk of them.
  fn group_pairs(n: u64) -> Vec<(G1Operand, G2Operand)> {
    (0..n)
      .map(|i| (Operand::Group(g1(i + 1)), Operand::Group(g2(3 * i + 2))))
      .collect()
  }

  /// Every pair rebuilt into the engine.
  fn as_engine(pairs: &[(G1Operand, G2Operand)]) -> Vec<(G1Operand, G2Operand)> {
    pairs
      .iter()
      .map(|(p, q)| (Operand::Engine(p.engine()), Operand::Engine(q.engine())))
      .collect()
  }

  /// Core's `NativeVerify` product with relic's pairing played by the
  /// engine: per chunk of 250 (`schemes.cpp:337-341`), the Miller value and
  /// its final exponentiation.
  fn cores_product(pairs: &[(G1Operand, G2Operand)]) -> Fp12 {
    pairs.chunks(250).fold(Fp12::one(), |acc, chunk| {
      let chunk: Vec<(Ep, Ep2)> = chunk.iter().map(|(p, q)| (p.engine(), q.engine())).collect();
      acc * pp::map_sim(&chunk).final_exp()
    })
  }

  /// An off-curve G1 point, which only the engine holds.
  fn off_curve() -> G1Operand {
    Operand::Engine(Ep::affine(Fp::from_u64(5), Fp::from_u64(7), Coord::Basic))
  }

  /// BS11a-4 D6, a model check across the 250-pair boundary: the router's
  /// one final exponentiation gives Core's product of per-chunk pairings,
  /// with every chunk on blst, every chunk on the engine, the chunks split
  /// between them, and an Exotic operand sending its chunk to the engine.
  /// The partition is not observable (D5), so this cannot pin [`CHUNK`].
  #[test]
  fn the_router_gives_cores_product_across_chunks() {
    let group = group_pairs(CHUNK as u64 + 3);
    let engine = as_engine(&group);
    let mut mixed = group.clone();
    mixed[CHUNK + 1] = engine[CHUNK + 1];
    let mut exotic = group.clone();
    exotic[CHUNK].0 = off_curve();
    assert!(!cores_product(&group).is_one());
    for pairs in [&group, &engine, &mixed, &exotic, &as_engine(&exotic)] {
      assert_eq!(chunked_miller_product(pairs).final_exp(), cores_product(pairs));
    }
  }

  /// A pair with an infinity side adds nothing, on blst and on the engine,
  /// where blst's identity becomes relic's infinity rather than the
  /// off-curve point (0, 0).
  #[test]
  fn infinity_pairs_add_nothing() {
    assert!(Operand::<G1Affine, Ep>::Group(G1Affine::default()).engine().is_infty());
    assert!(Operand::<G2Affine, Ep2>::Group(G2Affine::default()).engine().is_infty());
    let pairs = group_pairs(3);
    let want = chunked_miller_product(&pairs).final_exp();
    let inf = [
      (Operand::Group(G1Affine::default()), Operand::Group(g2(9))),
      (Operand::Group(g1(9)), Operand::Group(G2Affine::default())),
      (Operand::Engine(Ep::INFTY), Operand::Group(g2(9))),
      (Operand::Group(g1(9)), Operand::Engine(Ep2::INFTY)),
    ];
    for extra in inf {
      let mut with = pairs.clone();
      with.insert(1, extra);
      assert_eq!(chunked_miller_product(&with).final_exp(), want);
      assert_eq!(chunked_miller_product(&as_engine(&with)).final_exp(), want);
    }
    assert!(native_verify(&[]));
    assert!(native_verify(&inf));
  }

  /// A signature check: e(-G1, [k]G2) e([k]G1, G2) is one, on either side,
  /// and stops being one when either point moves.
  #[test]
  fn a_cancelling_product_verifies() {
    let k = 0x5eed;
    let neg = |a: G1Affine| G1Affine::from_coords(a.x(), -a.y());
    let pairs = [
      (Operand::Group(neg(g1(1))), Operand::Group(g2(k))),
      (Operand::Group(g1(k)), Operand::Group(g2(1))),
    ];
    assert!(native_verify(&pairs));
    assert!(native_verify(&as_engine(&pairs)));
    let mut wrong = pairs;
    wrong[1].0 = Operand::Group(g1(k + 1));
    assert!(!native_verify(&wrong));
    wrong[1].0 = off_curve();
    assert!(!native_verify(&wrong));
    let mut y0 = pairs;
    y0[0].1 = Operand::Engine(Ep2::affine(g2(k).x(), Fp2::default(), Coord::Basic));
    assert!(!native_verify(&y0));
  }
}
