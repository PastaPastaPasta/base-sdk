//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Core's group elements as its arithmetic computes with them: dashbls's
//! `G1Element` and `G2Element`, apart from the wrapper's validity.
//!
//! A value is either a Group value, which blst computes, carried with the
//! coord tag Core's relic would give it, or an engine value with relic's
//! own coordinates (design §3.1, D27, Lemma T'). An operation stays on blst
//! while every operand is a Group value; otherwise each Group operand is
//! rebuilt into the engine, and the result keeps the engine's coordinates
//! even when it lands in the subgroup.

use super::blst_ffi;
use super::group::{G1Affine, G2Affine, Point, G1, G2};
use super::relic::ep::Ep;
use super::relic::ep2::Ep2;
use super::relic::{Bn, Coord};
use super::scalar::{Fp, Fp2, FR_BITS};
use super::scheme_ctx::BlsSchemeKind;
use super::wrap_codec::{BlsPoint, BlsRepr, BlsWire, BlsWirePoint, COORD_MASK, FLAG_HIGH, FLAG_SIGN};
use super::wrap_value::BlsValue;
use super::{BLS_PK_LEN, BLS_SIG_LEN};
use crate::prelude::*;

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use zeroize::Zeroize;

use core::fmt::{self, Debug, Formatter};

/// How [`BlsElem`] holds an element.
#[doc(hidden)]
#[derive(Clone, Debug)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub enum BlsArith<P, E> {
  /// A point in the prime-order subgroup, computed by blst, with the coord
  /// tag Core's relic gives it; a `PROJC` identity is the infinity
  /// P + (-P) leaves.
  Group { point: P, tag: Coord },
  /// relic's coordinates.
  Relic(E),
}

/// relic's shape of an element, which the model target compares across the
/// two representations (BS11a-3 D18): the coord tag and which of x, y and
/// z are zero.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsShape {
  /// Whether the tag is `PROJC`.
  pub projc: bool,
  /// Whether x, y and z are zero.
  pub zero: [bool; 3],
}

/// A G1 or G2 element as Core's dashbls holds it, the `impl` of a wrapper.
///
/// Its operations are dashbls's operators: [`Self::add`] is `operator+`,
/// [`Self::neg`] is `Negate`, [`Self::mul`] is `operator*` by a scalar,
/// [`Self::core_eq`] is `operator==` and [`Self::is_valid`] is `IsValid`.
/// They give Core's result on every element, including those off the
/// curve or outside the subgroup that legacy decoding admits.
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsElem<K: BlsWirePoint<N>, const N: usize>(K::Arith);

impl BlsElem<G1, BLS_PK_LEN> {
  /// `*this * k` for a secret key's stored bytes, at most `r`: blst's
  /// constant-time multiplication on a Group element, where it gives
  /// [`Self::mul`]'s element, and the engine (variable-time, as relic is in
  /// Core) on an engine one.
  pub(crate) fn mul_secret(&self, k: &[u8; 32]) -> Self {
    match &self.0 {
      BlsArith::Group { point, .. } => {
        let mut scalar = blst_ffi::scalar_from_bendian(k);
        let product = point.mul_scalar(&scalar.b, FR_BITS);
        scalar.b.zeroize();
        Self::group(product, Coord::Basic)
      }
      BlsArith::Relic(e) => {
        let mut k = Bn::from_bendian(k);
        let product = e.mul(&k);
        k.wipe();
        Self(BlsArith::Relic(product))
      }
    }
  }

  /// The basic serialization of a [`Self::mul_secret`] product: blst's
  /// constant-time compression on a Group element, which writes the same
  /// bytes, and the engine's on an engine one.
  pub(crate) fn secret_basic(&self) -> [u8; BLS_PK_LEN] {
    match &self.0 {
      BlsArith::Group { point, .. } => point.to_affine().compress(),
      BlsArith::Relic(_) => self.to_bytes(BlsSchemeKind::Basic),
    }
  }

  /// The wrapper `DHKeyExchange` leaves (`bls.cpp:208-220`) for a secret
  /// key's stored bytes `k`, at most `r` as [`Self::mul_secret`] needs:
  /// that product with [`Self::secret_basic`]'s bytes, so that on a Group
  /// element only blst's constant-time code sees the secret multiple.
  /// [`Self::mul`] and the `From` conversion are for public scalars
  /// (BS11a-3 D34).
  pub(crate) fn mul_secret_value(&self, k: &[u8; 32]) -> BlsValue<G1, BLS_PK_LEN> {
    let product = self.mul_secret(k);
    let basic = product.secret_basic();
    product.into_value(basic)
  }
}

impl<K: BlsWirePoint<N>, const N: usize> Clone for BlsElem<K, N> {
  fn clone(&self) -> Self {
    Self(self.0.clone())
  }
}

impl<K: BlsWirePoint<N>, const N: usize> Debug for BlsElem<K, N> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "BlsElem({:?})", self.0)
  }
}

/// The scale Lemma T' rebuilds a `PROJC` Group value with: one, or a
/// nonzero value the model target picks.
fn scale(lambda: u64) -> Fp {
  Fp::from_u64(lambda.max(1))
}

/// Lemma C: an Exotic G1 value as relic decoded it, from its basic bytes.
/// Off the curve, y is the sign bit as a raw Montgomery digit; the points
/// of order 3, (0, ±2), take their true y.
fn g1_exotic(basic: &[u8; BLS_PK_LEN]) -> Ep {
  let mut xb = *basic;
  xb[0] &= COORD_MASK;
  let x = Fp::from(&xb);
  let sign = basic[0] & FLAG_SIGN != 0;
  let y = if x == Fp::default() {
    let two = Fp::from_u64(2);
    if sign {
      -two
    } else {
      two
    }
  } else {
    Fp::from_raw_limbs([u64::from(sign), 0, 0, 0, 0, 0])
  };
  Ep::affine(x, y, Coord::Basic)
}

/// Lemma C for G2: off the curve relic leaves y = (0, 0).
fn g2_exotic(basic: &[u8; BLS_SIG_LEN]) -> Ep2 {
  let mut c1 = [0u8; 48];
  let mut c0 = [0u8; 48];
  c1.copy_from_slice(&basic[..48]);
  c0.copy_from_slice(&basic[48..]);
  c1[0] &= COORD_MASK;
  Ep2::affine(Fp2::new(Fp::from(&c0), Fp::from(&c1)), Fp2::default(), Coord::Basic)
}

/// Lemma T': a Group G1 value as relic's coordinates, a `PROJC` one scaled
/// by lambda. The `PROJC` infinity is (0, lambda, 0).
fn g1_rebuild(point: &G1, tag: Coord, lambda: u64) -> Ep {
  let l = scale(lambda);
  let a = point.to_affine();
  match (a.is_inf(), tag) {
    (true, Coord::Basic) => Ep::INFTY,
    (true, Coord::Projc) => Ep {
      x: Fp::default(),
      y: l,
      z: Fp::default(),
      coord: Coord::Projc,
    },
    (false, Coord::Basic) => Ep::affine(a.x(), a.y(), Coord::Basic),
    (false, Coord::Projc) => Ep {
      x: a.x() * l,
      y: a.y() * l,
      z: l,
      coord: Coord::Projc,
    },
  }
}

/// Lemma T' for G2, Jacobian: (lambda² x, lambda³ y, lambda); the `PROJC`
/// infinity is (0, 0, 0).
fn g2_rebuild(point: &G2, tag: Coord, lambda: u64) -> Ep2 {
  let l = Fp2::from(scale(lambda));
  let a = point.to_affine();
  match (a.is_inf(), tag) {
    (true, Coord::Basic) => Ep2::INFTY,
    (true, Coord::Projc) => Ep2 {
      coord: Coord::Projc,
      ..Ep2::INFTY
    },
    (false, Coord::Basic) => Ep2::affine(a.x(), a.y(), Coord::Basic),
    (false, Coord::Projc) => Ep2 {
      x: a.x() * l.square(),
      y: a.y() * l.square() * l,
      z: l,
      coord: Coord::Projc,
    },
  }
}

/// dashbls's basic `SerializeToArray` of a written G1 point
/// (`elements.cpp:178-198`): x with the compression flag and the sign.
fn g1_basic(written: Option<(Fp, bool)>) -> [u8; BLS_PK_LEN] {
  written.map_or_else(
    || G1::default_element().0,
    |(x, sign)| {
      let mut out = <[u8; 48]>::from(x);
      out[0] |= FLAG_HIGH | if sign { FLAG_SIGN } else { 0 };
      out
    },
  )
}

/// dashbls's basic `SerializeToArray` of a written G2 point
/// (`elements.cpp:400-436`): c1 then c0, the flags on c1's first byte.
fn g2_basic(written: Option<(Fp2, bool)>) -> [u8; BLS_SIG_LEN] {
  written.map_or_else(
    || G2::default_element().0,
    |(x, sign)| {
      let mut out = [0u8; BLS_SIG_LEN];
      out[..48].copy_from_slice(&<[u8; 48]>::from(x.c1()));
      out[48..].copy_from_slice(&<[u8; 48]>::from(x.c0()));
      out[0] |= FLAG_HIGH | if sign { FLAG_SIGN } else { 0 };
      out
    },
  )
}

/// The point an engine G1 value holds once normalized, as legacy decoding
/// would classify it: the curve's points but those of order 3 are
/// `OnCurve`, the rest `Exotic`. blst's affine identity is (0, 0), so a
/// finite (0, 0) is classified by hand.
fn g1_point(e: &Ep) -> BlsPoint<G1Affine> {
  if e.is_infty() {
    return BlsPoint::OnCurve(G1Affine::default());
  }
  let n = e.norm();
  let a = G1Affine::from_coords(n.x, n.y);
  if n.x != Fp::default() && a.on_curve() {
    BlsPoint::OnCurve(a)
  } else {
    BlsPoint::Exotic
  }
}

/// As [`g1_point`], for G2.
fn g2_point(e: &Ep2) -> BlsPoint<G2Affine> {
  if e.is_infty() {
    return BlsPoint::OnCurve(G2Affine::default());
  }
  let n = e.norm();
  let a = G2Affine::from_coords(n.x, n.y);
  if !(n.x.is_zero() && n.y.is_zero()) && a.on_curve() {
    BlsPoint::OnCurve(a)
  } else {
    BlsPoint::Exotic
  }
}

/// Group-against-Group `g1_cmp` is group equality (design §3.1).
fn g1_group_eq(p: &G1, _tp: Coord, q: &G1, _tq: Coord) -> bool {
  p.is_equal(q)
}

/// Group-against-Group `g2_cmp`: group equality, except that two `PROJC`
/// operands are compared by Jacobian cross-products, so a `PROJC` infinity
/// equals every `PROJC` value (`relic_ep2_cmp.c:51-63`; BS11a-3 D24).
fn g2_group_eq(p: &G2, tp: Coord, q: &G2, tq: Coord) -> bool {
  (tp == Coord::Projc && tq == Coord::Projc && (p.is_inf() || q.is_inf())) || p.is_equal(q)
}

/// Implements [`BlsElem`] and its conversions for one group.
macro_rules! impl_elem {
  (
    $group:ty, $affine:ty, $engine:ty, $len:expr,
    exotic: $exotic:ident, rebuild: $rebuild:ident, basic: $basic:ident,
    point: $point:ident, group_eq: $group_eq:ident $(,)?
  ) => {
    impl Default for BlsElem<$group, $len> {
      /// Core's default element, `set_infty`: (0, 0, 0), `BASIC`.
      fn default() -> Self {
        Self::group(<$group>::default(), Coord::Basic)
      }
    }

    impl BlsElem<$group, $len> {
      fn group(point: $group, tag: Coord) -> Self {
        Self(BlsArith::Group { point, tag })
      }

      /// relic's coordinates for the element; a Group value is rebuilt by
      /// Lemma T'.
      fn engine(&self, lambda: u64) -> $engine {
        match &self.0 {
          BlsArith::Group { point, tag } => $rebuild(point, *tag, lambda),
          BlsArith::Relic(e) => *e,
        }
      }

      /// A wrapper's element whatever its validity, Core's `impl`
      /// (design D66, BS11a-3 D8). A legacy-decoded point on the curve runs
      /// the subgroup test here, once.
      pub fn from_impl(value: &BlsValue<$group, $len>) -> Self {
        let (basic, point, repr) = value.parts();
        let tag = match repr {
          BlsRepr::Relic(e) => return Self(BlsArith::Relic(**e)),
          BlsRepr::Basic => Coord::Basic,
          BlsRepr::Projc => Coord::Projc,
        };
        match point {
          BlsPoint::Usable(a) => Self::group(a.to_projective(), tag),
          BlsPoint::OnCurve(a) => {
            let p = a.to_projective();
            if p.in_subgroup() {
              Self::group(p, tag)
            } else {
              Self(BlsArith::Relic(<$engine>::affine(a.x(), a.y(), tag)))
            }
          }
          BlsPoint::Exotic => Self(BlsArith::Relic($exotic(basic))),
        }
      }

      /// `operator+` (`g*_add`). An infinite operand gives the other
      /// operand, tag included; two finite Group values give a `PROJC`
      /// sum.
      #[must_use]
      pub fn add(&self, other: &Self) -> Self {
        match (&self.0, &other.0) {
          (BlsArith::Group { point: p, .. }, BlsArith::Group { point: q, .. }) => {
            if p.is_inf() {
              other.clone()
            } else if q.is_inf() {
              self.clone()
            } else {
              Self::group(*p + *q, Coord::Projc)
            }
          }
          _ => Self(BlsArith::Relic(self.engine(1).add(&other.engine(1)))),
        }
      }

      /// `Negate` (`g*_neg`): an infinity becomes `set_infty`, `BASIC`;
      /// otherwise the tag is kept.
      #[must_use]
      pub fn neg(&self) -> Self {
        match &self.0 {
          BlsArith::Group { point, tag } => {
            if point.is_inf() {
              Self::default()
            } else {
              Self::group(-*point, *tag)
            }
          }
          BlsArith::Relic(e) => Self(BlsArith::Relic(e.neg())),
        }
      }

      /// `operator*` by the 32-byte big-endian scalar `k` (`g*_mul` of
      /// `bn_read_bin`), always `BASIC`. Core reduces k modulo r first
      /// unless it fits a digit.
      ///
      /// Variable-time on every element, so for public scalars only; a
      /// secret key's product is the crate's `mul_secret_value` (BS11a-3
      /// D34).
      #[must_use]
      pub fn mul(&self, k: &[u8; 32]) -> Self {
        let k = Bn::from_bendian(k);
        match &self.0 {
          BlsArith::Group { point, .. } => {
            let k = k.mod_r();
            if k.is_zero() || point.is_inf() {
              Self::default()
            } else {
              Self::group(point.mul_scalar(&k.to_lendian(), FR_BITS), Coord::Basic)
            }
          }
          BlsArith::Relic(e) => Self(BlsArith::Relic(e.mul(&k))),
        }
      }

      /// `operator==` (`g*_cmp`). It does not normalize, so it is not
      /// transitive: an infinity can equal points that differ from each
      /// other (BS11a-3 D24).
      pub fn core_eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
          (BlsArith::Group { point: p, tag: tp }, BlsArith::Group { point: q, tag: tq }) => $group_eq(p, *tp, q, *tq),
          _ => self.engine(1).cmp(&other.engine(1)),
        }
      }

      /// `IsValid`: an infinity is valid; any other element must lie on
      /// the curve and in the subgroup once normalized (BS11a-3 D13).
      pub fn is_valid(&self) -> bool {
        match &self.0 {
          BlsArith::Group { .. } => true,
          BlsArith::Relic(e) => {
            e.is_infty()
              || match $point(e) {
                BlsPoint::OnCurve(a) => a.to_projective().in_subgroup(),
                _ => false,
              }
          }
        }
      }

      /// `SerializeToArray(scheme == Legacy)`. Variable-time on every
      /// element, so not for a secret multiple (BS11a-3 D34).
      pub fn to_bytes(&self, scheme: BlsSchemeKind) -> [u8; $len] {
        <$group>::encode(&self.basic(), scheme)
      }

      fn basic(&self) -> [u8; $len] {
        $basic(self.engine(1).write_bin())
      }

      /// A valid wrapper holding the element, whose basic serialization is
      /// `basic`.
      fn into_value(self, basic: [u8; $len]) -> BlsValue<$group, $len> {
        match self.0 {
          BlsArith::Group { point, tag } => {
            let repr = match tag {
              Coord::Basic => BlsRepr::Basic,
              Coord::Projc => BlsRepr::Projc,
            };
            BlsValue::with_element(basic, BlsPoint::Usable(point.to_affine()), repr)
          }
          BlsArith::Relic(e) => BlsValue::with_element(basic, $point(&e), BlsRepr::Relic(Box::new(e))),
        }
      }

      /// The span `AggregateInsecure` (`schemes.cpp:176-192`): `None` for an
      /// empty span, otherwise the sum from the default element in order,
      /// of each wrapper's element whatever its validity (design D63).
      pub fn aggregate_insecure<'a, I>(values: I) -> Option<Self>
      where
        I: IntoIterator<Item = &'a BlsValue<$group, $len>>,
      {
        let mut values = values.into_iter().peekable();
        values.peek()?;
        Some(values.fold(Self::default(), |acc, v| acc.add(&Self::from_impl(v))))
      }

      /// The element rebuilt into the engine, a `PROJC` Group value scaled
      /// by `lambda` (zero reads as one). For the model target.
      #[doc(hidden)]
      #[must_use]
      pub fn __to_relic(&self, lambda: u64) -> Self {
        Self(BlsArith::Relic(self.engine(lambda)))
      }

      /// relic's shape of the element. For the model target.
      #[doc(hidden)]
      pub fn __shape(&self) -> BlsShape {
        let e = self.engine(1);
        BlsShape {
          projc: e.coord == Coord::Projc,
          zero: [e.x == Default::default(), e.y == Default::default(), e.is_infty()],
        }
      }

      /// Whether the element is held in relic's coordinates.
      #[doc(hidden)]
      pub fn __is_relic(&self) -> bool {
        matches!(self.0, BlsArith::Relic(_))
      }
    }

    /// A valid wrapper holding the element, as `AggregateInsecure` and an
    /// in-place operation's success leave it (BS11a-3 D9). Its
    /// serialization is variable-time, so it is for public scalars' products
    /// (BS11a-3 D34).
    impl From<BlsElem<$group, $len>> for BlsValue<$group, $len> {
      fn from(elem: BlsElem<$group, $len>) -> Self {
        let basic = elem.basic();
        elem.into_value(basic)
      }
    }

    impl BlsValue<$group, $len> {
      /// Core's wrapper `operator==`: the same validity, then
      /// [`BlsElem::core_eq`] of the elements. It is not transitive, unlike
      /// `==`, which compares the validity, serialized bytes and held point
      /// and is finer than Core's container key, the serialization's
      /// `GetHash()` (BS11a-3 D25).
      pub fn core_eq(&self, other: &Self) -> bool {
        self.is_valid() == other.is_valid()
          && BlsElem::<$group, $len>::from_impl(self).core_eq(&BlsElem::<$group, $len>::from_impl(other))
      }
    }
  };
}

impl_elem!(
  G1, G1Affine, Ep, BLS_PK_LEN,
  exotic: g1_exotic, rebuild: g1_rebuild, basic: g1_basic, point: g1_point, group_eq: g1_group_eq,
);
impl_elem!(
  G2, G2Affine, Ep2, BLS_SIG_LEN,
  exotic: g2_exotic, rebuild: g2_rebuild, basic: g2_basic, point: g2_point, group_eq: g2_group_eq,
);

#[cfg(test)]
mod tests {
  use super::super::tests::{G1_OFF_SUBGROUP_CHIA, G2_OFF_SUBGROUP_CHIA, GROUP_ORDER};
  use super::*;

  use hex_conservative::hex;

  type Pk = BlsElem<G1, BLS_PK_LEN>;
  type Sig = BlsElem<G2, BLS_SIG_LEN>;
  type PkValue = BlsValue<G1, BLS_PK_LEN>;
  type SigValue = BlsValue<G2, BLS_SIG_LEN>;

  const LEGACY: BlsSchemeKind = BlsSchemeKind::Legacy;
  const BASIC: BlsSchemeKind = BlsSchemeKind::Basic;

  /// Two G1 x off the curve whose legacy keys with the sign bit clear
  /// (y = 0 by Lemma C) sum to relic's (0, 0, 0) `PROJC`; found with the
  /// probe `/work/scratch/bs11a-3/probe/zz.c` against Core's relic, which
  /// also printed `ep_cmp` = EQ against the generator.
  const ZZ_X1: [u8; 48] =
    hex!("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001e");
  const ZZ_X2: [u8; 48] =
    hex!("15248e0fa7fb53ac007285570b6877260dc7f6e9e293c4f27734bc697f11ea88376dfaebe9096bf05858dbcf966cb9d6");

  fn scalar(k: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&k.to_be_bytes());
    out
  }

  fn g1() -> Pk {
    Pk::group(G1::generator(), Coord::Basic)
  }

  fn g2() -> Sig {
    Sig::group(G2::generator(), Coord::Basic)
  }

  fn legacy_pk(bytes: &[u8; 48]) -> PkValue {
    PkValue::from_canonical(bytes, LEGACY).unwrap_or_else(PkValue::invalid)
  }

  /// Every observable of `a` on blst equals the engine's for its rebuild
  /// under the scale `lambda`, and the engine copy equals it under Core's
  /// `==`.
  fn assert_engine_agrees<K: BlsWirePoint<N>, const N: usize>(
    a: &BlsElem<K, N>,
    relic: &BlsElem<K, N>,
    bytes: impl Fn(&BlsElem<K, N>, BlsSchemeKind) -> [u8; N],
    valid: impl Fn(&BlsElem<K, N>) -> bool,
    eq: impl Fn(&BlsElem<K, N>, &BlsElem<K, N>) -> bool,
  ) {
    for scheme in [LEGACY, BASIC] {
      assert_eq!(bytes(a, scheme), bytes(relic, scheme));
    }
    assert_eq!(valid(a), valid(relic));
    assert!(eq(a, relic) && eq(relic, a));
  }

  #[test]
  fn default_is_basic_infinity() {
    let d = Pk::default();
    assert_eq!(d.to_bytes(LEGACY)[0], 0xc0);
    assert_eq!(d.to_bytes(BASIC), G1::default_element().0);
    assert!(d.is_valid());
    assert_eq!(
      d.__shape(),
      BlsShape {
        projc: false,
        zero: [true; 3]
      }
    );
    assert!(Pk::from_impl(&PkValue::invalid()).core_eq(&d));
    assert_eq!(
      Sig::default().__shape(),
      BlsShape {
        projc: false,
        zero: [true; 3]
      }
    );
  }

  #[test]
  fn group_operations_match_the_engine_under_every_scale() {
    let g = g1();
    let two = g.add(&g);
    let values = [
      Pk::default(),
      g.clone(),
      two.clone(),
      two.add(&g),
      g.add(&g.neg()),
      g.add(&g.neg()).neg(),
      g.mul(&scalar(7)),
      g.mul(&GROUP_ORDER),
      two.neg(),
    ];
    for a in &values {
      for b in &values {
        for lambda in [1, 2, 0xdead_beef] {
          let (ra, rb) = (a.__to_relic(lambda), b.__to_relic(lambda + 1));
          assert_eq!(a.__shape(), ra.__shape());
          let pairs = [
            (a.add(b), ra.add(&rb)),
            (a.neg(), ra.neg()),
            (a.mul(&scalar(5)), ra.mul(&scalar(5))),
          ];
          for (group, engine) in &pairs {
            assert!(!group.__is_relic() && engine.__is_relic());
            assert_eq!(group.__shape().projc, engine.__shape().projc);
            assert_eq!(group.__shape().zero[2], engine.__shape().zero[2]);
            assert_engine_agrees(group, engine, Pk::to_bytes, Pk::is_valid, Pk::core_eq);
          }
          assert_eq!(a.core_eq(b), ra.core_eq(&rb), "{a:?} {b:?}");
        }
      }
    }
  }

  #[test]
  fn g2_group_operations_match_the_engine() {
    let g = g2();
    let two = g.add(&g);
    let values = [
      Sig::default(),
      g.clone(),
      two.clone(),
      two.add(&g),
      g.add(&g.neg()),
      g.mul(&scalar(3)),
    ];
    for a in &values {
      for b in &values {
        let (ra, rb) = (a.__to_relic(3), b.__to_relic(5));
        assert_eq!(a.__shape(), ra.__shape());
        for (group, engine) in [
          (a.add(b), ra.add(&rb)),
          (a.neg(), ra.neg()),
          (a.mul(&scalar(9)), ra.mul(&scalar(9))),
        ] {
          assert_eq!(group.__shape().projc, engine.__shape().projc);
          assert_engine_agrees(&group, &engine, Sig::to_bytes, Sig::is_valid, Sig::core_eq);
        }
        assert_eq!(a.core_eq(b), ra.core_eq(&rb), "{a:?} {b:?}");
      }
    }
  }

  #[test]
  fn tags_follow_cores_relic() {
    let g = g1();
    let sum = g.add(&g);
    assert!(sum.__shape().projc);
    // P + (-P) is the PROJC infinity; its negation is set_infty.
    let zero = g.add(&g.neg());
    assert_eq!(
      zero.__shape(),
      BlsShape {
        projc: true,
        zero: [true, false, true]
      }
    );
    assert_eq!(zero.neg().__shape(), Pk::default().__shape());
    // Adding the infinity copies the other operand's tag.
    assert!(zero.add(&sum).__shape().projc);
    assert!(!Pk::default().add(&g).__shape().projc);
    // Multiplication always normalizes.
    assert!(!sum.mul(&scalar(3)).__shape().projc);
    assert_eq!(sum.mul(&GROUP_ORDER).__shape(), Pk::default().__shape());
    let s = g2();
    assert_eq!(
      s.add(&s.neg()).__shape(),
      BlsShape {
        projc: true,
        zero: [true; 3]
      }
    );
  }

  #[test]
  fn g2_projc_infinity_equals_every_projc_value() {
    // relic_ep2_cmp.c:51-63 cross-multiplies by z, which is zero.
    let g = g2();
    let zero = g.add(&g.neg());
    let three = g.add(&g).add(&g);
    assert!(zero.core_eq(&three) && three.core_eq(&zero));
    assert!(!zero.core_eq(&g));
    assert!(zero.core_eq(&Sig::default()));
    // In G1 the PROJC infinity (0, y, 0) does not.
    let h = g1();
    let hz = h.add(&h.neg());
    assert!(!hz.core_eq(&h.add(&h).add(&h)));
    // Serialization still tells them apart, and so does `==`.
    let (zv, tv) = (SigValue::from(zero), SigValue::from(three));
    assert!(zv.core_eq(&tv));
    assert_ne!(zv, tv);
  }

  #[test]
  fn engine_points_are_classed_as_legacy_decoding_would() {
    let (one, two) = (Fp::from_u64(1), Fp::from_u64(2));
    assert!(matches!(g1_point(&Ep::INFTY), BlsPoint::OnCurve(_)));
    assert!(matches!(g1_point(&g1().engine(1)), BlsPoint::OnCurve(_)));
    assert!(matches!(
      g1_point(&Ep::affine(one, one, Coord::Basic)),
      BlsPoint::Exotic
    ));
    // (0, 2) is on the curve, of order 3.
    assert!(matches!(
      g1_point(&Ep::affine(Fp::default(), two, Coord::Basic)),
      BlsPoint::Exotic
    ));
    assert!(matches!(g2_point(&g2().engine(1)), BlsPoint::OnCurve(_)));
    let (one, zero) = (Fp2::from(one), Fp2::default());
    assert!(matches!(
      g2_point(&Ep2::affine(one, one, Coord::Basic)),
      BlsPoint::Exotic
    ));
    assert!(matches!(
      g2_point(&Ep2::affine(zero, zero, Coord::Basic)),
      BlsPoint::Exotic
    ));
  }

  #[test]
  fn secret_products_serialize_as_the_engine_does() {
    let mut r_minus_one = GROUP_ORDER;
    r_minus_one[31] -= 1;
    for k in [scalar(1), scalar(7), r_minus_one, GROUP_ORDER] {
      let p = g1().mul_secret(&k);
      assert!(!p.__is_relic());
      assert_eq!(p.secret_basic(), p.to_bytes(BASIC));
    }
    let e = Pk::from_impl(&legacy_pk(&G1_OFF_SUBGROUP_CHIA)).mul_secret(&scalar(7));
    assert!(e.__is_relic());
    assert_eq!(e.secret_basic(), e.to_bytes(BASIC));
  }

  /// The constant-time DH wrapper is the `From` wrapper of `mul`'s product,
  /// on Group keys (`BASIC`, `PROJC` and the infinity) and on off-subgroup
  /// and Exotic ones.
  #[test]
  fn secret_values_are_the_products_wrappers() {
    let mut r_minus_one = GROUP_ORDER;
    r_minus_one[31] -= 1;
    let keys = [
      g1(),
      g1().add(&g1()),
      Pk::default(),
      Pk::from_impl(&legacy_pk(&G1_OFF_SUBGROUP_CHIA)),
      Pk::from_impl(&legacy_pk(&ZZ_X1)),
    ];
    assert!(keys[3].__is_relic() && keys[4].__is_relic());
    for pk in &keys {
      for k in [scalar(0), scalar(1), scalar(7), r_minus_one, GROUP_ORDER] {
        let ct = pk.mul_secret_value(&k);
        let vt = PkValue::from(pk.mul(&k));
        assert_eq!(ct, vt);
        assert_eq!(
          core::mem::discriminant(ct.parts().2),
          core::mem::discriminant(vt.parts().2)
        );
        assert!(ct.is_valid() && ct.core_eq(&vt));
        assert_eq!(ct.to_bytes(LEGACY), vt.to_bytes(LEGACY));
        assert_eq!(ct.to_bytes(BASIC), vt.to_bytes(BASIC));
      }
    }
  }

  #[test]
  fn debug_names_the_representation() {
    assert!(format!("{:?}", g1()).starts_with("BlsElem(Group"));
    assert!(format!(
      "{:?}",
      Sig::from_impl(&SigValue::from_canonical(&G2_OFF_SUBGROUP_CHIA, LEGACY).unwrap_or_else(SigValue::invalid))
    )
    .starts_with("BlsElem(Relic"));
  }

  #[test]
  fn crafted_off_curve_keys_sum_to_an_element_equal_to_everything() {
    let a = Pk::from_impl(&legacy_pk(&ZZ_X1));
    let b = Pk::from_impl(&legacy_pk(&ZZ_X2));
    assert!(a.__is_relic() && b.__is_relic());
    let z = a.add(&b);
    assert_eq!(
      z.__shape(),
      BlsShape {
        projc: true,
        zero: [true; 3]
      }
    );
    assert!(z.core_eq(&g1()) && g1().core_eq(&z));
    assert!(z.core_eq(&g1().add(&g1())));
    assert!(z.is_valid());
    assert_eq!(z.to_bytes(LEGACY), Pk::default().to_bytes(LEGACY));
  }

  #[test]
  fn decoded_values_rebuild_as_core_decoded_them() {
    // On the curve, outside the subgroup: (x, y, 1) in the engine.
    let v = legacy_pk(&G1_OFF_SUBGROUP_CHIA);
    assert!(v.is_valid());
    let e = Pk::from_impl(&v);
    assert!(e.__is_relic());
    assert!(!e.is_valid());
    assert_eq!(e.to_bytes(LEGACY), G1_OFF_SUBGROUP_CHIA);
    let s = Sig::from_impl(&SigValue::from_canonical(&G2_OFF_SUBGROUP_CHIA, LEGACY).unwrap_or_else(SigValue::invalid));
    assert!(s.__is_relic() && !s.is_valid());
    assert_eq!(s.to_bytes(LEGACY), G2_OFF_SUBGROUP_CHIA);
    // Off the curve: Lemma C's y round-trips both sign bits.
    for x in [ZZ_X1, ZZ_X2] {
      let mut signed = x;
      signed[0] |= 0x80;
      for bytes in [x, signed] {
        let e = Pk::from_impl(&legacy_pk(&bytes));
        assert!(e.__is_relic());
        assert_eq!(e.to_bytes(LEGACY), bytes);
        assert!(!e.is_valid());
        assert!(e.core_eq(&e.clone()));
      }
    }
    // A usable key stays on blst.
    let g = G1::generator().to_affine().compress();
    let u = Pk::from_impl(&PkValue::from_canonical(&g, BASIC).unwrap_or_else(PkValue::invalid));
    assert!(!u.__is_relic());
    assert!(u.core_eq(&g1()));
  }

  #[test]
  fn values_keep_the_element_they_are_given() {
    let exotic = Pk::from_impl(&legacy_pk(&ZZ_X2));
    for e in [
      g1().add(&g1()),
      g1().add(&g1().neg()),
      exotic.clone(),
      exotic.mul(&scalar(3)),
      exotic.add(&g1()),
    ] {
      let v = PkValue::from(e.clone());
      assert!(v.is_valid());
      let back = Pk::from_impl(&v);
      assert_eq!(back.__shape(), e.__shape());
      assert_eq!(back.__is_relic(), e.__is_relic());
      for scheme in [LEGACY, BASIC] {
        assert_eq!(v.to_bytes(scheme), e.to_bytes(scheme));
      }
      assert!(v.core_eq(&v.clone()) || !e.core_eq(&e));
    }
    // An invalid wrapper's element still takes part.
    let mut inv = PkValue::from(g1());
    inv.invalidate();
    assert!(Pk::from_impl(&inv).core_eq(&g1()));
    assert!(!inv.core_eq(&PkValue::from(g1())));
  }

  #[test]
  fn aggregate_insecure_folds_from_the_default_element() {
    assert!(Pk::aggregate_insecure(core::iter::empty()).is_none());
    let sum = g1().add(&g1());
    let values = [PkValue::from(g1()), PkValue::from(sum.clone())];
    let one = Pk::aggregate_insecure(&values[1..]);
    // The first addition copies its operand, tag included.
    assert!(one.as_ref().is_some_and(|e| e.__shape().projc && e.core_eq(&sum)));
    let all = Pk::aggregate_insecure(&values);
    assert!(all.is_some_and(|e| e.core_eq(&g1().mul(&scalar(3)))));
    // Invalid inputs contribute their element.
    assert!(Pk::aggregate_insecure(&[PkValue::invalid()]).is_some_and(|e| e.core_eq(&Pk::default())));
  }

  #[test]
  fn multiplication_reduces_long_scalars() {
    let g = g1();
    let mut r_plus_two = GROUP_ORDER;
    r_plus_two[31] += 2;
    assert!(g.mul(&r_plus_two).core_eq(&g.mul(&scalar(2))));
    // Outside the subgroup too: g1_mul reduces a long scalar modulo r
    // before the GLV path, so r gives set_infty although [r]P is not the
    // identity there.
    let exotic = Pk::from_impl(&legacy_pk(&G1_OFF_SUBGROUP_CHIA));
    assert!(exotic.mul(&r_plus_two).core_eq(&exotic.mul(&scalar(2))));
    assert_eq!(exotic.mul(&GROUP_ORDER).__shape(), Pk::default().__shape());
    let mut r_minus_one = GROUP_ORDER;
    r_minus_one[31] -= 1;
    assert!(!exotic.mul(&r_minus_one).core_eq(&exotic.neg()));
  }

  /// A secret key's bytes multiply as `mul` does, `r` included, on blst
  /// and in the engine.
  #[test]
  fn secret_multiplication_is_mul() {
    let exotic = Pk::from_impl(&legacy_pk(&G1_OFF_SUBGROUP_CHIA));
    let mut r_minus_one = GROUP_ORDER;
    r_minus_one[31] -= 1;
    for a in [g1(), g1().mul(&scalar(7)).add(&g1()), Pk::default(), exotic] {
      for k in [scalar(1), scalar(3), [0x5a; 32], r_minus_one, GROUP_ORDER] {
        let (secret, public) = (a.mul_secret(&k), a.mul(&k));
        assert!(secret.core_eq(&public));
        assert_eq!(secret.__shape(), public.__shape());
        assert_eq!(secret.to_bytes(BASIC), public.to_bytes(BASIC));
      }
    }
  }
}
