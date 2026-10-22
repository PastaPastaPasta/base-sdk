//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Per-scheme decoding and encoding of the objects Core's BLS wrapper holds.
//!
//! Each kind answers one question per scheme. Does Core's `SetBytes` accept
//! the bytes as a valid object that re-serializes to the same bytes?

use super::elem::BlsArith;
use super::group::{G1Affine, G2Affine, G1, G2};
use super::relic::ep::Ep;
use super::relic::ep2::Ep2;
use super::scalar::{Fp, Fr};
use super::scheme_ctx::BlsSchemeKind;
use super::{BLS_PK_LEN, BLS_SIG_LEN, BLS_SK_LEN};
use crate::prelude::*;

use blst::BLST_ERROR;
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use hex_conservative::hex;
use subtle::{Choice, ConstantTimeEq};

use core::fmt::Debug;
use core::hash::{Hash, Hasher};

/// The BLS12-381 group order `r`, big-endian.
const GROUP_ORDER: [u8; BLS_SK_LEN] = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

/// Leading-byte bit 0x80, the sign of `y` in the legacy layout and the
/// compression flag in the basic one.
pub(super) const FLAG_HIGH: u8 = 0x80;
/// Leading-byte bit 0x40, infinity in the basic layout.
pub(super) const FLAG_INFINITY: u8 = 0x40;
/// Leading-byte bit 0x20, the sign of `y` in the basic layout.
pub(super) const FLAG_SIGN: u8 = 0x20;
/// The leading-byte bits that belong to a coordinate.
pub(super) const COORD_MASK: u8 = 0x1f;

/// Keeps [`BlsWire`] sealed to the kinds this crate defines.
pub(crate) mod sealed {
  pub trait Sealed {}
}

/// How an element is held besides its serialization and point (design D27,
/// Lemma T'): Core's coord tag for a value blst computes, or relic's
/// coordinates for one only the engine can.
#[doc(hidden)]
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub enum BlsRepr<E> {
  /// `BASIC`: decoded values, the default element and every `g*_mul`
  /// result.
  #[default]
  Basic,
  /// `PROJC`: a finite `g*_add` result, or the infinity a sum of a point
  /// and its negation leaves.
  Projc,
  /// relic's coordinates, for an element of the engine (BS11a-3 D6).
  Relic(Box<E>),
}

/// A curve point a valid object holds.
///
/// Legacy decoding checks neither the curve nor the subgroup, so a valid
/// legacy object may hold a point no pairing accepts. Core decides validity
/// without a subgroup test, so legacy decoding leaves that test to
/// [`Self::usable`].
///
/// Equality and hashing ignore whether the subgroup test has run: a point
/// decoded under both schemes is one element.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub enum BlsPoint<A> {
  /// On the curve and in the prime-order subgroup.
  Usable(A),
  /// On the curve, decoded under the legacy scheme; the subgroup is not yet
  /// tested.
  OnCurve(A),
  /// Off the curve, or one of the G1 points of order 3, which blst cannot
  /// hold; reachable only through legacy decoding.
  Exotic,
}

impl<A> BlsPoint<A> {
  /// The point blst holds, whether or not it is in the subgroup.
  fn held(&self) -> Option<&A> {
    match self {
      Self::Usable(point) | Self::OnCurve(point) => Some(point),
      Self::Exotic => None,
    }
  }
}

/// Implements [`BlsPoint::usable`] for an affine point type.
macro_rules! impl_usable {
  ($affine:ty) => {
    impl BlsPoint<$affine> {
      /// The point, when it is usable for curve arithmetic and pairings. A
      /// legacy-decoded point runs the subgroup test here, on every call.
      pub fn usable(&self) -> Option<&$affine> {
        match self {
          Self::Usable(point) => Some(point),
          Self::OnCurve(point) => point.to_projective().in_subgroup().then_some(point),
          Self::Exotic => None,
        }
      }
    }
  };
}

impl_usable!(G1Affine);
impl_usable!(G2Affine);

impl<A: Eq> Eq for BlsPoint<A> {}

impl<A: Hash> Hash for BlsPoint<A> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.held().hash(state);
  }
}

impl<A: PartialEq> PartialEq for BlsPoint<A> {
  fn eq(&self, other: &Self) -> bool {
    self.held() == other.held()
  }
}

/// An object kind Core's BLS wrapper serializes in `N` bytes, a G1 public key,
/// a G2 signature or a secret key.
pub trait BlsWire<const N: usize>: sealed::Sealed + Sized + 'static {
  /// What an object holds besides its bytes.
  type Point: Clone + Debug + Eq + Send + Sync;

  /// How an arithmetic result is held besides its bytes and point.
  #[doc(hidden)]
  type Repr: Clone + Debug + Default + Send + Sync;

  /// Core's default element as basic-scheme bytes and point: infinity for a
  /// curve point, zero for a secret key. An invalid object holds it unless an
  /// operation that failed in place kept its previous element.
  #[doc(hidden)]
  fn default_element() -> ([u8; N], Self::Point);

  /// Whether the bytes are secret, so they are redacted and wiped.
  #[doc(hidden)]
  const SECRET: bool;

  /// Core's `SetBytes` followed by its round-trip check under `scheme`.
  ///
  /// Returns the object's basic-scheme encoding and its point when the bytes
  /// decode to a valid object whose `scheme` serialization equals them.
  #[doc(hidden)]
  fn decode_canonical(bytes: &[u8; N], scheme: BlsSchemeKind) -> Option<([u8; N], Self::Point)>;

  /// Core's `SetBytes(bytes, false)`, the basic scheme with no round trip.
  ///
  /// Returns the object's basic-scheme serialization and its point when the
  /// bytes decode to a valid object. The serialization may differ from
  /// `bytes`.
  #[doc(hidden)]
  fn decode_set_basic(bytes: &[u8; N]) -> Option<([u8; N], Self::Point)>;

  /// Whether [`Self::decode_canonical`] would succeed, possibly cheaper.
  #[doc(hidden)]
  fn is_canonical(bytes: &[u8; N], scheme: BlsSchemeKind) -> bool {
    Self::decode_canonical(bytes, scheme).is_some()
  }

  /// Re-encodes an element's basic-scheme encoding under `scheme`, as dashbls
  /// serializes it; infinity, Core's default element, is the same in both.
  #[doc(hidden)]
  fn encode(basic: &[u8; N], scheme: BlsSchemeKind) -> [u8; N];
}

/// A curve-point kind, the kinds Core also wraps lazily.
pub trait BlsWirePoint<const N: usize>: BlsWire<N> {
  /// The element as `BlsElem` computes with it.
  #[doc(hidden)]
  type Arith: Clone + Debug + Send + Sync;
}

/// Whether the bytes are all zero, which Core's `SetBytes` resets to the
/// invalid object before any decoding. Constant time, as the bytes may be a
/// secret key.
pub(super) fn is_zero(bytes: &[u8]) -> bool {
  bytes.iter().fold(0u8, |acc, &b| acc | b) == 0
}

/// Whether the big-endian integer `a` is below `b`, in constant time.
fn ct_lt(a: &[u8; BLS_SK_LEN], b: &[u8; BLS_SK_LEN]) -> Choice {
  // The borrow out of `a - b`, from the least significant byte up.
  let borrow = a.iter().zip(b).rev().fold(0u16, |borrow, (&x, &y)| {
    (u16::from(x).wrapping_sub(u16::from(y)).wrapping_sub(borrow) >> 8) & 1
  });
  Choice::from(borrow as u8)
}

/// Moves the legacy G1 sign bit to its basic position and sets the
/// compression flag.
fn g1_legacy_to_basic(legacy: &[u8; BLS_PK_LEN]) -> [u8; BLS_PK_LEN] {
  let mut out = *legacy;
  let sign = if legacy[0] & FLAG_HIGH != 0 { FLAG_SIGN } else { 0 };
  out[0] = (legacy[0] & COORD_MASK) | FLAG_HIGH | sign;
  out
}

/// Inverse of [`g1_legacy_to_basic`] on valid encodings.
fn g1_basic_to_legacy(basic: &[u8; BLS_PK_LEN]) -> [u8; BLS_PK_LEN] {
  let mut out = *basic;
  let sign = if basic[0] & FLAG_SIGN != 0 { FLAG_HIGH } else { 0 };
  out[0] = (basic[0] & COORD_MASK) | sign;
  out
}

/// Swaps the legacy `c0 || c1` order to the basic `c1 || c0`, moves the sign
/// bit and sets the compression flag. `legacy` must hold coordinates below
/// 2^381.
fn g2_legacy_to_basic(legacy: &[u8; BLS_SIG_LEN]) -> [u8; BLS_SIG_LEN] {
  let mut out = *legacy;
  out.rotate_left(BLS_SIG_LEN / 2);
  out[BLS_SIG_LEN / 2] &= !FLAG_HIGH;
  let sign = if legacy[0] & FLAG_HIGH != 0 { FLAG_SIGN } else { 0 };
  out[0] |= FLAG_HIGH | sign;
  out
}

/// Inverse of [`g2_legacy_to_basic`] on valid encodings.
fn g2_basic_to_legacy(basic: &[u8; BLS_SIG_LEN]) -> [u8; BLS_SIG_LEN] {
  let mut out = *basic;
  out.rotate_left(BLS_SIG_LEN / 2);
  out[BLS_SIG_LEN / 2] &= COORD_MASK;
  if basic[0] & FLAG_SIGN != 0 {
    out[0] |= FLAG_HIGH;
  }
  out
}

/// Decodes a basic-layout G1 point as dashbls does, by uncompressing with the
/// subgroup check. The identity never decodes here; Core resets it. Returns
/// the serialization, which always equals the bytes, and the point.
fn g1_decode_basic(bytes: &[u8; BLS_PK_LEN]) -> Option<([u8; BLS_PK_LEN], G1Affine)> {
  if bytes[0] & (FLAG_HIGH | FLAG_INFINITY) != FLAG_HIGH {
    return None;
  }
  // blst rejects x >= p, x off the curve, and x = 0, the order-3 points
  // dashbls refuses for a coordinate that is zero once the flags are masked.
  let point = G1Affine::uncompress(bytes).ok()?;
  point.to_projective().in_subgroup().then_some((*bytes, point))
}

/// Decodes a legacy-layout G1 point as relic does, with no curve or subgroup
/// check. Returns the basic-layout encoding, and the point when blst can hold
/// it.
fn g1_decode_legacy(bytes: &[u8; BLS_PK_LEN]) -> Option<([u8; BLS_PK_LEN], Option<G1Affine>)> {
  // dashbls masks the 0x40 and 0x20 bits away, so input carrying them never
  // re-serializes to itself; 0xc0 is its infinity marker.
  if is_zero(bytes) || bytes[0] & (FLAG_INFINITY | FLAG_SIGN) != 0 {
    return None;
  }
  let basic = g1_legacy_to_basic(bytes);
  match G1Affine::uncompress(&basic) {
    Ok(point) => Some((basic, Some(point))),
    // blst refuses the order-3 points (0, 2) and (0, -2), which are on the
    // curve; relic decodes them like any other.
    Err(BLST_ERROR::BLST_POINT_NOT_IN_GROUP) => Some((basic, None)),
    // relic keeps the sign bit as y's Montgomery form, 0 or 1, and encodes
    // the sign of y. Those are 0 and R^-1 mod p > (p - 1) / 2 (R = 2^384),
    // so every off-curve x below p round-trips with either sign bit.
    Err(BLST_ERROR::BLST_POINT_NOT_ON_CURVE) => Some((basic, None)),
    Err(_) => None,
  }
}

/// Uncompresses a basic-layout G2 point as dashbls does, without the
/// subgroup check. Returns relic's serialization of it and the point.
fn g2_uncompress_basic(bytes: &[u8; BLS_SIG_LEN]) -> Option<([u8; BLS_SIG_LEN], G2Affine)> {
  if bytes[0] & (FLAG_HIGH | FLAG_INFINITY) != FLAG_HIGH || bytes[BLS_SIG_LEN / 2] & !COORD_MASK != 0 {
    return None;
  }
  let point = G2Affine::uncompress(bytes).ok()?;
  // relic re-encodes the sign from y.c1 alone, so a set sign bit with
  // y.c1 = 0 serializes cleared.
  let mut ser = *bytes;
  if point.y().c1() == Fp::default() {
    ser[0] &= !FLAG_SIGN;
  }
  Some((ser, point))
}

/// Decodes a basic-layout G2 point as dashbls does, with the subgroup check.
/// Returns the serialization and the point.
fn g2_decode_basic(bytes: &[u8; BLS_SIG_LEN]) -> Option<([u8; BLS_SIG_LEN], G2Affine)> {
  g2_uncompress_basic(bytes).filter(|(_, point)| point.to_projective().in_subgroup())
}

/// Decodes a legacy-layout G2 point as relic does, with no curve or subgroup
/// check. Returns the basic-layout encoding, and the point when blst can hold
/// it.
fn g2_decode_legacy(bytes: &[u8; BLS_SIG_LEN]) -> Option<([u8; BLS_SIG_LEN], Option<G2Affine>)> {
  // Both coordinates must lie below 2^381 before the layout swap, since blst
  // masks the top bits of the leading coordinate; it then checks them
  // against p. dashbls treats a 0xc0 lead as infinity and always throws.
  if is_zero(bytes) || bytes[0] & (FLAG_INFINITY | FLAG_SIGN) != 0 || bytes[BLS_SIG_LEN / 2] & !COORD_MASK != 0 {
    return None;
  }
  let signed = bytes[0] & FLAG_HIGH != 0;
  let basic = g2_legacy_to_basic(bytes);
  match G2Affine::uncompress(&basic) {
    // relic re-encodes the sign from y.c1 alone, as for the basic layout.
    Ok(point) if signed && point.y().c1() == Fp::default() => None,
    Ok(point) => Some((basic, Some(point))),
    // relic leaves y = (sign bit, 0) and re-encodes it with sign 0.
    Err(BLST_ERROR::BLST_POINT_NOT_ON_CURVE) if !signed => Some((basic, None)),
    Err(_) => None,
  }
}

/// Implements [`BlsWire`] and [`BlsWirePoint`] for a curve group from its
/// basic and legacy decoders and its legacy encoder.
macro_rules! impl_wire_point {
  ($group:ty, $affine:ty, $engine:ty, $len:expr, $decode_basic:ident, $decode_legacy:ident, $to_legacy:ident) => {
    impl sealed::Sealed for $group {}

    impl BlsWire<$len> for $group {
      type Point = BlsPoint<$affine>;
      type Repr = BlsRepr<$engine>;

      const SECRET: bool = false;

      fn default_element() -> ([u8; $len], Self::Point) {
        let mut basic = [0u8; $len];
        basic[0] = FLAG_HIGH | FLAG_INFINITY;
        // blst's affine identity is all zero.
        (basic, BlsPoint::Usable(<$affine>::default()))
      }

      fn decode_canonical(bytes: &[u8; $len], scheme: BlsSchemeKind) -> Option<([u8; $len], Self::Point)> {
        match scheme {
          BlsSchemeKind::Basic => Self::decode_set_basic(bytes).filter(|(ser, _)| ser == bytes),
          BlsSchemeKind::Legacy => {
            $decode_legacy(bytes).map(|(basic, point)| (basic, point.map_or(BlsPoint::Exotic, BlsPoint::OnCurve)))
          }
        }
      }

      fn decode_set_basic(bytes: &[u8; $len]) -> Option<([u8; $len], Self::Point)> {
        $decode_basic(bytes).map(|(ser, point)| (ser, BlsPoint::Usable(point)))
      }

      fn is_canonical(bytes: &[u8; $len], scheme: BlsSchemeKind) -> bool {
        match scheme {
          BlsSchemeKind::Basic => $decode_basic(bytes).is_some_and(|(ser, _)| ser == *bytes),
          BlsSchemeKind::Legacy => $decode_legacy(bytes).is_some(),
        }
      }

      fn encode(basic: &[u8; $len], scheme: BlsSchemeKind) -> [u8; $len] {
        match scheme {
          BlsSchemeKind::Legacy if basic[0] & FLAG_INFINITY == 0 => $to_legacy(basic),
          _ => *basic,
        }
      }
    }

    impl BlsWirePoint<$len> for $group {
      type Arith = BlsArith<$group, $engine>;
    }
  };
}

impl_wire_point!(
  G1,
  G1Affine,
  Ep,
  BLS_PK_LEN,
  g1_decode_basic,
  g1_decode_legacy,
  g1_basic_to_legacy
);
impl_wire_point!(
  G2,
  G2Affine,
  Ep2,
  BLS_SIG_LEN,
  g2_decode_basic,
  g2_decode_legacy,
  g2_basic_to_legacy
);

impl sealed::Sealed for Fr {}

/// Secret keys serialize the same in both schemes; the scheme flag is reused
/// as `modOrder`. Legacy reduces modulo `r`, so it keeps only keys below `r`.
/// Basic refuses keys above `r` and keeps `r` itself unreduced.
impl BlsWire<BLS_SK_LEN> for Fr {
  type Point = ();
  type Repr = ();

  const SECRET: bool = true;

  fn default_element() -> ([u8; BLS_SK_LEN], Self::Point) {
    ([0u8; BLS_SK_LEN], ())
  }

  fn decode_canonical(bytes: &[u8; BLS_SK_LEN], scheme: BlsSchemeKind) -> Option<([u8; BLS_SK_LEN], Self::Point)> {
    let in_range = match scheme {
      BlsSchemeKind::Legacy => ct_lt(bytes, &GROUP_ORDER),
      BlsSchemeKind::Basic => !ct_lt(&GROUP_ORDER, bytes),
    };
    let nonzero = !bytes.ct_eq(&[0u8; BLS_SK_LEN]);
    bool::from(in_range & nonzero).then_some((*bytes, ()))
  }

  /// Basic keys always re-serialize to their bytes.
  fn decode_set_basic(bytes: &[u8; BLS_SK_LEN]) -> Option<([u8; BLS_SK_LEN], Self::Point)> {
    Self::decode_canonical(bytes, BlsSchemeKind::Basic)
  }

  fn encode(basic: &[u8; BLS_SK_LEN], _scheme: BlsSchemeKind) -> [u8; BLS_SK_LEN] {
    *basic
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// A point on the G2 curve outside the subgroup, with y in Fp and the sign
  /// bit set; the corpus's first `realy_basic_s1` signature.
  const REALY_BASIC_S1: [u8; BLS_SIG_LEN] = hex!("a9fe2de1602ea40da4d030d64bd648b98ff50450dacd18f4d937071fc5e5c22724028b4aa4af59474133c694e215547b163308bb5daa4f03cf2e40a3dfb07ccc0b7912431431364fcb5fe5655ff81b65f824cd7adc3e2a0ffc0874b5939d63d6");

  /// relic serializes a point with y.c1 = 0 with the sign bit clear, whatever
  /// sign selected it; only the subgroup check keeps it from `SetBytes`.
  #[test]
  fn g2_basic_sign_of_real_y_serializes_cleared() {
    let decoded = g2_uncompress_basic(&REALY_BASIC_S1);
    assert!(decoded.is_some_and(|(ser, point)| {
      let mut cleared = REALY_BASIC_S1;
      cleared[0] &= !FLAG_SIGN;
      ser == cleared && point.y().c1() == Fp::default()
    }));
    assert!(g2_decode_basic(&REALY_BASIC_S1).is_none());
  }
}
