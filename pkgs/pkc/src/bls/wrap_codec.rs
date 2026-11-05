//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Canonical decoding and re-encoding of each BLS wire kind under a scheme.
//!
//! Bytes are canonical under a scheme when they are not all zero and the
//! scheme reads them as an element other than the identity that encodes back
//! to them, as [`BlsScheme::is_canonical_pk`] and
//! [`BlsScheme::is_canonical_sig`] decide for points.

use super::byte_bags::{BLS_PK_LEN, BLS_SIG_LEN, BLS_SK_LEN};
use super::error::BlsError;
use super::group::{G1Affine, G2Affine, G1, G2};
use super::scheme_ctx::BlsSchemeKind;
use super::scheme_ops::BlsScheme;
use super::schemes::{BlsScChia, BlsScIetf};
use crate::sealed::Sealed;

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use hex_conservative::hex;
use subtle::{Choice, ConstantTimeEq};

use core::fmt::Debug;

/// The BLS12-381 group order `r`, big-endian.
pub(crate) const GROUP_ORDER: [u8; BLS_SK_LEN] =
  hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

/// Leading-byte bit 0x80: the sign of `y` in the legacy layout, compression
/// in the basic one.
const FLAG_HIGH: u8 = 0x80;
/// Leading-byte bit 0x20, the sign of `y` in the basic layout.
const FLAG_SIGN: u8 = 0x20;
/// The leading-byte bits that belong to a coordinate.
const COORD_MASK: u8 = 0x1f;

/// A curve point a valid object holds.
///
/// The legacy scheme checks neither the curve nor the subgroup, so a valid
/// legacy object may hold a point off the curve or outside the subgroup.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub enum BlsPoint<A> {
  /// On the curve and in the prime-order subgroup.
  Usable(A),
  /// Off the curve or outside the subgroup, which only the legacy scheme
  /// reads.
  Exotic,
}

impl<A> BlsPoint<A> {
  /// The point, when it is on the curve and in the subgroup.
  pub fn usable(&self) -> Option<&A> {
    match self {
      Self::Usable(point) => Some(point),
      Self::Exotic => None,
    }
  }
}

/// A BLS point written in `N` bytes: a G1 public key or a G2 signature.
pub trait BlsWire<const N: usize>: Sealed + Sized + 'static {
  /// What a valid object holds besides its bytes.
  type Point: Clone + Debug + Eq + Send + Sync;

  /// The error for bytes canonical under neither scheme.
  #[doc(hidden)]
  const INVALID: BlsError;

  /// Decodes bytes canonical under `scheme`.
  ///
  /// Returns the object's basic encoding and its point.
  #[doc(hidden)]
  fn decode(bytes: &[u8; N], scheme: BlsSchemeKind) -> Option<([u8; N], Self::Point)>;

  /// Whether `bytes` are canonical under `scheme`, possibly cheaper than
  /// [`Self::decode`].
  #[doc(hidden)]
  fn is_canonical(bytes: &[u8; N], scheme: BlsSchemeKind) -> bool;

  /// Encodes a valid object, given its basic encoding, under `scheme`.
  #[doc(hidden)]
  fn encode(basic: &[u8; N], scheme: BlsSchemeKind) -> [u8; N];
}

/// Whether the bytes are all zero, in constant time as they may be a secret
/// key.
pub(super) fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
  bool::from(bytes.ct_eq(&[0u8; N]))
}

/// Whether the big-endian integer `a` is below `b`, in constant time.
fn ct_lt(a: &[u8; BLS_SK_LEN], b: &[u8; BLS_SK_LEN]) -> Choice {
  // The borrow out of `a - b`, from the least significant byte up.
  let borrow = a.iter().zip(b).rev().fold(0u16, |borrow, (&x, &y)| {
    (u16::from(x).wrapping_sub(u16::from(y)).wrapping_sub(borrow) >> 8) & 1
  });
  Choice::from(borrow as u8)
}

/// The basic encoding of a canonical legacy G1 encoding.
fn g1_legacy_to_basic(legacy: &[u8; BLS_PK_LEN]) -> [u8; BLS_PK_LEN] {
  BlsScChia::pk_ietf_bytes(legacy)
}

/// The legacy encoding of a canonical basic G1 encoding: the sign moves from
/// bit 0x20 to bit 0x80, which no longer marks compression.
fn g1_basic_to_legacy(basic: &[u8; BLS_PK_LEN]) -> [u8; BLS_PK_LEN] {
  let mut out = *basic;
  out[0] &= COORD_MASK;
  if basic[0] & FLAG_SIGN != 0 {
    out[0] |= FLAG_HIGH;
  }
  out
}

/// The basic encoding of a canonical legacy G2 encoding: `x.c1` comes first,
/// with compression and the sign at bit 0x20.
fn g2_legacy_to_basic(legacy: &[u8; BLS_SIG_LEN]) -> [u8; BLS_SIG_LEN] {
  let mut out = BlsScChia::sig_ietf_x_bytes(legacy);
  if legacy[0] & FLAG_HIGH != 0 {
    out[0] |= FLAG_SIGN;
  }
  out
}

/// The legacy encoding of a canonical basic G2 encoding: `x.c0` comes first,
/// with the sign at bit 0x80.
fn g2_basic_to_legacy(basic: &[u8; BLS_SIG_LEN]) -> [u8; BLS_SIG_LEN] {
  let mut out = *basic;
  out.rotate_left(BLS_SIG_LEN / 2);
  out[BLS_SIG_LEN / 2] &= COORD_MASK;
  if basic[0] & FLAG_SIGN != 0 {
    out[0] |= FLAG_HIGH;
  }
  out
}

/// The point of a canonical encoding, usable when it is in the subgroup.
fn classify<A>(point: Option<A>, in_subgroup: impl Fn(&A) -> bool) -> BlsPoint<A> {
  point.filter(in_subgroup).map_or(BlsPoint::Exotic, BlsPoint::Usable)
}

impl Sealed for G1 {}

impl BlsWire<BLS_PK_LEN> for G1 {
  type Point = BlsPoint<G1Affine>;

  const INVALID: BlsError = BlsError::InvalidPublicKey;

  /// Under the legacy scheme the point is exotic when it is outside the
  /// subgroup, or when the encoded `x` has no point on the curve.
  fn decode(bytes: &[u8; BLS_PK_LEN], scheme: BlsSchemeKind) -> Option<([u8; BLS_PK_LEN], Self::Point)> {
    if !Self::is_canonical(bytes, scheme) {
      return None;
    }
    Some(match scheme {
      BlsSchemeKind::Basic => (*bytes, BlsPoint::Usable(G1Affine::uncompress(bytes).ok()?)),
      BlsSchemeKind::Legacy => {
        let point = BlsScChia::pk_from_bytes(bytes).ok();
        let point = classify(point, |p| p.to_projective().in_subgroup());
        (g1_legacy_to_basic(bytes), point)
      }
    })
  }

  fn is_canonical(bytes: &[u8; BLS_PK_LEN], scheme: BlsSchemeKind) -> bool {
    match scheme {
      BlsSchemeKind::Basic => BlsScIetf::is_canonical_pk(bytes),
      BlsSchemeKind::Legacy => BlsScChia::is_canonical_pk(bytes),
    }
  }

  fn encode(basic: &[u8; BLS_PK_LEN], scheme: BlsSchemeKind) -> [u8; BLS_PK_LEN] {
    match scheme {
      BlsSchemeKind::Basic => *basic,
      BlsSchemeKind::Legacy => g1_basic_to_legacy(basic),
    }
  }
}

impl Sealed for G2 {}

impl BlsWire<BLS_SIG_LEN> for G2 {
  type Point = BlsPoint<G2Affine>;

  const INVALID: BlsError = BlsError::InvalidSignature;

  /// Under the legacy scheme the point is exotic when it is outside the
  /// subgroup, or when the encoded `x` has no point on the curve.
  fn decode(bytes: &[u8; BLS_SIG_LEN], scheme: BlsSchemeKind) -> Option<([u8; BLS_SIG_LEN], Self::Point)> {
    if !Self::is_canonical(bytes, scheme) {
      return None;
    }
    Some(match scheme {
      BlsSchemeKind::Basic => (*bytes, BlsPoint::Usable(G2Affine::uncompress(bytes).ok()?)),
      BlsSchemeKind::Legacy => {
        let point = BlsScChia::sig_from_bytes(bytes).ok();
        let point = classify(point, |p| p.to_projective().in_subgroup());
        (g2_legacy_to_basic(bytes), point)
      }
    })
  }

  fn is_canonical(bytes: &[u8; BLS_SIG_LEN], scheme: BlsSchemeKind) -> bool {
    match scheme {
      BlsSchemeKind::Basic => BlsScIetf::is_canonical_sig(bytes),
      BlsSchemeKind::Legacy => BlsScChia::is_canonical_sig(bytes),
    }
  }

  fn encode(basic: &[u8; BLS_SIG_LEN], scheme: BlsSchemeKind) -> [u8; BLS_SIG_LEN] {
    match scheme {
      BlsSchemeKind::Basic => *basic,
      BlsSchemeKind::Legacy => g2_basic_to_legacy(basic),
    }
  }
}

/// Whether secret key bytes are canonical under `scheme`, in constant time.
///
/// Secret keys are written alike under both schemes. The legacy scheme reads
/// them modulo `r`, so only keys below `r` encode back to their bytes. The
/// basic scheme refuses keys above `r` and keeps `r` itself unreduced.
pub(super) fn sk_is_canonical(bytes: &[u8; BLS_SK_LEN], scheme: BlsSchemeKind) -> bool {
  let in_range = match scheme {
    BlsSchemeKind::Legacy => ct_lt(bytes, &GROUP_ORDER),
    BlsSchemeKind::Basic => !ct_lt(&GROUP_ORDER, bytes),
  };
  bool::from(in_range & !bytes.ct_eq(&[0u8; BLS_SK_LEN]))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bls::tests::{
    chia_pk_off_curve, G1_OFF_SUBGROUP_CHIA, G1_OFF_SUBGROUP_IETF, G1_X_EQ_PRIME_CHIA, G2_OFF_SUBGROUP_CHIA,
  };

  use rstest::rstest;

  /// `r` with its last byte, 0x01, replaced.
  fn order_with_last(last: u8) -> [u8; BLS_SK_LEN] {
    let mut key = GROUP_ORDER;
    key[BLS_SK_LEN - 1] = last;
    key
  }

  /// The keys at each end of each scheme's range.
  #[rstest]
  #[case::r_minus_1(order_with_last(0x00), true, true)]
  #[case::r(GROUP_ORDER, false, true)]
  #[case::r_plus_1(order_with_last(0x02), false, false)]
  #[case::max([0xff; BLS_SK_LEN], false, false)]
  fn secret_key_range(#[case] key: [u8; BLS_SK_LEN], #[case] legacy: bool, #[case] basic: bool) {
    assert_eq!(sk_is_canonical(&key, BlsSchemeKind::Legacy), legacy);
    assert_eq!(sk_is_canonical(&key, BlsSchemeKind::Basic), basic);
  }

  #[rstest]
  #[case::legacy(BlsSchemeKind::Legacy)]
  #[case::basic(BlsSchemeKind::Basic)]
  fn zero_bytes_are_never_canonical(#[case] scheme: BlsSchemeKind) {
    assert!(G1::decode(&[0u8; BLS_PK_LEN], scheme).is_none());
    assert!(G2::decode(&[0u8; BLS_SIG_LEN], scheme).is_none());
    assert!(!sk_is_canonical(&[0u8; BLS_SK_LEN], scheme));
  }

  /// A legacy point outside the subgroup decodes as exotic and encodes back
  /// to its bytes. Its basic encoding is not canonical, as the basic scheme
  /// checks the subgroup.
  #[test]
  fn legacy_points_off_the_subgroup_are_exotic() {
    let decoded = G1::decode(&G1_OFF_SUBGROUP_CHIA, BlsSchemeKind::Legacy);
    assert_eq!(decoded, Some((G1_OFF_SUBGROUP_IETF, BlsPoint::Exotic)));
    assert_eq!(
      G1::encode(&G1_OFF_SUBGROUP_IETF, BlsSchemeKind::Legacy),
      G1_OFF_SUBGROUP_CHIA
    );
    assert!(!G1::is_canonical(&G1_OFF_SUBGROUP_IETF, BlsSchemeKind::Basic));

    let decoded = G2::decode(&G2_OFF_SUBGROUP_CHIA, BlsSchemeKind::Legacy);
    assert!(decoded.is_some_and(|(basic, point)| {
      point == BlsPoint::Exotic && G2::encode(&basic, BlsSchemeKind::Legacy) == G2_OFF_SUBGROUP_CHIA
    }));
  }

  /// A legacy encoding of an `x` with no point on the curve, here `p - 1`
  /// with bit 0x80 set, decodes as exotic and encodes back to its bytes.
  #[test]
  fn legacy_points_off_the_curve_are_exotic() {
    let mut legacy = G1_X_EQ_PRIME_CHIA;
    legacy[0] |= FLAG_HIGH;
    legacy[BLS_PK_LEN - 1] -= 1;
    assert!(chia_pk_off_curve(&legacy));

    let decoded = G1::decode(&legacy, BlsSchemeKind::Legacy);
    assert!(decoded.is_some_and(|(basic, point)| {
      point == BlsPoint::Exotic && G1::encode(&basic, BlsSchemeKind::Legacy) == legacy
    }));
  }
}
