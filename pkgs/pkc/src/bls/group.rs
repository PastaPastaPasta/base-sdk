//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The BLS12-381 groups G1 and G2.

use super::macros::impl_group;
use super::scalar::{Fp, Fp2, Fr, FR_BITS};

use blst::{blst_p1, blst_p1_affine, blst_p2, blst_p2_affine};
use dash_types::type_cvrt;
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use hex_conservative::DisplayHex;
use rand_core::TryRng;
use subtle::{Choice, CtOption};
use zeroize::Zeroize;

use core::fmt::{self, Debug, Formatter};
use core::iter::Sum;
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

/// A projective group element supporting curve addition and scalar multiply.
pub(crate) trait Point: Copy + Default + Add<Output = Self> {
  /// The group identity (point at infinity).
  fn identity() -> Self {
    Self::default()
  }

  /// Scalar multiplication by a little-endian scalar of `nbits` bits.
  fn mul_scalar(&self, scalar: &[u8], nbits: usize) -> Self;
}

/// The compressed encoding of a group element, `N` bytes wide.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsPointRepr<const N: usize>([u8; N]);

impl<const N: usize> BlsPointRepr<N> {
  /// Borrows the encoding as a fixed-width array.
  pub(crate) fn as_bytes(&self) -> &[u8; N] {
    &self.0
  }
}

impl<const N: usize> AsMut<[u8]> for BlsPointRepr<N> {
  fn as_mut(&mut self) -> &mut [u8] {
    &mut self.0
  }
}

impl<const N: usize> AsRef<[u8]> for BlsPointRepr<N> {
  fn as_ref(&self) -> &[u8] {
    &self.0
  }
}

impl<const N: usize> Default for BlsPointRepr<N> {
  fn default() -> Self {
    Self([0u8; N])
  }
}

impl<const N: usize> From<[u8; N]> for BlsPointRepr<N> {
  fn from(bytes: [u8; N]) -> Self {
    Self(bytes)
  }
}

/// A point of the G1 group (over `Fp`) in projective coordinates.
#[derive(Clone, Copy, Default)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct G1(pub(super) blst_p1);

type_cvrt!(From<G1> for blst_p1, |g| g.0);

type_cvrt!(From<blst_p1> for G1, |raw| Self(*raw));

/// A point of the G1 group in affine coordinates.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct G1Affine(pub(super) blst_p1_affine);

impl G1Affine {
  /// The affine point with coordinates `x` and `y`, unchecked.
  pub(crate) fn from_coords(x: Fp, y: Fp) -> Self {
    Self(blst_p1_affine {
      x: x.into(),
      y: y.into(),
    })
  }

  /// The `x` coordinate.
  pub(crate) fn x(&self) -> Fp {
    Fp::from(self.0.x)
  }

  /// The `y` coordinate.
  pub(crate) fn y(&self) -> Fp {
    Fp::from(self.0.y)
  }
}

impl_group!(G1, G1Affine, 48);

type_cvrt!(From<G1Affine> for blst_p1_affine, |a| a.0);

type_cvrt!(From<blst_p1_affine> for G1Affine, |raw| Self(*raw));

/// A point of the G2 group (over `Fp2`) in projective coordinates.
#[derive(Clone, Copy, Default)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct G2(pub(super) blst_p2);

type_cvrt!(From<blst_p2> for G2, |raw| Self(*raw));

type_cvrt!(From<G2> for blst_p2, |g| g.0);

/// A point of the G2 group in affine coordinates.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct G2Affine(pub(super) blst_p2_affine);

impl G2Affine {
  /// Construct from affine `x` and `y` coordinates in `Fp2`.
  pub(crate) fn from_coords(x: Fp2, y: Fp2) -> Self {
    Self(blst_p2_affine {
      x: x.into(),
      y: y.into(),
    })
  }

  /// The affine `x` coordinate.
  pub(crate) fn x(&self) -> Fp2 {
    Fp2::from(self.0.x)
  }

  /// The affine `y` coordinate.
  pub(crate) fn y(&self) -> Fp2 {
    Fp2::from(self.0.y)
  }
}

type_cvrt!(From<G2Affine> for blst_p2_affine, |a| a.0);

type_cvrt!(From<blst_p2_affine> for G2Affine, |raw| Self(*raw));

impl_group!(G2, G2Affine, 96);

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bls::tests::{G1_OFF_SUBGROUP_IETF, G2_OFF_SUBGROUP_IETF};

  use getrandom::SysRng;
  use rand_core::UnwrapErr;
  use rstest::rstest;

  fn assert_group_axioms<G: Group<Scalar = Fr>>() {
    let mut rng = UnwrapErr(SysRng);
    let a = G::random(&mut rng);
    let b = G::random(&mut rng);

    assert_eq!(a + b, b + a);
    assert_eq!(a + b - b, a);
    assert_eq!(a + a, a.double());
    assert_eq!(-a + a, G::identity());
    assert!(bool::from(G::identity().is_identity()));
    assert!(!bool::from(a.is_identity()));
  }

  #[rstest]
  #[case::g1(assert_group_axioms::<G1>)]
  #[case::g2(assert_group_axioms::<G2>)]
  fn group_axioms(#[case] assertion: fn()) {
    assertion();
  }

  /// Scalar multiplication has to agree with repeated addition, which is the
  /// one place a wrong bit width or byte order would show up.
  fn assert_scalar_mul_matches_addition<G: Group<Scalar = Fr>>() {
    let g = G::generator();
    let three = g + g + g;

    assert_eq!(g * Fr::from(3), three);
    assert_eq!(G::mul_by_generator(&Fr::from(3)), three);
    assert_eq!(g * Fr::ZERO, G::identity());
    assert_eq!(g * -Fr::ONE, -g);
  }

  #[rstest]
  #[case::g1(assert_scalar_mul_matches_addition::<G1>)]
  #[case::g2(assert_scalar_mul_matches_addition::<G2>)]
  fn scalar_mul_matches_addition(#[case] assertion: fn()) {
    assertion();
  }

  /// The unchecked decoder is the one that admits a composite-order point,
  /// which is the whole of what separates the two.
  #[rstest]
  #[case::g1(
    G1::from_bytes(&G1_OFF_SUBGROUP_IETF.into()).is_none(),
    G1::from_bytes_unchecked(&G1_OFF_SUBGROUP_IETF.into()).is_some()
  )]
  #[case::g2(
    G2::from_bytes(&G2_OFF_SUBGROUP_IETF.into()).is_none(),
    G2::from_bytes_unchecked(&G2_OFF_SUBGROUP_IETF.into()).is_some()
  )]
  fn checked_decoding_refuses_off_subgroup_points(#[case] refused: Choice, #[case] admitted: Choice) {
    assert!(bool::from(refused));
    assert!(bool::from(admitted));
  }

  #[rstest]
  fn decoding_refuses_malformed_encodings() {
    assert!(bool::from(G1::from_bytes(&[0xff; 48].into()).is_none()));
    assert!(bool::from(G2::from_bytes(&[0xff; 96].into()).is_none()));
  }
}
