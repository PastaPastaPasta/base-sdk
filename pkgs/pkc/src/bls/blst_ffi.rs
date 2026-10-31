//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Bridging routines for unsafe blst FFI operations.

use super::group::{G1Affine, G2Affine, Point, G1, G2};
use super::scalar::{Fp, Fp2, Fr};

use blst::*;
use dash_types::type_cvrt;
use zeroize::{Zeroize, Zeroizing};

use core::ops::{Add, Mul, Neg, Sub};
use core::ptr::null_mut;

/// Serialize a scalar to its 32-byte big-endian encoding.
pub(crate) fn bendian_from_scalar(scalar: &blst_scalar) -> [u8; 32] {
  let mut out = [0u8; 32];
  unsafe { blst_bendian_from_scalar(out.as_mut_ptr(), scalar) };
  out
}

/// Whether `e(G1 generator, lhs_g2)` equals the product of `e(g1, g2)` over
/// the paired slices, the multi-pairing behind per-signer-message verifying.
pub(crate) fn pairings_equal_with_g1_generator_prod(lhs_g2: &G2Affine, rhs_g2: &[G2], rhs_g1: &[&G1Affine]) -> bool {
  if rhs_g2.len() != rhs_g1.len() || rhs_g2.is_empty() {
    return false;
  }

  let lhs_g2_aff = blst_p2_affine::from(*lhs_g2);
  let g1_generator = blst_p1_affine::from(G1Affine::generator());
  let mut lhs = blst_fp12::default();

  unsafe {
    blst_miller_loop(&mut lhs, &lhs_g2_aff, &g1_generator);
    let mut rhs = *blst_fp12_one();
    for (g2, g1) in rhs_g2.iter().zip(rhs_g1) {
      let g2_aff = blst_p2_affine::from(g2.to_affine());
      let g1_aff = blst_p1_affine::from(**g1);
      let mut term = blst_fp12::default();
      blst_miller_loop(&mut term, &g2_aff, &g1_aff);
      let acc = rhs;
      blst_fp12_mul(&mut rhs, &acc, &term);
    }
    blst_fp12_finalverify(&lhs, &rhs)
  }
}

/// Pairing check `e(lhs_g2, G1) == e(rhs_g2, rhs_g1)`
pub(crate) fn pairings_equal_with_g1_generator(lhs_g2: &G2Affine, rhs_g2: &G2, rhs_g1: &G1Affine) -> bool {
  let lhs_g2_aff = blst_p2_affine::from(*lhs_g2);
  let rhs_g2_aff = blst_p2_affine::from(rhs_g2.to_affine());
  let rhs_g1_aff = blst_p1_affine::from(*rhs_g1);
  let g1_generator = blst_p1_affine::from(G1Affine::generator());
  let mut lhs = blst_fp12::default();
  let mut rhs = blst_fp12::default();
  unsafe {
    blst_miller_loop(&mut lhs, &lhs_g2_aff, &g1_generator);
    blst_miller_loop(&mut rhs, &rhs_g2_aff, &rhs_g1_aff);
    blst_fp12_finalverify(&lhs, &rhs)
  }
}

/// Interpret 32 big-endian bytes as a 256-bit scalar.
pub(crate) fn scalar_from_bendian(bytes: &[u8; 32]) -> blst_scalar {
  let mut scalar = blst_scalar::default();
  unsafe { blst_scalar_from_bendian(&mut scalar, bytes.as_ptr()) };
  scalar
}

/// Whether the scalar is a valid BLS secret key, i.e. non-zero and less
/// than the group order.
pub(crate) fn sk_check(sk: &blst_scalar) -> bool {
  unsafe { blst_sk_check(sk) }
}

/// Derive the G1 public key `sk * G1_generator` for a secret-key scalar.
pub(crate) fn sk_to_pk2_in_g1(sk: &blst_scalar) -> G1Affine {
  let mut aff = blst_p1_affine::default();
  unsafe { blst_sk_to_pk2_in_g1(null_mut(), &mut aff, sk) };
  aff.into()
}

impl Fr {
  /// Doubles the element.
  pub(crate) fn double(&self) -> Self {
    let mut out = blst_fr::default();
    unsafe { blst_fr_lshift(&mut out, &self.0, 1) };
    Self(out)
  }

  /// Reduces a small integer into the field.
  pub(crate) fn from_u64(value: u64) -> Self {
    let mut out = blst_fr::default();
    let limbs = [value, 0, 0, 0];
    unsafe { blst_fr_from_uint64(&mut out, limbs.as_ptr()) };
    Self(out)
  }

  /// Parses a canonical little-endian encoding, rejecting anything at or above
  /// the group order.
  pub(crate) fn from_lendian(bytes: &[u8; 32]) -> Option<Self> {
    let mut scalar = blst_scalar::default();
    unsafe { blst_scalar_from_lendian(&mut scalar, bytes.as_ptr()) };
    let parsed = unsafe { blst_scalar_fr_check(&scalar) }.then(|| Self::from(&scalar));
    scalar.b.zeroize();
    parsed
  }

  /// Reduces a little-endian integer of any width into the field.
  ///
  /// Wider input than the modulus is the point; reducing 64 bytes into a
  /// 255-bit field leaves a bias below `2^-250`, where rejection sampling would
  /// need a loop and a branch on secret data.
  pub(crate) fn from_lendian_reduce(bytes: &[u8]) -> Self {
    let mut scalar = blst_scalar::default();
    unsafe { blst_scalar_from_le_bytes(&mut scalar, bytes.as_ptr(), bytes.len()) };
    let reduced = Self::from(&scalar);
    scalar.b.zeroize();
    reduced
  }

  /// Multiplicative inverse; the inverse of zero is left unspecified.
  pub(crate) fn inverse(&self) -> Self {
    let mut out = blst_fr::default();
    unsafe { blst_fr_inverse(&mut out, &self.0) };
    Self(out)
  }

  /// Squares the element.
  pub(crate) fn square(&self) -> Self {
    let mut out = blst_fr::default();
    unsafe { blst_fr_sqr(&mut out, &self.0) };
    Self(out)
  }

  /// Emits the canonical little-endian encoding.
  pub(crate) fn to_lendian(mut self) -> Zeroizing<[u8; 32]> {
    let mut scalar = blst_scalar::from(&self);
    let bytes = Zeroizing::new(scalar.b);
    scalar.b.zeroize();
    self.zeroize();
    bytes
  }
}

// `Fr` is `Copy`, so the operands arrive as copies the caller cannot wipe.
impl Add for Fr {
  type Output = Self;

  fn add(mut self, mut rhs: Self) -> Self::Output {
    let mut out = blst_fr::default();
    unsafe { blst_fr_add(&mut out, &self.0, &rhs.0) };
    self.zeroize();
    rhs.zeroize();
    Self(out)
  }
}

impl Mul for Fr {
  type Output = Self;

  fn mul(mut self, mut rhs: Self) -> Self::Output {
    let mut out = blst_fr::default();
    unsafe { blst_fr_mul(&mut out, &self.0, &rhs.0) };
    self.zeroize();
    rhs.zeroize();
    Self(out)
  }
}

impl Neg for Fr {
  type Output = Self;

  fn neg(mut self) -> Self::Output {
    let mut out = blst_fr::default();
    unsafe { blst_fr_cneg(&mut out, &self.0, true) };
    self.zeroize();
    Self(out)
  }
}

impl Sub for Fr {
  type Output = Self;

  fn sub(mut self, mut rhs: Self) -> Self::Output {
    let mut out = blst_fr::default();
    unsafe { blst_fr_sub(&mut out, &self.0, &rhs.0) };
    self.zeroize();
    rhs.zeroize();
    Self(out)
  }
}

type_cvrt!(From<blst_scalar> for Fr, |s| {
  let mut out = blst_fr::default();
  unsafe { blst_fr_from_scalar(&mut out, s) };
  Self(out)
});

type_cvrt!(From<Fr> for blst_scalar, |fr| {
  let mut out = blst_scalar::default();
  unsafe { blst_scalar_from_fr(&mut out, &fr.0) };
  out
});

impl Add for Fp {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp::default();
    unsafe { blst_fp_add(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Mul for Fp {
  type Output = Self;

  fn mul(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp::default();
    unsafe { blst_fp_mul(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Neg for Fp {
  type Output = Self;

  fn neg(self) -> Self::Output {
    let mut out = blst_fp::default();
    unsafe { blst_fp_cneg(&mut out, &self.0, true) };
    Self(out)
  }
}

impl Sub for Fp {
  type Output = Self;

  fn sub(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp::default();
    unsafe { blst_fp_sub(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

type_cvrt!(From<Fp> for [u8; 48], |fp| {
  let mut out = [0u8; 48];
  unsafe { blst_bendian_from_fp(out.as_mut_ptr(), &fp.0) };
  out
});

type_cvrt!(From<[u8; 48]> for Fp, |bytes| {
  let mut out = blst_fp::default();
  unsafe { blst_fp_from_bendian(&mut out, bytes.as_ptr()) };
  Self(out)
});

impl Fp2 {
  /// Multiplicative inverse; the inverse of zero is left unspecified.
  pub(crate) fn inverse(&self) -> Self {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_inverse(&mut out, &self.0) };
    Self(out)
  }

  /// A square root, or `None` when the value is not a quadratic residue.
  pub(crate) fn sqrt(&self) -> Option<Self> {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_sqrt(&mut out, &self.0) }.then_some(Self(out))
  }

  /// The square of this element.
  pub(crate) fn square(&self) -> Self {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_sqr(&mut out, &self.0) };
    Self(out)
  }
}

impl Add for Fp2 {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_add(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Mul for Fp2 {
  type Output = Self;

  fn mul(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_mul(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Neg for Fp2 {
  type Output = Self;

  fn neg(self) -> Self::Output {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_cneg(&mut out, &self.0, true) };
    Self(out)
  }
}

impl Sub for Fp2 {
  type Output = Self;

  fn sub(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_sub(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl G1 {
  /// Point doubling.
  pub(crate) fn double(&self) -> Self {
    let mut out = blst_p1::default();
    unsafe { blst_p1_double(&mut out, &self.0) };
    Self(out)
  }

  /// The conventional G1 generator.
  pub(crate) fn generator() -> Self {
    Self(unsafe { *blst_p1_generator() })
  }

  /// Whether the point lies in the prime-order subgroup.
  pub(crate) fn in_subgroup(&self) -> bool {
    unsafe { blst_p1_in_g1(&self.0) }
  }

  /// Whether two points are equal as group elements, projective coordinates
  /// notwithstanding.
  pub(crate) fn is_equal(&self, other: &Self) -> bool {
    unsafe { blst_p1_is_equal(&self.0, &other.0) }
  }

  /// Whether the point is at infinity, the group identity.
  pub(crate) fn is_inf(&self) -> bool {
    unsafe { blst_p1_is_inf(&self.0) }
  }

  /// Convert to affine coordinates.
  pub(crate) fn to_affine(self) -> G1Affine {
    let mut aff = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut aff, &self.0) };
    G1Affine(aff)
  }
}

impl Add for G1 {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    let mut out = blst_p1::default();
    unsafe { blst_p1_add_or_double(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Neg for G1 {
  type Output = Self;

  fn neg(self) -> Self::Output {
    let mut out = self.0;
    unsafe { blst_p1_cneg(&mut out, true) };
    Self(out)
  }
}

impl Point for G1 {
  fn mul_scalar(&self, scalar: &[u8], nbits: usize) -> Self {
    // Clamp to the bits actually backed by the slice: blst reads
    // ceil(nbits/8) bytes, so a larger nbits would read out of bounds.
    let nbits = nbits.min(scalar.len() * 8);
    let mut out = blst_p1::default();
    unsafe { blst_p1_mult(&mut out, &self.0, scalar.as_ptr(), nbits) };
    Self(out)
  }
}

impl G1Affine {
  /// The conventional G1 generator.
  pub(crate) fn generator() -> Self {
    Self(unsafe { *blst_p1_affine_generator() })
  }

  /// Convert to projective coordinates.
  pub(crate) fn to_projective(self) -> G1 {
    let mut out = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut out, &self.0) };
    G1(out)
  }

  /// Serialize to the 48-byte compressed encoding.
  pub(crate) fn compress(&self) -> [u8; 48] {
    let mut out = [0u8; 48];
    unsafe { blst_p1_affine_compress(out.as_mut_ptr(), &self.0) };
    out
  }

  /// Uncompress a 48-byte G1 point.
  ///
  /// # Errors
  ///
  /// Returns the blst error code when the bytes do not encode a valid
  /// compressed G1 point.
  pub(crate) fn uncompress(bytes: &[u8; 48]) -> Result<Self, BLST_ERROR> {
    let mut aff = blst_p1_affine::default();
    let rc = unsafe { blst_p1_uncompress(&mut aff, bytes.as_ptr()) };
    if rc != BLST_ERROR::BLST_SUCCESS {
      return Err(rc);
    }
    Ok(Self(aff))
  }

  /// Uncompress a 48-byte G1 point as [`uncompress`](Self::uncompress) does,
  /// adding only `x = 0` with the sign bit set, (0, -2), which blst writes out
  /// and then reports as an error.
  ///
  /// # Errors
  ///
  /// Returns the blst error code when the bytes are not a compressed point
  /// blst accepts, other than (0, -2).
  pub(crate) fn uncompress_on_curve(bytes: &[u8; 48]) -> Result<Self, BLST_ERROR> {
    let mut aff = blst_p1_affine::default();
    let rc = unsafe { blst_p1_uncompress(&mut aff, bytes.as_ptr()) };
    let x_is_zero = bytes[0] & 0x1f == 0 && bytes[1..].iter().all(|&b| b == 0);
    match rc {
      BLST_ERROR::BLST_SUCCESS => Ok(Self(aff)),
      BLST_ERROR::BLST_POINT_NOT_IN_GROUP if x_is_zero && bytes[0] & 0x20 != 0 => Ok(Self(aff)),
      rc => Err(rc),
    }
  }

  /// Deserialize a 96-byte uncompressed G1 point.
  ///
  /// # Errors
  ///
  /// Returns the blst error code when the bytes do not encode a point on the
  /// curve.
  pub(crate) fn deserialize(bytes: &[u8; 96]) -> Result<Self, BLST_ERROR> {
    let mut aff = blst_p1_affine::default();
    let rc = unsafe { blst_p1_deserialize(&mut aff, bytes.as_ptr()) };
    if rc != BLST_ERROR::BLST_SUCCESS {
      return Err(rc);
    }
    Ok(Self(aff))
  }
}

impl G2 {
  /// The conventional G2 generator.
  pub(crate) fn generator() -> Self {
    Self(unsafe { *blst_p2_generator() })
  }

  /// Whether the point lies in the prime-order subgroup.
  pub(crate) fn in_subgroup(&self) -> bool {
    unsafe { blst_p2_in_g2(&self.0) }
  }

  /// Whether two points are equal as group elements, notwithstanding projective
  /// coordinates.
  pub(crate) fn is_equal(&self, other: &Self) -> bool {
    unsafe { blst_p2_is_equal(&self.0, &other.0) }
  }

  /// Whether the point is at infinity, the group identity.
  pub(crate) fn is_inf(&self) -> bool {
    unsafe { blst_p2_is_inf(&self.0) }
  }

  /// Point doubling.
  pub(crate) fn double(&self) -> Self {
    let mut out = blst_p2::default();
    unsafe { blst_p2_double(&mut out, &self.0) };
    Self(out)
  }

  /// Convert to affine coordinates.
  pub(crate) fn to_affine(self) -> G2Affine {
    let mut aff = blst_p2_affine::default();
    unsafe { blst_p2_to_affine(&mut aff, &self.0) };
    G2Affine(aff)
  }
}

impl Add for G2 {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    let mut out = blst_p2::default();
    unsafe { blst_p2_add_or_double(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Neg for G2 {
  type Output = Self;

  fn neg(self) -> Self::Output {
    let mut out = self.0;
    unsafe { blst_p2_cneg(&mut out, true) };
    Self(out)
  }
}

impl Point for G2 {
  fn mul_scalar(&self, scalar: &[u8], nbits: usize) -> Self {
    // Clamp to the bits actually backed by the slice: blst reads
    // ceil(nbits/8) bytes, so a larger nbits would read out of bounds.
    let nbits = nbits.min(scalar.len() * 8);
    let mut out = blst_p2::default();
    unsafe { blst_p2_mult(&mut out, &self.0, scalar.as_ptr(), nbits) };
    Self(out)
  }
}

impl G2Affine {
  /// Convert to projective coordinates.
  pub(crate) fn to_projective(self) -> G2 {
    let mut out = blst_p2::default();
    unsafe { blst_p2_from_affine(&mut out, &self.0) };
    G2(out)
  }

  /// Whether the point is at infinity.
  pub(crate) fn is_inf(&self) -> bool {
    unsafe { blst_p2_affine_is_inf(&self.0) }
  }

  /// Serialize to the 96-byte compressed encoding.
  pub(crate) fn compress(&self) -> [u8; 96] {
    let mut out = [0u8; 96];
    unsafe { blst_p2_affine_compress(out.as_mut_ptr(), &self.0) };
    out
  }

  /// Serialize to the 192-byte uncompressed encoding.
  pub(crate) fn serialize(&self) -> [u8; 192] {
    let mut out = [0u8; 192];
    unsafe { blst_p2_affine_serialize(out.as_mut_ptr(), &self.0) };
    out
  }

  /// Uncompress a 96-byte G2 point.
  ///
  /// # Errors
  ///
  /// Returns the blst error code when the bytes do not encode a valid
  /// compressed G2 point.
  pub(crate) fn uncompress(bytes: &[u8; 96]) -> Result<Self, BLST_ERROR> {
    let mut aff = blst_p2_affine::default();
    let rc = unsafe { blst_p2_uncompress(&mut aff, bytes.as_ptr()) };
    if rc != BLST_ERROR::BLST_SUCCESS {
      return Err(rc);
    }
    Ok(Self(aff))
  }

  /// Deserialize a 192-byte uncompressed G2 point.
  ///
  /// # Errors
  ///
  /// Returns the blst error code when the bytes do not encode a point on the
  /// curve.
  pub(crate) fn deserialize(bytes: &[u8; 192]) -> Result<Self, BLST_ERROR> {
    let mut aff = blst_p2_affine::default();
    let rc = unsafe { blst_p2_deserialize(&mut aff, bytes.as_ptr()) };
    if rc != BLST_ERROR::BLST_SUCCESS {
      return Err(rc);
    }
    Ok(Self(aff))
  }
}
