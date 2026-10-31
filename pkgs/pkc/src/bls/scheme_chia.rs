//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS scheme implementation.

use super::blst_ffi;
use super::chia_h2c;
use super::curve_consts::HALF_P;
use super::error::BlsError;
use super::group::{G1Affine, G2Affine, Point, G1, G2};
use super::scalar::FR_BITS;
use super::scheme_ops::BlsScheme;
use super::schemes::BlsScChia;
use crate::prelude::*;
use crate::sealed::Sealed;

use blst::min_pk;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// y.c1 > (p-1)/2, matching the legacy sign convention.
fn y_c1_is_larger(y_c1: &[u8]) -> bool {
  y_c1.len() >= 48 && y_c1[..48] > HALF_P[..]
}

impl Sealed for BlsScChia {}

impl BlsScheme for BlsScChia {
  type InnerSk = blst::blst_scalar;
  type InnerPk = G1Affine;
  type InnerSig = G2Affine;
  type Msg<'a> = [u8; 32];

  /// Derive via draft-03 keygen, then range-check the scalar.
  fn sk_from_ikm(ikm: &[u8]) -> Result<Self::InnerSk, BlsError> {
    let sk = min_pk::SecretKey::key_gen_v3(ikm, &[]).map_err(|_| BlsError::InvalidKeyMaterial)?;
    let mut bytes = sk.to_bytes();
    let res = Self::sk_from_bytes(&bytes);
    bytes.zeroize();
    res
  }

  /// Interpret the bytes as a scalar and reject out-of-range values.
  fn sk_from_bytes(b: &[u8; 32]) -> Result<Self::InnerSk, BlsError> {
    let scalar = blst_ffi::scalar_from_bendian(b);
    if blst_ffi::sk_check(&scalar) {
      Ok(scalar)
    } else {
      Err(BlsError::InvalidSecretKey)
    }
  }

  /// Emit the scalar as big-endian bytes.
  fn sk_to_bytes(sk: &Self::InnerSk) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blst_ffi::bendian_from_scalar(sk))
  }

  /// Multiply the G1 generator by the secret scalar.
  fn derive_pk(sk: &Self::InnerSk) -> Self::InnerPk {
    blst_ffi::sk_to_pk2_in_g1(sk)
  }

  /// Wipe the scalar limbs.
  fn zeroize_sk(sk: &mut Self::InnerSk) {
    sk.b.zeroize();
  }

  /// Decode a G1 point from the legacy 48-byte format.
  ///
  /// No prime-order subgroup check is performed on the legacy path, for
  /// backwards compatibility: checking here would reject keys the legacy
  /// format accepts.
  ///
  /// `x = 0` with the sign bit set decodes to (0, -2), which blst's
  /// decompression alone refuses.
  fn pk_from_bytes(b: &[u8; 48]) -> Result<Self::InnerPk, BlsError> {
    // Reject the all-zero encoding and the infinity marker.
    if b.iter().all(|&byte| byte == 0) || b[0] & 0xc0 == 0xc0 {
      return Err(BlsError::InvalidPublicKey);
    }

    G1Affine::uncompress_on_curve(&Self::pk_ietf_bytes(b)).map_err(|_| BlsError::InvalidPublicKey)
  }

  /// Encode a G1 point in the legacy 48-byte format.
  fn pk_to_bytes(pk: &Self::InnerPk) -> [u8; 48] {
    Self::g1_bytes(pk)
  }

  /// Encode a G1 point in the legacy 48-byte layout, the IETF compressed form
  /// with the sign at bit 7 and no compression bit, or the IETF encoding of
  /// infinity unchanged.
  fn g1_bytes(point: &G1Affine) -> [u8; 48] {
    let ietf = point.compress();

    if ietf[0] & 0xc0 == 0xc0 {
      return ietf; // infinity is the same in both formats
    }

    // IETF sets bit 7 for compression and bit 5 for the sign. Legacy sets
    // bit 7 for the sign and has no compression bit.
    let sign = (ietf[0] >> 5) & 1;
    let mut legacy = ietf;
    legacy[0] &= 0x1f;
    if sign == 1 {
      legacy[0] |= 0x80;
    }
    legacy
  }

  /// The IETF compressed form of a legacy G1 encoding of a point other than
  /// infinity.
  fn pk_ietf_bytes(b: &[u8; 48]) -> [u8; 48] {
    let mut ietf = *b;
    // Only bit 7 is the legacy sign flag; normalize away stray high bits
    // rather than rejecting, to stay bit-for-bit compatible on the wire.
    ietf[0] &= 0x1f;
    ietf[0] |= 0x80; // compression
    if b[0] & 0x80 != 0 {
      ietf[0] |= 0x20; // sign
    }
    ietf
  }

  /// The legacy public key is already an affine G1 point.
  fn pk_to_g1(pk: &Self::InnerPk) -> Result<G1, BlsError> {
    Ok(pk.to_projective())
  }

  /// The legacy public key is an affine G1 point; no re-validation.
  fn g1_to_pk(point: G1) -> Result<Self::InnerPk, BlsError> {
    Ok(point.to_affine())
  }

  /// Decode the legacy encoding through `pk_from_bytes`, which rejects the
  /// infinity marker and the all-zero buffer before the point is weighted.
  fn secure_agg_point(pk_bytes: &[u8; 48]) -> Result<G1, BlsError> {
    Self::pk_to_g1(&Self::pk_from_bytes(pk_bytes)?)
  }

  /// Decode a G2 point from the legacy 96-byte format.
  ///
  /// No prime-order subgroup check is performed on the legacy path, for
  /// backwards compatibility: checking here would reject signatures the
  /// legacy format accepts.
  fn sig_from_bytes(b: &[u8; 96]) -> Result<Self::InnerSig, BlsError> {
    // Reject the all-zero encoding and the infinity marker.
    if b.iter().all(|&byte| byte == 0) || b[0] & 0xc0 == 0xc0 {
      return Err(BlsError::InvalidSignature);
    }

    let sign = (b[0] >> 7) & 1;

    // After swizzling, byte 48 (top of `x.c1`) sits in the IETF flag byte,
    // where blst reads flags instead of range-checking, so reject its stray
    // high bits here: kept, they would make `x.c1 >= p`.
    if b[48] & 0xe0 != 0 {
      return Err(BlsError::InvalidSignature);
    }

    let mut x_c0 = [0u8; 48];
    x_c0.copy_from_slice(&b[..48]);
    // Clear only the sign bit: stray bits 5-6 make `x.c0 >= p`, rejected by
    // the decompression range check like any out-of-range coordinate.
    x_c0[0] &= 0x7f;
    let x_c1 = &b[48..96];

    let mut ietf = [0u8; 96];
    ietf[..48].copy_from_slice(x_c1);
    ietf[48..96].copy_from_slice(&x_c0);

    ietf[0] |= 0x80; // compression

    // Decompress with sign=0, then negate y if needed.
    let out = G2Affine::uncompress(&ietf).map_err(|_| BlsError::InvalidSignature)?;

    let decompressed_sign = y_c1_is_larger(&out.y().c1_bendian());
    if (sign == 1) != decompressed_sign {
      return Ok(G2Affine::from_coords(out.x(), -out.y()));
    }

    Ok(out)
  }

  /// Encode a G2 point in the legacy 96-byte format.
  ///
  /// Uses the uncompressed 192-byte intermediate to sidestep sign-bit
  /// convention differences: blst lays out `[x.c1, x.c0, y.c1, y.c0]`,
  /// legacy `[x.c0, x.c1]` with the sign at byte\[0\] bit 7.
  fn sig_to_bytes(sig: &Self::InnerSig) -> [u8; 96] {
    // Take blst's own infinity flag rather than testing the buffer: its
    // uncompressed form sets bit 6 of byte 0 and zeroes the rest, so an
    // all-zero test never fires and the swizzle would relocate that flag.
    if sig.is_inf() {
      let mut out = [0u8; 96];
      out[0] = 0xc0;
      return out;
    }

    let uncomp = sig.serialize();
    let x_c1 = &uncomp[0..48];
    let x_c0 = &uncomp[48..96];
    let y_c1 = &uncomp[96..144];

    let sign = y_c1_is_larger(y_c1);

    let mut legacy = [0u8; 96];
    legacy[..48].copy_from_slice(x_c0);
    legacy[48..96].copy_from_slice(x_c1);
    if sign {
      legacy[0] |= 0x80;
    }
    legacy
  }

  /// The legacy signature is already an affine G2 point.
  fn sig_to_g2(sig: &Self::InnerSig) -> Result<G2, BlsError> {
    Ok(sig.to_projective())
  }

  /// The legacy signature is an affine G2 point; no re-validation.
  fn g2_to_sig(point: G2) -> Result<Self::InnerSig, BlsError> {
    Ok(point.to_affine())
  }

  /// Hash the message to G2 and multiply by the secret scalar (no DST).
  fn sign(sk: &Self::InnerSk, msg: Self::Msg<'_>) -> Self::InnerSig {
    let h = chia_h2c::hash_to_g2(&msg);
    // blst_sign_pk_in_g1 applies IETF transformations, do manually instead.
    h.mul_scalar(&sk.b, FR_BITS).to_affine()
  }

  /// Check the pairing e(sig, G1) == e(H(msg), pk).
  fn verify(sig: &Self::InnerSig, msg: Self::Msg<'_>, pk: &Self::InnerPk) -> Result<(), BlsError> {
    let h_proj = chia_h2c::hash_to_g2(&msg);
    if blst_ffi::pairings_equal_with_g1_generator(sig, &h_proj, pk) {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
  }

  /// The legacy message is the 32-byte digest itself.
  fn digest_msg(digest: &[u8; 32]) -> Self::Msg<'_> {
    *digest
  }

  /// The legacy scheme signs the SHA-256 digest of the message.
  fn plaintext_msg(msg: &[u8]) -> Self::Msg<'_> {
    Sha256::digest(msg).into()
  }

  /// Sum the public keys in G1.
  fn aggregate_pk(pks: &[&Self::InnerPk]) -> Result<Self::InnerPk, BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let mut acc = pks[0].to_projective();
    for pk in &pks[1..] {
      acc += pk.to_projective();
    }
    Ok(acc.to_affine())
  }

  /// Sum the signatures in G2.
  fn aggregate_sig(sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError> {
    if sigs.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let mut acc = sigs[0].to_projective();
    for sig in &sigs[1..] {
      acc += sig.to_projective();
    }
    Ok(acc.to_affine())
  }

  /// Sum the keys, then verify once against the shared message.
  fn fast_verify_aggregates(sig: &Self::InnerSig, msg: Self::Msg<'_>, pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let agg_pk = Self::aggregate_pk(pks)?;
    Self::verify(sig, msg, &agg_pk)
  }

  /// Hash each message on its own, then verify all pairs in one multi-pairing.
  fn verify_aggregates(sig: &Self::InnerSig, msgs: &[Self::Msg<'_>], pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    if pks.len() != msgs.len() {
      return Err(BlsError::CountMismatch);
    }
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }

    let hashes: Vec<G2> = msgs.iter().map(chia_h2c::hash_to_g2).collect();
    if blst_ffi::pairings_equal_with_g1_generator_prod(sig, &hashes, pks) {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::tests::{ser_pairs, SerType, MSG_8BADFOOD, MSG_DEADBEEF, RSEED};

  use dash_dev::{arr_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct DhVector {
    sk: String,
    peer_pk: String,
    shared: String,
  }

  #[derive(Deserialize)]
  struct SignVector {
    sk: String,
    msg: String,
    sig: String,
  }

  #[test]
  fn dh_exchange_matches_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_dh").scope("chia");
    let vecs: Vec<DhVector> = corpus.vectors("dh");

    for v in &vecs {
      let sk = BlsScChia::sk_from_bytes(&arr_from_hex(&v.sk)).unwrap();
      let peer = BlsScChia::pk_from_bytes(&arr_from_hex(&v.peer_pk)).unwrap();
      let shared = BlsScChia::dh_exchange(&sk, &peer).unwrap();
      assert_eq!(BlsScChia::pk_to_bytes(&shared).to_lower_hex_string(), v.shared);
    }
  }

  #[test]
  fn signature_serialization_matches_vectors() {
    for (sig_legacy, sig_ietf) in ser_pairs(SerType::Signature) {
      let sig = BlsScChia::sig_from_bytes(&arr_from_hex(&sig_legacy)).unwrap();
      assert_eq!(BlsScChia::sig_to_bytes(&sig).to_lower_hex_string(), sig_legacy);
      assert_eq!(sig.compress().to_lower_hex_string(), sig_ietf);
      assert_ne!(sig_legacy, sig_ietf, "legacy and ietf should differ");
    }
  }

  #[test]
  fn signing_matches_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_sign").scope("chia");
    let vecs: Vec<SignVector> = corpus.vectors("sign");

    for v in &vecs {
      let sk = BlsScChia::sk_from_bytes(&arr_from_hex(&v.sk)).unwrap();
      let msg: [u8; 32] = arr_from_hex(&v.msg);
      let sig = BlsScChia::sign(&sk, msg);
      assert_eq!(BlsScChia::sig_to_bytes(&sig).to_lower_hex_string(), v.sig);
    }
  }

  #[test]
  fn signing_verifies_and_rejects_mismatches() {
    let sk0 = BlsScChia::sk_from_ikm(&RSEED[0]).unwrap();
    let sk1 = BlsScChia::sk_from_ikm(&RSEED[1]).unwrap();
    let pk0 = BlsScChia::derive_pk(&sk0);
    let pk1 = BlsScChia::derive_pk(&sk1);
    let sig = BlsScChia::sign(&sk0, MSG_DEADBEEF);

    assert!(BlsScChia::verify(&sig, MSG_DEADBEEF, &pk0).is_ok());
    assert!(BlsScChia::verify(&sig, MSG_8BADFOOD, &pk0).is_err());
    assert!(BlsScChia::verify(&sig, MSG_DEADBEEF, &pk1).is_err());
    assert_eq!(BlsScChia::sign(&sk0, MSG_DEADBEEF), sig);
  }

  #[test]
  fn secure_verify_rejects_infinity_input_key() {
    let sk = BlsScChia::sk_from_ikm(&RSEED[0]).unwrap();
    let real_pk = BlsScChia::derive_pk(&sk);
    let inf_pk = G1::identity().to_affine();
    // The identity key serializes to the infinity marker (bits 6-7 set).
    assert_eq!(BlsScChia::pk_to_bytes(&inf_pk)[0] & 0xc0, 0xc0);

    let sig = BlsScChia::sign(&sk, MSG_DEADBEEF);
    let res = BlsScChia::secure_verify_aggregates(&sig, MSG_DEADBEEF, &[&real_pk, &inf_pk]);
    assert!(matches!(res, Err(BlsError::InvalidPublicKey)));
  }

  #[test]
  fn tweaks_refuse_a_zero_scalar() {
    // A key never holds zero, but the backend type can; the tweak has to name
    // the key rather than leak the field's own error.
    let zero = blst::blst_scalar::default();
    assert_eq!(
      BlsScChia::add_tweak_sk(&zero, &[1; 32]),
      Err(BlsError::InvalidSecretKey)
    );
    assert_eq!(
      BlsScChia::mul_tweak_sk(&zero, &[1; 32]),
      Err(BlsError::InvalidSecretKey)
    );
    assert_eq!(BlsScChia::negate_sk(&zero), Err(BlsError::InvalidSecretKey));
  }
}
