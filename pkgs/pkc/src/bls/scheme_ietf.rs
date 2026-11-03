//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Basic BLS scheme implementation.

use super::error::BlsError;
use super::group::{G1Affine, G2Affine, G1, G2};
use super::scheme_ops::{verify_ok, BlsScheme};
use super::schemes::BlsScIetf;
use super::sig_id::BlsSigId;
use crate::prelude::*;
use crate::sealed::Sealed;

use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use zeroize::Zeroizing;

/// Domain separation tag for the basic (NUL) signature scheme.
const DST_BASIC: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
/// Domain separation tag for signatures in the proof-of-possession scheme.
const DST_POP: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Domain separation tag for proofs of possession.
const DST_POP_PROVE: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

impl Sealed for BlsScIetf {}

impl BlsScheme for BlsScIetf {
  type InnerSk = SecretKey;
  type InnerPk = PublicKey;
  type InnerSig = Signature;
  type Msg<'a> = &'a [u8];

  /// Derive via draft-03 keygen.
  fn sk_from_ikm(ikm: &[u8]) -> Result<Self::InnerSk, BlsError> {
    SecretKey::key_gen_v3(ikm, &[]).map_err(|_| BlsError::InvalidKeyMaterial)
  }

  /// Parse the 32-byte scalar through blst.
  fn sk_from_bytes(b: &[u8; 32]) -> Result<Self::InnerSk, BlsError> {
    SecretKey::from_bytes(b).map_err(|_| BlsError::InvalidSecretKey)
  }

  /// Emit the scalar as big-endian bytes.
  fn sk_to_bytes(sk: &Self::InnerSk) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(sk.to_bytes())
  }

  /// Map the secret key to its G1 public key.
  fn derive_pk(sk: &Self::InnerSk) -> Self::InnerPk {
    sk.sk_to_pk()
  }

  /// Wipe the scalar limbs.
  fn zeroize_sk(sk: &mut Self::InnerSk) {
    // blst's SecretKey wipes itself on drop but exposes no in-place wipe,
    // so assign over it. The old value drops, dropping is the wipe.
    *sk = SecretKey::default();
  }

  /// Decode the compressed G1 point and run `validate`.
  fn pk_from_bytes(b: &[u8; 48]) -> Result<Self::InnerPk, BlsError> {
    let pk = PublicKey::from_bytes(b).map_err(|_| BlsError::InvalidPublicKey)?;
    // blst `from_bytes` checks only encoding and curve; validate also
    // rejects the identity and non-prime-order points before use.
    pk.validate().map_err(|_| BlsError::InvalidPublicKey)?;
    Ok(pk)
  }

  /// Compress the G1 point to 48 bytes.
  fn pk_to_bytes(pk: &Self::InnerPk) -> [u8; 48] {
    pk.compress()
  }

  /// Compress the G1 point to 48 bytes.
  fn g1_bytes(point: &G1Affine) -> [u8; 48] {
    point.compress()
  }

  /// The bytes are already in the IETF compressed form.
  fn pk_ietf_bytes(b: &[u8; 48]) -> [u8; 48] {
    *b
  }

  /// Decode `b` and require it to encode back to the same bytes.
  fn is_canonical_pk(b: &[u8; 48]) -> bool {
    Self::pk_from_bytes(b).is_ok_and(|pk| Self::pk_to_bytes(&pk) == *b)
  }

  /// Lift the blst public key into a projective G1 point.
  fn pk_to_g1(pk: &Self::InnerPk) -> Result<G1, BlsError> {
    let aff = G1Affine::deserialize(&pk.serialize()).map_err(|_| BlsError::InvalidPublicKey)?;
    Ok(aff.to_projective())
  }

  /// Re-encode the projective point and parse it back through `validate`.
  fn g1_to_pk(point: G1) -> Result<Self::InnerPk, BlsError> {
    Self::pk_from_bytes(&Self::g1_bytes(&point.to_affine()))
  }

  /// Uncompress the standard encoding without re-running `validate`.
  ///
  /// The bytes come from `pk_to_bytes` on a key that `pk_from_bytes` already
  /// validated, so a second subgroup check would only repeat that work.
  fn secure_agg_point(pk_bytes: &[u8; 48]) -> Result<G1, BlsError> {
    let aff = G1Affine::uncompress(pk_bytes).map_err(|_| BlsError::InvalidPublicKey)?;
    Ok(aff.to_projective())
  }

  /// Decode the compressed G2 point and run `validate`.
  fn sig_from_bytes(b: &[u8; 96]) -> Result<Self::InnerSig, BlsError> {
    let sig = Signature::from_bytes(b).map_err(|_| BlsError::InvalidSignature)?;
    // blst `from_bytes` checks only encoding and curve; validate also
    // rejects the identity and non-prime-order points before use.
    sig.validate(true).map_err(|_| BlsError::InvalidSignature)?;
    Ok(sig)
  }

  /// Compress the G2 point to 96 bytes.
  fn sig_to_bytes(sig: &Self::InnerSig) -> [u8; 96] {
    sig.compress()
  }

  /// Compress the G2 point to 96 bytes.
  fn g2_bytes(point: &G2Affine) -> [u8; 96] {
    point.compress()
  }

  /// The `x` of the encoding, with the sign bit, bit 5 of byte 0, clear.
  fn sig_ietf_x_bytes(b: &[u8; 96]) -> [u8; 96] {
    let mut ietf = *b;
    ietf[0] &= !0x20;
    ietf
  }

  /// Decode `b` and require it to encode back to the same bytes.
  fn is_canonical_sig(b: &[u8; 96]) -> bool {
    Self::sig_from_bytes(b).is_ok_and(|sig| Self::sig_to_bytes(&sig) == *b)
  }

  /// Lift the blst signature into a projective G2 point.
  fn sig_to_g2(sig: &Self::InnerSig) -> Result<G2, BlsError> {
    let aff = G2Affine::deserialize(&sig.serialize()).map_err(|_| BlsError::InvalidSignature)?;
    Ok(aff.to_projective())
  }

  /// Re-encode the projective point and parse it back through `validate`.
  fn g2_to_sig(point: G2) -> Result<Self::InnerSig, BlsError> {
    Self::sig_from_bytes(&Self::g2_bytes(&point.to_affine()))
  }

  /// Sign with the basic-scheme DST.
  fn sign(sk: &Self::InnerSk, msg: Self::Msg<'_>) -> Self::InnerSig {
    sk.sign(msg, DST_BASIC, &[])
  }

  /// Verify against the basic-scheme DST.
  fn verify(sig: &Self::InnerSig, msg: Self::Msg<'_>, pk: &Self::InnerPk) -> Result<(), BlsError> {
    verify_ok(sig.verify(true, msg, DST_BASIC, &[], pk, true))
  }

  /// A digest is hashed to the curve like any other message.
  fn digest_msg(digest: &[u8; 32]) -> Self::Msg<'_> {
    digest
  }

  /// The message is hashed to the curve directly.
  fn plaintext_msg(msg: &[u8]) -> Self::Msg<'_> {
    msg
  }

  /// Aggregate the public keys via blst.
  fn aggregate_pk(pks: &[&Self::InnerPk]) -> Result<Self::InnerPk, BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let agg = AggregatePublicKey::aggregate(pks, true).map_err(|_| BlsError::InvalidPublicKey)?;
    Ok(agg.to_public_key())
  }

  /// Aggregate the signatures via blst.
  fn aggregate_sig(sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError> {
    if sigs.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let agg = AggregateSignature::aggregate(sigs, true).map_err(|_| BlsError::InvalidSignature)?;
    Ok(agg.to_signature())
  }

  /// Aggregate-verify one shared message against many keys.
  fn fast_verify_aggregates(sig: &Self::InnerSig, msg: Self::Msg<'_>, pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    verify_ok(sig.fast_aggregate_verify(true, msg, DST_BASIC, pks))
  }

  fn verify_aggregates(sig: &Self::InnerSig, msgs: &[Self::Msg<'_>], pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    if pks.len() != msgs.len() {
      return Err(BlsError::CountMismatch);
    }
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }

    // Two equal messages collapse to `e(H(m), pk_a + pk_b)`, proving only
    // that someone holds the sum. Absent a proof of possession, one signer
    // can pick `pk_b` to cancel `pk_a` and verify without them.
    let mut sorted: Vec<&[u8]> = msgs.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
      return Err(BlsError::DuplicateMessage);
    }
    verify_ok(sig.aggregate_verify(true, msgs, DST_BASIC, pks, true))
  }
}

impl BlsScIetf {
  /// The domain separation tag `id` signs and verifies under.
  const fn dst_of(id: BlsSigId) -> &'static [u8] {
    match id {
      BlsSigId::Basic => DST_BASIC,
      BlsSigId::ProofOfPossession => DST_POP,
    }
  }

  /// Sign under the DST selected by `id`.
  pub(crate) fn sign_with(sk: &SecretKey, msg: &[u8], id: BlsSigId) -> Signature {
    sk.sign(msg, Self::dst_of(id), &[])
  }

  /// Verify under the DST selected by `id`.
  ///
  /// # Errors
  ///
  /// Returns `VerifyFailed` when the pairing check does not hold.
  pub(crate) fn verify_with(sig: &Signature, msg: &[u8], pk: &PublicKey, id: BlsSigId) -> Result<(), BlsError> {
    verify_ok(sig.verify(true, msg, Self::dst_of(id), &[], pk, true))
  }

  /// Prove possession by signing the public key under the PoP-prove DST.
  pub(crate) fn prove_possession(sk: &SecretKey, pk: &PublicKey) -> Signature {
    sk.sign(&pk.compress(), DST_POP_PROVE, &[])
  }

  /// Verify a proof of possession under the PoP-prove DST.
  ///
  /// # Errors
  ///
  /// Returns `VerifyFailed` when the proof does not match the key.
  pub(crate) fn verify_possession(pk: &PublicKey, pop: &Signature) -> Result<(), BlsError> {
    verify_ok(pop.verify(true, &pk.compress(), DST_POP_PROVE, &[], pk, true))
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::tests::{MSG_DEADBEEF, RSEED};

  use dash_dev::{arr_from_hex, vec_from_hex, Corpus};
  use hex_conservative::hex;
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
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_dh").scope("ietf");
    let vecs: Vec<DhVector> = corpus.vectors("dh");

    for v in &vecs {
      let sk = BlsScIetf::sk_from_bytes(&arr_from_hex(&v.sk)).unwrap();
      let peer = BlsScIetf::pk_from_bytes(&arr_from_hex(&v.peer_pk)).unwrap();
      let shared = BlsScIetf::dh_exchange(&sk, &peer).unwrap();
      assert_eq!(BlsScIetf::pk_to_bytes(&shared).to_lower_hex_string(), v.shared);
    }
  }

  /// The lifts skip decompression, so they have to land on the point that
  /// decompressing the compressed encoding yields, inclusive of identity.
  /// A cancelled aggregate serializes to the infinity marker on both paths.
  #[test]
  fn lifts_agree_with_decompression() {
    let sk = BlsScIetf::sk_from_ikm(&RSEED[0]).unwrap();
    let pk = BlsScIetf::derive_pk(&sk);
    let sig = BlsScIetf::sign(&sk, &MSG_DEADBEEF);

    let decompressed = G1Affine::uncompress(&pk.compress()).unwrap().to_projective();
    assert_eq!(BlsScIetf::pk_to_g1(&pk).unwrap(), decompressed);
    let decompressed = G2Affine::uncompress(&sig.compress()).unwrap().to_projective();
    assert_eq!(BlsScIetf::sig_to_g2(&sig).unwrap(), decompressed);

    let mut negated = pk.compress();
    negated[0] ^= 0x20;
    let negated = PublicKey::from_bytes(&negated).unwrap();
    let cancelled = AggregatePublicKey::aggregate(&[&pk, &negated], true)
      .unwrap()
      .to_public_key();
    let decompressed = G1Affine::uncompress(&cancelled.compress()).unwrap().to_projective();
    assert!(decompressed.is_inf());
    assert_eq!(BlsScIetf::pk_to_g1(&cancelled).unwrap(), decompressed);

    let mut negated = sig.compress();
    negated[0] ^= 0x20;
    let negated = Signature::from_bytes(&negated).unwrap();
    let cancelled = AggregateSignature::aggregate(&[&sig, &negated], true)
      .unwrap()
      .to_signature();
    let decompressed = G2Affine::uncompress(&cancelled.compress()).unwrap().to_projective();
    assert!(decompressed.is_inf());
    assert_eq!(BlsScIetf::sig_to_g2(&cancelled).unwrap(), decompressed);
  }

  #[test]
  fn pyecc_signature_matches() {
    let sk = BlsScIetf::sk_from_bytes(&hex!(
      "0101010101010101010101010101010101010101010101010101010101010101"
    ))
    .unwrap();
    let msg = hex!("030104010509");
    let expected = hex!(concat!(
      "96ba34fac33c7f129d602a0bc8a3d43f9abc014eceaab7359146b4b150e57b808645738f35671e9e10e0d862a30cab70",
      "074eb5831d13e6a5b162d01eebe687d0164adbd0a864370a7c222a2768d7704da254f1bf1823665bc2361f9dd8c00e99"
    ));
    let sig = BlsScIetf::sign(&sk, &msg);
    assert_eq!(BlsScIetf::sig_to_bytes(&sig), expected);
    assert!(BlsScIetf::verify(&sig, &msg, &BlsScIetf::derive_pk(&sk)).is_ok());
  }

  #[test]
  fn signing_matches_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_sign").scope("ietf");
    let vecs: Vec<SignVector> = corpus.vectors("sign");

    for v in &vecs {
      let sk = BlsScIetf::sk_from_bytes(&arr_from_hex(&v.sk)).unwrap();
      let sig = BlsScIetf::sign(&sk, &vec_from_hex(&v.msg));
      assert_eq!(BlsScIetf::sig_to_bytes(&sig).to_lower_hex_string(), v.sig);
    }
  }

  #[test]
  fn signing_verifies_and_rejects_mismatches() {
    let sk0 = BlsScIetf::sk_from_ikm(&RSEED[0]).unwrap();
    let sk1 = BlsScIetf::sk_from_ikm(&RSEED[1]).unwrap();
    let pk0 = BlsScIetf::derive_pk(&sk0);
    let pk1 = BlsScIetf::derive_pk(&sk1);
    let sig = BlsScIetf::sign(&sk0, &MSG_DEADBEEF);

    assert!(BlsScIetf::verify(&sig, &MSG_DEADBEEF, &pk0).is_ok());
    assert!(BlsScIetf::verify(&sig, b"wrong", &pk0).is_err());
    assert!(BlsScIetf::verify(&sig, &MSG_DEADBEEF, &pk1).is_err());
    assert_eq!(BlsScIetf::sign(&sk0, &MSG_DEADBEEF), sig);
  }
}
