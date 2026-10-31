//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scheme-generic BLS signature.

use super::error::BlsError;
use super::group::G2;
use super::scheme_ops::BlsScheme;
use super::BlsSigBytes;
#[cfg(feature = "codec")]
use super::BLS_SIG_LEN;

#[cfg(feature = "codec")]
use dash_num::Hash256;
#[cfg(feature = "codec")]
use dash_types::dlgt_codec;
#[cfg(feature = "codec")]
use dash_types::type_id::TypeId;
use dash_types::{qtypestr, type_cvrt};
use hex_conservative::DisplayHex;

use core::fmt::{Debug, Formatter, Result as FmtResult};
use core::hash::{Hash, Hasher};

/// A BLS signature (96-byte compressed G2 point)
#[cfg_attr(feature = "codec", derive(TypeId))]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "BlsSigBytes", try_from = "BlsSigBytes"))]
#[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
pub struct BlsSignature<S: BlsScheme>(pub(crate) S::InnerSig);

#[cfg(feature = "codec")]
dlgt_codec!(for[S: BlsScheme] BlsSignature<S> => BlsSigBytes, Hash256, BlsError, BLS_SIG_LEN);

impl<S: BlsScheme> BlsSignature<S> {
  /// Deserialize from 96 bytes.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSignature` when the bytes are not a valid point.
  pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, BlsError> {
    S::sig_from_bytes(bytes).map(Self)
  }

  /// Serialize to 96 bytes.
  pub fn to_bytes(&self) -> [u8; 96] {
    S::sig_to_bytes(&self.0)
  }

  /// Re-encode this signature under another scheme.
  ///
  /// The signature is lifted to its point and lowered again, so the target
  /// scheme's admission rules apply. Message augmentation is unaffected and a
  /// converted signature still verifies only under the scheme that produced it.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSignature` when the target scheme refuses the point.
  pub fn to_scheme<T: BlsScheme>(&self) -> Result<BlsSignature<T>, BlsError> {
    T::g2_to_sig(S::sig_to_g2(&self.0)?).map(BlsSignature::from_inner)
  }

  pub(crate) fn as_inner(&self) -> &S::InnerSig {
    &self.0
  }

  pub(crate) fn from_inner(inner: S::InnerSig) -> Self {
    Self(inner)
  }
}

impl<S: BlsScheme> Clone for BlsSignature<S> {
  fn clone(&self) -> Self {
    *self
  }
}

impl<S: BlsScheme> Copy for BlsSignature<S> {}

impl<S: BlsScheme> Debug for BlsSignature<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    qtypestr(f, core::any::type_name::<Self>())?;
    write!(f, "({})", self.to_bytes().as_hex())
  }
}

impl<S: BlsScheme> PartialEq for BlsSignature<S> {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}

impl<S: BlsScheme> Eq for BlsSignature<S> {}

impl<S: BlsScheme> Hash for BlsSignature<S> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_bytes().hash(state);
  }
}

type_cvrt!(for[S: BlsScheme] From<BlsSignature<S>> for BlsSigBytes, |sig| {
  Self::from_bytes(sig.to_bytes())
});

type_cvrt!(for[S: BlsScheme] TryFrom<BlsSigBytes> for BlsSignature<S>, BlsError, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

impl BlsSigBytes {
  /// Validates the bytes as a signature under scheme `S`.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSignature` when the bytes are not a valid point under `S`.
  /// That includes legacy encodings of an `x` with no point on the curve,
  /// which [`is_canonical`](Self::is_canonical) accepts; there is no point to
  /// return for them.
  pub fn to<S: BlsScheme>(&self) -> Result<BlsSignature<S>, BlsError> {
    BlsSignature::try_from(self)
  }

  /// Whether `S` reads the bytes as a signature that re-encodes to them, or
  /// under the legacy scheme as an `x` with no point on the curve and the sign
  /// bit clear.
  ///
  /// Null bytes pass, so pair with [`is_null`](Self::is_null) to require a
  /// signature.
  pub fn is_canonical<S: BlsScheme>(&self) -> bool {
    self.is_null() || S::is_canonical_sig(self.as_bytes())
  }
}

type_cvrt!(for[S: BlsScheme] TryFrom<BlsSignature<S>> for G2, BlsError, |sig| {
  S::sig_to_g2(&sig.0)
});

type_cvrt!(for[S: BlsScheme] TryFrom<G2> for BlsSignature<S>, BlsError, |point| {
  S::g2_to_sig(*point).map(Self::from_inner)
});

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::public_ops::BlsPublicKey;
  use crate::bls::secret_ops::BlsSecretKey;
  use crate::bls::tests::{
    ser_pairs, test_ikm, test_msg, SerType, G2_OFF_SUBGROUP_CHIA, G2_OFF_SUBGROUP_IETF, MSG_8BADFOOD, MSG_DEADBEEF,
    RSEED,
  };
  use crate::bls::{BlsScChia, BlsScIetf, BlsSigId};
  use crate::prelude::*;

  use cfg_if::cfg_if;
  use dash_dev::{arr_from_hex, vec_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct SignVec {
    sk: String,
    msg: String,
    sig: String,
  }

  fn assert_sign_verify<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let pk = sk.public_key();
    let sig = sk.sign_digest(&MSG_DEADBEEF);

    assert!(pk.verify_digest(&MSG_DEADBEEF, &sig).is_ok());
    assert!(pk.verify_digest(&MSG_8BADFOOD, &sig).is_err());

    let other_pk = BlsSecretKey::<S>::from_ikm(&RSEED[1]).unwrap().public_key();
    assert!(other_pk.verify_digest(&MSG_DEADBEEF, &sig).is_err());
  }

  #[rstest]
  #[case::chia(assert_sign_verify::<BlsScChia>)]
  #[case::ietf(assert_sign_verify::<BlsScIetf>)]
  fn signing_roundtrip_and_rejections(#[case] assertion: fn()) {
    assertion();
  }

  /// The byte-oriented IETF entry points must bind a signature to the selected
  /// DST. Correct variants verify, while the other variant, another message,
  /// and another key all fail.
  #[rstest]
  fn ietf_signature_variant_contract() {
    let sk = BlsSecretKey::<BlsScIetf>::from_ikm(&RSEED[0]).unwrap();
    let pk = sk.public_key();
    let other_pk = BlsSecretKey::<BlsScIetf>::from_ikm(&RSEED[1]).unwrap().public_key();
    let msg = b"variant-bound message";
    let wrong_msg = b"another message";

    for (variant, other) in [
      (BlsSigId::Basic, BlsSigId::ProofOfPossession),
      (BlsSigId::ProofOfPossession, BlsSigId::Basic),
    ] {
      let sig = sk.sign_with(msg, variant);
      assert!(pk.verify_with(msg, &sig, variant).is_ok());
      assert!(pk.verify_with(msg, &sig, other).is_err());
      assert!(pk.verify_with(wrong_msg, &sig, variant).is_err());
      assert!(other_pk.verify_with(msg, &sig, variant).is_err());

      let decoded = BlsSignature::<BlsScIetf>::from_bytes(&sig.to_bytes()).unwrap();
      assert!(pk.verify_with(msg, &decoded, variant).is_ok());
    }

    assert_ne!(
      sk.sign_with(msg, BlsSigId::Basic),
      sk.sign_with(msg, BlsSigId::ProofOfPossession),
      "different DSTs must produce different signatures",
    );
  }

  /// BLS signing draws no randomness, so the same key over the same message
  /// yields the same signature every time.
  fn assert_sign_is_deterministic<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let msg = &MSG_DEADBEEF;
    assert_eq!(sk.sign_digest(msg), sk.sign_digest(msg));
  }

  #[rstest]
  #[case::chia(assert_sign_is_deterministic::<BlsScChia>)]
  #[case::ietf(assert_sign_is_deterministic::<BlsScIetf>)]
  fn signing_is_deterministic(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_sig_bytes_canonical<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let clean = sk.sign_digest(&MSG_DEADBEEF).to_bytes();
    assert!(BlsSigBytes::from_bytes(clean).is_canonical::<S>());
    assert!(BlsSigBytes::from_bytes([0u8; 96]).is_canonical::<S>());

    let mut infinity = [0u8; 96];
    infinity[0] = 0xc0;
    assert!(!BlsSigBytes::from_bytes(infinity).is_canonical::<S>());

    let mut out_of_range = clean;
    out_of_range[48] |= 0xe0;
    assert!(!BlsSigBytes::from_bytes(out_of_range).is_canonical::<S>());
  }

  #[rstest]
  #[case::chia(assert_sig_bytes_canonical::<BlsScChia>)]
  #[case::ietf(assert_sig_bytes_canonical::<BlsScIetf>)]
  fn sig_bytes_canonical_signatures_and_null(#[case] assertion: fn()) {
    assertion();
  }

  /// A legacy encoding of an `x` with no point on the curve is canonical, while
  /// `to` has no point to return. With the sign bit set or a flag bit on `x.c1`
  /// the same `x` is not canonical.
  #[rstest]
  fn chia_off_curve_x_is_canonical_but_not_a_signature() {
    let encoded: [u8; 96] = arr_from_hex(concat!(
      "0097926406fa8040c0069d1b53b861b1df87e8e4c38b9b9418dd80a2fb113fdf1878624f7f624d512d56cd267360453e",
      "0e6992f1207908245f455d4d0bd6fcf0d7bb962c5f1913d4c18b8deb8c4670d233493576e8ad4ddc308fea94f8a109d7"
    ));
    let bytes = BlsSigBytes::from_bytes(encoded);
    assert!(bytes.is_canonical::<BlsScChia>());
    assert!(bytes.to::<BlsScChia>().is_err());

    let mut signed = encoded;
    signed[0] |= 0x80;
    assert!(!BlsSigBytes::from_bytes(signed).is_canonical::<BlsScChia>());
    for flag in [0x20, 0x40, 0x80] {
      let mut flagged = encoded;
      flagged[48] |= flag;
      assert!(
        !BlsSigBytes::from_bytes(flagged).is_canonical::<BlsScChia>(),
        "{flag:#x}"
      );
    }
  }

  fn assert_sig_roundtrip<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let bytes = sk.sign_digest(&MSG_DEADBEEF).to_bytes();
    assert_eq!(BlsSignature::<S>::from_bytes(&bytes).unwrap().to_bytes(), bytes);
  }

  #[rstest]
  #[case::chia(assert_sig_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_sig_roundtrip::<BlsScIetf>)]
  fn serialization_roundtrip(#[case] assertion: fn()) {
    assertion();
  }

  /// A small fixed vector set can miss one half of the compressed-point sign
  /// convention. Exercise many deterministic keys and require both sign-bit
  /// branches to round-trip for public keys and signatures.
  fn assert_many_serialization_roundtrips<S: BlsScheme>(sign_bit: u8) {
    let mut pk_signs = [false; 2];
    let mut sig_signs = [false; 2];

    for i in 0..64 {
      let sk = BlsSecretKey::<S>::from_ikm(&test_ikm(i)).unwrap();
      let pk = sk.public_key();
      let sig = sk.sign_digest(&test_msg(i));

      let pk_bytes = pk.to_bytes();
      let sig_bytes = sig.to_bytes();
      pk_signs[usize::from(pk_bytes[0] & sign_bit != 0)] = true;
      sig_signs[usize::from(sig_bytes[0] & sign_bit != 0)] = true;

      assert_eq!(BlsPublicKey::<S>::from_bytes(&pk_bytes).unwrap(), pk);
      assert_eq!(BlsSignature::<S>::from_bytes(&sig_bytes).unwrap(), sig);
    }

    assert!(pk_signs.into_iter().all(core::convert::identity));
    assert!(sig_signs.into_iter().all(core::convert::identity));
  }

  #[rstest]
  #[case::chia(assert_many_serialization_roundtrips::<BlsScChia>, 0x80)]
  #[case::ietf(assert_many_serialization_roundtrips::<BlsScIetf>, 0x20)]
  fn many_serialization_roundtrips(#[case] assertion: fn(u8), #[case] sign_bit: u8) {
    assertion(sign_bit);
  }

  /// Neither decoder yields an identity signature. Chia guards the marker and
  /// the all-zero buffer outright, IETF reaches the same answer through
  /// `validate`, which refuses the identity despite a canonical encoding.
  fn assert_identity_signature_rejected<S: BlsScheme>() {
    let mut infinity = [0u8; 96];
    infinity[0] = 0xc0;
    assert!(BlsSignature::<S>::from_bytes(&infinity).is_err());
    assert!(BlsSignature::<S>::from_bytes(&[0u8; 96]).is_err());
  }

  #[rstest]
  #[case::chia(assert_identity_signature_rejected::<BlsScChia>)]
  #[case::ietf(assert_identity_signature_rejected::<BlsScIetf>)]
  fn identity_signature_rejected(#[case] assertion: fn()) {
    assertion();
  }

  /// Only bit 7 of byte 0 is the legacy sign flag, and unlike G1 the legacy
  /// G2 decoder rejects stray high bits rather than masking them, at the sign
  /// byte (index 0) and the swizzled `x.c1` byte (index 48) alike.
  ///
  /// Rejecting at the decoder is stricter than decoding the bits into an
  /// out-of-range point and failing later, but a point so decoded never
  /// verifies, so the two agree on every observable outcome.
  #[rstest]
  #[case::sign_byte(0, 0x20)]
  #[case::swizzled_byte(48, 0x40)]
  fn chia_rejects_stray_signature_bits(#[case] index: usize, #[case] mask: u8) {
    let clean = BlsSecretKey::<BlsScChia>::from_ikm(&RSEED[0])
      .unwrap()
      .sign_digest(&MSG_DEADBEEF)
      .to_bytes();

    let mut mutated = clean;
    mutated[index] |= mask;
    assert!(BlsSignature::<BlsScChia>::from_bytes(&mutated).is_err());
  }

  /// Rejection alone is weak evidence, since the policy test below cannot
  /// tell a composite-order point from a malformed one. Hold both encodings
  /// to a single point so that distinction is made here.
  #[rstest]
  fn off_subgroup_g2_fixtures_are_one_point() {
    let chia = BlsSignature::<BlsScChia>::from_bytes(&G2_OFF_SUBGROUP_CHIA).unwrap();
    let point = BlsScChia::sig_to_g2(&chia.0).unwrap();

    assert!(!point.in_subgroup(), "fixture is not off-subgroup");
    assert_eq!(
      point.to_affine().compress(),
      G2_OFF_SUBGROUP_IETF,
      "the IETF fixture encodes a different point"
    );
  }

  /// Chia has no prime-order subgroup check, so a composite-order G2 point
  /// decodes and round-trips. IETF validates and refuses the same point in
  /// its own encoding.
  fn assert_off_subgroup_signature_policy<S: BlsScheme>(encoded: &[u8; 96], accepted: bool) {
    match BlsSignature::<S>::from_bytes(encoded) {
      Ok(sig) => {
        assert!(accepted, "off-subgroup signature accepted");
        assert_eq!(sig.to_bytes(), *encoded);
      }
      Err(_) => assert!(!accepted, "off-subgroup signature rejected"),
    }
  }

  #[rstest]
  #[case::chia(assert_off_subgroup_signature_policy::<BlsScChia>, &G2_OFF_SUBGROUP_CHIA, true)]
  #[case::ietf(assert_off_subgroup_signature_policy::<BlsScIetf>, &G2_OFF_SUBGROUP_IETF, false)]
  fn off_subgroup_signature_policy(
    #[case] assertion: fn(&[u8; 96], bool),
    #[case] encoded: &[u8; 96],
    #[case] accepted: bool,
  ) {
    assertion(encoded, accepted);
  }

  /// The same G2 point encodes differently under the two schemes, and each
  /// encoding must round-trip through the wrapper of its own scheme.
  #[rstest]
  fn serialization_formats_match_vectors() {
    for (sig_legacy, sig_ietf) in ser_pairs(SerType::Signature) {
      let legacy = BlsSignature::<BlsScChia>::from_bytes(&arr_from_hex(&sig_legacy)).unwrap();
      assert_eq!(legacy.to_bytes().to_lower_hex_string(), sig_legacy);

      let ietf = BlsSignature::<BlsScIetf>::from_bytes(&arr_from_hex(&sig_ietf)).unwrap();
      assert_eq!(ietf.to_bytes().to_lower_hex_string(), sig_ietf);

      assert_ne!(sig_legacy, sig_ietf, "legacy and ietf should differ");
    }
  }

  /// The scheme-level KAT pins `BlsScheme::sign`; this pins that the wrapper's
  /// byte-oriented bridge is still wired to it, message length checks included.
  fn assert_signing_matches_vectors<S: BlsScheme>(scheme: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_sign").scope(scheme);
    let vecs: Vec<SignVec> = corpus.vectors("sign");

    for v in &vecs {
      let sk = BlsSecretKey::<S>::from_bytes(&arr_from_hex(&v.sk)).unwrap();
      let sig = sk.sign_digest(&arr_from_hex(&v.msg));
      assert_eq!(sig.to_bytes().to_lower_hex_string(), v.sig);
    }
  }

  #[rstest]
  #[case::chia(assert_signing_matches_vectors::<BlsScChia>, "chia")]
  #[case::ietf(assert_signing_matches_vectors::<BlsScIetf>, "ietf")]
  fn signing_matches_vectors(#[case] assertion: fn(&str), #[case] scheme: &str) {
    assertion(scheme);
  }

  fn assert_message_signing_matches_vectors<S: BlsScheme>(scheme: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_sign").scope(scheme);
    let vecs: Vec<SignVec> = corpus.vectors("sign_message");
    assert!(!vecs.is_empty(), "corpus section is empty");

    for v in &vecs {
      let sk = BlsSecretKey::<S>::from_bytes(&arr_from_hex(&v.sk)).unwrap();
      let msg = vec_from_hex(&v.msg);
      let sig = sk.sign_message(&msg);
      assert_eq!(sig.to_bytes().to_lower_hex_string(), v.sig);
      assert!(sk.public_key().verify_message(&msg, &sig).is_ok());
    }
  }

  #[rstest]
  #[case::chia(assert_message_signing_matches_vectors::<BlsScChia>, "chia")]
  #[case::ietf(assert_message_signing_matches_vectors::<BlsScIetf>, "ietf")]
  fn message_signing_matches_vectors(#[case] assertion: fn(&str), #[case] scheme: &str) {
    assertion(scheme);
  }

  /// An IETF digest is an ordinary message, so both paths sign it alike.
  #[rstest]
  fn ietf_digest_signs_as_message() {
    let sk = BlsSecretKey::<BlsScIetf>::from_ikm(&RSEED[1]).unwrap();
    let sig = sk.sign_digest(&MSG_DEADBEEF);
    assert_eq!(sk.sign_message(&MSG_DEADBEEF), sig);
    assert!(sk.public_key().verify_message(&MSG_DEADBEEF, &sig).is_ok());
    assert!(sk.public_key().verify_message(&MSG_8BADFOOD, &sig).is_err());
  }

  /// One secret scalar over one message yields two different signatures, so a
  /// scheme mix-up cannot go unnoticed.
  #[rstest]
  fn signatures_differ_across_schemes() {
    let chia = BlsSecretKey::<BlsScChia>::from_ikm(&RSEED[0]).unwrap();
    let ietf = BlsSecretKey::<BlsScIetf>::from_bytes(&chia.to_bytes()).unwrap();
    assert_ne!(
      chia.sign_digest(&MSG_DEADBEEF).to_bytes(),
      ietf.sign_digest(&MSG_DEADBEEF).to_bytes()
    );
  }

  /// Conversion re-encodes one point, so a round trip returns the original.
  fn assert_sig_scheme_conversion_round_trips<S: BlsScheme, T: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let sig = sk.sign_digest(&MSG_DEADBEEF);
    let there = sig.to_scheme::<T>().unwrap();

    assert_eq!(there.to_scheme::<S>().unwrap().to_bytes(), sig.to_bytes());
  }

  #[rstest]
  #[case::chia_to_ietf(assert_sig_scheme_conversion_round_trips::<BlsScChia, BlsScIetf>)]
  #[case::ietf_to_chia(assert_sig_scheme_conversion_round_trips::<BlsScIetf, BlsScChia>)]
  #[case::chia_to_chia(assert_sig_scheme_conversion_round_trips::<BlsScChia, BlsScChia>)]
  fn sig_scheme_conversion_round_trips(#[case] assertion: fn()) {
    assertion();
  }

  /// Conversion moves the encoding and nothing else, so the signature still
  /// answers to the scheme that made it: the message is hashed differently
  /// under each, and a converted signature verifies under neither the target's
  /// hash nor the target's key.
  #[rstest]
  fn sig_scheme_conversion_does_not_move_the_augmentation() {
    let sk = BlsSecretKey::<BlsScChia>::from_ikm(&RSEED[0]).unwrap();
    let sig = sk.sign_digest(&MSG_DEADBEEF);

    let converted = sig.to_scheme::<BlsScIetf>().unwrap();
    let pk_ietf = sk.public_key().to_scheme::<BlsScIetf>().unwrap();
    assert!(pk_ietf.verify_digest(&MSG_DEADBEEF, &converted).is_err());
  }

  /// A signature Chia admits and IETF does not must not become an IETF one by
  /// being converted.
  #[rstest]
  fn sig_scheme_conversion_applies_target_rules() {
    let off_subgroup = BlsSignature::<BlsScChia>::from_bytes(&G2_OFF_SUBGROUP_CHIA).unwrap();

    assert!(off_subgroup.to_scheme::<BlsScChia>().is_ok());
    assert!(off_subgroup.to_scheme::<BlsScIetf>().is_err());
  }

  cfg_if! {
    if #[cfg(feature = "serde")] {
      use dash_dev::{assert_json_rt, to_json};

      /// The wrapper serializes through the byte bag, so the round-trip is
      /// pinned per scheme.
      #[rstest]
      fn serde_roundtrip() {
        let chia = BlsSecretKey::<BlsScChia>::from_ikm(&RSEED[0]).unwrap();
        assert_json_rt(&chia.sign_digest(&MSG_DEADBEEF));
        let ietf = BlsSecretKey::<BlsScIetf>::from_ikm(&RSEED[0]).unwrap();
        assert_json_rt(&ietf.sign_digest(&MSG_DEADBEEF));
      }

      #[rstest]
      fn serde_emits_hex_string() {
        let chia = BlsSecretKey::<BlsScChia>::from_ikm(&RSEED[0])
          .unwrap()
          .sign_digest(&MSG_DEADBEEF);
        let ietf = BlsSecretKey::<BlsScIetf>::from_ikm(&RSEED[0])
          .unwrap()
          .sign_digest(&MSG_DEADBEEF);

        assert_eq!(to_json(&chia), format!("\"{}\"", chia.to_bytes().to_lower_hex_string()));
        assert_eq!(to_json(&ietf), format!("\"{}\"", ietf.to_bytes().to_lower_hex_string()));
      }
    }
  }

  fn assert_to_matches_from_bytes<S: BlsScheme>() {
    let valid = BlsSecretKey::<S>::from_ikm(&RSEED[0])
      .unwrap()
      .sign_digest(&MSG_DEADBEEF)
      .to_bytes();
    for encoded in [valid, G2_OFF_SUBGROUP_CHIA, G2_OFF_SUBGROUP_IETF, [0; 96]] {
      assert_eq!(
        BlsSigBytes::from_bytes(encoded).to::<S>(),
        BlsSignature::<S>::from_bytes(&encoded)
      );
    }
  }

  #[rstest]
  #[case::chia(assert_to_matches_from_bytes::<BlsScChia>)]
  #[case::ietf(assert_to_matches_from_bytes::<BlsScIetf>)]
  fn to_admits_what_from_bytes_admits(#[case] assertion: fn()) {
    assertion();
  }
}
