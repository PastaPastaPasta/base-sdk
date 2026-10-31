//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scheme-generic BLS public key.

use super::error::BlsError;
use super::group::G1;
#[cfg(feature = "codec")]
use super::public_hash::BlsPkHash;
use super::scheme_ops::BlsScheme;
use super::sig_basic::BlsSignature;
use super::BlsPkBytes;
#[cfg(feature = "codec")]
use super::BLS_PK_LEN;
use super::{BlsScIetf, BlsSigId};
use crate::prelude::*;

#[cfg(feature = "codec")]
use dash_types::{dlgt_codec, type_id::TypeId};
use dash_types::{qtypestr, type_cvrt};
use hex_conservative::DisplayHex;

use core::any::type_name;
use core::fmt::{Debug, Formatter, Result as FmtResult};
use core::hash::{Hash, Hasher};

/// A BLS public key (48-byte compressed G1 point)
#[cfg_attr(feature = "codec", derive(TypeId))]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "BlsPkBytes", try_from = "BlsPkBytes",))]
#[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
pub struct BlsPublicKey<S: BlsScheme>(pub(crate) S::InnerPk);

#[cfg(feature = "codec")]
dlgt_codec!(for[S: BlsScheme] BlsPublicKey<S> => BlsPkBytes, BlsPkHash, BlsError, BLS_PK_LEN);

impl<S: BlsScheme> BlsPublicKey<S> {
  /// Deserialize from 48 bytes.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the bytes are not a valid point.
  pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, BlsError> {
    S::pk_from_bytes(bytes).map(Self)
  }

  /// Serialize to 48 bytes.
  pub fn to_bytes(&self) -> [u8; 48] {
    S::pk_to_bytes(&self.0)
  }

  /// Re-encode this key under another scheme.
  ///
  /// The key is lifted to its point and lowered again, so the target scheme's
  /// admission rules apply.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the target scheme refuses the point.
  pub fn to_scheme<T: BlsScheme>(&self) -> Result<BlsPublicKey<T>, BlsError> {
    T::g1_to_pk(S::pk_to_g1(&self.0)?).map(BlsPublicKey::from_inner)
  }

  /// Add `tweak * G` to the point.
  ///
  /// # Errors
  ///
  /// Returns `InvalidTweak` when `tweak` is not below the group order or the
  /// sum is the point at infinity, and `InvalidPublicKey` when this key does
  /// not decode to a point.
  pub fn add_tweak(&self, tweak: &[u8; 32]) -> Result<Self, BlsError> {
    S::add_tweak_pk(&self.0, tweak).map(Self::from_inner)
  }

  /// Multiply the point by `tweak`.
  ///
  /// # Errors
  ///
  /// Returns `InvalidTweak` when `tweak` is not below the group order or the
  /// product is the point at infinity, and `InvalidPublicKey` when this key
  /// does not decode to a point.
  pub fn mul_tweak(&self, tweak: &[u8; 32]) -> Result<Self, BlsError> {
    S::mul_tweak_pk(&self.0, tweak).map(Self::from_inner)
  }

  /// Negate the point.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when this key does not decode to a point.
  pub fn negate(&self) -> Result<Self, BlsError> {
    S::negate_pk(&self.0).map(Self::from_inner)
  }

  /// Aggregate multiple public keys into one.
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no keys are given, or `InvalidPublicKey`
  /// when a key fails to aggregate.
  pub fn aggregate(keys: &[&Self]) -> Result<Self, BlsError> {
    let inner_refs: Vec<&S::InnerPk> = keys.iter().map(|k| &k.0).collect();
    S::aggregate_pk(&inner_refs).map(Self::from_inner)
  }

  /// Aggregate public keys under secure-verification weighting.
  ///
  /// Keys are weighted in [`BlsSignature::secure_verify_aggregates_digest`],
  /// sorted by encoding, so the result is order-independent and a signature
  /// passing that check verifies plainly against this key.
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no keys are given, or `InvalidPublicKey`
  /// when a key or the weighted sum fails to decode.
  pub fn secure_aggregate(keys: &[&Self]) -> Result<Self, BlsError> {
    let inner_refs: Vec<&S::InnerPk> = keys.iter().map(|k| &k.0).collect();
    S::secure_aggregate_pk(&inner_refs).map(Self::from_inner)
  }

  /// Verify `sig` over a 32-byte hashed message.
  ///
  /// # Errors
  ///
  /// Returns `VerifyFailed` when the pairing check does not hold.
  pub fn verify_digest(&self, digest: &[u8; 32], sig: &BlsSignature<S>) -> Result<(), BlsError> {
    S::verify(sig.as_inner(), S::digest_msg(digest), &self.0)
  }

  /// Verify `sig` over an arbitrary-length message, hashed as
  /// [`BlsSecretKey::sign_message`](super::BlsSecretKey::sign_message) does.
  ///
  /// # Errors
  ///
  /// Returns `VerifyFailed` when the pairing check does not hold.
  pub fn verify_message(&self, msg: &[u8], sig: &BlsSignature<S>) -> Result<(), BlsError> {
    S::verify(sig.as_inner(), S::plaintext_msg(msg), &self.0)
  }

  pub(crate) fn from_inner(inner: S::InnerPk) -> Self {
    Self(inner)
  }
}

impl BlsPublicKey<BlsScIetf> {
  /// Verify `sig` under the domain separation tag selected by `scheme`.
  ///
  /// # Errors
  ///
  /// Returns `VerifyFailed` when the pairing check does not hold.
  pub fn verify_with(&self, msg: &[u8], sig: &BlsSignature<BlsScIetf>, scheme: BlsSigId) -> Result<(), BlsError> {
    BlsScIetf::verify_with(sig.as_inner(), msg, &self.0, scheme)
  }
}

impl<S: BlsScheme> Clone for BlsPublicKey<S> {
  fn clone(&self) -> Self {
    *self
  }
}

impl<S: BlsScheme> Copy for BlsPublicKey<S> {}

impl<S: BlsScheme> Debug for BlsPublicKey<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    qtypestr(f, type_name::<Self>())?;
    write!(f, "({})", self.to_bytes().as_hex())
  }
}

impl<S: BlsScheme> Eq for BlsPublicKey<S> {}

impl<S: BlsScheme> Hash for BlsPublicKey<S> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_bytes().hash(state);
  }
}

impl<S: BlsScheme> PartialEq for BlsPublicKey<S> {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}

type_cvrt!(for[S: BlsScheme] From<BlsPublicKey<S>> for BlsPkBytes, |pk| {
  Self::from_bytes(pk.to_bytes())
});

type_cvrt!(for[S: BlsScheme] TryFrom<BlsPkBytes> for BlsPublicKey<S>, BlsError, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

impl BlsPkBytes {
  /// Validates the bytes as a public key under scheme `S`.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the bytes are not a valid point under `S`.
  pub fn to<S: BlsScheme>(&self) -> Result<BlsPublicKey<S>, BlsError> {
    BlsPublicKey::try_from(self)
  }

  /// Whether `S` decodes the bytes to a key that re-encodes to them.
  ///
  /// Null bytes pass, so pair with [`is_null`](Self::is_null) to require a key.
  pub fn is_canonical<S: BlsScheme>(&self) -> bool {
    self.is_null() || self.to::<S>().is_ok_and(|pk| pk.to_bytes() == *self.as_bytes())
  }
}

type_cvrt!(for[S: BlsScheme] TryFrom<BlsPublicKey<S>> for G1, BlsError, |pk| {
  S::pk_to_g1(&pk.0)
});

type_cvrt!(for[S: BlsScheme] TryFrom<G1> for BlsPublicKey<S>, BlsError, |point| {
  S::g1_to_pk(*point).map(Self::from_inner)
});

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::tests::{
    ietf_g1_encoding, ser_pairs, SerType, G1_OFF_SUBGROUP_CHIA, G1_OFF_SUBGROUP_IETF, G1_X_EQ_PRIME_CHIA,
    G1_X_GE_PRIME_CHIA, G1_X_MAX_CHIA, MSG_8BADFOOD, RSEED,
  };
  use crate::bls::{BlsScChia, BlsScIetf, BlsSecretKey, BlsSignature};

  use cfg_if::cfg_if;
  use dash_dev::{arr_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct AggPkVec {
    pks: Vec<String>,
    agg_pk: String,
  }

  #[derive(Deserialize)]
  struct DhVec {
    sk: String,
    peer_pk: String,
    shared: String,
  }

  #[derive(Deserialize)]
  struct SecureVec {
    msg: String,
    pks: Vec<String>,
    agg_sig_secure: String,
  }

  fn assert_dh_matches_vectors<S: BlsScheme>(scheme: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_dh").scope(scheme);
    let vecs: Vec<DhVec> = corpus.vectors("dh");

    for v in &vecs {
      let sk = BlsSecretKey::<S>::from_bytes(&arr_from_hex(&v.sk)).unwrap();
      let peer = BlsPublicKey::<S>::from_bytes(&arr_from_hex(&v.peer_pk)).unwrap();
      let shared = sk.dh_exchange(&peer).unwrap();
      assert_eq!(shared.as_bytes().to_lower_hex_string(), v.shared);
    }
  }

  #[rstest]
  #[case::chia(assert_dh_matches_vectors::<BlsScChia>, "chia")]
  #[case::ietf(assert_dh_matches_vectors::<BlsScIetf>, "ietf")]
  fn dh_exchange_matches_vectors(#[case] assertion: fn(&str), #[case] scheme: &str) {
    assertion(scheme);
  }

  fn assert_dh_roundtrip<S: BlsScheme>() {
    let sk_a = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let sk_b = BlsSecretKey::<S>::from_ikm(&RSEED[1]).unwrap();

    let shared_ab = sk_a.dh_exchange(&sk_b.public_key()).unwrap();
    let shared_ba = sk_b.dh_exchange(&sk_a.public_key()).unwrap();
    assert_eq!(shared_ab, shared_ba);
  }

  #[rstest]
  #[case::chia(assert_dh_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_dh_roundtrip::<BlsScIetf>)]
  fn dh_exchange_roundtrip(#[case] assertion: fn()) {
    assertion();
  }

  /// In the Chia scheme, DH weighs whatever the decoder passed, which leaks
  /// the scalar mod the cofactor's small factors. IETF rejects this.
  fn assert_off_subgroup_peer_policy<S: BlsScheme>(encoded: &[u8; 48], reaches_dh: bool) {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();

    match BlsPublicKey::<S>::from_bytes(encoded) {
      Ok(peer) => {
        assert!(reaches_dh, "decoder admitted an off-subgroup key");
        assert!(!S::pk_to_g1(&peer.0).unwrap().in_subgroup());
        assert!(sk.dh_exchange(&peer).is_ok(), "weighted without complaint");
      }
      Err(_) => assert!(!reaches_dh, "decoder refused it before DH could see it"),
    }
  }

  #[rstest]
  #[case::chia(assert_off_subgroup_peer_policy::<BlsScChia>, &G1_OFF_SUBGROUP_CHIA, true)]
  #[case::ietf(assert_off_subgroup_peer_policy::<BlsScIetf>, &G1_OFF_SUBGROUP_IETF, false)]
  fn off_subgroup_peer_policy(
    #[case] assertion: fn(&[u8; 48], bool),
    #[case] encoded: &[u8; 48],
    #[case] reaches_dh: bool,
  ) {
    assertion(encoded, reaches_dh);
  }

  /// Conversion re-encodes one point, so a round trip returns the original and
  /// the same-scheme case is a copy.
  fn assert_scheme_conversion_round_trips<S: BlsScheme, T: BlsScheme>() {
    let pk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap().public_key();
    let there = pk.to_scheme::<T>().unwrap();

    assert_eq!(there.to_scheme::<S>().unwrap().to_bytes(), pk.to_bytes());
  }

  #[rstest]
  #[case::chia_to_ietf(assert_scheme_conversion_round_trips::<BlsScChia, BlsScIetf>)]
  #[case::ietf_to_chia(assert_scheme_conversion_round_trips::<BlsScIetf, BlsScChia>)]
  #[case::chia_to_chia(assert_scheme_conversion_round_trips::<BlsScChia, BlsScChia>)]
  #[case::ietf_to_ietf(assert_scheme_conversion_round_trips::<BlsScIetf, BlsScIetf>)]
  fn scheme_conversion_round_trips(#[case] assertion: fn()) {
    assertion();
  }

  /// A key Chia admits and IETF does not must not become an IETF key by being
  /// converted, or the conversion would launder it past the check that refused
  /// it at the decoder.
  #[rstest]
  fn scheme_conversion_applies_target_rules() {
    let off_subgroup = BlsPublicKey::<BlsScChia>::from_bytes(&G1_OFF_SUBGROUP_CHIA).unwrap();

    assert!(off_subgroup.to_scheme::<BlsScChia>().is_ok());
    assert!(off_subgroup.to_scheme::<BlsScIetf>().is_err());
  }

  /// Rejection alone is weak evidence, since the policy test below cannot
  /// tell a composite-order point from a malformed one. Hold both encodings
  /// to a single point so that distinction is made here.
  #[rstest]
  fn off_subgroup_g1_fixtures_are_one_point() {
    let chia = BlsPublicKey::<BlsScChia>::from_bytes(&G1_OFF_SUBGROUP_CHIA).unwrap();
    let point = BlsScChia::pk_to_g1(&chia.0).unwrap();

    assert!(!point.in_subgroup(), "fixture is not off-subgroup");
    assert_eq!(
      point.to_affine().compress(),
      G1_OFF_SUBGROUP_IETF,
      "the IETF fixture encodes a different point"
    );
  }

  fn assert_pk_roundtrip<S: BlsScheme>() {
    let pk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap().public_key();
    let bytes = pk.to_bytes();
    assert_eq!(BlsPublicKey::<S>::from_bytes(&bytes).unwrap().to_bytes(), bytes);
  }

  #[rstest]
  #[case::chia(assert_pk_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_pk_roundtrip::<BlsScIetf>)]
  fn serialization_roundtrip(#[case] assertion: fn()) {
    assertion();
  }

  /// Neither decoder yields an identity key. Chia guards the marker and the
  /// all-zero buffer outright, IETF reaches the same answer through
  /// `validate`, which refuses the identity despite a canonical encoding.
  fn assert_identity_public_key_rejected<S: BlsScheme>() {
    let mut infinity = [0u8; 48];
    infinity[0] = 0xc0;
    assert!(BlsPublicKey::<S>::from_bytes(&infinity).is_err());
    assert!(BlsPublicKey::<S>::from_bytes(&[0u8; 48]).is_err());
  }

  #[rstest]
  #[case::chia(assert_identity_public_key_rejected::<BlsScChia>)]
  #[case::ietf(assert_identity_public_key_rejected::<BlsScIetf>)]
  fn identity_public_key_rejected(#[case] assertion: fn()) {
    assertion();
  }

  /// Chia has no prime-order subgroup check, so a composite-order point decodes
  /// and round-trips; refusing it would diverge on a value Chia encodings
  /// already carry. IETF validates and refuses it.
  fn assert_off_subgroup_public_key_policy<S: BlsScheme>(encoded: &[u8; 48], accepted: bool) {
    match BlsPublicKey::<S>::from_bytes(encoded) {
      Ok(pk) => {
        assert!(accepted, "off-subgroup key accepted");
        assert_eq!(pk.to_bytes(), *encoded);
      }
      Err(_) => assert!(!accepted, "off-subgroup key rejected"),
    }
  }

  #[rstest]
  #[case::chia(assert_off_subgroup_public_key_policy::<BlsScChia>, &G1_OFF_SUBGROUP_CHIA, true)]
  #[case::ietf(assert_off_subgroup_public_key_policy::<BlsScIetf>, &G1_OFF_SUBGROUP_IETF, false)]
  fn off_subgroup_public_key_policy(
    #[case] assertion: fn(&[u8; 48], bool),
    #[case] encoded: &[u8; 48],
    #[case] accepted: bool,
  ) {
    assertion(encoded, accepted);
  }

  /// An `x` at or above the field prime is not a coordinate, and neither scheme
  /// reduces it into range.
  ///
  /// Under Chia the refusal is a divergence rather than agreement, since the
  /// read error is suppressed there and the G1 value left behind is not the
  /// identity, which is all the consumer tests before calling a key valid.
  ///
  /// It stands because the alternative is a decoded point for bytes that hold
  /// none, and the value left behind verifies nothing in any case.
  ///
  /// Each case was measured, not assumed: `p`, `p + 4` and an all-ones `x`
  /// decode under Chia and are refused under IETF.
  fn assert_out_of_range_coordinate_rejected<S: BlsScheme>(encoded: [u8; 48]) {
    assert!(BlsPublicKey::<S>::from_bytes(&encoded).is_err());
  }

  #[rstest]
  #[case::chia_eq_prime(assert_out_of_range_coordinate_rejected::<BlsScChia>, G1_X_EQ_PRIME_CHIA)]
  #[case::chia_gt_prime(assert_out_of_range_coordinate_rejected::<BlsScChia>, G1_X_GE_PRIME_CHIA)]
  #[case::chia_max(assert_out_of_range_coordinate_rejected::<BlsScChia>, G1_X_MAX_CHIA)]
  #[case::ietf_eq_prime(assert_out_of_range_coordinate_rejected::<BlsScIetf>, ietf_g1_encoding(G1_X_EQ_PRIME_CHIA))]
  #[case::ietf_gt_prime(assert_out_of_range_coordinate_rejected::<BlsScIetf>, ietf_g1_encoding(G1_X_GE_PRIME_CHIA))]
  #[case::ietf_max(assert_out_of_range_coordinate_rejected::<BlsScIetf>, ietf_g1_encoding(G1_X_MAX_CHIA))]
  fn out_of_range_coordinate_rejected(#[case] assertion: fn([u8; 48]), #[case] encoded: [u8; 48]) {
    assertion(encoded);
  }

  /// The legacy decoder normalizes stray high bits, so a mutated encoding
  /// round-trips back to its canonical form.
  #[rstest]
  fn chia_masks_stray_public_key_bits() {
    let clean = BlsSecretKey::<BlsScChia>::from_ikm(&RSEED[0])
      .unwrap()
      .public_key()
      .to_bytes();

    let mut mutated = clean;
    mutated[0] |= 0x20;
    let decoded = BlsPublicKey::<BlsScChia>::from_bytes(&mutated).unwrap();
    assert_eq!(decoded.to_bytes(), clean);
  }

  /// Bit 6 has no meaning on its own in the Chia encoding and is masked like
  /// bit 5; paired with bit 7 it is read as the infinity marker instead, which
  /// the decoder rejects whether or not the rest of the buffer is zero.
  #[rstest]
  fn chia_masks_stray_bit_six() {
    let (pk_legacy, _) = ser_pairs(SerType::PublicKey).swap_remove(0);

    // Clear the sign bit so bit 6 is the only stray bit under test.
    let mut clean: [u8; 48] = arr_from_hex(&pk_legacy);
    clean[0] &= 0x1f;
    assert_eq!(BlsPublicKey::<BlsScChia>::from_bytes(&clean).unwrap().to_bytes(), clean);

    let mut stray = clean;
    stray[0] |= 0x40;
    assert_eq!(
      BlsPublicKey::<BlsScChia>::from_bytes(&stray).unwrap().to_bytes(),
      clean,
      "bit 6 alone must be masked, not read as a flag"
    );

    let mut marker = clean;
    marker[0] |= 0xc0;
    assert!(
      BlsPublicKey::<BlsScChia>::from_bytes(&marker).is_err(),
      "bits 6 and 7 together mark infinity, which the decoder rejects"
    );
  }

  fn assert_pk_bytes_canonical<S: BlsScheme>() {
    let clean = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap().public_key().to_bytes();
    assert!(BlsPkBytes::from_bytes(clean).is_canonical::<S>());
    assert!(BlsPkBytes::from_bytes([0u8; 48]).is_canonical::<S>());

    let mut infinity = [0u8; 48];
    infinity[0] = 0xc0;
    assert!(!BlsPkBytes::from_bytes(infinity).is_canonical::<S>());
  }

  #[rstest]
  #[case::chia(assert_pk_bytes_canonical::<BlsScChia>)]
  #[case::ietf(assert_pk_bytes_canonical::<BlsScIetf>)]
  fn pk_bytes_canonical_keys_and_null(#[case] assertion: fn()) {
    assertion();
  }

  /// The Chia decoder masks stray bits, so only `is_canonical` tells a masked
  /// encoding apart.
  #[rstest]
  #[case::bit_five(0x20)]
  #[case::bit_six(0x40)]
  fn chia_pk_bytes_with_stray_bits_are_not_canonical(#[case] stray: u8) {
    let clean = BlsSecretKey::<BlsScChia>::from_ikm(&RSEED[0])
      .unwrap()
      .public_key()
      .to_bytes();
    // A set sign bit would turn `0x40` into the infinity marker `0xc0`.
    assert_eq!(clean[0] & 0x80, 0);
    let mut mutated = clean;
    mutated[0] |= stray;

    assert!(BlsPublicKey::<BlsScChia>::from_bytes(&mutated).is_ok());
    assert!(!BlsPkBytes::from_bytes(mutated).is_canonical::<BlsScChia>());
  }

  fn assert_pk_bytes_not_canonical<S: BlsScheme>(encoded: [u8; 48]) {
    assert!(!BlsPkBytes::from_bytes(encoded).is_canonical::<S>());
  }

  #[rstest]
  #[case::chia_x_eq_prime(assert_pk_bytes_not_canonical::<BlsScChia>, G1_X_EQ_PRIME_CHIA)]
  #[case::ietf_x_eq_prime(assert_pk_bytes_not_canonical::<BlsScIetf>, ietf_g1_encoding(G1_X_EQ_PRIME_CHIA))]
  #[case::ietf_off_subgroup(assert_pk_bytes_not_canonical::<BlsScIetf>, G1_OFF_SUBGROUP_IETF)]
  fn pk_bytes_undecodable_are_not_canonical(#[case] assertion: fn([u8; 48]), #[case] encoded: [u8; 48]) {
    assertion(encoded);
  }

  /// `x = 0` with the sign bit set, (0, -2), reads under the legacy scheme as
  /// a key that encodes back to the same bytes, as in the reference
  /// implementation.
  #[rstest]
  fn chia_reads_x_zero_with_sign_bit() {
    let mut encoded = [0u8; 48];
    encoded[0] = 0x80;

    let pk = BlsPublicKey::<BlsScChia>::from_bytes(&encoded).unwrap();
    assert_eq!(pk.to_bytes(), encoded);
    assert!(BlsPkBytes::from_bytes(encoded).is_canonical::<BlsScChia>());
  }

  /// With `x = 0` and the sign bit clear, stray bits 5-6 mask down to the null
  /// encoding, so the bytes are neither a key nor canonical.
  #[rstest]
  #[case::bit_five(0x20)]
  #[case::bit_six(0x40)]
  #[case::bits_five_six(0x60)]
  fn chia_x_zero_with_stray_bits_is_not_a_key(#[case] byte0: u8) {
    let mut encoded = [0u8; 48];
    encoded[0] = byte0;

    let bytes = BlsPkBytes::from_bytes(encoded);
    assert!(bytes.to::<BlsScChia>().is_err());
    assert!(!bytes.is_canonical::<BlsScChia>());
  }

  /// The same G1 point encodes differently under the two schemes, and each
  /// encoding must round-trip through the wrapper of its own scheme.
  #[rstest]
  fn serialization_formats_match_vectors() {
    for (pk_legacy, pk_ietf) in ser_pairs(SerType::PublicKey) {
      let legacy = BlsPublicKey::<BlsScChia>::from_bytes(&arr_from_hex(&pk_legacy)).unwrap();
      assert_eq!(legacy.to_bytes().to_lower_hex_string(), pk_legacy);

      let ietf = BlsPublicKey::<BlsScIetf>::from_bytes(&arr_from_hex(&pk_ietf)).unwrap();
      assert_eq!(ietf.to_bytes().to_lower_hex_string(), pk_ietf);

      assert_ne!(pk_legacy, pk_ietf, "legacy and ietf should differ");
    }
  }

  fn assert_aggregate_vectors<S: BlsScheme>(scheme: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_aggregate").scope(scheme);
    let vecs: Vec<AggPkVec> = corpus.vectors("pk");

    for v in &vecs {
      let pks: Vec<BlsPublicKey<S>> = v
        .pks
        .iter()
        .map(|pk| BlsPublicKey::<S>::from_bytes(&arr_from_hex(pk)).unwrap())
        .collect();
      let refs: Vec<&BlsPublicKey<S>> = pks.iter().collect();
      let agg = BlsPublicKey::<S>::aggregate(&refs).unwrap();
      assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_pk);
    }
  }

  #[rstest]
  #[case::chia(assert_aggregate_vectors::<BlsScChia>, "chia")]
  #[case::ietf(assert_aggregate_vectors::<BlsScIetf>, "ietf")]
  fn aggregate_matches_vectors(#[case] assertion: fn(&str), #[case] scheme: &str) {
    assertion(scheme);
  }

  fn assert_secure_aggregate_is_what_verify_checks<S: BlsScheme>(scheme: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_secure_aggregate").scope(scheme);
    let vecs: Vec<SecureVec> = corpus.vectors("verify");
    assert!(!vecs.is_empty(), "corpus section is empty");

    for v in &vecs {
      let pks: Vec<BlsPublicKey<S>> = v
        .pks
        .iter()
        .map(|pk| BlsPublicKey::<S>::from_bytes(&arr_from_hex(pk)).unwrap())
        .collect();
      let refs: Vec<&BlsPublicKey<S>> = pks.iter().collect();
      let agg_pk = BlsPublicKey::<S>::secure_aggregate(&refs).unwrap();

      let sig = BlsSignature::<S>::from_bytes(&arr_from_hex(&v.agg_sig_secure)).unwrap();
      let msg: [u8; 32] = arr_from_hex(&v.msg);
      assert!(agg_pk.verify_digest(&msg, &sig).is_ok());
      assert!(sig.secure_verify_aggregates_digest(&msg, &refs).is_ok());
    }
  }

  #[rstest]
  #[case::chia(assert_secure_aggregate_is_what_verify_checks::<BlsScChia>, "chia")]
  #[case::ietf(assert_secure_aggregate_is_what_verify_checks::<BlsScIetf>, "ietf")]
  fn secure_aggregate_is_what_verify_checks(#[case] assertion: fn(&str), #[case] scheme: &str) {
    assertion(scheme);
  }

  /// The weights go by the sorted keys, so the set decides the aggregate and
  /// the order it arrives in does not. A plain sum would ignore the weights
  /// and land somewhere else entirely.
  fn assert_secure_aggregate_follows_the_set<S: BlsScheme>() {
    let pks: Vec<BlsPublicKey<S>> = [&RSEED[0], &RSEED[1], &RSEED[2]]
      .iter()
      .map(|ikm| BlsSecretKey::<S>::from_ikm(*ikm).unwrap().public_key())
      .collect();

    let straight = BlsPublicKey::<S>::secure_aggregate(&[&pks[0], &pks[1], &pks[2]]).unwrap();
    let rotated = BlsPublicKey::<S>::secure_aggregate(&[&pks[2], &pks[0], &pks[1]]).unwrap();
    assert_eq!(straight, rotated);

    let plain = BlsPublicKey::<S>::aggregate(&[&pks[0], &pks[1], &pks[2]]).unwrap();
    assert_ne!(straight, plain, "the weights left no mark on the sum");
  }

  #[rstest]
  #[case::chia(assert_secure_aggregate_follows_the_set::<BlsScChia>)]
  #[case::ietf(assert_secure_aggregate_follows_the_set::<BlsScIetf>)]
  fn secure_aggregate_follows_the_set(#[case] assertion: fn()) {
    assertion();
  }

  /// A lone signer is still weighted, so the aggregate is not that signer's
  /// key; nothing is left to weight for an empty set, which is refused as it
  /// is elsewhere.
  fn assert_secure_aggregate_edges<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let pk = sk.public_key();

    let alone = BlsPublicKey::<S>::secure_aggregate(&[&pk]).unwrap();
    assert_ne!(alone, pk, "a single key went through unweighted");

    let sig = sk.sign_digest(&MSG_8BADFOOD);
    let weighted = BlsSignature::<S>::secure_aggregate(&[&sig], &[&pk]).unwrap();
    assert!(alone.verify_digest(&MSG_8BADFOOD, &weighted).is_ok());

    let none: [&BlsPublicKey<S>; 0] = [];
    assert_eq!(
      BlsPublicKey::<S>::secure_aggregate(&none),
      Err(BlsError::EmptyAggregation)
    );
  }

  #[rstest]
  #[case::chia(assert_secure_aggregate_edges::<BlsScChia>)]
  #[case::ietf(assert_secure_aggregate_edges::<BlsScIetf>)]
  fn secure_aggregate_edges(#[case] assertion: fn()) {
    assertion();
  }

  cfg_if! {
    if #[cfg(feature = "serde")] {
      use dash_dev::{assert_cbor_raw, assert_json_rt, to_json};
      use dash_types::Hashable;

      #[rstest]
      fn serde_emits_hex_string() {
        let (pk_legacy, pk_ietf) = ser_pairs(SerType::PublicKey).swap_remove(0);

        let chia = BlsPublicKey::<BlsScChia>::from_bytes(&arr_from_hex(&pk_legacy)).unwrap();
        let ietf = BlsPublicKey::<BlsScIetf>::from_bytes(&arr_from_hex(&pk_ietf)).unwrap();
        assert_eq!(to_json(&chia), format!("\"{pk_legacy}\""));
        assert_eq!(to_json(&ietf), format!("\"{pk_ietf}\""));
      }

      #[rstest]
      fn serde_roundtrip() {
        let (pk_legacy, pk_ietf) = ser_pairs(SerType::PublicKey).swap_remove(0);

        assert_json_rt(&BlsPublicKey::<BlsScChia>::from_bytes(&arr_from_hex(&pk_legacy)).unwrap());
        assert_json_rt(&BlsPublicKey::<BlsScIetf>::from_bytes(&arr_from_hex(&pk_ietf)).unwrap());
      }

      #[rstest]
      fn serde_carries_bytes_as_data() {
        let (pk_legacy, _) = ser_pairs(SerType::PublicKey).swap_remove(0);
        let pk = BlsPublicKey::<BlsScChia>::from_bytes(&arr_from_hex(&pk_legacy)).unwrap();
        let hash = Hashable::hash(&pk);

        // The hash renders reversed, but a binary format carries storage order.
        assert_cbor_raw(&pk, &pk.to_bytes());
        assert_cbor_raw(&hash, hash.as_bytes());
      }
    }
  }
}
