//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS signature aggregation and aggregate verification.

use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::scheme_ops::BlsScheme;
use super::sig_basic::BlsSignature;
use crate::prelude::*;

impl<S: BlsScheme> BlsSignature<S> {
  /// Aggregate multiple signatures into one.
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no signatures are given, or
  /// `InvalidSignature` when a signature fails to aggregate.
  pub fn aggregate(sigs: &[&Self]) -> Result<Self, BlsError> {
    let inner_refs: Vec<&S::InnerSig> = sigs.iter().map(|s| &s.0).collect();
    S::aggregate_sig(&inner_refs).map(Self::from_inner)
  }

  /// Remove `other` from this signature, leaving behind the aggregate of the
  /// rest.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSignature` when either signature or the difference fails
  /// to decode, or when the difference is the identity.
  pub fn sub_insecure(&self, other: &Self) -> Result<Self, BlsError> {
    S::sub_sig(&self.0, &other.0).map(Self::from_inner)
  }

  /// Verify an aggregated signature where every signer signed
  /// the same message.
  ///
  /// Binds only the sum of `pks`, so a key chosen after seeing an honest one
  /// can cancel it out. Every key must already be bound to its holder, by a
  /// proof of possession or by provenance.
  ///
  /// Without such a binding, use [`Self::secure_verify_aggregates`], which
  /// weights each key.
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no keys are given, or `VerifyFailed` on
  /// mismatch.
  pub fn fast_verify_aggregates(&self, msg: S::Msg<'_>, pks: &[&BlsPublicKey<S>]) -> Result<(), BlsError> {
    let inner_pks: Vec<&S::InnerPk> = pks.iter().map(|k| &k.0).collect();
    S::fast_verify_aggregates(&self.0, msg, &inner_pks)
  }

  /// Aggregate signatures under public-key weighting, the counterpart to
  /// [`Self::secure_verify_aggregates`]: each signature is raised to its own
  /// key's weight, so a rogue key cannot cancel an honest one.
  ///
  /// # Errors
  ///
  /// Returns `CountMismatch` when the signature and key counts differ,
  /// `EmptyAggregation` when nothing is given, or `InvalidSignature` when a
  /// signature or the weighted sum fails to decode.
  pub fn secure_aggregate(sigs: &[&Self], pks: &[&BlsPublicKey<S>]) -> Result<Self, BlsError> {
    let inner_sigs: Vec<&S::InnerSig> = sigs.iter().map(|sig| &sig.0).collect();
    let inner_pks: Vec<&S::InnerPk> = pks.iter().map(|pk| &pk.0).collect();
    S::secure_aggregate_sig(&inner_sigs, &inner_pks).map(Self::from_inner)
  }

  /// Securely aggregate and verify signatures with public-key
  /// weighting.
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no keys are given, `InvalidPublicKey`
  /// when a key fails to decode, or `VerifyFailed` on mismatch.
  pub fn secure_verify_aggregates(&self, msg: S::Msg<'_>, pks: &[&BlsPublicKey<S>]) -> Result<(), BlsError> {
    let inner_pks: Vec<&S::InnerPk> = pks.iter().map(|k| &k.0).collect();
    S::secure_verify_aggregates(&self.0, msg, &inner_pks)
  }
}

impl<S: BlsScheme> BlsSignature<S> {
  /// Verify an aggregate carrying one message per signer.
  ///
  /// # Errors
  ///
  /// Returns `CountMismatch` when the message and key counts differ,
  /// `EmptyAggregation` when no keys are given, `DuplicateMessage` where the
  /// scheme refuses a repeat, or `VerifyFailed` on mismatch.
  pub fn verify_aggregates(&self, msgs: &[S::Msg<'_>], pks: &[&BlsPublicKey<S>]) -> Result<(), BlsError> {
    let inner_pks: Vec<_> = pks.iter().map(|k| &k.0).collect();
    S::verify_aggregates(&self.0, msgs, &inner_pks)
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::secret_ops::BlsSecretKey;
  use crate::bls::tests::{MSG_8BADFOOD, MSG_DEADBEEF, RSEED};
  use crate::bls::{BlsScChia, BlsScIetf};

  use dash_dev::{arr_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct SecureVec {
    msg: String,
    pks: Vec<String>,
    sigs: Vec<String>,
    agg_sig_secure: String,
  }

  #[derive(Deserialize)]
  struct AggSigVec {
    sigs: Vec<String>,
    agg_sig: String,
  }

  #[derive(Deserialize)]
  struct AggVerifyVec {
    pks: Vec<String>,
    msgs: Vec<String>,
    agg_sig: String,
    accepted: bool,
  }

  fn assert_aggregate_same_message<S: BlsScheme>() {
    let sk1 = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let sk2 = BlsSecretKey::<S>::from_ikm(&RSEED[1]).unwrap();
    let sig1 = sk1.sign(S::msg_ref(&MSG_DEADBEEF));
    let sig2 = sk2.sign(S::msg_ref(&MSG_DEADBEEF));

    let agg = BlsSignature::<S>::aggregate(&[&sig1, &sig2]).unwrap();
    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();

    let msg = S::msg_ref(&MSG_DEADBEEF);
    assert!(agg.fast_verify_aggregates(msg, &[&pk1, &pk2]).is_ok());
    // A key not in the set must make verification fail.
    let pk3 = BlsSecretKey::<S>::from_ikm(&RSEED[2]).unwrap().public_key();
    assert!(agg.fast_verify_aggregates(msg, &[&pk1, &pk3]).is_err());
    // Rogue-key resistance: a naive aggregate must not pass weighted verify.
    assert!(agg.secure_verify_aggregates(msg, &[&pk1, &pk2]).is_err());
  }

  #[rstest]
  #[case::chia(assert_aggregate_same_message::<BlsScChia>)]
  #[case::ietf(assert_aggregate_same_message::<BlsScIetf>)]
  fn aggregate_and_verify_same_message(#[case] assertion: fn()) {
    assertion();
  }

  /// Subtraction is the inverse of aggregation, so taking one signature back
  /// out of the pair leaves the other exactly as it was signed.
  fn assert_sub_insecure_undoes_aggregation<S: BlsScheme>() {
    let sk1 = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let sk2 = BlsSecretKey::<S>::from_ikm(&RSEED[1]).unwrap();
    let msg = S::msg_ref(&MSG_DEADBEEF);

    let sig1 = sk1.sign(msg);
    let sig2 = sk2.sign(msg);
    let agg = BlsSignature::<S>::aggregate(&[&sig1, &sig2]).unwrap();

    assert_eq!(agg.sub_insecure(&sig1).unwrap(), sig2);
    assert_eq!(agg.sub_insecure(&sig2).unwrap(), sig1);
    assert!(sk2.public_key().verify(msg, &agg.sub_insecure(&sig1).unwrap()).is_ok());
  }

  #[rstest]
  #[case::chia(assert_sub_insecure_undoes_aggregation::<BlsScChia>)]
  #[case::ietf(assert_sub_insecure_undoes_aggregation::<BlsScIetf>)]
  fn sub_insecure_undoes_aggregation(#[case] assertion: fn()) {
    assertion();
  }

  /// A signature taken from itself leaves the identity, which signs nothing.
  /// Only the IETF decoder refuses identities, so a check is added to ensure
  /// rejection under both schemes.
  fn assert_sub_insecure_rejects_the_identity<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let sig = sk.sign(S::msg_ref(&MSG_DEADBEEF));

    assert_eq!(sig.sub_insecure(&sig), Err(BlsError::InvalidSignature));
  }

  #[rstest]
  #[case::chia(assert_sub_insecure_rejects_the_identity::<BlsScChia>)]
  #[case::ietf(assert_sub_insecure_rejects_the_identity::<BlsScIetf>)]
  fn sub_insecure_rejects_the_identity(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_secure_verify<S: BlsScheme>(scheme: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_secure_aggregate").scope(scheme);
    let vecs: Vec<SecureVec> = corpus.vectors("verify");
    for v in &vecs {
      let pks: Vec<BlsPublicKey<S>> = v
        .pks
        .iter()
        .map(|pk| BlsPublicKey::<S>::from_bytes(&arr_from_hex(pk)).unwrap())
        .collect();
      let pk_refs: Vec<&BlsPublicKey<S>> = pks.iter().collect();
      let agg = BlsSignature::<S>::from_bytes(&arr_from_hex(&v.agg_sig_secure)).unwrap();
      let msg: [u8; 32] = arr_from_hex(&v.msg);
      assert!(agg.secure_verify_aggregates(S::msg_ref(&msg), &pk_refs).is_ok());
    }
  }

  #[rstest]
  #[case::chia(assert_secure_verify::<BlsScChia>, "chia")]
  #[case::ietf(assert_secure_verify::<BlsScIetf>, "ietf")]
  fn secure_verify_matches_vectors(#[case] assertion: fn(&str), #[case] scheme: &str) {
    assertion(scheme);
  }

  /// Per-signer messages verify, and each binds to its own signer, swapping
  /// the two fails. Both schemes agree here, along with the count and
  /// emptiness contracts.
  fn assert_distinct_messages_verify<S: BlsScheme>() {
    let sk1 = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let sk2 = BlsSecretKey::<S>::from_ikm(&RSEED[1]).unwrap();

    let msg1 = S::msg_ref(&MSG_8BADFOOD);
    let msg2 = S::msg_ref(&MSG_DEADBEEF);
    let sig1 = sk1.sign(msg1);
    let sig2 = sk2.sign(msg2);
    let agg = BlsSignature::<S>::aggregate(&[&sig1, &sig2]).unwrap();

    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();
    assert!(agg.verify_aggregates(&[msg1, msg2], &[&pk1, &pk2]).is_ok());
    assert!(agg.verify_aggregates(&[msg2, msg1], &[&pk1, &pk2]).is_err());

    assert_eq!(
      agg.verify_aggregates(&[msg1], &[&pk1, &pk2]),
      Err(BlsError::CountMismatch)
    );
    assert_eq!(agg.verify_aggregates(&[], &[]), Err(BlsError::EmptyAggregation));
  }

  #[rstest]
  #[case::chia(assert_distinct_messages_verify::<BlsScChia>)]
  #[case::ietf(assert_distinct_messages_verify::<BlsScIetf>)]
  fn verify_aggregate_distinct_messages(#[case] assertion: fn()) {
    assertion();
  }

  /// A repeat collapses the check onto the sum of the repeated signers' keys,
  /// which either could have picked to cancel the other. IETF refuses it; Chia
  /// accepts.
  fn assert_duplicate_message_policy<S: BlsScheme>(accepted: bool) {
    let sk1 = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let sk2 = BlsSecretKey::<S>::from_ikm(&RSEED[1]).unwrap();

    let msg = S::msg_ref(&MSG_DEADBEEF);
    let sig1 = sk1.sign(msg);
    let sig2 = sk2.sign(msg);
    let agg = BlsSignature::<S>::aggregate(&[&sig1, &sig2]).unwrap();

    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();
    let res = agg.verify_aggregates(&[msg, msg], &[&pk1, &pk2]);
    assert_eq!(res.is_ok(), accepted, "duplicate-message policy");
    if !accepted {
      assert_eq!(res, Err(BlsError::DuplicateMessage));
    }

    // Sound results either way through the shared-message entry point, so the
    // refusal above is a matter of policy and not a bad aggregate.
    assert!(agg.fast_verify_aggregates(msg, &[&pk1, &pk2]).is_ok());
  }

  #[rstest]
  #[case::chia(assert_duplicate_message_policy::<BlsScChia>, true)]
  #[case::ietf(assert_duplicate_message_policy::<BlsScIetf>, false)]
  fn verify_policy_duplicate_messages(#[case] assertion: fn(bool), #[case] accepted: bool) {
    assertion(accepted);
  }

  fn assert_aggregate_verify_matches_vectors<S: BlsScheme>(scheme: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_aggregate").scope(scheme);
    let vecs: Vec<AggVerifyVec> = corpus.vectors("verify");
    assert!(!vecs.is_empty(), "corpus section is empty");

    for v in &vecs {
      let pks: Vec<BlsPublicKey<S>> = v
        .pks
        .iter()
        .map(|pk| BlsPublicKey::<S>::from_bytes(&arr_from_hex(pk)).unwrap())
        .collect();
      let pk_refs: Vec<&BlsPublicKey<S>> = pks.iter().collect();
      let msgs: Vec<[u8; 32]> = v.msgs.iter().map(|m| arr_from_hex(m)).collect();
      let msg_refs: Vec<S::Msg<'_>> = msgs.iter().map(|m| S::msg_ref(m)).collect();
      let agg = BlsSignature::<S>::from_bytes(&arr_from_hex(&v.agg_sig)).unwrap();
      assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_sig);

      assert_eq!(
        agg.verify_aggregates(&msg_refs, &pk_refs).is_ok(),
        v.accepted,
        "reference verdict for {} signers",
        v.pks.len()
      );
    }
  }

  #[rstest]
  #[case::chia(assert_aggregate_verify_matches_vectors::<BlsScChia>, "chia")]
  #[case::ietf(assert_aggregate_verify_matches_vectors::<BlsScIetf>, "ietf")]
  fn aggregate_verify_matches_vectors(#[case] assertion: fn(&str), #[case] scheme: &str) {
    assertion(scheme);
  }

  /// The weighted aggregate is what the weighted verify accepts, and the
  /// weights follow the sorted keys rather than the caller's order, so the
  /// same set aggregates alike however it is presented.
  fn assert_secure_aggregate_round_trips<S: BlsScheme>() {
    let sk1 = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let sk2 = BlsSecretKey::<S>::from_ikm(&RSEED[1]).unwrap();
    let msg = S::msg_ref(&MSG_DEADBEEF);

    let sig1 = sk1.sign(msg);
    let sig2 = sk2.sign(msg);
    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();

    let agg = BlsSignature::<S>::secure_aggregate(&[&sig1, &sig2], &[&pk1, &pk2]).unwrap();
    assert!(agg.secure_verify_aggregates(msg, &[&pk1, &pk2]).is_ok());

    let swapped = BlsSignature::<S>::secure_aggregate(&[&sig2, &sig1], &[&pk2, &pk1]).unwrap();
    assert_eq!(agg, swapped, "weights follow the keys, not the argument order");

    // A plain aggregate carries no weights, so the weighted check rejects it.
    let plain = BlsSignature::<S>::aggregate(&[&sig1, &sig2]).unwrap();
    assert!(plain.secure_verify_aggregates(msg, &[&pk1, &pk2]).is_err());

    assert_eq!(
      BlsSignature::<S>::secure_aggregate(&[&sig1], &[&pk1, &pk2]),
      Err(BlsError::CountMismatch)
    );
    assert_eq!(
      BlsSignature::<S>::secure_aggregate(&[], &[]),
      Err(BlsError::EmptyAggregation)
    );
  }

  /// A wrong sort order or weight formula would still round-trip against our
  /// own verifier above, so only the recorded aggregate can catch a convention
  /// that is self-consistent and still not canonical.
  fn assert_secure_aggregate_matches_vectors<S: BlsScheme>(scheme: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_secure_aggregate").scope(scheme);
    let vecs: Vec<SecureVec> = corpus.vectors("verify");
    for v in &vecs {
      let pks: Vec<BlsPublicKey<S>> = v
        .pks
        .iter()
        .map(|pk| BlsPublicKey::<S>::from_bytes(&arr_from_hex(pk)).unwrap())
        .collect();
      let sigs: Vec<BlsSignature<S>> = v
        .sigs
        .iter()
        .map(|sig| BlsSignature::<S>::from_bytes(&arr_from_hex(sig)).unwrap())
        .collect();
      let pk_refs: Vec<&BlsPublicKey<S>> = pks.iter().collect();
      let sig_refs: Vec<&BlsSignature<S>> = sigs.iter().collect();

      let agg = BlsSignature::<S>::secure_aggregate(&sig_refs, &pk_refs).unwrap();
      assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_sig_secure);
    }
  }

  #[rstest]
  #[case::chia(assert_secure_aggregate_matches_vectors::<BlsScChia>, "chia")]
  #[case::ietf(assert_secure_aggregate_matches_vectors::<BlsScIetf>, "ietf")]
  fn secure_aggregate_matches_vectors(#[case] assertion: fn(&str), #[case] scheme: &str) {
    assertion(scheme);
  }

  #[rstest]
  #[case::chia(assert_secure_aggregate_round_trips::<BlsScChia>)]
  #[case::ietf(assert_secure_aggregate_round_trips::<BlsScIetf>)]
  fn secure_aggregate_round_trips(#[case] assertion: fn()) {
    assertion();
  }

  /// Weights go by position in the sorted keys, so a repeated key leaves two
  /// weights and nothing in the keys to say which signature takes which.
  ///
  /// A stable sort settles that by argument order and an unstable one settles
  /// it otherwise, so a duplicated key costs the caller a canonical aggregate
  /// whichever implementation computes it.
  ///
  /// [`secure_aggregate_round_trips`] holds the distinct-key case, where the
  /// keys give a total order and the argument order stops mattering.
  fn assert_duplicate_key_pairing_is_order_bound<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let pk = sk.public_key();

    let sig_a = sk.sign(S::msg_ref(&MSG_8BADFOOD));
    let sig_b = sk.sign(S::msg_ref(&MSG_DEADBEEF));

    let ab = BlsSignature::<S>::secure_aggregate(&[&sig_a, &sig_b], &[&pk, &pk]).unwrap();
    let ba = BlsSignature::<S>::secure_aggregate(&[&sig_b, &sig_a], &[&pk, &pk]).unwrap();
    assert_ne!(ab, ba, "a repeated key leaves the pairing to the caller's order");
  }

  #[rstest]
  #[case::chia(assert_duplicate_key_pairing_is_order_bound::<BlsScChia>)]
  #[case::ietf(assert_duplicate_key_pairing_is_order_bound::<BlsScIetf>)]
  fn secure_aggregate_duplicate_key_pairing(#[case] assertion: fn()) {
    assertion();
  }

  /// An empty aggregate has no signers to bind, so both aggregation entry
  /// points reject it rather than returning the identity.
  fn assert_empty_aggregation_rejected<S: BlsScheme>() {
    let pks: [&BlsPublicKey<S>; 0] = [];
    let sigs: [&BlsSignature<S>; 0] = [];
    assert!(BlsPublicKey::<S>::aggregate(&pks).is_err());
    assert!(BlsSignature::<S>::aggregate(&sigs).is_err());
  }

  #[rstest]
  #[case::chia(assert_empty_aggregation_rejected::<BlsScChia>)]
  #[case::ietf(assert_empty_aggregation_rejected::<BlsScIetf>)]
  fn aggregate_empty_fails(#[case] assertion: fn()) {
    assertion();
  }

  /// Aggregation is a group sum, so neither the aggregate nor the verification
  /// may depend on the order the caller supplies.
  fn assert_order_independent<S: BlsScheme>() {
    let sks: Vec<BlsSecretKey<S>> = [RSEED[0], RSEED[1], RSEED[2]]
      .iter()
      .map(|seed| BlsSecretKey::<S>::from_ikm(seed).unwrap())
      .collect();
    let sigs: Vec<BlsSignature<S>> = sks.iter().map(|sk| sk.sign(S::msg_ref(&MSG_DEADBEEF))).collect();
    let pks: Vec<BlsPublicKey<S>> = sks.iter().map(BlsSecretKey::public_key).collect();

    let straight = BlsSignature::<S>::aggregate(&[&sigs[0], &sigs[1], &sigs[2]]).unwrap();
    let rotated = BlsSignature::<S>::aggregate(&[&sigs[2], &sigs[0], &sigs[1]]).unwrap();
    assert_eq!(straight, rotated);

    let msg = S::msg_ref(&MSG_DEADBEEF);
    assert!(straight
      .fast_verify_aggregates(msg, &[&pks[0], &pks[1], &pks[2]])
      .is_ok());
    assert!(straight
      .fast_verify_aggregates(msg, &[&pks[2], &pks[0], &pks[1]])
      .is_ok());
  }

  #[rstest]
  #[case::chia(assert_order_independent::<BlsScChia>)]
  #[case::ietf(assert_order_independent::<BlsScIetf>)]
  fn aggregate_order_independent(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_aggregate_vectors<S: BlsScheme>(scheme: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_aggregate").scope(scheme);
    let vecs: Vec<AggSigVec> = corpus.vectors("sig");

    for v in &vecs {
      let sigs: Vec<BlsSignature<S>> = v
        .sigs
        .iter()
        .map(|sig| BlsSignature::<S>::from_bytes(&arr_from_hex(sig)).unwrap())
        .collect();
      let refs: Vec<&BlsSignature<S>> = sigs.iter().collect();
      let agg = BlsSignature::<S>::aggregate(&refs).unwrap();
      assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_sig);
    }
  }

  #[rstest]
  #[case::chia(assert_aggregate_vectors::<BlsScChia>, "chia")]
  #[case::ietf(assert_aggregate_vectors::<BlsScIetf>, "ietf")]
  fn aggregate_matches_vectors(#[case] assertion: fn(&str), #[case] scheme: &str) {
    assertion(scheme);
  }

  /// Aggregating a point with its own negation cancels to the identity, which
  /// then verifies against any message at all. The legacy scheme accepts that,
  /// and consensus depends on it continuing to; the IETF scheme rejects it.
  /// The sign bit sits at bit 7 for legacy and bit 5 for IETF.
  fn assert_identity_cancellation<S: BlsScheme>(sign_bit: u8, accepted: bool) {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let signed = MSG_8BADFOOD;
    let sig = sk.sign(S::msg_ref(&signed));
    let pk = sk.public_key();

    let mut neg_sig_bytes = sig.to_bytes();
    neg_sig_bytes[0] ^= sign_bit;
    let neg_sig = BlsSignature::<S>::from_bytes(&neg_sig_bytes).unwrap();

    let mut neg_pk_bytes = pk.to_bytes();
    neg_pk_bytes[0] ^= sign_bit;
    let neg_pk = BlsPublicKey::<S>::from_bytes(&neg_pk_bytes).unwrap();

    let identity = BlsSignature::<S>::aggregate(&[&sig, &neg_sig]).unwrap();
    // The outcome must not depend on the message, signed or otherwise.
    for msg in [signed, MSG_DEADBEEF] {
      let res = identity.fast_verify_aggregates(S::msg_ref(&msg), &[&pk, &neg_pk]);
      assert_eq!(res.is_ok(), accepted, "identity aggregate over {msg:?}");
    }
  }

  /// An identity aggregate encodes to the canonical infinity form, `0xc0` over
  /// zeros. The decoder refuses that encoding as the identity is reachable
  /// by computation, not off the wire.
  #[rstest]
  fn chia_identity_encodes_canonically() {
    let sk = BlsSecretKey::<BlsScChia>::from_ikm(&RSEED[0]).unwrap();
    let sig = sk.sign(MSG_8BADFOOD);

    let mut neg_bytes = sig.to_bytes();
    neg_bytes[0] ^= 0x80;
    let neg_sig = BlsSignature::<BlsScChia>::from_bytes(&neg_bytes).unwrap();
    let identity = BlsSignature::<BlsScChia>::aggregate(&[&sig, &neg_sig]).unwrap();

    let mut expected = [0u8; 96];
    expected[0] = 0xc0;
    assert_eq!(identity.to_bytes(), expected);
    assert!(BlsSignature::<BlsScChia>::from_bytes(&expected).is_err());
  }

  #[rstest]
  #[case::chia(assert_identity_cancellation::<BlsScChia>, 0x80, true)]
  #[case::ietf(assert_identity_cancellation::<BlsScIetf>, 0x20, false)]
  fn identity_cancellation_follows_scheme(
    #[case] assertion: fn(u8, bool),
    #[case] sign_bit: u8,
    #[case] accepted: bool,
  ) {
    assertion(sign_bit, accepted);
  }
}
