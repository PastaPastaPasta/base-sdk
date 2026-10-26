//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Core's aggregates and `SubInsecure` on wrapper values.
//!
//! Core asserts that both operands of a pair form are valid; here an invalid
//! operand gives the invalid value, so a peer's object cannot abort a node.

use super::{secure_weights, sk_scalar, sk_value, BlsPkElem, BlsPkValue, BlsSigElem, BlsSigValue, BlsSkValue, Fr};
use crate::bls::{BlsSchemeKind, BLS_PK_LEN};
use crate::prelude::*;

use ff::Field;
use zeroize::Zeroize;

/// `CBLSSecretKey::AggregateInsecure(Span)` (`bls.cpp:43-60`): the invalid
/// key for an empty span, otherwise the sum modulo `r` of every key's
/// element whatever its validity, `PrivateKey::Aggregate`
/// (`privatekey.cpp:237-255`). The sum is valid even when zero. Constant
/// time in the keys.
pub fn aggregate_secret_keys_insecure(sks: &[&BlsSkValue]) -> BlsSkValue {
  if sks.is_empty() {
    return BlsSkValue::invalid();
  }
  let mut sum = Fr::ZERO;
  for sk in sks {
    let mut term = sk_scalar(sk);
    sum += term;
    term.zeroize();
  }
  sk_value(&mut sum)
}

/// `CBLSSecretKey::AggregateInsecure(o)` (`bls.cpp:36-41`): the sum of
/// `a` and `b`, or the invalid key when either is invalid.
pub fn aggregate_secret_keys_insecure_pair(a: &BlsSkValue, b: &BlsSkValue) -> BlsSkValue {
  if !a.is_valid() || !b.is_valid() {
    return BlsSkValue::invalid();
  }
  aggregate_secret_keys_insecure(&[a, b])
}

/// `CBLSPublicKey::AggregateInsecure(Span)` (`bls.cpp:155-177`): the
/// invalid key for an empty span, otherwise the valid sum from the default
/// element in order of every key's element whatever its validity
/// (`schemes.cpp:185-192`). The sum is valid even when infinite.
pub fn aggregate_public_keys_insecure(pks: &[&BlsPkValue]) -> BlsPkValue {
  BlsPkElem::aggregate_insecure(pks.iter().copied()).map_or_else(BlsPkValue::invalid, Into::into)
}

/// `CBLSPublicKey::AggregateInsecure(o)` (`bls.cpp:144-153`): the span sum
/// of `[a, b]`, or the invalid key when either is invalid.
pub fn aggregate_public_keys_insecure_pair(a: &BlsPkValue, b: &BlsPkValue) -> BlsPkValue {
  if !a.is_valid() || !b.is_valid() {
    return BlsPkValue::invalid();
  }
  aggregate_public_keys_insecure(&[a, b])
}

/// `CBLSSignature::AggregateInsecure(Span)` (`bls.cpp:233-255`): the
/// invalid signature for an empty span, otherwise the valid sum from the
/// default element in order of every signature's element whatever its
/// validity (`schemes.cpp:176-183`). The sum is valid even when infinite.
pub fn aggregate_signatures_insecure(sigs: &[&BlsSigValue]) -> BlsSigValue {
  BlsSigElem::aggregate_insecure(sigs.iter().copied()).map_or_else(BlsSigValue::invalid, Into::into)
}

/// `CBLSSignature::AggregateInsecure(o)` (`bls.cpp:222-231`): the span sum
/// of `[a, b]`, or the invalid signature when either is invalid.
pub fn aggregate_signatures_insecure_pair(a: &BlsSigValue, b: &BlsSigValue) -> BlsSigValue {
  if !a.is_valid() || !b.is_valid() {
    return BlsSigValue::invalid();
  }
  aggregate_signatures_insecure(&[a, b])
}

/// `CBLSSignature::SubInsecure(o)` (`bls.cpp:289-294`): `a + (-b)` with `a`
/// as the first operand, valid even when infinite, or the invalid signature
/// when either is invalid.
pub fn sub_signatures_insecure(a: &BlsSigValue, b: &BlsSigValue) -> BlsSigValue {
  if !a.is_valid() || !b.is_valid() {
    return BlsSigValue::invalid();
  }
  BlsSigElem::from_impl(a).add(&BlsSigElem::from_impl(b).neg()).into()
}

/// `CBLSSignature::AggregateSecure(sigs, pks, hash)` under the flag
/// (`bls.cpp:257-287`), `CoreMPL::AggregateSecure` (`schemes.cpp:194-223`).
///
/// The invalid signature for empty or unequal spans. No validity is tested:
/// each object takes part with its element. The pairs are sorted by the
/// key's serialization under `flag`, stably, where Core's `std::sort` is
/// stable only up to 16 elements; each signature is multiplied by its
/// `HashPubKeys` weight modulo `r`, and the products are summed from the
/// default element. Core's message argument is unused, so it is not taken.
pub fn aggregate_signatures_secure(sigs: &[&BlsSigValue], pks: &[&BlsPkValue], flag: BlsSchemeKind) -> BlsSigValue {
  if sigs.is_empty() || sigs.len() != pks.len() {
    return BlsSigValue::invalid();
  }
  let mut keyed: Vec<([u8; BLS_PK_LEN], &BlsSigValue)> = pks
    .iter()
    .map(|pk| BlsPkElem::from_impl(pk).to_bytes(flag))
    .zip(sigs.iter().copied())
    .collect();
  keyed.sort_by_key(|(bytes, _)| *bytes);
  let sorted: Vec<[u8; BLS_PK_LEN]> = keyed.iter().map(|(bytes, _)| *bytes).collect();
  keyed
    .iter()
    .zip(secure_weights(&sorted))
    .fold(BlsSigElem::default(), |sum, ((_, sig), t)| {
      sum.add(&BlsSigElem::from_impl(sig).mul(&Fr::from(&t).to_bendian()))
    })
    .into()
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::super::tests::{values, values_of};
  use super::*;
  use crate::bls::tests::{negate_scalar, G1_OFF_SUBGROUP_CHIA, G2_OFF_SUBGROUP_CHIA, GROUP_ORDER};
  use crate::bls::{BlsPublicKey, BlsScChia, BlsScIetf, BlsScheme, BlsSecretKey, BlsSignature, BlsValue};

  use rstest::rstest;

  const LEGACY: BlsSchemeKind = BlsSchemeKind::Legacy;
  const BASIC: BlsSchemeKind = BlsSchemeKind::Basic;

  fn sk_value<S: BlsScheme>(sk: &BlsSecretKey<S>, kind: BlsSchemeKind) -> BlsSkValue {
    BlsSkValue::from_canonical(&sk.to_bytes(), kind).unwrap()
  }

  fn keys<S: BlsScheme>(n: u8) -> Vec<BlsSecretKey<S>> {
    (1..=n)
      .map(|i| BlsSecretKey::<S>::from_ikm(&[i; 32]).unwrap())
      .collect()
  }

  fn assert_agrees_with_typed<S: BlsScheme>(kind: BlsSchemeKind) {
    let msg = [9u8; 32];
    let sks = keys::<S>(4);
    let sk_values: Vec<BlsSkValue> = sks.iter().map(|sk| sk_value(sk, kind)).collect();
    let pks: Vec<BlsPublicKey<S>> = sks.iter().map(BlsSecretKey::public_key).collect();
    let sigs: Vec<BlsSignature<S>> = sks.iter().map(|sk| sk.sign(S::msg_ref(&msg))).collect();
    let pk_values: Vec<BlsPkValue> = pks
      .iter()
      .map(|pk| BlsPkValue::from_canonical(&pk.to_bytes(), kind).unwrap())
      .collect();
    let sig_values: Vec<BlsSigValue> = sigs
      .iter()
      .map(|sig| BlsSigValue::from_canonical(&sig.to_bytes(), kind).unwrap())
      .collect();
    let sk_refs: Vec<&BlsSkValue> = sk_values.iter().collect();
    let pk_refs: Vec<&BlsPkValue> = pk_values.iter().collect();
    let sig_refs: Vec<&BlsSigValue> = sig_values.iter().collect();

    let typed = BlsSecretKey::aggregate(&sks.iter().collect::<Vec<_>>()).unwrap();
    assert_eq!(
      aggregate_secret_keys_insecure(&sk_refs).to_bytes(kind),
      *typed.to_bytes()
    );
    let typed = BlsPublicKey::aggregate(&pks.iter().collect::<Vec<_>>()).unwrap();
    assert_eq!(
      aggregate_public_keys_insecure(&pk_refs).to_bytes(kind),
      typed.to_bytes()
    );
    let typed = BlsSignature::aggregate(&sigs.iter().collect::<Vec<_>>()).unwrap();
    assert_eq!(
      aggregate_signatures_insecure(&sig_refs).to_bytes(kind),
      typed.to_bytes()
    );

    let pair = BlsSecretKey::aggregate(&[&sks[0], &sks[1]]).unwrap();
    let got = aggregate_secret_keys_insecure_pair(&sk_values[0], &sk_values[1]);
    assert_eq!(got.to_bytes(kind), *pair.to_bytes());
    let pair = BlsPublicKey::aggregate(&[&pks[0], &pks[1]]).unwrap();
    let got = aggregate_public_keys_insecure_pair(&pk_values[0], &pk_values[1]);
    assert_eq!(got.to_bytes(kind), pair.to_bytes());
    let pair = BlsSignature::aggregate(&[&sigs[0], &sigs[1]]).unwrap();
    let got = aggregate_signatures_insecure_pair(&sig_values[0], &sig_values[1]);
    assert_eq!(got.to_bytes(kind), pair.to_bytes());

    let typed = sigs[0].sub_insecure(&sigs[1]).unwrap();
    let got = sub_signatures_insecure(&sig_values[0], &sig_values[1]);
    assert_eq!(got.to_bytes(kind), typed.to_bytes());

    let pk_typed: Vec<&BlsPublicKey<S>> = pks.iter().collect();
    let sig_typed: Vec<&BlsSignature<S>> = sigs.iter().collect();
    for n in 1..=sigs.len() {
      let typed = BlsSignature::secure_aggregate(&sig_typed[..n], &pk_typed[..n]).unwrap();
      let got = aggregate_signatures_secure(&sig_refs[..n], &pk_refs[..n], kind);
      assert!(got.is_valid());
      assert_eq!(got.to_bytes(kind), typed.to_bytes(), "{n} signers");
      let verdict = super::super::verify_secure_aggregated(&got, &pk_refs[..n], &msg, kind);
      assert!(verdict.is_valid(), "{n} signers");
    }
  }

  #[rstest]
  #[case::legacy(assert_agrees_with_typed::<BlsScChia>, LEGACY)]
  #[case::basic(assert_agrees_with_typed::<BlsScIetf>, BASIC)]
  fn aggregates_agree_with_the_typed_api(#[case] assertion: fn(BlsSchemeKind), #[case] kind: BlsSchemeKind) {
    assertion(kind);
  }

  /// Empty spans give the invalid value; an invalid pair operand too.
  #[rstest]
  #[case::legacy(LEGACY)]
  #[case::basic(BASIC)]
  fn empty_spans_and_invalid_pairs_are_invalid(#[case] kind: BlsSchemeKind) {
    let (sig, pk) = values_of(1, &[1; 32], kind);
    let sk = BlsSkValue::from_canonical(&[1; 32], kind).unwrap();
    assert!(!aggregate_secret_keys_insecure(&[]).is_valid());
    assert!(!aggregate_public_keys_insecure(&[]).is_valid());
    assert!(!aggregate_signatures_insecure(&[]).is_valid());
    assert!(!aggregate_signatures_secure(&[], &[], kind).is_valid());
    assert!(!aggregate_signatures_secure(&[&sig], &[&pk, &pk], kind).is_valid());

    let (no_sk, no_pk, no_sig) = (BlsSkValue::invalid(), BlsPkValue::invalid(), BlsSigValue::invalid());
    assert!(!aggregate_secret_keys_insecure_pair(&sk, &no_sk).is_valid());
    assert!(!aggregate_secret_keys_insecure_pair(&no_sk, &sk).is_valid());
    assert!(!aggregate_public_keys_insecure_pair(&pk, &no_pk).is_valid());
    assert!(!aggregate_public_keys_insecure_pair(&no_pk, &pk).is_valid());
    assert!(!aggregate_signatures_insecure_pair(&sig, &no_sig).is_valid());
    assert!(!aggregate_signatures_insecure_pair(&no_sig, &sig).is_valid());
    assert!(!sub_signatures_insecure(&sig, &no_sig).is_valid());
    assert!(!sub_signatures_insecure(&no_sig, &sig).is_valid());
  }

  /// A key and its negation sum to a valid zero key, a signature less itself
  /// is a valid infinity, and so is the sum of a key and its negation.
  #[rstest]
  #[case::legacy(LEGACY)]
  #[case::basic(BASIC)]
  fn zero_and_infinite_results_are_valid(#[case] kind: BlsSchemeKind) {
    let k = [0x11u8; 32];
    let (a, b) = (
      BlsSkValue::from_canonical(&k, kind).unwrap(),
      BlsSkValue::from_canonical(&negate_scalar(&k), kind).unwrap(),
    );
    let zero = aggregate_secret_keys_insecure(&[&a, &b]);
    assert!(zero.is_valid());
    assert_eq!(zero.to_bytes(kind), [0u8; 32]);
    assert_eq!(aggregate_secret_keys_insecure_pair(&a, &b), zero);

    let (sig, pk) = values_of(2, &[2; 32], kind);
    let infinity = sub_signatures_insecure(&sig, &sig);
    assert!(infinity.is_valid());
    assert_eq!(infinity.to_bytes(kind), BlsSigValue::invalid().element(kind).0);
    let neg: BlsPkValue = BlsPkElem::from_impl(&pk).neg().into();
    let sum = aggregate_public_keys_insecure_pair(&pk, &neg);
    assert!(sum.is_valid());
    assert_eq!(sum.to_bytes(kind), BlsPkValue::invalid().element(kind).0);
  }

  /// The ungated sums take an invalid value's element: the default element
  /// adds nothing, and an element kept by a failed in-place operation adds
  /// itself.
  #[rstest]
  #[case::legacy(LEGACY)]
  #[case::basic(BASIC)]
  fn invalid_values_contribute_their_elements(#[case] kind: BlsSchemeKind) {
    let (sig, pk) = values_of(3, &[3; 32], kind);
    let (mut kept_sig, mut kept_pk) = (sig.clone(), pk.clone());
    kept_sig.invalidate();
    kept_pk.invalidate();
    let twice_sig = aggregate_signatures_insecure(&[&sig, &sig]);
    let twice_pk = aggregate_public_keys_insecure(&[&pk, &pk]);

    assert_eq!(aggregate_signatures_insecure(&[&sig, &BlsSigValue::invalid()]), sig);
    assert_eq!(aggregate_public_keys_insecure(&[&BlsPkValue::invalid(), &pk]), pk);
    assert_eq!(aggregate_signatures_insecure(&[&sig, &kept_sig]), twice_sig);
    assert_eq!(aggregate_public_keys_insecure(&[&kept_pk, &pk]), twice_pk);
    let only = aggregate_signatures_insecure(&[&BlsSigValue::invalid()]);
    assert!(only.is_valid());
    assert_eq!(only.to_bytes(kind), BlsSigValue::invalid().element(kind).0);

    let sk = BlsSkValue::from_canonical(&[5; 32], kind).unwrap();
    let mut kept_sk = sk.clone();
    kept_sk.invalidate();
    let twice_sk = aggregate_secret_keys_insecure(&[&sk, &sk]);
    assert_eq!(aggregate_secret_keys_insecure(&[&sk, &kept_sk]), twice_sk);
    assert_eq!(aggregate_secret_keys_insecure(&[&sk, &BlsSkValue::invalid()]), sk);
  }

  /// A basic key equal to `r` reads as zero, as `bn_mod_basic` makes it.
  #[test]
  fn the_order_reads_as_zero() {
    let r = BlsSkValue::from_canonical(&GROUP_ORDER, BASIC).unwrap();
    let mut k = [0u8; 32];
    k[31] = 1;
    let one = BlsSkValue::from_canonical(&k, BASIC).unwrap();
    assert_eq!(aggregate_secret_keys_insecure(&[&r, &one]), one);
    assert_eq!(aggregate_secret_keys_insecure(&[&r]).to_bytes(BASIC), [0u8; 32]);
  }

  /// The secure aggregate tests no validity: an invalid key sorts as the
  /// infinity's serialization and an invalid signature adds nothing, so the
  /// aggregate over the remaining pair is the weighted signature alone.
  #[rstest]
  #[case::legacy(LEGACY)]
  #[case::basic(BASIC)]
  fn secure_aggregate_runs_invalid_operands(#[case] kind: BlsSchemeKind) {
    let msg = [4u8; 32];
    let (sig, pk) = values_of(4, &msg, kind);
    let (no_sig, no_pk) = (BlsSigValue::invalid(), BlsPkValue::invalid());
    let got = aggregate_signatures_secure(&[&sig, &no_sig], &[&pk, &no_pk], kind);
    assert!(got.is_valid());
    let mut sorted = [BlsPkElem::from_impl(&pk).to_bytes(kind), no_pk.element(kind).0];
    sorted.sort_unstable();
    let weights = secure_weights(&sorted);
    let at = sorted.iter().position(|b| *b == pk.to_bytes(kind)).unwrap();
    let want: BlsSigValue = BlsSigElem::from_impl(&sig)
      .mul(&Fr::from(&weights[at]).to_bendian())
      .into();
    assert_eq!(got, want);
    assert!(super::super::verify_secure_aggregated(&got, &[&pk, &no_pk], &msg, kind).is_valid());
  }

  /// Equal keys keep their input order, so the weights go to the signatures
  /// in that order.
  #[test]
  fn secure_aggregate_sorts_stably() {
    let (s0, pk) = values::<BlsScIetf>(5, &[5; 32], BASIC);
    let (s1, _) = values::<BlsScIetf>(6, &[6; 32], BASIC);
    let got = aggregate_signatures_secure(&[&s0, &s1], &[&pk, &pk], BASIC);
    let bytes = pk.to_bytes(BASIC);
    let weights = secure_weights(&[bytes, bytes]);
    let want = BlsSigElem::from_impl(&s0)
      .mul(&Fr::from(&weights[0]).to_bendian())
      .add(&BlsSigElem::from_impl(&s1).mul(&Fr::from(&weights[1]).to_bendian()));
    assert_eq!(got, want.into());
  }

  /// Legacy keys and signatures outside the subgroup go through the engine.
  #[test]
  fn exotic_operands_run_the_engine() {
    let pk = BlsPkValue::from_canonical(&G1_OFF_SUBGROUP_CHIA, LEGACY).unwrap();
    let sig = BlsSigValue::from_canonical(&G2_OFF_SUBGROUP_CHIA, LEGACY).unwrap();
    let (s1, p1) = values::<BlsScChia>(7, &[7; 32], LEGACY);
    let agg = aggregate_public_keys_insecure(&[&pk, &p1]);
    let want = BlsPkElem::default()
      .add(&BlsPkElem::from_impl(&pk))
      .add(&BlsPkElem::from_impl(&p1));
    assert!(agg.is_valid());
    assert!(BlsPkElem::from_impl(&agg).__is_relic());
    assert!(BlsPkElem::from_impl(&agg).core_eq(&want));
    let diff = sub_signatures_insecure(&sig, &s1);
    assert!(BlsSigElem::from_impl(&diff).__is_relic());
    let secure = aggregate_signatures_secure(&[&sig, &s1], &[&pk, &p1], LEGACY);
    assert!(secure.is_valid());
    assert!(BlsSigElem::from_impl(&secure).__is_relic());
    assert_eq!(
      BlsValue::from(BlsSigElem::from_impl(&secure)).to_bytes(LEGACY),
      secure.to_bytes(LEGACY)
    );
  }
}
