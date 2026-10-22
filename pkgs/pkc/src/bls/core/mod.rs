//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Core's three signature verifications, on the calling thread alone.
//!
//! Each function is a `CBLSSignature` method taking the verify flag apart
//! from the scheme its objects were decoded under, as Core does. They follow
//! Core's code rather than blst's verification API:
//!
//! - the wrapper's validity checks, where Core makes them;
//! - `VerifyAggregateSignatureArguments`, with Core's assertion of equal,
//!   non-empty lengths giving [`BlsVerdict::Invalid`];
//! - the basic scheme's distinct-message check, which the legacy scheme lacks;
//! - `NativeVerify`'s product of pairings, which skips a pair with an infinity
//!   side.
//!
//! Only serial blst calls are made (Miller loops, the final exponentiation,
//! hashing to G2 and point arithmetic), so no thread is ever started or
//! woken.
//!
//! The module shares the language crate's name: inside it, `::core::` is
//! that crate; elsewhere, name its items rather than glob-importing
//! `dash_pkc::bls::*`.

use super::blst_ffi::{hash_to_g2, pairing_product_is_one};
use super::chia_h2c;
use super::group::{G1Affine, G2Affine, Point, G1, G2};
use super::scalar::Fr;
use super::scheme_ietf::DST_BASIC;
use super::scheme_ops::secure_weights;
use super::{BlsSchemeKind, BlsValue, BLS_PK_LEN, BLS_SIG_LEN, BLS_SK_LEN};
use crate::prelude::*;

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use zeroize::Zeroizing;

pub use super::elem::BlsElem;
#[doc(hidden)]
pub use super::elem::BlsShape;

/// A secret key as Core's wrapper holds it.
pub type BlsSkValue = BlsValue<Fr, BLS_SK_LEN>;
/// A public key as Core's wrapper holds it.
pub type BlsPkValue = BlsValue<G1, BLS_PK_LEN>;
/// A signature as Core's wrapper holds it.
pub type BlsSigValue = BlsValue<G2, BLS_SIG_LEN>;
/// A public key's element as Core's arithmetic holds it.
pub type BlsPkElem = BlsElem<G1, BLS_PK_LEN>;
/// A signature's element as Core's arithmetic holds it.
pub type BlsSigElem = BlsElem<G2, BLS_SIG_LEN>;

/// Core's answer to a verification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
#[must_use]
pub enum BlsVerdict {
  /// Core accepts the signature.
  Valid,
  /// Core rejects the signature.
  Invalid,
  /// Core computes the answer with relic's arithmetic on a point off the
  /// curve or outside the prime-order subgroup, which this crate does not
  /// reproduce yet.
  Unsupported,
}

impl BlsVerdict {
  /// Whether Core accepts the signature.
  pub const fn is_valid(self) -> bool {
    matches!(self, Self::Valid)
  }
}

impl From<bool> for BlsVerdict {
  fn from(ok: bool) -> Self {
    if ok {
      Self::Valid
    } else {
      Self::Invalid
    }
  }
}

/// `CBLSSignature::VerifyInsecure(pk, h, flag)`.
pub fn verify_insecure(sig: &BlsSigValue, pk: &BlsPkValue, h: &[u8; 32], flag: BlsSchemeKind) -> BlsVerdict {
  let (Some(sig), Some(pk)) = (sig.point(), pk.point()) else {
    return BlsVerdict::Invalid;
  };
  aggregate_verify(
    flag,
    sig.usable().copied(),
    &[pk.usable().copied()],
    ::core::slice::from_ref(h),
  )
}

/// `CBLSSignature::VerifyInsecureAggregated(pks, hs)` under the verify
/// flag.
pub fn verify_insecure_aggregated(
  sig: &BlsSigValue,
  pks: &[&BlsPkValue],
  hs: &[[u8; 32]],
  flag: BlsSchemeKind,
) -> BlsVerdict {
  let Some(sig) = sig.point() else {
    return BlsVerdict::Invalid;
  };
  if pks.is_empty() || pks.len() != hs.len() {
    return BlsVerdict::Invalid;
  }
  let Some(points) = pks
    .iter()
    .map(|pk| pk.point().map(|p| p.usable().copied()))
    .collect::<Option<Vec<_>>>()
  else {
    return BlsVerdict::Invalid;
  };
  aggregate_verify(flag, sig.usable().copied(), &points, hs)
}

/// `CBLSSignature::VerifySecureAggregated(pks, h)` under the verify flag.
///
/// Core checks no object's validity here: an invalid object takes part with
/// the element it holds, dashbls's default element, infinity, unless an
/// operation that failed in place kept an earlier one.
pub fn verify_secure_aggregated(
  sig: &BlsSigValue,
  pks: &[&BlsPkValue],
  h: &[u8; 32],
  flag: BlsSchemeKind,
) -> BlsVerdict {
  if pks.is_empty() {
    return BlsVerdict::Invalid;
  }
  let sig = sig.element(flag).1.usable().copied();

  // HashPubKeys weighs the keys in the order of their serializations under
  // the flag, and Core then decodes each serialization again. Under the
  // basic flag that decoding checks the point and throws for an exotic one,
  // which Core reports as false; under the legacy flag the point survives
  // and is left to relic's arithmetic.
  let mut keyed = Vec::with_capacity(pks.len());
  for pk in pks {
    let (bytes, point) = pk.element(flag);
    let Some(point) = point.usable() else {
      return match flag {
        BlsSchemeKind::Basic => BlsVerdict::Invalid,
        BlsSchemeKind::Legacy => BlsVerdict::Unsupported,
      };
    };
    keyed.push((bytes, point.to_projective()));
  }
  keyed.sort_unstable_by_key(|(bytes, _)| *bytes);
  let sorted: Vec<[u8; BLS_PK_LEN]> = keyed.iter().map(|(bytes, _)| *bytes).collect();

  let mut sum = G1::identity();
  for ((_, point), weight) in keyed.iter().zip(secure_weights(&sorted)) {
    sum += point.mul_scalar(&weight.b, 256);
  }
  aggregate_verify(flag, sig, &[Some(sum.to_affine())], ::core::slice::from_ref(h))
}

/// The scheme's `AggregateVerify` (its `Verify` for one key) over
/// non-empty lists of equal length. `None` stands for a point no pairing
/// accepts.
fn aggregate_verify(
  flag: BlsSchemeKind,
  sig: Option<G2Affine>,
  pks: &[Option<G1Affine>],
  hs: &[[u8; 32]],
) -> BlsVerdict {
  // dashbls `IsValid` rejects a point off the curve or outside the
  // subgroup, after the messages are found distinct; the legacy scheme
  // pairs whatever points it holds.
  if flag == BlsSchemeKind::Basic {
    let mut distinct = hs.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() != hs.len() {
      return BlsVerdict::Invalid;
    }
  }
  let (Some(sig), Some(pks)) = (sig, pks.iter().copied().collect::<Option<Vec<_>>>()) else {
    return match flag {
      BlsSchemeKind::Basic => BlsVerdict::Invalid,
      BlsSchemeKind::Legacy => BlsVerdict::Unsupported,
    };
  };

  let mut pairs = Vec::with_capacity(pks.len() + 1);
  pairs.push(((-G1::generator()).to_affine(), sig));
  for (pk, h) in pks.into_iter().zip(hs) {
    let hashed = match flag {
      BlsSchemeKind::Legacy => chia_h2c::hash_to_g2(h),
      BlsSchemeKind::Basic => hash_to_g2(h, DST_BASIC),
    };
    pairs.push((pk, hashed.to_affine()));
  }
  pairing_product_is_one(&pairs).into()
}

/// The BLS-IES symmetric key for `sk` and a peer key: the product
/// `DHKeyExchange` forms, serialized basic and cut to 32 bytes, as Core's IES
/// code takes it under either scheme (`bls.cpp:208-220`,
/// `bls_ies.cpp:43-48,79-84,96-101`).
///
/// `None` when either value is invalid. A basic key equal to `r` gives the
/// infinity, whose key is `c0 00 ... 00`. A subgroup peer key stays on blst,
/// constant-time; an Exotic one runs the engine, which is variable-time, as
/// relic is in Core.
#[must_use]
pub fn ies_key(sk: &BlsSkValue, pk: &BlsPkValue) -> Option<Zeroizing<[u8; 32]>> {
  if !sk.is_valid() || !pk.is_valid() {
    return None;
  }
  let (k, (), ()) = sk.parts();
  let shared = Zeroizing::new(BlsPkElem::from_impl(pk).mul_secret(k).secret_basic());
  let mut key = Zeroizing::new([0u8; 32]);
  key.copy_from_slice(&shared[..32]);
  Some(key)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::{BlsPublicKey, BlsScChia, BlsScIetf, BlsScheme, BlsSecretKey, BlsSignature};

  use hex_conservative::hex;
  use rstest::rstest;

  fn values<S: BlsScheme>(seed: u8, msg: &[u8; 32], kind: BlsSchemeKind) -> (BlsSigValue, BlsPkValue) {
    let sk = BlsSecretKey::<S>::from_ikm(&[seed; 32]).unwrap();
    let sig = sk.sign(S::msg_ref(msg)).to_bytes();
    let pk = sk.public_key().to_bytes();
    (
      BlsValue::from_canonical(&sig, kind).unwrap(),
      BlsValue::from_canonical(&pk, kind).unwrap(),
    )
  }

  fn assert_core_rules<S: BlsScheme>(kind: BlsSchemeKind) {
    let (m0, m1) = ([1u8; 32], [2u8; 32]);
    let (s0, p0) = values::<S>(1, &m0, kind);
    let (s1, p1) = values::<S>(2, &m1, kind);
    assert_eq!(verify_insecure(&s0, &p0, &m0, kind), BlsVerdict::Valid);
    assert_eq!(verify_insecure(&s0, &p0, &m1, kind), BlsVerdict::Invalid);
    assert_eq!(
      verify_insecure(&s0, &BlsValue::invalid(), &m0, kind),
      BlsVerdict::Invalid
    );

    let agg = BlsSignature::<S>::aggregate(&[
      &BlsSignature::from_bytes(&s0.to_bytes(kind)).unwrap(),
      &BlsSignature::from_bytes(&s1.to_bytes(kind)).unwrap(),
    ])
    .unwrap();
    let agg = BlsValue::from_canonical(&agg.to_bytes(), kind).unwrap();
    let verdict = verify_insecure_aggregated(&agg, &[&p0, &p1], &[m0, m1], kind);
    assert_eq!(verdict, BlsVerdict::Valid);
    assert_eq!(verify_insecure_aggregated(&agg, &[], &[], kind), BlsVerdict::Invalid);
    assert_eq!(
      verify_insecure_aggregated(&agg, &[&p0], &[m0, m1], kind),
      BlsVerdict::Invalid
    );
    assert_eq!(verify_secure_aggregated(&agg, &[], &m0, kind), BlsVerdict::Invalid);
  }

  #[rstest]
  #[case::legacy(assert_core_rules::<BlsScChia>, BlsSchemeKind::Legacy)]
  #[case::basic(assert_core_rules::<BlsScIetf>, BlsSchemeKind::Basic)]
  fn core_verify_rules(#[case] assertion: fn(BlsSchemeKind), #[case] kind: BlsSchemeKind) {
    assertion(kind);
  }

  /// A legacy key outside the G1 subgroup (bls_wrapper's `nonsub_000`):
  /// Core's basic checks refuse it, and its legacy pairing is relic's.
  #[rstest]
  #[case::legacy(BlsSchemeKind::Legacy, BlsVerdict::Unsupported)]
  #[case::basic(BlsSchemeKind::Basic, BlsVerdict::Invalid)]
  fn exotic_key(#[case] flag: BlsSchemeKind, #[case] want: BlsVerdict) {
    let bytes =
      hex!("0589c416bd798099fb08ed6d642e04865013fbd317a1ec5ec1041e2fb4b06c404e2059fb0145504474fac768c3c3e1af");
    let exotic = BlsPkValue::from_canonical(&bytes, BlsSchemeKind::Legacy).unwrap();
    assert_eq!(exotic.point().map(|p| p.usable()), Some(None));
    let msg = [5u8; 32];
    let (sig, pk) = values::<BlsScChia>(5, &msg, BlsSchemeKind::Legacy);
    assert_eq!(verify_insecure(&sig, &exotic, &msg, flag), want);
    assert_eq!(
      verify_insecure_aggregated(&sig, &[&pk, &exotic], &[msg, [6u8; 32]], flag),
      want
    );
    assert_eq!(verify_secure_aggregated(&sig, &[&pk, &exotic], &msg, flag), want);
  }

  /// The secure verify takes an invalid object as infinity: with every key
  /// invalid both pairs are skipped and the empty product is one.
  #[rstest]
  #[case::legacy(BlsSchemeKind::Legacy)]
  #[case::basic(BlsSchemeKind::Basic)]
  fn secure_verify_takes_invalid_objects_as_infinity(#[case] kind: BlsSchemeKind) {
    let msg = [3u8; 32];
    let (no_sig, no_pk) = (BlsSigValue::invalid(), BlsPkValue::invalid());
    assert_eq!(
      verify_secure_aggregated(&no_sig, &[&no_pk], &msg, kind),
      BlsVerdict::Valid
    );
    let (_, pk) = values::<BlsScIetf>(4, &msg, BlsSchemeKind::Basic);
    assert_eq!(
      verify_secure_aggregated(&no_sig, &[&pk], &msg, kind),
      BlsVerdict::Invalid
    );
  }

  fn assert_secure_kept_elements<S: BlsScheme>(kind: BlsSchemeKind) {
    let msg = [7u8; 32];
    let (sig, pk) = values::<S>(7, &msg, kind);
    let secure = BlsSignature::<S>::secure_aggregate(
      &[&BlsSignature::from_bytes(&sig.to_bytes(kind)).unwrap()],
      &[&BlsPublicKey::from_bytes(&pk.to_bytes(kind)).unwrap()],
    )
    .unwrap();
    let secure = BlsValue::from_canonical(&secure.to_bytes(), kind).unwrap();
    assert_eq!(verify_secure_aggregated(&secure, &[&pk], &msg, kind), BlsVerdict::Valid);
    let (mut no_sig, mut no_pk) = (secure.clone(), pk.clone());
    no_sig.invalidate();
    no_pk.invalidate();
    assert_eq!(verify_secure_aggregated(&no_sig, &[&pk], &msg, kind), BlsVerdict::Valid);
    assert_eq!(
      verify_secure_aggregated(&secure, &[&no_pk], &msg, kind),
      BlsVerdict::Valid
    );
  }

  /// An object invalidated in place keeps its element, and the secure
  /// verify uses it as Core uses `impl`, not infinity.
  #[rstest]
  #[case::legacy(assert_secure_kept_elements::<BlsScChia>, BlsSchemeKind::Legacy)]
  #[case::basic(assert_secure_kept_elements::<BlsScIetf>, BlsSchemeKind::Basic)]
  fn secure_verify_uses_kept_elements(#[case] assertion: fn(BlsSchemeKind), #[case] kind: BlsSchemeKind) {
    assertion(kind);
  }

  /// The key is the basic encoding of the DH point whatever scheme decoded
  /// the operands, and is the one the IES code uses.
  fn assert_ies_key<S: BlsScheme>(kind: BlsSchemeKind) {
    let sk = BlsSecretKey::<S>::from_ikm(&[3; 32]).unwrap();
    let peer = BlsSecretKey::<S>::from_ikm(&[4; 32]).unwrap().public_key();
    let shared = BlsSecretKey::<BlsScIetf>::from_bytes(&sk.to_bytes())
      .unwrap()
      .dh_exchange(&BlsPublicKey::<BlsScIetf>::from_bytes(&peer.to_scheme::<BlsScIetf>().unwrap().to_bytes()).unwrap())
      .unwrap();
    let sk_value = BlsSkValue::from_canonical(&sk.to_bytes(), kind).unwrap();
    let pk_value = BlsPkValue::from_canonical(&peer.to_bytes(), kind).unwrap();
    let key = ies_key(&sk_value, &pk_value).unwrap();
    assert_eq!(key[..], shared.as_bytes()[..32]);
    assert!(ies_key(&BlsSkValue::invalid(), &pk_value).is_none());
    assert!(ies_key(&sk_value, &BlsPkValue::invalid()).is_none());
  }

  #[rstest]
  #[case::legacy(assert_ies_key::<BlsScChia>, BlsSchemeKind::Legacy)]
  #[case::basic(assert_ies_key::<BlsScIetf>, BlsSchemeKind::Basic)]
  fn ies_key_is_the_basic_dh_encoding(#[case] assertion: fn(BlsSchemeKind), #[case] kind: BlsSchemeKind) {
    assertion(kind);
  }

  /// A basic key equal to `r` is valid and gives the infinity's key.
  #[test]
  fn ies_key_of_the_order_is_the_infinity() {
    let r = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    let sk = BlsSkValue::from_canonical(&r, BlsSchemeKind::Basic).unwrap();
    assert!(BlsSkValue::from_canonical(&r, BlsSchemeKind::Legacy).is_none());
    let (_, pk) = values::<BlsScIetf>(1, &[0; 32], BlsSchemeKind::Basic);
    let mut infinity = [0u8; 32];
    infinity[0] = 0xc0;
    assert_eq!(*ies_key(&sk, &pk).unwrap(), infinity);
  }
}
