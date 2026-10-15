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
use super::scheme_ietf::DST_BASIC;
use super::scheme_ops::secure_weights;
use super::{BlsSchemeKind, BlsValue, BLS_PK_LEN, BLS_SIG_LEN};
use crate::prelude::*;

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

/// A public key as Core's wrapper holds it.
pub type BlsPkValue = BlsValue<G1, BLS_PK_LEN>;
/// A signature as Core's wrapper holds it.
pub type BlsSigValue = BlsValue<G2, BLS_SIG_LEN>;

/// The basic serialization of dashbls's default element, infinity, which
/// both schemes write alike.
const INFINITY_PK: [u8; BLS_PK_LEN] = {
  let mut bytes = [0u8; BLS_PK_LEN];
  bytes[0] = 0xc0;
  bytes
};

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
/// Core checks no object's validity here. An invalid object holds dashbls's
/// default element, infinity, and takes part as that.
pub fn verify_secure_aggregated(
  sig: &BlsSigValue,
  pks: &[&BlsPkValue],
  h: &[u8; 32],
  flag: BlsSchemeKind,
) -> BlsVerdict {
  if pks.is_empty() {
    return BlsVerdict::Invalid;
  }
  let sig = sig.point().map_or(Some(G2Affine::default()), |p| p.usable().copied());

  // HashPubKeys weighs the keys in the order of their serializations under
  // the flag, and Core then decodes each serialization again. Under the
  // basic flag that decoding checks the point and throws for an exotic one,
  // which Core reports as false; under the legacy flag the point survives
  // and is left to relic's arithmetic.
  let mut keyed = Vec::with_capacity(pks.len());
  for pk in pks {
    let entry = match pk.point().map(|p| p.usable()) {
      None => (INFINITY_PK, G1::identity()),
      Some(Some(point)) => (pk.to_bytes(flag), point.to_projective()),
      Some(None) => {
        return match flag {
          BlsSchemeKind::Basic => BlsVerdict::Invalid,
          BlsSchemeKind::Legacy => BlsVerdict::Unsupported,
        };
      }
    };
    keyed.push(entry);
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::{BlsScChia, BlsScIetf, BlsScheme, BlsSecretKey, BlsSignature};

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
}
