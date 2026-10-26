//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Core's BLS wrapper operations on its objects as Core holds them, on the
//! calling thread alone: the three signature verifications, the aggregates,
//! the threshold operations and `DHKeyExchange`.
//!
//! Unlike the typed API, these give Core's results where it refuses them:
//! valid zero secret keys and valid infinities from aggregates, shares,
//! recovery, `SubInsecure` and DH, and an id that reduces to zero.
//!
//! Each verification is a `CBLSSignature` method taking the verify flag apart
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

mod aggregate;
mod batch;
mod ies;
mod threshold;
mod worker;

use super::blst_ffi::{hash_to_g2, pairing_product_is_one};
use super::chia_h2c;
use super::group::{G1Affine, G2Affine, Point, G1, G2};
use super::scalar::Fr;
use super::scheme_ietf::DST_BASIC;
use super::scheme_ops::secure_weights;
#[cfg(feature = "codec")]
use super::wrap_codec::BlsWire;
use super::{BlsSchemeKind, BlsValue, BLS_PK_LEN, BLS_SIG_LEN, BLS_SK_LEN};
use crate::prelude::*;

#[cfg(feature = "codec")]
use bitcoin_hashes::sha256d::Hash as Sha256d;
#[cfg(feature = "codec")]
use dash_num::Hash256;
#[cfg(feature = "codec")]
use dash_types::codec::BaseCodec;
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
#[cfg(feature = "codec")]
use dash_types::CompactSize;
#[cfg(feature = "codec")]
use dash_types::Numeric;
use hex_conservative::hex;
use rand_core::CryptoRng;
use zeroize::{Zeroize, Zeroizing};

pub use super::elem::BlsElem;
#[doc(hidden)]
pub use super::elem::BlsShape;

pub use aggregate::{
  aggregate_public_keys_insecure, aggregate_public_keys_insecure_pair, aggregate_secret_keys_insecure,
  aggregate_secret_keys_insecure_pair, aggregate_signatures_insecure, aggregate_signatures_insecure_pair,
  aggregate_signatures_secure, sub_signatures_insecure,
};
pub use batch::BlsBatchVerifier;
pub use ies::{BlsIesBlobValue, BlsIesMultiBlobs};
pub use threshold::{public_key_share, recover_signature, secret_key_share};
pub use worker::{
  aggregate_public_keys, aggregate_secret_keys, aggregate_signatures, build_pub_key_share,
  build_quorum_verification_vector, generate_contributions, verify_contribution_share, verify_contribution_shares,
  verify_vector, verify_verification_vectors, CONTRIBUTION_VERIFY_BATCH_SIZE,
};

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

/// `CBLSPublicKey::DHKeyExchange(sk, pk)` (`bls.cpp:208-220`) into `out`:
/// `false` with `out` invalid and its element kept when either value is
/// invalid; otherwise `out` is the product with `sk`'s stored bytes, valid
/// even when infinite (a basic key equal to `r`). It does not depend on the
/// flag. A subgroup key stays on blst, constant-time; an Exotic one runs the
/// engine, which is variable-time, as relic is in Core.
///
/// `out` is a shared secret, held as Core holds it, in a public key: its
/// `Debug` shows it, it is not wiped on drop and its comparison is not
/// constant-time. Derive keys with [`ies_key`], which returns them in
/// `Zeroizing`.
pub fn dh_key_exchange(out: &mut BlsPkValue, sk: &BlsSkValue, pk: &BlsPkValue) -> bool {
  out.invalidate();
  if !sk.is_valid() || !pk.is_valid() {
    return false;
  }
  let (k, (), ()) = sk.parts();
  *out = BlsPkElem::from_impl(pk).mul_secret_value(k);
  true
}

/// `SerializeHash` of a vector of objects, the DKG's `quorumVvecHash`
/// (`llmq/dkgsession.cpp:596-600`): SHA-256d of the count as a CompactSize
/// and each object's `ToBytes` under `flag`, zeros for an invalid one.
#[cfg(feature = "codec")]
pub fn serialize_hash_vector<'a, K, const N: usize, I>(values: I, flag: BlsSchemeKind) -> Hash256
where
  K: BlsWire<N>,
  I: IntoIterator<Item = &'a BlsValue<K, N>>,
  I::IntoIter: ExactSizeIterator,
{
  let values = values.into_iter();
  let mut buf = Zeroizing::new(Vec::with_capacity(9 + values.len() * N));
  CompactSize::from(values.len()).encode(&mut *buf);
  for value in values {
    let mut bytes = value.to_bytes(flag);
    bytes.encode(&mut *buf);
    bytes.zeroize();
  }
  Hash256::from_lendian(Sha256d::hash(&buf).to_byte_array())
}

/// A secret key's element, its stored bytes read modulo `r` (BS11b D4).
fn sk_scalar(sk: &BlsSkValue) -> Fr {
  let (k, (), ()) = sk.parts();
  Fr::from_bendian_mod(k)
}

/// A valid secret key holding `k`, which is wiped.
fn sk_value(k: &mut Fr) -> BlsSkValue {
  let value = BlsValue::with_element(*k.to_bendian(), (), ());
  k.zeroize();
  value
}

/// The G1 generator, compressed in the basic layout.
const G1_GENERATOR: [u8; BLS_PK_LEN] =
  hex!("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");

/// `CBLSSecretKey::GetPublicKey`: the generator times the key, valid even
/// when infinite (a basic key equal to `r`), or the invalid key.
pub fn public_key(sk: &BlsSkValue) -> BlsPkValue {
  match BlsPkValue::from_canonical(&G1_GENERATOR, BlsSchemeKind::Basic) {
    Some(g) if sk.is_valid() => {
      let (k, (), ()) = sk.parts();
      BlsPkElem::from_impl(&g).mul_secret_value(k)
    }
    _ => BlsPkValue::invalid(),
  }
}

/// `CBLSSecretKey::MakeNewKey`: 32 random bytes until they decode as a
/// basic secret key other than zero, so at most `r`.
pub fn make_new_key(rng: &mut impl CryptoRng) -> BlsSkValue {
  loop {
    let mut bytes = Zeroizing::new([0u8; BLS_SK_LEN]);
    rng.fill_bytes(bytes.as_mut());
    if let Some(key) = BlsSkValue::from_canonical(&bytes, BlsSchemeKind::Basic) {
      return key;
    }
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::{BlsPublicKey, BlsScChia, BlsScIetf, BlsScheme, BlsSecretKey, BlsSignature};

  use hex_conservative::hex;
  use rstest::rstest;

  pub(super) fn values<S: BlsScheme>(seed: u8, msg: &[u8; 32], kind: BlsSchemeKind) -> (BlsSigValue, BlsPkValue) {
    let sk = BlsSecretKey::<S>::from_ikm(&[seed; 32]).unwrap();
    let sig = sk.sign(S::msg_ref(msg)).to_bytes();
    let pk = sk.public_key().to_bytes();
    (
      BlsValue::from_canonical(&sig, kind).unwrap(),
      BlsValue::from_canonical(&pk, kind).unwrap(),
    )
  }

  /// [`values`] in the scheme `kind` decodes.
  pub(super) fn values_of(seed: u8, msg: &[u8; 32], kind: BlsSchemeKind) -> (BlsSigValue, BlsPkValue) {
    match kind {
      BlsSchemeKind::Legacy => values::<BlsScChia>(seed, msg, kind),
      BlsSchemeKind::Basic => values::<BlsScIetf>(seed, msg, kind),
    }
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

  /// The product is the typed exchange's in the scheme's own encoding, and
  /// its basic encoding begins with the IES key.
  fn assert_dh<S: BlsScheme>(kind: BlsSchemeKind) {
    let sk = BlsSecretKey::<S>::from_ikm(&[5; 32]).unwrap();
    let peer = BlsSecretKey::<S>::from_ikm(&[6; 32]).unwrap().public_key();
    let typed = sk.dh_exchange(&peer).unwrap();
    let sk_value = BlsSkValue::from_canonical(&sk.to_bytes(), kind).unwrap();
    let pk_value = BlsPkValue::from_canonical(&peer.to_bytes(), kind).unwrap();
    let mut out = BlsPkValue::invalid();
    assert!(dh_key_exchange(&mut out, &sk_value, &pk_value));
    assert_eq!(out.to_bytes(kind), *typed.as_bytes());
    let key = ies_key(&sk_value, &pk_value).unwrap();
    assert_eq!(key[..], out.to_bytes(BlsSchemeKind::Basic)[..32]);
  }

  #[rstest]
  #[case::legacy(assert_dh::<BlsScChia>, BlsSchemeKind::Legacy)]
  #[case::basic(assert_dh::<BlsScIetf>, BlsSchemeKind::Basic)]
  fn dh_agrees_with_the_typed_api(#[case] assertion: fn(BlsSchemeKind), #[case] kind: BlsSchemeKind) {
    assertion(kind);
  }

  /// An invalid side fails and the receiver keeps its element; on success
  /// the receiver is replaced.
  #[rstest]
  #[case::legacy(BlsSchemeKind::Legacy)]
  #[case::basic(BlsSchemeKind::Basic)]
  fn dh_failure_keeps_the_receivers_element(#[case] kind: BlsSchemeKind) {
    let (_, pk) = values_of(7, &[7; 32], kind);
    let sk = BlsSkValue::from_canonical(&[7; 32], kind).unwrap();
    for (sk, pk) in [(&BlsSkValue::invalid(), &pk), (&sk, &BlsPkValue::invalid())] {
      let mut out = pk.clone();
      assert!(!dh_key_exchange(&mut out, sk, pk));
      assert!(!out.is_valid());
      assert_eq!(out.element(kind), pk.element(kind));
    }
    let mut out = pk.clone();
    assert!(dh_key_exchange(&mut out, &sk, &pk));
    let want: BlsPkValue = BlsPkElem::from_impl(&pk).mul(&[7; 32]).into();
    assert_eq!(out, want);
  }

  /// A basic key equal to `r` gives a valid infinity, and an Exotic legacy
  /// key goes through the engine as the public product does.
  #[test]
  fn dh_infinity_and_exotic_keys() {
    let r = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    let sk = BlsSkValue::from_canonical(&r, BlsSchemeKind::Basic).unwrap();
    let (_, pk) = values::<BlsScIetf>(1, &[0; 32], BlsSchemeKind::Basic);
    let mut out = BlsPkValue::invalid();
    assert!(dh_key_exchange(&mut out, &sk, &pk));
    assert!(out.is_valid());
    assert_eq!(
      out.to_bytes(BlsSchemeKind::Basic),
      BlsPkValue::invalid().element(BlsSchemeKind::Basic).0
    );

    let bytes =
      hex!("0589c416bd798099fb08ed6d642e04865013fbd317a1ec5ec1041e2fb4b06c404e2059fb0145504474fac768c3c3e1af");
    let exotic = BlsPkValue::from_canonical(&bytes, BlsSchemeKind::Legacy).unwrap();
    let sk = BlsSkValue::from_canonical(&[3; 32], BlsSchemeKind::Legacy).unwrap();
    assert!(dh_key_exchange(&mut out, &sk, &exotic));
    let want = BlsPkElem::from_impl(&exotic).mul(&[3; 32]);
    assert!(BlsPkElem::from_impl(&out).__is_relic());
    assert!(BlsPkElem::from_impl(&out).core_eq(&want));
    assert_eq!(
      out.to_bytes(BlsSchemeKind::Legacy),
      want.to_bytes(BlsSchemeKind::Legacy)
    );
  }

  /// `GetHash` hashes the serialization under the scheme asked, zeros for
  /// an invalid object, as the lazy wrapper does for a decoded one.
  #[rstest]
  #[case::legacy(BlsSchemeKind::Legacy)]
  #[case::basic(BlsSchemeKind::Basic)]
  fn serialize_hash_is_the_serializations(#[case] kind: BlsSchemeKind) {
    use crate::bls::{BlsLazy, BlsSchemeSource};

    use bitcoin_hashes::sha256d::Hash as Sha256d;
    use dash_num::Hash256;
    use dash_types::Numeric;

    let (sig, pk) = values_of(8, &[8; 32], kind);
    let lazy = BlsLazy::<G1, BLS_PK_LEN>::from_bytes(&pk.to_bytes(kind), BlsSchemeSource::Version(kind));
    assert_eq!(pk.serialize_hash(kind), lazy.serialize_hash());
    let sha = |bytes: &[u8]| Hash256::from_lendian(Sha256d::hash(bytes).to_byte_array());
    for other in [BlsSchemeKind::Legacy, BlsSchemeKind::Basic] {
      assert_eq!(sig.serialize_hash(other), sha(&sig.to_bytes(other)));
    }
    let mut kept = pk.clone();
    kept.invalidate();
    assert_eq!(kept.serialize_hash(kind), sha(&[0; BLS_PK_LEN]));
    let sk = BlsSkValue::from_canonical(&[9; 32], kind).unwrap();
    assert_eq!(sk.serialize_hash(kind), sha(&[9; 32]));
  }

  /// The vector hash covers the count as a CompactSize and each
  /// serialization, zeros for an invalid entry.
  #[cfg(feature = "codec")]
  #[rstest]
  #[case::legacy(BlsSchemeKind::Legacy)]
  #[case::basic(BlsSchemeKind::Basic)]
  fn serialize_hash_vector_prefixes_the_count(#[case] kind: BlsSchemeKind) {
    use bitcoin_hashes::sha256d::Hash as Sha256d;
    use dash_num::Hash256;
    use dash_types::Numeric;

    let sha = |bytes: &[u8]| Hash256::from_lendian(Sha256d::hash(bytes).to_byte_array());
    let empty: [BlsPkValue; 0] = [];
    assert_eq!(serialize_hash_vector(&empty, kind), sha(&[0]));
    let vvec: Vec<BlsPkValue> = (1..=3)
      .map(|i| values_of(i, &[i; 32], kind).1)
      .chain([BlsPkValue::invalid()])
      .collect();
    let mut buf = vec![4u8];
    for pk in &vvec {
      buf.extend(pk.to_bytes(kind));
    }
    assert_eq!(serialize_hash_vector(&vvec, kind), sha(&buf));
    let refs: Vec<&BlsPkValue> = vvec.iter().collect();
    assert_eq!(serialize_hash_vector(refs.iter().copied(), kind), sha(&buf));
  }
}
