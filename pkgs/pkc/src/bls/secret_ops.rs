//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scheme-generic BLS secret key.

use super::byte_bags::BlsDhBytes;
use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::scalar::Fr;
use super::scheme_ops::BlsScheme;
use super::sig_basic::BlsSignature;
#[cfg(feature = "codec")]
use super::BLS_SK_LEN;
use super::{BlsScIetf, BlsSigId, BlsSkBytes};
use crate::prelude::*;

#[cfg(feature = "codec")]
use dash_num::Hash256;
#[cfg(feature = "codec")]
use dash_types::dlgt_scodec;
#[cfg(feature = "codec")]
use dash_types::type_id::TypeId;
use dash_types::{qtypestr, type_cvrt};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use core::fmt::{Debug, Formatter, Result as FmtResult};

/// A BLS secret key (32-byte scalar).
#[cfg_attr(feature = "codec", derive(TypeId))]
pub struct BlsSecretKey<S: BlsScheme>(pub(crate) S::InnerSk);

#[cfg(feature = "codec")]
dlgt_scodec!(for[S: BlsScheme] BlsSecretKey<S> => BlsSkBytes, Hash256, BlsError, BLS_SK_LEN);

impl<S: BlsScheme> BlsSecretKey<S> {
  /// Derive a secret key from input keying material (>= 32 bytes).
  ///
  /// # Errors
  ///
  /// Returns `InvalidKeyMaterial` when `ikm` is shorter than 32 bytes.
  pub fn from_ikm(ikm: &[u8]) -> Result<Self, BlsError> {
    S::sk_from_ikm(ikm).map(Self)
  }

  /// Generate a new random secret key.
  ///
  /// Draws the key material and hands it to [`from_ikm`](Self::from_ikm).
  pub fn generate(rng: &mut impl CryptoRng) -> Self {
    loop {
      let mut ikm = Zeroizing::new([0u8; 32]);
      rng.fill_bytes(&mut *ikm);

      if let Ok(key) = Self::from_ikm(&*ikm) {
        return key;
      }
    }
  }

  /// Parse from a 32-byte big-endian scalar.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSecretKey` when the bytes are not a valid scalar.
  pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, BlsError> {
    S::sk_from_bytes(bytes).map(Self)
  }

  /// Serialize to 32 bytes, wiped when the returned value drops.
  pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
    S::sk_to_bytes(&self.0)
  }

  /// Retag this key under another scheme.
  ///
  /// A secret key is a scalar, so a retag re-encodes nothing; only the public
  /// key it derives changes encoding rather than value. The secret-side
  /// companion to [`BlsPublicKey::to_scheme`], for a holder typed to one arm.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSecretKey` when the target scheme refuses the scalar.
  pub fn to_scheme<T: BlsScheme>(&self) -> Result<BlsSecretKey<T>, BlsError> {
    BlsSecretKey::<T>::from_bytes(&self.to_bytes())
  }

  /// Add `tweak` to the secret scalar, modulo the group order.
  ///
  /// # Errors
  ///
  /// Returns `InvalidTweak` when `tweak` is not below the group order, or when
  /// the sum is zero. A zero sum means the tweak is this scalar's additive
  /// inverse, so whoever chose the tweak already knows the key; the sum is
  /// refused rather than returned as a key.
  pub fn add_tweak(&self, tweak: &[u8; 32]) -> Result<Self, BlsError> {
    S::add_tweak_sk(&self.0, tweak).map(Self::from_inner)
  }

  /// Multiply the secret scalar by `tweak`, modulo the group order.
  ///
  /// # Errors
  ///
  /// Returns `InvalidTweak` when `tweak` is not below the group order, or when
  /// it is zero. The order is prime, so no other tweak can zero the product.
  pub fn mul_tweak(&self, tweak: &[u8; 32]) -> Result<Self, BlsError> {
    S::mul_tweak_sk(&self.0, tweak).map(Self::from_inner)
  }

  /// Negate the secret scalar, modulo the group order.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSecretKey` when the scalar is zero, including after the
  /// key has been zeroized.
  pub fn negate(&self) -> Result<Self, BlsError> {
    S::negate_sk(&self.0).map(Self::from_inner)
  }

  /// Derive the corresponding public key.
  pub fn public_key(&self) -> BlsPublicKey<S> {
    BlsPublicKey(S::derive_pk(&self.0))
  }

  /// Whether `pubkey` is this key's public counterpart.
  pub fn verify_pubkey(&self, pubkey: &BlsPublicKey<S>) -> bool {
    self.public_key() == *pubkey
  }

  /// Sign a message of the scheme's message type.
  pub fn sign(&self, msg: S::Msg<'_>) -> BlsSignature<S> {
    BlsSignature::from_inner(S::sign(&self.0, msg))
  }

  /// Compute a DH shared key: `self * peer_pk`.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the peer key or the product point
  /// is invalid.
  pub fn dh_exchange(&self, peer_pk: &BlsPublicKey<S>) -> Result<BlsDhBytes, BlsError> {
    S::dh_bytes(&self.0, &peer_pk.0)
  }

  /// Sum multiple secret keys (mod group order).
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no keys are given, or `InvalidSecretKey`
  /// when the sum is not a valid scalar.
  pub fn aggregate(keys: &[&Self]) -> Result<Self, BlsError> {
    let inner_refs: Vec<&S::InnerSk> = keys.iter().map(|k| &k.0).collect();
    S::aggregate_sk(&inner_refs).map(Self::from_inner)
  }

  pub(crate) fn from_inner(inner: S::InnerSk) -> Self {
    Self(inner)
  }
}

impl BlsSecretKey<BlsScIetf> {
  /// Sign under the domain separation tag selected by `scheme`.
  pub fn sign_with(&self, msg: &[u8], scheme: BlsSigId) -> BlsSignature<BlsScIetf> {
    BlsSignature::from_inner(BlsScIetf::sign_with(&self.0, msg, scheme))
  }
}

impl<S: BlsScheme> Clone for BlsSecretKey<S> {
  fn clone(&self) -> Self {
    Self(self.0.clone())
  }
}

impl<S: BlsScheme> Drop for BlsSecretKey<S> {
  fn drop(&mut self) {
    self.zeroize();
  }
}

impl<S: BlsScheme> Debug for BlsSecretKey<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    qtypestr(f, core::any::type_name::<Self>())?;
    f.write_str("(..)")
  }
}

impl<S: BlsScheme> Eq for BlsSecretKey<S> {}

impl<S: BlsScheme> PartialEq for BlsSecretKey<S> {
  fn eq(&self, other: &Self) -> bool {
    use subtle::ConstantTimeEq;
    (*self.to_bytes()).ct_eq(&*other.to_bytes()).into()
  }
}

impl<S: BlsScheme> Zeroize for BlsSecretKey<S> {
  fn zeroize(&mut self) {
    S::zeroize_sk(&mut self.0);
  }
}

impl<S: BlsScheme> ZeroizeOnDrop for BlsSecretKey<S> {}

type_cvrt!(for[S: BlsScheme] From<BlsSecretKey<S>> for BlsSkBytes, |sk| {
  Self::from_bytes(*sk.to_bytes())
});

type_cvrt!(for[S: BlsScheme] TryFrom<BlsSkBytes> for BlsSecretKey<S>, BlsError, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

impl BlsSkBytes {
  /// Validates the bytes as a secret key under scheme `S`.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSecretKey` when the bytes are not a valid scalar.
  pub fn to<S: BlsScheme>(&self) -> Result<BlsSecretKey<S>, BlsError> {
    BlsSecretKey::try_from(self)
  }
}

type_cvrt!(for[S: BlsScheme] TryFrom<BlsSecretKey<S>> for Zeroizing<Fr>, BlsError, |sk| {
  Fr::from_bendian_reduce(&sk.to_bytes()).map(Zeroizing::new)
});

type_cvrt!(for[S: BlsScheme] TryFrom<Fr> for BlsSecretKey<S>, BlsError, |scalar| {
  Self::from_bytes(&scalar.to_bendian())
});

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::tests::{negate_scalar, GROUP_ORDER, RSEED};
  use crate::bls::{BlsError, BlsScChia, BlsScIetf};

  use dash_dev::{arr_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Clone, Copy, Debug)]
  enum Tweak {
    Add,
    Mul,
    Neg,
  }

  impl Tweak {
    fn on_sk<S: BlsScheme>(self, sk: &BlsSecretKey<S>, tweak: &[u8; 32]) -> BlsSecretKey<S> {
      match self {
        Tweak::Add => sk.add_tweak(tweak).unwrap(),
        Tweak::Mul => sk.mul_tweak(tweak).unwrap(),
        Tweak::Neg => sk.negate().unwrap(),
      }
    }

    fn on_pk<S: BlsScheme>(self, pk: &BlsPublicKey<S>, tweak: &[u8; 32]) -> BlsPublicKey<S> {
      match self {
        Tweak::Add => pk.add_tweak(tweak).unwrap(),
        Tweak::Mul => pk.mul_tweak(tweak).unwrap(),
        Tweak::Neg => pk.negate().unwrap(),
      }
    }
  }

  /// A tweak on `a` has to land on the matching tweak on `aG`, or the same
  /// tweak applied to the two halves of a key pair would part them.
  fn assert_tweak_agrees_on_both_sides<S: BlsScheme>(op: Tweak) {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let tweak = *BlsSecretKey::<S>::from_ikm(&RSEED[1]).unwrap().to_bytes();

    let tweaked_sk = op.on_sk(&sk, &tweak);
    let tweaked_pk = op.on_pk(&sk.public_key(), &tweak);

    assert_eq!(tweaked_sk.public_key(), tweaked_pk);
    assert!(tweaked_sk.verify_pubkey(&tweaked_pk));

    let msg = S::msg_ref(&[0x5a; 32]);
    assert_eq!(tweaked_pk.verify(msg, &tweaked_sk.sign(msg)), Ok(()));
  }

  #[rstest]
  #[case::chia(assert_tweak_agrees_on_both_sides::<BlsScChia>)]
  #[case::ietf(assert_tweak_agrees_on_both_sides::<BlsScIetf>)]
  fn tweak_agrees_on_both_sides(#[case] assertion: fn(Tweak), #[values(Tweak::Add, Tweak::Mul, Tweak::Neg)] op: Tweak) {
    assertion(op);
  }

  fn assert_tweak_add_refuses_order_or_above<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();

    assert_eq!(sk.add_tweak(&GROUP_ORDER), Err(BlsError::InvalidTweak));
    assert_eq!(sk.add_tweak(&[0xff; 32]), Err(BlsError::InvalidTweak));
    assert_eq!(sk.public_key().add_tweak(&GROUP_ORDER), Err(BlsError::InvalidTweak));
  }

  #[rstest]
  #[case::chia(assert_tweak_add_refuses_order_or_above::<BlsScChia>)]
  #[case::ietf(assert_tweak_add_refuses_order_or_above::<BlsScIetf>)]
  fn tweak_add_refuses_order_or_above(#[case] assertion: fn()) {
    assertion();
  }

  /// `order - a`, so `a + t == 0`. Whoever picks the tweak can compute it
  /// from `aG` alone, so the sum has to be refused rather than handed back.
  fn assert_tweak_add_refuses_zero_sum<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let tweak = negate_scalar(&sk.to_bytes());

    assert_eq!(sk.add_tweak(&tweak), Err(BlsError::InvalidTweak));
    // The point at infinity is no key either.
    assert_eq!(sk.public_key().add_tweak(&tweak), Err(BlsError::InvalidTweak));
  }

  #[rstest]
  #[case::chia(assert_tweak_add_refuses_zero_sum::<BlsScChia>)]
  #[case::ietf(assert_tweak_add_refuses_zero_sum::<BlsScIetf>)]
  fn tweak_add_refuses_zero_sum(#[case] assertion: fn()) {
    assertion();
  }

  /// `at == ta`, so `t(aG) == a(tG)`.
  fn assert_tweak_mul_commutes<S: BlsScheme>() {
    let a = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let t = BlsSecretKey::<S>::from_ikm(&RSEED[1]).unwrap();

    assert_eq!(a.mul_tweak(&t.to_bytes()).unwrap(), t.mul_tweak(&a.to_bytes()).unwrap());
    assert_eq!(
      a.public_key().mul_tweak(&t.to_bytes()).unwrap(),
      t.public_key().mul_tweak(&a.to_bytes()).unwrap()
    );
  }

  #[rstest]
  #[case::chia(assert_tweak_mul_commutes::<BlsScChia>)]
  #[case::ietf(assert_tweak_mul_commutes::<BlsScIetf>)]
  fn tweak_mul_commutes(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_tweak_mul_by_one_is_identity<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let mut one = [0u8; 32];
    one[31] = 1;

    assert_eq!(sk.mul_tweak(&one).unwrap(), sk);
    assert_eq!(sk.public_key().mul_tweak(&one).unwrap(), sk.public_key());
  }

  #[rstest]
  #[case::chia(assert_tweak_mul_by_one_is_identity::<BlsScChia>)]
  #[case::ietf(assert_tweak_mul_by_one_is_identity::<BlsScIetf>)]
  fn tweak_mul_by_one_is_identity(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_tweak_mul_refuses_bad_factor<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let zero = [0u8; 32];

    assert_eq!(sk.mul_tweak(&zero), Err(BlsError::InvalidTweak));
    assert_eq!(sk.mul_tweak(&GROUP_ORDER), Err(BlsError::InvalidTweak));
    assert_eq!(sk.public_key().mul_tweak(&zero), Err(BlsError::InvalidTweak));
    assert_eq!(sk.public_key().mul_tweak(&GROUP_ORDER), Err(BlsError::InvalidTweak));
  }

  #[rstest]
  #[case::chia(assert_tweak_mul_refuses_bad_factor::<BlsScChia>)]
  #[case::ietf(assert_tweak_mul_refuses_bad_factor::<BlsScIetf>)]
  fn tweak_mul_refuses_bad_factor(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_tweak_neg_is_order_minus_scalar<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();

    assert_eq!(*sk.negate().unwrap().to_bytes(), negate_scalar(&sk.to_bytes()));
  }

  #[rstest]
  #[case::chia(assert_tweak_neg_is_order_minus_scalar::<BlsScChia>)]
  #[case::ietf(assert_tweak_neg_is_order_minus_scalar::<BlsScIetf>)]
  fn tweak_neg_is_order_minus_scalar(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_tweak_neg_twice_is_identity<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let negated = sk.negate().unwrap();

    assert_ne!(negated, sk);
    assert_eq!(negated.negate().unwrap(), sk);
    assert_ne!(sk.public_key().negate().unwrap(), sk.public_key());
    assert_eq!(sk.public_key().negate().unwrap().negate().unwrap(), sk.public_key());
  }

  #[rstest]
  #[case::chia(assert_tweak_neg_twice_is_identity::<BlsScChia>)]
  #[case::ietf(assert_tweak_neg_twice_is_identity::<BlsScIetf>)]
  fn tweak_neg_twice_is_identity(#[case] assertion: fn()) {
    assertion();
  }

  #[derive(Deserialize)]
  struct KeygenVec {
    sk: String,
    pk: String,
  }

  #[derive(Deserialize)]
  struct AggSkVec {
    sks: Vec<String>,
    agg_sk: String,
  }

  /// A retag moves no scalar, so the bytes survive and the derived public key
  /// is the converted one rather than a different key.
  fn assert_scheme_retag_keeps_the_scalar<S: BlsScheme, T: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let there = sk.to_scheme::<T>().unwrap();

    assert_eq!(*there.to_bytes(), *sk.to_bytes());
    assert_eq!(there.public_key(), sk.public_key().to_scheme::<T>().unwrap());
  }

  #[rstest]
  #[case::chia_to_ietf(assert_scheme_retag_keeps_the_scalar::<BlsScChia, BlsScIetf>)]
  #[case::ietf_to_chia(assert_scheme_retag_keeps_the_scalar::<BlsScIetf, BlsScChia>)]
  #[case::ietf_to_ietf(assert_scheme_retag_keeps_the_scalar::<BlsScIetf, BlsScIetf>)]
  fn scheme_retag_keeps_the_scalar(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_roundtrip<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let bytes = sk.to_bytes();
    let decoded = BlsSecretKey::<S>::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.to_bytes(), bytes);
  }

  #[rstest]
  #[case::chia(assert_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_roundtrip::<BlsScIetf>)]
  fn serialization_roundtrip(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_derive_pk<S: BlsScheme>(scheme: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_keygen").scope(scheme);
    let vecs: Vec<KeygenVec> = corpus.vectors("derive_pk");
    for v in &vecs {
      let sk = BlsSecretKey::<S>::from_bytes(&arr_from_hex(&v.sk)).unwrap();
      assert_eq!(sk.public_key().to_bytes().to_lower_hex_string(), v.pk);
    }
  }

  #[rstest]
  #[case::chia(assert_derive_pk::<BlsScChia>, "chia")]
  #[case::ietf(assert_derive_pk::<BlsScIetf>, "ietf")]
  fn derive_public_key_matches_vectors(#[case] assertion: fn(&str), #[case] scheme: &str) {
    assertion(scheme);
  }

  /// Key generation follows the KeyGen of draft-irtf-cfrg-bls-signature-03
  /// for both schemes; another variant would change these bytes.
  fn assert_keygen_draft03<S: BlsScheme>(ikm: &[u8], expected: &str) {
    let sk = BlsSecretKey::<S>::from_ikm(ikm).unwrap();
    assert_eq!(sk.to_bytes().to_lower_hex_string(), expected);
  }

  #[rstest]
  #[case::seed0(&RSEED[0], "4a353be3dac091a0a7e640620372f5e1e2e4401717c1e79cac6ffba8f6905604")]
  #[case::seed1(&RSEED[1], "6fc9d9a2b05fd1f0e51bc91041a03be8657081f272ec281aff731624f0d1c220")]
  #[case::seed2(&RSEED[2], "01433a85a09ef4c9f7a2cd973c007c1150631a35a1d0e199eca4364e051809bb")]
  fn keygen_uses_draft03_variant(#[case] ikm: &[u8], #[case] expected: &str) {
    assert_keygen_draft03::<BlsScChia>(ikm, expected);
    assert_keygen_draft03::<BlsScIetf>(ikm, expected);
  }

  /// The keygen variant requires at least 32 bytes of input key material.
  fn assert_short_ikm_rejected<S: BlsScheme>() {
    assert_eq!(
      BlsSecretKey::<S>::from_ikm(&[0u8; 31]).map(|_| ()),
      Err(BlsError::InvalidKeyMaterial)
    );
  }

  #[rstest]
  #[case::chia(assert_short_ikm_rejected::<BlsScChia>)]
  #[case::ietf(assert_short_ikm_rejected::<BlsScIetf>)]
  fn generate_rejects_short_ikm(#[case] assertion: fn()) {
    assertion();
  }

  /// One secret scalar derives two differently encoded public keys, so a
  /// scheme mix-up cannot go unnoticed.
  #[rstest]
  fn public_key_formats_differ() {
    let chia = BlsSecretKey::<BlsScChia>::from_ikm(&RSEED[0]).unwrap();
    let ietf = BlsSecretKey::<BlsScIetf>::from_bytes(&chia.to_bytes()).unwrap();
    assert_ne!(chia.public_key().to_bytes(), ietf.public_key().to_bytes());
  }

  #[cfg(feature = "codec")]
  fn assert_codec_roundtrip<S: BlsScheme>() {
    use dash_types::codec::BaseCodec;

    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let mut buf = Vec::new();
    sk.encode(&mut buf);
    assert_eq!(buf.len(), 32);

    let mut slice = buf.as_slice();
    let decoded = BlsSecretKey::<S>::decode(&mut slice).unwrap();
    assert_eq!(decoded.to_bytes(), sk.to_bytes());
    assert!(slice.is_empty());
  }

  #[cfg(feature = "codec")]
  #[rstest]
  #[case::chia(assert_codec_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_codec_roundtrip::<BlsScIetf>)]
  fn codec_roundtrip(#[case] assertion: fn()) {
    assertion();
  }

  /// Summing scalars is scheme-independent, so one corpus serves both.
  fn assert_aggregate_vectors<S: BlsScheme>() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_aggregate").scope("base");
    let vecs: Vec<AggSkVec> = corpus.vectors("sk");

    for v in &vecs {
      let sks: Vec<BlsSecretKey<S>> = v
        .sks
        .iter()
        .map(|sk| BlsSecretKey::<S>::from_bytes(&arr_from_hex(sk)).unwrap())
        .collect();
      let refs: Vec<&BlsSecretKey<S>> = sks.iter().collect();
      let agg = BlsSecretKey::<S>::aggregate(&refs).unwrap();
      assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_sk);
    }
  }

  #[rstest]
  #[case::chia(assert_aggregate_vectors::<BlsScChia>)]
  #[case::ietf(assert_aggregate_vectors::<BlsScIetf>)]
  fn aggregate_matches_vectors(#[case] assertion: fn()) {
    assertion();
  }
}
